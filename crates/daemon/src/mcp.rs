//! `snitchhiker mcp`: an MCP server (stdio) for coding agents, speaking to the node's agent socket (decision 0008).
//!
//! MCP over stdio is JSON-RPC 2.0, one message a line. The server answers `initialize`, `ping`, `tools/list` and
//! `tools/call`; its tools map one to one onto the agent role's requests. It runs as the user, started by the agent
//! (whose processes the node then knows as the agent's); it can propose, never decide.

use std::io::{self, BufRead as _, Write as _};
use std::path::Path;

use serde_json::{Value, json};
use snitchhiker_client::{AGENT_SOCKET, Client};
use snitchhiker_proto::{convert, v1};

/// The MCP versions this server speaks, newest first.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "\
Snitchhiker is the application firewall of this machine: it decides which programs may connect where. When a \
network command fails (a timeout, a refused or reset connection, a DNS name that resolves but never connects), \
call recent_blocked: it lists what this session's own processes were refused. To get access, call propose_rules \
with the narrowest rules that would let them through and a one-line reason, then wait_for_proposal: a person \
approves or denies it, and you are told why. Approved rules last for this session unless the person chooses \
otherwise. Never try to get around the firewall.";

/// Runs the server on stdin and stdout until stdin closes.
pub fn serve(version: &str) -> io::Result<()> {
    let mut server = Server {
        version: version.to_owned(),
        client: None,
    };
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) => {
                let answers: Vec<Value> = batch.iter().filter_map(|m| server.handle(m)).collect();
                (!answers.is_empty()).then_some(Value::Array(answers))
            }
            Ok(message) => server.handle(&message),
            Err(e) => Some(failure(&Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(answer) = answer {
            serde_json::to_writer(&mut stdout, &answer)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

struct Server {
    version: String,
    /// The connection to the node, made when a tool first needs it, and again after it broke.
    client: Option<Client>,
}

#[expect(clippy::needless_pass_by_value, reason = "answers are built in place")]
fn success(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn failure(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

impl Server {
    /// The answer to a message; none for notifications.
    fn handle(&mut self, message: &Value) -> Option<Value> {
        let id = message.get("id")?.clone();
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        Some(match method {
            "initialize" => {
                let asked = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let version = VERSIONS
                    .iter()
                    .find(|v| **v == asked)
                    .or(VERSIONS.first())
                    .copied()
                    .unwrap_or_default();
                success(
                    &id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "snitchhiker", "version": self.version},
                        "instructions": INSTRUCTIONS,
                    }),
                )
            }
            "ping" => success(&id, json!({})),
            "tools/list" => success(&id, json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                let (text, is_error) = match self.call(name, &arguments) {
                    Ok(value) => (
                        serde_json::to_string_pretty(&value).unwrap_or_default(),
                        false,
                    ),
                    Err(message) => (message, true),
                };
                success(
                    &id,
                    json!({"content": [{"type": "text", "text": text}], "isError": is_error}),
                )
            }
            _ => failure(&id, -32601, &format!("unknown method {method}")),
        })
    }

    /// A request to the node, connecting first if needed (and once more if the connection broke).
    fn request(&mut self, method: &v1::request::Method) -> Result<v1::response::Result, String> {
        for attempt in 0..2 {
            if self.client.is_none() {
                let client = Client::connect(Path::new(AGENT_SOCKET), "mcp", &self.version)
                    .map_err(|e| {
                        format!("can't reach the Snitchhiker node ({AGENT_SOCKET}): {e}")
                    })?;
                self.client = Some(client);
            }
            let Some(client) = self.client.as_mut() else {
                continue;
            };
            match client.call(method.clone()) {
                Ok(result) => return Ok(result),
                Err(snitchhiker_client::Error::Remote { message, .. }) => return Err(message),
                Err(e) if attempt == 0 => {
                    let _ = e;
                    self.client = None;
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("can't reach the Snitchhiker node".to_owned())
    }

    /// The proposal tools.
    fn call_proposals(&mut self, tool: &str, args: &Value) -> Result<Value, String> {
        use v1::request::Method;
        use v1::response::Result as R;
        let unexpected = || "the node answered something unexpected".to_owned();
        match tool {
            "propose_rules" => {
                let rules = args
                    .get("rules")
                    .and_then(Value::as_array)
                    .ok_or("rules: a list of rules")?
                    .iter()
                    .map(proposed_rule)
                    .collect::<Result<Vec<_>, _>>()?;
                let propose = v1::ProposeRules {
                    justification: text(args, "justification")?,
                    rules,
                };
                match self.request(&Method::ProposeRules(propose))? {
                    R::Proposal(proposal) => Ok(proposal_json(&proposal)),
                    _ => Err(unexpected()),
                }
            }
            "get_proposal" | "wait_for_proposal" => {
                let id = id(args)?;
                // The node answers once it changes (or the time is up).
                let wait_secs = if tool == "wait_for_proposal" {
                    let secs = args
                        .get("timeout_secs")
                        .and_then(Value::as_u64)
                        .unwrap_or(300);
                    u32::try_from(secs.min(3600)).unwrap_or(3600)
                } else {
                    0
                };
                match self.request(&Method::GetProposal(v1::GetProposal { id, wait_secs }))? {
                    R::Proposal(proposal) => Ok(proposal_json(&proposal)),
                    _ => Err(unexpected()),
                }
            }
            "withdraw_proposal" => {
                let id = id(args)?;
                match self.request(&Method::WithdrawProposal(v1::WithdrawProposal { id }))? {
                    R::Proposal(proposal) => Ok(proposal_json(&proposal)),
                    _ => Err(unexpected()),
                }
            }
            "annotate_pending" => {
                let annotate = v1::AnnotatePending {
                    prompt: args
                        .get("prompt")
                        .and_then(Value::as_u64)
                        .ok_or("prompt: the prompt's id")?,
                    note: text(args, "note")?,
                };
                match self.request(&Method::AnnotatePending(annotate))? {
                    R::Done(_) => Ok(json!({"annotated": true})),
                    _ => Err(unexpected()),
                }
            }
            other => Err(format!("no tool {other}")),
        }
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, String> {
        use v1::request::Method;
        use v1::response::Result as R;
        let unexpected = || "the node answered something unexpected".to_owned();
        match tool {
            "get_status" => match self.request(&Method::GetStatus(v1::GetStatus {}))? {
                R::Status(status) => Ok(json!({
                    "enforcing": status.mode() == v1::Mode::Enforce,
                    "unmatched_connections": match status.no_match() {
                        v1::Policy::Ask => "a person is asked; refused if nobody answers in time",
                        v1::Policy::Allow => "allowed",
                        v1::Policy::Reject => "rejected",
                        v1::Policy::Deny | v1::Policy::Unspecified => "dropped (they time out)",
                    },
                    "rules": status.rules,
                })),
                _ => Err(unexpected()),
            },
            "check_connection" => {
                let check = v1::CheckConnection {
                    exe: text(args, "exe")?,
                    host: text(args, "host")?,
                    port: u32::try_from(
                        args.get("port")
                            .and_then(Value::as_u64)
                            .ok_or("port: a number")?,
                    )
                    .map_err(|_| "port: 0-65535")?,
                    protocol: args
                        .get("protocol")
                        .and_then(Value::as_str)
                        .unwrap_or("tcp")
                        .to_owned(),
                };
                match self.request(&Method::CheckConnection(check))? {
                    R::Checked(checked) => Ok(json!({
                        "decision": if checked.asked { "ask" } else { action(checked.action()) },
                        "rule": checked.rule,
                    })),
                    _ => Err(unexpected()),
                }
            }
            "recent_blocked" => match self.request(&Method::RecentBlocked(v1::RecentBlocked {}))? {
                R::Blocked(list) => Ok(json!({
                    "connections": list.connections.iter().map(blocked).collect::<Vec<_>>(),
                })),
                _ => Err(unexpected()),
            },
            other => self.call_proposals(other, args),
        }
    }
}

fn text(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{key}: text"))
}

fn id(args: &Value) -> Result<u64, String> {
    args.get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "id: the proposal's id".to_owned())
}

fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Number(n)) => vec![n.to_string()],
        _ => Vec::new(),
    }
}

fn proposed_rule(rule: &Value) -> Result<v1::ProposedRule, String> {
    let context = match rule.get("context").and_then(Value::as_str).unwrap_or("") {
        "" | "host" => v1::Context::Unspecified,
        "container" => v1::Context::Container,
        "vm" => v1::Context::Vm,
        other => return Err(format!("context `{other}`: host, container or vm")),
    };
    Ok(v1::ProposedRule {
        exe: rule
            .get("exe")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        hosts: strings(rule.get("hosts")),
        ports: strings(rule.get("ports")),
        protocol: rule
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        context: context.into(),
    })
}

fn action(action: v1::Action) -> &'static str {
    match action {
        v1::Action::Allow => "allow",
        v1::Action::Deny => "deny",
        v1::Action::Reject => "reject",
        v1::Action::Unspecified => "none",
    }
}

fn blocked(b: &v1::BlockedConnection) -> Value {
    let address = convert::address_from(&b.address).map(|a| a.to_string());
    json!({
        "program": b.exe,
        "host": if b.host.is_empty() { None } else { Some(&b.host) },
        "address": address,
        "port": b.port,
        "protocol": match b.protocol { 6 => "tcp".to_owned(), 17 => "udp".to_owned(), n => n.to_string() },
        "count": b.count,
        "outcome": match b.outcome() {
            v1::BlockedOutcome::Asked if b.prompt.is_some() => "waiting for a person",
            v1::BlockedOutcome::Asked => "a person was asked",
            _ => "refused",
        },
        "prompt": b.prompt,
    })
}

fn proposal_json(p: &v1::Proposal) -> Value {
    let state = match p.state() {
        v1::ProposalState::Pending => "pending",
        v1::ProposalState::Approved => "approved",
        v1::ProposalState::Denied => "denied",
        v1::ProposalState::Withdrawn => "withdrawn",
        v1::ProposalState::Expired => "expired",
        v1::ProposalState::Unspecified => "unknown",
    };
    let rules: Vec<Value> = p
        .rules
        .iter()
        .map(|r| {
            let c = r.conditions.clone().unwrap_or_default();
            json!({
                "program": c.exe.first(),
                "hosts": c.host.iter().chain(&c.net).collect::<Vec<_>>(),
                "ports": c.port,
                "protocol": c.protocol.first(),
                "marked": r.risks.iter().map(|r| r.description.clone()).collect::<Vec<_>>(),
                "matches_refused_connections": r.evidence.iter().map(|e| e.count).sum::<u32>(),
                "already_allowed": r.already_allowed,
                "approved": r.included,
            })
        })
        .collect();
    let note = match p.state() {
        v1::ProposalState::Pending if p.id == 0 => {
            "Today's rules already allow all of it: nothing to approve.".to_owned()
        }
        v1::ProposalState::Pending => format!(
            "Waiting for a person{}. Call wait_for_proposal with id {}.",
            if p.broad {
                " (some rules are marked, so approving takes them a password)"
            } else {
                ""
            },
            p.id
        ),
        v1::ProposalState::Approved => format!(
            "Approved{}; retry what failed.",
            match p.duration() {
                v1::ProposalDuration::Hour => " for an hour",
                v1::ProposalDuration::TwelveHours => " for 12 hours",
                v1::ProposalDuration::Forever => " for good",
                _ => " for this session",
            }
        ),
        v1::ProposalState::Denied => {
            "Denied: don't propose the same again; ask the user if it is needed.".to_owned()
        }
        v1::ProposalState::Withdrawn => "Withdrawn.".to_owned(),
        v1::ProposalState::Expired | v1::ProposalState::Unspecified => "Expired.".to_owned(),
    };
    json!({
        "id": p.id,
        "state": state,
        "reason": if p.reason.is_empty() { None } else { Some(&p.reason) },
        "rules": rules,
        "folder": if p.folder.is_empty() { None } else { Some(&p.folder) },
        "envelope": if p.envelope.is_empty() { None } else { Some(&p.envelope) },
        "note": note,
    })
}

/// The tools, with their descriptions and input schemas.
#[must_use]
pub fn tools() -> Value {
    let rule = json!({
        "type": "object",
        "properties": {
            "exe": {"type": "string", "description": "The program's full path, as recent_blocked shows it (e.g. /usr/bin/cargo). The node uses the program it saw refused, whatever is written here."},
            "hosts": {"type": "array", "items": {"type": "string"}, "description": "Exact host names (crates.io), `*.` and a name for its subdomains (*.githubusercontent.com), addresses or networks. Never empty: a rule for anywhere is refused or marked."},
            "ports": {"type": "array", "items": {"type": "string"}, "description": "Ports or ranges (443, 8000-8080)."},
            "protocol": {"type": "string", "enum": ["tcp", "udp"]},
            "context": {"type": "string", "enum": ["host", "container", "vm"], "description": "Where the program runs; host by default."}
        },
        "required": ["hosts"]
    });
    json!([
        {
            "name": "get_status",
            "description": "Whether the firewall is enforcing, and what happens to connections no rule decides. Call it when network commands fail in ways that could be the firewall.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "check_connection",
            "description": "How a connection would be decided now (allow, deny, reject, or ask a person), and by which rule. Changes nothing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "exe": {"type": "string", "description": "The program's full path."},
                    "host": {"type": "string", "description": "A host name or an address."},
                    "port": {"type": "integer", "description": "The destination port."},
                    "protocol": {"type": "string", "enum": ["tcp", "udp"], "description": "tcp by default."}
                },
                "required": ["exe", "host", "port"]
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "recent_blocked",
            "description": "The connections of this session's own processes (the agent and the commands it ran) that the firewall refused or is asking a person about, over the last hour: program, host, port, count. Nothing of other processes. Call it first when a network command fails.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "propose_rules",
            "description": "Propose rules that allow connections, for a person to approve. Propose only what recent_blocked shows was refused and the task needs, as narrow as possible: the exact program, exact host names, the port. Good: `{exe: /usr/bin/cargo, hosts: [index.crates.io, static.crates.io], ports: [443]}`. Bad: any program, any host, `*.com`, a `/8` network, the LAN or `169.254.169.254`: those are refused or marked, and marked rules need the person's password. Approved rules apply to this session's processes only, and end with it, unless the person chooses longer. The justification is shown to the person as your words: one or two plain sentences on why the task needs it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "justification": {"type": "string", "description": "Why the task needs these connections."},
                    "rules": {"type": "array", "items": rule, "minItems": 1, "maxItems": 16}
                },
                "required": ["justification", "rules"]
            }
        },
        {
            "name": "get_proposal",
            "description": "A proposal's state: pending, approved (with the rules the person kept, possibly narrowed), denied (with their reason), withdrawn or expired.",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "integer", "description": "The proposal's id, as propose_rules returned it."}}, "required": ["id"]},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "wait_for_proposal",
            "description": "Waits until a person answers a proposal (or timeout_secs pass, 300 by default), then returns it as get_proposal does.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer", "description": "The proposal's id, as propose_rules returned it."},
                    "timeout_secs": {"type": "integer", "maximum": 3600, "description": "How long to wait at most; 300 by default."}
                },
                "required": ["id"]
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "withdraw_proposal",
            "description": "Withdraws a pending proposal (it is no longer needed).",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "integer", "description": "The proposal's id, as propose_rules returned it."}}, "required": ["id"]}
        },
        {
            "name": "annotate_pending",
            "description": "Adds a short note to a prompt that one of this session's processes caused and a person is being asked about now (its id is in recent_blocked), saying what the connection is for. Shown to them as your words.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "integer", "description": "The prompt's id, from recent_blocked."},
                    "note": {"type": "string", "maxLength": 500, "description": "What the connection is for."}
                },
                "required": ["prompt", "note"]
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_and_lists_tools() {
        let mut server = Server {
            version: "0".to_owned(),
            client: None,
        };
        let init = server
            .handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}))
            .unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(
            server
                .handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                .is_none()
        );
        let list = server
            .handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "get_status",
                "check_connection",
                "recent_blocked",
                "propose_rules",
                "get_proposal",
                "wait_for_proposal",
                "withdraw_proposal",
                "annotate_pending"
            ]
        );
        let unknown = server
            .handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}))
            .unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[test]
    fn an_unknown_protocol_version_gets_the_newest() {
        let mut server = Server {
            version: "0".to_owned(),
            client: None,
        };
        let init = server
            .handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}))
            .unwrap();
        assert_eq!(init["result"]["protocolVersion"], VERSIONS[0]);
    }

    #[test]
    fn rules_take_numbers_and_strings() {
        let rule = proposed_rule(
            &json!({"exe": "/usr/bin/cargo", "hosts": "crates.io", "ports": [443, "8000-8080"]}),
        )
        .unwrap();
        assert_eq!(rule.hosts, ["crates.io"]);
        assert_eq!(rule.ports, ["443", "8000-8080"]);
        assert!(proposed_rule(&json!({"context": "moon"})).is_err());
    }
}
