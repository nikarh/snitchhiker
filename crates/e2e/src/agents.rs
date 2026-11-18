//! Agents (decision 0008): an agent's MCP server sees only its own processes' refused connections, proposes rules, a
//! person approves them, and the rules apply to the agent's processes alone until it ends.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::daemon::Running;
use crate::util::{check, run};

/// An address of the VM's own (on the loopback interface) that no alias names: not `loopback`, not `lan`.
const ADDRESS: &str = "192.0.2.77";

/// The agent: connects (refused), starts `snitchhiker mcp`, finds the refused connection, proposes a rule, prints
/// the proposal, waits for the answer, connects again, and prints all of it; then waits for a line before exiting.
const AGENT: &str = r#"
import json, subprocess, sys
host, port = sys.argv[1], int(sys.argv[2])
def connect():
    code = f"import socket\ntry:\n    socket.create_connection(('{host}', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
    return subprocess.run(['python3', '-c', code], capture_output=True, text=True).stdout.strip()
first = connect()
mcp = subprocess.Popen(['snitchhiker', 'mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
n = 0
def call(method, params):
    global n
    n += 1
    mcp.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': n, 'method': method, 'params': params}) + '\n')
    mcp.stdin.flush()
    return json.loads(mcp.stdout.readline())
def tool(name, args):
    result = call('tools/call', {'name': name, 'arguments': args})['result']
    text = result['content'][0]['text']
    return json.loads(text) if not result.get('isError') else {'error': text}
call('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'e2e', 'version': '1'}})
blocked = tool('recent_blocked', {})
# Anywhere, for any program: narrowed to the program the agent was refused, and marked.
everything = tool('propose_rules', {'justification': 'everything', 'rules': [{'hosts': []}]})
proposal = tool('propose_rules', {'justification': 'The tests need their server.',
    'rules': [{'exe': '/usr/bin/python3', 'hosts': [host], 'ports': [str(port)]}]})
print(json.dumps({'first': first, 'blocked': blocked, 'everything': everything, 'proposal': proposal}), flush=True)
answer = tool('wait_for_proposal', {'id': proposal.get('id', 0), 'timeout_secs': 30})
second = connect()
print(json.dumps({'answer': answer, 'second': second}), flush=True)
sys.stdin.readline()
"#;

/// The value at a JSON pointer, null where there is none.
fn at<'a>(value: &'a serde_json::Value, pointer: &str) -> &'a serde_json::Value {
    value.pointer(pointer).unwrap_or(&serde_json::Value::Null)
}

/// `--agent <host> <port>`: the agent of the scenario, for the desktop scripts (a person answers in the app). Its
/// two reports go to stdout.
pub fn agent(host: &str, port: &str) -> Result<(), String> {
    let status = Command::new("python3")
        .args(["-c", AGENT, host, port])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("the agent ended with {status}"))
    }
}

pub fn a_proposal_is_approved_for_the_session() -> Result<(), String> {
    let _ = run(
        "ip",
        &["addr", "add", &format!("{ADDRESS}/32"), "dev", "lo"],
    );
    let result = scenario();
    let _ = run(
        "ip",
        &["addr", "del", &format!("{ADDRESS}/32"), "dev", "lo"],
    );
    result
}

fn scenario() -> Result<(), String> {
    let daemon = Running::start("agents", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let listener = TcpListener::bind(format!("{ADDRESS}:0")).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    // Something else of mallory's, outside the agent's tree, is refused too: the agent mustn't see it.
    let _ = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "curl",
            "-s",
            "-m",
            "1",
            "http://192.0.2.77:9",
        ])
        .output();
    let mut agent = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "python3",
            "-c",
            AGENT,
            ADDRESS,
            &port.to_string(),
        ])
        .current_dir("/tmp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(agent.stdout.take().ok_or("no stdout")?).lines();
    let mut next = || -> Result<serde_json::Value, String> {
        let line = lines
            .next()
            .ok_or("the agent ended early")?
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&line).map_err(|e| format!("{e}: {line}"))
    };
    let proposed = next()?;
    let id = at(&proposed, "/proposal/id").as_u64().unwrap_or(0);
    let listed = daemon.cli(&["proposals"])?;
    let shown = daemon.cli(&["proposals", "show", &id.to_string()])?;
    let approved = daemon.cli(&["proposals", "approve", &id.to_string(), "--reason", "fine"])?;
    let answered = next()?;
    let rules = daemon.cli(&["rules"])?;
    // Mallory's other processes don't get the rule.
    let outside = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "python3",
            "-c",
            &format!(
                "import socket\ntry:\n    socket.create_connection(('{ADDRESS}', {port}), timeout=2)\n    print('connected')\nexcept OSError:\n    print('failed')"
            ),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let outside = String::from_utf8_lossy(&outside.stdout).trim().to_owned();
    // The agent ends: its session's rule goes.
    if let Some(stdin) = agent.stdin.as_mut() {
        let _ = stdin.write_all(b"\n");
    }
    let _ = agent.wait();
    thread::sleep(Duration::from_secs(4));
    let after = daemon.cli(&["rules"])?;
    let all = daemon.cli(&["proposals", "--all"])?;
    drop(listener);
    let found = format!(
        "{proposed:#}\n{listed}{shown}{approved}{answered:#}\noutside: {outside}\n{rules}--- after:\n{after}{all}"
    );
    verify(
        &proposed, &answered, port, id, &listed, &shown, &rules, &outside, &after, &all, &found,
    )
}

fn verify(
    proposed: &serde_json::Value,
    answered: &serde_json::Value,
    port: u16,
    id: u64,
    listed: &str,
    shown: &str,
    rules: &str,
    outside: &str,
    after: &str,
    all: &str,
    found: &str,
) -> Result<(), String> {
    check(
        at(proposed, "/first")
            .as_str()
            .is_some_and(|f| f.starts_with("failed")),
        "the agent's first connection wasn't refused",
        found,
    )?;
    let blocked = at(proposed, "/blocked/connections")
        .as_array()
        .cloned()
        .unwrap_or_default();
    check(
        blocked.iter().any(|b| at(b, "/port") == port)
            && !blocked.iter().any(|b| at(b, "/port") == 9),
        "recent_blocked doesn't list just the agent's own refused connections",
        found,
    )?;
    check(
        at(proposed, "/everything/rules/0/program")
            .as_str()
            .is_some_and(|p| p.starts_with("/usr/bin/python3."))
            && at(proposed, "/everything/rules/0/marked")
                .as_array()
                .is_some_and(|m| m.iter().any(|m| m == "any destination")),
        "a rule for anywhere wasn't narrowed to the program refused and marked",
        found,
    )?;
    check(
        at(proposed, "/proposal/state") == "pending"
            && at(proposed, "/proposal/rules/0/marked")
                .as_array()
                .is_some_and(Vec::is_empty)
            && at(proposed, "/proposal/rules/0/program")
                .as_str()
                .is_some_and(|p| p.starts_with("/usr/bin/python3.")),
        "the proposal isn't pending, unmarked, with the program the kernel saw",
        found,
    )?;
    check(
        listed.contains(&format!("proposal {id}: pending"))
            && shown.contains("| The tests need their server.")
            && shown.contains("refused: /usr/bin/python3."),
        "the command line doesn't show the proposal with the agent's words and the evidence",
        found,
    )?;
    check(
        at(answered, "/answer/state") == "approved"
            && at(answered, "/answer/reason") == "fine"
            && at(answered, "/answer/folder")
                .as_str()
                .is_some_and(|f| f.starts_with("Agents/python3") && f.ends_with("/tmp")),
        "the agent wasn't told it was approved, why, and where the rules are",
        found,
    )?;
    check(
        at(answered, "/second") == "connected",
        "the agent's process couldn't connect after the approval",
        found,
    )?;
    check(
        rules.contains("session"),
        "the rule isn't limited to the session",
        found,
    )?;
    check(
        outside == "failed",
        "a process outside the agent's tree got through on its rule",
        found,
    )?;
    check(
        !after.contains("session") && all.contains(&format!("proposal {id}: approved")),
        "the session's rule stayed after the agent ended",
        found,
    )
}

/// A proposal marked broad (any destination) is shown with its risks and approved by a client like any other: what a
/// rule says takes no authorization (decision 0018), polkit refusing or not.
pub fn a_broad_proposal_is_marked_and_approved() -> Result<(), String> {
    let _ = run(
        "ip",
        &["addr", "add", &format!("{ADDRESS}/32"), "dev", "lo"],
    );
    let result = broad_scenario();
    let _ = crate::stepup::polkit_answers(None);
    let _ = run(
        "ip",
        &["addr", "del", &format!("{ADDRESS}/32"), "dev", "lo"],
    );
    result
}

fn broad_scenario() -> Result<(), String> {
    crate::local_auth::install_clients()?;
    let daemon = Running::start(
        "agents-step-up",
        &format!(
            "mode = \"enforce\"\nno_match = \"deny\"\ntrusted_clients = [\"{}\"]\n",
            crate::local_auth::CLIENT
        ),
    )?;
    let listener = TcpListener::bind(format!("{ADDRESS}:0")).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut agent = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "python3",
            "-c",
            AGENT,
            ADDRESS,
            &port.to_string(),
        ])
        .current_dir("/tmp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(agent.stdout.take().ok_or("no stdout")?).lines();
    let line = lines
        .next()
        .ok_or("the agent ended early")?
        .map_err(|e| e.to_string())?;
    let proposed: serde_json::Value =
        serde_json::from_str(&line).map_err(|e| format!("{e}: {line}"))?;
    let broad = at(&proposed, "/everything/id").as_u64().unwrap_or(0);
    let narrow = at(&proposed, "/proposal/id").as_u64().unwrap_or(0);
    let marked = at(&proposed, "/everything/rules/0/marked")
        .as_bool()
        .unwrap_or(false);
    crate::stepup::polkit_answers(Some("NO"))?;
    let broad_approved = crate::stepup::approve_as_client(broad)?;
    let narrow_approved = crate::stepup::approve_as_client(narrow)?;
    crate::stepup::polkit_answers(None)?;
    let audit = daemon.cli(&["audit"])?;
    if let Some(stdin) = agent.stdin.as_mut() {
        let _ = stdin.write_all(b"\n");
    }
    let _ = agent.wait();
    drop(listener);
    let found = format!("{proposed:#}\nbroad: {broad_approved}narrow: {narrow_approved}{audit}");
    check(marked, "a broad proposal wasn't marked", &found)?;
    check(
        broad_approved.trim() == "approved" && narrow_approved.trim() == "approved",
        "a proposal wasn't approved",
        &found,
    )?;
    check(
        !audit.contains("approve agent proposal"),
        "approving a proposal asked for authorization",
        &found,
    )
}

/// An agent that proposes the rules given as JSON arguments one after another, printing each answer as it comes
/// (without waiting for a person), and then waits for a line before exiting.
const PROPOSER: &str = r"
import json, subprocess, sys
mcp = subprocess.Popen(['snitchhiker', 'mcp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
n = 0
def call(method, params):
    global n
    n += 1
    mcp.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': n, 'method': method, 'params': params}) + '\n')
    mcp.stdin.flush()
    return json.loads(mcp.stdout.readline())
def tool(name, args):
    result = call('tools/call', {'name': name, 'arguments': args})['result']
    text = result['content'][0]['text']
    return json.loads(text) if not result.get('isError') else {'error': text}
call('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'e2e', 'version': '1'}})
for line in sys.stdin:
    if not line.strip():
        break
    rule = json.loads(line)
    print(json.dumps(tool('propose_rules', {'justification': 'The build needs it.', 'rules': [rule]})), flush=True)
";

/// Inside an envelope a known agent's proposal is approved without asking, for its session; outside, it waits for a
/// person; once the person denies and mutes the agent, its next proposal is denied without asking.
pub fn envelopes_approve_and_muting_denies() -> Result<(), String> {
    let daemon = Running::start(
        "envelopes",
        "mode = \"enforce\"\nno_match = \"deny\"\nagent_programs = [\"glob:/usr/bin/python3*\"]\n",
    )?;
    let added = daemon.cli(&[
        "envelopes",
        "add",
        "registries",
        "--project",
        "glob:/tmp/**",
        "--host",
        "registry.test",
        "--host",
        "*.crates.test",
        "--port",
        "443",
    ])?;
    let _ = std::fs::create_dir_all("/tmp/project");
    let mut agent = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", PROPOSER])
        .current_dir("/tmp/project")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut input = agent.stdin.take().ok_or("no stdin")?;
    let mut lines = BufReader::new(agent.stdout.take().ok_or("no stdout")?).lines();
    let mut propose = |rule: &str| -> Result<serde_json::Value, String> {
        writeln!(input, "{rule}").map_err(|e| e.to_string())?;
        let line = lines
            .next()
            .ok_or("the agent ended early")?
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&line).map_err(|e| format!("{e}: {line}"))
    };
    let inside =
        propose(r#"{"exe": "/usr/bin/curl", "hosts": ["static.crates.test"], "ports": ["443"]}"#)?;
    let outside =
        propose(r#"{"exe": "/usr/bin/curl", "hosts": ["elsewhere.test"], "ports": ["443"]}"#)?;
    let waiting = at(&outside, "/id").as_u64().unwrap_or(0);
    let denied = daemon.cli(&["proposals", "deny", &waiting.to_string(), "--mute"])?;
    let muted =
        propose(r#"{"exe": "/usr/bin/curl", "hosts": ["registry.test"], "ports": ["443"]}"#)?;
    let alerts = daemon.cli(&["alerts"])?;
    let history = daemon.cli(&["history"])?;
    drop(propose);
    let _ = agent.kill();
    let _ = agent.wait();
    let found = format!(
        "{added}\ninside: {inside:#}\noutside: {outside:#}\n{denied}\nmuted: {muted:#}\n{alerts}{history}"
    );
    check(
        at(&inside, "/state").as_str() == Some("approved")
            && at(&inside, "/envelope").as_str() == Some("registries"),
        "a proposal inside the envelope wasn't approved by it",
        &found,
    )?;
    check(
        at(&outside, "/state").as_str() == Some("pending"),
        "a proposal outside the envelope didn't wait for a person",
        &found,
    )?;
    check(
        at(&muted, "/state").as_str() == Some("denied"),
        "a muted agent's proposal wasn't denied",
        &found,
    )?;
    check(
        alerts.contains("envelope") && history.contains("envelope \"registries\""),
        "the envelope's approval isn't in the alerts and the history",
        &found,
    )
}
