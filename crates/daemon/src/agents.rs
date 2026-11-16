//! Agents (decision 0008): who an agent is, what its own processes were refused, and its proposals.
//!
//! An agent is the process that started the MCP server on the agent socket; its *tree* is it and everything it
//! started, each process held by pid and start time. The node remembers, in memory, the lineage of every connection
//! it didn't allow over the last hour, so it can tell an agent what its own processes were refused, and nothing else.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use snitchhiker_core::engine::Facts;
use snitchhiker_core::pattern::{Pattern, PatternSource};
use snitchhiker_core::proposal::{self, Observation, Proposed, Risk};
use snitchhiker_core::rule::{
    Action, Condition, ContextKind, Expiry, Folder, FolderId, ProcessRef, Rule, Tier,
};
use snitchhiker_core::spec::Conditions;
use snitchhiker_proto::{convert, v1};

use crate::peer::Peer;
use crate::store::{Batch, Error as StoreError, Store};

/// How long refused connections are remembered.
const WINDOW_MS: u64 = 3_600_000;
/// Refused connections remembered, at most.
const CAPACITY: usize = 4096;
/// Limits on what an agent sends.
pub const MAX_JUSTIFICATION: usize = 2000;
pub const MAX_RULES: usize = 16;
pub const MAX_PENDING: usize = 10;
pub const MAX_NOTE: usize = 500;
/// The folder agents' rules go in.
pub const AGENTS: &str = "Agents";

/// A connection the node didn't allow, with the processes it came from.
#[derive(Debug, Clone)]
pub struct Blocked {
    pub time_ms: u64,
    /// The process and its ancestors, nearest first.
    pub lineage: Vec<ProcessRef>,
    pub exe: Arc<str>,
    pub host: Option<String>,
    pub address: IpAddr,
    pub port: u16,
    pub protocol: u8,
    pub uid: u32,
    pub context: ContextKind,
    /// The prompt it waits on (or waited on); none: a rule or the policy refused it.
    pub prompt: Option<u64>,
}

/// The refused connections of the last hour.
#[derive(Default)]
pub struct Ring {
    entries: Mutex<VecDeque<Blocked>>,
}

impl Ring {
    pub fn record(&self, blocked: Blocked) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let cutoff = blocked.time_ms.saturating_sub(WINDOW_MS);
        while entries
            .front()
            .is_some_and(|e| e.time_ms < cutoff || entries.len() >= CAPACITY)
        {
            entries.pop_front();
        }
        entries.push_back(blocked);
    }

    /// The refused connections of `agent`'s tree since `since_ms`.
    #[must_use]
    pub fn of(&self, agent: ProcessRef, now_ms: u64) -> Vec<Blocked> {
        let cutoff = now_ms.saturating_sub(WINDOW_MS);
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|e| e.time_ms >= cutoff && e.lineage.contains(&agent))
            .cloned()
            .collect()
    }
}

/// The agent behind a connection to the agent socket, as the kernel says.
#[derive(Debug, Clone)]
pub struct Agent {
    pub anchor: ProcessRef,
    pub provenance: v1::Provenance,
}

/// Who the agent behind the MCP server `server` is: its parent, a process of the same user. `programs` are the
/// node's `agent_programs`: when there are any, only those may propose.
pub fn identify(server: &Peer, programs: &[String]) -> Result<Agent, String> {
    let pid = crate::process::parent(server.pid).ok_or("the MCP server has no parent")?;
    let start = crate::process::start_time(pid).ok_or("the MCP server's parent exited")?;
    if pid <= 1 {
        return Err("the MCP server's parent exited".to_owned());
    }
    let status = fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|uid| uid.parse::<u32>().ok());
    if uid != Some(server.uid) {
        return Err("the MCP server's parent is another user's process".to_owned());
    }
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| e.to_string())?;
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).map_or_else(
        |_| String::new(),
        |bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(String::from_utf8_lossy)
                .collect::<Vec<_>>()
                .join(" ")
        },
    );
    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .map_or_else(|_| String::new(), |p| p.to_string_lossy().into_owned());
    let session = fs::read_to_string(format!("/proc/{pid}/sessionid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(u32::MAX);
    let (ancestors, _) = crate::process::lineage(pid);
    // Everything read was the process that started then: a pid reused meanwhile is caught here.
    if crate::process::start_time(pid) != Some(start) {
        return Err("the MCP server's parent exited".to_owned());
    }
    let home = crate::process::home_of(uid.unwrap_or(u32::MAX));
    let known_agent = !programs.is_empty()
        && programs.iter().any(|p| {
            Pattern::compile(&pattern(p))
                .is_ok_and(|pattern| pattern.matches(&exe, home.as_deref()))
        });
    if !programs.is_empty() && !known_agent {
        return Err(format!("{exe} isn't one of the node's agent programs"));
    }
    Ok(Agent {
        anchor: ProcessRef { pid, start },
        provenance: v1::Provenance {
            uid: server.uid,
            user: crate::process::user_of(server.uid).unwrap_or_default(),
            agent_pid: pid,
            agent_start: start,
            agent_exe: exe,
            agent_cmdline: truncate(&cmdline, 1000),
            cwd,
            session,
            ancestors,
            server_pid: server.pid,
            server_exe: server.exe.to_string_lossy().into_owned(),
            known_agent,
        },
    })
}

fn pattern(text: &str) -> PatternSource {
    if let Some(glob) = text.strip_prefix("glob:") {
        PatternSource::Glob(glob.to_owned())
    } else if let Some(regex) = text.strip_prefix("re:") {
        PatternSource::Regex(regex.to_owned())
    } else {
        PatternSource::Exact(text.to_owned())
    }
}

fn truncate(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

/// The agents whose session rules or waiting proposals end with them, each held by a pidfd: it becomes readable when
/// the process exits, so nothing is polled.
pub struct Watch {
    agents: Mutex<HashMap<ProcessRef, Arc<std::os::fd::OwnedFd>>>,
    wake_reader: std::io::PipeReader,
    wake: Mutex<std::io::PipeWriter>,
}

impl Watch {
    pub fn new() -> std::io::Result<Self> {
        let (wake_reader, wake) = std::io::pipe()?;
        Ok(Self {
            agents: Mutex::new(HashMap::new()),
            wake_reader,
            wake: Mutex::new(wake),
        })
    }

    /// Watches `agent`; false when it has ended already.
    pub fn add(&self, agent: ProcessRef) -> bool {
        use std::io::Write as _;
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        if agents.contains_key(&agent) {
            return true;
        }
        let pidfd = rustix::process::Pid::from_raw(i32::try_from(agent.pid).unwrap_or(-1))
            .and_then(|pid| {
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()
            });
        // The pid held is the agent's only if it still started when the agent did.
        let Some(pidfd) = pidfd.filter(|_| alive(agent)) else {
            return false;
        };
        agents.insert(agent, Arc::new(pidfd));
        drop(agents);
        let _ = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(&[1]);
        true
    }

    /// Waits until agents end (or the list changes); the agents that ended, no longer watched.
    pub fn wait(&self) -> Vec<ProcessRef> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::io::Read as _;
        use std::os::fd::AsFd as _;
        let watched: Vec<(ProcessRef, Arc<std::os::fd::OwnedFd>)> = self
            .agents
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(agent, fd)| (*agent, Arc::clone(fd)))
            .collect();
        let mut fds: Vec<PollFd<'_>> =
            std::iter::once(PollFd::new(self.wake_reader.as_fd(), PollFlags::POLLIN))
                .chain(
                    watched
                        .iter()
                        .map(|(_, fd)| PollFd::new(fd.as_fd(), PollFlags::POLLIN)),
                )
                .collect();
        if poll(&mut fds, PollTimeout::NONE).is_err() {
            return Vec::new();
        }
        let ready = |fd: &PollFd<'_>| fd.revents().is_some_and(|r| !r.is_empty());
        if fds.first().is_some_and(ready) {
            let _ = (&self.wake_reader).read(&mut [0; 64]);
        }
        let ended: Vec<ProcessRef> = watched
            .iter()
            .zip(fds.iter().skip(1))
            .filter(|(_, fd)| ready(fd))
            .map(|((agent, _), _)| *agent)
            .collect();
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        for agent in &ended {
            agents.remove(agent);
        }
        ended
    }
}

/// Whether the process still runs (the same one: pid and start time).
#[must_use]
pub fn alive(process: ProcessRef) -> bool {
    crate::process::start_time(process.pid) == Some(process.start)
}

/// Refused connections, grouped (program, destination, port, protocol, outcome), most recent first. `waiting` says
/// whether a prompt still waits.
#[must_use]
pub fn summarize(blocked: &[Blocked], waiting: &dyn Fn(u64) -> bool) -> Vec<v1::BlockedConnection> {
    let mut groups: HashMap<(Arc<str>, String, u16, u8, bool), v1::BlockedConnection> =
        HashMap::new();
    for b in blocked {
        let destination = b.host.clone().unwrap_or_else(|| b.address.to_string());
        let key = (
            Arc::clone(&b.exe),
            destination,
            b.port,
            b.protocol,
            b.prompt.is_some(),
        );
        let entry = groups.entry(key).or_insert_with(|| v1::BlockedConnection {
            exe: b.exe.to_string(),
            host: b.host.clone().unwrap_or_default(),
            address: convert::address(b.address),
            port: u32::from(b.port),
            protocol: u32::from(b.protocol),
            context: convert::context(b.context).into(),
            outcome: if b.prompt.is_some() {
                v1::BlockedOutcome::Asked
            } else {
                v1::BlockedOutcome::Denied
            }
            .into(),
            ..v1::BlockedConnection::default()
        });
        entry.count += 1;
        if b.time_ms >= entry.last_ms {
            entry.last_ms = b.time_ms;
            entry.prompt = b.prompt.filter(|&id| waiting(id));
        }
    }
    let mut list: Vec<_> = groups.into_values().collect();
    list.sort_by_key(|b| std::cmp::Reverse(b.last_ms));
    list
}

fn observation(b: &Blocked) -> Observation {
    Observation {
        exe: b.exe.to_string(),
        host: b.host.clone(),
        address: b.address,
        port: b.port,
    }
}

fn risk(r: &Risk) -> v1::Risk {
    let kind = match r {
        Risk::AnyHost => "any_host",
        Risk::PublicSuffix(_) => "public_suffix",
        Risk::AnyProgram => "any_program",
        Risk::AnyPort => "any_port",
        Risk::WideNetwork(_) => "wide_network",
        Risk::SensitiveAlias(_) => "sensitive_alias",
        Risk::WritableBinary(_) => "writable_binary",
        Risk::Speculative => "speculative",
    };
    v1::Risk {
        kind: kind.to_owned(),
        description: r.describe(),
    }
}

/// What a rule proposed on the wire is, for shaping.
#[must_use]
pub fn proposed(rule: &v1::ProposedRule) -> Proposed {
    Proposed {
        exe: rule.exe.clone(),
        hosts: rule.hosts.clone(),
        ports: rule.ports.clone(),
        protocol: rule.protocol.clone(),
        context: convert::context_from(rule.context()),
    }
}

/// Edited conditions, as a proposal again (so they are shaped, and their risks known, the same way).
#[must_use]
pub fn proposed_from(conditions: &v1::Conditions) -> Proposed {
    Proposed {
        exe: conditions.exe.first().cloned().unwrap_or_default(),
        hosts: conditions
            .host
            .iter()
            .chain(&conditions.net)
            .cloned()
            .collect(),
        ports: conditions.port.clone(),
        protocol: conditions.protocol.first().cloned().unwrap_or_default(),
        context: convert::context_from(conditions.context()),
    }
}

/// Shapes one proposed rule against the agent's refused connections: its conditions, risks and evidence.
/// `allowed` tells whether today's rules let a refused connection through already.
pub fn shape(
    proposed: &Proposed,
    blocked: &[Blocked],
    waiting: &dyn Fn(u64) -> bool,
    allowed: &dyn Fn(&Blocked, &Conditions) -> bool,
) -> Result<v1::ShapedRule, proposal::Refusal> {
    let observed: Vec<Observation> = blocked.iter().map(observation).collect();
    let shaped = proposal::shape(
        proposed,
        &observed,
        &crate::process::writable_by_others_path,
    )?;
    let exe = shaped.conditions.exe.first().cloned().unwrap_or_default();
    let evidence: Vec<Blocked> = blocked
        .iter()
        .filter(|b| proposal::grounds(&observation(b), &shaped.conditions, &exe))
        .cloned()
        .collect();
    let already_allowed =
        !evidence.is_empty() && evidence.iter().all(|b| allowed(b, &shaped.conditions));
    Ok(v1::ShapedRule {
        conditions: Some(convert::conditions(&shaped.conditions)),
        risks: shaped.risks.iter().map(risk).collect(),
        evidence: summarize(&evidence, waiting),
        already_allowed,
        included: false,
    })
}

/// Facts for a refused connection, to decide it again by today's rules.
#[must_use]
pub fn decide_again(rules: &snitchhiker_core::engine::RuleSet, b: &Blocked, now_ms: u64) -> bool {
    let hosts: Vec<Arc<str>> = b.host.iter().map(|h| Arc::from(h.as_str())).collect();
    let home = crate::process::home_of(b.uid);
    let facts = Facts {
        exe: &b.exe,
        apps: &[],
        cmdline: "",
        ancestors: &[],
        lineage: &b.lineage,
        uid: b.uid,
        home: home.as_deref(),
        hosts: &hosts,
        address: b.address,
        port: b.port,
        protocol: b.protocol,
        context: b.context,
        now_ms,
        container: None,
        vm: None,
        netns: None,
    };
    rules
        .decide(&facts)
        .is_some_and(|d| d.action == Action::Allow)
}

/// A short name for a rule made from a proposal: the program and where to.
#[must_use]
pub fn rule_name(conditions: &Conditions) -> String {
    let program = conditions
        .exe
        .first()
        .and_then(|e| e.rsplit('/').next())
        .unwrap_or("any program");
    let mut to: Vec<&str> = conditions
        .host
        .iter()
        .chain(&conditions.net)
        .map(String::as_str)
        .collect();
    if to.len() > 3 {
        to.truncate(3);
        to.push("…");
    }
    let mut name = if to.is_empty() {
        program.to_owned()
    } else {
        format!("{program} → {}", to.join(", "))
    };
    if !conditions.port.is_empty() {
        name.push_str(" :");
        name.push_str(&conditions.port.join(","));
    }
    name
}

/// The folder for an agent's rules: `Agents/<agent>/<project>`, made in `batch` where missing.
pub fn folder(
    store: &Store,
    batch: &Batch,
    provenance: &v1::Provenance,
) -> Result<FolderId, StoreError> {
    let agent = provenance
        .agent_exe
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("agent");
    let project = provenance
        .cwd
        .rsplit('/')
        .find(|n| !n.is_empty())
        .unwrap_or("/");
    let mut parent: Option<FolderId> = None;
    for name in [AGENTS, agent, project] {
        let folders = store.folders()?;
        let found = folders
            .iter()
            .find(|f| f.parent == parent && f.name == name && f.scope.is_empty())
            .map(|f| f.id)
            .filter(|id| id & crate::managed::MANAGED_ID == 0);
        parent = Some(match found {
            Some(id) => id,
            None => store.put_folder(
                &Folder {
                    id: 0,
                    parent,
                    name: name.to_owned(),
                    enabled: true,
                    scope: Vec::new(),
                },
                batch,
            )?,
        });
    }
    Ok(parent.unwrap_or(0))
}

/// A rule from an approved proposal's rule.
pub fn rule(
    conditions: &Conditions,
    folder: FolderId,
    duration: v1::ProposalDuration,
    agent: ProcessRef,
    proposal: u64,
    now_ms: u64,
) -> Result<Rule, snitchhiker_core::spec::SpecError> {
    let mut conditions_model = conditions.to_conditions()?;
    let expiry = match duration {
        v1::ProposalDuration::Hour => Expiry::At(now_ms + 3_600_000),
        v1::ProposalDuration::TwelveHours => Expiry::At(now_ms + 12 * 3_600_000),
        v1::ProposalDuration::Forever => Expiry::Never,
        v1::ProposalDuration::Session | v1::ProposalDuration::Unspecified => {
            conditions_model.push(Condition::Session(vec![agent]));
            Expiry::Never
        }
    };
    Ok(Rule {
        id: 0,
        folder: Some(folder),
        name: rule_name(conditions),
        enabled: true,
        action: Action::Allow,
        tier: Tier::Normal,
        expiry,
        log: true,
        notes: format!("From agent proposal {proposal}."),
        conditions: conditions_model,
    })
}

/// The agents (pid@start) a rule is limited to, if it is a session's.
#[must_use]
pub fn sessions(rule: &Rule) -> Option<&[ProcessRef]> {
    rule.conditions.iter().find_map(|c| match c {
        Condition::Session(roots) => Some(roots.as_slice()),
        _ => None,
    })
}

/// An envelope as clients send it.
#[must_use]
pub fn envelope_from(wire: &v1::Envelope) -> snitchhiker_core::envelope::Envelope {
    snitchhiker_core::envelope::Envelope {
        id: wire.id,
        name: wire.name.trim().to_owned(),
        enabled: wire.enabled,
        project: wire.project.trim().to_owned(),
        agents: wire.agents.clone(),
        programs: wire.programs.clone(),
        hosts: wire.hosts.clone(),
        ports: wire.ports.clone(),
    }
}

/// An envelope as clients see it.
#[must_use]
pub fn envelope_wire(envelope: &snitchhiker_core::envelope::Envelope) -> v1::Envelope {
    v1::Envelope {
        id: envelope.id,
        name: envelope.name.clone(),
        enabled: envelope.enabled,
        project: envelope.project.clone(),
        agents: envelope.agents.clone(),
        programs: envelope.programs.clone(),
        hosts: envelope.hosts.clone(),
        ports: envelope.ports.clone(),
    }
}
