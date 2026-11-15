//! The running daemon: the table, the attribution programs, one deciding thread per queue, and the writer.
//!
//! The packet path: receive → parse the headers → look the flow's owner up (eBPF) → the process's facts (cached) →
//! the rules (an immutable set, swapped atomically on change) → verdict, and an event to the writer's queue. Nothing
//! on it waits for the database, and a full event queue drops the event (counted), never the verdict.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use snitchhiker_core::engine::{Facts, RuleSet};
use snitchhiker_core::rule::{Action, Condition, ContextKind};
use snitchhiker_ebpf::{Attribution, FlowKey};
use snitchhiker_netfilter::netlink::{Socket, Writer};
use snitchhiker_netfilter::nftables::{Table, encode_install, encode_remove};
use snitchhiker_netfilter::packet;
use snitchhiker_netfilter::queue::{Packet, Queue, Verdict};
use snitchhiker_netfilter::sockdiag::{SockDiag, SocketId};
use tracing::{error, info, warn};

use crate::hub::Outgoing;
use snitchhiker_core::rule::{Expiry, FolderId, Rule, RuleId, Tier};
use snitchhiker_proto::columns::{self, EventRow};
use snitchhiker_proto::{convert, v1};

use crate::config::{Config, Fail, Mode, Policy};
use crate::dns::{Names, parse_answer};
use crate::hub::Hub;
use crate::process::{HostNamespaces, ProcessCache};
use crate::prompts::{Broker, Held, Hold, NewPrompt, Pending, PromptKey};
use crate::store::{Event, Source, Store};

/// Events waiting for the writer; beyond this they are dropped (and counted).
const EVENT_QUEUE: usize = 65_536;
/// Events written per transaction at most.
const BATCH: usize = 1024;
/// How long the writer waits to fill a batch.
const BATCH_WAIT: Duration = Duration::from_millis(100);
/// How much of a DNS answer is copied: a whole UDP answer, as large as resolvers send without EDNS tricks.
const DNS_COPY: u32 = 4096;
const DNS_PORT: u16 = 53;
/// How often byte counts are written to the history.
const BYTES_EVERY: Duration = Duration::from_secs(5);
/// How often old history is pruned, and how many rows per chunk.
const PRUNE_EVERY: Duration = Duration::from_secs(600);
const PRUNE_CHUNK: u32 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("eBPF: {0}")]
    Ebpf(#[from] snitchhiker_ebpf::Error),
    #[error("store: {0}")]
    Store(#[from] crate::store::Error),
    #[error("rules: {0}")]
    Rules(#[from] snitchhiker_core::engine::CompileError),
    #[error("managed rules: {0}")]
    Managed(#[from] crate::managed::Error),
}

/// Why an answer to a prompt was refused.
#[derive(Debug, thiserror::Error)]
pub enum AnswerError {
    #[error("no such prompt (answered already, or timed out)")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Runtime(#[from] Error),
}

fn placement_error(error: crate::placement::Error) -> AnswerError {
    match error {
        crate::placement::Error::Store(e) => AnswerError::Runtime(Error::from(e)),
        other => AnswerError::Invalid(other.to_string()),
    }
}

/// What the deciding threads share.
pub struct Shared {
    pub config: Config,
    pub rules: ArcSwap<RuleSet>,
    attribution: Attribution,
    names: RwLock<Names>,
    netns: u32,
    host: HostNamespaces,
    events: SyncSender<Event>,
    pub dropped_events: AtomicU64,
    /// The executable recorded for connections whose process isn't known.
    unknown: Arc<str>,
    pub decided: AtomicU64,
    pub hub: Arc<Hub>,
    pub broker: Broker,
}

/// The daemon, running. Shared by the signal handler and the API's threads.
pub struct Daemon {
    pub shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
    table: Table,
}

impl Daemon {
    /// Opens the store, compiles the rules, installs the table, loads the attribution programs and starts the
    /// deciding threads and the writer.
    pub fn start(config: Config) -> Result<Arc<Self>, Error> {
        if let Some(parent) = config.database.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store = Store::open(&config.database)?;
        let rules = compile(&config, &store)?;
        info!(rules = rules.len(), "rules loaded");
        // The programs first: from the moment the table is in place, every new flow's owner must be known.
        let attribution = Attribution::load()?;
        let table = Table {
            queue: config.queue,
            queues: config.queues,
            bypass: config.fail == Fail::Open,
            dns_queue: config.dns_queue(),
            ..Table::default()
        };
        install(&table)?;
        info!(queues = config.queues, mode = ?config.mode, "table installed");

        // Until-restart rules from before don't apply any more.
        let mut store = store;
        store.delete_until_restart()?;
        let (sender, receiver) = sync_channel(EVENT_QUEUE);
        let store = Arc::new(Mutex::new(store));
        let mut queues = Vec::with_capacity(usize::from(config.queues));
        let mut writers = Vec::with_capacity(usize::from(config.queues));
        for offset in 0..config.queues {
            let queue = Queue::bind(config.queue + offset)?;
            writers.push(queue.verdict_writer()?);
            queues.push(queue);
        }
        let broker = Broker::new(writers, Duration::from_secs(config.prompt_timeout_secs));
        let shared = Arc::new(Shared {
            rules: ArcSwap::from_pointee(rules),
            attribution,
            names: RwLock::new(Names::default()),
            netns: u32::try_from(std::fs::metadata("/proc/self/ns/net")?.ino()).unwrap_or(0),
            host: HostNamespaces::read()?,
            events: sender,
            dropped_events: AtomicU64::new(0),
            unknown: Arc::from(""),
            decided: AtomicU64::new(0),
            hub: Arc::new(Hub::default()),
            broker,
            config,
        });
        for (offset, queue) in queues.into_iter().enumerate() {
            let number = queue.number();
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name(format!("queue-{number}"))
                .spawn(move || {
                    if let Err(error) = decide_loop(&shared, queue, offset) {
                        error!(%error, queue = number, "deciding thread stopped");
                    }
                })?;
        }
        if let Some(number) = shared.config.dns_queue() {
            let queue = Queue::bind_copying(number, DNS_COPY)?;
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("dns".to_owned())
                .spawn(move || {
                    if let Err(error) = dns_loop(&shared, queue) {
                        error!(%error, "learning names stopped");
                    }
                })?;
        }
        {
            let store = Arc::clone(&store);
            let shared = Arc::clone(&shared);
            let retention = Duration::from_secs(u64::from(shared.config.retention_days) * 86_400);
            thread::Builder::new()
                .name("writer".to_owned())
                .spawn(move || write_loop(&shared, &store, &receiver, retention))?;
        }
        let daemon = Arc::new(Self {
            shared,
            store,
            table,
        });
        {
            let daemon = Arc::clone(&daemon);
            thread::Builder::new()
                .name("prompt-timeouts".to_owned())
                .spawn(move || {
                    loop {
                        for pending in daemon.shared.broker.wait_expired() {
                            let action = daemon.shared.config.on_timeout;
                            daemon.resolve(&pending, action, Source::Timeout, None, "", true);
                        }
                    }
                })?;
        }
        Ok(daemon)
    }

    /// The daemon's version, with the suffix of development builds.
    #[must_use]
    pub fn version(&self) -> &'static str {
        option_env!("SNITCHHIKER_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
    }

    /// The store, for the API's reads and writes.
    pub fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The live TCP connections and connected UDP sockets, each with its program as the attribution programs
    /// recorded it when it opened (unknown for inbound sockets, and for ones older than the daemon).
    pub fn connections(&self) -> std::io::Result<Vec<v1::LiveConnection>> {
        let sockets = SockDiag::open()?.list()?;
        let bytes: HashMap<u64, (u64, u64)> = self
            .shared
            .attribution
            .socket_bytes()
            .map(|(cookie, sent, read)| (cookie, (sent, read)))
            .collect();
        let mut processes = ProcessCache::new(self.shared.host);
        let names = self
            .shared
            .names
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let now = now_ms();
        let plain = |address: std::net::IpAddr| match address {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, std::net::IpAddr::V4),
            v4 @ std::net::IpAddr::V4(_) => v4,
        };
        Ok(sockets
            .iter()
            .map(|socket| {
                let remote = plain(socket.id.remote);
                let key = FlowKey {
                    netns: self.shared.netns,
                    protocol: socket.id.protocol,
                    source_port: socket.id.local_port,
                    destination: remote,
                    destination_port: socket.id.remote_port,
                };
                let owner = self.shared.attribution.owner(&key);
                let process = owner.and_then(|o| processes.get(o.pid, o.start_boottime));
                let pid = owner.map_or(0, |o| o.pid);
                let (sent, read) = bytes.get(&socket.cookie).copied().unwrap_or_default();
                v1::LiveConnection {
                    protocol: u32::from(socket.id.protocol),
                    local: convert::address(plain(socket.id.local)),
                    local_port: u32::from(socket.id.local_port),
                    remote: convert::address(remote),
                    remote_port: u32::from(socket.id.remote_port),
                    state: snitchhiker_netfilter::sockdiag::state_name(
                        socket.id.protocol,
                        socket.state,
                    )
                    .to_owned(),
                    uid: owner.map_or(socket.uid, |o| o.uid),
                    pid,
                    exe: process
                        .as_ref()
                        .map_or_else(String::new, |p| p.exe.to_string()),
                    host: names
                        .lookup(pid, remote, now)
                        .first()
                        .map_or_else(String::new, ToString::to_string),
                    bytes_out: sent,
                    bytes_in: read,
                    context: convert::context(
                        process.as_ref().map_or(ContextKind::Host, |p| p.context),
                    )
                    .into(),
                }
            })
            .collect())
    }

    /// Why the recorded connection `seq` is decided as it is, by today's rules; `None` if there is no such event.
    pub fn explain(&self, seq: i64) -> Result<Option<v1::Explanation>, Error> {
        let Some(stored) = self.store().event(seq)? else {
            return Ok(None);
        };
        let rules = self.shared.rules.load();
        let hosts: Vec<Arc<str>> = stored.host.iter().map(|h| Arc::from(h.as_str())).collect();
        let home = crate::process::home_of(stored.uid);
        let facts = Facts {
            exe: &stored.exe,
            apps: &[],
            cmdline: "",
            ancestors: &[],
            uid: stored.uid,
            home: home.as_deref(),
            hosts: &hosts,
            address: stored.address,
            port: stored.port,
            protocol: stored.protocol,
            context: match stored.context {
                1 => ContextKind::Container,
                2 => ContextKind::Vm,
                3 => ContextKind::Netns,
                _ => ContextKind::Host,
            },
            now_ms: now_ms(),
        };
        let matches = rules.explain(&facts);
        // Names and whether a match depends on what the history doesn't keep.
        let store = self.store();
        let managed = crate::managed::Managed::load(
            self.shared.config.default_rules,
            &self.shared.config.rules_dir,
        )
        .map_err(Error::from)?;
        // Rules on command lines or parents can't be checked against the history: their absence from the matches says
        // nothing.
        let needs_more = |r: &Rule| {
            r.enabled
                && r.conditions
                    .iter()
                    .any(|c| matches!(c, Condition::Cmdline(_) | Condition::Parent(_)))
        };
        let partial = store.rules()?.iter().any(needs_more) || managed.rules.iter().any(needs_more);
        let mut explained = Vec::new();
        for m in &matches {
            let rule = match store.rule(m.rule)? {
                Some(rule) => Some(rule),
                None => managed.rules.iter().find(|r| r.id == m.rule).cloned(),
            };
            explained.push(v1::ExplainedRule {
                id: m.rule,
                name: rule.map_or_else(String::new, |r| r.name),
                action: convert::action(m.action).into(),
                tier: convert::tier(m.tier).into(),
                specificity: m.specificity,
            });
        }
        Ok(Some(v1::Explanation {
            event: Some(crate::api::event(&stored)),
            rules: explained,
            partial,
        }))
    }

    /// Closes a live socket (as `reject` does): its program's next call fails with `ECONNABORTED`.
    pub fn kill(&self, id: &SocketId) -> std::io::Result<()> {
        SockDiag::open()?.destroy(id)
    }

    /// Answers a prompt: makes a rule of the chosen suggestion (or `conditions`) unless `duration` is once, then
    /// decides every connection waiting on it. Returns the rule made, if any.
    pub fn answer_prompt(
        &self,
        id: u64,
        action: Action,
        duration: v1::Duration,
        suggestion: usize,
        conditions: Option<&v1::Conditions>,
        folder: Option<FolderId>,
        by: &str,
    ) -> Result<Option<RuleId>, AnswerError> {
        let now = now_ms();
        let expiry = match duration {
            v1::Duration::Once => None,
            v1::Duration::UntilRestart => Some(Expiry::UntilRestart),
            v1::Duration::Hour => Some(Expiry::At(now + 3_600_000)),
            v1::Duration::HalfDay => Some(Expiry::At(now + 43_200_000)),
            v1::Duration::Forever | v1::Duration::Unspecified => Some(Expiry::Never),
        };
        // The rule is checked before the prompt is taken: a refused answer leaves it waiting.
        let rule = match expiry {
            None => None,
            Some(expiry) => Some(
                self.shared
                    .broker
                    .peek(id, |pending| -> Result<(Rule, String), AnswerError> {
                        let (label, spec) = match conditions {
                            Some(conditions) => (
                                "Answer to a prompt".to_owned(),
                                convert::conditions_from(conditions),
                            ),
                            None => pending
                                .suggestions
                                .get(suggestion)
                                .map(|s| (s.label.clone(), s.conditions.clone()))
                                .ok_or_else(|| {
                                    AnswerError::Invalid(format!("no suggestion {suggestion}"))
                                })?,
                        };
                        let conditions = spec
                            .to_conditions()
                            .map_err(|e| AnswerError::Invalid(e.to_string()))?;
                        if conditions.is_empty() {
                            return Err(AnswerError::Invalid(
                                "the answer's rule has no conditions".to_owned(),
                            ));
                        }
                        let program = pending
                            .prompt
                            .exe
                            .rsplit('/')
                            .next()
                            .unwrap_or_default()
                            .to_owned();
                        let rule = Rule {
                            id: 0,
                            folder: None,
                            name: label,
                            enabled: true,
                            action,
                            tier: Tier::Normal,
                            expiry,
                            log: true,
                            notes: String::new(),
                            conditions,
                        };
                        Ok((rule, program))
                    })
                    .ok_or(AnswerError::NotFound)??,
            ),
        };
        // Into the chosen folder, or the program's own.
        let rule = match rule {
            Some((rule, program)) => {
                // A folder the rule can't go in leaves the prompt waiting.
                crate::placement::check(&self.store(), folder).map_err(placement_error)?;
                Some((rule, program))
            }
            None => None,
        };
        let pending = self.shared.broker.take(id).ok_or(AnswerError::NotFound)?;
        let rule_id = match rule {
            Some((mut rule, program)) => {
                let id = {
                    let mut store = self.store();
                    let batch = store.batch(by, now).map_err(Error::from)?;
                    store
                        .atomically(|store| {
                            crate::placement::place(store, &batch, &mut rule, folder, &program)?;
                            Ok(store.put_rule(&rule, &batch)?)
                        })
                        .map_err(placement_error)?
                };
                self.reload_rules()?;
                Some(id)
            }
            None => None,
        };
        self.resolve(&pending, action, Source::Prompt, rule_id, by, false);
        Ok(rule_id)
    }

    /// Decides a prompt's connections, records the decision, and tells the clients.
    fn resolve(
        &self,
        pending: &Pending,
        action: Action,
        source: Source,
        rule: Option<RuleId>,
        by: &str,
        timed_out: bool,
    ) {
        let verdict = if action == Action::Allow {
            Verdict::Accept
        } else {
            Verdict::Drop
        };
        self.shared.broker.release(pending, verdict);
        let mut event = pending.event.clone();
        event.time_ms = now_ms();
        event.action = action;
        event.source = source;
        event.rule = rule;
        if self.shared.events.try_send(event).is_err() {
            self.shared.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
        self.shared.hub.publish(
            v1::Topic::Prompts,
            &v1::notice::Body::PromptResolved(v1::PromptResolved {
                id: pending.prompt.id,
                action: convert::action(action).into(),
                by: by.to_owned(),
                rule,
                timed_out,
            }),
        );
    }

    /// Reads the rules again and swaps them in.
    pub fn reload_rules(&self) -> Result<usize, Error> {
        let rules = {
            let store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
            compile(&self.shared.config, &store)?
        };
        let count = rules.len();
        self.shared.rules.store(Arc::new(rules));
        self.shared.hub.publish(
            v1::Topic::Rules,
            &v1::notice::Body::RulesChanged(v1::RulesChanged {}),
        );
        Ok(count)
    }

    /// Stops: with `fail = open` the table is removed, so traffic flows freely; with `fail = closed` it stays, so
    /// nothing new gets out until the daemon is back.
    pub fn stop(&self) {
        if self.shared.config.fail == Fail::Open
            && let Err(error) = remove(&self.table.name)
        {
            warn!(%error, "removing the table");
        }
        info!(
            decided = self.shared.decided.load(Ordering::Relaxed),
            dropped_events = self.shared.dropped_events.load(Ordering::Relaxed),
            "stopped"
        );
    }
}

/// The rules in effect: the stored ones, the System folder and the managed files.
fn compile(config: &Config, store: &Store) -> Result<RuleSet, Error> {
    let managed = crate::managed::Managed::load(config.default_rules, &config.rules_dir)?;
    let mut folders = store.folders()?;
    folders.extend(managed.folders);
    let mut rules = store.rules()?;
    rules.extend(managed.rules);
    Ok(RuleSet::compile(&folders, &rules)?)
}

fn install(table: &Table) -> std::io::Result<()> {
    let mut socket = Socket::open()?;
    let mut writer = Writer::new();
    let batch = encode_install(&mut writer, table, 1);
    socket.transact(&writer, batch.first, batch.last)
}

fn remove(name: &str) -> std::io::Result<()> {
    let mut socket = Socket::open()?;
    let mut writer = Writer::new();
    let batch = encode_remove(&mut writer, name, 1);
    socket.transact(&writer, batch.first, batch.last)
}

/// Learns names from DNS answers: only those to sockets that sent a query to that resolver, and remembered for the
/// process that sent it. Every packet passes; this queue only observes.
fn dns_loop(shared: &Shared, mut queue: Queue) -> Result<(), Error> {
    let mut ids: Vec<u32> = Vec::with_capacity(64);
    loop {
        ids.clear();
        for queued in queue.receive()? {
            ids.push(queued.id);
            let Some(headers) = packet::parse(queued.payload) else {
                continue;
            };
            let Some(answer) = packet::udp_payload(queued.payload, &headers).and_then(parse_answer)
            else {
                continue;
            };
            let query = FlowKey {
                netns: shared.netns,
                protocol: packet::IPPROTO_UDP,
                source_port: headers.destination_port,
                destination: headers.source,
                destination_port: DNS_PORT,
            };
            // An answer nobody asked for teaches nothing.
            let Some(asker) = shared.attribution.owner(&query) else {
                continue;
            };
            shared
                .names
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .learn(asker.pid, &answer, now_ms());
        }
        for &id in &ids {
            queue.verdict(id, Verdict::Accept)?;
        }
    }
}

fn decide_loop(shared: &Shared, mut queue: Queue, offset: usize) -> Result<(), Error> {
    let mut processes = ProcessCache::new(shared.host);
    let mut verdicts: Vec<(u32, Verdict)> = Vec::with_capacity(64);
    let mut rejected: Vec<SocketId> = Vec::with_capacity(8);
    let mut sockdiag: Option<SockDiag> = None;
    loop {
        verdicts.clear();
        rejected.clear();
        for packet in queue.receive()? {
            let (verdict, reject) = decide(shared, &mut processes, &packet, offset);
            // No verdict: the packet waits for a prompt's answer.
            if let Some(verdict) = verdict {
                verdicts.push((packet.id, verdict));
            }
            rejected.extend(reject);
        }
        for &(id, verdict) in &verdicts {
            queue.verdict(id, verdict)?;
        }
        // After the drop: the program's socket is closed, so it fails at once instead of retrying.
        for id in &rejected {
            if sockdiag.is_none() {
                sockdiag = SockDiag::open()
                    .inspect_err(|error| warn!(%error, "sock_diag: rejected connections will time out instead"))
                    .ok();
            }
            if let Some(diag) = sockdiag.as_mut()
                && let Err(error) = diag.destroy(id)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(%error, "closing a rejected socket");
            }
        }
    }
}

/// Unix time in milliseconds.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn context_code(context: ContextKind) -> u8 {
    match context {
        ContextKind::Host | ContextKind::Any => 0,
        ContextKind::Container => 1,
        ContextKind::Vm => 2,
        ContextKind::Netns => 3,
    }
}

/// The history's record of a connection, before it is decided.
fn undecided_event(facts: &Facts<'_>, exe: Arc<str>, pid: u32, cookie: Option<u64>) -> Event {
    Event {
        time_ms: facts.now_ms,
        exe,
        host: facts.hosts.first().cloned(),
        uid: facts.uid,
        pid,
        protocol: facts.protocol,
        address: facts.address,
        port: facts.port,
        context: context_code(facts.context),
        action: Action::Deny,
        source: Source::Policy,
        rule: None,
        cookie,
    }
}

/// Whether a connection no rule decides is held for a prompt: the policy asks, the daemon enforces, and some client
/// listens for prompts.
fn asks(shared: &Shared) -> bool {
    shared.config.no_match == Policy::Ask
        && shared.config.mode == Mode::Enforce
        && shared.hub.has_subscribers(v1::Topic::Prompts)
}

/// What a policy does without asking (`ask` falls back to `no_client`).
fn policy_action(policy: Policy, no_client: Action) -> Action {
    match policy {
        Policy::Allow => Action::Allow,
        Policy::Deny => Action::Deny,
        Policy::Reject => Action::Reject,
        Policy::Ask => no_client,
    }
}

/// The verdict for one packet (none: it is held for a prompt), recording what happened, and the socket to close for a
/// rejected connection.
fn decide(
    shared: &Shared,
    processes: &mut ProcessCache,
    queued: &Packet<'_>,
    queue: usize,
) -> (Option<Verdict>, Option<SocketId>) {
    shared.decided.fetch_add(1, Ordering::Relaxed);
    let Some(headers) = packet::parse(queued.payload) else {
        // Not IPv4 or IPv6: nothing rules speak about.
        return (Some(Verdict::Accept), None);
    };
    let key = FlowKey {
        netns: shared.netns,
        protocol: headers.protocol,
        source_port: headers.source_port,
        destination: headers.destination,
        destination_port: headers.destination_port,
    };
    let owner = shared.attribution.owner(&key);
    let process = owner.and_then(|owner| processes.get(owner.pid, owner.start_boottime));
    let now = now_ms();
    // The user as the kernel recorded it when the socket was opened (the queue's uid is the socket's owner, for
    // packets the attribution programs didn't see).
    let uid = owner.map(|o| o.uid).or(queued.uid).unwrap_or(u32::MAX);
    let home = process.as_ref().and_then(|_| processes.home(uid));
    let pid = owner.map_or(0, |o| o.pid);
    let hosts = shared
        .names
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .lookup(pid, headers.destination, now);
    let empty: &[String] = &[];
    let facts = Facts {
        exe: process.as_ref().map_or("", |p| &*p.exe),
        apps: empty,
        cmdline: process.as_ref().map_or("", |p| p.cmdline.as_str()),
        ancestors: process.as_ref().map_or(empty, |p| p.ancestors.as_slice()),
        uid,
        home: home.as_deref(),
        hosts: &hosts,
        address: headers.destination,
        port: headers.destination_port,
        protocol: headers.protocol,
        context: process.as_ref().map_or(ContextKind::Host, |p| p.context),
        now_ms: now,
    };
    let exe = process
        .as_ref()
        .map_or_else(|| Arc::clone(&shared.unknown), |p| Arc::clone(&p.exe));
    let mut event = undecided_event(&facts, exe, pid, owner.map(|o| o.cookie));
    let rules = shared.rules.load();
    let (action, source, rule) = if let Some(decision) = rules.decide(&facts) {
        (decision.action, Source::Rule, Some(decision.rule))
    } else {
        if asks(shared) {
            hold(
                shared,
                &facts,
                &event,
                Held {
                    queue,
                    id: queued.id,
                },
            );
            return (None, None);
        }
        let action = policy_action(shared.config.no_match, shared.config.no_client);
        (action, Source::Policy, None)
    };
    let (verdict, source) = match shared.config.mode {
        Mode::Monitor => (Verdict::Accept, Source::Monitor),
        Mode::Enforce => (
            if action == Action::Allow {
                Verdict::Accept
            } else {
                Verdict::Drop
            },
            source,
        ),
    };
    event.action = action;
    event.source = source;
    event.rule = rule;
    if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
        shared.events.try_send(event)
    {
        shared.dropped_events.fetch_add(1, Ordering::Relaxed);
    }
    let reject = (verdict == Verdict::Drop && action == Action::Reject).then_some(SocketId {
        protocol: headers.protocol,
        local: headers.source,
        local_port: headers.source_port,
        remote: headers.destination,
        remote_port: headers.destination_port,
    });
    (Some(verdict), reject)
}

/// Holds a packet for the prompt of its program and destination, opening (and announcing) one if none is open.
fn hold(shared: &Shared, facts: &Facts<'_>, event: &Event, packet: Held) {
    let destination = facts
        .hosts
        .first()
        .map_or_else(|| facts.address.to_string(), ToString::to_string);
    let key = PromptKey {
        exe: Arc::clone(&event.exe),
        uid: facts.uid,
        destination,
        port: facts.port,
        protocol: facts.protocol,
    };
    let opened = shared.broker.hold(key, packet, facts.now_ms, || {
        let suggestions = snitchhiker_core::suggest::suggestions(
            facts.exe,
            facts.home,
            facts.hosts,
            facts.address,
            facts.port,
            facts.protocol,
        );
        NewPrompt {
            prompt: v1::Prompt {
                exe: facts.exe.to_owned(),
                cmdline: facts.cmdline.to_owned(),
                uid: facts.uid,
                user: crate::process::user_of(facts.uid).unwrap_or_default(),
                pid: event.pid,
                hosts: facts.hosts.iter().map(ToString::to_string).collect(),
                address: convert::address(facts.address),
                port: u32::from(facts.port),
                protocol: u32::from(facts.protocol),
                context: convert::context(facts.context).into(),
                exe_writable: crate::process::writable_by_others(event.pid),
                suggestions: suggestions
                    .iter()
                    .map(|s| v1::Suggestion {
                        label: s.label.clone(),
                        conditions: Some(convert::conditions(&s.conditions)),
                        broad: s.broad,
                    })
                    .collect(),
                ..v1::Prompt::default()
            },
            suggestions,
            event: event.clone(),
        }
    });
    if let Hold::Opened(prompt) = opened {
        shared
            .hub
            .publish(v1::Topic::Prompts, &v1::notice::Body::Prompt(prompt));
    }
}

/// Pushes recorded events to the subscribers of the events topic: one message each to those that want messages, and
/// the batch as one columnar block to those that want blocks.
fn publish_events(shared: &Shared, batch: &[Event], recorded: &[crate::store::Recorded]) {
    let (messages, blocks) = shared.hub.wanted(v1::Topic::Events);
    let plain: Vec<Outgoing> = if messages {
        batch
            .iter()
            .zip(recorded)
            .map(|(event, r)| {
                Outgoing::Notice(v1::notice::Body::Event(crate::api::event(
                    &event.stored(r.seq),
                )))
            })
            .collect()
    } else {
        Vec::new()
    };
    let block = if blocks {
        let rows: Vec<EventRow> = batch
            .iter()
            .zip(recorded)
            .map(|(e, r)| event_row(e, r))
            .collect();
        let mut strings: Vec<(u32, Arc<str>)> = Vec::new();
        for (event, r) in batch.iter().zip(recorded) {
            strings.push((r.exe, Arc::clone(&event.exe)));
            if let Some(host) = &event.host {
                strings.push((r.host, Arc::clone(host)));
            }
        }
        let mut columns = Vec::new();
        match columns::encode_events(&rows, &mut columns) {
            Ok(()) => Some(Outgoing::Block {
                columns: bytes::Bytes::from(columns),
                strings: Arc::from(strings),
            }),
            Err(error) => {
                error!(%error, "encoding an event block");
                None
            }
        }
    } else {
        None
    };
    if messages || block.is_some() {
        shared
            .hub
            .publish_all(v1::Topic::Events, &plain, block.as_ref());
    }
}

/// A recorded event as a block's row: the protocol's numbers, the strings' ids.
fn event_row(event: &Event, recorded: &crate::store::Recorded) -> EventRow {
    let address = match event.address {
        std::net::IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(a) => a.octets(),
    };
    EventRow {
        seq: recorded.seq,
        time_ms: event.time_ms,
        exe: recorded.exe,
        host: recorded.host,
        uid: event.uid,
        pid: event.pid,
        address,
        port: event.port,
        protocol: event.protocol,
        context: event.context.saturating_add(1),
        action: u8::try_from(i32::from(convert::action(event.action))).unwrap_or(0),
        source: event.source as u8,
        rule: event.rule.unwrap_or(0),
        bytes_out: 0,
        bytes_in: 0,
    }
}

fn write_loop(
    shared: &Shared,
    store: &Mutex<Store>,
    events: &Receiver<Event>,
    retention: Duration,
) {
    let mut batch = Vec::with_capacity(BATCH);
    let mut recorded = Vec::with_capacity(BATCH);
    let mut last_prune = Instant::now();
    let mut last_bytes = Instant::now();
    let mut counted: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut changed: Vec<(u64, u64, u64)> = Vec::new();
    loop {
        batch.clear();
        match events.recv_timeout(BYTES_EVERY) {
            Ok(event) => batch.push(event),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let deadline = Instant::now() + BATCH_WAIT;
        while batch.len() < BATCH {
            let left = deadline.saturating_duration_since(Instant::now());
            match events.recv_timeout(left) {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        let mut store = store.lock().unwrap_or_else(PoisonError::into_inner);
        if !batch.is_empty() {
            match store.record(&batch, &mut recorded) {
                Ok(()) => publish_events(shared, &batch, &recorded),
                Err(error) => error!(%error, events = batch.len(), "recording events"),
            }
        }
        if last_bytes.elapsed() >= BYTES_EVERY {
            last_bytes = Instant::now();
            changed.clear();
            let mut live: HashMap<u64, (u64, u64)> = HashMap::with_capacity(counted.len());
            for (cookie, sent, read) in shared.attribution.socket_bytes() {
                if counted.get(&cookie) != Some(&(sent, read)) {
                    changed.push((cookie, sent, read));
                }
                live.insert(cookie, (sent, read));
            }
            counted = live;
            if !changed.is_empty()
                && let Err(error) = store.record_bytes(&changed)
            {
                error!(%error, "recording byte counts");
            }
        }
        if last_prune.elapsed() >= PRUNE_EVERY {
            last_prune = Instant::now();
            let cutoff =
                now_ms().saturating_sub(u64::try_from(retention.as_millis()).unwrap_or(u64::MAX));
            while let Ok(pruned) = store.prune(cutoff, PRUNE_CHUNK) {
                if pruned < PRUNE_CHUNK as usize {
                    break;
                }
            }
            if let Err(error) = store.prune_rollups(cutoff) {
                error!(%error, "pruning rollups");
            }
        }
    }
}
