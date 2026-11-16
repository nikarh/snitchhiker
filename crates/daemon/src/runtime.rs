//! The running daemon: the table, the attribution programs, one deciding thread per queue, and the writer.
//!
//! The packet path: receive → parse the headers → look the flow's owner up (eBPF) → the process's facts (cached) →
//! the rules (an immutable set, swapped atomically on change) → verdict, and an event to the writer's queue. Nothing
//! on it waits for the database, and a full event queue drops the event (counted), never the verdict.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use snitchhiker_core::engine::{Facts, RuleSet};
use snitchhiker_core::rule::{Action, Condition, ContextKind, ProcessRef};
use snitchhiker_ebpf::{Attribution, FlowKey};
use snitchhiker_netfilter::netlink::{Socket, Writer};
use snitchhiker_netfilter::nftables::{Table, encode_get_table, encode_install, encode_remove};
use snitchhiker_netfilter::packet;
use snitchhiker_netfilter::queue::{Packet, Queue, Verdict};
use snitchhiker_netfilter::sockdiag::{SockDiag, SocketId};
use tracing::{debug, error, info, warn};

use crate::hub::Outgoing;
use snitchhiker_core::rule::{Expiry, FolderId, Rule, RuleId, Tier};
use snitchhiker_proto::columns::{self, EventRow};
use snitchhiker_proto::{convert, v1};

use crate::config::{Config, Fail, Mode, Policy};
use crate::dns::{Names, parse_answer};
use crate::hub::Hub;
use crate::policy::Effective;
use crate::process::{HostNamespaces, ProcessCache};
use crate::prompts::{Broker, Held, Hold, NewPrompt, Pending, PromptKey};
use crate::store::{Event, Source, Store};

/// Events waiting for the writer; beyond this they are dropped (and counted). Allocated up front (128 bytes each):
/// enough for 300 ms of 50 000 connections a second while the writer commits.
const EVENT_QUEUE: usize = 16_384;
/// Events written per transaction at most. Large, so that at a high rate the index pages a transaction changes are
/// shared by many events (the writer still waits at most `BATCH_WAIT`).
pub const BATCH: usize = 8192;
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
    /// Counts changes of the alert rules, so the writer loads them again.
    pub alert_rules_changed: AtomicU64,
    pub rules: ArcSwap<RuleSet>,
    attribution: Attribution,
    names: RwLock<Names>,
    pub(crate) netns: u32,
    pub(crate) host: HostNamespaces,
    events: SyncSender<Event>,
    pub dropped_events: AtomicU64,
    /// The executable recorded for connections whose process isn't known.
    unknown: Arc<str>,
    pub decided: AtomicU64,
    pub hub: Arc<Hub>,
    pub broker: Broker,
    /// The policy in effect: daemon.toml's, with what clients changed.
    pub policy: ArcSwap<Effective>,
    /// The connections not allowed over the last hour, with their processes' lineage, for agents.
    pub blocked: crate::agents::Ring,
    /// Agents with session rules or proposals waiting: when one ends, so do they.
    pub agents: crate::agents::Watch,
    /// Who is notified of prompts.
    pub router: crate::router::Router,
    /// The containers connections come from.
    pub contexts: crate::contexts::Contexts,
    /// The namespaces decided inside (rootless containers').
    pub namespaces: crate::namespaces::Namespaces,
    /// Alerts' webhook, if one is configured.
    pub webhook: crate::webhook::Webhook,
    /// The blocklists rules name.
    pub blocklists: crate::blocklists::Blocklists,
    /// Programs' packages, for `pkg:` identities.
    pub packages: Arc<crate::apps::Packages>,
    /// Agents whose proposals are denied without asking anyone (muted by a person).
    pub muted_agents: Mutex<HashSet<ProcessRef>>,
    /// Counts changes of proposals, for requests waiting for one.
    proposals_changed: (Mutex<u64>, std::sync::Condvar),
}

/// The daemon, running. Shared by the signal handler and the API's threads.
pub struct Daemon {
    pub shared: Arc<Shared>,
    store: Arc<crate::locked::Locked>,
    table: Table,
    /// A change of the system firewall waiting to be confirmed.
    trial: Mutex<Trial>,
    /// Paired devices over the network.
    pub remote: crate::remote::Remote,
    /// Dangerous actions of remote devices waiting for a local approval.
    pub approvals: crate::approvals::Approvals,
}

/// A system firewall change on trial: reverted to `previous` at `reverts_at_ms` unless confirmed first.
#[derive(Default)]
struct Trial {
    /// Counts trials, so a timer only reverts its own.
    generation: u64,
    pending: Option<(u64, snitchhiker_core::system::Firewall)>,
}

impl Daemon {
    /// Opens the store, compiles the rules, installs the table, loads the attribution programs and starts the
    /// deciding threads and the writer.
    pub fn start(config: Config) -> Result<Arc<Self>, Error> {
        if let Some(parent) = config.database.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store = Store::open(&config.database)?;
        let blocklists = load_blocklists(&config, &store)?;
        let (rules, mut agents) = compile(&config, &store, &blocklists)?;
        info!(rules = rules.len(), "rules loaded");
        // Agents whose proposals wait, to expire them if the agent ends.
        agents.extend(waiting_agents(&store)?);
        // The programs first: from the moment the table is in place, every new flow's owner must be known.
        let attribution = Attribution::load()?;
        let table = table_of(&config);
        install(&table)?;
        info!(queues = config.queues, mode = ?config.mode, "table installed");

        // Until-restart rules from before don't apply any more.
        let mut store = store;
        store.delete_until_restart()?;
        let (sender, receiver) = sync_channel(EVENT_QUEUE);
        let store = Arc::new(crate::locked::Locked::new(store));
        let mut queues = Vec::with_capacity(usize::from(config.queues));
        let mut writers = Vec::with_capacity(usize::from(config.queues));
        for offset in 0..config.queues {
            let queue = Queue::bind(config.queue + offset)?;
            writers.push(queue.verdict_writer()?);
            queues.push(queue);
        }
        let policy = Effective::of(&config, &store.lock().policy()?);
        let broker = Broker::new(writers, Duration::from_secs(policy.prompt_timeout_secs));
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
            alert_rules_changed: AtomicU64::new(0),
            policy: ArcSwap::from_pointee(policy),
            blocked: crate::agents::Ring::default(),
            agents: crate::agents::Watch::new()?,
            proposals_changed: (Mutex::new(0), std::sync::Condvar::new()),
            router: crate::router::Router::new(
                config.prompt_routing,
                Duration::from_secs(config.escalate_after_secs),
            ),
            contexts: crate::contexts::Contexts::default(),
            namespaces: crate::namespaces::Namespaces::default(),
            webhook: crate::webhook::Webhook::default(),
            blocklists,
            packages: Arc::new(crate::apps::Packages::load()),
            muted_agents: Mutex::default(),
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
            thread::Builder::new()
                .name("writer".to_owned())
                .spawn(move || write_loop(&shared, &store, &receiver))?;
        }
        check_marker(&shared, &store.lock());
        // The system firewall as last set: a rule the kernel refuses mustn't keep the daemon from deciding.
        let firewall = store.lock().system_firewall()?;
        if let Err(error) = crate::system::apply(&firewall, &shared.config) {
            error!(%error, "installing the system firewall");
        }
        let daemon = Arc::new(Self {
            shared,
            store,
            table,
            trial: Mutex::new(Trial::default()),
            remote: crate::remote::Remote::default(),
            approvals: crate::approvals::Approvals::default(),
        });
        daemon.spawn_watches(agents)?;
        Ok(daemon)
    }

    /// The threads that wait for something: prompts timing out, the tables, agents ending, prompts to escalate.
    fn spawn_watches(self: &Arc<Self>, agents: HashSet<ProcessRef>) -> std::io::Result<()> {
        self.spawn_prompt_timeouts()?;
        self.spawn_table_watch()?;
        self.spawn_agent_watch()?;
        self.spawn_blocklist_refresh()?;
        self.shared.packages.watch()?;
        if self.shared.config.learn_dns {
            // Names programs resolved through systemd-resolved's cache or its library interface: no packet shows them.
            let shared = Arc::clone(&self.shared);
            crate::resolved::spawn(move |answer| {
                shared
                    .names
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .learn(0, answer, now_ms());
            })?;
        }
        self.watch_agents(agents);
        crate::router::Router::spawn(&self.shared)?;
        crate::namespaces::Namespaces::spawn(self)?;
        if !self.shared.config.alert_webhook.is_empty() {
            self.shared.webhook.start(
                &self.shared.config.alert_webhook,
                self.shared.config.alert_webhook_secret_file.as_deref(),
            )?;
        }
        self.devices_changed();
        Ok(())
    }

    /// Tells the router which devices are muted and where each is woken, from the store.
    pub fn devices_changed(&self) {
        let devices = self.store().devices();
        match devices {
            Ok(devices) => {
                let router = &self.shared.router;
                router.set_muted(devices.iter().filter(|d| d.muted).map(|d| d.id.clone()));
                router.push.set_targets(
                    devices
                        .iter()
                        .filter_map(|d| {
                            Some((d.id.clone(), crate::push::target(d.push.as_deref()?)?))
                        })
                        .collect(),
                );
            }
            Err(error) => error!(%error, "reading the paired devices"),
        }
    }

    /// Announces a proposal made or changed: to subscribers, and to requests waiting for a change.
    pub fn publish_proposal(&self, proposal: &v1::Proposal) {
        self.shared.hub.publish(
            v1::Topic::Proposals,
            &v1::notice::Body::Proposal(Box::new(proposal.clone())),
        );
        let (count, changed) = &self.shared.proposals_changed;
        *count.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        changed.notify_all();
    }

    /// Waits until `still` says no, checking it again whenever a proposal changes, for at most `timeout`.
    pub fn wait_for_proposals(&self, timeout: Duration, mut still: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        let (count, changed) = &self.shared.proposals_changed;
        let mut seen = *count.lock().unwrap_or_else(PoisonError::into_inner);
        while still() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let guard = count.lock().unwrap_or_else(PoisonError::into_inner);
            let (guard, _) = changed
                .wait_timeout_while(guard, left, |now| *now == seen)
                .unwrap_or_else(PoisonError::into_inner);
            seen = *guard;
        }
    }

    /// Watches `agents` too: their session rules and waiting proposals end with them (at once, for those already
    /// gone).
    pub fn watch_agents(&self, agents: impl IntoIterator<Item = ProcessRef>) {
        let ended: Vec<ProcessRef> = agents
            .into_iter()
            .filter(|a| !self.shared.agents.add(*a))
            .collect();
        if !ended.is_empty() {
            self.end_agents(&ended);
        }
    }

    /// Waits for watched agents to end, and ends what they left.
    fn spawn_agent_watch(self: &Arc<Self>) -> std::io::Result<()> {
        let daemon = Arc::clone(self);
        thread::Builder::new()
            .name("agent-watch".to_owned())
            .spawn(move || {
                loop {
                    let ended = daemon.shared.agents.wait();
                    if !ended.is_empty() {
                        daemon.end_agents(&ended);
                    }
                }
            })?;
        Ok(())
    }

    /// Ends what the agents that exited left: their session rules are removed (one batch of the history) and their
    /// waiting proposals expire.
    fn end_agents(&self, ended: &[ProcessRef]) {
        let now = now_ms();
        let removed = {
            let mut store = self.store();
            let rules = store.rules();
            rules.and_then(|rules| {
                let gone: Vec<RuleId> = rules
                    .iter()
                    .filter(|r| {
                        crate::agents::sessions(r).is_some_and(|roots| {
                            roots
                                .iter()
                                .all(|a| ended.contains(a) || !crate::agents::alive(*a))
                        })
                    })
                    .map(|r| r.id)
                    .collect();
                if gone.is_empty() {
                    return Ok(0);
                }
                let batch = store.batch("snitchhikerd (an agent's session ended)", now)?;
                store.atomically(|store| {
                    for id in &gone {
                        store.remove_rule(*id, &batch)?;
                    }
                    Ok(gone.len())
                })
            })
        };
        match removed {
            Ok(0) => {}
            Ok(count) => {
                info!(count, "an agent ended: its session's rules are removed");
                if let Err(error) = self.reload_rules() {
                    error!(%error, "reloading the rules");
                }
            }
            Err(error) => error!(%error, "removing an ended agent's rules"),
        }
        let pending = self
            .store()
            .proposals(Some(v1::ProposalState::Pending), 1000);
        for mut proposal in pending.unwrap_or_default() {
            let Some(p) = &proposal.provenance else {
                continue;
            };
            let agent = ProcessRef {
                pid: p.agent_pid,
                start: p.agent_start,
            };
            if !ended.contains(&agent) {
                continue;
            }
            proposal.state = v1::ProposalState::Expired.into();
            proposal.decided_ms = now;
            let updated = self.store().update_proposal(&proposal);
            match updated {
                Ok(()) => self.publish_proposal(&proposal),
                Err(error) => error!(%error, "expiring a proposal"),
            }
        }
    }

    /// Every few seconds, checks that the tables are still there: one removed by someone else is put back, with an alert.
    fn spawn_table_watch(self: &Arc<Self>) -> std::io::Result<()> {
        let daemon = Arc::clone(self);
        thread::Builder::new()
            .name("table-watch".to_owned())
            .spawn(move || {
                loop {
                    thread::sleep(TABLE_WATCH_EVERY);
                    daemon.check_tables();
                }
            })?;
        Ok(())
    }

    fn check_tables(&self) {
        let missing = |name: &str| {
            let mut writer = Writer::new();
            let sequence = encode_get_table(&mut writer, name, 1);
            Socket::open()
                .and_then(|mut socket| socket.transact(&writer, sequence, sequence))
                .is_err_and(|e| e.raw_os_error() == Some(2))
        };
        if missing(&self.table.name) {
            let put_back = install(&self.table);
            self.raise_table_removed("the daemon's", &put_back);
        }
        let firewall = self.store().system_firewall();
        if firewall.as_ref().is_ok_and(|f| f.enabled) && missing(crate::system::TABLE) {
            let put_back = self
                .apply_system()
                .map_err(|e| std::io::Error::other(e.to_string()));
            self.raise_table_removed("the system firewall's", &put_back);
        }
    }

    fn raise_table_removed(&self, which: &str, put_back: &std::io::Result<()>) {
        crate::alerts::raise(
            &self.shared,
            &self.store(),
            &crate::alerts::NewAlert {
                kind: "table_removed",
                title: format!("Something removed {which} nftables table"),
                body: match put_back {
                    Ok(()) => {
                        "It was put back. Another firewall tool may be flushing the whole ruleset."
                            .to_owned()
                    }
                    Err(error) => format!("Putting it back failed: {error}"),
                },
                rule: None,
            },
        );
    }

    /// Raises an alert from the API's side.
    pub fn raise(&self, alert: &crate::alerts::NewAlert) {
        crate::alerts::raise(&self.shared, &self.store(), alert);
    }

    /// The alert rules changed: the writer loads them again.
    pub fn alert_rules_changed(&self) {
        self.shared
            .alert_rules_changed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Fetches blocklists when they are due.
    fn spawn_blocklist_refresh(self: &Arc<Self>) -> std::io::Result<()> {
        let daemon = Arc::clone(self);
        thread::Builder::new()
            .name("blocklists".to_owned())
            .spawn(move || {
                loop {
                    let records = daemon.store().blocklists();
                    let records = match records {
                        Ok(records) => records,
                        Err(error) => {
                            error!(%error, "reading the blocklists; they are no longer refreshed");
                            return;
                        }
                    };
                    let now = now_ms();
                    let due: Vec<_> = records
                        .iter()
                        .filter(|r| crate::blocklists::is_due(r, now))
                        .cloned()
                        .collect();
                    if due.is_empty() {
                        daemon
                            .shared
                            .blocklists
                            .wait(crate::blocklists::next_due(&records), now);
                        continue;
                    }
                    for mut record in due {
                        daemon.refresh_blocklist(&mut record);
                    }
                }
            })?;
        Ok(())
    }

    /// Fetches a list now, records how it went and, when it changed, compiles the rules again.
    pub fn refresh_blocklist(&self, record: &mut crate::blocklists::Record) {
        let changed = self.shared.blocklists.fetch(record, now_ms());
        let updated = self.store().update_blocklist(record);
        if let Err(error) = updated {
            warn!(%error, list = record.name, "recording a blocklist's fetch");
        }
        if changed && let Err(error) = self.reload_rules() {
            warn!(%error, "compiling the rules with a changed blocklist");
        }
    }

    /// Prompts nobody answered in time are decided by the policy's `on_timeout`.
    fn spawn_prompt_timeouts(self: &Arc<Self>) -> std::io::Result<()> {
        let daemon = Arc::clone(self);
        thread::Builder::new()
            .name("prompt-timeouts".to_owned())
            .spawn(move || {
                loop {
                    for pending in daemon.shared.broker.wait_expired() {
                        let action = daemon.shared.policy.load().on_timeout;
                        daemon.resolve(&pending, action, Source::Timeout, None, "", true);
                    }
                }
            })?;
        Ok(())
    }

    /// The daemon's version, with the suffix of development builds.
    #[must_use]
    pub fn version(&self) -> &'static str {
        option_env!("SNITCHHIKER_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
    }

    /// The store, for the API's reads and writes.
    #[track_caller]
    pub fn store(&self) -> crate::locked::Guard<'_> {
        self.store.lock()
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
                    container: owner
                        .filter(|_| {
                            process.as_ref().map(|p| p.context) == Some(ContextKind::Container)
                        })
                        .and_then(|o| self.shared.contexts.container(o.pid, o.cgroup))
                        .map(|c| Box::new(convert::container(&c.container))),
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
            sha256: None,
            writable: false,
            cmdline: "",
            ancestors: &[],
            lineage: &[],
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
            container: None,
            vm: None,
            netns: None,
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
        self.shared.router.closed(pending.prompt.id);
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
    /// Makes the kernel's system table what the store says.
    pub fn apply_system(&self) -> Result<(), Error> {
        let firewall = self.store().system_firewall()?;
        crate::system::apply(&firewall, &self.shared.config)?;
        Ok(())
    }

    /// Replaces the system firewall with `firewall` (checked), recording it as `app`'s change. With `revert_after`,
    /// the previous one comes back then unless [`Daemon::confirm_system`] is called first.
    pub fn set_system(
        self: &Arc<Self>,
        firewall: &snitchhiker_core::system::Firewall,
        app: &str,
        revert_after: Option<Duration>,
    ) -> Result<u64, Error> {
        let before = self.store().system_firewall()?;
        // The kernel first: a table it refuses is never recorded.
        crate::system::apply(firewall, &self.shared.config)?;
        let what = crate::system::describe(&before, firewall);
        let recorded = {
            let mut store = self.store();
            store.batch(app, now_ms()).and_then(|batch| {
                store.atomically(|s| s.put_system_firewall(firewall, &what, &batch))
            })
        };
        if let Err(error) = recorded {
            let _ = crate::system::apply(&before, &self.shared.config);
            return Err(error.into());
        }
        let mut trial = self.trial.lock().unwrap_or_else(PoisonError::into_inner);
        trial.generation += 1;
        trial.pending = None;
        let Some(after) = revert_after else {
            return Ok(0);
        };
        let reverts_at_ms = now_ms() + u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
        trial.pending = Some((reverts_at_ms, before));
        let generation = trial.generation;
        drop(trial);
        let daemon = Arc::clone(self);
        thread::Builder::new()
            .name("system-trial".to_owned())
            .spawn(move || {
                thread::sleep(after);
                daemon.revert_system(generation);
            })?;
        Ok(reverts_at_ms)
    }

    /// Reverts trial `generation` if it is still waiting.
    fn revert_system(self: &Arc<Self>, generation: u64) {
        let previous = {
            let mut trial = self.trial.lock().unwrap_or_else(PoisonError::into_inner);
            if trial.generation != generation {
                return;
            }
            trial.pending.take()
        };
        if let Some((_, previous)) = previous {
            warn!("the system firewall change wasn't confirmed in time: reverting it");
            if let Err(error) = self.set_system(&previous, "daemon (not confirmed)", None) {
                error!(%error, "reverting the system firewall");
            }
        }
    }

    /// Confirms the change on trial; false when none waits.
    pub fn confirm_system(&self) -> bool {
        let mut trial = self.trial.lock().unwrap_or_else(PoisonError::into_inner);
        trial.generation += 1;
        trial.pending.take().is_some()
    }

    /// When the change on trial reverts (Unix ms); 0 for none.
    pub fn system_reverts_at(&self) -> u64 {
        self.trial
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .as_ref()
            .map_or(0, |(at, _)| *at)
    }

    /// Applies the policy as the store has it (after a client changed it, or an undo).
    pub fn reload_policy(&self) -> Result<Effective, Error> {
        let overrides = self.store.lock().policy()?;
        let effective = Effective::of(&self.shared.config, &overrides);
        self.shared
            .broker
            .set_timeout(Duration::from_secs(effective.prompt_timeout_secs));
        self.shared.policy.store(Arc::new(effective));
        Ok(effective)
    }

    pub fn reload_rules(&self) -> Result<usize, Error> {
        let (rules, agents) = {
            let store = self.store.lock();
            compile(&self.shared.config, &store, &self.shared.blocklists)?
        };
        self.watch_agents(agents);
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
        // Clients are told before the connections end, so a planned stop isn't taken for a crash.
        let reason = if std::process::Command::new("systemctl")
            .arg("is-system-running")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "stopping")
        {
            "the machine is shutting down or restarting"
        } else {
            "the daemon was stopped (by an administrator, or for an upgrade)"
        };
        self.shared.router.push.stopping(reason);
        self.shared.hub.publish(
            v1::Topic::Prompts,
            &v1::notice::Body::Stopping(v1::Stopping {
                reason: reason.to_owned(),
            }),
        );
        // A moment for the notices to leave.
        thread::sleep(Duration::from_millis(300));
        let _ = std::fs::remove_file(config_marker(&self.shared.config));
        if self.shared.config.fail == Fail::Open {
            if let Err(error) = remove(&self.table.name) {
                warn!(%error, "removing the table");
            }
            if let Err(error) = crate::system::remove() {
                warn!(%error, "removing the system firewall");
            }
        }
        info!(
            decided = self.shared.decided.load(Ordering::Relaxed),
            dropped_events = self.shared.dropped_events.load(Ordering::Relaxed),
            "stopped"
        );
    }
}

/// The blocklists as last fetched, next to the database.
fn load_blocklists(config: &Config, store: &Store) -> Result<crate::blocklists::Blocklists, Error> {
    Ok(crate::blocklists::Blocklists::load(
        config
            .database
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/"))
            .join("lists"),
        config.blocklist_max_bytes,
        &store.blocklists()?,
    ))
}

/// The agents whose proposals wait for an answer.
fn waiting_agents(store: &Store) -> Result<Vec<ProcessRef>, Error> {
    Ok(store
        .proposals(Some(v1::ProposalState::Pending), 1000)?
        .iter()
        .filter_map(|p| p.provenance.as_ref())
        .map(|p| ProcessRef {
            pid: p.agent_pid,
            start: p.agent_start,
        })
        .collect())
}

/// The rules in effect: the stored ones, the System folder and the managed files; and the agents whose sessions
/// rules are limited to.
fn compile(
    config: &Config,
    store: &Store,
    blocklists: &crate::blocklists::Blocklists,
) -> Result<(RuleSet, HashSet<ProcessRef>), Error> {
    let managed = crate::managed::Managed::load(config.default_rules, &config.rules_dir)?;
    let mut folders = store.folders()?;
    folders.extend(managed.folders);
    let mut rules = store.rules()?;
    let agents = rules
        .iter()
        .filter_map(crate::agents::sessions)
        .flatten()
        .copied()
        .collect();
    rules.extend(managed.rules);
    let set = RuleSet::compile_with(&folders, &rules, &blocklists.lists())?;
    blocklists.rules_compiled(&rules);
    Ok((set, agents))
}

/// The daemon's table, as its configuration has it.
fn table_of(config: &Config) -> Table {
    Table {
        queue: config.queue,
        queues: config.queues,
        bypass: config.fail == Fail::Open,
        dns_queue: config.dns_queue(),
        forward_from: config
            .forward_from
            .iter()
            .map(|name| match name.strip_suffix('*') {
                Some(prefix) => snitchhiker_netfilter::nftables::Interface {
                    name: prefix.to_owned(),
                    prefix: true,
                },
                None => snitchhiker_netfilter::nftables::Interface {
                    name: name.clone(),
                    prefix: false,
                },
            })
            .collect(),
        ..Table::default()
    }
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
    let mut processes =
        ProcessCache::with_packages(shared.host, Some(Arc::clone(&shared.packages)));
    let mut senders = crate::forward::Senders::default();
    let mut verdicts: Vec<(u32, Verdict)> = Vec::with_capacity(64);
    let mut rejected: Vec<SocketId> = Vec::with_capacity(8);
    let mut sockdiag: Option<SockDiag> = None;
    loop {
        verdicts.clear();
        rejected.clear();
        for packet in queue.receive()? {
            let (verdict, reject) = decide(
                shared,
                &mut processes,
                &mut senders,
                &packet,
                (offset, shared.netns),
            );
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
fn undecided_event(
    facts: &Facts<'_>,
    exe: Arc<str>,
    pid: u32,
    cookie: Option<u64>,
    container: Option<Arc<str>>,
) -> Event {
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
        container,
    }
}

/// Whether a connection no rule decides is held for a prompt: the policy asks, the daemon enforces, and some client
/// listens for prompts, or a device can be woken to.
pub fn asks(shared: &Shared) -> bool {
    let policy = shared.policy.load();
    policy.no_match == Policy::Ask
        && policy.mode == Mode::Enforce
        && (shared.hub.has_subscribers(v1::Topic::Prompts) || shared.router.can_wake_someone())
}

/// What a policy does without asking (`ask` falls back to `no_client`).
#[must_use]
pub fn policy_action(policy: Policy, no_client: Action) -> Action {
    match policy {
        Policy::Allow => Action::Allow,
        Policy::Deny => Action::Deny,
        Policy::Reject => Action::Reject,
        Policy::Ask => no_client,
    }
}

/// The verdict for one packet (none: it is held for a prompt), recording what happened, and the socket to close for a
/// rejected connection.
/// The context a connection comes from: the process's own (its cgroup names its container), or, for a rootless
/// container's user-mode network helper, the container it connects for (`true`: the program in it is unknown).
fn context_of(
    shared: &Shared,
    owner: Option<snitchhiker_ebpf::FlowOwner>,
    process: Option<&crate::process::ProcessInfo>,
) -> (ContextKind, Option<Arc<crate::contexts::Identified>>, bool) {
    let (Some(owner), Some(process)) = (owner, process) else {
        return (ContextKind::Host, None, false);
    };
    // A helper makes its connections from the host's network namespace (rootless, it runs in the runtime's user
    // namespace): a program of that name inside a container is no helper.
    if crate::contexts::is_network_helper(&process.exe)
        && std::fs::metadata(format!("/proc/{}/ns/net", owner.pid))
            .is_ok_and(|m| u32::try_from(m.ino()).ok() == Some(shared.netns))
        && let Some(served) =
            shared
                .contexts
                .served_by(owner.pid, owner.start_boottime, &process.exe)
    {
        return (ContextKind::Container, Some(served), true);
    }
    let container = (process.context == ContextKind::Container)
        .then(|| shared.contexts.container(owner.pid, owner.cgroup))
        .flatten();
    (process.context, container, false)
}

/// The netfilter hook of forwarded packets.
const NF_INET_FORWARD: u8 = 2;

/// The owner of a forwarded packet's flow, as its sender's namespace recorded it (see [`crate::forward`]).
fn forwarded_owner(
    shared: &Shared,
    senders: &mut crate::forward::Senders,
    queued: &Packet<'_>,
    key: &FlowKey,
) -> Owner {
    let (Some(bridge), Some(mac)) = (queued.in_interface, queued.source_mac) else {
        debug!(in_interface = ?queued.in_interface, mac = ?queued.source_mac, "a forwarded packet without its sender's link");
        return Owner::Unknown;
    };
    for fresh in [false, true] {
        let sender = senders.sender(bridge, mac, fresh);
        debug!(bridge, ?mac, ?sender, fresh, "a forwarded packet's sender");
        match sender {
            Some(crate::forward::Sender::Netns(netns)) => {
                if let Some(owner) = shared.attribution.owner(&FlowKey { netns, ..*key }) {
                    return Owner::Process(owner);
                }
            }
            Some(crate::forward::Sender::Tap(tap)) => return Owner::Tap(tap),
            None => {}
        }
    }
    Owner::Unknown
}

/// Who sent a queued packet.
enum Owner {
    /// The process that opened its flow.
    Process(snitchhiker_ebpf::FlowOwner),
    /// A VM, through this tap.
    Tap(Arc<str>),
    Unknown,
}

/// Who opened a queued packet's flow: on this host, or, for a forwarded packet, in its sender's namespace.
fn owner_of(
    shared: &Shared,
    senders: &mut crate::forward::Senders,
    queued: &Packet<'_>,
    (key, source): (&FlowKey, std::net::IpAddr),
) -> Owner {
    if queued.hook == NF_INET_FORWARD {
        forwarded_owner(shared, senders, queued, key)
    } else {
        // A flow the programs didn't record: its socket, if exactly one process holds it.
        shared
            .attribution
            .owner(key)
            .or_else(|| {
                crate::fallback::owner(
                    key.protocol,
                    (source, key.source_port),
                    (key.destination, key.destination_port),
                )
            })
            .map_or(Owner::Unknown, Owner::Process)
    }
}

pub(crate) fn decide(
    shared: &Shared,
    processes: &mut ProcessCache,
    senders: &mut crate::forward::Senders,
    queued: &Packet<'_>,
    (queue, netns): (usize, u32),
) -> (Option<Verdict>, Option<SocketId>) {
    shared.decided.fetch_add(1, Ordering::Relaxed);
    let Some(headers) = packet::parse(queued.payload) else {
        // Not IPv4 or IPv6: nothing rules speak about.
        return (Some(Verdict::Accept), None);
    };
    let key = FlowKey {
        netns,
        protocol: headers.protocol,
        source_port: headers.source_port,
        destination: headers.destination,
        destination_port: headers.destination_port,
    };
    let (owner, vm) = match owner_of(shared, senders, queued, (&key, headers.source)) {
        Owner::Process(owner) => (Some(owner), None),
        Owner::Tap(tap) => (None, shared.contexts.vm_on_tap(&tap)),
        Owner::Unknown => (None, None),
    };
    // The daemon's own traffic (its remote endpoint: the relay, devices) is never decided, as marked packets aren't
    // queued: its sockets come from a library that can't mark them, but the kernel names their process.
    if owner.is_some_and(|o| o.pid == std::process::id()) {
        return (Some(Verdict::Accept), None);
    }
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
    let (context, container, helper) = if vm.is_some() {
        (ContextKind::Vm, None, false)
    } else {
        context_of(shared, owner, process.as_deref())
    };
    // A helper's connection for a namespace decided inside was decided there already, with its program: deciding it
    // again here, knowing less, could only contradict that. Until then, the daemon starts deciding inside.
    if helper && let Some((pid, inode)) = container.as_ref().and_then(|c| c.served) {
        if shared.namespaces.is_managed(inode) {
            return (Some(Verdict::Accept), None);
        }
        shared.namespaces.request(pid, inode);
    }
    // A network helper isn't the program: the one in the container is, unknown from out here.
    let process = if helper { None } else { process };
    // A named namespace's connections (queued inside it) carry its name.
    let named = (netns != shared.netns)
        .then(|| shared.namespaces.named(u64::from(netns)))
        .flatten();
    // Hashed only while a rule pins a binary.
    let sha256 = process
        .as_ref()
        .filter(|_| shared.rules.load().needs_sha256())
        .and_then(|p| crate::process::sha256_of(p.pid));
    let facts = Facts {
        exe: process.as_ref().map_or("", |p| &*p.exe),
        apps: process.as_ref().map_or(&[], |p| p.apps.as_slice()),
        sha256: sha256.as_deref(),
        writable: process.as_ref().is_some_and(|p| p.writable),
        cmdline: process.as_ref().map_or("", |p| p.cmdline.as_str()),
        ancestors: process.as_ref().map_or(empty, |p| p.ancestors.as_slice()),
        lineage: process.as_ref().map_or(&[], |p| p.lineage.as_slice()),
        uid,
        home: home.as_deref(),
        hosts: &hosts,
        address: headers.destination,
        port: headers.destination_port,
        protocol: headers.protocol,
        context,
        now_ms: now,
        container: container.as_deref().map(|c| &c.container),
        vm: vm.as_deref().map(|v| &v.vm),
        netns: named.as_ref().map(|(name, _)| &**name),
    };
    let exe = process
        .as_ref()
        .map_or_else(|| Arc::clone(&shared.unknown), |p| Arc::clone(&p.exe));
    let event = undecided_event(
        &facts,
        exe,
        pid,
        owner.map(|o| o.cookie),
        container
            .as_ref()
            .map(|c| Arc::clone(&c.key))
            .or_else(|| named.as_ref().map(|(_, key)| Arc::clone(key)))
            .or_else(|| vm.as_ref().map(|v| Arc::clone(&v.key))),
    );
    let rules = shared.rules.load();
    let (action, source, rule) = if let Some(decision) = rules.decide(&facts) {
        (decision.action, Source::Rule, Some(decision.rule))
    } else {
        let held = Held {
            queue,
            id: queued.id,
        };
        match undecided(shared, &facts, &event, held) {
            Some(decided) => decided,
            None => return (None, None),
        }
    };
    conclude(shared, &facts, event, &headers, (action, source, rule))
}

/// A decided connection: its verdict by the mode, the history's record, and the socket to close for a rejection.
fn conclude(
    shared: &Shared,
    facts: &Facts<'_>,
    mut event: Event,
    headers: &packet::Headers,
    (action, source, rule): (Action, Source, Option<RuleId>),
) -> (Option<Verdict>, Option<SocketId>) {
    let (verdict, source) = match shared.policy.load().mode {
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
    if action != Action::Allow {
        remember(shared, facts, &event, None);
    }
    event.action = action;
    event.source = source;
    event.rule = rule;
    if let Some(rule) = rule {
        shared.blocklists.decided(rule);
    }
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

/// Remembers a connection not allowed, with its process's lineage, for agents (see `agents`).
fn remember(shared: &Shared, facts: &Facts<'_>, event: &Event, prompt: Option<u64>) {
    if facts.lineage.is_empty() {
        return;
    }
    shared.blocked.record(crate::agents::Blocked {
        time_ms: facts.now_ms,
        lineage: facts.lineage.to_vec(),
        exe: Arc::clone(&event.exe),
        host: facts.hosts.first().map(ToString::to_string),
        address: facts.address,
        port: facts.port,
        protocol: facts.protocol,
        uid: facts.uid,
        context: facts.context,
        prompt,
    });
}

/// A connection no rule decides: held for a prompt (`None`), or decided by the policy (by `on_timeout` when asking
/// but too many prompts are open).
fn undecided(
    shared: &Shared,
    facts: &Facts<'_>,
    event: &Event,
    held: Held,
) -> Option<(Action, Source, Option<RuleId>)> {
    let asking = asks(shared);
    if asking && let Some(prompt) = hold(shared, facts, event, held) {
        remember(shared, facts, event, Some(prompt));
        return None;
    }
    let policy = shared.policy.load();
    Some(if asking {
        (policy.on_timeout, Source::Timeout, None)
    } else {
        let action = policy_action(policy.no_match, policy.no_client);
        (action, Source::Policy, None)
    })
}

/// Holds a packet for the prompt of its program and destination, opening (and announcing) one if none is open; the
/// prompt's id, or `None` when the broker is full (see [`crate::prompts::MAX_PROMPTS`]).
fn hold(shared: &Shared, facts: &Facts<'_>, event: &Event, packet: Held) -> Option<u64> {
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
        container: event.container.clone(),
    };
    let opened = shared.broker.hold(key, packet, facts.now_ms, || {
        let suggestions = snitchhiker_core::suggest::in_context(
            snitchhiker_core::suggest::suggestions(
                facts.exe,
                facts.home,
                facts.hosts,
                facts.address,
                facts.port,
                facts.protocol,
            ),
            facts.context,
            facts.container,
            facts.vm,
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
                container: event
                    .container
                    .as_deref()
                    .map(|key| Box::new(convert::container_from_key(key))),
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
    match opened {
        Hold::Opened(prompt) => {
            shared.router.opened(&shared.hub, &prompt);
            Some(prompt.id)
        }
        Hold::Joined(id) => Some(id),
        Hold::Full => None,
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
            if let Some(container) = &event.container {
                strings.push((r.container, Arc::clone(container)));
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
        container: recorded.container,
    }
}

/// Raises an alert when the last daemon didn't stop cleanly (its marker is still there: it crashed, was killed, or the
/// machine lost power), then puts this one's marker in place.
fn check_marker(shared: &Shared, store: &Store) {
    let marker = config_marker(&shared.config);
    if marker.exists() {
        crate::alerts::raise(
            shared,
            store,
            &crate::alerts::NewAlert {
                kind: "crashed",
                title: "The daemon stopped unexpectedly".to_owned(),
                body: "It didn't stop cleanly last time: it crashed, was killed, or the machine lost power."
                    .to_owned(),
                rule: None,
            },
        );
    }
    let _ = std::fs::write(&marker, b"");
}

/// Where a running daemon keeps its marker: next to its database, so a crash is noticed after a reboot too.
fn config_marker(config: &Config) -> std::path::PathBuf {
    config.database.with_extension("running")
}

/// How often the tables are checked.
const TABLE_WATCH_EVERY: Duration = Duration::from_secs(10);
/// How often the counters of what was lost are checked.
const LOSS_CHECK_EVERY: Duration = Duration::from_secs(60);

/// Packets the kernel dropped on queues `first..first + count` (`/proc/net/netfilter/nfnetlink_queue`: the queue
/// overflowed, or the daemon's socket couldn't take them).
fn queue_drops(first: u16, count: u16) -> u64 {
    std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue").map_or(0, |text| {
        text.lines()
            .filter_map(|line| {
                let fields: Vec<u64> = line
                    .split_whitespace()
                    .filter_map(|f| f.parse().ok())
                    .collect();
                let queue = u16::try_from(*fields.first()?).ok()?;
                (queue >= first && queue < first.saturating_add(count)).then(|| {
                    fields.get(5).copied().unwrap_or(0) + fields.get(6).copied().unwrap_or(0)
                })
            })
            .sum()
    })
}

/// Alerts about what the node lost since the last check: events the history couldn't keep, packets the kernel
/// dropped.
fn check_losses(shared: &Shared, store: &Store, seen: &mut (u64, u64)) {
    let dropped = shared.dropped_events.load(Ordering::Relaxed);
    if dropped > seen.0 {
        crate::alerts::raise(
            shared,
            store,
            &crate::alerts::NewAlert {
                kind: "dropped_events",
                title: "Connections weren't recorded".to_owned(),
                body: format!(
                    "{} connections were decided but not kept in the history: the database couldn't keep up.",
                    dropped - seen.0
                ),
                rule: None,
            },
        );
    }
    let queued = queue_drops(shared.config.queue, shared.config.queues);
    if queued > seen.1 {
        crate::alerts::raise(
            shared,
            store,
            &crate::alerts::NewAlert {
                kind: "queue_overflow",
                title: "The kernel dropped packets waiting for a decision".to_owned(),
                body: format!(
                    "{} packets were dropped on the daemon's queues: they overflowed. New connections were refused \
                     while that lasted.",
                    queued - seen.1
                ),
                rule: None,
            },
        );
    }
    *seen = (dropped, queued.max(seen.1));
}

fn write_loop(shared: &Shared, store: &crate::locked::Locked, events: &Receiver<Event>) {
    let mut batch = Vec::with_capacity(BATCH);
    let mut engine = crate::alerts::Engine::default();
    let mut rules_seen = u64::MAX;
    let mut last_loss_check = Instant::now();
    let mut losses = (0, queue_drops(shared.config.queue, shared.config.queues));
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
        let mut store = store.lock();
        let generation = shared.alert_rules_changed.load(Ordering::Relaxed);
        if generation != rules_seen {
            rules_seen = generation;
            match store.alert_rules() {
                Ok(rules) => engine.load(rules),
                Err(error) => error!(%error, "loading the alert rules"),
            }
        }
        if !batch.is_empty() {
            match store.record(&batch, &mut recorded) {
                Ok(()) => {
                    publish_events(shared, &batch, &recorded);
                    for alert in engine.check(&batch, &recorded) {
                        crate::alerts::raise(shared, &store, &alert);
                    }
                }
                Err(error) => error!(%error, events = batch.len(), "recording events"),
            }
        }
        if last_loss_check.elapsed() >= LOSS_CHECK_EVERY {
            last_loss_check = Instant::now();
            check_losses(shared, &store, &mut losses);
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
            let retention_ms = u64::from(shared.policy.load().retention_days) * 86_400_000;
            let cutoff = now_ms().saturating_sub(retention_ms);
            while let Ok(pruned) = store.prune(cutoff, PRUNE_CHUNK) {
                if pruned < PRUNE_CHUNK as usize {
                    break;
                }
            }
            if let Err(error) = store.prune_alerts(cutoff) {
                error!(%error, "pruning alerts");
            }
            if let Err(error) = store.prune_proposals(cutoff) {
                error!(%error, "pruning proposals");
            }
            if let Err(error) = store.prune_rollups(cutoff) {
                error!(%error, "pruning rollups");
            }
        }
    }
}
