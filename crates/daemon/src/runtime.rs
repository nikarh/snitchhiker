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
use snitchhiker_core::rule::{Action, ContextKind};
use snitchhiker_ebpf::{Attribution, FlowKey};
use snitchhiker_netfilter::netlink::{Socket, Writer};
use snitchhiker_netfilter::nftables::{Table, encode_install, encode_remove};
use snitchhiker_netfilter::packet;
use snitchhiker_netfilter::queue::{Packet, Queue, Verdict};
use snitchhiker_netfilter::sockdiag::{SockDiag, SocketId};
use tracing::{error, info, warn};

use crate::config::{Config, Fail, Mode};
use crate::dns::{Names, parse_answer};
use crate::process::{HostNamespaces, ProcessCache};
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
    #[error("netlink: {0}")]
    Netlink(#[from] std::io::Error),
    #[error("eBPF: {0}")]
    Ebpf(#[from] snitchhiker_ebpf::Error),
    #[error("store: {0}")]
    Store(#[from] crate::store::Error),
    #[error("rules: {0}")]
    Rules(#[from] snitchhiker_core::engine::CompileError),
    #[error("managed rules: {0}")]
    Managed(#[from] crate::managed::Error),
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
}

/// The daemon, running.
pub struct Daemon {
    pub shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
    table: Table,
}

impl Daemon {
    /// Opens the store, compiles the rules, installs the table, loads the attribution programs and starts the
    /// deciding threads and the writer.
    pub fn start(config: Config) -> Result<Self, Error> {
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

        let (sender, receiver) = sync_channel(EVENT_QUEUE);
        let store = Arc::new(Mutex::new(store));
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
            config,
        });
        for offset in 0..shared.config.queues {
            let number = shared.config.queue + offset;
            let queue = Queue::bind(number)?;
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name(format!("queue-{number}"))
                .spawn(move || {
                    if let Err(error) = decide_loop(&shared, queue) {
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
        Ok(Self {
            shared,
            store,
            table,
        })
    }

    /// Reads the rules again and swaps them in.
    pub fn reload_rules(&self) -> Result<usize, Error> {
        let rules = {
            let store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
            compile(&self.shared.config, &store)?
        };
        let count = rules.len();
        self.shared.rules.store(Arc::new(rules));
        Ok(count)
    }

    /// Stops: with `fail = open` the table is removed, so traffic flows freely; with `fail = closed` it stays, so
    /// nothing new gets out until the daemon is back.
    pub fn stop(self) {
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

fn decide_loop(shared: &Shared, mut queue: Queue) -> Result<(), Error> {
    let mut processes = ProcessCache::new(shared.host);
    let mut verdicts: Vec<(u32, Verdict)> = Vec::with_capacity(64);
    let mut rejected: Vec<SocketId> = Vec::with_capacity(8);
    let mut sockdiag: Option<SockDiag> = None;
    loop {
        verdicts.clear();
        rejected.clear();
        for packet in queue.receive()? {
            let (verdict, reject) = decide(shared, &mut processes, &packet);
            verdicts.push((packet.id, verdict));
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

/// The verdict for one packet, recording what happened, and the socket to close for a rejected connection.
fn decide(
    shared: &Shared,
    processes: &mut ProcessCache,
    queued: &Packet<'_>,
) -> (Verdict, Option<SocketId>) {
    shared.decided.fetch_add(1, Ordering::Relaxed);
    let Some(headers) = packet::parse(queued.payload) else {
        // Not IPv4 or IPv6: nothing rules speak about.
        return (Verdict::Accept, None);
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
    let uid = process
        .as_ref()
        .map(|p| p.uid)
        .or(owner.map(|o| o.uid))
        .or(queued.uid)
        .unwrap_or(u32::MAX);
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
        home: process.as_ref().and_then(|p| p.home.as_deref()),
        hosts: &hosts,
        address: headers.destination,
        port: headers.destination_port,
        protocol: headers.protocol,
        context: process.as_ref().map_or(ContextKind::Host, |p| p.context),
        now_ms: now,
    };
    let rules = shared.rules.load();
    let decision = rules.decide(&facts);
    let (action, source, rule) = match decision {
        Some(decision) => (decision.action, Source::Rule, Some(decision.rule)),
        None => (shared.config.no_match, Source::Policy, None),
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
    let event = Event {
        time_ms: now,
        exe: process
            .as_ref()
            .map_or_else(|| Arc::clone(&shared.unknown), |p| Arc::clone(&p.exe)),
        host: hosts.first().cloned(),
        uid,
        pid,
        protocol: headers.protocol,
        address: headers.destination,
        port: headers.destination_port,
        context: context_code(facts.context),
        action,
        source,
        rule,
        cookie: owner.map(|o| o.cookie),
    };
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
    (verdict, reject)
}

fn write_loop(
    shared: &Shared,
    store: &Mutex<Store>,
    events: &Receiver<Event>,
    retention: Duration,
) {
    let mut batch = Vec::with_capacity(BATCH);
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
        if !batch.is_empty()
            && let Err(error) = store.record(&batch)
        {
            error!(%error, events = batch.len(), "recording events");
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
        }
    }
}
