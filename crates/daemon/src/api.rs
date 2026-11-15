//! The daemon's local API: the client socket (the desktop app, the MCP server: verified by the kernel, see `peer`) and
//! the admin socket (root, the command line), both speaking the client protocol (`snitchhiker-proto`).
//!
//! Each connection has a thread reading its requests and a writer thread draining its outbound queue (responses and
//! subscription notices), so a slow client never blocks the node.

use std::io::{BufReader, BufWriter, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread;

use nix::sys::socket::{getsockopt, sockopt};
use snitchhiker_proto::{MAJOR, MINOR, convert, frame, v1};
use tracing::{debug, info, warn};

use crate::config::{Config, StepUp};
use crate::hub::{OUTBOUND, Outbox, Outgoing};
use crate::peer::{end_with_process, identify, verify};
use crate::runtime::{AnswerError, Daemon, now_ms};
use crate::store::{
    AuditEntry, Batch, Dimension, Error as StoreError, HOUR_MS, Store, StringKind, UndoError,
};
use snitchhiker_core::query::{self, EventFilter};
use snitchhiker_core::rule::{Action, Condition, Expiry, allows_everything};
use snitchhiker_proto::columns::{self, EventRow};

pub const RUN_DIR: &str = "/run/snitchhiker";
pub const CLIENT_SOCKET: &str = "/run/snitchhiker/client.sock";
pub const ADMIN_SOCKET: &str = "/run/snitchhiker/admin.sock";
pub const AGENT_SOCKET: &str = "/run/snitchhiker/agent.sock";

static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static OPEN: AtomicU64 = AtomicU64::new(0);

/// How many clients are connected.
pub fn connected() -> u64 {
    OPEN.load(Ordering::Relaxed)
}

/// Binds both sockets and serves them on threads of their own.
pub fn spawn(daemon: &Arc<Daemon>) -> std::io::Result<()> {
    std::fs::create_dir_all(RUN_DIR)?;
    std::fs::set_permissions(RUN_DIR, std::fs::Permissions::from_mode(0o755))?;
    let config = &daemon.shared.config;
    let group = group_id(&config.client_group);
    if group.is_none() {
        warn!(group = %config.client_group, "the client group doesn't exist: the desktop app can't connect");
    }

    let client = bind(CLIENT_SOCKET, 0o660, group)?;
    {
        let daemon = Arc::clone(daemon);
        let access = Access::Client {
            group: group.unwrap_or(u32::MAX),
        };
        thread::Builder::new()
            .name("api-client".to_owned())
            .spawn(move || accept(&daemon, &client, &access))?;
    }
    let admin = bind(ADMIN_SOCKET, 0o600, Some(0))?;
    {
        let daemon = Arc::clone(daemon);
        thread::Builder::new()
            .name("api-admin".to_owned())
            .spawn(move || accept(&daemon, &admin, &Access::Admin))?;
    }
    // Anyone may open it: the agent role changes nothing (decision 0008).
    let agent = bind(AGENT_SOCKET, 0o666, Some(0))?;
    {
        let daemon = Arc::clone(daemon);
        thread::Builder::new()
            .name("api-agent".to_owned())
            .spawn(move || accept(&daemon, &agent, &Access::Agent))?;
    }
    if daemon.shared.config.remote {
        crate::remote::start(daemon)?;
    }
    Ok(())
}

fn bind(path: &str, mode: u32, group: Option<u32>) -> std::io::Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::os::unix::fs::chown(path, Some(0), group)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// The gid of a group, from the group database.
#[must_use]
pub fn group_id(name: &str) -> Option<u32> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name)
            .then(|| fields.nth(1)?.parse().ok())
            .flatten()
    })
}

/// Who a socket admits.
enum Access {
    /// Trusted client binaries, setgid to this group (the registry is read for every connection).
    Client {
        group: u32,
    },
    Admin,
    /// Any local process, as an agent.
    Agent,
}

fn accept(daemon: &Arc<Daemon>, listener: &UnixListener, access: &Access) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, "accepting a client");
                continue;
            }
        };
        let (caller, pidfd) = match admit(&stream, access, &daemon.shared.config) {
            Ok(admitted) => admitted,
            Err(reason) => {
                info!(%reason, "refused a client");
                refuse(&stream, &reason);
                continue;
            }
        };
        let daemon = Arc::clone(daemon);
        let _ = thread::Builder::new()
            .name("api-connection".to_owned())
            .spawn(move || {
                // Held until the connection ends; dropping it stops the watch.
                let _watch = match pidfd.map(|pidfd| end_with_process(pidfd, &stream)) {
                    Some(Err(error)) => {
                        warn!(%error, "watching a client's process; refusing it");
                        return;
                    }
                    Some(Ok(guard)) => Some(guard),
                    None => None,
                };
                OPEN.fetch_add(1, Ordering::Relaxed);
                if let Err(error) = serve(&daemon, &stream, &caller) {
                    debug!(%error, "client connection ended");
                }
                OPEN.fetch_sub(1, Ordering::Relaxed);
            });
    }
}

/// Who is on the other end of a connection.
pub(crate) struct Caller {
    pub(crate) role: v1::Role,
    /// The user (`u32::MAX` for a remote device).
    pub(crate) uid: u32,
    pub(crate) pid: u32,
    /// A client's process, for step-up (root's connections need none).
    pub(crate) pidfd: Option<OwnedFd>,
    /// On the agent socket: the agent behind the MCP server.
    pub(crate) agent: Option<crate::agents::Agent>,
    /// A remote device: its name and key.
    pub(crate) device: Option<(String, String)>,
}

/// Who a connection is, or why it is refused. For a client, also its process's pidfd: the connection ends when that
/// process does.
fn admit(
    stream: &UnixStream,
    access: &Access,
    config: &Config,
) -> Result<(Caller, Option<OwnedFd>), String> {
    match access {
        Access::Admin => {
            let credentials =
                getsockopt(stream, sockopt::PeerCredentials).map_err(|e| e.to_string())?;
            if credentials.uid() == 0 {
                let caller = Caller {
                    role: v1::Role::Root,
                    uid: 0,
                    pid: u32::try_from(credentials.pid()).unwrap_or(0),
                    pidfd: None,
                    agent: None,
                    device: None,
                };
                Ok((caller, None))
            } else {
                Err("the admin socket is root's".to_owned())
            }
        }
        Access::Client { group } => {
            let policy = crate::trust::policy(config, *group)
                .map_err(|e| format!("the trusted-client registry: {e}"))?;
            let (peer, pidfd) = identify(stream).map_err(|e| e.to_string())?;
            verify(&peer, &policy).map_err(|e| e.to_string())?;
            let caller = Caller {
                role: v1::Role::Admin,
                uid: peer.uid,
                pid: peer.pid,
                pidfd: Some(pidfd.try_clone().map_err(|e| e.to_string())?),
                agent: None,
                device: None,
            };
            Ok((caller, Some(pidfd)))
        }
        Access::Agent => {
            let (peer, pidfd) = identify(stream).map_err(|e| e.to_string())?;
            let agent = crate::agents::identify(&peer, &config.agent_programs)?;
            let caller = Caller {
                role: v1::Role::Agent,
                uid: peer.uid,
                pid: peer.pid,
                pidfd: None,
                agent: Some(agent),
                device: None,
            };
            Ok((caller, Some(pidfd)))
        }
    }
}

pub(crate) fn refuse(stream: &UnixStream, reason: &str) {
    let frame = v1::ServerFrame {
        body: Some(v1::server_frame::Body::Refusal(v1::Refusal {
            reason: reason.to_owned(),
        })),
    };
    let _ = frame::write(&mut &*stream, &frame, &mut Vec::new());
}

pub(crate) fn serve(
    daemon: &Arc<Daemon>,
    stream: &UnixStream,
    caller: &Caller,
) -> std::io::Result<()> {
    let role = caller.role;
    let connection = CONNECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut buffer = Vec::new();
    let major = frame::read_preamble(&mut reader)?;
    if major != MAJOR {
        refuse(
            stream,
            &format!("this node speaks protocol {MAJOR}, not {major}"),
        );
        return Ok(());
    }
    let hello: v1::ClientFrame = frame::read(&mut reader, &mut buffer)?;
    let Some(v1::client_frame::Body::Hello(hello)) = hello.body else {
        refuse(stream, "expected a hello");
        return Ok(());
    };
    debug!(app = %hello.app, version = %hello.app_version, ?role, "client connected");

    let (outbound, frames) = sync_channel::<v1::ServerFrame>(OUTBOUND);
    let outbox = Arc::new(Outbox::new(outbound));
    let writer = {
        let stream = stream.try_clone()?;
        thread::Builder::new()
            .name("api-writer".to_owned())
            .spawn(move || write_frames(stream, &frames))?
    };
    daemon.shared.hub.set_audience(
        connection,
        match (&caller.device, caller.role) {
            (Some((_, key)), _) => crate::hub::Audience::Device { id: key.clone() },
            (None, v1::Role::Admin | v1::Role::Viewer) => {
                crate::hub::Audience::Local { uid: caller.uid }
            }
            _ => crate::hub::Audience::Other,
        },
    );
    let welcome = v1::ServerFrame {
        body: Some(v1::server_frame::Body::Welcome(v1::Welcome {
            minor: MINOR,
            daemon_version: daemon.version().to_owned(),
            node_name: hostname(),
            node_epoch: daemon.store().epoch().unwrap_or(0),
            capabilities: vec!["prompts".to_owned()],
            role: role.into(),
        })),
    };
    let _ = outbox.send(welcome);
    let result = loop {
        let incoming: v1::ClientFrame = match frame::read(&mut reader, &mut buffer) {
            Ok(frame) => frame,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
            Err(error) => break Err(error),
        };
        let Some(v1::client_frame::Body::Request(request)) = incoming.body else {
            continue;
        };
        let id = request.id;
        let response = |result| v1::ServerFrame {
            body: Some(v1::server_frame::Body::Response(v1::Response {
                id,
                result: Some(result),
            })),
        };
        let sent = match handle(daemon, connection, caller, &hello.app, &outbox, request) {
            Reply::Result(result) => outbox.send(response(result)),
            // A block's dictionary is filled in as it is queued: see hub::Outbox.
            Reply::Block {
                columns,
                strings,
                scanned_from,
            } => outbox
                .send_block(&strings, true, |dictionary| {
                    response(v1::response::Result::EventBlock(v1::EventBlock {
                        columns,
                        dictionary: Some(dictionary),
                        scanned_from,
                    }))
                })
                .map_err(|_| crate::hub::Closed),
        };
        if sent.is_err() {
            break Ok(());
        }
    };
    daemon.shared.hub.forget(connection);
    drop(outbox);
    let _ = writer.join();
    result
}

fn write_frames(stream: UnixStream, frames: &Receiver<v1::ServerFrame>) {
    let mut out = BufWriter::new(stream);
    let mut buffer = Vec::new();
    // Everything already waiting is written before one flush, so bursts go out together.
    while let Ok(first) = frames.recv() {
        let mut next = Some(first);
        while let Some(frame) = next {
            if frame::write(&mut out, &frame, &mut buffer).is_err() {
                return;
            }
            next = frames.try_recv().ok();
        }
        if out.flush().is_err() {
            return;
        }
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map_or_else(|_| String::new(), |name| name.trim().to_owned())
}

fn error(code: v1::ErrorCode, message: impl Into<String>) -> v1::response::Result {
    v1::response::Result::Error(v1::Error {
        code: code.into(),
        message: message.into(),
    })
}

fn internal(error: impl std::fmt::Display) -> v1::response::Result {
    self::error(v1::ErrorCode::Internal, error.to_string())
}

/// Whether `role` may call `method`.
fn allowed(role: v1::Role, method: &v1::request::Method) -> bool {
    use v1::request::Method;
    let reads = matches!(
        method,
        Method::GetStatus(_)
            | Method::ListRules(_)
            | Method::ListEvents(_)
            | Method::Subscribe(_)
            | Method::Unsubscribe(_)
            | Method::ListPrompts(_)
            | Method::ExportRules(_)
            | Method::ListAudit(_)
            | Method::ListChanges(_)
            | Method::Explore(_)
            | Method::ListConnections(_)
            | Method::Explain(_)
            | Method::LintRules(_)
            | Method::GetPolicy(_)
            | Method::ListTrustedClients(_)
            | Method::GetSystemFirewall(_)
            | Method::ListAlerts(_)
            | Method::ListAlertRules(_)
    );
    let agents = matches!(
        method,
        Method::GetStatus(_)
            | Method::CheckConnection(_)
            | Method::RecentBlocked(_)
            | Method::ProposeRules(_)
            | Method::GetProposal(_)
            | Method::WithdrawProposal(_)
            | Method::AnnotatePending(_)
    );
    let reads = reads
        || matches!(
            method,
            Method::ListProposals(_)
                | Method::ListDevices(_)
                | Method::ListApprovals(_)
                // A device's own push target: any device may be woken.
                | Method::SetPushTarget(_)
        );
    match role {
        // The agent role's requests are about the caller's own agent: a person's client has none.
        v1::Role::Root | v1::Role::Admin => {
            !agents || matches!(method, Method::GetStatus(_) | Method::GetProposal(_))
        }
        v1::Role::Viewer => reads,
        v1::Role::Agent => agents,
        v1::Role::Unspecified => false,
    }
}

fn handle(
    daemon: &Arc<Daemon>,
    connection: u64,
    caller: &Caller,
    app: &str,
    outbox: &Arc<Outbox>,
    request: v1::Request,
) -> Reply {
    use v1::request::Method;
    use v1::response::Result as R;
    let role = caller.role;
    let Some(method) = request.method else {
        return Reply::Result(error(v1::ErrorCode::Unsupported, "unknown method"));
    };
    if !allowed(role, &method) {
        return Reply::Result(error(
            v1::ErrorCode::Forbidden,
            "not allowed for this connection",
        ));
    }
    Reply::Result(match method {
        Method::GetStatus(_) => R::Status(status(daemon)),
        Method::ListRules(_) => list_rules(daemon),
        Method::AddRule(add) => add_rule(daemon, caller, app, add),
        Method::DeleteRule(delete) => delete_rule(daemon, app, delete.id),
        Method::SetRuleEnabled(set) => set_rule_enabled(daemon, app, &set),
        Method::UpdateRule(update) => update_rule(daemon, caller, app, &update),
        Method::AddFolder(add) => add_folder(daemon, app, &add),
        Method::UpdateFolder(update) => update_folder(daemon, app, &update),
        Method::DeleteFolder(delete) => delete_folder(daemon, caller, app, delete),
        Method::ListChanges(list) => list_changes(daemon, &list),
        Method::Undo(request) => undo(daemon, app, request),
        Method::Explore(explore) => self::explore(daemon, &explore),
        Method::ListConnections(_) => match daemon.connections() {
            Ok(connections) => R::Connections(v1::ConnectionList { connections }),
            Err(e) => internal(e),
        },
        Method::KillConnection(kill) => kill_connection(daemon, &kill),
        Method::LintRules(lint) => lint_rules(daemon, lint),
        Method::GetPolicy(_) => match daemon.store().policy() {
            Ok(overrides) => R::Policy(crate::policy::wire(
                &daemon.shared.policy.load(),
                &overrides,
            )),
            Err(e) => internal(e),
        },
        Method::SetPolicy(set) => set_policy(daemon, caller, app, &set),
        Method::ListTrustedClients(_) => trusted_clients(&daemon.shared.config),
        Method::ListAlerts(list) => list_alerts(daemon, &list),
        Method::AcknowledgeAlerts(ack) => acknowledge_alerts(daemon, app, &ack),
        Method::ListAlertRules(_) => alert_rules(daemon),
        Method::PutAlertRule(put) => put_alert_rule(daemon, &put),
        Method::DeleteAlertRule(delete) => delete_alert_rule(daemon, delete.id),
        Method::GetSystemFirewall(_) => get_system_firewall(daemon),
        Method::SetSystemFirewall(set) => set_system_firewall(daemon, caller, app, &set),
        method @ (Method::CheckConnection(_)
        | Method::RecentBlocked(_)
        | Method::ProposeRules(_)
        | Method::GetProposal(_)
        | Method::WithdrawProposal(_)
        | Method::AnnotatePending(_)
        | Method::ListProposals(_)
        | Method::DecideProposal(_)) => agents(daemon, caller, app, method),
        method @ (Method::StartPairing(_)
        | Method::ListDevices(_)
        | Method::RemoveDevice(_)
        | Method::ListApprovals(_)
        | Method::DecideApproval(_)
        | Method::SetDeviceMuted(_)
        | Method::SetPushTarget(_)) => devices(daemon, caller, app, method),
        Method::ConfirmSystemFirewall(_) => confirm_system_firewall(daemon),
        Method::EditRules(edit) => edit_rules(daemon, caller, app, &edit),
        Method::Explain(explain) => match daemon.explain(explain.seq) {
            Ok(Some(explanation)) => R::Explanation(Box::new(explanation)),
            Ok(None) => error(v1::ErrorCode::NotFound, format!("no event {}", explain.seq)),
            Err(e) => internal(e),
        },
        Method::ListEvents(list) if list.columnar => return event_block(daemon, &list),
        Method::ListEvents(list) => list_events(daemon, &list),
        Method::Subscribe(subscribe) => self::subscribe(
            daemon,
            connection,
            outbox,
            caller.device.as_ref().map(|(_, key)| key.as_str()),
            &subscribe,
        ),
        Method::Unsubscribe(unsubscribe) => {
            if daemon
                .shared
                .hub
                .unsubscribe(connection, unsubscribe.subscription)
            {
                R::Done(v1::Done {})
            } else {
                error(v1::ErrorCode::NotFound, "no such subscription")
            }
        }
        Method::ListPrompts(_) => R::Prompts(v1::PromptList {
            prompts: daemon.shared.broker.list(),
        }),
        Method::AnswerPrompt(answer) => answer_prompt(daemon, caller, app, &answer),
        Method::Learn(learn) => self::learn(daemon, &learn),
        Method::ImportRules(import) => import_rules(daemon, caller, app, &import),
        Method::ListAudit(list) => list_audit(daemon, &list),
        Method::ExportRules(_) => export_rules(daemon),
    })
}

fn get_system_firewall(daemon: &Daemon) -> v1::response::Result {
    let firewall = daemon.store().system_firewall();
    match firewall {
        Ok(firewall) => v1::response::Result::SystemFirewall(crate::system::wire(
            &firewall,
            daemon.system_reverts_at(),
        )),
        Err(e) => internal(e),
    }
}

fn confirm_system_firewall(daemon: &Daemon) -> v1::response::Result {
    if daemon.confirm_system() {
        v1::response::Result::Done(v1::Done {})
    } else {
        error(v1::ErrorCode::NotFound, "no change waits to be confirmed")
    }
}

/// A block's columns and the strings they use.
type Block = (bytes::Bytes, Vec<(u32, Arc<str>)>);

/// What a request is answered with: a result, or a columnar block whose dictionary is filled in as it is queued.
enum Reply {
    Result(v1::response::Result),
    Block {
        columns: bytes::Bytes,
        strings: Vec<(u32, Arc<str>)>,
        scanned_from: i64,
    },
}

/// Rows and the strings they use, as a block.
fn block_of(daemon: &Daemon, rows: &[EventRow]) -> Result<Block, String> {
    let mut ids: Vec<u32> = rows.iter().flat_map(|r| [r.exe, r.host]).collect();
    ids.sort_unstable();
    ids.dedup();
    let strings = daemon.store().strings_of(ids).map_err(|e| e.to_string())?;
    let mut columns = Vec::new();
    columns::encode_events(rows, &mut columns).map_err(|e| e.to_string())?;
    Ok((bytes::Bytes::from(columns), strings))
}

/// `ListEvents` as a block: the newest events before `before`, oldest first.
fn event_block(daemon: &Daemon, list: &v1::ListEvents) -> Reply {
    let before = if list.before == 0 {
        i64::MAX
    } else {
        list.before
    };
    let limit = list.limit.clamp(1, 10_000);
    let rows = match event_filter(&list.query) {
        Err(e) => return Reply::Result(e),
        Ok(None) => daemon.store().event_rows(before, limit).map(|rows| {
            // Oldest first: the first row is where the next page starts.
            let scanned_from = match rows.first() {
                Some(oldest) if rows.len() >= limit as usize => oldest.seq,
                _ => 0,
            };
            (rows, scanned_from)
        }),
        Ok(Some(filter)) => daemon.store().event_rows_matching(before, limit, &filter),
    };
    match rows
        .map_err(|e| e.to_string())
        .and_then(|(rows, scanned_from)| {
            block_of(daemon, &rows).map(|(columns, strings)| (columns, strings, scanned_from))
        }) {
        Ok((columns, strings, scanned_from)) => Reply::Block {
            columns,
            strings,
            scanned_from,
        },
        Err(e) => Reply::Result(internal(e)),
    }
}

/// A history query compiled for this node (`None` for the empty one), or the error to answer with.
fn event_filter(query: &str) -> Result<Option<EventFilter>, v1::response::Result> {
    if query.trim().is_empty() {
        return Ok(None);
    }
    let cx = query::Context {
        now_ms: crate::runtime::now_ms(),
        uid_of: &crate::process::uid_of,
    };
    match EventFilter::parse(query, &cx) {
        Ok(filter) if filter.is_all() => Ok(None),
        Ok(filter) => Ok(Some(filter)),
        Err(e) => Err(error(
            v1::ErrorCode::Invalid,
            format!("query: {} (at {}..{})", e.message, e.span.start, e.span.end),
        )),
    }
}

fn add_rule(daemon: &Daemon, caller: &Caller, app: &str, add: v1::AddRule) -> v1::response::Result {
    let Some(wire) = add.rule else {
        return error(v1::ErrorCode::Invalid, "no rule");
    };
    let mut rule = match convert::rule_from(&wire) {
        Ok(rule) => rule,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    rule.id = 0;
    let scope = match scope_of(daemon, rule.folder) {
        Ok(scope) => scope,
        Err(e) => return internal(e),
    };
    if allows_everything(rule.action, rule.conditions.iter().chain(&scope))
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!(
                "add the rule \"{}\", which allows every program to connect anywhere",
                rule.name
            ),
        )
    {
        return refused;
    }
    match change(daemon, app, |store, batch| store.put_rule(&rule, batch)) {
        Ok(id) => v1::response::Result::RuleAdded(v1::RuleAdded { id }),
        Err(e) => e,
    }
}

/// Runs `apply` as one batch of `app`'s changes, all stored or none, then reloads the rules.
fn change<T>(
    daemon: &Daemon,
    app: &str,
    apply: impl FnOnce(&Store, &Batch) -> Result<T, StoreError>,
) -> Result<T, v1::response::Result> {
    let applied = {
        let mut store = daemon.store();
        store
            .batch(app, now_ms())
            .and_then(|batch| store.atomically(|store| apply(store, &batch)))
    };
    let value = applied.map_err(|e| match e {
        StoreError::NotFound(what, id) => error(v1::ErrorCode::NotFound, format!("no {what} {id}")),
        other => internal(other),
    })?;
    daemon.reload_rules().map_err(internal)?;
    Ok(value)
}

fn locked(id: u64) -> Option<v1::response::Result> {
    (id & crate::managed::MANAGED_ID != 0)
        .then(|| error(v1::ErrorCode::Locked, "a default or managed rule or folder"))
}

fn done<T>(result: Result<T, v1::response::Result>) -> v1::response::Result {
    result.map_or_else(|e| e, |_| v1::response::Result::Done(v1::Done {}))
}

fn delete_rule(daemon: &Daemon, app: &str, id: u64) -> v1::response::Result {
    if let Some(refused) = locked(id) {
        return refused;
    }
    done(change(daemon, app, |store, batch| {
        if store.remove_rule(id, batch)? {
            Ok(())
        } else {
            Err(StoreError::NotFound("rule", id))
        }
    }))
}

fn set_rule_enabled(daemon: &Daemon, app: &str, set: &v1::SetRuleEnabled) -> v1::response::Result {
    if let Some(refused) = locked(set.id) {
        return refused;
    }
    done(change(daemon, app, |store, batch| {
        let mut rule = store
            .rule(set.id)?
            .ok_or(StoreError::NotFound("rule", set.id))?;
        rule.enabled = set.enabled;
        store.put_rule(&rule, batch)
    }))
}

fn update_rule(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    update: &v1::UpdateRule,
) -> v1::response::Result {
    let Some(wire) = &update.rule else {
        return error(v1::ErrorCode::Invalid, "no rule");
    };
    if let Some(refused) = locked(wire.id) {
        return refused;
    }
    let rule = match convert::rule_from(wire) {
        Ok(rule) => rule,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    let scope = match scope_of(daemon, rule.folder) {
        Ok(scope) => scope,
        Err(e) => return internal(e),
    };
    if allows_everything(rule.action, rule.conditions.iter().chain(&scope))
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!(
                "change the rule \"{}\" to allow every program to connect anywhere",
                rule.name
            ),
        )
    {
        return refused;
    }
    done(change(daemon, app, |store, batch| {
        store.put_rule(&rule, batch)
    }))
}

fn add_folder(daemon: &Daemon, app: &str, add: &v1::AddFolder) -> v1::response::Result {
    let Some(wire) = &add.folder else {
        return error(v1::ErrorCode::Invalid, "no folder");
    };
    let mut folder = match convert::folder_from(wire) {
        Ok(folder) => folder,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    folder.id = 0;
    if let Some(refused) = folder.parent.and_then(locked) {
        return refused;
    }
    match change(daemon, app, |store, batch| store.put_folder(&folder, batch)) {
        Ok(id) => v1::response::Result::FolderAdded(v1::FolderAdded { id }),
        Err(e) => e,
    }
}

fn update_folder(daemon: &Daemon, app: &str, update: &v1::UpdateFolder) -> v1::response::Result {
    let Some(wire) = &update.folder else {
        return error(v1::ErrorCode::Invalid, "no folder");
    };
    if let Some(refused) = locked(wire.id).or_else(|| wire.parent.and_then(locked)) {
        return refused;
    }
    let folder = match convert::folder_from(wire) {
        Ok(folder) => folder,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    // A folder can't go below itself.
    let folders = match daemon.store().folders() {
        Ok(folders) => folders,
        Err(e) => return internal(e),
    };
    let mut next = folder.parent;
    for _ in 0..=folders.len() {
        match next {
            Some(id) if id == folder.id => {
                return error(v1::ErrorCode::Invalid, "a folder can't go inside itself");
            }
            Some(id) => next = folders.iter().find(|f| f.id == id).and_then(|f| f.parent),
            None => break,
        }
    }
    done(change(daemon, app, |store, batch| {
        store.put_folder(&folder, batch)
    }))
}

/// Deleting more rules than this at once is a dangerous action.
const DANGEROUS_DELETE: usize = 20;

fn list_alerts(daemon: &Daemon, list: &v1::ListAlerts) -> v1::response::Result {
    let before = if list.before == 0 {
        u64::MAX
    } else {
        list.before
    };
    let store = daemon.store();
    match store
        .alerts(before, list.limit.clamp(1, 500), list.open_only)
        .and_then(|alerts| Ok((alerts, store.open_alerts()?)))
    {
        Ok((alerts, open)) => v1::response::Result::Alerts(v1::AlertPage {
            alerts: alerts
                .iter()
                .map(crate::alerts::StoredAlert::wire)
                .collect(),
            open,
        }),
        Err(e) => internal(e),
    }
}

fn acknowledge_alerts(
    daemon: &Daemon,
    app: &str,
    ack: &v1::AcknowledgeAlerts,
) -> v1::response::Result {
    let store = daemon.store();
    let done = store
        .acknowledge_alerts(&ack.ids, ack.all, app)
        .and_then(|_| store.open_alerts());
    drop(store);
    match done {
        Ok(open) => {
            daemon.shared.hub.publish(
                v1::Topic::Alerts,
                &v1::notice::Body::AlertsChanged(v1::AlertsChanged { open }),
            );
            v1::response::Result::Done(v1::Done {})
        }
        Err(e) => internal(e),
    }
}

fn alert_rules(daemon: &Daemon) -> v1::response::Result {
    match daemon.store().alert_rules() {
        Ok(rules) => v1::response::Result::AlertRules(v1::AlertRules {
            rules: rules.iter().map(crate::alerts::AlertRule::wire).collect(),
        }),
        Err(e) => internal(e),
    }
}

fn delete_alert_rule(daemon: &Daemon, id: u64) -> v1::response::Result {
    // The store's lock is let go before the rules are listed again.
    let deleted = daemon.store().delete_alert_rule(id);
    match deleted {
        Ok(true) => {
            daemon.alert_rules_changed();
            alert_rules(daemon)
        }
        Ok(false) => error(v1::ErrorCode::NotFound, format!("no alert rule {id}")),
        Err(e) => internal(e),
    }
}

fn put_alert_rule(daemon: &Daemon, put: &v1::PutAlertRule) -> v1::response::Result {
    let Some(wire) = &put.rule else {
        return error(v1::ErrorCode::Invalid, "no rule");
    };
    let rule = match crate::alerts::AlertRule::from_wire(wire) {
        Ok(rule) => rule,
        Err(e) => return error(v1::ErrorCode::Invalid, e),
    };
    let stored = daemon.store().put_alert_rule(&rule);
    match stored {
        Ok(_) => {
            daemon.alert_rules_changed();
            alert_rules(daemon)
        }
        Err(StoreError::NotFound(what, id)) => {
            error(v1::ErrorCode::NotFound, format!("no {what} {id}"))
        }
        Err(e) => internal(e),
    }
}

/// A trial lasts at least this long (time to confirm) and at most this long.
const SYSTEM_TRIAL_SECS: std::ops::RangeInclusive<u32> = 10..=600;

fn set_system_firewall(
    daemon: &Arc<Daemon>,
    caller: &Caller,
    app: &str,
    set: &v1::SetSystemFirewall,
) -> v1::response::Result {
    let Some(wire) = &set.firewall else {
        return error(v1::ErrorCode::Invalid, "no firewall");
    };
    let firewall = match crate::system::from_wire(wire) {
        Ok(firewall) => firewall,
        Err(e) => return error(v1::ErrorCode::Invalid, e),
    };
    if set.revert_after_secs != 0 && !SYSTEM_TRIAL_SECS.contains(&set.revert_after_secs) {
        return error(v1::ErrorCode::Invalid, "a trial lasts 10 to 600 seconds");
    }
    let before = match daemon.store().system_firewall() {
        Ok(before) => before,
        Err(e) => return internal(e),
    };
    if crate::system::loosened(&before, &firewall)
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!(
                "change the system firewall so that it lets in what it kept out ({})",
                crate::system::describe(&before, &firewall)
            ),
        )
    {
        return refused;
    }
    let trial = (set.revert_after_secs != 0)
        .then(|| std::time::Duration::from_secs(u64::from(set.revert_after_secs)));
    match daemon.set_system(&firewall, app, trial) {
        Ok(reverts_at_ms) => {
            v1::response::Result::SystemFirewall(crate::system::wire(&firewall, reverts_at_ms))
        }
        Err(e) => error(
            v1::ErrorCode::Invalid,
            format!("the kernel refused it: {e}"),
        ),
    }
}

fn trusted_clients(config: &Config) -> v1::response::Result {
    let registered = match crate::trust::load(&crate::trust::registry_path(config)) {
        Ok(registered) => registered,
        Err(e) => return internal(e),
    };
    let digest_now = |path: &std::path::Path| {
        std::fs::File::open(path)
            .and_then(|mut file| crate::peer::sha256(&mut file))
            .ok()
            .map(|digest| {
                digest.iter().fold(String::new(), |mut hex, b| {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{b:02x}");
                    hex
                })
            })
    };
    let mut clients: Vec<v1::TrustedClient> = registered
        .iter()
        .map(|entry| v1::TrustedClient {
            path: entry.path.display().to_string(),
            sha256: entry.sha256.clone(),
            current: digest_now(&entry.path).is_some_and(|now| now == entry.sha256),
        })
        .collect();
    clients.extend(config.trusted_clients.iter().map(|path| v1::TrustedClient {
        path: path.display().to_string(),
        sha256: String::new(),
        current: path.exists(),
    }));
    v1::response::Result::TrustedClients(v1::TrustedClients { clients })
}

fn set_policy(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    set: &v1::SetPolicy,
) -> v1::response::Result {
    let before_overrides = match daemon.store().policy() {
        Ok(overrides) => overrides,
        Err(e) => return internal(e),
    };
    let overrides = match before_overrides.apply(set) {
        Ok(overrides) => overrides,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    let config = &daemon.shared.config;
    let before = crate::policy::Effective::of(config, &before_overrides);
    let after = crate::policy::Effective::of(config, &overrides);
    if before.loosened_by(&after)
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!(
                "change the policy so that blocked connections get through ({})",
                crate::policy::describe(&before, &after)
            ),
        )
    {
        return refused;
    }
    let what = crate::policy::describe(&before, &after);
    let stored = {
        let mut store = daemon.store();
        store
            .batch(app, now_ms())
            .and_then(|batch| store.atomically(|store| store.put_policy(&overrides, &what, &batch)))
    };
    if let Err(e) = stored {
        return internal(e);
    }
    match daemon.reload_policy() {
        Ok(effective) => {
            // Clients showing the status see the new mode and policy.
            daemon.shared.hub.publish(
                v1::Topic::Rules,
                &v1::notice::Body::RulesChanged(v1::RulesChanged {}),
            );
            v1::response::Result::Policy(crate::policy::wire(&effective, &overrides))
        }
        Err(e) => internal(e),
    }
}

fn lint_rules(daemon: &Daemon, lint: v1::LintRules) -> v1::response::Result {
    let managed = match crate::managed::Managed::load(
        daemon.shared.config.default_rules,
        &daemon.shared.config.rules_dir,
    ) {
        Ok(managed) => managed,
        Err(e) => return internal(e),
    };
    let loaded = {
        let store = daemon.store();
        store
            .rules()
            .and_then(|rules| Ok((rules, store.folders()?, store.rule_times()?)))
    };
    let (rules, mut folders, times) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => return internal(e),
    };
    folders.extend(managed.folders);
    let facts = crate::lint::Facts { times };
    v1::response::Result::LintReport(v1::LintReport {
        findings: crate::lint::report(
            &rules,
            &managed.rules,
            &folders,
            &facts,
            now_ms(),
            lint.unused_days,
        ),
    })
}

/// The dangerous actions among bulk edits: many deletions at once, or allowing everything.
fn edit_rules_step_up(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    edit: &v1::EditRules,
    action: Option<Action>,
) -> Result<(), v1::response::Result> {
    use v1::edit_rules::Edit;
    if matches!(edit.edit, Some(Edit::Delete(true)))
        && edit.ids.len() > DANGEROUS_DELETE
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!("delete {} rules", edit.ids.len()),
        )
    {
        return Err(refused);
    }
    if let Some(action) = action {
        let mut everything = false;
        for id in &edit.ids {
            let rule = match daemon.store().rule(*id) {
                Ok(Some(rule)) => rule,
                Ok(None) => return Err(error(v1::ErrorCode::NotFound, format!("no rule {id}"))),
                Err(e) => return Err(internal(e)),
            };
            let scope = match scope_of(daemon, rule.folder) {
                Ok(scope) => scope,
                Err(e) => return Err(internal(e)),
            };
            everything |= allows_everything(action, rule.conditions.iter().chain(&scope));
        }
        if everything
            && let Err(refused) = step_up(
                daemon,
                caller,
                app,
                "change rules to allow every program to connect anywhere",
            )
        {
            return Err(refused);
        }
    }
    Ok(())
}

fn edit_rules(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    edit: &v1::EditRules,
) -> v1::response::Result {
    use v1::edit_rules::Edit;
    let Some(change_wanted) = &edit.edit else {
        return error(v1::ErrorCode::Invalid, "no edit");
    };
    if edit.ids.is_empty() {
        return error(v1::ErrorCode::Invalid, "no rules");
    }
    if let Some(refused) = edit.ids.iter().find_map(|id| locked(*id)) {
        return refused;
    }
    let expiry = match change_wanted {
        Edit::Expires(duration) => {
            let now = now_ms();
            match v1::Duration::try_from(*duration).unwrap_or(v1::Duration::Unspecified) {
                v1::Duration::UntilRestart => Some(Expiry::UntilRestart),
                v1::Duration::Hour => Some(Expiry::At(now + 3_600_000)),
                v1::Duration::HalfDay => Some(Expiry::At(now + 43_200_000)),
                v1::Duration::Forever => Some(Expiry::Never),
                v1::Duration::Once | v1::Duration::Unspecified => {
                    return error(v1::ErrorCode::Invalid, "a rule can't expire once");
                }
            }
        }
        _ => None,
    };
    let action = match change_wanted {
        Edit::Action(action) => match convert::action_from(
            v1::Action::try_from(*action).unwrap_or(v1::Action::Unspecified),
        ) {
            Some(action) => Some(action),
            None => return error(v1::ErrorCode::Invalid, "no action"),
        },
        _ => None,
    };
    if let Err(refused) = edit_rules_step_up(daemon, caller, app, edit, action) {
        return refused;
    }
    if let Edit::Move(v1::MoveRules {
        folder: Some(folder),
    }) = change_wanted
        && let Some(refused) = locked(*folder)
    {
        return refused;
    }
    done(change(daemon, app, |store, batch| {
        for id in &edit.ids {
            if matches!(change_wanted, Edit::Delete(true)) {
                if !store.remove_rule(*id, batch)? {
                    return Err(StoreError::NotFound("rule", *id));
                }
                continue;
            }
            let mut rule = store.rule(*id)?.ok_or(StoreError::NotFound("rule", *id))?;
            match change_wanted {
                Edit::Enabled(enabled) => rule.enabled = *enabled,
                Edit::Move(to) => {
                    if let Some(folder) = to.folder
                        && store.folder(folder)?.is_none()
                    {
                        return Err(StoreError::NotFound("folder", folder));
                    }
                    rule.folder = to.folder;
                }
                Edit::Action(_) => rule.action = action.unwrap_or(rule.action),
                Edit::Expires(_) => rule.expiry = expiry.unwrap_or(rule.expiry),
                Edit::Delete(_) => {}
            }
            store.put_rule(&rule, batch)?;
        }
        Ok(())
    }))
}

fn delete_folder(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    delete: v1::DeleteFolder,
) -> v1::response::Result {
    let id = delete.id;
    if let Some(refused) = locked(id) {
        return refused;
    }
    // The rules it holds, below it included.
    let count = {
        let store = daemon.store();
        let folders = match store.folders() {
            Ok(folders) => folders,
            Err(e) => return internal(e),
        };
        let mut inside = vec![id];
        let mut index = 0;
        while let Some(&folder) = inside.get(index) {
            inside.extend(
                folders
                    .iter()
                    .filter(|f| f.parent == Some(folder))
                    .map(|f| f.id),
            );
            index += 1;
        }
        let mut count = 0;
        for folder in inside {
            match store.rules_in(folder) {
                Ok(rules) => count += rules.len(),
                Err(e) => return internal(e),
            }
        }
        count
    };
    if count > DANGEROUS_DELETE
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!("delete a folder of {count} rules"),
        )
    {
        return refused;
    }
    done(change(daemon, app, |store, batch| {
        store
            .remove_folder(id, batch)?
            .ok_or(StoreError::NotFound("folder", id))
    }))
}

fn list_changes(daemon: &Daemon, list: &v1::ListChanges) -> v1::response::Result {
    let before = if list.before == 0 {
        u64::MAX
    } else {
        list.before
    };
    match daemon.store().changes(before, list.limit.clamp(1, 1000)) {
        Ok(changes) => v1::response::Result::Changes(v1::ChangePage {
            changes: changes
                .into_iter()
                .map(|c| v1::Change {
                    id: c.id,
                    batch: c.batch,
                    time_ms: c.time_ms,
                    app: c.app,
                    what: c.what,
                })
                .collect(),
        }),
        Err(e) => internal(e),
    }
}

fn undo(daemon: &Daemon, app: &str, undo: v1::Undo) -> v1::response::Result {
    let undone = {
        let mut store = daemon.store();
        store
            .batch(app, now_ms())
            .map_err(UndoError::Store)
            .and_then(|batch| store.undo(undo.change, &batch))
    };
    match undone {
        Ok(_) => reload(daemon),
        Err(UndoError::NotFound(id)) => error(v1::ErrorCode::NotFound, format!("no change {id}")),
        Err(e @ UndoError::Changed(_)) => error(v1::ErrorCode::Invalid, e.to_string()),
        Err(UndoError::Store(e)) => internal(e),
    }
}

fn list_events(daemon: &Daemon, list: &v1::ListEvents) -> v1::response::Result {
    let before = if list.before == 0 {
        i64::MAX
    } else {
        list.before
    };
    let limit = list.limit.clamp(1, 1000);
    let store = daemon.store();
    let events =
        match event_filter(&list.query) {
            Err(e) => return e,
            Ok(None) => store.events(before, limit).map(|events| {
                let scanned_from = match events.last() {
                    Some(oldest) if events.len() >= limit as usize => oldest.seq,
                    _ => 0,
                };
                (events, scanned_from)
            }),
            Ok(Some(filter)) => store.event_rows_matching(before, limit, &filter).and_then(
                |(rows, scanned_from)| {
                    let mut events = Vec::with_capacity(rows.len());
                    for row in rows.iter().rev() {
                        events.extend(store.event(row.seq)?);
                    }
                    Ok((events, scanned_from))
                },
            ),
        };
    match events {
        Ok((events, scanned_from)) => v1::response::Result::Events(v1::EventPage {
            events: events.iter().map(event).collect(),
            scanned_from,
        }),
        Err(e) => internal(e),
    }
}

fn answer_prompt(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    answer: &v1::AnswerPrompt,
) -> v1::response::Result {
    let Some(action) = convert::action_from(answer.action()) else {
        return error(v1::ErrorCode::Invalid, "no action");
    };
    // The suggestions all name a program or a destination; conditions of the client's own may not.
    if let Some(conditions) = &answer.conditions
        && answer.duration() != v1::Duration::Once
    {
        let conditions = match convert::conditions_from(conditions).to_conditions() {
            Ok(conditions) => conditions,
            Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
        };
        if allows_everything(action, &conditions)
            && let Err(refused) = step_up(
                daemon,
                caller,
                app,
                "answer a prompt with a rule that allows every program to connect anywhere",
            )
        {
            return refused;
        }
    }
    let suggestion = usize::try_from(answer.suggestion).unwrap_or(usize::MAX);
    match daemon.answer_prompt(
        answer.id,
        action,
        answer.duration(),
        suggestion,
        answer.conditions.as_ref(),
        answer.folder,
        app,
    ) {
        Ok(_) => v1::response::Result::Done(v1::Done {}),
        Err(AnswerError::NotFound) => {
            error(v1::ErrorCode::NotFound, AnswerError::NotFound.to_string())
        }
        Err(AnswerError::Invalid(message)) => error(v1::ErrorCode::Invalid, message),
        Err(AnswerError::Runtime(e)) => internal(e),
    }
}

fn learn(daemon: &Daemon, learn: &v1::Learn) -> v1::response::Result {
    let since = now_ms().saturating_sub(u64::from(learn.hours.max(1)) * 3_600_000);
    let folder = if learn.folder.is_empty() {
        "Learned"
    } else {
        &learn.folder
    };
    let seen = daemon.store().undecided_since(since);
    match seen {
        Ok(seen) => rule_file(&crate::learn::suggest(
            &seen,
            folder,
            crate::process::home_of,
        )),
        Err(e) => internal(e),
    }
}

fn export_rules(daemon: &Daemon) -> v1::response::Result {
    let rules = daemon.store().rules();
    match rules {
        Ok(rules) => rule_file(&snitchhiker_core::spec::RuleFile {
            folder: None,
            rule: rules
                .iter()
                .map(snitchhiker_core::spec::RuleSpec::from_rule)
                .collect(),
        }),
        Err(e) => internal(e),
    }
}

fn rule_file(file: &snitchhiker_core::spec::RuleFile) -> v1::response::Result {
    match toml::to_string(file) {
        Ok(toml) => v1::response::Result::RuleFile(v1::RuleFile { toml }),
        Err(e) => internal(e),
    }
}

fn reload(daemon: &Daemon) -> v1::response::Result {
    // An undo may have put a policy or the system firewall back as well as rules.
    if let Err(e) = daemon.reload_policy() {
        return internal(e);
    }
    if let Err(e) = daemon.apply_system() {
        return internal(e);
    }
    match daemon.reload_rules() {
        Ok(_) => v1::response::Result::Done(v1::Done {}),
        Err(e) => internal(e),
    }
}

fn status(daemon: &Daemon) -> v1::Status {
    let config: &Config = &daemon.shared.config;
    let policy = daemon.shared.policy.load();
    // One lock of the store for both: two in one expression would deadlock (the first is held to its end).
    let (oldest_seq, open_alerts) = {
        let store = daemon.store();
        (
            store.oldest_seq().ok().flatten().unwrap_or(0),
            store.open_alerts().unwrap_or(0),
        )
    };
    v1::Status {
        daemon_version: daemon.version().to_owned(),
        mode: crate::policy::mode(policy.mode).into(),
        no_match: crate::policy::policy(policy.no_match).into(),
        fail_open: config.fail == crate::config::Fail::Open,
        decided: daemon.shared.decided.load(Ordering::Relaxed),
        dropped_events: daemon.shared.dropped_events.load(Ordering::Relaxed),
        rules: u32::try_from(daemon.shared.rules.load().len()).unwrap_or(u32::MAX),
        oldest_seq,
        open_alerts,
        pending_prompts: u32::try_from(daemon.shared.broker.count()).unwrap_or(u32::MAX),
        clients: u32::try_from(connected()).unwrap_or(u32::MAX),
    }
}

fn list_rules(daemon: &Daemon) -> v1::response::Result {
    let config = &daemon.shared.config;
    let managed = match crate::managed::Managed::load(config.default_rules, &config.rules_dir) {
        Ok(managed) => managed,
        Err(e) => return internal(e),
    };
    let store = daemon.store();
    let (folders, rules) = match (store.folders(), store.rules()) {
        (Ok(folders), Ok(rules)) => (folders, rules),
        (Err(e), _) | (_, Err(e)) => return internal(e),
    };
    drop(store);
    v1::response::Result::Rules(v1::RuleList {
        folders: folders
            .iter()
            .map(|f| convert::folder(f, false))
            .chain(managed.folders.iter().map(|f| convert::folder(f, true)))
            .collect(),
        rules: rules
            .iter()
            .map(|r| convert::rule(r, false))
            .chain(managed.rules.iter().map(|r| convert::rule(r, true)))
            .collect(),
    })
}

fn import_rules(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    import: &v1::ImportRules,
) -> v1::response::Result {
    let file: snitchhiker_core::spec::RuleFile = match toml::from_str(&import.toml) {
        Ok(file) => file,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    let name = file.folder.as_ref().map_or_else(
        || {
            if import.folder.is_empty() {
                "Imported".to_owned()
            } else {
                import.folder.clone()
            }
        },
        |f| f.name.clone(),
    );
    let scope = match &file.folder {
        Some(folder) => match folder.scope.to_conditions() {
            Ok(scope) => scope,
            Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
        },
        None => Vec::new(),
    };
    // Every rule is checked before anything is stored.
    let rules = match file
        .rule
        .iter()
        .map(|spec| spec.to_rule(0, None))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(rules) => rules,
        Err(e) => return error(v1::ErrorCode::Invalid, e.to_string()),
    };
    let everything = rules
        .iter()
        .filter(|rule| {
            rule.enabled && allows_everything(rule.action, rule.conditions.iter().chain(&scope))
        })
        .count();
    if everything > 0
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!(
                "import {everything} rule(s) into \"{name}\" that allow every program to connect anywhere"
            ),
        )
    {
        return refused;
    }
    done(change(daemon, app, |store, batch| {
        let folder = store.put_folder(
            &snitchhiker_core::rule::Folder {
                id: 0,
                parent: None,
                name,
                enabled: true,
                scope,
            },
            batch,
        )?;
        rules.into_iter().try_for_each(|mut rule| {
            rule.folder = Some(folder);
            store.put_rule(&rule, batch).map(|_| ())
        })
    }))
}

pub(crate) fn event(stored: &crate::store::StoredEvent) -> v1::ConnectionEvent {
    v1::ConnectionEvent {
        seq: stored.seq,
        time_ms: stored.time_ms,
        exe: stored.exe.clone(),
        host: stored.host.clone().unwrap_or_default(),
        uid: stored.uid,
        pid: stored.pid,
        protocol: u32::from(stored.protocol),
        address: convert::address(stored.address),
        port: u32::from(stored.port),
        context: match stored.context {
            1 => v1::Context::Container,
            2 => v1::Context::Vm,
            3 => v1::Context::Netns,
            _ => v1::Context::Host,
        }
        .into(),
        action: convert::action(stored.action).into(),
        source: match stored.source {
            1 => v1::Source::Rule,
            2 => v1::Source::Policy,
            3 => v1::Source::Monitor,
            4 => v1::Source::Prompt,
            5 => v1::Source::Timeout,
            _ => v1::Source::Unspecified,
        }
        .into(),
        rule: stored.rule,
        bytes_out: stored.bytes_out,
        bytes_in: stored.bytes_in,
    }
}

/// The conditions the folder `folder` and those above it add to their rules.
fn scope_of(daemon: &Daemon, folder: Option<u64>) -> Result<Vec<Condition>, crate::store::Error> {
    let Some(mut next) = folder else {
        return Ok(Vec::new());
    };
    let folders = daemon.store().folders()?;
    let mut scope = Vec::new();
    // A cycle can't be stored, but the walk is bounded anyway.
    for _ in 0..folders.len() {
        let Some(folder) = folders.iter().find(|f| f.id == next) else {
            break;
        };
        scope.extend(folder.scope.iter().cloned());
        match folder.parent {
            Some(parent) => next = parent,
            None => break,
        }
    }
    Ok(scope)
}

/// A dangerous action asked for by `caller`: goes ahead when root asks, when step-up is off, or when polkit authorizes
/// the client's process; otherwise the error to answer with. Every attempt is audited.
fn step_up(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    action: &str,
) -> Result<(), v1::response::Result> {
    let unchecked = caller.role == v1::Role::Root || daemon.shared.config.step_up == StepUp::Off;
    let outcome = if unchecked {
        v1::AuditOutcome::Unchecked
    } else if let Some((name, key)) = &caller.device {
        // A remote device: a local admin approves, or no one does.
        if approved_locally(daemon, name, key, action) {
            v1::AuditOutcome::Authorized
        } else {
            v1::AuditOutcome::Refused
        }
    } else {
        let message = format!("Authentication is required to {action}.");
        match caller
            .pidfd
            .as_ref()
            .map(|pidfd| crate::stepup::authorize(pidfd, caller.uid, &message))
        {
            Some(Ok(true)) => v1::AuditOutcome::Authorized,
            Some(Ok(false)) | None => v1::AuditOutcome::Refused,
            Some(Err(reason)) => {
                warn!(%reason, "step-up authorization couldn't be asked for; refused");
                v1::AuditOutcome::Refused
            }
        }
    };
    let entry = AuditEntry {
        id: 0,
        time_ms: now_ms(),
        app: app.to_owned(),
        uid: caller.uid,
        pid: caller.pid,
        action: action.to_owned(),
        outcome: u8::try_from(i32::from(outcome)).unwrap_or(0),
    };
    let recorded = daemon.store().audit(&entry);
    if let Err(error) = recorded {
        // An action that can't be audited doesn't happen.
        return Err(internal(format!("auditing: {error}")));
    }
    info!(
        app,
        uid = caller.uid,
        pid = caller.pid,
        action,
        ?outcome,
        "dangerous action"
    );
    if outcome != v1::AuditOutcome::Refused {
        daemon.raise(&crate::alerts::NewAlert {
            kind: "dangerous_action",
            title: format!("{app} was allowed to {action}"),
            body: format!(
                "uid {}, pid {}: {}",
                caller.uid,
                caller.pid,
                if outcome == v1::AuditOutcome::Authorized {
                    "authorized with polkit"
                } else {
                    "unchecked (root, or step-up off)"
                }
            ),
            rule: None,
        });
    }
    if outcome == v1::AuditOutcome::Refused {
        return Err(error(
            v1::ErrorCode::NotAuthorized,
            format!("not authorized to {action}"),
        ));
    }
    Ok(())
}

fn list_audit(daemon: &Daemon, list: &v1::ListAudit) -> v1::response::Result {
    let before = if list.before == 0 {
        u64::MAX
    } else {
        list.before
    };
    let page = daemon.store().audit_page(before, list.limit.clamp(1, 1000));
    match page {
        Ok(entries) => v1::response::Result::Audit(v1::AuditPage {
            entries: entries
                .into_iter()
                .map(|e| v1::AuditEntry {
                    id: e.id,
                    time_ms: e.time_ms,
                    app: e.app,
                    uid: e.uid,
                    pid: e.pid,
                    action: e.action,
                    outcome: i32::from(e.outcome),
                })
                .collect(),
        }),
        Err(e) => internal(e),
    }
}

/// The most stored events a subscription catches up with; further behind, the client pages with `ListEvents`.
const BACKFILL: u32 = 4000;

fn subscribe(
    daemon: &Daemon,
    connection: u64,
    outbox: &Arc<Outbox>,
    device: Option<&str>,
    subscribe: &v1::Subscribe,
) -> v1::response::Result {
    let topic = subscribe.topic();
    let columnar = subscribe.columnar && topic == v1::Topic::Events;
    let backfill = || -> Option<Vec<Outgoing>> {
        match (topic, subscribe.after) {
            (v1::Topic::Proposals, _) => Some(
                daemon
                    .store()
                    .proposals(Some(v1::ProposalState::Pending), 100)
                    .inspect_err(|error| warn!(%error, "reading proposals for a subscription"))
                    .ok()?
                    .into_iter()
                    .map(|p| Outgoing::Notice(v1::notice::Body::Proposal(Box::new(p))))
                    .collect(),
            ),
            (v1::Topic::Approvals, _) => Some(
                daemon
                    .approvals
                    .list()
                    .into_iter()
                    .map(|a| Outgoing::Notice(v1::notice::Body::Approval(a)))
                    .collect(),
            ),
            // Each says whether this client is to be told of it, as when it opened (a device woken for it is).
            (v1::Topic::Prompts, _) => Some(
                daemon
                    .shared
                    .broker
                    .list()
                    .into_iter()
                    .map(|prompt| {
                        let notify = daemon.shared.router.notifies_now(device, prompt.id);
                        Outgoing::Notice(v1::notice::Body::Prompt(v1::Prompt { notify, ..prompt }))
                    })
                    .collect(),
            ),
            (v1::Topic::Events, Some(after)) if columnar => {
                let rows = daemon.store().event_rows_after(after, BACKFILL + 1);
                let rows = rows
                    .inspect_err(|error| warn!(%error, "reading events for a subscription"))
                    .ok()?;
                if rows.len() > BACKFILL as usize {
                    return None;
                }
                if rows.is_empty() {
                    return Some(Vec::new());
                }
                let (columns, strings) = block_of(daemon, &rows)
                    .inspect_err(|error| warn!(%error, "an event block for a subscription"))
                    .ok()?;
                Some(vec![Outgoing::Block {
                    columns,
                    strings: Arc::from(strings),
                }])
            }
            (v1::Topic::Events, Some(after)) => {
                let events = match daemon.store().events_after(after, BACKFILL + 1) {
                    Ok(events) => events,
                    Err(error) => {
                        warn!(%error, "reading events for a subscription");
                        return None;
                    }
                };
                (events.len() <= BACKFILL as usize).then(|| {
                    events
                        .iter()
                        .map(|e| Outgoing::Notice(v1::notice::Body::Event(event(e))))
                        .collect()
                })
            }
            _ => Some(Vec::new()),
        }
    };
    if topic == v1::Topic::Unspecified {
        return error(v1::ErrorCode::Invalid, "no topic");
    }
    match daemon.shared.hub.subscribe_with(
        connection,
        topic,
        Arc::clone(outbox),
        columnar,
        backfill,
    ) {
        Ok(subscription) => v1::response::Result::Subscribed(v1::Subscribed { subscription }),
        Err(crate::hub::BackfillError::TooMuch) => error(
            v1::ErrorCode::Invalid,
            format!(
                "more than {BACKFILL} events since {}: page them with ListEvents, then subscribe from the newest",
                subscribe.after.unwrap_or_default()
            ),
        ),
        Err(crate::hub::BackfillError::Closed) => {
            error(v1::ErrorCode::Internal, "the connection closed")
        }
    }
}

fn dimension(dimension: v1::Dimension) -> Option<Dimension> {
    match dimension {
        v1::Dimension::Program => Some(Dimension::Exe),
        v1::Dimension::Host => Some(Dimension::Host),
        v1::Dimension::Port => Some(Dimension::Port),
        v1::Dimension::User => Some(Dimension::Uid),
        v1::Dimension::Unspecified => None,
    }
}

fn explore(daemon: &Daemon, explore: &v1::Explore) -> v1::response::Result {
    let Some(group) = dimension(explore.group_by()) else {
        return error(v1::ErrorCode::Invalid, "no dimension to group by");
    };
    let store = daemon.store();
    // A filter's value as the rollups hold it: a string's id, or the number. A name the history doesn't have
    // matches nothing.
    let filter = match &explore.filter {
        None => None,
        Some(filter) => {
            let Some(by) = dimension(filter.dimension()) else {
                return error(v1::ErrorCode::Invalid, "no dimension to filter by");
            };
            let value = match by {
                Dimension::Host if filter.value.is_empty() => Ok(Some(0)),
                Dimension::Exe => store.string_id(StringKind::Exe, &filter.value),
                Dimension::Host => store.string_id(StringKind::Host, &filter.value),
                Dimension::Port | Dimension::Uid => match filter.value.parse() {
                    Ok(number) => Ok(Some(number)),
                    Err(_) => return error(v1::ErrorCode::Invalid, "not a number"),
                },
            };
            match value {
                Ok(Some(value)) => Some((by, value)),
                Ok(None) => return v1::response::Result::Explored(v1::ExplorePage::default()),
                Err(e) => return internal(e),
            }
        }
    };
    let rows = store.explore(
        explore.from_ms / HOUR_MS,
        explore.to_ms.div_ceil(HOUR_MS),
        group,
        filter,
        explore.limit.clamp(1, 1000),
    );
    let rows = match rows {
        Ok(rows) => rows,
        Err(e) => return internal(e),
    };
    // Programs and hosts by name.
    let names = if matches!(group, Dimension::Exe | Dimension::Host) {
        match store.strings_of(rows.iter().filter_map(|r| u32::try_from(r.key).ok())) {
            Ok(names) => names,
            Err(e) => return internal(e),
        }
    } else {
        Vec::new()
    };
    v1::response::Result::Explored(v1::ExplorePage {
        rows: rows
            .iter()
            .map(|row| v1::ExploreRow {
                key: match group {
                    Dimension::Exe | Dimension::Host => u32::try_from(row.key)
                        .ok()
                        .and_then(|id| names.iter().find(|(i, _)| *i == id))
                        .map_or_else(String::new, |(_, name)| name.to_string()),
                    Dimension::Port | Dimension::Uid => row.key.to_string(),
                },
                allowed: row.allowed,
                blocked: row.blocked,
                bytes_out: row.bytes_out,
                bytes_in: row.bytes_in,
            })
            .collect(),
    })
}

fn kill_connection(daemon: &Daemon, kill: &v1::KillConnection) -> v1::response::Result {
    let (Some(local), Some(remote)) = (
        convert::address_from(&kill.local),
        convert::address_from(&kill.remote),
    ) else {
        return error(v1::ErrorCode::Invalid, "addresses are 4 or 16 bytes");
    };
    let (Ok(protocol), Ok(local_port), Ok(remote_port)) = (
        u8::try_from(kill.protocol),
        u16::try_from(kill.local_port),
        u16::try_from(kill.remote_port),
    ) else {
        return error(v1::ErrorCode::Invalid, "not a protocol or a port");
    };
    let id = snitchhiker_netfilter::sockdiag::SocketId {
        protocol,
        local,
        local_port,
        remote,
        remote_port,
    };
    match daemon.kill(&id) {
        Ok(()) => v1::response::Result::Done(v1::Done {}),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => error(
            v1::ErrorCode::NotFound,
            "no such connection (it may have closed)",
        ),
        Err(e) => internal(e),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Agents (decision 0008)

/// The agents' requests, and the proposals'.
fn agents(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    method: v1::request::Method,
) -> v1::response::Result {
    use v1::request::Method;
    match method {
        Method::CheckConnection(check) => check_connection(daemon, caller, &check),
        Method::RecentBlocked(_) => recent_blocked(daemon, caller),
        Method::ProposeRules(propose) => propose_rules(daemon, caller, &propose),
        Method::GetProposal(get) => get_proposal(daemon, caller, get),
        Method::WithdrawProposal(withdraw) => withdraw_proposal(daemon, caller, withdraw.id),
        Method::AnnotatePending(annotate) => annotate_pending(daemon, caller, &annotate),
        Method::ListProposals(list) => list_proposals(daemon, list),
        Method::DecideProposal(decide) => decide_proposal(daemon, caller, app, &decide),
        _ => error(v1::ErrorCode::Unsupported, "not an agent request"),
    }
}

/// The requests about remote devices: pairing, the devices, and their actions waiting for approval.
fn devices(
    daemon: &Arc<Daemon>,
    caller: &Caller,
    app: &str,
    method: v1::request::Method,
) -> v1::response::Result {
    use v1::request::Method;
    match method {
        Method::StartPairing(start) => start_pairing(daemon, caller, app, &start),
        Method::ListDevices(_) => crate::remote::list_devices(daemon),
        Method::RemoveDevice(remove) => crate::remote::remove_device(daemon, &remove.id),
        Method::ListApprovals(_) => v1::response::Result::Approvals(v1::ApprovalList {
            approvals: daemon.approvals.list(),
        }),
        Method::DecideApproval(decide) => decide_approval(daemon, caller, app, decide),
        Method::SetDeviceMuted(set) => {
            let muted = daemon.store().mute_device(&set.id, set.muted);
            match muted {
                Ok(true) => {
                    daemon.devices_changed();
                    v1::response::Result::Done(v1::Done {})
                }
                Ok(false) => error(v1::ErrorCode::NotFound, format!("no device {}", set.id)),
                Err(e) => internal(e),
            }
        }
        Method::SetPushTarget(set) => set_push_target(daemon, caller, &set),
        _ => error(v1::ErrorCode::Unsupported, "not a device request"),
    }
}

/// `SetPushTarget`: where the calling device is woken.
fn set_push_target(
    daemon: &Daemon,
    caller: &Caller,
    set: &v1::SetPushTarget,
) -> v1::response::Result {
    use snitchhiker_proto::prost::Message;
    let Some((_, device)) = &caller.device else {
        return error(
            v1::ErrorCode::Invalid,
            "only a paired device has a push target",
        );
    };
    let encoded = set
        .target
        .as_ref()
        .filter(|t| t.kind.is_some())
        .map(Message::encode_to_vec);
    // Bound first: the store's lock is released before devices_changed takes it again.
    let set = daemon.store().set_device_push(device, encoded.as_deref());
    match set {
        Ok(true) => {
            daemon.devices_changed();
            v1::response::Result::Done(v1::Done {})
        }
        Ok(false) => error(v1::ErrorCode::NotFound, "this device isn't paired"),
        Err(e) => internal(e),
    }
}

/// A remote device's dangerous action, put to the node's local admins: whether one approved it in time.
fn approved_locally(daemon: &Daemon, device: &str, key: &str, action: &str) -> bool {
    let now = now_ms();
    let approval = daemon.approvals.open(v1::Approval {
        id: 0,
        action: action.to_owned(),
        device: device.to_owned(),
        fingerprint: snitchhiker_remote::fingerprint(key),
        requested_ms: now,
        expires_ms: now + u64::try_from(crate::approvals::WAIT.as_millis()).unwrap_or(u64::MAX),
    });
    let id = approval.id;
    daemon
        .shared
        .hub
        .publish(v1::Topic::Approvals, &v1::notice::Body::Approval(approval));
    let approved = daemon.approvals.wait(id, crate::approvals::WAIT);
    daemon.shared.hub.publish(
        v1::Topic::Approvals,
        &v1::notice::Body::ApprovalResolved(v1::ApprovalResolved { id, approved }),
    );
    approved
}

/// `DecideApproval`: only a local client decides, and approving takes its own step-up.
fn decide_approval(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    decide: v1::DecideApproval,
) -> v1::response::Result {
    if caller.device.is_some() {
        return error(
            v1::ErrorCode::Forbidden,
            "a remote device can't approve: it takes a client on the node, or root",
        );
    }
    let Some(approval) = daemon
        .approvals
        .list()
        .into_iter()
        .find(|a| a.id == decide.id)
    else {
        return error(
            v1::ErrorCode::NotFound,
            format!("no request {} waits", decide.id),
        );
    };
    if decide.approve
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!("let {} {}", approval.device, approval.action),
        )
    {
        return refused;
    }
    if daemon.approvals.decide(decide.id, decide.approve) {
        v1::response::Result::Done(v1::Done {})
    } else {
        error(
            v1::ErrorCode::NotFound,
            format!("no request {} waits", decide.id),
        )
    }
}

/// `StartPairing`: a dangerous action (a device paired as admin can change everything).
fn start_pairing(
    daemon: &Arc<Daemon>,
    caller: &Caller,
    app: &str,
    start: &v1::StartPairing,
) -> v1::response::Result {
    if let Err(refused) = step_up(daemon, caller, app, "pair a new device") {
        return refused;
    }
    crate::remote::start_pairing(daemon, &start.name, start.role())
}

fn agent_of(caller: &Caller) -> Result<&crate::agents::Agent, v1::response::Result> {
    caller.agent.as_ref().ok_or_else(|| {
        error(
            v1::ErrorCode::Forbidden,
            "only an agent has its own processes",
        )
    })
}

fn check_connection(
    daemon: &Daemon,
    caller: &Caller,
    check: &v1::CheckConnection,
) -> v1::response::Result {
    use snitchhiker_core::engine::Facts;
    let agent = match agent_of(caller) {
        Ok(agent) => agent,
        Err(e) => return e,
    };
    let Ok(port) = u16::try_from(check.port) else {
        return error(v1::ErrorCode::Invalid, "a port is 0-65535");
    };
    let protocol = match check.protocol.as_str() {
        "" | "tcp" => 6,
        "udp" => 17,
        other => return error(v1::ErrorCode::Invalid, format!("`{other}`: tcp or udp")),
    };
    let host = check.host.trim().trim_end_matches('.').to_ascii_lowercase();
    let address: std::net::IpAddr = host
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let hosts: Vec<Arc<str>> = if host.parse::<std::net::IpAddr>().is_ok() || host.is_empty() {
        Vec::new()
    } else {
        vec![Arc::from(host.as_str())]
    };
    let home = crate::process::home_of(caller.uid);
    let lineage = [agent.anchor];
    let facts = Facts {
        exe: &check.exe,
        apps: &[],
        cmdline: "",
        ancestors: &[],
        lineage: &lineage,
        uid: caller.uid,
        home: home.as_deref(),
        hosts: &hosts,
        address,
        port,
        protocol,
        context: snitchhiker_core::rule::ContextKind::Host,
        now_ms: now_ms(),
    };
    let rules = daemon.shared.rules.load();
    if let Some(decision) = rules.decide(&facts) {
        let name = daemon
            .store()
            .rule(decision.rule)
            .ok()
            .flatten()
            .map_or_else(String::new, |r| r.name);
        return v1::response::Result::Checked(v1::CheckedConnection {
            action: convert::action(decision.action).into(),
            rule: name,
            asked: false,
        });
    }
    let policy = daemon.shared.policy.load();
    let asked = policy.no_match == crate::config::Policy::Ask;
    v1::response::Result::Checked(v1::CheckedConnection {
        action: if asked {
            v1::Action::Unspecified
        } else {
            convert::action(crate::runtime::policy_action(
                policy.no_match,
                policy.no_client,
            ))
        }
        .into(),
        rule: String::new(),
        asked,
    })
}

fn recent_blocked(daemon: &Daemon, caller: &Caller) -> v1::response::Result {
    let agent = match agent_of(caller) {
        Ok(agent) => agent,
        Err(e) => return e,
    };
    let blocked = daemon.shared.blocked.of(agent.anchor, now_ms());
    let broker = &daemon.shared.broker;
    v1::response::Result::Blocked(v1::BlockedList {
        connections: crate::agents::summarize(&blocked, &|id| broker.is_open(id)),
    })
}

fn publish_proposal(daemon: &Daemon, proposal: &v1::Proposal) {
    daemon.publish_proposal(proposal);
}

fn propose_rules(
    daemon: &Daemon,
    caller: &Caller,
    propose: &v1::ProposeRules,
) -> v1::response::Result {
    use crate::agents::{MAX_JUSTIFICATION, MAX_PENDING, MAX_RULES};
    let agent = match agent_of(caller) {
        Ok(agent) => agent,
        Err(e) => return e,
    };
    if propose.rules.is_empty() {
        return error(v1::ErrorCode::Invalid, "no rules proposed");
    }
    if propose.rules.len() > MAX_RULES {
        return error(
            v1::ErrorCode::Invalid,
            format!("at most {MAX_RULES} rules a proposal"),
        );
    }
    if propose.justification.chars().count() > MAX_JUSTIFICATION {
        return error(
            v1::ErrorCode::Invalid,
            format!("a justification is at most {MAX_JUSTIFICATION} characters"),
        );
    }
    if propose.justification.trim().is_empty() {
        return error(
            v1::ErrorCode::Invalid,
            "say why: the person approving reads it",
        );
    }
    let now = now_ms();
    let blocked = daemon.shared.blocked.of(agent.anchor, now);
    let rules = daemon.shared.rules.load();
    let broker = &daemon.shared.broker;
    let mut shaped = Vec::new();
    for (index, proposed) in propose.rules.iter().enumerate() {
        match crate::agents::shape(
            &crate::agents::proposed(proposed),
            &blocked,
            &|id| broker.is_open(id),
            &|b, _| crate::agents::decide_again(&rules, b, now),
        ) {
            Ok(rule) => shaped.push(rule),
            Err(refusal) => {
                return error(
                    v1::ErrorCode::Invalid,
                    format!("rule {}: refused: {refusal}", index + 1),
                );
            }
        }
    }
    let key = agent.anchor.to_string();
    let pending = match daemon
        .store()
        .agent_proposals(&key, v1::ProposalState::Pending)
    {
        Ok(pending) => pending,
        Err(e) => return internal(e),
    };
    // The same rules proposed again: the pending proposal is the answer.
    let conditions =
        |p: &[v1::ShapedRule]| p.iter().map(|r| r.conditions.clone()).collect::<Vec<_>>();
    if let Some(same) = pending
        .iter()
        .find(|p| conditions(&p.rules) == conditions(&shaped))
    {
        return v1::response::Result::Proposal(Box::new(same.clone()));
    }
    if pending.len() >= MAX_PENDING {
        return error(
            v1::ErrorCode::Invalid,
            format!(
                "{MAX_PENDING} proposals already wait for an answer: wait for them, or withdraw some"
            ),
        );
    }
    let broad = shaped
        .iter()
        .any(|r| !r.risks.is_empty() && !r.already_allowed);
    let mut proposal = v1::Proposal {
        id: 0,
        created_ms: now,
        state: v1::ProposalState::Pending.into(),
        provenance: Some(agent.provenance.clone()),
        justification: propose.justification.clone(),
        rules: shaped,
        broad,
        ..v1::Proposal::default()
    };
    if proposal.rules.iter().all(|r| r.already_allowed) {
        // Nothing to ask anyone: today's rules allow it all.
        return v1::response::Result::Proposal(Box::new(proposal));
    }
    let stored = daemon.store().insert_proposal(&proposal, &key);
    match stored {
        Ok(id) => proposal.id = id,
        Err(e) => return internal(e),
    }
    daemon.watch_agents([agent.anchor]);
    info!(id = proposal.id, agent = %agent.provenance.agent_exe, cwd = %agent.provenance.cwd, "an agent proposed rules");
    publish_proposal(daemon, &proposal);
    v1::response::Result::Proposal(Box::new(proposal))
}

/// A proposal the caller may see: an agent sees only its own.
fn visible_proposal(
    daemon: &Daemon,
    caller: &Caller,
    id: u64,
) -> Result<v1::Proposal, v1::response::Result> {
    let found = daemon.store().proposal(id).map_err(internal)?;
    let proposal =
        found.ok_or_else(|| error(v1::ErrorCode::NotFound, format!("no proposal {id}")))?;
    if let Some(agent) = &caller.agent {
        let own = proposal.provenance.as_ref().is_some_and(|p| {
            p.agent_pid == agent.anchor.pid && p.agent_start == agent.anchor.start
        });
        if !own {
            return Err(error(v1::ErrorCode::NotFound, format!("no proposal {id}")));
        }
    }
    Ok(proposal)
}

fn get_proposal(daemon: &Daemon, caller: &Caller, get: v1::GetProposal) -> v1::response::Result {
    let mut found = visible_proposal(daemon, caller, get.id);
    if get.wait_secs > 0 {
        let timeout = std::time::Duration::from_secs(u64::from(get.wait_secs.min(3600)));
        daemon.wait_for_proposals(timeout, || {
            let pending = matches!(&found, Ok(p) if p.state() == v1::ProposalState::Pending);
            if pending {
                found = visible_proposal(daemon, caller, get.id);
            }
            matches!(&found, Ok(p) if p.state() == v1::ProposalState::Pending)
        });
    }
    match found {
        Ok(proposal) => v1::response::Result::Proposal(Box::new(proposal)),
        Err(e) => e,
    }
}

fn withdraw_proposal(daemon: &Daemon, caller: &Caller, id: u64) -> v1::response::Result {
    let mut proposal = match visible_proposal(daemon, caller, id) {
        Ok(proposal) => proposal,
        Err(e) => return e,
    };
    if proposal.state() != v1::ProposalState::Pending {
        return error(v1::ErrorCode::Invalid, "it was answered already");
    }
    proposal.state = v1::ProposalState::Withdrawn.into();
    proposal.decided_ms = now_ms();
    let updated = daemon.store().update_proposal(&proposal);
    if let Err(e) = updated {
        return internal(e);
    }
    publish_proposal(daemon, &proposal);
    v1::response::Result::Proposal(Box::new(proposal))
}

fn annotate_pending(
    daemon: &Daemon,
    caller: &Caller,
    annotate: &v1::AnnotatePending,
) -> v1::response::Result {
    let agent = match agent_of(caller) {
        Ok(agent) => agent,
        Err(e) => return e,
    };
    if annotate.note.chars().count() > crate::agents::MAX_NOTE {
        return error(
            v1::ErrorCode::Invalid,
            format!("a note is at most {} characters", crate::agents::MAX_NOTE),
        );
    }
    // Only a prompt the agent's own process opened or joined.
    let own = daemon
        .shared
        .blocked
        .of(agent.anchor, now_ms())
        .iter()
        .any(|b| b.prompt == Some(annotate.prompt));
    if !own {
        return error(
            v1::ErrorCode::NotFound,
            format!(
                "no prompt {} of this agent's processes waits",
                annotate.prompt
            ),
        );
    }
    match daemon
        .shared
        .broker
        .annotate(annotate.prompt, annotate.note.trim())
    {
        Some(prompt) => {
            daemon
                .shared
                .hub
                .publish(v1::Topic::Prompts, &v1::notice::Body::Prompt(prompt));
            v1::response::Result::Done(v1::Done {})
        }
        None => error(
            v1::ErrorCode::NotFound,
            format!("prompt {} was answered", annotate.prompt),
        ),
    }
}

fn list_proposals(daemon: &Daemon, list: v1::ListProposals) -> v1::response::Result {
    let limit = if list.limit == 0 {
        100
    } else {
        list.limit.min(1000)
    };
    let state = list.pending_only.then_some(v1::ProposalState::Pending);
    match daemon.store().proposals(state, limit) {
        Ok(proposals) => v1::response::Result::Proposals(v1::ProposalList { proposals }),
        Err(e) => internal(e),
    }
}

fn decide_proposal(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    decide: &v1::DecideProposal,
) -> v1::response::Result {
    let mut proposal = match visible_proposal(daemon, caller, decide.id) {
        Ok(proposal) => proposal,
        Err(e) => return e,
    };
    if proposal.state() != v1::ProposalState::Pending {
        return error(
            v1::ErrorCode::Invalid,
            "it was answered, withdrawn or expired already",
        );
    }
    if decide.reason.chars().count() > crate::agents::MAX_JUSTIFICATION {
        return error(v1::ErrorCode::Invalid, "the reason is too long");
    }
    let now = now_ms();
    decide.reason.trim().clone_into(&mut proposal.reason);
    proposal.decided_ms = now;
    if !decide.approve {
        proposal.state = v1::ProposalState::Denied.into();
        let updated = daemon.store().update_proposal(&proposal);
        if let Err(e) = updated {
            return internal(e);
        }
        publish_proposal(daemon, &proposal);
        return v1::response::Result::Proposal(Box::new(proposal));
    }
    approve(daemon, caller, app, decide, proposal, now)
}

/// The rules approving `proposal` makes, with their indexes in it: as edited (shaped again, so their risks are
/// today's), or as proposed.
fn chosen_rules(
    daemon: &Daemon,
    decide: &v1::DecideProposal,
    proposal: &v1::Proposal,
    anchor: snitchhiker_core::rule::ProcessRef,
    now: u64,
) -> Result<Vec<(usize, v1::ShapedRule)>, v1::response::Result> {
    let blocked = daemon.shared.blocked.of(anchor, now);
    let rules_now = daemon.shared.rules.load();
    let broker = &daemon.shared.broker;
    let mut chosen: Vec<(usize, v1::ShapedRule)> = Vec::new();
    if decide.rules.is_empty() {
        chosen.extend(
            proposal
                .rules
                .iter()
                .enumerate()
                .filter(|(_, r)| !r.already_allowed)
                .map(|(i, r)| (i, r.clone())),
        );
    } else {
        for edited in &decide.rules {
            let index = edited.index as usize;
            if index >= proposal.rules.len() {
                return Err(error(
                    v1::ErrorCode::Invalid,
                    format!("no rule {index} in the proposal"),
                ));
            }
            let Some(conditions) = &edited.conditions else {
                return Err(error(
                    v1::ErrorCode::Invalid,
                    "an edited rule without conditions",
                ));
            };
            match crate::agents::shape(
                &crate::agents::proposed_from(conditions),
                &blocked,
                &|id| broker.is_open(id),
                &|b, _| crate::agents::decide_again(&rules_now, b, now),
            ) {
                Ok(shaped) => chosen.push((index, shaped)),
                Err(refusal) => {
                    return Err(error(
                        v1::ErrorCode::Invalid,
                        format!("rule {}: {refusal}", index + 1),
                    ));
                }
            }
        }
    }
    Ok(chosen)
}

/// Approves `proposal` as `decide` says: makes its rules (as edited) in its agent's folder.
fn approve(
    daemon: &Daemon,
    caller: &Caller,
    app: &str,
    decide: &v1::DecideProposal,
    mut proposal: v1::Proposal,
    now: u64,
) -> v1::response::Result {
    let Some(provenance) = proposal.provenance.clone() else {
        return internal("a proposal without provenance");
    };
    let anchor = snitchhiker_core::rule::ProcessRef {
        pid: provenance.agent_pid,
        start: provenance.agent_start,
    };
    let duration = match decide.duration() {
        v1::ProposalDuration::Unspecified => v1::ProposalDuration::Session,
        other => other,
    };
    if duration == v1::ProposalDuration::Session && !crate::agents::alive(anchor) {
        return error(
            v1::ErrorCode::Invalid,
            "the agent ended: its session's rules would never apply",
        );
    }
    let chosen = match chosen_rules(daemon, decide, &proposal, anchor, now) {
        Ok(chosen) => chosen,
        Err(e) => return e,
    };
    if chosen.is_empty() {
        return error(v1::ErrorCode::Invalid, "no rule to make");
    }
    // A marked rule (broad, or one nothing the agent tried matches) takes step-up.
    let mut risky: Vec<String> = chosen
        .iter()
        .flat_map(|(_, r)| r.risks.iter().map(|r| r.description.clone()))
        .collect();
    risky.dedup();
    if !risky.is_empty()
        && let Err(refused) = step_up(
            daemon,
            caller,
            app,
            &format!(
                "approve agent proposal {}, which allows {}",
                proposal.id,
                risky.join(", ")
            ),
        )
    {
        return refused;
    }
    let made = change(daemon, app, |store, batch| {
        let folder = crate::agents::folder(store, batch, &provenance)?;
        let mut ids = Vec::new();
        for (_, shaped) in &chosen {
            let conditions = convert::conditions_from(
                shaped
                    .conditions
                    .as_ref()
                    .unwrap_or(&v1::Conditions::default()),
            );
            let rule = crate::agents::rule(&conditions, folder, duration, anchor, proposal.id, now)
                .map_err(|e| StoreError::Corrupt {
                    what: "a proposed rule",
                    error: e.to_string(),
                })?;
            ids.push(store.put_rule(&rule, batch)?);
        }
        let path = store.folder_path(folder)?;
        Ok((ids, path))
    });
    let (ids, path) = match made {
        Ok(made) => made,
        Err(e) => return e,
    };
    for (index, shaped) in &chosen {
        if let Some(rule) = proposal.rules.get_mut(*index) {
            *rule = v1::ShapedRule {
                included: true,
                ..shaped.clone()
            };
        }
    }
    proposal.state = v1::ProposalState::Approved.into();
    proposal.duration = duration.into();
    proposal.rule_ids = ids;
    proposal.folder = path;
    let updated = daemon.store().update_proposal(&proposal);
    if let Err(e) = updated {
        return internal(e);
    }
    info!(
        id = proposal.id,
        rules = proposal.rule_ids.len(),
        "an agent's proposal was approved"
    );
    publish_proposal(daemon, &proposal);
    v1::response::Result::Proposal(Box::new(proposal))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewers_only_read_and_agents_do_nothing_here() {
        use v1::request::Method;
        assert!(allowed(
            v1::Role::Viewer,
            &Method::ListRules(v1::ListRules {})
        ));
        assert!(!allowed(
            v1::Role::Viewer,
            &Method::AddRule(v1::AddRule::default())
        ));
        assert!(!allowed(
            v1::Role::Viewer,
            &Method::AnswerPrompt(v1::AnswerPrompt::default())
        ));
        assert!(allowed(
            v1::Role::Admin,
            &Method::AnswerPrompt(v1::AnswerPrompt::default())
        ));
        assert!(!allowed(
            v1::Role::Agent,
            &Method::ListRules(v1::ListRules {})
        ));
    }

    #[test]
    fn reads_group_ids() {
        assert_eq!(group_id("root"), Some(0));
        assert_eq!(group_id("no-such-group-here"), None);
    }

    #[test]
    fn runs_dir_paths_are_consistent() {
        assert!(std::path::Path::new(CLIENT_SOCKET).starts_with(RUN_DIR));
        assert!(std::path::Path::new(ADMIN_SOCKET).starts_with(RUN_DIR));
    }
}
