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

use crate::config::{Config, Mode, Policy, StepUp};
use crate::hub::{OUTBOUND, Outbox, Outgoing};
use crate::peer::{end_with_process, identify, verify};
use crate::runtime::{AnswerError, Daemon, now_ms};
use crate::store::{
    AuditEntry, Batch, Dimension, Error as StoreError, HOUR_MS, Store, StringKind, UndoError,
};
use snitchhiker_core::query::{self, EventFilter};
use snitchhiker_core::rule::{Condition, allows_everything};
use snitchhiker_proto::columns::{self, EventRow};

pub const RUN_DIR: &str = "/run/snitchhiker";
pub const CLIENT_SOCKET: &str = "/run/snitchhiker/client.sock";
pub const ADMIN_SOCKET: &str = "/run/snitchhiker/admin.sock";

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
    let daemon = Arc::clone(daemon);
    thread::Builder::new()
        .name("api-admin".to_owned())
        .spawn(move || accept(&daemon, &admin, &Access::Admin))?;
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
struct Caller {
    role: v1::Role,
    uid: u32,
    pid: u32,
    /// A client's process, for step-up (root's connections need none).
    pidfd: Option<OwnedFd>,
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
            };
            Ok((caller, Some(pidfd)))
        }
    }
}

fn refuse(stream: &UnixStream, reason: &str) {
    let frame = v1::ServerFrame {
        body: Some(v1::server_frame::Body::Refusal(v1::Refusal {
            reason: reason.to_owned(),
        })),
    };
    let _ = frame::write(&mut &*stream, &frame, &mut Vec::new());
}

fn serve(daemon: &Arc<Daemon>, stream: &UnixStream, caller: &Caller) -> std::io::Result<()> {
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
    let welcome = v1::ServerFrame {
        body: Some(v1::server_frame::Body::Welcome(v1::Welcome {
            minor: MINOR,
            daemon_version: daemon.version().to_owned(),
            node_name: hostname(),
            node_epoch: 0,
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
    );
    match role {
        v1::Role::Root | v1::Role::Admin => true,
        v1::Role::Viewer => reads,
        v1::Role::Agent | v1::Role::Unspecified => false,
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
        Method::Explain(explain) => match daemon.explain(explain.seq) {
            Ok(Some(explanation)) => R::Explanation(Box::new(explanation)),
            Ok(None) => error(v1::ErrorCode::NotFound, format!("no event {}", explain.seq)),
            Err(e) => internal(e),
        },
        Method::ListEvents(list) if list.columnar => return event_block(daemon, &list),
        Method::ListEvents(list) => list_events(daemon, &list),
        Method::Subscribe(subscribe) => self::subscribe(daemon, connection, outbox, &subscribe),
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
    match daemon.reload_rules() {
        Ok(_) => v1::response::Result::Done(v1::Done {}),
        Err(e) => internal(e),
    }
}

fn status(daemon: &Daemon) -> v1::Status {
    let config: &Config = &daemon.shared.config;
    v1::Status {
        daemon_version: daemon.version().to_owned(),
        mode: match config.mode {
            Mode::Enforce => v1::Mode::Enforce,
            Mode::Monitor => v1::Mode::Monitor,
        }
        .into(),
        no_match: match config.no_match {
            Policy::Allow => v1::Policy::Allow,
            Policy::Deny => v1::Policy::Deny,
            Policy::Reject => v1::Policy::Reject,
            Policy::Ask => v1::Policy::Ask,
        }
        .into(),
        fail_open: config.fail == crate::config::Fail::Open,
        decided: daemon.shared.decided.load(Ordering::Relaxed),
        dropped_events: daemon.shared.dropped_events.load(Ordering::Relaxed),
        rules: u32::try_from(daemon.shared.rules.load().len()).unwrap_or(u32::MAX),
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
    subscribe: &v1::Subscribe,
) -> v1::response::Result {
    let topic = subscribe.topic();
    let columnar = subscribe.columnar && topic == v1::Topic::Events;
    let backfill = || -> Option<Vec<Outgoing>> {
        match (topic, subscribe.after) {
            (v1::Topic::Prompts, _) => Some(
                daemon
                    .shared
                    .broker
                    .list()
                    .into_iter()
                    .map(|prompt| Outgoing::Notice(v1::notice::Body::Prompt(prompt)))
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
