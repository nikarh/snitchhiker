//! Paired devices over the network (plan §8.2, §8.3, decision 0016): pairing with one-time secrets, and the devices'
//! connections, served as local ones are and closed when a device is unpaired.
//!
//! The network itself is `snitchhiker-remote`'s, a service of its own (an unprivileged user, installed only where
//! remote access is wanted): the daemon carries no network stack for it. The bridge connects to the daemon's remote
//! socket, which serves its user alone (the kernel's peer credentials), and hands over each stream a peer opened, as a
//! file descriptor with the peer's id, which TLS proved. Everything else is decided here: whether the peer is a paired
//! device, what it may do, whether its pairing secret is right.
//!
//! A device is its key: only keys paired with the node are served. Pairing hands the node the device's key: the device
//! connects on the pairing ALPN and sends a one-time secret it got from a link, a QR code or a code (single use, 10
//! minutes, compared in constant time).

use std::collections::HashMap;
use std::io::BufReader;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use snitchhiker_client::packet::{PacketListener, Packets};
use snitchhiker_proto::{frame, v1};
use tracing::{info, warn};

use crate::runtime::{Daemon, now_ms};
use crate::store::Device;

/// Where the bridge connects.
pub const SOCKET: &str = "/run/snitchhiker/remote.sock";
/// The bridge's user (the `snitchhiker-remote` package makes it): the only one the remote socket serves.
pub const USER: &str = "snitchhiker-remote";

/// How long a pairing secret is valid.
const PAIRING_MS: u64 = 10 * 60 * 1000;
/// How long the bridge has to answer.
const ANSWER: Duration = Duration::from_secs(30);

/// A pairing started and not used yet.
struct Pairing {
    name: String,
    role: v1::Role,
    expires_ms: u64,
}

type Answer = (v1::BridgeReply, Option<OwnedFd>);

/// The bridge connected now.
pub struct Bridge {
    packets: Packets,
    node_id: String,
    /// Requests waiting for their answer, by id.
    waiting: Mutex<HashMap<u64, Sender<Answer>>>,
    next: AtomicU64,
}

impl Bridge {
    /// Asks the bridge, and waits for its answer.
    fn ask(&self, body: v1::node_frame::Body) -> Result<Answer, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, answer) = channel();
        lock(&self.waiting).insert(id, sender);
        let frame = v1::NodeFrame {
            id,
            body: Some(body),
        };
        if let Err(error) = self.packets.send(&frame, None) {
            lock(&self.waiting).remove(&id);
            return Err(format!("asking the remote service: {error}"));
        }
        let answer = answer.recv_timeout(ANSWER);
        lock(&self.waiting).remove(&id);
        let (reply, fd) = answer.map_err(|_| "the remote service didn't answer".to_owned())?;
        if reply.error.is_empty() {
            Ok((reply, fd))
        } else {
            Err(reply.error)
        }
    }

    fn tell(&self, body: v1::node_frame::Body) {
        let frame = v1::NodeFrame {
            id: 0,
            body: Some(body),
        };
        let _ = self.packets.send(&frame, None);
    }

    /// A stream to the push gateway.
    pub fn open_gateway(&self) -> std::io::Result<UnixStream> {
        let (_, fd) = self
            .ask(v1::node_frame::Body::OpenGateway(v1::OpenGateway {}))
            .map_err(std::io::Error::other)?;
        fd.map(UnixStream::from)
            .ok_or_else(|| std::io::Error::other("the remote service sent no stream"))
    }
}

/// The node's remote side: the bridge while connected, pairings waiting, and the devices' open connections.
#[derive(Default)]
pub struct Remote {
    bridge: Mutex<Option<Arc<Bridge>>>,
    pairings: Mutex<HashMap<String, Pairing>>,
    /// Each device's open connections, by a number of their own.
    connections: Mutex<HashMap<String, Vec<(u64, UnixStream)>>>,
    next: AtomicU64,
}

impl Remote {
    /// The bridge, if one is connected.
    pub fn bridge(&self) -> Option<Arc<Bridge>> {
        lock(&self.bridge).clone()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A key's fingerprint for people: its id's first 16 characters, in groups of four.
#[must_use]
pub fn fingerprint(id: &str) -> String {
    id.chars()
        .take(16)
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// A one-time secret: 128 random bits, base32 (lowercase, no padding).
fn secret() -> std::io::Result<String> {
    use std::io::Read as _;
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let letter = |index: u32| {
        ALPHABET
            .get((index & 31) as usize)
            .map_or('a', |b| char::from(*b))
    };
    let mut out = String::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(letter(buffer >> bits));
        }
    }
    if bits > 0 {
        out.push(letter(buffer << (5 - bits)));
    }
    Ok(out)
}

/// The bridge's user's id, if it exists.
#[must_use]
pub fn bridge_uid() -> Option<u32> {
    nix::unistd::User::from_name(USER)
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
}

/// Listens for the bridge: anyone may connect, only its user is served.
pub fn listen(daemon: &Arc<Daemon>, path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let listener = PacketListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let weak = Arc::downgrade(daemon);
    thread::Builder::new()
        .name("remote-bridge".to_owned())
        .spawn(move || {
            loop {
                let packets = match listener.accept() {
                    Ok(packets) => packets,
                    Err(error) => {
                        warn!(%error, "accepting the remote service");
                        continue;
                    }
                };
                let Some(daemon) = weak.upgrade() else {
                    return;
                };
                let pid = match admit(&daemon, &packets) {
                    Ok(pid) => pid,
                    Err(reason) => {
                        info!(%reason, "refused a connection to the remote socket");
                        continue;
                    }
                };
                let _ = thread::Builder::new()
                    .name("remote-session".to_owned())
                    .spawn(move || session(&daemon, &packets, pid));
            }
        })?;
    Ok(())
}

/// Whether `packets` is the bridge: its user's process, while no other bridge is connected.
fn admit(daemon: &Daemon, packets: &Packets) -> Result<u32, String> {
    let peer = packets.peer().map_err(|e| e.to_string())?;
    let user = bridge_uid();
    if user != Some(peer.uid) {
        return Err(format!(
            "uid {} isn't {USER}'s{}",
            peer.uid,
            if user.is_none() {
                " (no such user)"
            } else {
                ""
            }
        ));
    }
    if daemon.remote.bridge().is_some() {
        return Err("another remote service is connected".to_owned());
    }
    Ok(peer.pid)
}

/// One bridge's connection (its process `pid`), from its Hello until it ends.
fn session(daemon: &Arc<Daemon>, packets: &Packets, pid: u32) {
    let Ok(Some((
        v1::BridgeFrame {
            body: Some(v1::bridge_frame::Body::Hello(hello)),
        },
        _,
    ))) = packets.receive::<v1::BridgeFrame>()
    else {
        warn!("the remote service didn't say hello");
        return;
    };
    let sender = match packets.try_clone() {
        Ok(sender) => sender,
        Err(error) => {
            warn!(%error, "keeping the remote service's connection");
            return;
        }
    };
    let bridge = Arc::new(Bridge {
        packets: sender,
        node_id: hello.node_id.clone(),
        waiting: Mutex::default(),
        next: AtomicU64::new(1),
    });
    {
        let mut current = lock(&daemon.remote.bridge);
        if current.is_some() {
            warn!("another remote service is connected");
            return;
        }
        *current = Some(Arc::clone(&bridge));
        // Before the bridge has its endpoint: it binds it after its hello.
        daemon.shared.remote_pid.store(pid, Ordering::Relaxed);
    }
    info!(id = %hello.node_id, pid, "the remote service connected");
    bridge.tell(v1::node_frame::Body::Ready(v1::Ready {}));
    if hello.push_gateway
        && let Err(error) = daemon.shared.router.push.spawn(
            Arc::clone(&bridge),
            hostname(),
            hello.offline_after_secs,
        )
    {
        warn!(%error, "starting the push gateway's connection");
    }
    loop {
        let (frame, fd) = match packets.receive::<v1::BridgeFrame>() {
            Ok(Some(received)) => received,
            Ok(None) => break,
            Err(error) => {
                warn!(%error, "reading from the remote service");
                break;
            }
        };
        match frame.body {
            Some(v1::bridge_frame::Body::Accepted(accepted)) => {
                let Some(fd) = fd else { continue };
                let daemon = Arc::clone(daemon);
                let _ = thread::Builder::new()
                    .name("remote-connection".to_owned())
                    .spawn(move || serve(&daemon, &accepted, &UnixStream::from(fd)));
            }
            Some(v1::bridge_frame::Body::Reply(reply)) => {
                if let Some(waiting) = lock(&bridge.waiting).remove(&reply.id) {
                    let _ = waiting.send((reply, fd));
                }
            }
            Some(v1::bridge_frame::Body::CodeTried(tried)) => code_tried(daemon, &bridge, &tried),
            Some(v1::bridge_frame::Body::Leaving(_)) => {
                daemon.shared.router.push.stopping(leaving());
                bridge.tell(v1::node_frame::Body::Left(v1::Left {}));
            }
            Some(v1::bridge_frame::Body::Hello(_)) | None => {}
        }
    }
    info!("the remote service disconnected");
    {
        let mut current = lock(&daemon.remote.bridge);
        current.take();
        daemon.shared.remote_pid.store(0, Ordering::Relaxed);
    }
    // Requests waiting are answered: with nothing.
    lock(&bridge.waiting).clear();
    daemon.shared.router.push.end();
}

/// Why the node goes offline when its remote service stops. The service stops before the daemon (it is bound to it),
/// so the daemon may be stopping too: systemd's queued jobs say so.
fn leaving() -> &'static str {
    if crate::runtime::shutting_down() {
        return crate::runtime::SHUTDOWN;
    }
    let daemon_stopping = std::process::Command::new("systemctl")
        .args(["list-jobs", "--no-legend", "snitchhikerd.service"])
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|word| word == "stop")
        });
    if daemon_stopping {
        "the daemon was stopped (by an administrator, or for an upgrade)"
    } else {
        "the node's remote access was stopped (by an administrator, or for an upgrade)"
    }
}

fn serve(daemon: &Arc<Daemon>, accepted: &v1::BridgeAccepted, stream: &UnixStream) {
    if accepted.kind() == v1::StreamKind::Pairing {
        pair(daemon, &accepted.peer, stream);
        return;
    }
    let number = daemon
        .remote
        .next
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Looked up and registered under the connections' lock, which unpairing holds while it deletes the device: a
    // device unpaired meanwhile is either not found here, or its connection registered and shut by the unpairing.
    let device = {
        let mut connections = lock(&daemon.remote.connections);
        let device = daemon.store().device(&accepted.peer);
        let device = match device {
            Ok(Some(device)) => device,
            Ok(None) => {
                drop(connections);
                info!(peer = %accepted.peer, "refused a device that isn't paired");
                crate::api::refuse(stream, "this device isn't paired with the node");
                return;
            }
            Err(error) => {
                warn!(%error, "reading the paired devices");
                return;
            }
        };
        match stream.try_clone() {
            Ok(clone) => connections
                .entry(device.id.clone())
                .or_default()
                .push((number, clone)),
            Err(error) => {
                // A connection unpairing couldn't shut isn't served.
                warn!(%error, "keeping a device's connection");
                return;
            }
        }
        device
    };
    let seen = daemon.store().device_seen(&device.id, now_ms());
    if let Err(error) = seen {
        warn!(%error, "recording a device's connection");
    }
    let caller = crate::api::Caller {
        role: v1::Role::try_from(device.role).unwrap_or(v1::Role::Viewer),
        uid: u32::MAX,
        pid: 0,
        pidfd: None,
        agent: None,
        device: Some((device.name.clone(), device.id.clone())),
    };
    info!(device = %device.name, "a paired device connected");
    daemon.shared.router.push.connected(&device.id);
    if let Err(error) = crate::api::serve(daemon, stream, &caller) {
        tracing::debug!(%error, "a device's connection ended");
    }
    if let Some(open) = lock(&daemon.remote.connections).get_mut(&device.id) {
        open.retain(|(n, _)| *n != number);
    }
    // A connection that died (a phone killed, or losing its network) took prompts with it that it was told of.
    daemon
        .shared
        .router
        .device_left(&daemon.shared.hub, &daemon.shared.broker, &device.id);
}

/// A pairing code was tried: a wrong attempt spends the pairing, and is reported.
fn code_tried(daemon: &Daemon, bridge: &Bridge, tried: &v1::BridgeCodeTried) {
    bridge.tell(v1::node_frame::Body::Withdraw(v1::Withdraw {
        secret: tried.secret.clone(),
    }));
    if tried.right {
        return;
    }
    warn!("a pairing code was tried with the wrong words");
    lock(&daemon.remote.pairings).remove(&tried.secret);
    daemon.raise(&crate::alerts::NewAlert {
        kind: "pairing",
        title: "A device tried a pairing code with the wrong words".to_owned(),
        body: "The code is spent: start pairing again.".to_owned(),
        rule: None,
    });
}

/// Whether two secrets are equal, in time independent of where they differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// One pairing attempt: the device's frame, checked against the secrets waiting; the answer.
fn pair(daemon: &Daemon, peer: &str, stream: &UnixStream) {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    let Ok(request) = frame::read::<v1::PairRequest>(&mut reader, &mut buffer) else {
        return;
    };
    let now = now_ms();
    let found = {
        let mut pairings = lock(&daemon.remote.pairings);
        pairings.retain(|_, p| p.expires_ms > now);
        let secret = pairings.keys().find(|s| same(s, &request.secret)).cloned();
        // Single use: taken whatever happens next.
        secret.and_then(|s| pairings.remove(&s).map(|p| (s, p)))
    };
    // The same pairing's code goes too.
    let found = found.map(|(secret, pairing)| {
        if let Some(bridge) = daemon.remote.bridge() {
            bridge.tell(v1::node_frame::Body::Withdraw(v1::Withdraw { secret }));
        }
        pairing
    });
    let response = match found {
        None => {
            warn!(%peer, "a pairing attempt with a wrong or used secret");
            daemon.raise(&crate::alerts::NewAlert {
                kind: "pairing",
                title: "A device tried to pair with a wrong secret".to_owned(),
                body: format!(
                    "Device {} offered a pairing secret that is wrong, used or expired.",
                    fingerprint(peer)
                ),
                rule: None,
            });
            v1::PairResponse {
                error: "the pairing secret is wrong, used or expired".to_owned(),
                ..v1::PairResponse::default()
            }
        }
        Some(pairing) => {
            let name = if pairing.name.is_empty() {
                request.device_name.chars().take(64).collect()
            } else {
                pairing.name
            };
            let device = Device {
                id: peer.to_owned(),
                name: name.clone(),
                role: pairing.role.into(),
                paired_ms: now,
                last_seen_ms: 0,
                muted: false,
                push: None,
            };
            let stored = daemon.store().put_device(&device);
            match stored {
                Ok(()) => {
                    info!(%name, role = ?pairing.role, "a device was paired");
                    v1::PairResponse {
                        error: String::new(),
                        node_name: hostname(),
                        role: pairing.role.into(),
                    }
                }
                Err(error) => v1::PairResponse {
                    error: format!("storing the device: {error}"),
                    ..v1::PairResponse::default()
                },
            }
        }
    };
    let _ = frame::write(&mut &*stream, &response, &mut Vec::new());
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

/// `StartPairing`: a one-time secret, the link that carries it, and the same as a code.
pub fn start_pairing(daemon: &Arc<Daemon>, name: &str, role: v1::Role) -> v1::response::Result {
    let Some(bridge) = daemon.remote.bridge() else {
        return error(v1::ErrorCode::Invalid, NOT_RUNNING);
    };
    let role = match role {
        v1::Role::Viewer => v1::Role::Viewer,
        v1::Role::Admin | v1::Role::Unspecified => v1::Role::Admin,
        _ => return error(v1::ErrorCode::Invalid, "a device is an admin or a viewer"),
    };
    let secret = match secret() {
        Ok(secret) => secret,
        Err(e) => return error(v1::ErrorCode::Internal, e.to_string()),
    };
    let expires_ms = now_ms() + PAIRING_MS;
    lock(&daemon.remote.pairings).insert(
        secret.clone(),
        Pairing {
            name: name.chars().take(64).collect(),
            role,
            expires_ms,
        },
    );
    let offer = v1::Offer {
        secret: secret.clone(),
        name: hostname(),
        role: if role == v1::Role::Viewer {
            "viewer"
        } else {
            "admin"
        }
        .to_owned(),
        expires_ms,
    };
    let offered = match bridge.ask(v1::node_frame::Body::Offer(offer)) {
        Ok((reply, _)) => reply.offered.unwrap_or_default(),
        Err(reason) => {
            lock(&daemon.remote.pairings).remove(&secret);
            return error(v1::ErrorCode::Internal, reason);
        }
    };
    // Expired: the secret and its code go.
    let weak = Arc::downgrade(daemon);
    let _ = thread::Builder::new()
        .name("pairing-expiry".to_owned())
        .spawn(move || {
            thread::sleep(Duration::from_millis(PAIRING_MS));
            if let Some(daemon) = weak.upgrade() {
                lock(&daemon.remote.pairings).remove(&secret);
                if let Some(bridge) = daemon.remote.bridge() {
                    bridge.tell(v1::node_frame::Body::Withdraw(v1::Withdraw { secret }));
                }
            }
        });
    v1::response::Result::Pairing(v1::Pairing {
        link: offered.link,
        expires_ms,
        fingerprint: fingerprint(&offered.node_id),
        code: offered.code,
        node_id: offered.node_id,
    })
}

/// Why a node doesn't accept devices.
const NOT_RUNNING: &str = "the node's remote access isn't running: install snitchhiker-remote, then `systemctl enable --now snitchhiker-remote`";

pub fn list_devices(daemon: &Daemon) -> v1::response::Result {
    let devices = daemon.store().devices();
    let devices = match devices {
        Ok(devices) => devices,
        Err(e) => return error(v1::ErrorCode::Internal, e.to_string()),
    };
    let connections = lock(&daemon.remote.connections);
    let bridge = daemon.remote.bridge();
    let node_id = bridge
        .as_ref()
        .map_or_else(String::new, |bridge| bridge.node_id.clone());
    v1::response::Result::Devices(v1::DeviceList {
        devices: devices
            .into_iter()
            .map(|d| v1::Device {
                connected: connections.get(&d.id).is_some_and(|c| !c.is_empty()),
                fingerprint: fingerprint(&d.id),
                id: d.id,
                name: d.name,
                role: d.role,
                paired_ms: d.paired_ms,
                last_seen_ms: d.last_seen_ms,
                muted: d.muted,
                push: d.push.is_some(),
            })
            .collect(),
        fingerprint: fingerprint(&node_id),
        remote: bridge.is_some(),
        node_id,
    })
}

/// `RemoveDevice`: unpaired, and its connections closed.
pub fn remove_device(daemon: &Daemon, id: &str) -> v1::response::Result {
    // Under the connections' lock: a connection being admitted is either refused or registered and shut here.
    let mut connections = lock(&daemon.remote.connections);
    let removed = daemon.store().delete_device(id);
    let open = if matches!(removed, Ok(true)) {
        connections.remove(id).unwrap_or_default()
    } else {
        Vec::new()
    };
    drop(connections);
    match removed {
        Ok(true) => {
            for (_, stream) in open {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            info!(device = %id, "a device was unpaired");
            daemon.devices_changed();
            v1::response::Result::Done(v1::Done {})
        }
        Ok(false) => error(v1::ErrorCode::NotFound, format!("no device {id}")),
        Err(e) => error(v1::ErrorCode::Internal, e.to_string()),
    }
}
