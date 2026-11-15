//! Paired devices over the network (plan §8.2, §8.3): the node's iroh endpoint, pairing with one-time secrets, and
//! the devices' connections, served as local ones are and closed when a device is unpaired.
//!
//! A device is its key: TLS proves the peer holds the key it connects with, and only keys paired with the node are
//! served. Pairing hands the node the device's key: the device connects on the pairing ALPN and sends a one-time
//! secret it got from a link or a QR code (single use, 10 minutes, compared in constant time).

use std::collections::HashMap;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;

use snitchhiker_proto::{frame, v1};
use snitchhiker_remote::code::{Code, Offer};
use snitchhiker_remote::{Accepted, Key, Listener, Options, PAIR_ALPN, PairLink};
use tracing::{info, warn};

use crate::runtime::{Daemon, now_ms};
use crate::store::Device;

/// How long a pairing secret is valid.
const PAIRING_MS: u64 = 10 * 60 * 1000;

/// A pairing started and not used yet.
struct Pairing {
    name: String,
    role: v1::Role,
    expires_ms: u64,
}

/// The node's remote side: its endpoint once started, pairings waiting, and the devices' open connections.
#[derive(Default)]
pub struct Remote {
    listener: OnceLock<Arc<Listener>>,
    pairings: Mutex<HashMap<String, Pairing>>,
    /// The codes offered, by their pairing's secret.
    offers: Mutex<HashMap<String, Offer>>,
    /// Each device's open connections, by a number of their own.
    connections: Mutex<HashMap<String, Vec<(u64, UnixStream)>>>,
    next: std::sync::atomic::AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where the node's key is: next to its database.
fn key_path(daemon: &Daemon) -> PathBuf {
    daemon
        .shared
        .config
        .database
        .parent()
        .map_or_else(|| PathBuf::from("node.key"), |dir| dir.join("node.key"))
}

/// Starts the node's endpoint.
pub fn start(daemon: &Arc<Daemon>) -> std::io::Result<()> {
    let key = Key::load_or_create(&key_path(daemon))?;
    let config = &daemon.shared.config;
    let options = options(config);
    let weak = Arc::downgrade(daemon);
    let listener = Listener::bind(&key, &options, move |accepted| {
        let Some(daemon) = weak.upgrade() else {
            return;
        };
        let _ = thread::Builder::new()
            .name("remote-connection".to_owned())
            .spawn(move || serve(&daemon, &accepted));
    })?;
    info!(id = %listener.id(), relays = ?config.relays, "remote endpoint started");
    let listener = Arc::new(listener);
    if !config.push_gateway.is_empty() {
        let gateway = snitchhiker_remote::NodeAddress {
            id: config.push_gateway.clone(),
            relays: config.relays.clone(),
            addrs: Vec::new(),
        };
        daemon.shared.router.push.spawn(
            Arc::clone(&listener),
            gateway,
            hostname(),
            config.offline_after_secs,
        )?;
    }
    let _ = daemon.remote.listener.set(listener);
    Ok(())
}

fn options(config: &crate::config::Config) -> Options {
    Options {
        relays: config.relays.clone(),
        port: config.remote_port,
        port_mapping: false,
        lan: config.lan_discovery,
    }
}

fn serve(daemon: &Arc<Daemon>, accepted: &Accepted) {
    if accepted.alpn == PAIR_ALPN {
        pair(daemon, &accepted.peer, &accepted.stream);
        return;
    }
    let device = daemon.store().device(&accepted.peer);
    let device = match device {
        Ok(Some(device)) => device,
        Ok(None) => {
            info!(peer = %accepted.peer, "refused a device that isn't paired");
            crate::api::refuse(&accepted.stream, "this device isn't paired with the node");
            return;
        }
        Err(error) => {
            warn!(%error, "reading the paired devices");
            return;
        }
    };
    let seen = daemon.store().device_seen(&device.id, now_ms());
    if let Err(error) = seen {
        warn!(%error, "recording a device's connection");
    }
    let number = daemon
        .remote
        .next
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(clone) = accepted.stream.try_clone() {
        lock(&daemon.remote.connections)
            .entry(device.id.clone())
            .or_default()
            .push((number, clone));
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
    if let Err(error) = crate::api::serve(daemon, &accepted.stream, &caller) {
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
    // The same pairing's code goes too (dropped here, with no lock held: closing it waits for its task).
    let found = found.map(|(secret, pairing)| {
        let offer = lock(&daemon.remote.offers).remove(&secret);
        drop(offer);
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
                    snitchhiker_remote::fingerprint(peer)
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

/// Offers `link` as a code too; a wrong attempt spends the pairing (and is reported). The code goes after the
/// pairing's time.
fn offer_code(daemon: &Arc<Daemon>, secret: &str, link: &PairLink) -> Option<Code> {
    let code = Code::generate().ok()?;
    let weak = Arc::downgrade(daemon);
    let spent = secret.to_owned();
    let offer = Offer::open(
        &code,
        &options(&daemon.shared.config),
        link.to_string(),
        move |right| {
            let Some(daemon) = weak.upgrade() else {
                return;
            };
            if !right {
                warn!("a pairing code was tried with the wrong words");
                lock(&daemon.remote.pairings).remove(&spent);
                daemon.raise(&crate::alerts::NewAlert {
                    kind: "pairing",
                    title: "A device tried a pairing code with the wrong words".to_owned(),
                    body: "The code is spent: start pairing again.".to_owned(),
                    rule: None,
                });
            }
        },
    );
    match offer {
        Ok(offer) => {
            lock(&daemon.remote.offers).insert(secret.to_owned(), offer);
            let weak = Arc::downgrade(daemon);
            let secret = secret.to_owned();
            let _ = thread::Builder::new()
                .name("pairing-expiry".to_owned())
                .spawn(move || {
                    thread::sleep(std::time::Duration::from_millis(PAIRING_MS));
                    if let Some(daemon) = weak.upgrade() {
                        let offer = lock(&daemon.remote.offers).remove(&secret);
                        drop(offer);
                        lock(&daemon.remote.pairings).remove(&secret);
                    }
                });
            Some(code)
        }
        Err(error) => {
            warn!(%error, "offering a pairing code");
            None
        }
    }
}

/// `StartPairing`: a one-time secret, the link that carries it, and the same as a code.
pub fn start_pairing(daemon: &Arc<Daemon>, name: &str, role: v1::Role) -> v1::response::Result {
    let Some(listener) = daemon.remote.listener.get() else {
        return error(
            v1::ErrorCode::Invalid,
            "the node doesn't accept devices: set remote = true in daemon.toml",
        );
    };
    let role = match role {
        v1::Role::Viewer => v1::Role::Viewer,
        v1::Role::Admin | v1::Role::Unspecified => v1::Role::Admin,
        _ => return error(v1::ErrorCode::Invalid, "a device is an admin or a viewer"),
    };
    let secret = match snitchhiker_remote::secret() {
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
    let node = listener.address();
    let link = PairLink {
        node: node.clone(),
        name: hostname(),
        secret: secret.clone(),
        role: if role == v1::Role::Viewer {
            "viewer"
        } else {
            "admin"
        }
        .to_owned(),
    };
    let code = offer_code(daemon, &secret, &link);
    v1::response::Result::Pairing(v1::Pairing {
        link: link.to_string(),
        expires_ms,
        fingerprint: snitchhiker_remote::fingerprint(&node.id),
        code: code.map_or_else(String::new, |c| c.to_string()),
        node_id: node.id,
    })
}

pub fn list_devices(daemon: &Daemon) -> v1::response::Result {
    let devices = daemon.store().devices();
    let devices = match devices {
        Ok(devices) => devices,
        Err(e) => return error(v1::ErrorCode::Internal, e.to_string()),
    };
    let connections = lock(&daemon.remote.connections);
    let node_id = daemon
        .remote
        .listener
        .get()
        .map_or_else(String::new, |listener| listener.id());
    v1::response::Result::Devices(v1::DeviceList {
        devices: devices
            .into_iter()
            .map(|d| v1::Device {
                connected: connections.get(&d.id).is_some_and(|c| !c.is_empty()),
                fingerprint: snitchhiker_remote::fingerprint(&d.id),
                id: d.id,
                name: d.name,
                role: d.role,
                paired_ms: d.paired_ms,
                last_seen_ms: d.last_seen_ms,
                muted: d.muted,
                push: d.push.is_some(),
            })
            .collect(),
        fingerprint: snitchhiker_remote::fingerprint(&node_id),
        remote: daemon.remote.listener.get().is_some(),
        node_id,
    })
}

/// `RemoveDevice`: unpaired, and its connections closed.
pub fn remove_device(daemon: &Daemon, id: &str) -> v1::response::Result {
    let removed = daemon.store().delete_device(id);
    match removed {
        Ok(true) => {
            for (_, stream) in lock(&daemon.remote.connections)
                .remove(id)
                .unwrap_or_default()
            {
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
