//! The push gateway (plan §8.4, §8.5): an iroh endpoint of its own, homed on this relay, that nodes keep a stream open
//! to (ALPN `snitchhiker-push/1`). On it a node says who to tell (its devices' push targets), who to wake, and why it
//! stops. The stream ending is the node going away; if it doesn't come back within its `offline_after_secs`, its
//! devices are told it is offline, and that it is back when it returns.
//!
//! What the gateway keeps, in its state file: each node's name, threshold and devices' push targets, so a node that
//! dies while the gateway restarts is still reported. Nothing about prompts, connections or rules ever reaches it.

use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use snitchhiker_proto::prost::Message;
use snitchhiker_proto::{frame, v1};
use snitchhiker_remote::{Accepted, Key, Listener, Options, PUSH_ALPN};
use tracing::{debug, info, warn};

use crate::fcm::Fcm;
use crate::webpush;

/// The `[push]` section of the relay's configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// This relay's own URL, as nodes reach it (`https://relay.example.org/`): the gateway's endpoint is homed here.
    pub url: String,
    /// The gateway's key (created on first start): nodes name the gateway by its id (`push_gateway`).
    pub key: PathBuf,
    /// Where the nodes' registrations are kept.
    pub state: PathBuf,
    /// Node ids that may use the gateway; none: any.
    pub allow: Vec<String>,
    /// A Firebase service account key (JSON), to push to the Play build of the app; none: FCM targets are skipped.
    pub fcm_service_account: Option<PathBuf>,
    /// Where FCM is (for tests).
    pub fcm_api: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: String::new(),
            key: PathBuf::from("/var/lib/snitchhiker-relay/push.key"),
            state: PathBuf::from("/var/lib/snitchhiker-relay/push.json"),
            allow: Vec::new(),
            fcm_service_account: None,
            fcm_api: "https://fcm.googleapis.com".to_owned(),
        }
    }
}

/// A node, as the gateway knows it.
#[derive(Default)]
struct Node {
    registration: v1::GatewayRegister,
    /// Its streams open now.
    streams: u32,
    /// Changes on each connection and disconnection: an offline check is for one disconnection only.
    generation: u64,
    /// What it said when it last stopped.
    stopping: Option<String>,
    /// Its devices were told it is offline.
    told_offline: bool,
}

pub struct Gateway {
    nodes: Mutex<HashMap<String, Node>>,
    state: PathBuf,
    allow: Vec<String>,
    http: reqwest::Client,
    fcm: Option<Arc<Fcm>>,
    runtime: tokio::runtime::Handle,
    /// Kept for the endpoint's life.
    listener: Mutex<Option<Listener>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The gateway's endpoint id, from its key (created if missing).
pub fn id(config: &Config) -> std::io::Result<String> {
    Ok(Key::load_or_create(&config.key)?.id())
}

impl Gateway {
    /// Starts the gateway: its endpoint, and the offline checks of the nodes it knew.
    pub fn start(config: &Config, runtime: tokio::runtime::Handle) -> Result<Arc<Self>, String> {
        if config.url.is_empty() {
            return Err("[push] needs url: this relay's URL, as nodes reach it".to_owned());
        }
        let fcm = config
            .fcm_service_account
            .as_deref()
            .map(|path| Fcm::load(path, &config.fcm_api).map(Arc::new))
            .transpose()
            .map_err(|e| e.to_string())?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        let gateway = Arc::new(Self {
            nodes: Mutex::new(load(&config.state)),
            state: config.state.clone(),
            allow: config.allow.clone(),
            http,
            fcm,
            runtime,
            listener: Mutex::new(None),
        });
        let key = Key::load_or_create(&config.key)
            .map_err(|e| format!("{}: {e}", config.key.display()))?;
        let options = Options {
            relays: vec![config.url.clone()],
            ..Options::default()
        };
        let weak = Arc::downgrade(&gateway);
        let listener = Listener::bind_for(&key, &options, &[PUSH_ALPN], move |accepted| {
            if let Some(gateway) = weak.upgrade() {
                let _ = std::thread::Builder::new()
                    .name("push-node".to_owned())
                    .spawn(move || gateway.serve(&accepted));
            }
        })
        .map_err(|e| e.to_string())?;
        info!(id = %listener.id(), nodes = lock(&gateway.nodes).len(), "push gateway serving");
        *lock(&gateway.listener) = Some(listener);
        // The nodes known from before: offline unless they connect in time.
        let known: Vec<(String, u64)> = lock(&gateway.nodes)
            .iter()
            .map(|(id, node)| (id.clone(), node.generation))
            .collect();
        for (id, generation) in known {
            gateway.check_later(&id, generation);
        }
        Ok(gateway)
    }

    /// Closes the gateway's endpoint (outside any runtime: it waits for its own).
    pub fn stop(&self) {
        let listener = lock(&self.listener).take();
        drop(listener);
    }

    fn serve(self: &Arc<Self>, accepted: &Accepted) {
        let id = accepted.peer.clone();
        if !self.allow.is_empty() && !self.allow.contains(&id) {
            info!(node = %id, "refused a node that isn't allowed on the push gateway");
            return;
        }
        let mut reader = BufReader::new(&accepted.stream);
        if frame::read_preamble(&mut reader).is_err() {
            return;
        }
        let mut buffer = Vec::new();
        let mut connected = false;
        while let Ok(frame) = frame::read::<v1::GatewayFrame>(&mut reader, &mut buffer) {
            match frame.body {
                Some(v1::gateway_frame::Body::Register(register)) => {
                    if !connected {
                        connected = true;
                        self.connected(&id);
                    }
                    self.register(&id, register);
                }
                Some(v1::gateway_frame::Body::Wake(wake)) => {
                    self.push(&id, &wake.devices, v1::PushKind::Wake, String::new());
                }
                Some(v1::gateway_frame::Body::Stopping(stopping)) => {
                    debug!(node = %id, reason = %stopping.reason, "a node stops");
                    if let Some(node) = lock(&self.nodes).get_mut(&id) {
                        node.stopping = Some(stopping.reason);
                    }
                }
                None => {}
            }
        }
        if connected {
            self.disconnected(&id);
        }
    }

    fn connected(&self, id: &str) {
        let back = {
            let mut nodes = lock(&self.nodes);
            let node = nodes.entry(id.to_owned()).or_default();
            node.streams += 1;
            node.generation += 1;
            node.stopping = None;
            std::mem::take(&mut node.told_offline)
        };
        info!(node = %id, "a node connected to the push gateway");
        if back {
            self.push_all(id, v1::PushKind::Online, String::new());
        }
    }

    fn register(&self, id: &str, register: v1::GatewayRegister) {
        {
            let mut nodes = lock(&self.nodes);
            if register.devices.is_empty() {
                // Nobody to tell: the node is forgotten (until it registers devices again).
                if let Some(node) = nodes.get_mut(id) {
                    node.registration = v1::GatewayRegister::default();
                }
            } else if let Some(node) = nodes.get_mut(id) {
                node.registration = register;
            }
        }
        self.save();
    }

    fn disconnected(self: &Arc<Self>, id: &str) {
        let generation = {
            let mut nodes = lock(&self.nodes);
            let Some(node) = nodes.get_mut(id) else {
                return;
            };
            node.streams = node.streams.saturating_sub(1);
            if node.streams > 0 {
                return;
            }
            node.generation += 1;
            node.generation
        };
        info!(node = %id, "a node left the push gateway");
        self.check_later(id, generation);
    }

    /// After the node's threshold: if it is still gone (the same disconnection), its devices are told.
    fn check_later(self: &Arc<Self>, id: &str, generation: u64) {
        let after = lock(&self.nodes)
            .get(id)
            .map_or(120, |n| n.registration.offline_after_secs);
        let after = Duration::from_secs(u64::from(if after == 0 { 120 } else { after }));
        let gateway = Arc::clone(self);
        let id = id.to_owned();
        self.runtime.spawn(async move {
            tokio::time::sleep(after).await;
            let reason = {
                let mut nodes = lock(&gateway.nodes);
                let Some(node) = nodes.get_mut(&id) else {
                    return;
                };
                if node.generation != generation || node.streams > 0 || node.told_offline {
                    return;
                }
                node.told_offline = true;
                node.stopping.clone().unwrap_or_default()
            };
            info!(node = %id, "a node is offline");
            gateway.push_all(&id, v1::PushKind::Offline, reason);
        });
    }

    fn push_all(&self, node: &str, kind: v1::PushKind, reason: String) {
        let devices: Vec<String> = lock(&self.nodes).get(node).map_or_default(|n| {
            n.registration
                .devices
                .iter()
                .map(|d| d.id.clone())
                .collect()
        });
        self.push(node, &devices, kind, reason);
    }

    /// Pushes to the node's `devices` (those it registered).
    fn push(&self, node: &str, devices: &[String], kind: v1::PushKind, reason: String) {
        let (name, targets) = {
            let nodes = lock(&self.nodes);
            let Some(known) = nodes.get(node) else {
                return;
            };
            let targets: Vec<(String, v1::PushTarget)> = known
                .registration
                .devices
                .iter()
                .filter(|d| devices.contains(&d.id))
                .filter_map(|d| Some((d.id.clone(), d.target.clone()?)))
                .collect();
            (known.registration.node_name.clone(), targets)
        };
        let payload = v1::PushMessage {
            node: node.to_owned(),
            kind: kind.into(),
            reason,
            node_name: name,
        }
        .encode_to_vec();
        for (device, target) in targets {
            let delivery = deliver(self.http.clone(), self.fcm.clone(), target, payload.clone());
            self.runtime.spawn(async move {
                match delivery.await {
                    Ok(()) => debug!(%device, ?kind, "pushed"),
                    Err(error) => warn!(%device, %error, "pushing to a device"),
                }
            });
        }
    }

    fn save(&self) {
        let saved: HashMap<String, String> = lock(&self.nodes)
            .iter()
            .filter(|(_, node)| !node.registration.devices.is_empty())
            .map(|(id, node)| {
                (
                    id.clone(),
                    STANDARD.encode(node.registration.encode_to_vec()),
                )
            })
            .collect();
        let written = serde_json::to_vec(&saved)
            .map_err(std::io::Error::other)
            .and_then(|bytes| write_private(&self.state, &bytes));
        if let Err(error) = written {
            warn!(%error, path = %self.state.display(), "saving the push registrations");
        }
    }
}

/// Sends one push: encrypted to a `UnifiedPush` endpoint, or through FCM.
async fn deliver(
    http: reqwest::Client,
    fcm: Option<Arc<Fcm>>,
    target: v1::PushTarget,
    payload: Vec<u8>,
) -> Result<(), String> {
    match target.kind {
        Some(v1::push_target::Kind::UnifiedPush(up)) => {
            let body = webpush::encrypt(
                &webpush::Keys {
                    p256dh: &up.p256dh,
                    auth: &up.auth,
                },
                &payload,
            )
            .map_err(|e| e.to_string())?;
            http.post(&up.endpoint)
                .header("content-encoding", "aes128gcm")
                .header("content-type", "application/octet-stream")
                // Kept a day by the push server for a device that is off; delivered at once to one that is on.
                .header("ttl", "86400")
                .header("urgency", "high")
                .body(body)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Some(v1::push_target::Kind::Fcm(fcm_token)) => match fcm {
            Some(fcm) => fcm
                .send(&http, &fcm_token.token, &payload)
                .await
                .map_err(|e| e.to_string()),
            None => Err("an FCM target, and no FCM service account".to_owned()),
        },
        None => Ok(()),
    }
}

/// Writes a file only its owner reads, replacing the old one at once.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
}

fn load(path: &Path) -> HashMap<String, Node> {
    let Ok(bytes) = std::fs::read(path) else {
        return HashMap::new();
    };
    let saved: HashMap<String, String> = serde_json::from_slice(&bytes).unwrap_or_default();
    saved
        .into_iter()
        .filter_map(|(id, encoded)| {
            let registration =
                v1::GatewayRegister::decode(STANDARD.decode(encoded).ok()?.as_slice()).ok()?;
            Some((
                id,
                Node {
                    registration,
                    ..Node::default()
                },
            ))
        })
        .collect()
}
