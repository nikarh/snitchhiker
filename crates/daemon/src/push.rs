//! The node's push gateway (plan §8.5): a `snitchhiker-relay` with its push service on, which wakes devices that are
//! asleep when a prompt waits for them, and tells them when the node goes offline. The node keeps one stream open to
//! it (ALPN `snitchhiker-push/1`) for as long as it runs: the stream ending is how the gateway knows the node is gone,
//! exactly, with no heartbeats to count. On it the node says who to tell (each device's push target, again on each
//! change), who to wake, and why it stops, when it does.
//!
//! The gateway learns the devices' push targets and when the node needs them. It learns nothing about prompts,
//! connections or rules: a wake-up says only "connect".

use std::collections::HashMap;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use snitchhiker_proto::prost::Message;
use snitchhiker_proto::{frame, v1};
use snitchhiker_remote::{Listener, NodeAddress, PUSH_ALPN};
use tracing::{debug, info, warn};

/// What the gateway connection's thread is told.
enum Event {
    /// The devices' targets changed: register again.
    Changed,
    /// Wake these devices.
    Wake(Vec<String>),
    /// The node stops, for this reason: the last frame.
    Stopping(String, Sender<()>),
    /// The stream to the gateway ended.
    Lost,
}

/// The push side of the router: the devices that can be woken, and the gateway connection's thread.
#[derive(Default)]
pub struct Push {
    /// The devices' push targets, by device id.
    targets: Mutex<HashMap<String, v1::PushTarget>>,
    events: Mutex<Option<Sender<Event>>>,
    /// The gateway is connected and has the targets.
    up: AtomicBool,
    /// When each device was last woken.
    woken: Mutex<HashMap<String, Instant>>,
}

/// How long a wake-up holds for: a woken device connects within seconds.
const WAKE_AGAIN: Duration = Duration::from_secs(30);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Push {
    fn send(&self, event: Event) {
        if let Some(events) = lock(&self.events).as_ref() {
            let _ = events.send(event);
        }
    }

    /// The devices' push targets (from the store, at start and on each change).
    pub fn set_targets(&self, targets: HashMap<String, v1::PushTarget>) {
        *lock(&self.targets) = targets;
        self.send(Event::Changed);
    }

    /// Whether `device` can be woken now.
    pub fn can_wake(&self, device: &str) -> bool {
        self.up.load(Ordering::Relaxed) && lock(&self.targets).contains_key(device)
    }

    /// The devices that can be woken now.
    pub fn wakeable(&self) -> Vec<String> {
        if !self.up.load(Ordering::Relaxed) {
            return Vec::new();
        }
        lock(&self.targets).keys().cloned().collect()
    }

    /// Wakes devices (those with a target; the others are skipped by the gateway). A device woken within the last
    /// [`WAKE_AGAIN`] isn't woken again: it is connecting, and will be sent everything that waits.
    pub fn wake(&self, devices: Vec<String>) {
        let now = Instant::now();
        let devices: Vec<String> = {
            let mut woken = lock(&self.woken);
            woken.retain(|_, at| now.duration_since(*at) < WAKE_AGAIN);
            devices
                .into_iter()
                .filter(|d| {
                    let fresh = !woken.contains_key(d);
                    if fresh {
                        woken.insert(d.clone(), now);
                    }
                    fresh
                })
                .collect()
        };
        if !devices.is_empty() {
            debug!(?devices, "waking devices through the push gateway");
            self.send(Event::Wake(devices));
        }
    }

    /// Tells the gateway why the node stops, and waits (briefly) for the frame to leave.
    pub fn stopping(&self, reason: &str) {
        let (done, wait) = channel();
        self.send(Event::Stopping(reason.to_owned(), done));
        let _ = wait.recv_timeout(Duration::from_secs(1));
    }

    /// Starts the gateway connection's thread: it connects through the listener's endpoint, registers, and reconnects
    /// when the stream ends.
    pub fn spawn(
        self: &Arc<Self>,
        listener: Arc<Listener>,
        gateway: NodeAddress,
        node_name: String,
        offline_after_secs: u32,
    ) -> std::io::Result<()> {
        let (sender, receiver) = channel();
        *lock(&self.events) = Some(sender.clone());
        let push = Arc::clone(self);
        thread::Builder::new()
            .name("push-gateway".to_owned())
            .spawn(move || {
                push.run(
                    &listener,
                    &gateway,
                    &node_name,
                    offline_after_secs,
                    &sender,
                    &receiver,
                );
            })?;
        Ok(())
    }

    fn register(&self, node_name: &str, offline_after_secs: u32) -> v1::GatewayFrame {
        let devices = lock(&self.targets)
            .iter()
            .map(|(id, target)| v1::GatewayDevice {
                id: id.clone(),
                target: Some(target.clone()),
            })
            .collect();
        v1::GatewayFrame {
            body: Some(v1::gateway_frame::Body::Register(v1::GatewayRegister {
                node_name: node_name.to_owned(),
                offline_after_secs,
                devices,
            })),
        }
    }

    fn run(
        &self,
        listener: &Listener,
        gateway: &NodeAddress,
        node_name: &str,
        offline_after_secs: u32,
        sender: &Sender<Event>,
        events: &Receiver<Event>,
    ) {
        // Waits between attempts, doubling up to a minute.
        let mut retry = Duration::from_secs(1);
        // The gateway is reached through the relays: once the endpoint has one.
        let _ = listener.address();
        loop {
            let connected = listener.open(gateway, PUSH_ALPN).and_then(|stream| {
                self.serve(stream, node_name, offline_after_secs, sender, events)
            });
            self.up.store(false, Ordering::Relaxed);
            match connected {
                Ok(Served::Stopped) => return,
                Ok(Served::Lost) => retry = Duration::from_secs(1),
                Err(error) => info!(%error, retry_in = ?retry, "connecting to the push gateway"),
            }
            // Until the next attempt: only stopping matters (registering happens on connecting anyway, and a wake-up
            // missed is made up for by the prompt waiting when the device connects).
            match events.recv_timeout(retry) {
                Ok(Event::Stopping(_, done)) => {
                    let _ = done.send(());
                    return;
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            retry = (retry * 2).min(Duration::from_secs(60));
        }
    }

    fn serve(
        &self,
        stream: UnixStream,
        node_name: &str,
        offline_after_secs: u32,
        sender: &Sender<Event>,
        events: &Receiver<Event>,
    ) -> std::io::Result<Served> {
        let mut writer = stream.try_clone()?;
        // Shut down when the node stops: the watch below holds the stream too, and the gateway must see it end.
        let ending = stream.try_clone()?;
        let mut buffer = Vec::new();
        frame::write_preamble(&mut writer)?;
        frame::write(
            &mut writer,
            &self.register(node_name, offline_after_secs),
            &mut buffer,
        )?;
        // The gateway sends nothing: reading only notices the stream ending.
        {
            let sender = sender.clone();
            thread::Builder::new()
                .name("push-gateway-watch".to_owned())
                .spawn(move || {
                    let mut reader = BufReader::new(stream);
                    let mut buffer = Vec::new();
                    while frame::read::<v1::GatewayFrame>(&mut reader, &mut buffer).is_ok() {}
                    let _ = sender.send(Event::Lost);
                })?;
        }
        self.up.store(true, Ordering::Relaxed);
        info!("connected to the push gateway");
        loop {
            let event = events
                .recv()
                .map_err(|_| std::io::Error::other("the daemon is gone"))?;
            let frame = match event {
                Event::Changed => self.register(node_name, offline_after_secs),
                Event::Wake(devices) => v1::GatewayFrame {
                    body: Some(v1::gateway_frame::Body::Wake(v1::GatewayWake { devices })),
                },
                Event::Stopping(reason, done) => {
                    let frame = v1::GatewayFrame {
                        body: Some(v1::gateway_frame::Body::Stopping(v1::Stopping { reason })),
                    };
                    let _ = frame::write(&mut writer, &frame, &mut buffer);
                    let _ = ending.shutdown(std::net::Shutdown::Both);
                    let _ = done.send(());
                    return Ok(Served::Stopped);
                }
                Event::Lost => {
                    warn!("the push gateway connection ended");
                    return Ok(Served::Lost);
                }
            };
            frame::write(&mut writer, &frame, &mut buffer)?;
        }
    }
}

enum Served {
    Stopped,
    Lost,
}

/// Decodes a stored push target.
#[must_use]
pub fn target(encoded: &[u8]) -> Option<v1::PushTarget> {
    v1::PushTarget::decode(encoded)
        .ok()
        .filter(|t| t.kind.is_some())
}
