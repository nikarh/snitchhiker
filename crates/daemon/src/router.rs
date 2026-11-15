//! Prompt routing (plan §5.5): which clients are notified of a prompt. Every admin client lists every prompt and can
//! answer it; routing only says who is to be told.
//!
//! - `all`: every client, but devices muted.
//! - `escalate`: the clients on this machine first. Remote devices are notified when no client here listens, when the
//!   local users' sessions are all locked or idle (logind says so), or once the prompt has waited
//!   `escalate_after_secs`. The decision is made on a thread of its own, never on the packet path: asking logind
//!   takes a D-Bus round trip.

use std::collections::{BTreeSet, HashSet};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use snitchhiker_proto::v1;
use tracing::debug;

use crate::config::Routing;
use crate::hub::{Audience, Hub};
use crate::prompts::Broker;

/// What the router needs of the daemon.
pub struct Router {
    routing: Routing,
    after: Duration,
    /// Devices not notified of prompts.
    muted: Mutex<HashSet<String>>,
    /// New prompts to decide about (escalate only).
    opened: Mutex<Option<Sender<u64>>>,
}

impl Router {
    #[must_use]
    pub fn new(routing: Routing, after: Duration) -> Self {
        Self {
            routing,
            after,
            muted: Mutex::new(HashSet::new()),
            opened: Mutex::new(None),
        }
    }

    /// The devices muted (from the store, at start and on each change).
    pub fn set_muted(&self, muted: impl IntoIterator<Item = String>) {
        *self.muted.lock().unwrap_or_else(PoisonError::into_inner) = muted.into_iter().collect();
    }

    fn is_muted(&self, device: &str) -> bool {
        self.muted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(device)
    }

    /// Whether `audience` is notified of a prompt now (`escalated`: the remote devices' turn came).
    fn notifies(&self, audience: &Audience, escalated: bool) -> bool {
        match audience {
            Audience::Device { id } => {
                !self.is_muted(id) && (self.routing == Routing::All || escalated)
            }
            Audience::Local { .. } | Audience::Other => true,
        }
    }

    /// Announces a prompt that opened.
    pub fn opened(&self, hub: &Hub, prompt: &v1::Prompt) {
        hub.publish_each(v1::Topic::Prompts, |audience| {
            Some(v1::notice::Body::Prompt(v1::Prompt {
                notify: self.notifies(audience, false),
                ..prompt.clone()
            }))
        });
        if self.routing == Routing::Escalate
            && let Some(opened) = self
                .opened
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
        {
            let _ = opened.send(prompt.id);
        }
    }

    /// Notifies the remote devices (not muted) of a prompt still waiting.
    fn escalate(&self, hub: &Hub, broker: &Broker, id: u64) {
        let Some(prompt) = broker.peek(id, |p| p.prompt.clone()) else {
            return;
        };
        debug!(id, "a prompt is escalated to the remote devices");
        hub.publish_each(v1::Topic::Prompts, |audience| match audience {
            Audience::Device { id } if !self.is_muted(id) => {
                Some(v1::notice::Body::Prompt(v1::Prompt {
                    notify: true,
                    ..prompt.clone()
                }))
            }
            _ => None,
        });
    }

    /// Starts the escalation thread (with `escalate` only).
    pub fn spawn(shared: &Arc<crate::runtime::Shared>) -> std::io::Result<()> {
        if shared.router.routing != Routing::Escalate {
            return Ok(());
        }
        let (sender, receiver) = channel();
        *shared
            .router
            .opened
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(sender);
        let shared = Arc::clone(shared);
        thread::Builder::new()
            .name("prompt-router".to_owned())
            .spawn(move || shared.router.run(&shared.hub, &shared.broker, &receiver))?;
        Ok(())
    }

    fn run(&self, hub: &Hub, broker: &Broker, opened: &Receiver<u64>) {
        // Prompts waiting for their turn to escalate, by when.
        let mut due: BTreeSet<(Instant, u64)> = BTreeSet::new();
        loop {
            let next = due.first().copied();
            let received = match next {
                Some((at, _)) => opened.recv_timeout(at.saturating_duration_since(Instant::now())),
                None => opened.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(id) => {
                    let local: Vec<u32> = hub
                        .audiences(v1::Topic::Prompts)
                        .iter()
                        .filter_map(|a| match a {
                            Audience::Local { uid } => Some(*uid),
                            _ => None,
                        })
                        .collect();
                    if local.is_empty() || !crate::logind::anyone_present(&local) {
                        self.escalate(hub, broker, id);
                    } else {
                        due.insert((Instant::now() + self.after, id));
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    let now = Instant::now();
                    let ready: Vec<(Instant, u64)> = due
                        .iter()
                        .take_while(|(at, _)| *at <= now)
                        .copied()
                        .collect();
                    for key in ready {
                        due.remove(&key);
                        self.escalate(hub, broker, key.1);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}
