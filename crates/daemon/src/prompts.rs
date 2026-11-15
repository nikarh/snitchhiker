//! Prompts: connections no rule decides, held until a client answers or the prompt times out.
//!
//! Connections of the same program and user to the same destination, port and protocol join one prompt: one question
//! for a burst of connections, and for the retransmissions of a held SYN. Different prompts are independent: there
//! is no "already asking" lock that makes every other connection get a default.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use snitchhiker_core::suggest::Suggestion;
use snitchhiker_netfilter::queue::{Verdict, VerdictWriter};
use snitchhiker_proto::v1;
use tracing::warn;

use crate::store::Event;

/// A packet waiting for a prompt's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    /// Which of the daemon's queues (0 for the first) it waits in.
    pub queue: usize,
    pub id: u32,
}

/// What makes connections the same question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PromptKey {
    pub exe: Arc<str>,
    pub uid: u32,
    /// The host name, or the address when there is none.
    pub destination: String,
    pub port: u16,
    pub protocol: u8,
}

/// A prompt waiting for an answer.
#[derive(Debug)]
pub struct Pending {
    pub prompt: v1::Prompt,
    pub suggestions: Vec<Suggestion>,
    /// The connection as the history records it once decided.
    pub event: Event,
    key: PromptKey,
    packets: Vec<Held>,
    expires: Instant,
}

/// What [`Broker::hold`] needs to open a prompt: built only when a new prompt is opened.
pub struct NewPrompt {
    pub prompt: v1::Prompt,
    pub suggestions: Vec<Suggestion>,
    pub event: Event,
}

#[derive(Default)]
struct State {
    by_key: HashMap<PromptKey, u64>,
    pending: HashMap<u64, Pending>,
}

pub struct Broker {
    state: Mutex<State>,
    wake: Condvar,
    writers: Vec<Mutex<VerdictWriter>>,
    /// How long a prompt waits, in ms (the policy changes it while the daemon runs).
    timeout_ms: AtomicU64,
    next: AtomicU64,
}

/// What became of a held packet.
#[expect(
    clippy::large_enum_variant,
    reason = "made once per held packet and matched right away"
)]
#[derive(Debug, PartialEq)]
pub enum Hold {
    /// It opened a prompt (to publish).
    Opened(v1::Prompt),
    /// It joined the open prompt with this id.
    Joined(u64),
}

impl Broker {
    /// A broker deciding packets through `writers` (one per queue, in queue order).
    #[must_use]
    pub fn new(writers: Vec<VerdictWriter>, timeout: Duration) -> Self {
        Self {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            writers: writers.into_iter().map(Mutex::new).collect(),
            timeout_ms: AtomicU64::new(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            next: AtomicU64::new(0),
        }
    }

    /// How long prompts opened from now on wait.
    pub fn set_timeout(&self, timeout: Duration) {
        self.timeout_ms.store(
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Holds a packet for the prompt of `key`, opening one (with `open`, called only then) if none is open.
    pub fn hold(
        &self,
        key: PromptKey,
        packet: Held,
        now_ms: u64,
        open: impl FnOnce() -> NewPrompt,
    ) -> Hold {
        let mut state = self.lock();
        if let Some(pending) = state
            .by_key
            .get(&key)
            .copied()
            .and_then(|id| state.pending.get_mut(&id))
        {
            pending.packets.push(packet);
            pending.prompt.waiting = u32::try_from(pending.packets.len()).unwrap_or(u32::MAX);
            return Hold::Joined(pending.prompt.id);
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let NewPrompt {
            mut prompt,
            suggestions,
            event,
        } = open();
        let timeout_ms = self.timeout_ms.load(Ordering::Relaxed);
        prompt.id = id;
        prompt.created_ms = now_ms;
        prompt.expires_ms = now_ms.saturating_add(timeout_ms);
        prompt.waiting = 1;
        state.by_key.insert(key.clone(), id);
        state.pending.insert(
            id,
            Pending {
                prompt: prompt.clone(),
                suggestions,
                event,
                key,
                packets: vec![packet],
                expires: Instant::now() + Duration::from_millis(timeout_ms),
            },
        );
        drop(state);
        self.wake.notify_all();
        Hold::Opened(prompt)
    }

    /// Looks at an open prompt without taking it; `None` when there is none with that id.
    pub fn peek<R>(&self, id: u64, look: impl FnOnce(&Pending) -> R) -> Option<R> {
        self.lock().pending.get(&id).map(look)
    }

    /// Sets an agent's note on an open prompt; the prompt as it is now, or `None` when it isn't open.
    pub fn annotate(&self, id: u64, note: &str) -> Option<v1::Prompt> {
        let mut state = self.lock();
        let pending = state.pending.get_mut(&id)?;
        note.clone_into(&mut pending.prompt.agent_note);
        Some(pending.prompt.clone())
    }

    /// Whether a prompt is open.
    #[must_use]
    pub fn is_open(&self, id: u64) -> bool {
        self.lock().pending.contains_key(&id)
    }

    /// Takes a prompt to answer it; `None` when it was answered already (or timed out).
    pub fn take(&self, id: u64) -> Option<Pending> {
        let mut state = self.lock();
        let pending = state.pending.remove(&id)?;
        state.by_key.remove(&pending.key);
        Some(pending)
    }

    /// Waits until prompts time out, and takes them.
    pub fn wait_expired(&self) -> Vec<Pending> {
        let mut state = self.lock();
        loop {
            let now = Instant::now();
            let expired: Vec<u64> = state
                .pending
                .iter()
                .filter(|(_, p)| p.expires <= now)
                .map(|(id, _)| *id)
                .collect();
            if !expired.is_empty() {
                return expired
                    .into_iter()
                    .filter_map(|id| {
                        let pending = state.pending.remove(&id)?;
                        state.by_key.remove(&pending.key);
                        Some(pending)
                    })
                    .collect();
            }
            let next = state
                .pending
                .values()
                .map(|p| p.expires)
                .min()
                .map_or(Duration::from_secs(3600), |at| {
                    at.saturating_duration_since(now)
                });
            state = self
                .wake
                .wait_timeout(state, next)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Gives every packet of a prompt its verdict.
    pub fn release(&self, pending: &Pending, verdict: Verdict) {
        for held in &pending.packets {
            let Some(writer) = self.writers.get(held.queue) else {
                continue;
            };
            let mut writer = writer.lock().unwrap_or_else(PoisonError::into_inner);
            if let Err(error) = writer.verdict(held.id, verdict) {
                warn!(%error, queue = writer.number(), "deciding a held packet");
            }
        }
    }

    /// The open prompts.
    #[must_use]
    pub fn list(&self) -> Vec<v1::Prompt> {
        self.lock()
            .pending
            .values()
            .map(|p| p.prompt.clone())
            .collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.lock().pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Source;

    fn key(port: u16) -> PromptKey {
        PromptKey {
            exe: Arc::from("/usr/bin/curl"),
            uid: 1000,
            destination: "example.com".to_owned(),
            port,
            protocol: 6,
        }
    }

    fn new_prompt() -> NewPrompt {
        NewPrompt {
            prompt: v1::Prompt::default(),
            suggestions: vec![],
            event: Event {
                time_ms: 0,
                exe: Arc::from("/usr/bin/curl"),
                host: None,
                uid: 1000,
                pid: 1,
                protocol: 6,
                address: "198.51.100.7".parse().unwrap(),
                port: 443,
                context: 0,
                action: snitchhiker_core::rule::Action::Deny,
                source: Source::Policy,
                rule: None,
                cookie: None,
            },
        }
    }

    #[test]
    fn the_same_question_is_asked_once() {
        let broker = Broker::new(vec![], Duration::from_secs(30));
        let opened = broker.hold(key(443), Held { queue: 0, id: 1 }, 1000, new_prompt);
        let Hold::Opened(prompt) = opened else {
            panic!("no prompt opened");
        };
        assert_eq!((prompt.created_ms, prompt.expires_ms), (1000, 31_000));
        assert_eq!(
            broker.hold(key(443), Held { queue: 1, id: 2 }, 1001, new_prompt),
            Hold::Joined(prompt.id)
        );
        assert!(matches!(
            broker.hold(key(80), Held { queue: 0, id: 3 }, 1002, new_prompt),
            Hold::Opened(_)
        ));
        assert_eq!(broker.count(), 2);
        let taken = broker.take(prompt.id).unwrap();
        assert_eq!(taken.packets.len(), 2);
        assert_eq!(taken.prompt.waiting, 2);
        assert!(broker.take(prompt.id).is_none());
        // Answered: the next connection opens a new prompt.
        assert!(matches!(
            broker.hold(key(443), Held { queue: 0, id: 4 }, 2000, new_prompt),
            Hold::Opened(_)
        ));
    }

    #[test]
    fn prompts_time_out() {
        let broker = Broker::new(vec![], Duration::from_millis(50));
        broker.hold(key(443), Held { queue: 0, id: 1 }, 0, new_prompt);
        let expired = broker.wait_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(broker.count(), 0);
    }
}
