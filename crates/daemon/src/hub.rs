//! Subscriptions: which connection wants which topic, and pushing notices to them.
//!
//! Every connection has an outbound queue its writer thread drains; a slow client's queue fills up and it misses
//! notices rather than slowing the node down. The next notice it gets says so (`missed`), so it can resume.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Mutex, PoisonError};

use snitchhiker_proto::v1;

/// Frames waiting for one client's writer; beyond this, notices for it are dropped.
pub const OUTBOUND: usize = 4096;

struct Subscription {
    connection: u64,
    id: u64,
    topic: v1::Topic,
    outbound: SyncSender<v1::ServerFrame>,
    /// Notices were dropped since the last one delivered.
    missed: bool,
}

/// Why a subscription with a backfill wasn't made.
#[derive(Debug, PartialEq, Eq)]
pub enum BackfillError {
    /// The backfill is larger than allowed, or doesn't fit the connection's queue.
    TooMuch,
    /// The connection is gone.
    Closed,
}

fn notice(id: u64, body: v1::notice::Body, missed: bool) -> v1::ServerFrame {
    v1::ServerFrame {
        body: Some(v1::server_frame::Body::Notice(v1::Notice {
            subscription: id,
            body: Some(body),
            missed,
        })),
    }
}

#[derive(Default)]
pub struct Hub {
    subscriptions: Mutex<Vec<Subscription>>,
    next: AtomicU64,
}

impl Hub {
    /// Subscribes `connection` to `topic`; returns the subscription's id.
    pub fn subscribe(
        &self,
        connection: u64,
        topic: v1::Topic,
        outbound: SyncSender<v1::ServerFrame>,
    ) -> u64 {
        self.subscribe_with(connection, topic, outbound, || Some(Vec::new()))
            .unwrap_or_default()
    }

    /// Subscribes `connection` to `topic`, first sending what `backfill` gives (the stored events after a point, the
    /// prompts waiting). `backfill` runs while no notice of any topic is published, so nothing published after it can
    /// arrive before it. Returns the subscription's id.
    pub fn subscribe_with(
        &self,
        connection: u64,
        topic: v1::Topic,
        outbound: SyncSender<v1::ServerFrame>,
        backfill: impl FnOnce() -> Option<Vec<v1::notice::Body>>,
    ) -> Result<u64, BackfillError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for body in backfill().ok_or(BackfillError::TooMuch)? {
            match outbound.try_send(notice(id, body, false)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => return Err(BackfillError::TooMuch),
                Err(TrySendError::Disconnected(_)) => return Err(BackfillError::Closed),
            }
        }
        subscriptions.push(Subscription {
            connection,
            id,
            topic,
            outbound,
            missed: false,
        });
        Ok(id)
    }

    /// Ends one of `connection`'s subscriptions; whether it existed.
    pub fn unsubscribe(&self, connection: u64, id: u64) -> bool {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let before = subscriptions.len();
        subscriptions.retain(|s| !(s.connection == connection && s.id == id));
        subscriptions.len() != before
    }

    /// Ends every subscription of a connection that closed.
    pub fn forget(&self, connection: u64) {
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|s| s.connection != connection);
    }

    /// Whether anyone listens to `topic` (e.g. whether there is anyone to ask).
    pub fn has_subscribers(&self, topic: v1::Topic) -> bool {
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|s| s.topic == topic)
    }

    /// Pushes `body` to every subscriber of `topic`. Subscriptions whose connection is gone are dropped.
    pub fn publish(&self, topic: v1::Topic, body: &v1::notice::Body) {
        self.publish_all(topic, std::slice::from_ref(body));
    }

    /// Pushes each of `bodies`, in order, to every subscriber of `topic`.
    pub fn publish_all(&self, topic: v1::Topic, bodies: &[v1::notice::Body]) {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        subscriptions.retain_mut(|s| {
            if s.topic != topic {
                return true;
            }
            for body in bodies {
                match s.outbound.try_send(notice(s.id, body.clone(), s.missed)) {
                    Ok(()) => s.missed = false,
                    Err(TrySendError::Full(_)) => s.missed = true,
                    Err(TrySendError::Disconnected(_)) => return false,
                }
            }
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::sync_channel;

    use super::*;

    #[test]
    fn publishes_to_subscribers_of_the_topic_only() {
        let hub = Hub::default();
        let (prompts, prompts_rx) = sync_channel(8);
        let (rules, rules_rx) = sync_channel(8);
        let id = hub.subscribe(1, v1::Topic::Prompts, prompts);
        hub.subscribe(2, v1::Topic::Rules, rules);
        assert!(hub.has_subscribers(v1::Topic::Prompts));
        hub.publish(
            v1::Topic::Prompts,
            &v1::notice::Body::RulesChanged(v1::RulesChanged {}),
        );
        let Some(v1::server_frame::Body::Notice(notice)) = prompts_rx.try_recv().unwrap().body
        else {
            panic!("not a notice");
        };
        assert_eq!(notice.subscription, id);
        assert!(rules_rx.try_recv().is_err());
    }

    #[test]
    fn a_full_queue_marks_the_next_notice_missed() {
        let hub = Hub::default();
        let (sender, receiver) = sync_channel(1);
        hub.subscribe(1, v1::Topic::Events, sender);
        let body = v1::notice::Body::RulesChanged(v1::RulesChanged {});
        hub.publish_all(v1::Topic::Events, &[body.clone(), body.clone()]);
        let missed = |frame: v1::ServerFrame| match frame.body {
            Some(v1::server_frame::Body::Notice(notice)) => notice.missed,
            _ => panic!("not a notice"),
        };
        assert!(!missed(receiver.try_recv().unwrap()));
        assert!(receiver.try_recv().is_err());
        hub.publish(v1::Topic::Events, &body);
        assert!(missed(receiver.try_recv().unwrap()));
    }

    #[test]
    fn a_backfill_comes_first_and_must_fit() {
        let hub = Hub::default();
        let (sender, receiver) = sync_channel(2);
        let body = v1::notice::Body::RulesChanged(v1::RulesChanged {});
        let three = || Some(vec![body.clone(), body.clone(), body.clone()]);
        assert_eq!(
            hub.subscribe_with(1, v1::Topic::Events, sender.clone(), three),
            Err(BackfillError::TooMuch)
        );
        assert!(!hub.has_subscribers(v1::Topic::Events));
        while receiver.try_recv().is_ok() {}
        let id = hub
            .subscribe_with(1, v1::Topic::Events, sender, || Some(vec![body.clone()]))
            .unwrap();
        assert!(receiver.try_recv().is_ok());
        assert!(hub.has_subscribers(v1::Topic::Events));
        assert!(hub.unsubscribe(1, id));
    }

    #[test]
    fn closed_connections_are_dropped() {
        let hub = Hub::default();
        let (sender, receiver) = sync_channel(8);
        hub.subscribe(1, v1::Topic::Events, sender);
        drop(receiver);
        hub.publish(
            v1::Topic::Events,
            &v1::notice::Body::RulesChanged(v1::RulesChanged {}),
        );
        assert!(!hub.has_subscribers(v1::Topic::Events));
        let (sender, _receiver) = sync_channel(8);
        let id = hub.subscribe(3, v1::Topic::Events, sender);
        assert!(hub.unsubscribe(3, id));
        assert!(!hub.unsubscribe(3, id));
    }
}
