//! Subscriptions: which connection wants which topic, and pushing notices to them.
//!
//! Every connection has an outbound queue its writer thread drains; a slow client's queue fills up and it misses
//! notices (it is told to resubscribe) rather than slowing the node down.

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
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Subscription {
                connection,
                id,
                topic,
                outbound,
            });
        id
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
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        subscriptions.retain(|s| {
            if s.topic != topic {
                return true;
            }
            let frame = v1::ServerFrame {
                body: Some(v1::server_frame::Body::Notice(v1::Notice {
                    subscription: s.id,
                    body: Some(body.clone()),
                })),
            };
            !matches!(
                s.outbound.try_send(frame),
                Err(TrySendError::Disconnected(_))
            )
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
