//! Subscriptions: which connection wants which topic, and pushing notices to them.
//!
//! Every connection has an outbox: a bounded queue its writer thread drains, and the strings the connection has been
//! sent. A slow client's queue fills up and it misses notices rather than slowing the node down; the next notice it
//! gets says so (`missed`), so it can resume.
//!
//! Columnar blocks refer to strings by id. The dictionary entries a frame carries are decided at the moment it is
//! queued, under the outbox's lock: an entry is in the first frame queued that needs it, so no frame can arrive using
//! an id the client hasn't been told yet, however responses and notices interleave.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};

use snitchhiker_proto::v1;

/// Frames waiting for one client's writer; beyond this, notices for it are dropped.
pub const OUTBOUND: usize = 4096;

/// A block's strings: (id, text).
pub type Strings = [(u32, Arc<str>)];

/// The connection is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

/// What leaves for one connection.
pub struct Outbox {
    sender: SyncSender<v1::ServerFrame>,
    /// String ids this connection has been sent.
    sent: Mutex<HashSet<u32>>,
}

impl Outbox {
    #[must_use]
    pub fn new(sender: SyncSender<v1::ServerFrame>) -> Self {
        Self {
            sender,
            sent: Mutex::new(HashSet::new()),
        }
    }

    /// Queues a frame, waiting for room (responses: the client asked for them).
    pub fn send(&self, frame: v1::ServerFrame) -> Result<(), Closed> {
        self.sender.send(frame).map_err(|_| Closed)
    }

    /// Queues a frame if there is room.
    fn try_send(&self, frame: v1::ServerFrame) -> Result<(), TrySendError<()>> {
        self.sender.try_send(frame).map_err(|e| match e {
            TrySendError::Full(_) => TrySendError::Full(()),
            TrySendError::Disconnected(_) => TrySendError::Disconnected(()),
        })
    }

    /// Queues the frame `make` builds around the dictionary entries of `strings` this connection hasn't been sent;
    /// `wait` waits for room, otherwise a full queue drops it. The entries count as sent only once the frame is queued.
    pub fn send_block(
        &self,
        strings: &Strings,
        wait: bool,
        make: impl FnOnce(v1::Dictionary) -> v1::ServerFrame,
    ) -> Result<(), TrySendError<()>> {
        let mut sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
        let mut dictionary = v1::Dictionary::default();
        let mut new = HashSet::new();
        for (id, text) in strings {
            if *id != 0 && !sent.contains(id) && new.insert(*id) {
                dictionary.ids.push(*id);
                dictionary.values.push(text.to_string());
            }
        }
        let frame = make(dictionary);
        if wait {
            self.send(frame)
                .map_err(|Closed| TrySendError::Disconnected(()))?;
        } else {
            self.try_send(frame)?;
        }
        sent.extend(new);
        Ok(())
    }
}

/// A notice to push: a message, or a columnar block and the strings it uses.
#[derive(Clone)]
pub enum Outgoing {
    Notice(v1::notice::Body),
    Block {
        columns: bytes::Bytes,
        strings: Arc<Strings>,
    },
}

struct Subscription {
    connection: u64,
    id: u64,
    topic: v1::Topic,
    outbox: Arc<Outbox>,
    /// Events as blocks rather than one message each.
    columnar: bool,
    /// Notices were dropped since the last one delivered.
    missed: bool,
}

impl Subscription {
    fn push(&self, outgoing: &Outgoing) -> Result<(), TrySendError<()>> {
        let (id, missed) = (self.id, self.missed);
        match outgoing {
            Outgoing::Notice(body) => self.outbox.try_send(notice(id, body.clone(), missed)),
            Outgoing::Block { columns, strings } => {
                self.outbox.send_block(strings, false, |dictionary| {
                    let block = v1::EventBlock {
                        columns: columns.clone(),
                        dictionary: Some(dictionary),
                        scanned_from: 0,
                    };
                    notice(id, v1::notice::Body::EventBlock(block), missed)
                })
            }
        }
    }
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
    /// Who each connection is, for routing prompts.
    audiences: Mutex<std::collections::HashMap<u64, Audience>>,
    /// The connections whose role may answer prompts (a viewer's may only see them).
    answerers: Mutex<std::collections::HashSet<u64>>,
}

/// Who is on the other end of a connection, as prompt routing sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// A client on this machine, of a user.
    Local { uid: u32 },
    /// A paired device over the network, by its key.
    Device { id: String },
    /// Root's command line, or anything else.
    Other,
}

impl Hub {
    /// Subscribes `connection` to `topic`; returns the subscription's id.
    pub fn subscribe(&self, connection: u64, topic: v1::Topic, outbox: Arc<Outbox>) -> u64 {
        self.subscribe_with(connection, topic, outbox, false, || Some(Vec::new()))
            .unwrap_or_default()
    }

    /// Subscribes `connection` to `topic`, first sending what `backfill` gives (the stored events after a point, the
    /// prompts waiting); `None` from it means too much. `backfill` runs while no notice of any topic is published, so
    /// nothing published after it can arrive before it. Returns the subscription's id.
    pub fn subscribe_with(
        &self,
        connection: u64,
        topic: v1::Topic,
        outbox: Arc<Outbox>,
        columnar: bool,
        backfill: impl FnOnce() -> Option<Vec<Outgoing>>,
    ) -> Result<u64, BackfillError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let subscription = Subscription {
            connection,
            id,
            topic,
            outbox,
            columnar,
            missed: false,
        };
        for outgoing in backfill().ok_or(BackfillError::TooMuch)? {
            match subscription.push(&outgoing) {
                Ok(()) => {}
                Err(TrySendError::Full(())) => return Err(BackfillError::TooMuch),
                Err(TrySendError::Disconnected(())) => return Err(BackfillError::Closed),
            }
        }
        subscriptions.push(subscription);
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
        self.audiences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&connection);
        self.answerers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&connection);
    }

    /// Says who `connection` is, and whether it may answer prompts.
    pub fn set_audience(&self, connection: u64, audience: Audience, answers: bool) {
        self.audiences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(connection, audience);
        if answers {
            self.answerers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(connection);
        }
    }

    /// Whether anyone who may answer prompts listens to `topic`: someone to ask.
    pub fn has_answerers(&self, topic: v1::Topic) -> bool {
        let answerers = self
            .answerers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|s| s.topic == topic && answerers.contains(&s.connection))
    }

    /// Who listens to `topic` and may answer prompts.
    pub fn answering_audiences(&self, topic: v1::Topic) -> Vec<Audience> {
        let answerers = self
            .answerers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let audiences = self
            .audiences
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|s| s.topic == topic && answerers.contains(&s.connection))
            .map(|s| {
                audiences
                    .get(&s.connection)
                    .cloned()
                    .unwrap_or(Audience::Other)
            })
            .collect()
    }

    /// Who listens to `topic`.
    pub fn audiences(&self, topic: v1::Topic) -> Vec<Audience> {
        let audiences = self
            .audiences
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|s| s.topic == topic)
            .map(|s| {
                audiences
                    .get(&s.connection)
                    .cloned()
                    .unwrap_or(Audience::Other)
            })
            .collect()
    }

    /// Pushes to each subscriber of `topic` what `make` says for its audience (nothing: skipped).
    pub fn publish_each(
        &self,
        topic: v1::Topic,
        make: impl Fn(&Audience) -> Option<v1::notice::Body>,
    ) {
        let audiences = self
            .audiences
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        subscriptions.retain_mut(|s| {
            if s.topic != topic {
                return true;
            }
            let audience = audiences.get(&s.connection).unwrap_or(&Audience::Other);
            let Some(body) = make(audience) else {
                return true;
            };
            match s.push(&Outgoing::Notice(body)) {
                Ok(()) => s.missed = false,
                Err(TrySendError::Full(())) => s.missed = true,
                Err(TrySendError::Disconnected(())) => return false,
            }
            true
        });
    }

    /// Whether anyone listens to `topic` (e.g. whether there is anyone to ask).
    pub fn has_subscribers(&self, topic: v1::Topic) -> bool {
        self.subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|s| s.topic == topic)
    }

    /// Which forms `topic`'s subscribers want: (one message each, blocks).
    pub fn wanted(&self, topic: v1::Topic) -> (bool, bool) {
        let subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let of_topic = || subscriptions.iter().filter(|s| s.topic == topic);
        (
            of_topic().any(|s| !s.columnar),
            of_topic().any(|s| s.columnar),
        )
    }

    /// Pushes `body` to every subscriber of `topic`. Subscriptions whose connection is gone are dropped.
    pub fn publish(&self, topic: v1::Topic, body: &v1::notice::Body) {
        self.publish_all(topic, &[Outgoing::Notice(body.clone())], None);
    }

    /// Pushes `messages`, in order, to `topic`'s subscribers that want messages, and `block` to those that want
    /// blocks.
    pub fn publish_all(&self, topic: v1::Topic, messages: &[Outgoing], block: Option<&Outgoing>) {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        subscriptions.retain_mut(|s| {
            if s.topic != topic {
                return true;
            }
            let outgoing = if s.columnar {
                block.map_or(&[][..], std::slice::from_ref)
            } else {
                messages
            };
            for item in outgoing {
                match s.push(item) {
                    Ok(()) => s.missed = false,
                    Err(TrySendError::Full(())) => s.missed = true,
                    Err(TrySendError::Disconnected(())) => return false,
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

    fn outbox(size: usize) -> (Arc<Outbox>, std::sync::mpsc::Receiver<v1::ServerFrame>) {
        let (sender, receiver) = sync_channel(size);
        (Arc::new(Outbox::new(sender)), receiver)
    }

    fn rules_changed() -> Outgoing {
        Outgoing::Notice(v1::notice::Body::RulesChanged(v1::RulesChanged {}))
    }

    fn notice_of(frame: v1::ServerFrame) -> v1::Notice {
        match frame.body {
            Some(v1::server_frame::Body::Notice(notice)) => notice,
            _ => panic!("not a notice"),
        }
    }

    #[test]
    fn publishes_to_subscribers_of_the_topic_only() {
        let hub = Hub::default();
        let (prompts, prompts_rx) = outbox(8);
        let (rules, rules_rx) = outbox(8);
        let id = hub.subscribe(1, v1::Topic::Prompts, prompts);
        hub.subscribe(2, v1::Topic::Rules, rules);
        assert!(hub.has_subscribers(v1::Topic::Prompts));
        hub.publish(
            v1::Topic::Prompts,
            &v1::notice::Body::RulesChanged(v1::RulesChanged {}),
        );
        assert_eq!(notice_of(prompts_rx.try_recv().unwrap()).subscription, id);
        assert!(rules_rx.try_recv().is_err());
    }

    #[test]
    fn a_full_queue_marks_the_next_notice_missed() {
        let hub = Hub::default();
        let (outbox, receiver) = outbox(1);
        hub.subscribe(1, v1::Topic::Events, outbox);
        hub.publish_all(v1::Topic::Events, &[rules_changed(), rules_changed()], None);
        assert!(!notice_of(receiver.try_recv().unwrap()).missed);
        assert!(receiver.try_recv().is_err());
        hub.publish_all(v1::Topic::Events, &[rules_changed()], None);
        assert!(notice_of(receiver.try_recv().unwrap()).missed);
    }

    #[test]
    fn a_backfill_comes_first_and_must_fit() {
        let hub = Hub::default();
        let (outbox, receiver) = outbox(2);
        let three = || Some(vec![rules_changed(), rules_changed(), rules_changed()]);
        assert_eq!(
            hub.subscribe_with(1, v1::Topic::Events, Arc::clone(&outbox), false, three),
            Err(BackfillError::TooMuch)
        );
        assert!(!hub.has_subscribers(v1::Topic::Events));
        while receiver.try_recv().is_ok() {}
        let id = hub
            .subscribe_with(1, v1::Topic::Events, outbox, false, || {
                Some(vec![rules_changed()])
            })
            .unwrap();
        assert!(receiver.try_recv().is_ok());
        assert!(hub.has_subscribers(v1::Topic::Events));
        assert!(hub.unsubscribe(1, id));
    }

    #[test]
    fn blocks_carry_each_string_once_per_connection_and_go_to_who_wants_them() {
        let hub = Hub::default();
        let (columnar, columnar_rx) = outbox(8);
        let (plain, plain_rx) = outbox(8);
        hub.subscribe_with(1, v1::Topic::Events, columnar, true, || Some(Vec::new()))
            .unwrap();
        hub.subscribe(2, v1::Topic::Events, plain);
        assert_eq!(hub.wanted(v1::Topic::Events), (true, true));
        let strings: Arc<Strings> = Arc::from(vec![
            (3, Arc::from("/usr/bin/curl")),
            (3, Arc::from("/usr/bin/curl")),
        ]);
        let block = Outgoing::Block {
            columns: bytes::Bytes::from_static(b"columns"),
            strings,
        };
        for _ in 0..2 {
            hub.publish_all(v1::Topic::Events, &[rules_changed()], Some(&block));
        }
        let dictionary = |frame| match notice_of(frame).body {
            Some(v1::notice::Body::EventBlock(block)) => block.dictionary.unwrap(),
            _ => panic!("not a block"),
        };
        assert_eq!(dictionary(columnar_rx.try_recv().unwrap()).ids, vec![3]);
        assert_eq!(
            dictionary(columnar_rx.try_recv().unwrap()).ids,
            Vec::<u32>::new()
        );
        assert!(matches!(
            notice_of(plain_rx.try_recv().unwrap()).body,
            Some(v1::notice::Body::RulesChanged(_))
        ));
    }

    #[test]
    fn closed_connections_are_dropped() {
        let hub = Hub::default();
        let (sender, receiver) = sync_channel(8);
        hub.subscribe(1, v1::Topic::Events, Arc::new(Outbox::new(sender)));
        drop(receiver);
        hub.publish(
            v1::Topic::Events,
            &v1::notice::Body::RulesChanged(v1::RulesChanged {}),
        );
        assert!(!hub.has_subscribers(v1::Topic::Events));
        let (outbox, _receiver) = outbox(8);
        let id = hub.subscribe(3, v1::Topic::Events, outbox);
        assert!(hub.unsubscribe(3, id));
        assert!(!hub.unsubscribe(3, id));
    }
}
