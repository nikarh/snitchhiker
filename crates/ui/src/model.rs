//! What the app knows of the node, as plain data: events (newest first, with the node's strings), the prompts waiting,
//! the rules and the status. The views read it; `Model::apply` folds the backend's updates in.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

use snitchhiker_core::query::{EventFilter, EventView};
use snitchhiker_proto::columns::EventRow;
use snitchhiker_proto::v1;

use crate::backend::Update;

/// The events loaded, newest first, without duplicates (a resumed subscription may repeat some): all of them, or those
/// a query matches.
#[derive(Debug)]
pub struct Events {
    rows: VecDeque<EventRow>,
    seen: HashSet<i64>,
    strings: HashMap<u32, String>,
    /// Older events may exist: scrolling down loads them.
    pub more: bool,
    /// The query shown, and its filter for live events (`None`: everything).
    pub query: String,
    filter: Option<EventFilter>,
    /// Where the next page of history starts (its `before`; 0 for the newest).
    next: i64,
    /// The page last asked for, so one isn't asked twice.
    requested: Option<i64>,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            rows: VecDeque::new(),
            seen: HashSet::new(),
            strings: HashMap::new(),
            more: true,
            query: String::new(),
            filter: None,
            next: 0,
            requested: None,
        }
    }
}

impl Events {
    /// Shows the events `filter` matches (all for `None`) from now on: the history loaded is dropped and loaded again
    /// for the query.
    pub fn set_query(&mut self, query: String, filter: Option<EventFilter>) {
        self.rows.clear();
        self.seen.clear();
        self.more = true;
        self.next = 0;
        self.requested = None;
        self.query = query;
        self.filter = filter;
    }

    /// The next page of history to ask for (its `before`), unless there is none or it was asked for already.
    pub fn next_page(&mut self) -> Option<i64> {
        if !self.more || self.requested == Some(self.next) {
            return None;
        }
        self.requested = Some(self.next);
        Some(self.next)
    }

    /// A page of history for `query`, covering down to `scanned_from` (0: nothing older). Pages of an earlier query
    /// are dropped.
    pub fn add_page(
        &mut self,
        rows: &[EventRow],
        strings: Vec<(u32, String)>,
        scanned_from: i64,
        query: &str,
    ) -> bool {
        if query != self.query {
            return false;
        }
        self.add(rows, strings);
        self.next = scanned_from;
        self.more = scanned_from != 0;
        true
    }

    /// Live events: those the query matches.
    pub fn add_live(&mut self, rows: &[EventRow], strings: Vec<(u32, String)>) {
        self.strings.extend(strings);
        let Some(filter) = &self.filter else {
            self.add(rows, Vec::new());
            return;
        };
        let matching: Vec<EventRow> = rows
            .iter()
            .filter(|row| {
                filter.matches(&EventView {
                    time_ms: row.time_ms,
                    exe: self.string(row.exe).unwrap_or(""),
                    host: if row.host == 0 {
                        ""
                    } else {
                        self.string(row.host).unwrap_or("")
                    },
                    address: address(row),
                    port: row.port,
                    protocol: row.protocol,
                    uid: row.uid,
                    action: row.action,
                    rule: row.rule,
                    // Blocks carry the protocol's numbers, which start at 1 for the host.
                    context: row.context.saturating_sub(1),
                    bytes_out: row.bytes_out,
                    bytes_in: row.bytes_in,
                })
            })
            .copied()
            .collect();
        self.add(&matching, Vec::new());
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<&EventRow> {
        self.rows.get(index)
    }

    /// A string of the node's dictionary.
    #[must_use]
    pub fn string(&self, id: u32) -> Option<&str> {
        self.strings.get(&id).map(String::as_str)
    }

    /// Adds events from anywhere (live or a page), keeping the newest first.
    pub fn add(&mut self, rows: &[EventRow], strings: Vec<(u32, String)>) {
        self.strings.extend(strings);
        let mut new: Vec<EventRow> = rows
            .iter()
            .filter(|r| self.seen.insert(r.seq))
            .copied()
            .collect();
        if new.is_empty() {
            return;
        }
        new.sort_unstable_by_key(|r| std::cmp::Reverse(r.seq));
        let (Some(newest), Some(oldest)) = (new.first().map(|r| r.seq), new.last().map(|r| r.seq))
        else {
            return;
        };
        if self.rows.back().is_none_or(|held| newest < held.seq) {
            // A page of history: after everything held.
            self.rows.extend(new);
        } else if self.rows.front().is_some_and(|held| oldest > held.seq) {
            // Live events: before everything held, newest first.
            for row in new.into_iter().rev() {
                self.rows.push_front(row);
            }
        } else {
            // Overlapping (rare): merge by sorting.
            self.rows.extend(new);
            self.rows
                .make_contiguous()
                .sort_unstable_by_key(|r| std::cmp::Reverse(r.seq));
        }
    }
}

/// A row's destination address, as people read it.
#[must_use]
pub fn address(row: &EventRow) -> IpAddr {
    let v6 = Ipv6Addr::from(row.address);
    v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
}

#[derive(Debug, Default)]
pub struct Model {
    /// The node, once connected: its name and version.
    pub node: Option<v1::Welcome>,
    /// Why the node isn't connected, when it isn't.
    pub disconnected: Option<String>,
    pub status: Option<v1::Status>,
    pub rules: v1::RuleList,
    pub prompts: BTreeMap<u64, v1::Prompt>,
    pub events: Events,
    /// The history of rules and folders, newest first.
    pub changes: Vec<v1::Change>,
    /// The Explorer's groups, as last asked.
    pub explored: Vec<v1::ExploreRow>,
    /// The live connections, as last listed.
    pub connections: Vec<v1::LiveConnection>,
    /// The last explanation the node sent.
    pub explanation: Option<v1::Explanation>,
    /// The last request that failed, for the user.
    pub error: Option<String>,
}

/// What an update changed, so only those views refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changed {
    Nothing,
    Events,
    Rules,
    Prompts,
    Status,
    /// The rules changed on the node: they are to be listed again.
    RulesOnNode,
    /// The prompts are to be shown.
    ShowPrompts,
    Connections,
}

impl Model {
    pub fn apply(&mut self, update: Update) -> Changed {
        match update {
            Update::Connected(welcome) => {
                self.node = Some(welcome);
                self.disconnected = None;
                // The subscription sends every prompt waiting: the list starts again from those.
                self.prompts.clear();
                Changed::Prompts
            }
            Update::Disconnected(reason) => {
                self.disconnected = Some(reason);
                Changed::Status
            }
            Update::Status(status) => {
                self.status = Some(status);
                Changed::Status
            }
            Update::Rules(rules) => {
                self.rules = rules;
                Changed::Rules
            }
            Update::Prompt(prompt) => {
                self.prompts.insert(prompt.id, prompt);
                Changed::Prompts
            }
            Update::Resolved(resolved) => {
                if self.prompts.remove(&resolved.id).is_some() {
                    Changed::Prompts
                } else {
                    Changed::Nothing
                }
            }
            Update::Events {
                rows,
                strings,
                live: true,
                ..
            } => {
                self.events.add_live(&rows, strings);
                Changed::Events
            }
            Update::Events {
                rows,
                strings,
                scanned_from,
                query,
                ..
            } => {
                if self.events.add_page(&rows, strings, scanned_from, &query) {
                    Changed::Events
                } else {
                    Changed::Nothing
                }
            }
            Update::RulesChanged => Changed::RulesOnNode,
            Update::Changes(changes) => {
                self.changes = changes;
                Changed::Status
            }
            Update::Explored(rows) => {
                self.explored = rows;
                Changed::Status
            }
            Update::Connections(connections) => {
                self.connections = connections;
                Changed::Connections
            }
            Update::Explanation(explanation) => {
                self.explanation = Some(*explanation);
                Changed::Status
            }
            Update::ShowPrompts => Changed::ShowPrompts,
            Update::Failed(error) => {
                self.error = Some(error);
                Changed::Status
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(seq: i64) -> EventRow {
        EventRow {
            seq,
            exe: 1,
            ..EventRow::default()
        }
    }

    fn seqs(events: &Events) -> Vec<i64> {
        (0..events.len())
            .filter_map(|i| events.get(i))
            .map(|r| r.seq)
            .collect()
    }

    #[test]
    fn events_stay_newest_first_without_duplicates() {
        let mut events = Events::default();
        events.add(
            &[row(10), row(11), row(12)],
            vec![(1, "/usr/bin/curl".to_owned())],
        );
        // A page of older history.
        events.add(&[row(8), row(9)], Vec::new());
        // Live events, one of them repeated by a resumed subscription.
        events.add(&[row(12), row(13)], Vec::new());
        assert_eq!(seqs(&events), vec![13, 12, 11, 10, 9, 8]);
        assert_eq!(events.string(1), Some("/usr/bin/curl"));
    }

    #[test]
    fn a_query_filters_live_events_and_drops_stale_pages() {
        let cx = snitchhiker_core::query::Context {
            now_ms: 0,
            uid_of: &|_| None,
        };
        let mut events = Events::default();
        assert_eq!(events.next_page(), Some(0));
        assert_eq!(events.next_page(), None, "asked for already");
        events.set_query(
            "port:443".to_owned(),
            Some(EventFilter::parse("port:443", &cx).unwrap()),
        );
        assert_eq!(events.next_page(), Some(0));
        // A page of the query before is dropped.
        assert!(!events.add_page(&[row(1)], Vec::new(), 0, ""));
        let https = EventRow {
            port: 443,
            ..row(5)
        };
        assert!(events.add_page(&[https], Vec::new(), 3, "port:443"));
        assert_eq!(events.next_page(), Some(3));
        events.add_live(
            &[
                row(6),
                EventRow {
                    port: 443,
                    ..row(7)
                },
            ],
            Vec::new(),
        );
        assert_eq!(seqs(&events), vec![7, 5]);
        assert!(events.add_page(&[], Vec::new(), 0, "port:443"));
        assert_eq!(events.next_page(), None, "nothing older");
    }

    #[test]
    fn reconnecting_starts_the_prompts_again() {
        let mut model = Model::default();
        model.apply(Update::Prompt(v1::Prompt {
            id: 7,
            ..v1::Prompt::default()
        }));
        model.apply(Update::Connected(v1::Welcome::default()));
        assert!(model.prompts.is_empty());
        let changed = model.apply(Update::Resolved(v1::PromptResolved {
            id: 7,
            ..v1::PromptResolved::default()
        }));
        assert_eq!(changed, Changed::Nothing);
    }

    #[test]
    fn addresses_read_as_v4_when_mapped() {
        let mut mapped = row(1);
        mapped.address = std::net::Ipv4Addr::new(192, 0, 2, 10)
            .to_ipv6_mapped()
            .octets();
        assert_eq!(address(&mapped).to_string(), "192.0.2.10");
    }
}
