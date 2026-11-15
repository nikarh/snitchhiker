//! What the app knows of the node, as plain data: events (newest first, with the node's strings), the prompts waiting,
//! the rules and the status. The views read it; `Model::apply` folds the backend's updates in.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

use snitchhiker_proto::columns::EventRow;
use snitchhiker_proto::v1;

use crate::backend::Update;

/// The events loaded, newest first, without duplicates (a resumed subscription may repeat some).
#[derive(Debug, Default)]
pub struct Events {
    rows: VecDeque<EventRow>,
    seen: HashSet<i64>,
    strings: HashMap<u32, String>,
    /// Older events may exist: scrolling down loads them.
    pub more: bool,
}

impl Events {
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<&EventRow> {
        self.rows.get(index)
    }

    /// The oldest event's seq: where the next page of history starts.
    #[must_use]
    pub fn oldest(&self) -> Option<i64> {
        self.rows.back().map(|r| r.seq)
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
                live,
                more,
            } => {
                self.events.add(&rows, strings);
                if !live {
                    self.events.more = more;
                }
                Changed::Events
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
        assert_eq!(events.oldest(), Some(8));
        assert_eq!(events.string(1), Some("/usr/bin/curl"));
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
