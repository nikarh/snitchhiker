//! Names of addresses, learned from the DNS answers processes receive.
//!
//! An answer counts only for the name asked and its CNAME chain (a resolver can't attach other names to addresses),
//! and only if the query it answers was really sent: the answer's destination port is a socket the attribution
//! programs saw send a query to that resolver. That query also says which process asked, so a connection is matched
//! first against the names *its own process* resolved for the address, then against any name recently resolved for
//! it (for programs that resolve through systemd-resolved, whose own queries are the ones seen).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arrayvec::ArrayVec;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;

/// Names kept per address.
pub const NAMES: usize = 4;
/// Answers are remembered at least this long, whatever their TTL: programs keep using addresses past it.
const MIN_KEEP: Duration = Duration::from_secs(600);
/// Entries kept in each map before the oldest are dropped.
const CAPACITY: usize = 65_536;

/// What a DNS answer says, for the name asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The name asked, lowercase, without the trailing dot.
    pub name: Arc<str>,
    /// Addresses of the name (or its aliases), with their TTL.
    pub addresses: Vec<(IpAddr, Duration)>,
}

/// Reads the answer in a DNS response; `None` for queries, malformed messages and answers without addresses.
#[must_use]
pub fn parse_answer(message: &[u8]) -> Option<Answer> {
    let message = Message::from_vec(message).ok()?;
    if message.metadata.message_type != MessageType::Response {
        return None;
    }
    let name = normalize(&message.queries.first()?.name().to_utf8());
    let records: Vec<(String, &RData, u32)> = message
        .answers
        .iter()
        .map(|record| (normalize(&record.name.to_utf8()), &record.data, record.ttl))
        .collect();
    // The name's CNAME chain, then the addresses of the names in it.
    let mut chain = vec![name.clone()];
    while let Some(target) = records.iter().find_map(|(owner, data, _)| match data {
        RData::CNAME(target) if chain.last() == Some(owner) => Some(normalize(&target.0.to_utf8())),
        _ => None,
    }) {
        if chain.contains(&target) {
            break;
        }
        chain.push(target);
    }
    let addresses: Vec<(IpAddr, Duration)> = records
        .iter()
        .filter(|(owner, _, _)| chain.contains(owner))
        .filter_map(|(_, data, ttl)| {
            let ttl = Duration::from_secs(u64::from(*ttl));
            match data {
                RData::A(address) => Some((IpAddr::V4(address.0), ttl)),
                RData::AAAA(address) => Some((IpAddr::V6(address.0), ttl)),
                _ => None,
            }
        })
        .collect();
    if addresses.is_empty() {
        return None;
    }
    Some(Answer {
        name: Arc::from(name),
        addresses,
    })
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone)]
struct Entry {
    names: ArrayVec<Arc<str>, NAMES>,
    expires_ms: u64,
    used: u64,
}

impl Entry {
    fn add(&mut self, name: &Arc<str>, expires_ms: u64) {
        if let Some(position) = self.names.iter().position(|n| n == name) {
            // Most recent first.
            self.names.remove(position);
        } else if self.names.is_full() {
            self.names.pop();
        }
        self.names.insert(0, Arc::clone(name));
        self.expires_ms = self.expires_ms.max(expires_ms);
    }
}

/// Names by (process, address) and by address alone.
#[derive(Debug, Default)]
pub struct Names {
    by_process: HashMap<(u32, IpAddr), Entry>,
    by_address: HashMap<IpAddr, Entry>,
    clock: u64,
}

impl Names {
    /// Remembers an answer received by process `pid` (0: unknown) at `now_ms`.
    pub fn learn(&mut self, pid: u32, answer: &Answer, now_ms: u64) {
        self.clock += 1;
        for &(address, ttl) in &answer.addresses {
            let keep = u64::try_from(ttl.max(MIN_KEEP).as_millis()).unwrap_or(u64::MAX);
            let expires = now_ms.saturating_add(keep);
            let clock = self.clock;
            let fresh = || Entry {
                names: ArrayVec::new(),
                expires_ms: expires,
                used: clock,
            };
            if pid != 0 {
                let entry = self.by_process.entry((pid, address)).or_insert_with(fresh);
                entry.add(&answer.name, expires);
                entry.used = clock;
            }
            let entry = self.by_address.entry(address).or_insert_with(fresh);
            entry.add(&answer.name, expires);
            entry.used = clock;
        }
        if self.by_process.len() > CAPACITY {
            evict(&mut self.by_process, now_ms);
        }
        if self.by_address.len() > CAPACITY {
            evict(&mut self.by_address, now_ms);
        }
    }

    /// The names for a connection of `pid` to `address`: those its process resolved, else any recently resolved.
    /// Copies at most [`NAMES`] reference-counted names; allocates nothing.
    #[must_use]
    pub fn lookup(&self, pid: u32, address: IpAddr, now_ms: u64) -> ArrayVec<Arc<str>, NAMES> {
        let live = |entry: &&Entry| entry.expires_ms > now_ms;
        self.by_process
            .get(&(pid, address))
            .filter(live)
            .or_else(|| self.by_address.get(&address).filter(live))
            .map_or_else(ArrayVec::new, |entry| entry.names.clone())
    }
}

/// Drops expired entries, and the least recently used half if that isn't enough.
fn evict<K: Eq + std::hash::Hash>(map: &mut HashMap<K, Entry>, now_ms: u64) {
    map.retain(|_, entry| entry.expires_ms > now_ms);
    if map.len() > CAPACITY / 2 {
        let mut uses: Vec<u64> = map.values().map(|e| e.used).collect();
        uses.sort_unstable();
        let cutoff = uses.get(uses.len() / 2).copied().unwrap_or(0);
        map.retain(|_, entry| entry.used > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, Record, RecordType};

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_str(text).unwrap()
    }

    fn a(owner: &str, address: &str, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(address.parse().unwrap())))
    }

    fn response(asked: &str, answers: Vec<Record>) -> Vec<u8> {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name(asked), RecordType::A));
        for answer in answers {
            message.add_answer(answer);
        }
        message.to_vec().unwrap()
    }

    #[test]
    fn follows_the_cname_chain_and_ignores_other_names() {
        let message = response(
            "www.Example.test.",
            vec![
                a("evil.test.", "203.0.113.66", 60),
                Record::from_rdata(
                    name("www.example.test."),
                    60,
                    RData::CNAME(CNAME(name("edge.cdn.test."))),
                ),
                a("edge.cdn.test.", "198.51.100.7", 30),
            ],
        );
        let answer = parse_answer(&message).unwrap();
        assert_eq!(&*answer.name, "www.example.test");
        assert_eq!(
            answer.addresses,
            vec![("198.51.100.7".parse().unwrap(), Duration::from_secs(30))]
        );
    }

    #[test]
    fn stops_at_cname_loops() {
        let message = response(
            "a.test.",
            vec![
                Record::from_rdata(name("a.test."), 60, RData::CNAME(CNAME(name("b.test.")))),
                Record::from_rdata(name("b.test."), 60, RData::CNAME(CNAME(name("a.test.")))),
            ],
        );
        assert_eq!(parse_answer(&message), None);
    }

    #[test]
    fn ignores_queries_and_garbage() {
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name("a.test."), RecordType::A));
        assert_eq!(parse_answer(&query.to_vec().unwrap()), None);
        assert_eq!(parse_answer(&[1, 2, 3]), None);
    }

    #[test]
    fn a_process_sees_its_own_names_first() {
        let mut names = Names::default();
        let address: IpAddr = "198.51.100.7".parse().unwrap();
        let mine = Answer {
            name: Arc::from("mine.test"),
            addresses: vec![(address, Duration::from_secs(1))],
        };
        let theirs = Answer {
            name: Arc::from("theirs.test"),
            addresses: vec![(address, Duration::from_secs(1))],
        };
        names.learn(10, &mine, 0);
        names.learn(20, &theirs, 0);
        assert_eq!(&*names.lookup(10, address, 1)[0], "mine.test");
        assert_eq!(&*names.lookup(20, address, 1)[0], "theirs.test");
        // A process that resolved nothing gets the most recent name for the address.
        assert_eq!(&*names.lookup(30, address, 1)[0], "theirs.test");
    }

    #[test]
    fn entries_last_at_least_ten_minutes_then_expire() {
        let mut names = Names::default();
        let address: IpAddr = "198.51.100.7".parse().unwrap();
        names.learn(
            0,
            &Answer {
                name: Arc::from("x.test"),
                addresses: vec![(address, Duration::from_secs(1))],
            },
            0,
        );
        assert_eq!(names.lookup(1, address, 599_000).len(), 1);
        assert!(names.lookup(1, address, 600_001).is_empty());
    }
}
