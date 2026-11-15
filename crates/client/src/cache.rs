//! A client's cache of a node's history (plan §11.6): the events it loaded, the strings they use, and which ranges of
//! sequence numbers it holds, so nothing is fetched twice and a query over a range held completely runs locally.
//!
//! Coverage is kept per query: a range held *completely* (from pages of every event, and from the live stream) answers
//! any query, evaluated with the same code the node's SQL calls; a range held for query Q (the node's answer to Q there)
//! answers Q only. A coverage range reaching the start of the node's history has its low end at 0.
//!
//! The cache holds connection history: it belongs where only the app can reach it (see `cache_dir`). A node whose
//! epoch changed (its database was recreated) starts a new cache.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension as _, params};
use snitchhiker_core::query::{EventFilter, EventView};
use snitchhiker_proto::columns::EventRow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the cache: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("the cache: {0}")]
    Io(#[from] std::io::Error),
}

/// Where the app's caches are: a directory only the app's group can enter (`root:snitchhiker-ui 0770`, made by its
/// package), with one directory per user in it. The user's other processes can't reach the files, though they are the
/// user's.
pub const CACHE_ROOT: &str = "/var/cache/snitchhiker-ui";

/// The user's cache directory, made if needed (mode 0700); `None` without the root directory (an app not installed
/// by its package).
#[must_use]
pub fn cache_dir(uid: u32) -> Option<PathBuf> {
    let root = Path::new(CACHE_ROOT);
    if !root.is_dir() {
        return None;
    }
    let dir = root.join(uid.to_string());
    if !dir.is_dir() {
        std::fs::create_dir(&dir).ok()?;
    }
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).ok()?;
    Some(dir)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS strings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    time_ms INTEGER NOT NULL,
    exe INTEGER NOT NULL,
    host INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    address BLOB NOT NULL,
    port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    context INTEGER NOT NULL,
    action INTEGER NOT NULL,
    source INTEGER NOT NULL,
    rule INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    container INTEGER NOT NULL
);
-- [low, high) of sequence numbers held for `query` ('' : every event).
CREATE TABLE IF NOT EXISTS coverage (query TEXT NOT NULL, low INTEGER NOT NULL, high INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS coverage_query ON coverage(query, low);
";

/// A page answered from the cache: rows newest first, the strings they use, and where the next page starts (0:
/// nothing older), as the node answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub rows: Vec<EventRow>,
    pub strings: Vec<(u32, String)>,
    pub scanned_from: i64,
}

pub struct Cache {
    connection: Connection,
}

fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn uint(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

impl Cache {
    /// The cache of node `epoch` in `dir` (one file per epoch: a recreated node starts afresh).
    pub fn open(dir: &Path, epoch: u64) -> Result<Self, Error> {
        // The format is in the name: a cache of an older format is dropped as another epoch's is.
        let path = dir.join(format!("{epoch:016x}.v2.db"));
        // Caches of other epochs are of a database that is gone.
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let other = entry.path();
                let name = other
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                let mine = path
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                // Another epoch's database, with its journal files.
                if !name.starts_with(&mine)
                    && [".db", ".db-wal", ".db-shm"]
                        .iter()
                        .any(|e| name.ends_with(e))
                {
                    let _ = std::fs::remove_file(other);
                }
            }
        }
        let connection = Connection::open(&path)?;
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        Self::init(connection)
    }

    /// A cache in memory, for tests.
    pub fn in_memory() -> Result<Self, Error> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(connection: Connection) -> Result<Self, Error> {
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    fn insert(&self, rows: &[EventRow], strings: &[(u32, String)]) -> Result<(), Error> {
        let mut string = self
            .connection
            .prepare_cached("INSERT OR REPLACE INTO strings (id, value) VALUES (?1, ?2)")?;
        for (id, value) in strings {
            string.execute(params![id, value])?;
        }
        let mut event = self.connection.prepare_cached(
            "INSERT OR REPLACE INTO events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        )?;
        for r in rows {
            event.execute(params![
                r.seq,
                int(r.time_ms),
                r.exe,
                r.host,
                r.uid,
                r.pid,
                &r.address[..],
                r.port,
                r.protocol,
                r.context,
                r.action,
                r.source,
                int(r.rule),
                int(r.bytes_out),
                int(r.bytes_in),
                r.container,
            ])?;
        }
        Ok(())
    }

    /// Records that `[low, high)` is held for `query`, merged with what touches it.
    fn cover(&self, query: &str, low: i64, high: i64) -> Result<(), Error> {
        if high <= low {
            return Ok(());
        }
        let mut statement = self.connection.prepare_cached(
            "SELECT rowid, low, high FROM coverage WHERE query = ?1 AND low <= ?3 AND high >= ?2",
        )?;
        let touching: Vec<(i64, i64, i64)> = statement
            .query_map(params![query, low, high], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        let (mut low, mut high) = (low, high);
        for (rowid, l, h) in touching {
            low = low.min(l);
            high = high.max(h);
            self.connection
                .execute("DELETE FROM coverage WHERE rowid = ?1", params![rowid])?;
        }
        self.connection.execute(
            "INSERT INTO coverage (query, low, high) VALUES (?1, ?2, ?3)",
            params![query, low, high],
        )?;
        Ok(())
    }

    /// Keeps a page the node answered: `rows` before `before` (`i64::MAX`: the newest) for `query`, which looked as
    /// far back as `scanned_from` (0: the start of history). A page of the newest events covers up to its newest row.
    pub fn add_page(
        &mut self,
        rows: &[EventRow],
        strings: &[(u32, String)],
        before: i64,
        scanned_from: i64,
        query: &str,
    ) -> Result<(), Error> {
        let transaction = self.connection.unchecked_transaction()?;
        self.insert(rows, strings)?;
        let high = if before == i64::MAX || before == 0 {
            rows.iter().map(|r| r.seq + 1).max()
        } else {
            Some(before)
        };
        if let Some(high) = high {
            let low = if scanned_from == 0 { 0 } else { scanned_from };
            self.cover(query.trim(), low, high)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Keeps events of the live stream: every event from `after + 1` on (the subscription's resume point; `None` when
    /// it started at the newest, so only the rows' own span is known whole).
    pub fn add_live(
        &mut self,
        rows: &[EventRow],
        strings: &[(u32, String)],
        after: Option<i64>,
    ) -> Result<(), Error> {
        let transaction = self.connection.unchecked_transaction()?;
        self.insert(rows, strings)?;
        if let (Some(low), Some(high)) = (
            after
                .map(|a| a + 1)
                .or_else(|| rows.iter().map(|r| r.seq).min()),
            rows.iter().map(|r| r.seq + 1).max(),
        ) {
            self.cover("", low, high)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The range around `seq` held for `query` (or completely), and whether it is the complete one.
    fn covering(&self, seq: i64, query: &str) -> Result<Option<(i64, bool)>, Error> {
        for (q, complete) in [("", true), (query.trim(), false)] {
            if !complete && q.is_empty() {
                continue;
            }
            let low: Option<i64> = self
                .connection
                .prepare_cached(
                    "SELECT low FROM coverage WHERE query = ?1 AND low <= ?2 AND high > ?2",
                )?
                .query_row(params![q, seq], |row| row.get(0))
                .optional()?;
            if let Some(low) = low {
                return Ok(Some((low, complete)));
            }
        }
        Ok(None)
    }

    /// The page the node would answer for `query` (compiled as `filter`) before `before`, when the cache holds that
    /// range; `None` when it doesn't.
    pub fn page(
        &self,
        before: i64,
        limit: usize,
        query: &str,
        filter: Option<&EventFilter>,
    ) -> Result<Option<Page>, Error> {
        if before <= 0 || before == i64::MAX {
            // The newest: only the node knows what is newest.
            return Ok(None);
        }
        let Some((low, complete)) = self.covering(before - 1, query)? else {
            return Ok(None);
        };
        let mut statement = self.connection.prepare_cached(
            "SELECT seq, time_ms, exe, host, uid, pid, address, port, protocol, context, action, source, rule,
                    bytes_out, bytes_in, container
             FROM events WHERE seq < ?1 AND seq >= ?2 ORDER BY seq DESC",
        )?;
        let candidates = statement.query_map(params![before, low], |row| {
            let address: Vec<u8> = row.get(6)?;
            Ok(EventRow {
                seq: row.get(0)?,
                time_ms: uint(row.get(1)?),
                exe: row.get(2)?,
                host: row.get(3)?,
                uid: row.get(4)?,
                pid: row.get(5)?,
                address: address.try_into().unwrap_or([0; 16]),
                port: row.get(7)?,
                protocol: row.get(8)?,
                context: row.get(9)?,
                action: row.get(10)?,
                source: row.get(11)?,
                rule: uint(row.get(12)?),
                bytes_out: uint(row.get(13)?),
                bytes_in: uint(row.get(14)?),
                container: row.get(15)?,
            })
        })?;
        let mut rows = Vec::new();
        let mut strings = Strings::new(&self.connection);
        for row in candidates {
            let row = row?;
            // A range held for this very query holds only its matches; a complete one is filtered here, with the
            // code the node's SQL calls.
            let keep = !complete || filter.is_none_or(|f| f.matches(&strings.view(&row)));
            if keep {
                rows.push(row);
                if rows.len() >= limit {
                    break;
                }
            }
        }
        let scanned_from = if rows.len() >= limit {
            rows.last().map_or(low, |r| r.seq)
        } else {
            low
        };
        let strings = strings.used(&rows);
        Ok(Some(Page {
            rows,
            strings,
            scanned_from,
        }))
    }

    /// Forgets what the node no longer has: events before its oldest. Coverage reaching that far reaches the start.
    pub fn clamp(&mut self, oldest: i64) -> Result<(), Error> {
        self.connection
            .execute("DELETE FROM events WHERE seq < ?1", params![oldest])?;
        self.connection
            .execute("DELETE FROM coverage WHERE high <= ?1", params![oldest])?;
        self.connection.execute(
            "UPDATE coverage SET low = 0 WHERE low <= ?1",
            params![oldest],
        )?;
        Ok(())
    }

    /// Keeps at most `max` events, the newest; coverage of what was dropped goes with it.
    pub fn budget(&mut self, max: u64) -> Result<(), Error> {
        let cut: Option<i64> = self
            .connection
            .query_row(
                "SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1",
                params![int(max)],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(cut) = cut {
            self.connection
                .execute("DELETE FROM events WHERE seq <= ?1", params![cut])?;
            self.connection
                .execute("DELETE FROM coverage WHERE high <= ?1 + 1", params![cut])?;
            self.connection.execute(
                "UPDATE coverage SET low = ?1 + 1 WHERE low <= ?1",
                params![cut],
            )?;
        }
        Ok(())
    }

    /// Events held.
    pub fn len(&self) -> Result<u64, Error> {
        let count: i64 = self
            .connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
        Ok(uint(count))
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }
}

/// The cache's strings, looked up as rows need them.
struct Strings<'a> {
    connection: &'a Connection,
    known: std::collections::HashMap<u32, String>,
}

impl<'a> Strings<'a> {
    fn new(connection: &'a Connection) -> Self {
        Self {
            connection,
            known: std::collections::HashMap::new(),
        }
    }

    fn get(&mut self, id: u32) -> &str {
        if id != 0 && !self.known.contains_key(&id) {
            let value: Option<String> = self
                .connection
                .query_row(
                    "SELECT value FROM strings WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()
                .ok()
                .flatten();
            self.known.insert(id, value.unwrap_or_default());
        }
        self.known.get(&id).map_or("", String::as_str)
    }

    fn view(&mut self, row: &EventRow) -> EventView<'_> {
        let _ = self.get(row.exe);
        let _ = self.get(row.host);
        let exe = self.known.get(&row.exe).map_or("", String::as_str);
        let host = if row.host == 0 {
            ""
        } else {
            self.known.get(&row.host).map_or("", String::as_str)
        };
        let v6 = std::net::Ipv6Addr::from(row.address);
        EventView {
            time_ms: row.time_ms,
            exe,
            host,
            address: v6
                .to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
            port: row.port,
            protocol: row.protocol,
            uid: row.uid,
            action: row.action,
            rule: row.rule,
            // Blocks carry the protocol's numbers, which start at 1 for the host.
            context: row.context.saturating_sub(1),
            bytes_out: row.bytes_out,
            bytes_in: row.bytes_in,
        }
    }

    /// The strings `rows` use.
    fn used(&mut self, rows: &[EventRow]) -> Vec<(u32, String)> {
        let ids: HashSet<u32> = rows
            .iter()
            .flat_map(|r| [r.exe, r.host])
            .filter(|id| *id != 0)
            .collect();
        ids.into_iter()
            .map(|id| (id, self.get(id).to_owned()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use snitchhiker_core::query::Context;

    use super::*;

    /// A node's history: events 1..=n, programs and hosts by turns, a few allowed.
    fn history(n: i64) -> (Vec<EventRow>, Vec<(u32, String)>) {
        let rows = (1..=n)
            .map(|seq| EventRow {
                seq,
                time_ms: 1_000 * u64::try_from(seq).unwrap(),
                exe: 1 + u32::try_from(seq % 3).unwrap(),
                host: if seq % 4 == 0 {
                    0
                } else {
                    10 + u32::try_from(seq % 2).unwrap()
                },
                port: if seq % 5 == 0 { 22 } else { 443 },
                action: if seq % 7 == 0 { 2 } else { 1 },
                address: std::net::Ipv4Addr::new(198, 51, 100, 7)
                    .to_ipv6_mapped()
                    .octets(),
                context: 1,
                ..EventRow::default()
            })
            .collect();
        let strings = vec![
            (1, "/usr/bin/curl".to_owned()),
            (2, "/usr/bin/wget".to_owned()),
            (3, "/usr/bin/ssh".to_owned()),
            (10, "example.com".to_owned()),
            (11, "api.example.org".to_owned()),
        ];
        (rows, strings)
    }

    fn filter(query: &str) -> Option<EventFilter> {
        let cx = Context {
            now_ms: 0,
            uid_of: &|_| None,
        };
        (!query.is_empty()).then(|| EventFilter::parse(query, &cx).unwrap())
    }

    /// What the node answers for a page: the rows before `before` matching, newest first, up to `limit`.
    fn node_page(
        all: &[EventRow],
        strings: &[(u32, String)],
        before: i64,
        limit: usize,
        query: &str,
    ) -> Vec<i64> {
        let cache = Cache::in_memory().unwrap();
        cache.insert(all, strings).unwrap();
        let mut s = Strings::new(&cache.connection);
        let f = filter(query);
        all.iter()
            .rev()
            .filter(|r| r.seq < before)
            .filter(|r| f.as_ref().is_none_or(|f| f.matches(&s.view(r))))
            .take(limit)
            .map(|r| r.seq)
            .collect()
    }

    #[test]
    fn a_completely_held_range_answers_any_query_as_the_node_would() {
        let (all, strings) = history(200);
        let mut cache = Cache::in_memory().unwrap();
        // The newest page (100 events), then the next (the rest): everything held, down to the start.
        let newest: Vec<EventRow> = all.iter().rev().take(100).copied().collect();
        cache
            .add_page(&newest, &strings, i64::MAX, 101, "")
            .unwrap();
        let older: Vec<EventRow> = all.iter().rev().skip(100).copied().collect();
        cache.add_page(&older, &strings, 101, 0, "").unwrap();
        for query in [
            "",
            "curl",
            "port:22",
            "-action:allow host:none",
            "exe:*/ssh OR host:*.org",
        ] {
            for before in [201, 150, 37] {
                let page = cache
                    .page(before, 10, query, filter(query).as_ref())
                    .unwrap()
                    .unwrap();
                let seqs: Vec<i64> = page.rows.iter().map(|r| r.seq).collect();
                assert_eq!(
                    seqs,
                    node_page(&all, &strings, before, 10, query),
                    "{query} before {before}"
                );
                // Every row comes with the strings it uses.
                for row in &page.rows {
                    assert!(page.strings.iter().any(|(id, _)| *id == row.exe));
                }
            }
        }
        // The newest is the node's to say.
        assert_eq!(cache.page(i64::MAX, 10, "", None).unwrap(), None);
    }

    #[test]
    fn a_query_held_range_answers_only_that_query() {
        let (all, strings) = history(50);
        let mut cache = Cache::in_memory().unwrap();
        let matching: Vec<EventRow> = all.iter().rev().filter(|r| r.port == 22).copied().collect();
        cache
            .add_page(&matching, &strings, 51, 0, "port:22")
            .unwrap();
        let page = cache
            .page(51, 100, "port:22", filter("port:22").as_ref())
            .unwrap()
            .unwrap();
        assert_eq!(page.rows.len(), 10);
        assert_eq!(page.scanned_from, 0);
        assert_eq!(
            cache
                .page(51, 100, "curl", filter("curl").as_ref())
                .unwrap(),
            None
        );
    }

    #[test]
    fn gaps_are_not_answered_and_coverage_merges() {
        let (all, strings) = history(30);
        let mut cache = Cache::in_memory().unwrap();
        let slice = |from: usize, to: usize| -> Vec<EventRow> {
            all[from..to].iter().rev().copied().collect()
        };
        // Events 21..=30 (the newest page) and 1..=10: 11..=20 missing.
        cache
            .add_page(&slice(20, 30), &strings, i64::MAX, 21, "")
            .unwrap();
        cache.add_page(&slice(0, 10), &strings, 11, 0, "").unwrap();
        assert!(
            cache
                .page(25, 100, "", None)
                .unwrap()
                .is_some_and(|p| p.scanned_from == 21)
        );
        assert_eq!(cache.page(15, 10, "", None).unwrap(), None);
        // The gap filled: one range from the start.
        cache
            .add_page(&slice(10, 20), &strings, 21, 11, "")
            .unwrap();
        let page = cache.page(31, 100, "", None).unwrap().unwrap();
        assert_eq!((page.rows.len(), page.scanned_from), (30, 0));
    }

    #[test]
    fn the_live_stream_extends_coverage_and_old_events_go() {
        let (all, strings) = history(20);
        let mut cache = Cache::in_memory().unwrap();
        cache
            .add_page(
                &all[..10].iter().rev().copied().collect::<Vec<_>>(),
                &strings,
                i64::MAX,
                0,
                "",
            )
            .unwrap();
        cache.add_live(&all[10..], &strings, Some(10)).unwrap();
        assert_eq!(
            cache.page(21, 100, "", None).unwrap().unwrap().rows.len(),
            20
        );
        // The node pruned events before 6: they go, and coverage from 6 is from the start.
        cache.clamp(6).unwrap();
        let page = cache.page(21, 100, "", None).unwrap().unwrap();
        assert_eq!((page.rows.len(), page.scanned_from), (15, 0));
        cache.budget(5).unwrap();
        assert_eq!(cache.len().unwrap(), 5);
        let page = cache.page(21, 100, "", None).unwrap().unwrap();
        assert_eq!((page.rows.len(), page.scanned_from), (5, 16));
    }
}
