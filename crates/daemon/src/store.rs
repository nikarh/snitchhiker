//! The daemon's state: rules, folders and the connection history, in one SQLite database.
//!
//! Every statement the daemon runs is in [`STATEMENTS`]; a test runs `EXPLAIN QUERY PLAN` on each against a populated
//! database and fails on a table scan or a temporary sort, so every query stays an index seek. Strings that repeat
//! (executables, hosts) are stored once and referred to by id.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};
use snitchhiker_core::rule::{Action, Expiry, Folder, FolderId, Rule, RuleId, Tier};

/// The schema, applied in order; the index of the last one applied is kept in `PRAGMA user_version`.
const MIGRATIONS: &[&str] = &[
    r"
CREATE TABLE folders (
    id INTEGER PRIMARY KEY,
    parent INTEGER REFERENCES folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    scope TEXT NOT NULL
);
CREATE INDEX folders_parent ON folders(parent);

CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    folder INTEGER REFERENCES folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    action TEXT NOT NULL,
    tier TEXT NOT NULL,
    expiry TEXT NOT NULL,
    log INTEGER NOT NULL,
    notes TEXT NOT NULL,
    conditions TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE INDEX rules_folder ON rules(folder);

CREATE TABLE strings (
    id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE events (
    seq INTEGER PRIMARY KEY,
    time_ms INTEGER NOT NULL,
    exe INTEGER NOT NULL REFERENCES strings(id),
    host INTEGER REFERENCES strings(id),
    uid INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    address BLOB NOT NULL,
    port INTEGER NOT NULL,
    context INTEGER NOT NULL,
    action INTEGER NOT NULL,
    source INTEGER NOT NULL,
    rule INTEGER
);
CREATE INDEX events_time ON events(time_ms);
CREATE INDEX events_exe ON events(exe, seq);
CREATE INDEX events_host ON events(host, seq);
",
    r"
ALTER TABLE events ADD COLUMN cookie INTEGER;
ALTER TABLE events ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0;
CREATE INDEX events_cookie ON events(cookie, seq) WHERE cookie IS NOT NULL;
",
];

/// What kind of string a `strings` row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StringKind {
    Exe = 1,
    Host = 2,
}

/// Why a connection got its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Source {
    /// A rule decided.
    Rule = 1,
    /// No rule matched; the node's policy decided.
    Policy = 2,
    /// Monitor mode: let through whatever a rule or the policy said.
    Monitor = 3,
    /// A client answered a prompt.
    Prompt = 4,
    /// Nobody answered a prompt in time.
    Timeout = 5,
}

/// A connection to record.
#[derive(Debug, Clone)]
pub struct Event {
    pub time_ms: u64,
    pub exe: std::sync::Arc<str>,
    pub host: Option<std::sync::Arc<str>>,
    pub uid: u32,
    pub pid: u32,
    pub protocol: u8,
    pub address: std::net::IpAddr,
    pub port: u16,
    pub context: u8,
    pub action: Action,
    pub source: Source,
    pub rule: Option<RuleId>,
    /// The socket's cookie, to attribute its bytes to this event; `None` when the socket isn't known.
    pub cookie: Option<u64>,
}

/// Named statements; the only SQL the daemon runs.
pub const STATEMENTS: &[(&str, &str)] = &[
    ("folders.all", "SELECT id, parent, name, enabled, scope FROM folders"),
    (
        "rules.all",
        "SELECT id, folder, name, enabled, action, tier, expiry, log, notes, conditions FROM rules",
    ),
    (
        "rules.insert",
        "INSERT INTO rules (folder, name, enabled, action, tier, expiry, log, notes, conditions, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    ),
    ("rules.delete", "DELETE FROM rules WHERE id = ?1"),
    (
        "rules.set_enabled",
        "UPDATE rules SET enabled = ?2, updated_ms = ?3 WHERE id = ?1",
    ),
    (
        "rules.delete_until_restart",
        "DELETE FROM rules WHERE expiry = '{\"kind\":\"until-restart\"}'",
    ),
    (
        "folders.insert",
        "INSERT INTO folders (parent, name, enabled, scope) VALUES (?1, ?2, ?3, ?4)",
    ),
    (
        "strings.find",
        "SELECT id FROM strings WHERE kind = ?1 AND value = ?2",
    ),
    (
        "strings.insert",
        "INSERT INTO strings (kind, value) VALUES (?1, ?2)",
    ),
    (
        "events.insert",
        "INSERT INTO events (time_ms, exe, host, uid, pid, protocol, address, port, context, action, source, rule,
                             cookie)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    ),
    (
        "events.page",
        "SELECT e.seq, e.time_ms, x.value, h.value, e.uid, e.pid, e.protocol, e.address, e.port, e.context,
                e.action, e.source, e.rule, e.bytes_out, e.bytes_in
         FROM events e CROSS JOIN strings x ON x.id = e.exe LEFT JOIN strings h ON h.id = e.host
         WHERE e.seq < ?1 ORDER BY e.seq DESC LIMIT ?2",
    ),
    // Connections no rule decided, since a time: what `learn` turns into rules.
    (
        "events.undecided_since",
        "SELECT x.value, h.value, e.uid, e.protocol, e.address, e.port
         FROM events e INDEXED BY events_time
              CROSS JOIN strings x ON x.id = e.exe LEFT JOIN strings h ON h.id = e.host
         WHERE e.time_ms >= ?1 AND e.source != 1",
    ),
    // A socket's bytes go to its newest event: an unconnected UDP socket may have several, one per destination.
    (
        "events.bytes",
        "UPDATE events SET bytes_out = ?2, bytes_in = ?3
         WHERE seq = (SELECT seq FROM events WHERE cookie = ?1 ORDER BY seq DESC LIMIT 1)",
    ),
    (
        "events.prune",
        "DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE time_ms < ?1 ORDER BY time_ms LIMIT ?2)",
    ),
];

/// Tables small enough that scanning them is fine (and SQLite may choose to).
#[cfg(test)]
const SCANNABLE: &[&str] = &["folders", "rules"];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("stored {what} isn't valid: {error}")]
    Corrupt { what: &'static str, error: String },
    #[error("no statement named {0}")]
    UnknownStatement(&'static str),
}

/// A recorded connection, as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub seq: i64,
    pub time_ms: u64,
    pub exe: String,
    pub host: Option<String>,
    pub uid: u32,
    pub pid: u32,
    pub protocol: u8,
    pub address: std::net::IpAddr,
    pub port: u16,
    pub context: u8,
    pub action: Action,
    pub source: u8,
    pub rule: Option<RuleId>,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// A connection no rule decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undecided {
    pub exe: String,
    pub host: Option<String>,
    pub uid: u32,
    pub protocol: u8,
    pub address: std::net::IpAddr,
    pub port: u16,
}

pub struct Store {
    connection: Connection,
    strings: HashMap<(StringKind, std::sync::Arc<str>), i64>,
}

fn sql(name: &'static str) -> Result<&'static str, Error> {
    STATEMENTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, sql)| *sql)
        .ok_or(Error::UnknownStatement(name))
}

impl Store {
    /// Opens (or creates) the database and brings its schema up to date.
    pub fn open(path: &Path) -> Result<Self, Error> {
        Self::init(Connection::open(path)?)
    }

    /// An in-memory database, for tests.
    pub fn in_memory() -> Result<Self, Error> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(connection: Connection) -> Result<Self, Error> {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let version = usize::try_from(version).unwrap_or(0);
        for (index, migration) in MIGRATIONS.iter().enumerate().skip(version) {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(migration)?;
            transaction.pragma_update(
                None,
                "user_version",
                i64::try_from(index + 1).unwrap_or(i64::MAX),
            )?;
            transaction.commit()?;
        }
        Ok(Self {
            connection,
            strings: HashMap::new(),
        })
    }

    pub fn folders(&self) -> Result<Vec<Folder>, Error> {
        let mut statement = self.connection.prepare_cached(sql("folders.all")?)?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (id, parent, name, enabled, scope) = row?;
            Ok(Folder {
                id: id_of(id),
                parent: parent.map(id_of),
                name,
                enabled,
                scope: serde_json::from_str(&scope).map_err(|e| Error::Corrupt {
                    what: "folder scope",
                    error: e.to_string(),
                })?,
            })
        })
        .collect()
    }

    pub fn rules(&self) -> Result<Vec<Rule>, Error> {
        let mut statement = self.connection.prepare_cached(sql("rules.all")?)?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;
        rows.map(|row| {
            let (id, folder, name, enabled, action, tier, expiry, log, notes, conditions) = row?;
            let corrupt = |what| {
                move |e: serde_json::Error| Error::Corrupt {
                    what,
                    error: e.to_string(),
                }
            };
            Ok(Rule {
                id: id_of(id),
                folder: folder.map(id_of),
                name,
                enabled,
                action: serde_json::from_str::<Action>(&action).map_err(corrupt("rule action"))?,
                tier: serde_json::from_str::<Tier>(&tier).map_err(corrupt("rule tier"))?,
                expiry: serde_json::from_str::<Expiry>(&expiry).map_err(corrupt("rule expiry"))?,
                log,
                notes,
                conditions: serde_json::from_str(&conditions)
                    .map_err(corrupt("rule conditions"))?,
            })
        })
        .collect()
    }

    /// Adds a rule (its `id` is ignored) and returns the id it got.
    pub fn insert_rule(&mut self, rule: &Rule, now_ms: u64) -> Result<RuleId, Error> {
        let mut statement = self.connection.prepare_cached(sql("rules.insert")?)?;
        statement.execute(params![
            rule.folder.map(db_id),
            rule.name,
            rule.enabled,
            json(&rule.action),
            json(&rule.tier),
            json(&rule.expiry),
            rule.log,
            rule.notes,
            json(&rule.conditions),
            db_id(now_ms),
        ])?;
        Ok(id_of(self.connection.last_insert_rowid()))
    }

    /// Switches a rule on or off; whether it exists.
    pub fn set_rule_enabled(
        &mut self,
        id: RuleId,
        enabled: bool,
        now_ms: u64,
    ) -> Result<bool, Error> {
        let mut statement = self.connection.prepare_cached(sql("rules.set_enabled")?)?;
        Ok(statement.execute(params![db_id(id), enabled, db_id(now_ms)])? > 0)
    }

    /// Deletes the rules that only applied until the daemon restarted.
    pub fn delete_until_restart(&mut self) -> Result<usize, Error> {
        let mut statement = self
            .connection
            .prepare_cached(sql("rules.delete_until_restart")?)?;
        Ok(statement.execute([])?)
    }

    pub fn delete_rule(&mut self, id: RuleId) -> Result<bool, Error> {
        let mut statement = self.connection.prepare_cached(sql("rules.delete")?)?;
        Ok(statement.execute(params![db_id(id)])? > 0)
    }

    /// Adds a folder (its `id` is ignored) and returns the id it got.
    pub fn insert_folder(&mut self, folder: &Folder) -> Result<FolderId, Error> {
        let mut statement = self.connection.prepare_cached(sql("folders.insert")?)?;
        statement.execute(params![
            folder.parent.map(db_id),
            folder.name,
            folder.enabled,
            serde_json::to_string(&folder.scope).unwrap_or_else(|_| "[]".to_owned()),
        ])?;
        Ok(id_of(self.connection.last_insert_rowid()))
    }

    /// Records events in one transaction.
    pub fn record(&mut self, events: &[Event]) -> Result<(), Error> {
        let transaction = self.connection.unchecked_transaction()?;
        for event in events {
            let exe = intern(
                &self.connection,
                &mut self.strings,
                StringKind::Exe,
                &event.exe,
            )?;
            let host = match &event.host {
                Some(host) => Some(intern(
                    &self.connection,
                    &mut self.strings,
                    StringKind::Host,
                    host,
                )?),
                None => None,
            };
            let address = match event.address {
                std::net::IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
                std::net::IpAddr::V6(a) => a.octets(),
            };
            self.connection
                .prepare_cached(sql("events.insert")?)?
                .execute(params![
                    db_id(event.time_ms),
                    exe,
                    host,
                    event.uid,
                    event.pid,
                    event.protocol,
                    &address[..],
                    event.port,
                    event.context,
                    action_code(event.action),
                    event.source as u8,
                    event.rule.map(db_id),
                    event.cookie.map(db_id),
                ])?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The newest events before `before` (a sequence number; `i64::MAX` for the newest), at most `limit`.
    pub fn events(&self, before: i64, limit: u32) -> Result<Vec<StoredEvent>, Error> {
        let mut statement = self.connection.prepare_cached(sql("events.page")?)?;
        let rows = statement.query_map(params![before, limit], |row| {
            let address: Vec<u8> = row.get(7)?;
            let address = address_from(&address);
            Ok(StoredEvent {
                seq: row.get(0)?,
                time_ms: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                exe: row.get(2)?,
                host: row.get(3)?,
                uid: row.get(4)?,
                pid: row.get(5)?,
                protocol: row.get(6)?,
                address,
                port: row.get(8)?,
                context: row.get(9)?,
                action: action_from(row.get(10)?),
                source: row.get(11)?,
                rule: row.get::<_, Option<i64>>(12)?.map(id_of),
                bytes_out: id_of(row.get(13)?),
                bytes_in: id_of(row.get(14)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Connections no rule decided since `since_ms`: (exe, host, uid, protocol, address, port).
    pub fn undecided_since(&self, since_ms: u64) -> Result<Vec<Undecided>, Error> {
        let mut statement = self
            .connection
            .prepare_cached(sql("events.undecided_since")?)?;
        let rows = statement.query_map(params![db_id(since_ms)], |row| {
            let address: Vec<u8> = row.get(4)?;
            Ok(Undecided {
                exe: row.get(0)?,
                host: row.get(1)?,
                uid: row.get(2)?,
                protocol: row.get(3)?,
                address: address_from(&address),
                port: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Records a socket's byte counts (totals so far) on its newest event.
    pub fn record_bytes(&mut self, counts: &[(u64, u64, u64)]) -> Result<(), Error> {
        let transaction = self.connection.unchecked_transaction()?;
        {
            let mut statement = self.connection.prepare_cached(sql("events.bytes")?)?;
            for &(cookie, sent, read) in counts {
                statement.execute(params![db_id(cookie), db_id(sent), db_id(read)])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Deletes up to `limit` of the events older than `before_ms`; returns how many. Called in small chunks, so pruning
    /// never holds the database for long.
    pub fn prune(&mut self, before_ms: u64, limit: u32) -> Result<usize, Error> {
        let mut statement = self.connection.prepare_cached(sql("events.prune")?)?;
        Ok(statement.execute(params![db_id(before_ms), limit])?)
    }

    #[cfg(test)]
    fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// The id of a string, adding it if new. Cached, so repeated strings cost no query.
fn intern(
    connection: &Connection,
    cache: &mut HashMap<(StringKind, std::sync::Arc<str>), i64>,
    kind: StringKind,
    value: &std::sync::Arc<str>,
) -> Result<i64, Error> {
    if let Some(&id) = cache.get(&(kind, std::sync::Arc::clone(value))) {
        return Ok(id);
    }
    let found: Option<i64> = connection
        .prepare_cached(sql("strings.find")?)?
        .query_row(params![kind as u8, &**value], |row| row.get(0))
        .optional()?;
    let id = if let Some(id) = found {
        id
    } else {
        connection
            .prepare_cached(sql("strings.insert")?)?
            .execute(params![kind as u8, &**value])?;
        connection.last_insert_rowid()
    };
    cache.insert((kind, std::sync::Arc::clone(value)), id);
    Ok(id)
}

/// A column's JSON (the model's types always serialize).
fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// An address as stored: 16 bytes, IPv4 mapped into IPv6.
fn address_from(bytes: &[u8]) -> std::net::IpAddr {
    <[u8; 16]>::try_from(bytes).map_or(
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        |octets| {
            let v6 = std::net::Ipv6Addr::from(octets);
            v6.to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4)
        },
    )
}

fn action_code(action: Action) -> u8 {
    match action {
        Action::Allow => 1,
        Action::Deny => 2,
        Action::Reject => 3,
    }
}

fn action_from(code: u8) -> Action {
    match code {
        1 => Action::Allow,
        3 => Action::Reject,
        _ => Action::Deny,
    }
}

/// Ids and times are unsigned in the model and signed in SQLite; both stay far below 2^63.
fn db_id(id: u64) -> i64 {
    i64::try_from(id).unwrap_or(i64::MAX)
}

fn id_of(id: i64) -> u64 {
    u64::try_from(id).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use snitchhiker_core::rule::Condition;

    use super::*;

    fn event(seq: u64, exe: &str, host: Option<&str>) -> Event {
        Event {
            time_ms: 1_000 + seq,
            exe: Arc::from(exe),
            host: host.map(Arc::from),
            uid: 1000,
            pid: 42,
            protocol: 6,
            address: "198.51.100.7".parse().unwrap(),
            port: 443,
            context: 0,
            action: Action::Allow,
            source: Source::Rule,
            rule: Some(1),
            cookie: Some(seq),
        }
    }

    #[test]
    fn rules_round_trip() {
        let mut store = Store::in_memory().unwrap();
        let folder = store
            .insert_folder(&Folder {
                id: 0,
                parent: None,
                name: "Apps".into(),
                enabled: true,
                scope: vec![Condition::Uid(vec![1000])],
            })
            .unwrap();
        let rule = Rule {
            id: 0,
            folder: Some(folder),
            name: "curl".into(),
            enabled: true,
            action: Action::Reject,
            tier: Tier::Override,
            expiry: Expiry::At(5),
            log: false,
            notes: "n".into(),
            conditions: vec![Condition::Port(vec![(443, 443)])],
        };
        let id = store.insert_rule(&rule, 1).unwrap();
        let stored = store.rules().unwrap();
        assert_eq!(stored, vec![Rule { id, ..rule }]);
        assert_eq!(
            store.folders().unwrap()[0].scope,
            vec![Condition::Uid(vec![1000])]
        );
        assert!(store.delete_rule(id).unwrap());
        assert_eq!(store.rules().unwrap(), vec![]);
    }

    #[test]
    fn events_round_trip_newest_first_with_strings_shared() {
        let mut store = Store::in_memory().unwrap();
        store
            .record(&[
                event(1, "/usr/bin/curl", Some("example.com")),
                event(2, "/usr/bin/curl", None),
                event(3, "/usr/bin/wget", Some("example.com")),
            ])
            .unwrap();
        let page = store.events(i64::MAX, 2).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].exe, "/usr/bin/wget");
        assert_eq!(page[1].host, None);
        assert_eq!(page[0].address, "198.51.100.7".parse::<IpAddr>().unwrap());
        let older = store.events(page[1].seq, 10).unwrap();
        assert_eq!(older.len(), 1);
        let strings: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM strings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(strings, 3);
    }

    #[test]
    fn bytes_go_to_the_sockets_newest_event() {
        let mut store = Store::in_memory().unwrap();
        let mut first = event(1, "/usr/bin/curl", None);
        let mut second = event(2, "/usr/bin/curl", None);
        first.cookie = Some(77);
        second.cookie = Some(77);
        store.record(&[first, second]).unwrap();
        store.record_bytes(&[(77, 1000, 5000)]).unwrap();
        let page = store.events(i64::MAX, 10).unwrap();
        assert_eq!((page[0].bytes_out, page[0].bytes_in), (1000, 5000));
        assert_eq!((page[1].bytes_out, page[1].bytes_in), (0, 0));
    }

    #[test]
    fn prunes_in_chunks() {
        let mut store = Store::in_memory().unwrap();
        let events: Vec<Event> = (0..10).map(|i| event(i, "/usr/bin/curl", None)).collect();
        store.record(&events).unwrap();
        assert_eq!(store.prune(1_005, 3).unwrap(), 3);
        assert_eq!(store.prune(1_005, 3).unwrap(), 2);
        assert_eq!(store.events(i64::MAX, 100).unwrap().len(), 5);
    }

    /// Every statement is an index seek: no scan of a growing table, no temporary sort.
    #[test]
    fn every_statement_uses_an_index() {
        let mut store = Store::in_memory().unwrap();
        // Enough rows that the planner can't prefer a scan for size reasons.
        let events: Vec<Event> = (0..2000)
            .map(|i| {
                event(
                    i,
                    &format!("/usr/bin/x{}", i % 50),
                    Some(&format!("h{}.example.com", i % 70)),
                )
            })
            .collect();
        store.record(&events).unwrap();
        store.connection().execute_batch("ANALYZE").unwrap();
        for (name, sql) in STATEMENTS {
            let params = sql.matches('?').count();
            let mut plan = store
                .connection()
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let values: Vec<rusqlite::types::Value> = (0..params)
                .map(|_| rusqlite::types::Value::Integer(1))
                .collect();
            let details: Vec<String> = plan
                .query_map(rusqlite::params_from_iter(values), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            for detail in &details {
                let scans_growing_table = detail.starts_with("SCAN")
                    && !SCANNABLE.iter().any(|t| detail == &format!("SCAN {t}"));
                assert!(!scans_growing_table, "{name} scans: {details:?}");
                assert!(!detail.contains("TEMP B-TREE"), "{name} sorts: {details:?}");
            }
        }
    }
}
