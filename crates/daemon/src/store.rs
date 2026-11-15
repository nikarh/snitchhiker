//! The daemon's state: rules, folders and the connection history, in one SQLite database.
//!
//! Every statement the daemon runs is in [`STATEMENTS`]; a test runs `EXPLAIN QUERY PLAN` on each against a populated
//! database and fails on a table scan or a temporary sort, so every query stays an index seek. Strings that repeat
//! (executables, hosts) are stored once and referred to by id.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};
use snitchhiker_core::query::{self, EventFilter, SqlValue};
use snitchhiker_core::rule::{Action, Expiry, Folder, FolderId, Rule, RuleId, Tier};
use snitchhiker_proto::columns::EventRow;

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
    // Dangerous actions attempted, and what came of them. Kept for good: there are few.
    r"
CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    time_ms INTEGER NOT NULL,
    app TEXT NOT NULL,
    uid INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    action TEXT NOT NULL,
    outcome INTEGER NOT NULL
);
",
    // Every change to rules and folders, by whom, with the object before and after (JSON; NULL where it didn't
    // exist): their history, and what undo puts back. A batch is what one request changed.
    r"
CREATE TABLE changes (
    id INTEGER PRIMARY KEY,
    batch INTEGER NOT NULL,
    time_ms INTEGER NOT NULL,
    app TEXT NOT NULL,
    kind TEXT NOT NULL,
    target INTEGER NOT NULL,
    before TEXT,
    after TEXT,
    what TEXT NOT NULL
);
CREATE INDEX changes_batch ON changes(batch);
",
    // Hourly rollups of the history: what the Explorer groups, whatever the number of events. One row per hour,
    // program, host (0: none), port, protocol, user and action; filled from the history there is, then kept as events
    // are recorded and their bytes counted.
    r"
CREATE TABLE rollups (
    hour INTEGER NOT NULL,
    exe INTEGER NOT NULL,
    host INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    action INTEGER NOT NULL,
    count INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    PRIMARY KEY (hour, exe, host, port, protocol, uid, action)
) WITHOUT ROWID;
INSERT INTO rollups
SELECT time_ms / 3600000, exe, coalesce(host, 0), port, protocol, uid, action, count(*), sum(bytes_out), sum(bytes_in)
FROM events GROUP BY 1, 2, 3, 4, 5, 6, 7;
",
    // The same, per dimension alone (1 program, 2 host, 3 port, 4 user): what grouping by one dimension reads, at
    // most one row per hour and value, however varied the rest of the traffic.
    r"
CREATE TABLE rollups_by (
    dimension INTEGER NOT NULL,
    hour INTEGER NOT NULL,
    key INTEGER NOT NULL,
    action INTEGER NOT NULL,
    count INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    PRIMARY KEY (dimension, hour, key, action)
) WITHOUT ROWID;
INSERT INTO rollups_by SELECT 1, hour, exe, action, sum(count), sum(bytes_out), sum(bytes_in) FROM rollups GROUP BY 2, 3, 4;
INSERT INTO rollups_by SELECT 2, hour, host, action, sum(count), sum(bytes_out), sum(bytes_in) FROM rollups GROUP BY 2, 3, 4;
INSERT INTO rollups_by SELECT 3, hour, port, action, sum(count), sum(bytes_out), sum(bytes_in) FROM rollups GROUP BY 2, 3, 4;
INSERT INTO rollups_by SELECT 4, hour, uid, action, sum(count), sum(bytes_out), sum(bytes_in) FROM rollups GROUP BY 2, 3, 4;
",
];

/// The Explorer's statement: `group` the rollups of an hour range, optionally of one value of `filter`.
macro_rules! explore {
    ($group:literal, $filter:literal) => {
        (
            concat!("explore.", $group, ".", $filter),
            concat!(
                "SELECT ", $group, ", sum(CASE WHEN action = 1 THEN count ELSE 0 END),
                        sum(CASE WHEN action = 1 THEN 0 ELSE count END), sum(bytes_out), sum(bytes_in)
                 FROM rollups WHERE hour >= ?1 AND hour < ?2 AND ", $filter, " = ?4
                 GROUP BY ", $group, " ORDER BY sum(count) DESC LIMIT ?3"
            ),
        )
    };
}

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
        "rules.get",
        "SELECT id, folder, name, enabled, action, tier, expiry, log, notes, conditions FROM rules WHERE id = ?1",
    ),
    (
        "rules.in_folder",
        "SELECT id, folder, name, enabled, action, tier, expiry, log, notes, conditions FROM rules WHERE folder = ?1",
    ),
    (
        "rules.insert_id",
        "INSERT INTO rules (id, folder, name, enabled, action, tier, expiry, log, notes, conditions, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    ),
    (
        "rules.update",
        "UPDATE rules SET folder = ?2, name = ?3, enabled = ?4, action = ?5, tier = ?6, expiry = ?7, log = ?8,
                          notes = ?9, conditions = ?10, updated_ms = ?11
         WHERE id = ?1",
    ),
    ("folders.get", "SELECT id, parent, name, enabled, scope FROM folders WHERE id = ?1"),
    ("folders.children", "SELECT id FROM folders WHERE parent = ?1"),
    (
        "folders.insert_id",
        "INSERT INTO folders (id, parent, name, enabled, scope) VALUES (?1, ?2, ?3, ?4, ?5)",
    ),
    (
        "folders.update",
        "UPDATE folders SET parent = ?2, name = ?3, enabled = ?4, scope = ?5 WHERE id = ?1",
    ),
    ("folders.delete", "DELETE FROM folders WHERE id = ?1"),
    (
        "changes.insert",
        "INSERT INTO changes (batch, time_ms, app, kind, target, before, after, what)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    ),
    (
        "changes.last_batch",
        "SELECT batch FROM changes WHERE id = (SELECT max(id) FROM changes)",
    ),
    (
        "changes.page",
        "SELECT id, batch, time_ms, app, kind, target, before, after, what FROM changes
         WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
    ),
    ("changes.batch_of", "SELECT batch FROM changes WHERE id = ?1"),
    (
        "changes.in_batch",
        "SELECT id, batch, time_ms, app, kind, target, before, after, what FROM changes
         WHERE batch = ?1 ORDER BY id",
    ),
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
    ("strings.by_id", "SELECT value FROM strings WHERE id = ?1"),
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
    (
        "events.one",
        "SELECT e.seq, e.time_ms, x.value, h.value, e.uid, e.pid, e.protocol, e.address, e.port, e.context,
                e.action, e.source, e.rule, e.bytes_out, e.bytes_in
         FROM events e CROSS JOIN strings x ON x.id = e.exe LEFT JOIN strings h ON h.id = e.host
         WHERE e.seq = ?1",
    ),
    // A subscriber catching up after a reconnect: the events after the last one it saw, oldest first.
    (
        "events.after",
        "SELECT e.seq, e.time_ms, x.value, h.value, e.uid, e.pid, e.protocol, e.address, e.port, e.context,
                e.action, e.source, e.rule, e.bytes_out, e.bytes_in
         FROM events e CROSS JOIN strings x ON x.id = e.exe LEFT JOIN strings h ON h.id = e.host
         WHERE e.seq > ?1 ORDER BY e.seq LIMIT ?2",
    ),
    // The same pages as rows for columnar blocks: strings stay ids.
    // Each from the primary key: one row each.
    (
        "events.span",
        "SELECT (SELECT min(seq) FROM events), (SELECT max(seq) FROM events)",
    ),
    (
        "events.page_rows",
        "SELECT seq, time_ms, exe, host, uid, pid, protocol, address, port, context, action, source, rule, bytes_out,
                bytes_in
         FROM events WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2",
    ),
    (
        "events.after_rows",
        "SELECT seq, time_ms, exe, host, uid, pid, protocol, address, port, context, action, source, rule, bytes_out,
                bytes_in
         FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2",
    ),
    // Connections no rule decided, since a time: what `learn` turns into rules.
    (
        "events.undecided_since",
        "SELECT x.value, h.value, e.uid, e.protocol, e.address, e.port
         FROM events e INDEXED BY events_time
              CROSS JOIN strings x ON x.id = e.exe LEFT JOIN strings h ON h.id = e.host
         WHERE e.time_ms >= ?1 AND e.source != 1",
    ),
    (
        "audit.insert",
        "INSERT INTO audit (time_ms, app, uid, pid, action, outcome) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    ),
    (
        "audit.page",
        "SELECT id, time_ms, app, uid, pid, action, outcome FROM audit WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
    ),
    (
        "rollups.add",
        "INSERT INTO rollups (hour, exe, host, port, protocol, uid, action, count, bytes_out, bytes_in)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT (hour, exe, host, port, protocol, uid, action) DO UPDATE SET
             count = count + excluded.count,
             bytes_out = bytes_out + excluded.bytes_out,
             bytes_in = bytes_in + excluded.bytes_in",
    ),
    ("rollups.prune", "DELETE FROM rollups WHERE hour < ?1"),
    (
        "rollups_by.add",
        "INSERT INTO rollups_by (dimension, hour, key, action, count, bytes_out, bytes_in)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (dimension, hour, key, action) DO UPDATE SET
             count = count + excluded.count,
             bytes_out = bytes_out + excluded.bytes_out,
             bytes_in = bytes_in + excluded.bytes_in",
    ),
    (
        "rollups_by.prune",
        "DELETE FROM rollups_by WHERE dimension = ?1 AND hour < ?2",
    ),
    (
        "explore.by",
        "SELECT key, sum(CASE WHEN action = 1 THEN count ELSE 0 END),
                sum(CASE WHEN action = 1 THEN 0 ELSE count END), sum(bytes_out), sum(bytes_in)
         FROM rollups_by WHERE dimension = ?4 AND hour >= ?1 AND hour < ?2
         GROUP BY key ORDER BY sum(count) DESC LIMIT ?3",
    ),
    // A socket's bytes go to its newest event: an unconnected UDP socket may have several, one per destination.
    (
        "events.by_cookie",
        "SELECT seq, time_ms, exe, coalesce(host, 0), port, protocol, uid, action, bytes_out, bytes_in
         FROM events WHERE cookie = ?1 ORDER BY seq DESC LIMIT 1",
    ),
    (
        "events.bytes_of",
        "UPDATE events SET bytes_out = ?2, bytes_in = ?3 WHERE seq = ?1",
    ),
    explore!("exe", "host"),
    explore!("exe", "port"),
    explore!("exe", "uid"),
    explore!("host", "exe"),
    explore!("host", "port"),
    explore!("host", "uid"),
    explore!("port", "exe"),
    explore!("port", "host"),
    explore!("port", "uid"),
    explore!("uid", "exe"),
    explore!("uid", "host"),
    explore!("uid", "port"),
    (
        "events.prune",
        "DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE time_ms < ?1 ORDER BY time_ms LIMIT ?2)",
    ),
];

/// One request's changes: who made them, when, and the batch they are grouped in (undone together).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub id: u64,
    pub app: String,
    pub now_ms: u64,
}

/// A change to a rule or a folder, as the history keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub id: u64,
    pub batch: u64,
    pub time_ms: u64,
    pub app: String,
    /// `rule` or `folder`.
    pub kind: String,
    pub target: u64,
    /// The object before and after, as JSON; `None` where it didn't exist.
    pub before: Option<String>,
    pub after: Option<String>,
    /// What changed, for people.
    pub what: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UndoError {
    #[error("no change {0}")]
    NotFound(u64),
    #[error("{0} was changed since: undo the later change first")]
    Changed(String),
    #[error(transparent)]
    Store(#[from] Error),
}

const RULE: &str = "rule";
const FOLDER: &str = "folder";

/// What changed between two versions of a rule, for people.
fn describe_rule(before: Option<&Rule>, after: Option<&Rule>) -> String {
    match (before, after) {
        (None, Some(after)) => format!("added rule \"{}\"", after.name),
        (Some(before), None) => format!("deleted rule \"{}\"", before.name),
        (Some(before), Some(after)) => {
            let mut parts = Vec::new();
            if before.name != after.name {
                parts.push(format!("renamed to \"{}\"", after.name));
            }
            if before.enabled != after.enabled {
                parts.push(
                    if after.enabled {
                        "switched on"
                    } else {
                        "switched off"
                    }
                    .to_owned(),
                );
            }
            if before.action != after.action {
                parts.push(
                    format!("action {:?} → {:?}", before.action, after.action).to_lowercase(),
                );
            }
            if before.tier != after.tier {
                parts.push(format!("tier {:?} → {:?}", before.tier, after.tier).to_lowercase());
            }
            if before.folder != after.folder {
                parts.push("moved".to_owned());
            }
            if before.conditions != after.conditions {
                parts.push("conditions changed".to_owned());
            }
            if before.expiry != after.expiry {
                parts.push("expiry changed".to_owned());
            }
            if before.notes != after.notes {
                parts.push("notes changed".to_owned());
            }
            format!("rule \"{}\": {}", before.name, parts.join(", "))
        }
        (None, None) => String::new(),
    }
}

fn describe_folder(before: Option<&Folder>, after: Option<&Folder>) -> String {
    match (before, after) {
        (None, Some(after)) => format!("added folder \"{}\"", after.name),
        (Some(before), None) => format!("deleted folder \"{}\"", before.name),
        (Some(before), Some(after)) => {
            let mut parts = Vec::new();
            if before.name != after.name {
                parts.push(format!("renamed to \"{}\"", after.name));
            }
            if before.enabled != after.enabled {
                parts.push(
                    if after.enabled {
                        "switched on"
                    } else {
                        "switched off"
                    }
                    .to_owned(),
                );
            }
            if before.parent != after.parent {
                parts.push("moved".to_owned());
            }
            if before.scope != after.scope {
                parts.push("scope changed".to_owned());
            }
            format!("folder \"{}\": {}", before.name, parts.join(", "))
        }
        (None, None) => String::new(),
    }
}

/// A rule as `rules.get`, `rules.all` and `rules.in_folder` select it.
fn rule_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Rule, Error>> {
    let (id, folder, name, enabled): (i64, Option<i64>, String, bool) =
        (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
    let (action, tier, expiry, log, notes, conditions): (
        String,
        String,
        String,
        bool,
        String,
        String,
    ) = (
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    );
    let corrupt = |what| {
        move |e: serde_json::Error| Error::Corrupt {
            what,
            error: e.to_string(),
        }
    };
    Ok((|| {
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
            conditions: serde_json::from_str(&conditions).map_err(corrupt("rule conditions"))?,
        })
    })())
}

fn folder_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Folder, Error>> {
    let (id, parent, name, enabled, scope): (i64, Option<i64>, String, bool, String) = (
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    );
    Ok(serde_json::from_str(&scope)
        .map_err(|e| Error::Corrupt {
            what: "folder scope",
            error: e.to_string(),
        })
        .map(|scope| Folder {
            id: id_of(id),
            parent: parent.map(id_of),
            name,
            enabled,
            scope,
        }))
}

fn change_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<Change> {
    Ok(Change {
        id: id_of(row.get(0)?),
        batch: id_of(row.get(1)?),
        time_ms: id_of(row.get(2)?),
        app: row.get(3)?,
        kind: row.get(4)?,
        target: id_of(row.get(5)?),
        before: row.get(6)?,
        after: row.get(7)?,
        what: row.get(8)?,
    })
}

impl Store {
    /// A new batch of changes, made by `app`.
    pub fn batch(&self, app: &str, now_ms: u64) -> Result<Batch, Error> {
        let last: Option<i64> = self
            .connection
            .prepare_cached(sql("changes.last_batch")?)?
            .query_row([], |row| row.get(0))
            .optional()?;
        Ok(Batch {
            id: last.map_or(1, |last| id_of(last) + 1),
            app: app.to_owned(),
            now_ms,
        })
    }

    pub fn rule(&self, id: RuleId) -> Result<Option<Rule>, Error> {
        self.connection
            .prepare_cached(sql("rules.get")?)?
            .query_row(params![db_id(id)], rule_of)
            .optional()?
            .transpose()
    }

    pub fn folder(&self, id: FolderId) -> Result<Option<Folder>, Error> {
        self.connection
            .prepare_cached(sql("folders.get")?)?
            .query_row(params![db_id(id)], folder_of)
            .optional()?
            .transpose()
    }

    fn record_change(
        &self,
        batch: &Batch,
        kind: &str,
        target: u64,
        before: Option<&str>,
        after: Option<&str>,
        what: &str,
    ) -> Result<(), Error> {
        self.connection
            .prepare_cached(sql("changes.insert")?)?
            .execute(params![
                db_id(batch.id),
                db_id(batch.now_ms),
                batch.app,
                kind,
                db_id(target),
                before,
                after,
                what,
            ])?;
        Ok(())
    }

    fn write_rule(&self, rule: &Rule, now_ms: u64, statement: &'static str) -> Result<(), Error> {
        self.connection
            .prepare_cached(sql(statement)?)?
            .execute(params![
                db_id(rule.id),
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
        Ok(())
    }

    /// Adds a rule (`id` 0) or replaces the rule with its id, recording the change; returns its id. A missing rule
    /// is `NotFound`.
    pub fn put_rule(&self, rule: &Rule, batch: &Batch) -> Result<RuleId, Error> {
        if rule.id == 0 {
            let id = self.insert_rule(rule, batch.now_ms)?;
            let stored = Rule { id, ..rule.clone() };
            self.record_change(
                batch,
                RULE,
                id,
                None,
                Some(&json(&stored)),
                &describe_rule(None, Some(&stored)),
            )?;
            return Ok(id);
        }
        let before = self.rule(rule.id)?.ok_or(Error::NotFound(RULE, rule.id))?;
        self.write_rule(rule, batch.now_ms, "rules.update")?;
        self.record_change(
            batch,
            RULE,
            rule.id,
            Some(&json(&before)),
            Some(&json(rule)),
            &describe_rule(Some(&before), Some(rule)),
        )?;
        Ok(rule.id)
    }

    /// Deletes a rule, recording it; whether it existed.
    pub fn remove_rule(&self, id: RuleId, batch: &Batch) -> Result<bool, Error> {
        let Some(before) = self.rule(id)? else {
            return Ok(false);
        };
        self.delete_rule(id)?;
        self.record_change(
            batch,
            RULE,
            id,
            Some(&json(&before)),
            None,
            &describe_rule(Some(&before), None),
        )?;
        Ok(true)
    }

    /// Adds a folder (`id` 0) or replaces the folder with its id, recording the change; returns its id.
    pub fn put_folder(&self, folder: &Folder, batch: &Batch) -> Result<FolderId, Error> {
        if folder.id == 0 {
            let id = self.insert_folder(folder)?;
            let stored = Folder {
                id,
                ..folder.clone()
            };
            self.record_change(
                batch,
                FOLDER,
                id,
                None,
                Some(&json(&stored)),
                &describe_folder(None, Some(&stored)),
            )?;
            return Ok(id);
        }
        let before = self
            .folder(folder.id)?
            .ok_or(Error::NotFound(FOLDER, folder.id))?;
        self.connection
            .prepare_cached(sql("folders.update")?)?
            .execute(params![
                db_id(folder.id),
                folder.parent.map(db_id),
                folder.name,
                folder.enabled,
                json(&folder.scope),
            ])?;
        self.record_change(
            batch,
            FOLDER,
            folder.id,
            Some(&json(&before)),
            Some(&json(folder)),
            &describe_folder(Some(&before), Some(folder)),
        )?;
        Ok(folder.id)
    }

    /// The rules of a folder (not of the folders below it).
    pub fn rules_in(&self, folder: FolderId) -> Result<Vec<Rule>, Error> {
        let mut statement = self.connection.prepare_cached(sql("rules.in_folder")?)?;
        let rows = statement.query_map(params![db_id(folder)], rule_of)?;
        rows.map(|row| row?).collect()
    }

    fn children(&self, folder: FolderId) -> Result<Vec<FolderId>, Error> {
        let mut statement = self.connection.prepare_cached(sql("folders.children")?)?;
        let rows = statement.query_map(params![db_id(folder)], |row| row.get::<_, i64>(0))?;
        Ok(rows.map(|id| id.map(id_of)).collect::<Result<_, _>>()?)
    }

    /// Deletes a folder, the folders below it and their rules, recording each (rules first, so undoing the batch puts
    /// the folders back before their rules); the number of rules deleted, or `None` if there was no such folder.
    pub fn remove_folder(&self, id: FolderId, batch: &Batch) -> Result<Option<usize>, Error> {
        let Some(folder) = self.folder(id)? else {
            return Ok(None);
        };
        let mut rules = 0;
        for child in self.children(id)? {
            rules += self.remove_folder(child, batch)?.unwrap_or(0);
        }
        for rule in self.rules_in(id)? {
            self.remove_rule(rule.id, batch)?;
            rules += 1;
        }
        self.connection
            .prepare_cached(sql("folders.delete")?)?
            .execute(params![db_id(id)])?;
        self.record_change(
            batch,
            FOLDER,
            id,
            Some(&json(&folder)),
            None,
            &describe_folder(Some(&folder), None),
        )?;
        Ok(Some(rules))
    }

    /// Runs `change` in one transaction: all of it is stored, or nothing.
    pub fn atomically<T, E: From<Error>>(
        &mut self,
        change: impl FnOnce(&Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(Error::from)?;
        let result = change(self)?;
        transaction.commit().map_err(Error::from)?;
        Ok(result)
    }

    /// The newest changes before the id `before` (`u64::MAX` for the newest), at most `limit`.
    pub fn changes(&self, before: u64, limit: u32) -> Result<Vec<Change>, Error> {
        let mut statement = self.connection.prepare_cached(sql("changes.page")?)?;
        let rows = statement.query_map(
            params![i64::try_from(before).unwrap_or(i64::MAX), limit],
            change_of,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Undoes the batch of change `change`, newest first, as a new batch: every object it touched must still be as
    /// the batch left it. Returns how many changes were undone.
    pub fn undo(&mut self, change: u64, batch: &Batch) -> Result<usize, UndoError> {
        let of: Option<i64> = self
            .connection
            .prepare_cached(sql("changes.batch_of").map_err(UndoError::Store)?)
            .map_err(Error::from)?
            .query_row(params![db_id(change)], |row| row.get(0))
            .optional()
            .map_err(Error::from)?;
        let undone_batch = of.ok_or(UndoError::NotFound(change))?;
        let mut statement = self
            .connection
            .prepare_cached(sql("changes.in_batch")?)
            .map_err(Error::from)?;
        let changes: Vec<Change> = statement
            .query_map(params![undone_batch], change_of)
            .map_err(Error::from)?
            .collect::<Result<_, _>>()
            .map_err(Error::from)?;
        drop(statement);
        // Everything is checked before anything is put back.
        for change in &changes {
            let now = match change.kind.as_str() {
                RULE => self.rule(change.target)?.map(|r| json(&r)),
                _ => self.folder(change.target)?.map(|f| json(&f)),
            };
            if now != change.after {
                return Err(UndoError::Changed(format!(
                    "{} {}",
                    change.kind, change.target
                )));
            }
        }
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(Error::from)?;
        for change in changes.iter().rev() {
            self.restore(change, batch)?;
        }
        transaction.commit().map_err(Error::from)?;
        Ok(changes.len())
    }

    /// Puts back what `change` found, recording that as a change of `batch`.
    fn restore(&self, change: &Change, batch: &Batch) -> Result<(), Error> {
        let corrupt = |e: serde_json::Error| Error::Corrupt {
            what: "a recorded change",
            error: e.to_string(),
        };
        if change.kind == RULE {
            let before: Option<Rule> = change
                .before
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(corrupt)?;
            let after: Option<Rule> = change
                .after
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(corrupt)?;
            match &before {
                None => {
                    self.delete_rule(change.target)?;
                }
                Some(rule) if after.is_none() => {
                    self.write_rule(rule, batch.now_ms, "rules.insert_id")?;
                }
                Some(rule) => self.write_rule(rule, batch.now_ms, "rules.update")?,
            }
            let what = format!("undid: {}", describe_rule(after.as_ref(), before.as_ref()));
            self.record_change(
                batch,
                RULE,
                change.target,
                change.after.as_deref(),
                change.before.as_deref(),
                &what,
            )
        } else {
            let before: Option<Folder> = change
                .before
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(corrupt)?;
            let after: Option<Folder> = change
                .after
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(corrupt)?;
            let statement = match (&before, &after) {
                (None, _) => {
                    self.connection
                        .prepare_cached(sql("folders.delete")?)?
                        .execute(params![db_id(change.target)])?;
                    None
                }
                (Some(_), None) => Some("folders.insert_id"),
                (Some(_), Some(_)) => Some("folders.update"),
            };
            if let (Some(statement), Some(folder)) = (statement, &before) {
                self.connection
                    .prepare_cached(sql(statement)?)?
                    .execute(params![
                        db_id(folder.id),
                        folder.parent.map(db_id),
                        folder.name,
                        folder.enabled,
                        json(&folder.scope),
                    ])?;
            }
            let what = format!(
                "undid: {}",
                describe_folder(after.as_ref(), before.as_ref())
            );
            self.record_change(
                batch,
                FOLDER,
                change.target,
                change.after.as_deref(),
                change.before.as_deref(),
                &what,
            )
        }
    }
}

/// Tables small enough that scanning them is fine (and SQLite may choose to).
#[cfg(test)]
const SCANNABLE: &[&str] = &["folders", "rules"];

/// Statements that group what an index range yields, and so sort it: the Explorer's, over the rollups of a range of
/// hours. Their cost is the rollup rows of those hours (the variety of the traffic), not the size of the history; the
/// gate checks that they start with that range search.
#[cfg(test)]
const GROUPS_IN_RANGE: &[&str] = &["explore."];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("stored {what} isn't valid: {error}")]
    Corrupt { what: &'static str, error: String },
    #[error("no statement named {0}")]
    UnknownStatement(&'static str),
    #[error("no {0} {1}")]
    NotFound(&'static str, u64),
}

impl Event {
    /// The event as recorded under `seq` (before any bytes are counted for it).
    #[must_use]
    pub fn stored(&self, seq: i64) -> StoredEvent {
        StoredEvent {
            seq,
            time_ms: self.time_ms,
            exe: self.exe.to_string(),
            host: self.host.as_deref().map(str::to_owned),
            uid: self.uid,
            pid: self.pid,
            protocol: self.protocol,
            address: self.address,
            port: self.port,
            context: self.context,
            action: self.action,
            source: self.source as u8,
            rule: self.rule,
            bytes_out: 0,
            bytes_in: 0,
        }
    }
}

/// What recording an event gave it: its seq, and the ids of its strings (0 for no host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
    pub seq: i64,
    pub exe: u32,
    pub host: u32,
}

/// An hour, in ms: rollups are kept per hour.
pub const HOUR_MS: u64 = 3_600_000;

/// What the Explorer groups by and narrows with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dimension {
    Exe,
    Host,
    Port,
    Uid,
}

impl Dimension {
    /// Its number in `rollups_by`.
    const fn number(self) -> i64 {
        match self {
            Self::Exe => 1,
            Self::Host => 2,
            Self::Port => 3,
            Self::Uid => 4,
        }
    }

    const fn column(self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::Host => "host",
            Self::Port => "port",
            Self::Uid => "uid",
        }
    }
}

/// One group of the Explorer: its key (a string id for programs and hosts, 0 for no host; the number otherwise) and
/// its connections and bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Explored {
    pub key: i64,
    pub allowed: u64,
    pub blocked: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
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

/// A dangerous action attempted, and its outcome (the protocol's `AuditOutcome` number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: u64,
    pub time_ms: u64,
    pub app: String,
    pub uid: u32,
    pub pid: u32,
    pub action: String,
    pub outcome: u8,
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
        register_query_functions(&connection)?;
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
    pub fn insert_rule(&self, rule: &Rule, now_ms: u64) -> Result<RuleId, Error> {
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

    pub fn delete_rule(&self, id: RuleId) -> Result<bool, Error> {
        let mut statement = self.connection.prepare_cached(sql("rules.delete")?)?;
        Ok(statement.execute(params![db_id(id)])? > 0)
    }

    /// Adds a folder (its `id` is ignored) and returns the id it got.
    pub fn insert_folder(&self, folder: &Folder) -> Result<FolderId, Error> {
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
    /// Records `events`; what `recorded` held is replaced by each one's seq and string ids, in the same order.
    pub fn record(&mut self, events: &[Event], recorded: &mut Vec<Recorded>) -> Result<(), Error> {
        recorded.clear();
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
            let seq = self.connection.last_insert_rowid();
            self.connection
                .prepare_cached(sql("rollups.add")?)?
                .execute(params![
                    db_id(event.time_ms / HOUR_MS),
                    exe,
                    host.unwrap_or(0),
                    event.port,
                    event.protocol,
                    event.uid,
                    action_code(event.action),
                    1,
                    0,
                    0,
                ])?;
            add_by(
                &self.connection,
                event.time_ms / HOUR_MS,
                [
                    exe,
                    host.unwrap_or(0),
                    i64::from(event.port),
                    i64::from(event.uid),
                ],
                action_code(event.action),
                (1, 0, 0),
            )?;
            recorded.push(Recorded {
                seq,
                exe: u32::try_from(exe).unwrap_or(0),
                host: host.map_or(0, |id| u32::try_from(id).unwrap_or(0)),
            });
        }
        transaction.commit()?;
        Ok(())
    }

    /// The newest events before `before` (a sequence number; `i64::MAX` for the newest), at most `limit`.
    pub fn events(&self, before: i64, limit: u32) -> Result<Vec<StoredEvent>, Error> {
        let mut statement = self.connection.prepare_cached(sql("events.page")?)?;
        let rows = statement.query_map(params![before, limit], stored_event)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The event recorded as `seq`.
    pub fn event(&self, seq: i64) -> Result<Option<StoredEvent>, Error> {
        Ok(self
            .connection
            .prepare_cached(sql("events.one")?)?
            .query_row(params![seq], stored_event)
            .optional()?)
    }

    /// The oldest events after `after` (a sequence number), at most `limit`.
    pub fn events_after(&self, after: i64, limit: u32) -> Result<Vec<StoredEvent>, Error> {
        let mut statement = self.connection.prepare_cached(sql("events.after")?)?;
        let rows = statement.query_map(params![after, limit], stored_event)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Records a dangerous action attempted (`entry.id` is ignored); returns its id.
    pub fn audit(&mut self, entry: &AuditEntry) -> Result<u64, Error> {
        let mut statement = self.connection.prepare_cached(sql("audit.insert")?)?;
        statement.execute(params![
            i64::try_from(entry.time_ms).unwrap_or(i64::MAX),
            entry.app,
            entry.uid,
            entry.pid,
            entry.action,
            entry.outcome,
        ])?;
        Ok(id_of(self.connection.last_insert_rowid()))
    }

    /// The newest audit entries before the id `before` (`u64::MAX` for the newest), at most `limit`.
    pub fn audit_page(&self, before: u64, limit: u32) -> Result<Vec<AuditEntry>, Error> {
        let mut statement = self.connection.prepare_cached(sql("audit.page")?)?;
        let rows = statement.query_map(
            params![i64::try_from(before).unwrap_or(i64::MAX), limit],
            |row| {
                Ok(AuditEntry {
                    id: id_of(row.get(0)?),
                    time_ms: id_of(row.get(1)?),
                    app: row.get(2)?,
                    uid: row.get(3)?,
                    pid: row.get(4)?,
                    action: row.get(5)?,
                    outcome: row.get(6)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The newest events before `before` as rows for a columnar block, oldest first.
    pub fn event_rows(&self, before: i64, limit: u32) -> Result<Vec<EventRow>, Error> {
        let mut statement = self.connection.prepare_cached(sql("events.page_rows")?)?;
        let rows = statement.query_map(params![before, limit], event_row)?;
        let mut rows: Vec<EventRow> = rows.collect::<Result<_, _>>()?;
        rows.reverse();
        Ok(rows)
    }

    /// The newest events before `before` that `filter` matches, at most `limit`, oldest first as `event_rows` gives
    /// them, and the oldest sequence number covered (the next page asks for events before it; 0: nothing older). At
    /// most [`SCAN_WINDOW`] sequence numbers are examined, so a sparse query over a long history answers in pages.
    pub fn event_rows_matching(
        &self,
        before: i64,
        limit: u32,
        filter: &EventFilter,
    ) -> Result<(Vec<EventRow>, i64), Error> {
        let span: (Option<i64>, Option<i64>) = self
            .connection
            .prepare_cached(sql("events.span")?)?
            .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let (Some(oldest), Some(newest)) = span else {
            return Ok((Vec::new(), 0));
        };
        let before = before.min(newest.saturating_add(1));
        let floor = before.saturating_sub(SCAN_WINDOW).max(oldest);
        let (condition, values) = filter.sql();
        let statement_sql = format!(
            "SELECT e.seq, e.time_ms, e.exe, e.host, e.uid, e.pid, e.protocol, e.address, e.port, e.context, e.action,
                    e.source, e.rule, e.bytes_out, e.bytes_in
             FROM events e CROSS JOIN strings x ON x.id = e.exe LEFT JOIN strings h ON h.id = e.host
             WHERE e.seq < ? AND e.seq >= ? AND {condition} ORDER BY e.seq DESC LIMIT ?"
        );
        let mut params: Vec<rusqlite::types::Value> = vec![before.into(), floor.into()];
        params.extend(values.into_iter().map(|v| match v {
            SqlValue::Int(i) => rusqlite::types::Value::Integer(i),
            SqlValue::Text(t) => rusqlite::types::Value::Text(t),
        }));
        params.push(i64::from(limit).into());
        let mut statement = self.connection.prepare_cached(&statement_sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(params), event_row)?;
        let mut rows: Vec<EventRow> = rows.collect::<Result<_, _>>()?;
        let full = rows.len() >= usize::try_from(limit).unwrap_or(usize::MAX);
        let scanned_from = match rows.last() {
            Some(last) if full => last.seq,
            _ if floor <= oldest => 0,
            _ => floor,
        };
        rows.reverse();
        Ok((rows, scanned_from))
    }

    /// The oldest events after `after` as rows for a columnar block.
    pub fn event_rows_after(&self, after: i64, limit: u32) -> Result<Vec<EventRow>, Error> {
        let mut statement = self.connection.prepare_cached(sql("events.after_rows")?)?;
        let rows = statement.query_map(params![after, limit], event_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The strings of `ids` (an exe's or a host's), for a block's dictionary; unknown ids are left out.
    pub fn strings_of(
        &self,
        ids: impl IntoIterator<Item = u32>,
    ) -> Result<Vec<(u32, std::sync::Arc<str>)>, Error> {
        let mut statement = self.connection.prepare_cached(sql("strings.by_id")?)?;
        let mut out = Vec::new();
        for id in ids {
            if id == 0 {
                continue;
            }
            let value: Option<String> = statement
                .query_row(params![id], |row| row.get(0))
                .optional()?;
            if let Some(value) = value {
                out.push((id, std::sync::Arc::from(value)));
            }
        }
        Ok(out)
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
            let mut find = self.connection.prepare_cached(sql("events.by_cookie")?)?;
            let mut update = self.connection.prepare_cached(sql("events.bytes_of")?)?;
            let mut rollup = self.connection.prepare_cached(sql("rollups.add")?)?;
            for &(cookie, sent, read) in counts {
                // The socket's newest event, and its bytes so far: the rollup gets the difference.
                let event = find
                    .query_row(params![db_id(cookie)], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            [
                                row.get::<_, i64>(1)? / i64::try_from(HOUR_MS).unwrap_or(i64::MAX),
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                                row.get(6)?,
                                row.get(7)?,
                            ],
                            row.get::<_, i64>(8)?,
                            row.get::<_, i64>(9)?,
                        ))
                    })
                    .optional()?;
                let Some((seq, key, old_out, old_in)) = event else {
                    continue;
                };
                let (sent, read) = (db_id(sent), db_id(read));
                update.execute(params![seq, sent, read])?;
                let [hour, exe, host, port, protocol, uid, action] = key;
                let (out, inn) = ((sent - old_out).max(0), (read - old_in).max(0));
                add_by(
                    &self.connection,
                    u64::try_from(hour).unwrap_or(0),
                    [exe, host, port, uid],
                    u8::try_from(action).unwrap_or(0),
                    (0, out, inn),
                )?;
                rollup.execute(params![
                    hour,
                    exe,
                    host,
                    port,
                    protocol,
                    uid,
                    action,
                    0,
                    (sent - old_out).max(0),
                    (read - old_in).max(0),
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Groups the rollups of hours [`from_hour`, `to_hour`) by `group`, optionally of one value of another dimension,
    /// busiest first, at most `limit` groups.
    pub fn explore(
        &self,
        from_hour: u64,
        to_hour: u64,
        group: Dimension,
        filter: Option<(Dimension, i64)>,
        limit: u32,
    ) -> Result<Vec<Explored>, Error> {
        let name = match (group, filter.map(|(d, _)| d)) {
            (_, None) => "explore.by".to_owned(),
            (g, Some(f)) if g != f => format!("explore.{}.{}", g.column(), f.column()),
            _ => return Ok(Vec::new()),
        };
        let statement_sql = STATEMENTS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, sql)| *sql)
            .ok_or(Error::NotFound("explore statement", 0))?;
        let mut statement = self.connection.prepare_cached(statement_sql)?;
        let row = |row: &rusqlite::Row<'_>| {
            Ok(Explored {
                key: row.get(0)?,
                allowed: id_of(row.get(1)?),
                blocked: id_of(row.get(2)?),
                bytes_out: id_of(row.get(3)?),
                bytes_in: id_of(row.get(4)?),
            })
        };
        let (from, to) = (db_id(from_hour), db_id(to_hour));
        let rows = match filter {
            None => statement.query_map(params![from, to, limit, group.number()], row)?,
            Some((_, value)) => statement.query_map(params![from, to, limit, value], row)?,
        };
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The id of a string, if the history has it.
    pub fn string_id(&self, kind: StringKind, value: &str) -> Result<Option<i64>, Error> {
        Ok(self
            .connection
            .prepare_cached(sql("strings.find")?)?
            .query_row(params![kind as u8, value], |row| row.get(0))
            .optional()?)
    }

    /// Deletes the rollups of the hours before `before_ms`.
    pub fn prune_rollups(&mut self, before_ms: u64) -> Result<usize, Error> {
        let hour = db_id(before_ms / HOUR_MS);
        let mut by = self.connection.prepare_cached(sql("rollups_by.prune")?)?;
        for dimension in 1..=4 {
            by.execute(params![dimension, hour])?;
        }
        let mut statement = self.connection.prepare_cached(sql("rollups.prune")?)?;
        Ok(statement.execute(params![hour])?)
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

/// Adds to the per-dimension rollups of an hour: `keys` are the program, host, port and user; `counts` the
/// connections and bytes out and in.
fn add_by(
    connection: &Connection,
    hour: u64,
    keys: [i64; 4],
    action: u8,
    counts: (i64, i64, i64),
) -> Result<(), Error> {
    let mut statement = connection.prepare_cached(sql("rollups_by.add")?)?;
    for (dimension, key) in (1..).zip(keys) {
        statement.execute(params![
            dimension,
            db_id(hour),
            key,
            action,
            counts.0,
            counts.1,
            counts.2
        ])?;
    }
    Ok(())
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

/// An event as `events.page_rows` and `events.after_rows` select it.
fn event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    let address: Vec<u8> = row.get(7)?;
    let id = |index| {
        row.get::<_, Option<i64>>(index)
            .map(|id| id.map_or(0, |id| u32::try_from(id).unwrap_or(0)))
    };
    Ok(EventRow {
        seq: row.get(0)?,
        time_ms: id_of(row.get(1)?),
        exe: id(2)?,
        host: id(3)?,
        uid: row.get(4)?,
        pid: row.get(5)?,
        address: address.try_into().unwrap_or([0; 16]),
        port: row.get(8)?,
        protocol: row.get(6)?,
        // Blocks carry the protocol's numbers; the history keeps the host as 0.
        context: row.get::<_, u8>(9)?.saturating_add(1),
        action: row.get(10)?,
        source: row.get(11)?,
        rule: row.get::<_, Option<i64>>(12)?.map_or(0, id_of),
        bytes_out: id_of(row.get(13)?),
        bytes_in: id_of(row.get(14)?),
    })
}

/// An event as `events.page` and `events.after` select it.
fn stored_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEvent> {
    let address: Vec<u8> = row.get(7)?;
    Ok(StoredEvent {
        seq: row.get(0)?,
        time_ms: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
        exe: row.get(2)?,
        host: row.get(3)?,
        uid: row.get(4)?,
        pid: row.get(5)?,
        protocol: row.get(6)?,
        address: address_from(&address),
        port: row.get(8)?,
        context: row.get(9)?,
        action: action_from(row.get(10)?),
        source: row.get(11)?,
        rule: row.get::<_, Option<i64>>(12)?.map(id_of),
        bytes_out: id_of(row.get(13)?),
        bytes_in: id_of(row.get(14)?),
    })
}

/// Sequence numbers a filtered page of history examines at most.
pub const SCAN_WINDOW: i64 = 100_000;

/// The query language's matching functions, for the SQL it compiles to: the same code the clients run.
fn register_query_functions(connection: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    connection.create_scalar_function("snitchhiker_glob", 2, flags, |cx| {
        let pattern: String = cx.get(0)?;
        let value: Option<String> = cx.get(1)?;
        Ok(value.is_some_and(|value| query::glob(&pattern, &value)))
    })?;
    connection.create_scalar_function("snitchhiker_text", 3, flags, |cx| {
        let needle: String = cx.get(0)?;
        let exe: Option<String> = cx.get(1)?;
        let host: Option<String> = cx.get(2)?;
        Ok(query::text(
            &needle,
            &[exe.as_deref().unwrap_or(""), host.as_deref().unwrap_or("")],
        ))
    })?;
    connection.create_scalar_function("snitchhiker_net", 2, flags, |cx| {
        let net: String = cx.get(0)?;
        let address: Vec<u8> = cx.get(1)?;
        Ok(net
            .parse::<ipnet::IpNet>()
            .is_ok_and(|net| query::in_net(&net, address_from(&address))))
    })?;
    Ok(())
}

fn id_of(id: i64) -> u64 {
    u64::try_from(id).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

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
    fn recording_gives_sequence_numbers_to_resume_from() {
        let mut store = Store::in_memory().unwrap();
        let mut recorded = Vec::new();
        store
            .record(
                &[
                    event(1, "/usr/bin/curl", None),
                    event(2, "/usr/bin/curl", None),
                    event(3, "/usr/bin/wget", None),
                ],
                &mut recorded,
            )
            .unwrap();
        let seqs: Vec<i64> = recorded.iter().map(|r| r.seq).collect();
        assert_eq!(seqs.len(), 3);
        assert!(
            recorded[0].exe != 0
                && recorded[0].exe == recorded[1].exe
                && recorded[2].exe != recorded[0].exe
        );
        let rows = store.event_rows_after(seqs[0], 10).unwrap();
        assert_eq!(rows.iter().map(|r| r.seq).collect::<Vec<_>>(), seqs[1..]);
        assert_eq!(
            store
                .event_rows(i64::MAX, 2)
                .unwrap()
                .iter()
                .map(|r| r.seq)
                .collect::<Vec<_>>(),
            seqs[1..]
        );
        let names = store.strings_of([recorded[2].exe, 0, 999_999]).unwrap();
        assert_eq!(
            names,
            vec![(recorded[2].exe, std::sync::Arc::from("/usr/bin/wget"))]
        );
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
        let after = store.events_after(seqs[0], 10).unwrap();
        let resumed: Vec<i64> = after.iter().map(|e| e.seq).collect();
        assert_eq!(resumed, seqs[1..]);
        assert_eq!(after[1].exe, "/usr/bin/wget");
        assert_eq!(store.events_after(seqs[0], 1).unwrap().len(), 1);
    }

    #[test]
    fn rules_round_trip() {
        let store = Store::in_memory().unwrap();
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

    fn sample(name: &str, folder: Option<FolderId>) -> Rule {
        Rule {
            id: 0,
            folder,
            name: name.into(),
            enabled: true,
            action: Action::Allow,
            tier: Tier::Normal,
            expiry: Expiry::Never,
            log: true,
            notes: String::new(),
            conditions: vec![Condition::Port(vec![(443, 443)])],
        }
    }

    #[test]
    fn rollups_follow_events_and_their_bytes() {
        let mut store = Store::in_memory().unwrap();
        let mut curl = event(1, "/usr/bin/curl", Some("example.com"));
        curl.cookie = Some(7);
        let mut wget = event(2, "/usr/bin/wget", Some("example.com"));
        wget.action = Action::Deny;
        let mut recorded = Vec::new();
        store
            .record(
                &[curl.clone(), event(3, "/usr/bin/curl", None), wget],
                &mut recorded,
            )
            .unwrap();
        store.record_bytes(&[(7, 500, 9000)]).unwrap();
        // Counted again: only the difference reaches the rollup.
        store.record_bytes(&[(7, 600, 9000)]).unwrap();
        let by_exe = store
            .explore(0, u64::MAX / HOUR_MS, Dimension::Exe, None, 10)
            .unwrap();
        let curl_id = i64::from(recorded[0].exe);
        let curl_row = by_exe.iter().find(|r| r.key == curl_id).unwrap();
        assert_eq!((curl_row.allowed, curl_row.blocked), (2, 0));
        assert_eq!((curl_row.bytes_out, curl_row.bytes_in), (600, 9000));
        assert_eq!(by_exe[0].key, curl_id, "busiest first");
        // Drill-down: the hosts of wget's connections, blocked.
        let wget_id = i64::from(recorded[2].exe);
        let hosts = store
            .explore(
                0,
                u64::MAX / HOUR_MS,
                Dimension::Host,
                Some((Dimension::Exe, wget_id)),
                10,
            )
            .unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!((hosts[0].allowed, hosts[0].blocked), (0, 1));
        assert_eq!(store.prune_rollups(u64::MAX / 2).unwrap(), 3);
    }

    /// The Explorer over a month of a million connections: `mise run perf` (release, `--ignored`).
    #[test]
    #[ignore = "a million events: run with mise run perf"]
    fn explore_stays_fast_over_a_million_events() {
        let mut store = Store::in_memory().unwrap();
        let programs: Vec<String> = (0..200)
            .map(|i| format!("/usr/lib/p{i}/bin/p{i}"))
            .collect();
        let hosts: Vec<String> = (0..2000).map(|i| format!("s{i}.example.com")).collect();
        let month = 30 * 24 * HOUR_MS;
        let mut recorded = Vec::new();
        for chunk in 0..1000_u64 {
            let events: Vec<Event> = (0..1000_u64)
                .map(|i| {
                    let n = chunk * 1000 + i;
                    let mut e = event(
                        n,
                        &programs[usize::try_from(n * 7 % 200).unwrap()],
                        Some(&hosts[usize::try_from(n * 13 % 2000).unwrap()]),
                    );
                    e.time_ms = n * month / 1_000_000;
                    e.port = [443, 80, 53][usize::try_from(n % 3).unwrap()];
                    e
                })
                .collect();
            store.record(&events, &mut recorded).unwrap();
        }
        let started = std::time::Instant::now();
        let by_program = store
            .explore(0, month / HOUR_MS + 1, Dimension::Exe, None, 1000)
            .unwrap();
        let grouped = started.elapsed();
        let program = by_program[0].key;
        let started = std::time::Instant::now();
        let hosts_of_one = store
            .explore(
                0,
                month / HOUR_MS + 1,
                Dimension::Host,
                Some((Dimension::Exe, program)),
                100,
            )
            .unwrap();
        let drilled = started.elapsed();
        let total: u64 = by_program.iter().map(|r| r.allowed + r.blocked).sum();
        assert_eq!(total, 1_000_000);
        assert_ne!(hosts_of_one.len(), 0);
        let _ = writeln!(
            std::io::stderr(),
            "a month of a million connections: by program {grouped:?}, one program's hosts {drilled:?}"
        );
        assert!(
            grouped < std::time::Duration::from_millis(500),
            "{grouped:?}"
        );
        assert!(
            drilled < std::time::Duration::from_millis(500),
            "{drilled:?}"
        );
    }

    #[test]
    fn changes_are_recorded_and_undone_by_batch() {
        let mut store = Store::in_memory().unwrap();
        // One batch: a folder and two rules in it.
        let first = store.batch("cli", 1).unwrap();
        let (folder, a) = store
            .atomically(|store| {
                let folder = store.put_folder(
                    &Folder {
                        id: 0,
                        parent: None,
                        name: "Apps".into(),
                        enabled: true,
                        scope: Vec::new(),
                    },
                    &first,
                )?;
                let a = store.put_rule(&sample("a", Some(folder)), &first)?;
                store.put_rule(&sample("b", Some(folder)), &first)?;
                Ok::<_, Error>((folder, a))
            })
            .unwrap();
        // A second: rule a switched off.
        let second = store.batch("desktop", 2).unwrap();
        let mut off = store.rule(a).unwrap().unwrap();
        off.enabled = false;
        store.put_rule(&off, &second).unwrap();
        // A third: the folder deleted, with its rules.
        let third = store.batch("desktop", 3).unwrap();
        assert_eq!(store.remove_folder(folder, &third).unwrap(), Some(2));
        assert_eq!(store.rules().unwrap(), Vec::new());
        let changes = store.changes(u64::MAX, 10).unwrap();
        let what: Vec<&str> = changes.iter().map(|c| c.what.as_str()).collect();
        assert_eq!(
            what,
            vec![
                "deleted folder \"Apps\"",
                "deleted rule \"b\"",
                "deleted rule \"a\"",
                "rule \"a\": switched off",
                "added rule \"b\"",
                "added rule \"a\"",
                "added folder \"Apps\""
            ]
        );
        // Undoing the deletion puts the folder and both rules back, as they were.
        let undo = store.batch("desktop", 4).unwrap();
        assert_eq!(store.undo(changes[0].id, &undo).unwrap(), 3);
        let rules = store.rules().unwrap();
        assert_eq!(rules.len(), 2);
        assert!(
            rules
                .iter()
                .any(|r| r.id == a && !r.enabled && r.folder == Some(folder))
        );
        // The first batch can't be undone now: rule a changed since.
        let again = store.batch("desktop", 5).unwrap();
        let first_change = changes.last().unwrap().id;
        assert!(matches!(
            store.undo(first_change, &again),
            Err(UndoError::Changed(_))
        ));
        assert!(matches!(
            store.undo(9999, &again),
            Err(UndoError::NotFound(9999))
        ));
    }

    #[test]
    fn events_round_trip_newest_first_with_strings_shared() {
        let mut store = Store::in_memory().unwrap();
        store
            .record(
                &[
                    event(1, "/usr/bin/curl", Some("example.com")),
                    event(2, "/usr/bin/curl", None),
                    event(3, "/usr/bin/wget", Some("example.com")),
                ],
                &mut Vec::new(),
            )
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
        store.record(&[first, second], &mut Vec::new()).unwrap();
        store.record_bytes(&[(77, 1000, 5000)]).unwrap();
        let page = store.events(i64::MAX, 10).unwrap();
        assert_eq!((page[0].bytes_out, page[0].bytes_in), (1000, 5000));
        assert_eq!((page[1].bytes_out, page[1].bytes_in), (0, 0));
    }

    #[test]
    fn prunes_in_chunks() {
        let mut store = Store::in_memory().unwrap();
        let events: Vec<Event> = (0..10).map(|i| event(i, "/usr/bin/curl", None)).collect();
        store.record(&events, &mut Vec::new()).unwrap();
        assert_eq!(store.prune(1_005, 3).unwrap(), 3);
        assert_eq!(store.prune(1_005, 3).unwrap(), 2);
        assert_eq!(store.events(i64::MAX, 100).unwrap().len(), 5);
    }

    /// Every statement is an index seek: no scan of a growing table, no temporary sort.
    /// The query language's two executors, SQL here and in memory in the clients, agree on the same history.
    #[test]
    fn queries_match_the_same_events_in_sql_and_in_memory() {
        let mut seed: u64 = 0x5eed;
        let mut next = move |n: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % n
        };
        let pick = |options: &[&'static str], i: u64| options[usize::try_from(i).unwrap()];
        let exes = [
            "/usr/bin/curl",
            "/usr/bin/firefox",
            "/opt/App Image/app",
            "/usr/lib/systemd/systemd-resolved",
        ];
        let hosts = [
            "example.com",
            "api.example.com",
            "Mirror.Example.ORG",
            "cdn.net",
        ];
        let addresses = [
            "198.51.100.7",
            "10.1.2.3",
            "192.168.0.10",
            "2001:db8::1",
            "::ffff:10.9.8.7",
        ];
        let mut events = Vec::new();
        for seq in 0..600 {
            let mut e = event(seq, pick(&exes, next(4)), None);
            e.host = (next(5) != 0).then(|| Arc::from(pick(&hosts, next(4))));
            e.uid = [0, 1000, 1001][usize::try_from(next(3)).unwrap()];
            e.port = [53, 80, 443, 8080][usize::try_from(next(4)).unwrap()];
            e.protocol = if next(3) == 0 { 17 } else { 6 };
            e.address = pick(&addresses, next(5)).parse().unwrap();
            e.action =
                [Action::Allow, Action::Deny, Action::Reject][usize::try_from(next(3)).unwrap()];
            e.rule = (next(3) != 0).then(|| next(4) + 1);
            e.context = u8::try_from(next(4)).unwrap();
            e.time_ms = 1_000_000 + seq * 60_000;
            events.push(e);
        }
        let mut store = Store::in_memory().unwrap();
        store.record(&events, &mut Vec::new()).unwrap();
        store
            .connection()
            .execute_batch(
                "UPDATE events SET bytes_out = (seq * 37) % 5000, bytes_in = (seq * 7919) % 3000000",
            )
            .unwrap();
        let stored = store.events(i64::MAX, 10_000).unwrap();
        assert_eq!(stored.len(), 600);
        let terms = [
            "curl",
            "EXAMPLE",
            "exe:*/curl",
            "exe:\"/opt/App Image/*\"",
            "host:*.example.com",
            "host:example",
            "host:none",
            "ip:10.0.0.0/8",
            "ip:2001:db8::/32",
            "ip:198.51.100.7",
            "port:443",
            "port:50-90",
            "port>80",
            "port<=53",
            "proto:udp",
            "user:1000",
            "user>=1000",
            "action:deny",
            "rule:none",
            "rule:2",
            "bytes>1M",
            "sent<100",
            "received>=2M",
            "time>1970-01-01T05:00",
            "time<2000000",
            "context:vm",
            "context:host",
            "a?p",
        ];
        let cx = query::Context {
            now_ms: 0,
            uid_of: &|_| None,
        };
        let mut queries: Vec<String> = terms.iter().map(|t| (*t).to_owned()).collect();
        for _ in 0..300 {
            let mut term = |next: &mut dyn FnMut(u64) -> u64| {
                let t = pick(&terms, next(terms.len() as u64));
                if next(4) == 0 {
                    format!("-{t}")
                } else {
                    t.to_owned()
                }
            };
            let shape = next(3);
            let (a, b, c, d) = (
                term(&mut next),
                term(&mut next),
                term(&mut next),
                term(&mut next),
            );
            queries.push(match shape {
                0 => format!("{a} {b}"),
                1 => format!("{a} OR {b}"),
                _ => format!("({a} OR {b}) -({c} {d})"),
            });
        }
        let mut matched_some = 0;
        for q in &queries {
            let filter = EventFilter::parse(q, &cx).unwrap();
            let (rows, scanned_from) = store
                .event_rows_matching(i64::MAX, 10_000, &filter)
                .unwrap();
            assert_eq!(scanned_from, 0, "{q}: the whole history fits one window");
            let in_sql: Vec<i64> = rows.iter().rev().map(|r| r.seq).collect();
            let in_memory: Vec<i64> = stored
                .iter()
                .filter(|e| {
                    filter.matches(&query::EventView {
                        time_ms: e.time_ms,
                        exe: &e.exe,
                        host: e.host.as_deref().unwrap_or(""),
                        address: e.address,
                        port: e.port,
                        protocol: e.protocol,
                        uid: e.uid,
                        action: action_code(e.action),
                        rule: e.rule.unwrap_or(0),
                        context: e.context,
                        bytes_out: e.bytes_out,
                        bytes_in: e.bytes_in,
                    })
                })
                .map(|e| e.seq)
                .collect();
            assert_eq!(in_sql, in_memory, "{q}");
            matched_some += usize::from(!in_sql.is_empty() && in_sql.len() < 600);
        }
        assert!(
            matched_some > queries.len() / 2,
            "the queries should discriminate"
        );
    }

    #[test]
    fn a_sparse_query_pages_through_history_in_windows() {
        let mut store = Store::in_memory().unwrap();
        let events: Vec<Event> = (0..10).map(|i| event(i, "/usr/bin/x", None)).collect();
        store.record(&events, &mut Vec::new()).unwrap();
        let cx = query::Context {
            now_ms: 0,
            uid_of: &|_| None,
        };
        let filter = EventFilter::parse("exe:x", &cx).unwrap();
        // A page full before the window ends continues from its oldest event.
        let (rows, scanned_from) = store.event_rows_matching(i64::MAX, 3, &filter).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(scanned_from, rows[0].seq);
        let none = EventFilter::parse("exe:nothing", &cx).unwrap();
        assert_eq!(
            store.event_rows_matching(i64::MAX, 3, &none).unwrap(),
            (Vec::new(), 0)
        );
    }

    /// Filtered pages walk the primary key down from `before`: whatever the query, never a table scan or a sort.
    #[test]
    fn filtered_pages_walk_the_primary_key() {
        let store = Store::in_memory().unwrap();
        let cx = query::Context {
            now_ms: 0,
            uid_of: &|_| None,
        };
        let filter = EventFilter::parse("(curl OR host:*.x) -port:443 time>5", &cx).unwrap();
        let (condition, values) = filter.sql();
        let mut plan = store
            .connection()
            .prepare(&format!(
                "EXPLAIN QUERY PLAN SELECT e.seq FROM events e CROSS JOIN strings x ON x.id = e.exe
                 LEFT JOIN strings h ON h.id = e.host WHERE e.seq < ? AND e.seq >= ? AND {condition}
                 ORDER BY e.seq DESC LIMIT ?"
            ))
            .unwrap();
        let params = values.len() + 3;
        let details: Vec<String> = plan
            .query_map(
                rusqlite::params_from_iter((0..params).map(|_| rusqlite::types::Value::Integer(1))),
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            details
                .first()
                .is_some_and(|d| d.starts_with("SEARCH e USING INTEGER PRIMARY KEY")),
            "{details:?}"
        );
        assert!(
            !details.iter().any(|d| d.contains("TEMP B-TREE")),
            "{details:?}"
        );
    }

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
        store.record(&events, &mut Vec::new()).unwrap();
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
                // A constant row is no table: the frame of scalar subqueries.
                let scans_growing_table = detail.starts_with("SCAN")
                    && detail != "SCAN CONSTANT ROW"
                    && !SCANNABLE.iter().any(|t| detail == &format!("SCAN {t}"));
                assert!(!scans_growing_table, "{name} scans: {details:?}");
                let sorts_within_range = GROUPS_IN_RANGE
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
                    && details.first().is_some_and(|first| {
                        first.starts_with("SEARCH") && first.contains("hour>? AND hour<?")
                    });
                assert!(
                    !detail.contains("TEMP B-TREE") || sorts_within_range,
                    "{name} sorts: {details:?}"
                );
            }
        }
    }
}
