//! Blocklists from URLs and files (plan §5.8): fetched on a schedule, checked before they replace what was there, kept
//! on disk so a restart without a network still has them, and named by rules' `list` condition.
//!
//! A list's source is an `https://` URL (plain HTTP isn't taken: anyone on the path could change it) or a file in
//! [`LOCAL_DIR`], a directory only root writes: a client may add lists, and must not make the daemon (root) read any
//! other file on the node, which the list's entries, counts and errors would then show. A fetch is refused, and the version before kept, when the file is larger than
//! `blocklist_max_bytes`, isn't text, has no entries, or has more than a tenth of its lines that aren't entries (an
//! error page, a list in a format this doesn't read). Unchanged lists aren't downloaded again (`If-None-Match`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use snitchhiker_core::blocklist::Blocklist;
use snitchhiker_core::engine::Lists;
use snitchhiker_core::rule::{Condition, Rule, RuleId};
use snitchhiker_proto::v1;
use tracing::{info, warn};

/// How often a list is fetched unless it says otherwise: daily.
pub const DEFAULT_REFRESH_SECS: u64 = 86_400;
/// Lists aren't fetched more often than this.
pub const MIN_REFRESH_SECS: u64 = 900;

/// A list as the store keeps it: what it is, and how its last fetch went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    #[serde(skip)]
    pub id: u64,
    #[serde(skip)]
    pub name: String,
    pub source: String,
    pub refresh_secs: u64,
    /// When the content last changed.
    pub updated_ms: u64,
    /// When it was last fetched, changed or not.
    pub checked_ms: u64,
    pub sha256: String,
    pub etag: String,
    pub bytes: u64,
    pub entries: u64,
    pub invalid: u64,
    /// The last fetch's error; empty when it worked.
    pub error: String,
}

impl Record {
    /// When it is fetched next: an hour after a failure, if that's sooner.
    fn due_ms(&self) -> u64 {
        let mut every = self.refresh_secs.max(MIN_REFRESH_SECS);
        if !self.error.is_empty() {
            every = every.min(3600);
        }
        self.checked_ms.saturating_add(every.saturating_mul(1000))
    }
}

/// The lists in use, and what decided by them.
pub struct Blocklists {
    dir: PathBuf,
    /// Where local lists are read from: [`LOCAL_DIR`].
    local_dir: PathBuf,
    max_bytes: u64,
    lists: RwLock<Lists>,
    /// Connections decided by rules naming each list, since the daemon started.
    matched: RwLock<HashMap<Box<str>, Arc<AtomicU64>>>,
    /// Each rule naming lists, with their counters.
    by_rule: ArcSwap<HashMap<RuleId, Vec<Arc<AtomicU64>>>>,
    /// One fetch at a time.
    fetching: Mutex<()>,
    /// Counts changes of the lists, to wake the refresher.
    changed: (Mutex<u64>, Condvar),
}

impl Blocklists {
    /// The lists of `records`, as last fetched into `dir`.
    #[must_use]
    pub fn load(dir: PathBuf, max_bytes: u64, records: &[Record]) -> Self {
        let mut lists = Lists::new();
        for record in records {
            match std::fs::read_to_string(file(&dir, record.id)) {
                Ok(text) => {
                    lists.insert(
                        record.name.as_str().into(),
                        Arc::new(Blocklist::parse(&text).list),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => warn!(%error, list = record.name, "reading a blocklist"),
            }
        }
        Self {
            dir,
            local_dir: PathBuf::from(LOCAL_DIR),
            max_bytes,
            lists: RwLock::new(lists),
            matched: RwLock::default(),
            by_rule: ArcSwap::default(),
            fetching: Mutex::new(()),
            changed: (Mutex::new(0), Condvar::new()),
        }
    }

    /// The lists, for compiling rules.
    #[must_use]
    pub fn lists(&self) -> Lists {
        self.lists
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Which lists `rules` name, for counting what they decide.
    pub fn rules_compiled(&self, rules: &[Rule]) {
        let mut matched = self.matched.write().unwrap_or_else(PoisonError::into_inner);
        let mut by_rule = HashMap::new();
        for rule in rules {
            let counters: Vec<Arc<AtomicU64>> = names(&rule.conditions)
                .map(|name| Arc::clone(matched.entry(name.into()).or_default()))
                .collect();
            if !counters.is_empty() {
                by_rule.insert(rule.id, counters);
            }
        }
        drop(matched);
        self.by_rule.store(Arc::new(by_rule));
    }

    /// Counts a connection `rule` decided.
    pub fn decided(&self, rule: RuleId) {
        if let Some(counters) = self.by_rule.load().get(&rule) {
            for counter in counters {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn matched(&self, name: &str) -> u64 {
        self.matched
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// The list as clients see it; `rules` are the rules naming it.
    #[must_use]
    pub fn wire(&self, record: &Record, rules: Vec<u64>) -> v1::Blocklist {
        v1::Blocklist {
            name: record.name.clone(),
            source: record.source.clone(),
            refresh_secs: record.refresh_secs,
            updated_ms: record.updated_ms,
            checked_ms: record.checked_ms,
            sha256: record.sha256.clone(),
            bytes: record.bytes,
            entries: record.entries,
            invalid: record.invalid,
            error: record.error.clone(),
            matched: self.matched(&record.name),
            rules,
        }
    }

    /// Wakes the refresher: lists were added, removed or changed.
    pub fn changed(&self) {
        let (lock, wake) = &self.changed;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        wake.notify_all();
    }

    /// Waits until the next list is due (`next_ms` from now, or forever) or the lists change.
    pub fn wait(&self, next_ms: Option<u64>, now_ms: u64) {
        let (lock, wake) = &self.changed;
        let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = *guard;
        let timeout =
            Duration::from_millis(next_ms.map_or(u64::MAX / 2, |at| at.saturating_sub(now_ms)));
        let _ = wake
            .wait_timeout_while(guard, timeout, |count| *count == seen)
            .unwrap_or_else(PoisonError::into_inner);
    }

    /// The list removed: its file and its set.
    pub fn removed(&self, record: &Record) {
        self.lists
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(record.name.as_str());
        let _ = std::fs::remove_file(file(&self.dir, record.id));
        self.changed();
    }

    /// Fetches a list; `record` is updated with how it went. True when its content changed (the rules then need
    /// compiling again).
    pub fn fetch(&self, record: &mut Record, now_ms: u64) -> bool {
        let _one = self.fetching.lock().unwrap_or_else(PoisonError::into_inner);
        record.checked_ms = now_ms;
        match self.download(record) {
            Ok(None) => {
                record.error.clear();
                false
            }
            Ok(Some((text, etag))) => match self.accept(record, &text) {
                Ok(changed) => {
                    record.etag = etag;
                    record.error.clear();
                    if changed {
                        record.updated_ms = now_ms;
                        info!(
                            list = record.name,
                            entries = record.entries,
                            "a blocklist changed"
                        );
                    }
                    changed
                }
                Err(error) => {
                    warn!(list = record.name, %error, "a blocklist was refused; the version before stays");
                    record.error = error;
                    false
                }
            },
            Err(error) => {
                warn!(list = record.name, %error, "fetching a blocklist");
                record.error = error;
                false
            }
        }
    }

    /// The content, or `None` when the server says it is unchanged.
    fn download(&self, record: &Record) -> Result<Option<(String, String)>, String> {
        let limit = self.max_bytes;
        let too_large = || format!("larger than {limit} bytes (`blocklist_max_bytes`)");
        let mut bytes = Vec::new();
        let mut etag = String::new();
        if record.source.starts_with('/') {
            // Checked again here, after resolving links: a list added before files were confined to the directory, or a
            // link put there.
            let file = std::fs::File::open(local_file(&self.local_dir, &record.source)?)
                .map_err(|e| e.to_string())?;
            file.take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
        } else {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .https_only(true)
                .build()
                .map_err(|e| e.to_string())?;
            let mut request = client.get(&record.source).header(
                "user-agent",
                concat!("snitchhiker/", env!("CARGO_PKG_VERSION")),
            );
            // Only when the file is still there to fall back on.
            if !record.etag.is_empty() && file(&self.dir, record.id).exists() {
                request = request.header("if-none-match", &record.etag);
            }
            let response = request
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .map_err(|e| e.to_string())?;
            if response.status() == reqwest::StatusCode::NOT_MODIFIED {
                return Ok(None);
            }
            if response.content_length().is_some_and(|n| n > limit) {
                return Err(too_large());
            }
            response
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .clone_into(&mut etag);
            response
                .take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
        }
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
            return Err(too_large());
        }
        let text = String::from_utf8(bytes).map_err(|_| "not a text file".to_owned())?;
        Ok(Some((text, etag)))
    }

    /// Checks `text` and puts it in use. True when it differs from what was there.
    fn accept(&self, record: &mut Record, text: &str) -> Result<bool, String> {
        let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
        let sha256 = digest
            .as_ref()
            .iter()
            .fold(String::with_capacity(64), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            });
        let present = self
            .lists
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(record.name.as_str());
        if sha256 == record.sha256 && present {
            return Ok(false);
        }
        let parsed = Blocklist::parse(text);
        if parsed.entries == 0 {
            return Err("no entries: not a list this reads (hosts, domains, adblock domain rules, addresses)".to_owned());
        }
        let lines = parsed.entries + parsed.invalid;
        if parsed.invalid * 10 > lines {
            return Err(format!(
                "{} of its lines aren't entries (the first: {:?})",
                parsed.invalid,
                parsed.first_invalid.unwrap_or_default()
            ));
        }
        write(&self.dir, record.id, text).map_err(|e| format!("saving it: {e}"))?;
        record.sha256 = sha256;
        record.bytes = u64::try_from(text.len()).unwrap_or(u64::MAX);
        record.entries = u64::try_from(parsed.entries).unwrap_or(u64::MAX);
        record.invalid = u64::try_from(parsed.invalid).unwrap_or(u64::MAX);
        self.lists
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(record.name.as_str().into(), Arc::new(parsed.list));
        Ok(true)
    }
}

/// The lists a rule's conditions name.
pub fn names(conditions: &[Condition]) -> impl Iterator<Item = &str> {
    conditions.iter().flat_map(|c| match c {
        Condition::List(names) => names.iter().map(String::as_str).collect::<Vec<_>>(),
        Condition::Not(inner) => names(std::slice::from_ref(inner.as_ref())).collect(),
        _ => Vec::new(),
    })
}

/// The next list due, if any.
#[must_use]
pub fn next_due(records: &[Record]) -> Option<u64> {
    records.iter().map(Record::due_ms).min()
}

/// Whether a list is due at `now_ms`.
#[must_use]
pub fn is_due(record: &Record, now_ms: u64) -> bool {
    record.due_ms() <= now_ms
}

/// The directory local lists are read from: regular files in it, never through a symbolic link out of it.
pub const LOCAL_DIR: &str = "/etc/snitchhiker/lists";

/// A local list's file, after resolving links: one that is still directly in `local_dir` and a regular file.
fn local_file(local_dir: &Path, source: &str) -> Result<PathBuf, String> {
    let outside = || format!("{source:?}: a local list is a file in {LOCAL_DIR}");
    let real = std::fs::canonicalize(source).map_err(|e| format!("{source:?}: {e}"))?;
    let dir =
        std::fs::canonicalize(local_dir).map_err(|e| format!("{}: {e}", local_dir.display()))?;
    if real.parent() != Some(dir.as_path()) {
        return Err(outside());
    }
    let metadata = std::fs::symlink_metadata(&real).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err(outside());
    }
    Ok(real)
}

/// Checks what a client asks for: a name rules can use, and a source this fetches.
pub fn check(name: &str, source: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "{name:?}: a list's name is 1 to 64 letters, digits, '-', '_' and '.'"
        ));
    }
    let local = Path::new(source);
    let in_dir = local.parent() == Some(Path::new(LOCAL_DIR))
        && local.file_name().is_some_and(|n| n != ".." && n != ".");
    if !(source.starts_with("https://") || in_dir) {
        return Err(format!(
            "{source:?}: a list comes from an https:// URL or a file in {LOCAL_DIR} on the node"
        ));
    }
    Ok(())
}

fn file(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id}.list"))
}

fn write(dir: &Path, id: u64, text: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = file(dir, id);
    let partial = path.with_extension("partial");
    std::fs::write(&partial, text)?;
    std::fs::rename(partial, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_checked_before_they_are_used() {
        let dir = std::env::temp_dir().join(format!("snitchhiker-lists-{}", std::process::id()));
        let source = dir.join("source.txt");
        std::fs::create_dir_all(&dir).unwrap();
        let mut lists = Blocklists::load(dir.join("lists"), 1024, &[]);
        lists.local_dir.clone_from(&dir);
        let mut record = Record {
            id: 1,
            name: "ads".to_owned(),
            source: source.to_string_lossy().into_owned(),
            ..Record::default()
        };
        std::fs::write(&source, "ads.example\n198.51.100.0/24\n").unwrap();
        assert!(lists.fetch(&mut record, 10));
        assert_eq!((record.entries, record.error.as_str()), (2, ""));
        assert!(lists.lists()["ads"].has_host("x.ads.example"));
        // The same again: nothing changed.
        assert!(!lists.fetch(&mut record, 20));
        assert_eq!((record.updated_ms, record.checked_ms), (10, 20));
        // An error page instead of the list: refused, the list before stays.
        std::fs::write(&source, "<html>\n<body>\nNot found\n</body>\n</html>\n").unwrap();
        assert!(!lists.fetch(&mut record, 30));
        assert!(record.error.starts_with("no entries"), "{}", record.error);
        std::fs::write(&source, "a.example\n<b>\n").unwrap();
        assert!(!lists.fetch(&mut record, 30));
        assert!(record.error.contains("aren't entries"), "{}", record.error);
        std::fs::write(&source, "x".repeat(2000)).unwrap();
        assert!(!lists.fetch(&mut record, 30));
        assert!(record.error.starts_with("larger than"), "{}", record.error);
        assert!(lists.lists()["ads"].has_host("ads.example"));
        // What was fetched is there after a restart.
        let again = Blocklists::load(dir.join("lists"), 1024, std::slice::from_ref(&record));
        assert!(again.lists()["ads"].has_host("ads.example"));
        // Counting what rules naming it decide.
        let rule = Rule {
            id: 7,
            folder: None,
            name: "ads".to_owned(),
            enabled: true,
            action: snitchhiker_core::rule::Action::Deny,
            tier: snitchhiker_core::rule::Tier::Normal,
            expiry: snitchhiker_core::rule::Expiry::Never,
            log: true,
            notes: String::new(),
            conditions: vec![Condition::List(vec!["ads".to_owned()])],
        };
        lists.rules_compiled(std::slice::from_ref(&rule));
        lists.decided(7);
        lists.decided(8);
        assert_eq!(lists.wire(&record, vec![7]).matched, 1);
        // A link from the directory to a file elsewhere isn't read.
        let elsewhere =
            std::env::temp_dir().join(format!("snitchhiker-elsewhere-{}", std::process::id()));
        std::fs::write(&elsewhere, "ads.example\n").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let mut linked = Record {
            id: 2,
            name: "linked".to_owned(),
            source: link.to_string_lossy().into_owned(),
            ..Record::default()
        };
        assert!(!lists.fetch(&mut linked, 40));
        assert!(
            linked.error.contains("a local list is a file in"),
            "{}",
            linked.error
        );
        std::fs::remove_file(elsewhere).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn names_and_sources_are_checked() {
        assert!(check("oisd-big", "https://big.oisd.nl/domainswild").is_ok());
        assert!(check("ads", "/etc/snitchhiker/lists/ads.txt").is_ok());
        // Only files in the lists directory: nothing else root can read.
        assert!(check("ads", "/etc/shadow").is_err());
        assert!(check("ads", "/etc/snitchhiker/ads.txt").is_err());
        assert!(check("ads", "/etc/snitchhiker/lists/../daemon.toml").is_err());
        assert!(check("ads", "/etc/snitchhiker/lists/sub/ads.txt").is_err());
        assert!(check("ads", "/etc/snitchhiker/lists/").is_err());
        assert!(check("ads", "http://example.com/list").is_err());
        assert!(check("ads", "relative.txt").is_err());
        assert!(check("bad name", "/x").is_err());
    }
}
