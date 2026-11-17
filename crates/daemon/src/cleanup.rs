//! `snitchhikerd cleanup`: what happens to the daemon's tables after it stopped (the service runs it after every
//! stop, `ExecStopPost`, with systemd's `SERVICE_RESULT` saying how the stop went).
//!
//! - With `fail = "open"`, run by hand, or with a configuration that doesn't read: they are removed.
//! - With `fail = "closed"`, after a clean stop: they stay (the daemon kept them; nothing gets out until it is back).
//! - With `fail = "closed"`, after a crash: they stay for a restart, unless the daemon crashed [`CRASHES`] times in
//!   [`WINDOW`]: a daemon that can't stay up mustn't keep the machine offline. Then they are removed after each crash
//!   until the crashes are that far apart again.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{Config, Fail};

/// Crashes in [`WINDOW`] after which the tables are removed even with `fail = "closed"`.
pub const CRASHES: usize = 3;
/// How far back crashes count.
pub const WINDOW: Duration = Duration::from_secs(300);

/// What to do with the tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Remove,
    Keep,
}

/// Decides, given the configuration (`None`: it doesn't read), systemd's `SERVICE_RESULT` (`None`: run by hand), the
/// times of the crashes before (seconds), and now. Returns what to do and the crashes to remember.
#[must_use]
pub fn decide(
    fail: Option<Fail>,
    result: Option<&str>,
    mut crashes: Vec<u64>,
    now: u64,
) -> (Outcome, Vec<u64>) {
    let (Some(Fail::Closed), Some(result)) = (fail, result) else {
        return (Outcome::Remove, Vec::new());
    };
    if result == "success" {
        return (Outcome::Keep, Vec::new());
    }
    crashes.retain(|&at| at <= now && now - at < WINDOW.as_secs());
    crashes.push(now);
    let outcome = if crashes.len() >= CRASHES {
        Outcome::Remove
    } else {
        Outcome::Keep
    };
    (outcome, crashes)
}

/// Where the crashes are remembered: next to the database.
fn record(config: &Config) -> PathBuf {
    config
        .database
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join("crashes")
}

fn read(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

fn write(path: &Path, crashes: &[u64]) {
    let result = if crashes.is_empty() {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    } else {
        let mut text = String::new();
        for at in crashes {
            text.push_str(&at.to_string());
            text.push('\n');
        }
        std::fs::write(path, text)
    };
    if let Err(error) = result {
        tracing::warn!(%error, path = %path.display(), "remembering the daemon's crashes");
    }
}

/// Runs the decision for the configuration at `config_path`; true when nothing failed.
#[must_use]
pub fn run(config_path: &Path) -> bool {
    let config = match Config::load(config_path) {
        Ok(config) => Some(config),
        Err(error) => {
            tracing::warn!(%error, "reading the configuration: removing the tables");
            None
        }
    };
    let result = std::env::var("SERVICE_RESULT").ok();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let path = config.as_ref().map(record);
    let before = path.as_deref().map_or_else(Vec::new, read);
    let (outcome, crashes) = decide(
        config.as_ref().map(|c| c.fail),
        result.as_deref(),
        before,
        now,
    );
    if let Some(path) = &path {
        write(path, &crashes);
    }
    match outcome {
        Outcome::Keep => {
            tracing::info!(
                result = result.as_deref().unwrap_or_default(),
                crashes = crashes.len(),
                "fail = closed: the tables stay until the daemon is back"
            );
            true
        }
        Outcome::Remove => {
            if crashes.len() >= CRASHES {
                tracing::warn!(
                    crashes = crashes.len(),
                    "the daemon keeps crashing: removing its tables despite fail = closed, so the machine isn't cut off"
                );
            }
            crate::runtime::remove_tables(&snitchhiker_netfilter::nftables::Table::default().name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_by_hand_or_unreadable_removes() {
        let removes = |fail, result| decide(fail, result, vec![], 1000).0 == Outcome::Remove;
        assert!(removes(Some(Fail::Open), Some("success")));
        assert!(removes(Some(Fail::Open), Some("signal")));
        assert!(removes(Some(Fail::Closed), None));
        assert!(removes(None, Some("success")));
    }

    #[test]
    fn closed_keeps_after_a_clean_stop_and_forgets_crashes() {
        assert_eq!(
            decide(Some(Fail::Closed), Some("success"), vec![990, 995], 1000),
            (Outcome::Keep, vec![])
        );
    }

    #[test]
    fn closed_removes_once_crashes_come_too_often() {
        let closed = Some(Fail::Closed);
        let (first, crashes) = decide(closed, Some("signal"), vec![], 1000);
        let (second, crashes) = decide(closed, Some("core-dump"), crashes, 1010);
        let (third, crashes) = decide(closed, Some("exit-code"), crashes, 1020);
        assert_eq!(
            (first, second, third),
            (Outcome::Keep, Outcome::Keep, Outcome::Remove)
        );
        // The next crash in the window removes them too.
        assert_eq!(
            decide(closed, Some("signal"), crashes, 1030).0,
            Outcome::Remove
        );
    }

    #[test]
    fn old_crashes_dont_count() {
        let (outcome, crashes) = decide(Some(Fail::Closed), Some("signal"), vec![100, 200], 1000);
        assert_eq!((outcome, crashes), (Outcome::Keep, vec![1000]));
    }
}
