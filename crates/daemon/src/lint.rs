//! The lint and dedupe report on this node: the rule set (the database's and the managed ones), what the filesystem
//! says about their binaries, and when each rule last decided a connection.

use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use snitchhiker_core::lint::{self, Kind, Linted, NodeFacts};
use snitchhiker_core::pattern::{Pattern, PatternSource};
use snitchhiker_core::rule::{Condition, Folder, Rule, RuleId};
use snitchhiker_proto::v1;

/// The node's side of the lint: the filesystem as root sees it, and the rules' times from the database.
pub struct Facts {
    /// For each rule: when it was last changed, and when it last decided a connection.
    pub times: HashMap<RuleId, (u64, Option<u64>)>,
}

/// Paths a glob may expand to before the search gives up (a pattern over a huge directory).
const EXPANSION_LIMIT: usize = 4096;

impl NodeFacts for Facts {
    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn writable_by_user(&self, path: &str) -> bool {
        writable_by_user(Path::new(path))
    }

    fn exists_like(&self, glob: &str) -> bool {
        let mut paths = vec![PathBuf::from("/")];
        for segment in glob.trim_start_matches('/').split('/') {
            if segment.is_empty() {
                continue;
            }
            let wild = segment.contains(['*', '?', '{']);
            let pattern = Pattern::compile(&PatternSource::Glob(segment.to_owned())).ok();
            let mut next = Vec::new();
            for path in &paths {
                if !wild {
                    let joined = path.join(segment);
                    if joined.exists() {
                        next.push(joined);
                    }
                    continue;
                }
                let Some(pattern) = &pattern else {
                    return false;
                };
                let Ok(entries) = std::fs::read_dir(path) else {
                    continue;
                };
                for entry in entries.flatten() {
                    if entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| pattern.matches(name, None))
                    {
                        next.push(entry.path());
                    }
                }
            }
            if next.len() > EXPANSION_LIMIT {
                return false;
            }
            paths = next;
            if paths.is_empty() {
                return false;
            }
        }
        true
    }

    fn last_hit_ms(&self, rule: RuleId) -> Option<u64> {
        self.times.get(&rule).and_then(|(_, hit)| *hit)
    }

    fn changed_ms(&self, rule: RuleId) -> Option<u64> {
        self.times.get(&rule).map(|(changed, _)| *changed)
    }
}

/// Whether a user other than root can change the file or put another in its place: the file, or a directory above it,
/// is owned by a user other than root, or writable by a group other than root's or by everyone (a sticky directory
/// lets others replace only their own files).
#[must_use]
pub fn writable_by_user(path: &Path) -> bool {
    let Ok(file) = std::fs::metadata(path) else {
        return false;
    };
    let others_write = |meta: &std::fs::Metadata| {
        let mode = meta.permissions().mode();
        meta.uid() != 0 || (mode & 0o020 != 0 && meta.gid() != 0) || mode & 0o002 != 0
    };
    if others_write(&file) {
        return true;
    }
    path.ancestors().skip(1).any(|dir| {
        std::fs::metadata(dir).is_ok_and(|meta| {
            let sticky = meta.permissions().mode() & 0o1000 != 0;
            meta.uid() != 0 || (!sticky && others_write(&meta))
        })
    })
}

/// Whether a folder and every folder above it is enabled, and their scopes.
fn folder_state(folders: &[Folder], mut next: Option<u64>) -> (bool, Vec<&Condition>) {
    let mut enabled = true;
    let mut scope = Vec::new();
    for _ in 0..=folders.len() {
        let Some(folder) = next.and_then(|id| folders.iter().find(|f| f.id == id)) else {
            break;
        };
        enabled &= folder.enabled;
        scope.extend(folder.scope.iter());
        next = folder.parent;
    }
    (enabled, scope)
}

/// The report over `rules` (the database's, then the managed ones: `locked`), as the protocol has it.
#[must_use]
pub fn report(
    rules: &[Rule],
    managed: &[Rule],
    folders: &[Folder],
    facts: &dyn NodeFacts,
    now_ms: u64,
    unused_days: u32,
) -> Vec<v1::LintFinding> {
    let linted: Vec<Linted<'_>> = rules
        .iter()
        .map(|r| (r, false))
        .chain(managed.iter().map(|r| (r, true)))
        .map(|(rule, locked)| {
            let (folders_enabled, scope) = folder_state(folders, rule.folder);
            Linted {
                rule,
                conditions: rule.conditions.iter().chain(scope).collect(),
                effective: rule.enabled && folders_enabled,
                locked,
            }
        })
        .collect();
    let name = |id: RuleId| {
        rules
            .iter()
            .chain(managed)
            .find(|r| r.id == id)
            .map_or_else(|| format!("rule {id}"), |r| format!("\"{}\"", r.name))
    };
    lint::lint(&linted, facts, now_ms, unused_days)
        .into_iter()
        .map(|finding| {
            let description = match (finding.kind, finding.other) {
                (Kind::Duplicate, Some(other)) => format!("duplicates {}", name(other)),
                (Kind::Redundant, Some(other)) => format!(
                    "{} already matches everything it does, with the same action",
                    name(other)
                ),
                (Kind::Shadowed, Some(other)) => format!("{} always beats it", name(other)),
                (Kind::NeverHit, _) => format!("decided no connection in {unused_days} days"),
                (Kind::Mergeable, Some(other)) => format!(
                    "{} differs from it only in its destinations: one rule would do",
                    name(other)
                ),
                (kind, _) => kind.describe().to_owned(),
            };
            v1::LintFinding {
                kind: kind(finding.kind).into(),
                rule: finding.rule,
                other: finding.other,
                suggestion: finding
                    .suggestion
                    .map_or_else(String::new, |s| s.to_string()),
                description,
                merged: finding.merged.map(|conditions| {
                    Box::new(snitchhiker_proto::convert::conditions(
                        &snitchhiker_core::spec::Conditions::from_conditions(&conditions),
                    ))
                }),
            }
        })
        .collect()
}

fn kind(kind: Kind) -> v1::LintKind {
    match kind {
        Kind::Duplicate => v1::LintKind::Duplicate,
        Kind::Redundant => v1::LintKind::Redundant,
        Kind::Shadowed => v1::LintKind::Shadowed,
        Kind::Expired => v1::LintKind::Expired,
        Kind::NeverHit => v1::LintKind::NeverHit,
        Kind::WritableBinary => v1::LintKind::WritableBinary,
        Kind::MissingBinary => v1::LintKind::MissingBinary,
        Kind::Mergeable => v1::LintKind::Mergeable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_expand_over_the_filesystem() {
        let facts = Facts {
            times: HashMap::new(),
        };
        let dir = std::env::temp_dir().join(format!("snitchhiker-lint-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("versions/2.0.40")).unwrap();
        std::fs::write(dir.join("versions/2.0.40/app"), b"").unwrap();
        let base = dir.to_str().unwrap();
        assert!(facts.exists_like(&format!("{base}/versions/*/app")));
        assert!(!facts.exists_like(&format!("{base}/versions/*/other")));
        assert!(!facts.exists_like(&format!("{base}/nothing/*/app")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_users_file_is_writable_by_a_user() {
        // The test runs as a user (in CI, and here): its own temporary file is theirs.
        let path =
            std::env::temp_dir().join(format!("snitchhiker-writable-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        if std::fs::metadata(&path).unwrap().uid() != 0 {
            assert!(writable_by_user(&path));
        }
        std::fs::remove_file(&path).unwrap();
        assert!(!writable_by_user(Path::new("/nonexistent/binary")));
    }
}
