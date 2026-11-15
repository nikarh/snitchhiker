//! Rules that aren't edited through Snitchhiker: the built-in System folder, and the files root keeps in
//! `rules.d/` (provisioning: a fleet's baseline from Ansible or cloud-init). They are read at start and on every
//! reload, live only in memory, and are locked: clients can see them, not change them.
//!
//! Their ids are derived from the file and the rule's name, so the history of a rule stays attributed to it across
//! restarts. Bit 62 is set in them, far above any id the database gives out.

use std::path::{Path, PathBuf};

use snitchhiker_core::rule::{Folder, Rule};
use snitchhiker_core::spec::{RuleFile, SpecError};

/// The built-in System folder.
pub const SYSTEM: &str = include_str!("../defaults/system.toml");
/// Ids of managed folders and rules have this bit set.
pub const MANAGED_ID: u64 = 1 << 62;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{file}: {error}")]
    Parse { file: String, error: String },
    #[error("{file}: {error}")]
    Spec { file: String, error: SpecError },
    #[error("reading {dir}: {error}")]
    Read { dir: PathBuf, error: std::io::Error },
}

/// Managed folders and rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Managed {
    pub folders: Vec<Folder>,
    pub rules: Vec<Rule>,
}

/// FNV-1a: a stable hash for ids (the standard library's isn't stable across builds).
fn fnv(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.bytes().chain([0]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn managed_id(parts: &[&str]) -> u64 {
    (fnv(parts) & (MANAGED_ID - 1)) | MANAGED_ID
}

impl Managed {
    /// The System folder (unless switched off) and every `*.toml` in `dir` (if it exists), in name order.
    pub fn load(default_rules: bool, dir: &Path) -> Result<Self, Error> {
        let mut managed = Self::default();
        if default_rules {
            managed.add("system", SYSTEM)?;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(managed),
            Err(error) => {
                return Err(Error::Read {
                    dir: dir.to_owned(),
                    error,
                });
            }
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        files.sort();
        for file in files {
            let name = file.display().to_string();
            let text = std::fs::read_to_string(&file).map_err(|error| Error::Read {
                dir: file.clone(),
                error,
            })?;
            managed.add(&name, &text)?;
        }
        Ok(managed)
    }

    /// Adds one file's folder and rules.
    pub fn add(&mut self, file: &str, text: &str) -> Result<(), Error> {
        let parsed: RuleFile = toml::from_str(text).map_err(|e| Error::Parse {
            file: file.to_owned(),
            error: e.to_string(),
        })?;
        let spec_error = |error| Error::Spec {
            file: file.to_owned(),
            error,
        };
        let folder_name = parsed
            .folder
            .as_ref()
            .map_or_else(|| file.to_owned(), |f| f.name.clone());
        let folder_id = managed_id(&[file, "folder"]);
        let scope = match &parsed.folder {
            Some(folder) => folder.scope.to_conditions().map_err(spec_error)?,
            None => Vec::new(),
        };
        self.folders.push(Folder {
            id: folder_id,
            parent: None,
            name: folder_name,
            enabled: true,
            scope,
        });
        for spec in &parsed.rule {
            let rule = spec
                .to_rule(managed_id(&[file, &spec.name]), Some(folder_id))
                .map_err(spec_error)?;
            self.rules.push(rule);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_folder_parses() {
        let managed = Managed::load(true, Path::new("/nonexistent")).unwrap();
        assert_eq!(managed.folders.len(), 1);
        assert_eq!(managed.folders[0].name, "System");
        assert!(managed.rules.iter().all(|r| r.id & MANAGED_ID != 0));
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        let text = "[[rule]]\nname = \"a\"\naction = \"allow\"\nport = [\"1\"]\n[[rule]]\nname = \"b\"\naction = \"deny\"\nport = [\"2\"]\n";
        let mut first = Managed::default();
        first.add("x.toml", text).unwrap();
        let mut second = Managed::default();
        second.add("x.toml", text).unwrap();
        assert_eq!(first, second);
        assert_ne!(first.rules[0].id, first.rules[1].id);
        let mut other = Managed::default();
        other.add("y.toml", text).unwrap();
        assert_ne!(first.rules[0].id, other.rules[0].id);
    }

    #[test]
    fn switching_defaults_off_leaves_nothing() {
        assert_eq!(
            Managed::load(false, Path::new("/nonexistent")).unwrap(),
            Managed::default()
        );
    }

    #[test]
    fn errors_name_the_file() {
        let mut managed = Managed::default();
        let error = managed
            .add("bad.toml", "[[rule]]\nname = \"x\"\naction = \"allow\"\n")
            .unwrap_err();
        assert!(error.to_string().starts_with("bad.toml:"));
    }
}
