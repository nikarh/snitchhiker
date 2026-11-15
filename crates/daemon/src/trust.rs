//! The trusted-client registry: the client binaries root registered with `snitchhikerd trust-client`, each pinned to
//! its SHA-256.
//!
//! It is a file next to the database (`trusted-clients.toml`), so packages can register their client from an install
//! hook whether or not the daemon runs. The daemon reads it whenever a client connects: a change applies to the next
//! connection, with nothing to reload. The paths in `trusted_clients` of daemon.toml are trusted too, by path alone.

use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::peer::{ClientPolicy, Refusal, TrustedExe, root_owned_and_unwritable, sha256};

/// The registry's file name, in the database's directory.
pub const FILE_NAME: &str = "trusted-clients.toml";

/// The setgid bit.
const SET_GID: u32 = 0o2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: PathBuf,
    /// Lowercase hex.
    pub sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    #[serde(default, rename = "client", skip_serializing_if = "Vec::is_empty")]
    clients: Vec<Entry>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("{0}: a path from the root is needed")]
    Relative(PathBuf),
    #[error("{0}")]
    Unsafe(Refusal),
    #[error("{path}: not setgid to the client group `{group}` (install it root:{group} 2755)")]
    NotSetgid { path: PathBuf, group: String },
    #[error("the client group `{0}` doesn't exist")]
    NoGroup(String),
}

/// Where the registry of `config` is.
#[must_use]
pub fn registry_path(config: &Config) -> PathBuf {
    config
        .database
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join(FILE_NAME)
}

/// The registered clients; none when there is no registry yet.
pub fn load(path: &Path) -> Result<Vec<Entry>, Error> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    let registry: Registry = toml::from_str(&text).map_err(|e| Error::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })?;
    for entry in &registry.clients {
        if parse_hex(&entry.sha256).is_none() {
            return Err(Error::Parse {
                path: path.to_owned(),
                message: format!("{}: sha256 isn't 64 hex digits", entry.path.display()),
            });
        }
    }
    Ok(registry.clients)
}

/// Writes the registry whole (a new file renamed over the old one), readable by root only.
fn save(path: &Path, clients: Vec<Entry>) -> Result<(), Error> {
    let io = |source| Error::Io {
        path: path.to_owned(),
        source,
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    let text = format!(
        "# Client binaries trusted on the client socket, each pinned to its SHA-256. Written by\n\
         # `snitchhikerd trust-client` and `untrust-client`; don't edit.\n\n{}",
        toml::to_string(&Registry { clients }).map_err(|e| Error::Parse {
            path: path.to_owned(),
            message: e.to_string(),
        })?
    );
    let partial = path.with_extension("toml.new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&partial)
        .map_err(io)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(io)?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(io)?;
    fs::rename(&partial, path).map_err(io)
}

/// Registers the binary at `exe` (or registers it again, after an upgrade): it must be root's, in directories only
/// root may write, and setgid to the client group.
pub fn trust(config: &Config, exe: &Path) -> Result<Entry, Error> {
    if !exe.is_absolute() {
        return Err(Error::Relative(exe.to_owned()));
    }
    root_owned_and_unwritable(exe).map_err(Error::Unsafe)?;
    let group = crate::api::group_id(&config.client_group)
        .ok_or_else(|| Error::NoGroup(config.client_group.clone()))?;
    let io = |source| Error::Io {
        path: exe.to_owned(),
        source,
    };
    let mut file = fs::File::open(exe).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || meta.mode() & SET_GID == 0 || meta.gid() != group {
        return Err(Error::NotSetgid {
            path: exe.to_owned(),
            group: config.client_group.clone(),
        });
    }
    let entry = Entry {
        path: exe.to_owned(),
        sha256: to_hex(&sha256(&mut file).map_err(io)?),
    };
    let registry = registry_path(config);
    let mut clients = load(&registry)?;
    clients.retain(|e| e.path != exe);
    clients.push(entry.clone());
    clients.sort_by(|a, b| a.path.cmp(&b.path));
    save(&registry, clients)?;
    Ok(entry)
}

/// Removes `exe` from the registry; whether it was there.
pub fn untrust(config: &Config, exe: &Path) -> Result<bool, Error> {
    let registry = registry_path(config);
    let mut clients = load(&registry)?;
    let before = clients.len();
    clients.retain(|e| e.path != exe);
    if clients.len() == before {
        return Ok(false);
    }
    save(&registry, clients)?;
    Ok(true)
}

/// Who may use the client socket now: the registered binaries, pinned to their digests, and the paths of
/// `trusted_clients` in daemon.toml.
pub fn policy(config: &Config, group: u32) -> Result<ClientPolicy, Error> {
    let registered = load(&registry_path(config))?;
    let mut trusted: Vec<TrustedExe> = registered
        .into_iter()
        .map(|entry| TrustedExe {
            sha256: parse_hex(&entry.sha256),
            path: entry.path,
        })
        .collect();
    for path in &config.trusted_clients {
        if !trusted.iter().any(|t| &t.path == path) {
            trusted.push(TrustedExe {
                path: path.clone(),
                sha256: None,
            });
        }
    }
    Ok(ClientPolicy { group, trusted })
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn parse_hex(text: &str) -> Option<[u8; 32]> {
    let mut out = [0_u8; 32];
    if text.len() != 64 {
        return None;
    }
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: [u8; 32] = std::array::from_fn(|i| u8::try_from(i * 7).unwrap());
        assert_eq!(parse_hex(&to_hex(&bytes)), Some(bytes));
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex(&"zz".repeat(32)), None);
    }

    #[test]
    fn registry_round_trips_and_policy_merges_the_config() {
        let dir = std::env::temp_dir().join(format!("snitchhiker-trust-{}", std::process::id()));
        let config = Config {
            database: dir.join("state.db"),
            trusted_clients: vec![PathBuf::from("/usr/bin/a"), PathBuf::from("/usr/bin/b")],
            ..Config::default()
        };
        let registry = registry_path(&config);
        assert_eq!(load(&registry).unwrap(), Vec::new());
        save(
            &registry,
            vec![Entry {
                path: PathBuf::from("/usr/bin/a"),
                sha256: "ab".repeat(32),
            }],
        )
        .unwrap();
        let policy = policy(&config, 977).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(policy.trusted.len(), 2);
        assert_eq!(policy.trusted[0].sha256, Some([0xab; 32]));
        assert_eq!(policy.trusted[1].path, PathBuf::from("/usr/bin/b"));
        assert_eq!(policy.trusted[1].sha256, None);
    }

    #[test]
    fn untrusted_binaries_cant_be_registered() {
        let config = Config::default();
        assert!(matches!(
            trust(&config, Path::new("relative")),
            Err(Error::Relative(_))
        ));
        // Not setgid to any client group (and, on a development machine, not in root's directories either).
        assert!(trust(&config, Path::new("/usr/bin/env")).is_err());
    }
}
