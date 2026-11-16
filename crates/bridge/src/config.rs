//! `/etc/snitchhiker/remote.toml`: the node's remote endpoint. What devices may do once connected is the daemon's
//! business (`daemon.toml`, the devices it paired); this file says only how the node is reached.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/snitchhiker/remote.toml";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The relays (the user's own `snitchhiker-relay`) the node keeps a connection to, so devices reach it behind NAT.
    /// None: direct connections only.
    pub relays: Vec<String>,
    /// The UDP port of the endpoint (0: any free port).
    pub port: u16,
    /// Announce the node on the local network (mDNS), so devices there find it without a relay, and pairing codes
    /// work there.
    pub lan_discovery: bool,
    /// The push gateway's endpoint id (a `snitchhiker-relay` with `[push]`, reached through `relays`): it wakes the
    /// devices with prompts while they are asleep, and tells them when the node goes offline. Empty: none, devices
    /// learn of prompts only while connected.
    pub push_gateway: String,
    /// How long the node may be gone from its push gateway before its devices are told it is offline (a restart
    /// doesn't make them wonder).
    pub offline_after_secs: u32,
    /// The node's key: made the first time, readable by the service's user only. Once sealed (`snitchhiker-remote
    /// seal-key`), systemd gives it to the service instead, and this file is gone.
    pub key: PathBuf,
    /// The daemon's socket for its remote endpoint.
    pub socket: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            port: 0,
            lan_discovery: true,
            push_gateway: String::new(),
            offline_after_secs: 120,
            key: PathBuf::from("/var/lib/snitchhiker-remote/node.key"),
            socket: PathBuf::from("/run/snitchhiker/remote.sock"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
}

impl Config {
    /// The configuration in `path`; the defaults when there is no file.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(Error::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        toml::from_str(&text).map_err(|source| Error::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_packaged_file_is_the_defaults() {
        let packaged: Config =
            toml::from_str(include_str!("../../../dist/remote/remote.toml")).unwrap();
        assert_eq!(packaged, Config::default());
    }

    #[test]
    fn every_setting_is_documented() {
        let defaults = toml::to_string(&Config::default()).unwrap();
        let table: toml::Table = toml::from_str(&defaults).unwrap();
        let page = include_str!("../../../site/src/content/docs/reference/configuration.mdx");
        let section = page.split("## remote.toml").nth(1).unwrap_or_default();
        let missing: Vec<&String> = table
            .keys()
            .filter(|key| !section.contains(&format!("### `{key}`")))
            .collect();
        assert!(
            missing.is_empty(),
            "settings missing from the configuration page: {missing:?}"
        );
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(toml::from_str::<Config>("relay = []").is_err());
    }
}
