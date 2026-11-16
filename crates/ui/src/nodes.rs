//! The remote nodes this app knows, and this device's key (plan §8.3).
//!
//! Both are kept in `/var/lib/snitchhiker-ui/<uid>`: the root directory is `root:snitchhiker-ui 1770` (made by the
//! package), so only the app, setgid to that group, can enter it. The key is what a node knows this device by; a
//! program of the user's that read it could connect to the user's nodes as this device, which the local socket's
//! setgid check exists to prevent.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snitchhiker_remote::{Key, NodeAddress};

pub const STATE_ROOT: &str = "/var/lib/snitchhiker-ui";

/// A node paired with this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteNode {
    pub name: String,
    pub id: String,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub addrs: Vec<String>,
}

impl RemoteNode {
    #[must_use]
    pub fn address(&self) -> NodeAddress {
        NodeAddress {
            id: self.id.clone(),
            relays: self.relays.clone(),
            addrs: self.addrs.iter().filter_map(|a| a.parse().ok()).collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Nodes {
    #[serde(default)]
    pub node: Vec<RemoteNode>,
}

/// The user's state directory, made if needed (0700); `None` without the root (an app not installed by its package).
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    snitchhiker_client::cache::own_dir(Path::new(STATE_ROOT), nix::unistd::getuid().as_raw())
}

impl Nodes {
    #[must_use]
    pub fn load() -> Self {
        state_dir()
            .and_then(|dir| std::fs::read_to_string(dir.join("nodes.toml")).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = state_dir().ok_or_else(|| {
            std::io::Error::other("no state directory (the app wasn't installed by its package)")
        })?;
        let text = toml::to_string(self).map_err(std::io::Error::other)?;
        let temporary = dir.join("nodes.toml.new");
        std::fs::write(&temporary, text)?;
        std::fs::rename(temporary, dir.join("nodes.toml"))
    }
}

/// This device's key, made the first time.
pub fn device_key() -> std::io::Result<Key> {
    let dir = state_dir().ok_or_else(|| {
        std::io::Error::other("no state directory (the app wasn't installed by its package)")
    })?;
    Key::load_or_create(&dir.join("device.key"))
}

/// What this device is called when it pairs: the machine's name.
#[must_use]
pub fn device_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map_or_else(|_| "desktop".to_owned(), |name| name.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_round_trip() {
        let nodes = Nodes {
            node: vec![RemoteNode {
                name: "web".to_owned(),
                id: Key::generate().id(),
                relays: vec!["https://relay.example.org/".to_owned()],
                addrs: vec!["192.0.2.1:7842".to_owned(), "nonsense".to_owned()],
            }],
        };
        let text = toml::to_string(&nodes).unwrap();
        let back: Nodes = toml::from_str(&text).unwrap();
        assert_eq!(back.node, nodes.node);
        assert_eq!(back.node[0].address().addrs.len(), 1);
    }
}
