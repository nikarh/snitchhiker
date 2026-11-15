//! Forwarded traffic (plan §5.10): a container on a bridge network, or a VM on a tap, sends packets that are forwarded
//! from its bridge port; they never pass the host's `output` hook. Their sender is found exactly:
//!
//! 1. the packet's link-layer source address, looked up in the bridge's forwarding database, gives the bridge port it
//!    came in through;
//! 2. a veth port names the namespace of its peer (by a namespace id local to this namespace), which is mapped to the
//!    namespace's inode through the processes in it; a tap port is a VM's;
//! 3. the flow is then looked up as its sender recorded it in that namespace: the tuple before NAT, which is what the
//!    forward hook sees.
//!
//! Each step is the kernel's own table. A stale cache can only make the lookup miss (the flow must exist in the
//! namespace it names, with that very tuple), never name the wrong sender; a miss is retried once afresh.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;

use snitchhiker_netfilter::route::{Link, Route};
use tracing::debug;

/// Who sent a forwarded packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    /// A network namespace (a container's), by its inode.
    Netns(u32),
    /// A tap interface (a VM's), by its index.
    Tap(u32),
}

/// The lookups, cached per deciding thread.
#[derive(Default)]
pub struct Senders {
    route: Option<Route>,
    /// Bridge port by (bridge, source address).
    ports: HashMap<(u32, [u8; 6]), u32>,
    links: HashMap<u32, Link>,
    /// Namespace inode by this namespace's id for it.
    namespaces: HashMap<i32, u32>,
}

impl Senders {
    /// The sender of a packet that came in through `bridge` from `mac`; `fresh` skips the caches (after a miss).
    pub fn sender(&mut self, bridge: u32, mac: [u8; 6], fresh: bool) -> Option<Sender> {
        if fresh {
            self.ports.remove(&(bridge, mac));
        }
        let port = if let Some(port) = self.ports.get(&(bridge, mac)) {
            *port
        } else {
            let port = self.route()?.bridge_port(bridge, mac).ok()??;
            self.ports.insert((bridge, mac), port);
            port
        };
        if fresh {
            self.links.remove(&port);
        }
        let link = if let Some(link) = self.links.get(&port) {
            link.clone()
        } else {
            let link = self.route()?.link(port).ok()??;
            self.links.insert(port, link.clone());
            link
        };
        match link.kind.as_deref() {
            Some("tun") => Some(Sender::Tap(port)),
            Some("veth") => {
                let id = link.peer_netns_id?;
                if fresh || !self.namespaces.contains_key(&id) {
                    self.scan_namespaces();
                }
                self.namespaces.get(&id).copied().map(Sender::Netns)
            }
            _ => None,
        }
    }

    fn route(&mut self) -> Option<&mut Route> {
        if self.route.is_none() {
            self.route = Route::open()
                .inspect_err(|error| debug!(%error, "opening a route netlink socket"))
                .ok();
        }
        self.route.as_mut()
    }

    /// Maps the namespace ids this namespace has given to the inodes of the namespaces they name, from one process in
    /// each namespace there is.
    fn scan_namespaces(&mut self) {
        let Ok(processes) = std::fs::read_dir("/proc") else {
            return;
        };
        let mut seen = std::collections::HashSet::new();
        let mut found = HashMap::new();
        for entry in processes.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(inode) = std::fs::metadata(format!("/proc/{pid}/ns/net")).map(|m| m.ino())
            else {
                continue;
            };
            let Ok(inode) = u32::try_from(inode) else {
                continue;
            };
            if !seen.insert(inode) {
                continue;
            }
            if let Some(Ok(Some(id))) = self.route().map(|route| route.netns_id_of_pid(pid)) {
                found.insert(id, inode);
            }
        }
        self.namespaces = found;
    }
}
