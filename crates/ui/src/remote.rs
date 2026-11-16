//! Remote nodes, through `snitchhiker-remote client` (decision 0016): the network stack is that helper's, installed
//! with the `snitchhiker-remote` package only where remote nodes are wanted. The app starts it once, gives it this
//! device's key over a socket pair (never its command line or environment), and asks it for a stream to each node and
//! for pairings; each stream comes back as a file descriptor, on which the app speaks the client protocol as on its
//! local socket.
//!
//! The helper is started by its full path, never looked up in `PATH`: the app is setgid, and a program of the user's
//! named `snitchhiker-remote` earlier in the path would be handed the key.

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use snitchhiker_client::packet::Packets;
use snitchhiker_proto::v1;

use crate::nodes::RemoteNode;

/// The helper, as its package installs it.
pub const HELPER: &str = "/usr/bin/snitchhiker-remote";

/// What the app says when the helper isn't there.
pub const NOT_INSTALLED: &str =
    "Remote nodes need the snitchhiker-remote package: install it, then try again.";

/// How long a connection or a pairing may take (the helper gives up on a node after 20 seconds).
const ANSWER: Duration = Duration::from_secs(45);

type Answer = (v1::HelperReply, Option<OwnedFd>);

struct Helper {
    packets: Packets,
    child: Mutex<Child>,
    waiting: Mutex<HashMap<u64, Sender<Answer>>>,
    next: AtomicU64,
    /// The key it was started with.
    key: [u8; 32],
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Its end of the socket closes with this one: it exits by itself; reaped here.
        self.packets.shutdown();
        let _ = lock(&self.child).wait();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The running helper.
fn slot() -> &'static Mutex<Option<Arc<Helper>>> {
    static RUNNING: Mutex<Option<Arc<Helper>>> = Mutex::new(None);
    &RUNNING
}

/// Whether the helper is installed.
#[must_use]
pub fn installed() -> bool {
    std::path::Path::new(HELPER).exists()
}

/// The helper for `key`: the running one, or a new one.
fn helper(key: &[u8; 32]) -> Result<Arc<Helper>, String> {
    let mut running = lock(slot());
    if let Some(helper) = running.as_ref()
        && helper.key == *key
    {
        return Ok(Arc::clone(helper));
    }
    let (ours, theirs) = Packets::pair().map_err(|e| e.to_string())?;
    let child = Command::new(HELPER)
        .arg("client")
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .env_clear()
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                NOT_INSTALLED.to_owned()
            } else {
                format!("starting {HELPER}: {error}")
            }
        })?;
    let start = v1::HelperRequest {
        id: 0,
        body: Some(v1::helper_request::Body::Start(v1::HelperStart {
            key: key.to_vec(),
        })),
    };
    ours.send(&start, None).map_err(|e| e.to_string())?;
    let reader = ours.try_clone().map_err(|e| e.to_string())?;
    let helper = Arc::new(Helper {
        packets: ours,
        child: Mutex::new(child),
        waiting: Mutex::default(),
        next: AtomicU64::new(1),
        key: *key,
    });
    let weak = Arc::downgrade(&helper);
    std::thread::Builder::new()
        .name("remote-helper".to_owned())
        .spawn(move || {
            while let Ok(Some((reply, fd))) = reader.receive::<v1::HelperReply>() {
                let Some(helper) = weak.upgrade() else {
                    return;
                };
                if let Some(waiting) = lock(&helper.waiting).remove(&reply.id) {
                    let _ = waiting.send((reply, fd));
                }
            }
            // It exited: the next request starts another; those waiting get no answer.
            let Some(helper) = weak.upgrade() else {
                return;
            };
            lock(&helper.waiting).clear();
            let mut running = lock(slot());
            if running.as_ref().is_some_and(|r| Arc::ptr_eq(r, &helper)) {
                running.take();
            }
        })
        .map_err(|e| e.to_string())?;
    *running = Some(Arc::clone(&helper));
    Ok(helper)
}

fn ask(key: &[u8; 32], body: v1::helper_request::Body) -> Result<Answer, String> {
    let helper = helper(key)?;
    let id = helper.next.fetch_add(1, Ordering::Relaxed);
    let (sender, answer) = channel();
    lock(&helper.waiting).insert(id, sender);
    let request = v1::HelperRequest {
        id,
        body: Some(body),
    };
    if let Err(error) = helper.packets.send(&request, None) {
        lock(&helper.waiting).remove(&id);
        return Err(format!("the remote helper: {error}"));
    }
    let answer = answer.recv_timeout(ANSWER);
    lock(&helper.waiting).remove(&id);
    let (reply, fd) = answer.map_err(|_| "the remote helper didn't answer".to_owned())?;
    if reply.error.is_empty() {
        Ok((reply, fd))
    } else {
        Err(reply.error)
    }
}

fn wire(node: &RemoteNode) -> v1::NodeAddress {
    v1::NodeAddress {
        id: node.id.clone(),
        relays: node.relays.clone(),
        addrs: node.addrs.clone(),
    }
}

/// A stream to `node`, as this device.
pub fn connect(key: &[u8; 32], node: &RemoteNode) -> Result<UnixStream, String> {
    let (_, fd) = ask(
        key,
        v1::helper_request::Body::Connect(v1::HelperConnect {
            node: Some(wire(node)),
        }),
    )?;
    fd.map(UnixStream::from)
        .ok_or_else(|| "the remote helper sent no stream".to_owned())
}

/// Pairs this device (called `device_name`) by a link or a code (looked up nearby or through `relays`): the node,
/// as this app keeps it, and its role for this device.
pub fn pair(
    key: &[u8; 32],
    text: &str,
    device_name: &str,
    relays: Vec<String>,
) -> Result<RemoteNode, String> {
    let (reply, _) = ask(
        key,
        v1::helper_request::Body::Pair(v1::HelperPair {
            text: text.trim().to_owned(),
            device_name: device_name.to_owned(),
            relays,
        }),
    )?;
    let paired = reply.paired.unwrap_or_default();
    let node = paired.node.unwrap_or_default();
    let response = paired.response.unwrap_or_default();
    Ok(RemoteNode {
        name: if response.node_name.is_empty() {
            paired.name
        } else {
            response.node_name
        },
        id: node.id,
        relays: node.relays,
        addrs: node.addrs,
    })
}
