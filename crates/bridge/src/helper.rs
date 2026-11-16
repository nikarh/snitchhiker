//! `snitchhiker-remote client`: the desktop app's way to remote nodes (decision 0016). The app starts it with one end
//! of a socket pair as its standard input, gives it this device's key, and asks it for streams to its nodes and for
//! pairings. Each stream comes back as a file descriptor; the app speaks the client protocol on it as on its local
//! socket.
//!
//! The device's key is what nodes know the device by, so no other program of the user's may read it: the app is
//! setgid for that, and this helper makes itself undumpable (no ptrace, no core dumps, /proc/<pid>/mem closed to the
//! user) before it is given the key, and refuses to go on if something attached before that.

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;
use std::thread;

use snitchhiker_client::packet::Packets;
use snitchhiker_proto::v1;
use snitchhiker_remote::code::Code;
use snitchhiker_remote::{ALPN, Key, NodeAddress, Options, PairLink};

use crate::Error;

/// Whether a tracer is attached to this process.
fn traced() -> Result<bool, Error> {
    let status =
        std::fs::read_to_string("/proc/self/status").map_err(|e| Error::Helper(e.to_string()))?;
    let tracer = status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .map(str::trim)
        .ok_or_else(|| Error::Helper("no TracerPid in /proc/self/status".to_owned()))?;
    Ok(tracer != "0")
}

fn address(node: &v1::NodeAddress) -> NodeAddress {
    NodeAddress {
        id: node.id.clone(),
        relays: node.relays.clone(),
        addrs: node.addrs.iter().filter_map(|a| a.parse().ok()).collect(),
    }
}

fn wire(node: &NodeAddress) -> v1::NodeAddress {
    v1::NodeAddress {
        id: node.id.clone(),
        relays: node.relays.clone(),
        addrs: node.addrs.iter().map(ToString::to_string).collect(),
    }
}

struct Helper {
    app: Packets,
    key: Key,
}

impl Helper {
    fn reply(
        &self,
        id: u64,
        answer: Result<Option<v1::HelperPaired>, String>,
        fd: Option<std::os::fd::BorrowedFd<'_>>,
    ) {
        let (error, paired) = match answer {
            Ok(paired) => (String::new(), paired),
            Err(error) => (error, None),
        };
        let _ = self.app.send(&v1::HelperReply { id, error, paired }, fd);
    }

    fn connect(&self, id: u64, node: &v1::NodeAddress) {
        // The node's relays (from its address), and its address looked up on the local network too.
        let options = Options {
            lan: true,
            ..Options::default()
        };
        match snitchhiker_remote::connect(&self.key, &address(node), &options, ALPN) {
            // The endpoint stays (one per process and key); the stream is the app's now.
            Ok(connected) => self.reply(id, Ok(None), Some(connected.stream.as_fd())),
            Err(error) => self.reply(id, Err(error.to_string()), None),
        }
    }

    fn pair(&self, id: u64, pair: &v1::HelperPair) {
        let answer = (|| {
            // A link, or a code to look up nearby or through the relays of the nodes already known.
            let target: Result<PairLink, Code> = match pair.text.parse() {
                Ok(link) => Ok(link),
                Err(error) => Err(pair
                    .text
                    .parse::<Code>()
                    .map_err(|_| format!("{error}, nor a pairing code"))?),
            };
            let options = Options {
                relays: pair.relays.clone(),
                lan: true,
                ..Options::default()
            };
            let (link, response) = match target {
                Ok(link) => {
                    let response = snitchhiker_client::remote::pair(
                        &self.key,
                        &link,
                        &pair.device_name,
                        &options,
                    )
                    .map_err(|e| e.to_string())?;
                    (link, response)
                }
                Err(code) => snitchhiker_client::remote::pair_with_code(
                    &self.key,
                    &code,
                    &pair.device_name,
                    &options,
                )
                .map_err(|e| e.to_string())?,
            };
            Ok(Some(v1::HelperPaired {
                node: Some(wire(&link.node)),
                name: link.name,
                response: Some(response),
            }))
        })();
        self.reply(id, answer, None);
    }
}

/// Serves the app on standard input until it closes its end.
pub fn run() -> Result<(), Error> {
    nix::sys::prctl::set_dumpable(false).map_err(|e| Error::Helper(e.to_string()))?;
    if traced()? {
        return Err(Error::Helper(
            "something is tracing this process: no key for it".to_owned(),
        ));
    }
    let stdin: OwnedFd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| Error::Helper(e.to_string()))?;
    let app = Packets::from_fd(stdin);
    let key = match app.receive::<v1::HelperRequest>() {
        Ok(Some((
            v1::HelperRequest {
                body: Some(v1::helper_request::Body::Start(start)),
                ..
            },
            _,
        ))) => {
            let bytes: [u8; 32] = start
                .key
                .try_into()
                .map_err(|_| Error::Helper("the key isn't 32 bytes".to_owned()))?;
            Key::from_bytes(&bytes)
        }
        Ok(None) => return Ok(()),
        Ok(Some(_)) => {
            return Err(Error::Helper(
                "the app didn't start with the key".to_owned(),
            ));
        }
        Err(error) => return Err(Error::Helper(error.to_string())),
    };
    let helper = Arc::new(Helper { app, key });
    loop {
        let request = match helper.app.receive::<v1::HelperRequest>() {
            Ok(Some((request, _))) => request,
            Ok(None) => return Ok(()),
            Err(error) => return Err(Error::Helper(error.to_string())),
        };
        let id = request.id;
        let helper = Arc::clone(&helper);
        let _ = match request.body {
            Some(v1::helper_request::Body::Connect(connect)) => thread::Builder::new()
                .name("connect".to_owned())
                .spawn(move || helper.connect(id, &connect.node.unwrap_or_default())),
            Some(v1::helper_request::Body::Pair(pair)) => thread::Builder::new()
                .name("pair".to_owned())
                .spawn(move || helper.pair(id, &pair)),
            Some(v1::helper_request::Body::Start(_)) | None => continue,
        };
    }
}
