//! The node's bridge (decision 0016): the iroh endpoint devices connect to, beside the daemon, as an unprivileged user
//! of its own. It connects to the daemon's remote socket, says who the node is, and hands over each stream a peer
//! opens, as a file descriptor with the peer's id (which TLS proved): the daemon decides whether the peer is a paired
//! device, and serves it as it serves a local client. The bridge decides nothing.
//!
//! It also does what only the endpoint can: open a stream to the push gateway, offer a pairing code, say where the
//! node is (for a pairing link).

use std::collections::HashMap;
use std::os::fd::AsFd as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use snitchhiker_client::packet::Packets;
use snitchhiker_proto::v1;
use snitchhiker_remote::code::{Code, Offer};
use snitchhiker_remote::{Key, Listener, NodeAddress, Options, PAIR_ALPN, PUSH_ALPN, PairLink};
use tracing::{info, warn};

use crate::config::Config;
use crate::{Error, KEY_CREDENTIAL};

/// The node's key: the sealed one systemd decrypted for the service (`ImportCredential=`), else the file (made if
/// there is none).
fn node_key(config: &Config) -> Result<Key, Error> {
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let sealed = std::path::PathBuf::from(dir).join(KEY_CREDENTIAL);
        if let Ok(bytes) = std::fs::read(&sealed) {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::Key(format!("{}: not a key", sealed.display())))?;
            info!("the node's key is the sealed credential");
            return Ok(Key::from_bytes(&bytes));
        }
    }
    Key::load_or_create(&config.key)
        .map_err(|e| Error::Key(format!("{}: {e}", config.key.display())))
}

fn options(config: &Config) -> Options {
    Options {
        relays: config.relays.clone(),
        port: config.port,
        port_mapping: false,
        lan: config.lan_discovery,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Node {
    daemon: Packets,
    listener: Listener,
    config: Config,
    /// The pairing codes offered, by their pairing's secret.
    offers: Mutex<HashMap<String, Offer>>,
}

impl Node {
    fn send(&self, body: v1::bridge_frame::Body, fd: Option<std::os::fd::BorrowedFd<'_>>) {
        let frame = v1::BridgeFrame { body: Some(body) };
        if let Err(error) = self.daemon.send(&frame, fd) {
            warn!(%error, "writing to the daemon");
        }
    }

    fn reply(
        &self,
        id: u64,
        answer: Result<Option<v1::BridgeOffered>, String>,
        fd: Option<std::os::fd::BorrowedFd<'_>>,
    ) {
        let (error, offered) = match answer {
            Ok(offered) => (String::new(), offered),
            Err(error) => (error, None),
        };
        self.send(
            v1::bridge_frame::Body::Reply(v1::BridgeReply { id, error, offered }),
            fd,
        );
    }

    fn open_gateway(&self, id: u64) {
        if self.config.push_gateway.is_empty() {
            self.reply(id, Err("no push gateway is configured".to_owned()), None);
            return;
        }
        let gateway = NodeAddress {
            id: self.config.push_gateway.clone(),
            relays: self.config.relays.clone(),
            addrs: Vec::new(),
        };
        // The gateway is reached through the relays: once the endpoint has one.
        let _ = self.listener.address();
        match self.listener.open(&gateway, PUSH_ALPN) {
            Ok(stream) => self.reply(id, Ok(None), Some(stream.as_fd())),
            Err(error) => self.reply(id, Err(error.to_string()), None),
        }
    }

    fn offer(self: &Arc<Self>, id: u64, offer: &v1::Offer) {
        let node = self.listener.address();
        let link = PairLink {
            node: node.clone(),
            name: offer.name.clone(),
            secret: offer.secret.clone(),
            role: offer.role.clone(),
        };
        // The code is offered when it can be; the link works without it.
        let code = Code::generate().and_then(|code| {
            let weak = Arc::downgrade(self);
            let secret = offer.secret.clone();
            let opened = Offer::open(
                &code,
                &options(&self.config),
                link.to_string(),
                // On the offer's own runtime: the daemon withdraws it (dropping it here would wait for this task).
                move |right| {
                    if let Some(node) = weak.upgrade() {
                        node.send(
                            v1::bridge_frame::Body::CodeTried(v1::BridgeCodeTried {
                                secret,
                                right,
                            }),
                            None,
                        );
                    }
                },
            )?;
            lock(&self.offers).insert(offer.secret.clone(), opened);
            Ok(code)
        });
        let code = code.map_or_else(
            |error| {
                warn!(%error, "offering a pairing code");
                String::new()
            },
            |code| code.to_string(),
        );
        self.reply(
            id,
            Ok(Some(v1::BridgeOffered {
                link: link.to_string(),
                node_id: node.id,
                code,
            })),
            None,
        );
    }

    fn withdraw(&self, secret: &str) {
        // Dropped with no lock held: closing it waits for its task.
        let offer = lock(&self.offers).remove(secret);
        drop(offer);
    }
}

/// The daemon closed the connection rather than serve this process: it serves one user alone, one service at a time,
/// and says which it refused in its log.
fn refused(error: impl std::fmt::Display) -> Error {
    Error::Daemon(format!(
        "refused ({error}): the daemon serves the snitchhiker-remote user alone, one service at a time"
    ))
}

/// What ended the bridge.
pub enum Ended {
    /// SIGTERM or SIGINT: the daemon was told, and had its say.
    Stopped,
    /// The daemon closed the connection (it stopped, or refused this bridge).
    DaemonGone,
}

/// Runs the bridge until it is stopped or the daemon goes. `stop` is called with a function that ends it gracefully,
/// for the signal thread.
pub fn run(config: Config, on_stop: impl FnOnce(Box<dyn FnOnce() + Send>)) -> Result<Ended, Error> {
    let key = node_key(&config)?;
    let daemon = Packets::connect(&config.socket)
        .map_err(|e| Error::Daemon(format!("{}: {e}", config.socket.display())))?;
    daemon
        .send(
            &v1::BridgeFrame {
                body: Some(v1::bridge_frame::Body::Hello(v1::BridgeHello {
                    node_id: key.id(),
                    push_gateway: !config.push_gateway.is_empty(),
                    offline_after_secs: config.offline_after_secs,
                })),
            },
            None,
        )
        .map_err(refused)?;
    // Served: from now on the daemon lets this process's traffic through undecided.
    match daemon.receive::<v1::NodeFrame>() {
        Ok(Some((
            v1::NodeFrame {
                body: Some(v1::node_frame::Body::Ready(_)),
                ..
            },
            _,
        ))) => {}
        Ok(_) => return Err(refused("the connection closed")),
        Err(error) => return Err(refused(error)),
    }
    let sender = daemon
        .try_clone()
        .map_err(|e| Error::Daemon(e.to_string()))?;
    let listener = Listener::bind(&key, &options(&config), move |accepted| {
        let kind = if accepted.alpn == PAIR_ALPN {
            v1::StreamKind::Pairing
        } else {
            v1::StreamKind::Device
        };
        let frame = v1::BridgeFrame {
            body: Some(v1::bridge_frame::Body::Accepted(v1::BridgeAccepted {
                peer: accepted.peer,
                kind: kind.into(),
            })),
        };
        // The daemon has the stream now; this end's copy closes when `accepted` is dropped.
        if let Err(error) = sender.send(&frame, Some(accepted.stream.as_fd())) {
            warn!(%error, "handing a stream to the daemon");
        }
    })
    .map_err(|e| Error::Endpoint(e.to_string()))?;
    info!(id = %listener.id(), relays = ?config.relays, "remote endpoint started");
    let node = Arc::new(Node {
        daemon,
        listener,
        config,
        offers: Mutex::default(),
    });
    {
        let node = Arc::clone(&node);
        on_stop(Box::new(move || {
            // The daemon says its last word to the gateway; the read loop ends at its answer.
            node.send(v1::bridge_frame::Body::Leaving(v1::BridgeLeaving {}), None);
        }));
    }
    let ended = loop {
        let frame = match node.daemon.receive::<v1::NodeFrame>() {
            Ok(Some((frame, _))) => frame,
            Ok(None) => break Ended::DaemonGone,
            Err(error) => {
                warn!(%error, "reading from the daemon");
                break Ended::DaemonGone;
            }
        };
        let id = frame.id;
        match frame.body {
            Some(v1::node_frame::Body::OpenGateway(_)) => {
                let node = Arc::clone(&node);
                let _ = thread::Builder::new()
                    .name("open-gateway".to_owned())
                    .spawn(move || node.open_gateway(id));
            }
            Some(v1::node_frame::Body::Offer(offer)) => {
                let node = Arc::clone(&node);
                let _ = thread::Builder::new()
                    .name("offer".to_owned())
                    .spawn(move || node.offer(id, &offer));
            }
            Some(v1::node_frame::Body::Withdraw(withdraw)) => node.withdraw(&withdraw.secret),
            Some(v1::node_frame::Body::Left(_)) => break Ended::Stopped,
            Some(v1::node_frame::Body::Ready(_)) | None => {}
        }
    };
    // What the daemon wrote to the gateway last reaches it before the endpoint closes.
    node.listener.finish_opened(Duration::from_secs(5));
    lock(&node.offers).clear();
    Ok(ended)
}
