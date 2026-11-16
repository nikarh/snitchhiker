//! Snitchhiker's remote transport (plan §8.2): the client protocol over iroh, QUIC between Ed25519 keys, direct
//! where a path is found (hole punching, port mapping) and through the user's own relays otherwise.
//!
//! The node and the clients speak the protocol on blocking sockets and threads; iroh is async. Each QUIC stream is
//! therefore bridged to one end of a Unix socket pair by a task on a small tokio runtime of its own, and the other end
//! is what the protocol code reads and writes: a remote connection is served exactly like a local one.

use std::io;
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::str::FromStr as _;
use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, RelayUrl, SecretKey, TransportAddr};

pub mod code;

/// The protocol's ALPN: major version 1.
pub const ALPN: &[u8] = b"snitchhiker/1";
/// Pairing a device with a one-time secret (a link or a QR code).
pub const PAIR_ALPN: &[u8] = b"snitchhiker-pair/1";
/// A node's connection to its push gateway (plan §8.5): who to wake, and the node's presence.
pub const PUSH_ALPN: &[u8] = b"snitchhiker-push/1";

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

/// A node's or a device's key: its identity on the network.
#[derive(Clone)]
pub struct Key(SecretKey);

impl Key {
    #[must_use]
    pub fn generate() -> Self {
        Self(SecretKey::generate())
    }

    /// The key in `path`, made (readable by its owner only) if there is none.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        match std::fs::read(path) {
            Ok(bytes) => {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| other(format!("{}: not a key", path.display())))?;
                Ok(Self(SecretKey::from_bytes(&bytes)))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let key = Self::generate();
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?;
                file.write_all(&key.0.to_bytes())?;
                file.sync_all()?;
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }

    /// A key from its 32 bytes (as stored elsewhere: an app's keystore).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SecretKey::from_bytes(bytes))
    }

    /// The key's 32 bytes, to store it elsewhere.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public id others know it by.
    #[must_use]
    pub fn id(&self) -> String {
        self.0.public().to_string()
    }
}

/// Where a node is: its id, its relays and the addresses it was last seen at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeAddress {
    pub id: String,
    pub relays: Vec<String>,
    pub addrs: Vec<SocketAddr>,
}

impl NodeAddress {
    fn endpoint_addr(&self) -> io::Result<EndpointAddr> {
        let id = PublicKey::from_str(&self.id).map_err(|e| other(format!("node id: {e}")))?;
        let mut addrs = Vec::new();
        for relay in &self.relays {
            addrs.push(TransportAddr::Relay(
                RelayUrl::from_str(relay).map_err(|e| other(format!("relay {relay}: {e}")))?,
            ));
        }
        addrs.extend(self.addrs.iter().map(|a| TransportAddr::Ip(*a)));
        Ok(EndpointAddr::from_parts(id, addrs))
    }
}

fn relay_mode(relays: &[String]) -> io::Result<RelayMode> {
    if relays.is_empty() {
        return Ok(RelayMode::Disabled);
    }
    let urls = relays
        .iter()
        .map(|r| RelayUrl::from_str(r).map_err(|e| other(format!("relay {r}: {e}"))))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(RelayMode::custom(urls))
}

fn runtime(name: &str) -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(name)
        .enable_all()
        .build()
}

/// Copies between a QUIC stream and the near end of a socket pair until either side ends.
async fn bridge(
    mut send: iroh::endpoint::SendStream,
    mut receive: iroh::endpoint::RecvStream,
    near: UnixStream,
) -> io::Result<()> {
    near.set_nonblocking(true)?;
    let near = tokio::net::UnixStream::from_std(near)?;
    let (mut read, mut write) = near.into_split();
    let upstream = async {
        let copied = tokio::io::copy(&mut read, &mut send).await;
        let _ = send.finish();
        // Until the peer has all of it: the connection may be closed right after, which would drop data in flight.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), send.stopped()).await;
        copied
    };
    let downstream = async {
        let copied = tokio::io::copy(&mut receive, &mut write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut write).await;
        copied
    };
    // Either direction ending ends the connection: the protocol is one exchange in both directions.
    tokio::select! {
        _ = upstream => {}
        _ = downstream => {}
    }
    Ok(())
}

/// A connection a node accepted: who it is (the peer's id, which TLS proved), what it asked for (the ALPN), and the
/// local end of its stream.
pub struct Accepted {
    pub peer: String,
    pub alpn: Vec<u8>,
    pub stream: UnixStream,
}

/// How an endpoint is set up.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Relay URLs (the user's own); none: direct connections only.
    pub relays: Vec<String>,
    /// The UDP port to bind (0: any).
    pub port: u16,
    /// Ask the gateway for a port mapping (`UPnP`, NAT-PMP, PCP), for direct connections from outside.
    pub port_mapping: bool,
    /// Find and be found on the local network (mDNS): a node announces itself, a client looks nodes up there.
    pub lan: bool,
}

/// How often an idle connection says it is alive: a node and its devices stay connected for hours with nothing to
/// say, and a connection silent for longer than QUIC's idle timeout is dropped (by it, or by a NAT in between).
const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(10);

fn builder(key: &Key, options: &Options) -> io::Result<iroh::endpoint::Builder> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(key.0.clone())
        .transport_config(
            iroh::endpoint::QuicTransportConfig::builder()
                .keep_alive_interval(KEEP_ALIVE)
                .build(),
        )
        .relay_mode(relay_mode(&options.relays)?)
        .portmapper_config(if options.port_mapping {
            iroh::endpoint::PortmapperConfig::default()
        } else {
            iroh::endpoint::PortmapperConfig::Disabled
        });
    if options.lan {
        builder = builder.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
    }
    if options.port != 0 {
        builder = builder
            .clear_ip_transports()
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], options.port)))
            .map_err(other)?
            .bind_addr(SocketAddr::from((
                std::net::Ipv6Addr::UNSPECIFIED,
                options.port,
            )))
            .map_err(other)?;
    }
    Ok(builder)
}

/// A node's endpoint, accepting connections until dropped.
pub struct Listener {
    endpoint: Endpoint,
    runtime: tokio::runtime::Runtime,
    /// The streams this endpoint opened, until each has ended.
    opened: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Listener {
    /// Binds the node's endpoint, and hands each accepted stream to `accept`, which runs on the runtime's threads: it
    /// must return quickly (starting a thread to serve it).
    pub fn bind(
        key: &Key,
        options: &Options,
        accept: impl Fn(Accepted) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::bind_for(key, options, &[ALPN, PAIR_ALPN], accept)
    }

    /// Binds an endpoint accepting `alpns` (a node's are [`ALPN`] and [`PAIR_ALPN`]).
    pub fn bind_for(
        key: &Key,
        options: &Options,
        alpns: &[&[u8]],
        accept: impl Fn(Accepted) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let runtime = runtime("remote")?;
        let accept = Arc::new(accept);
        let alpns = alpns.iter().map(|alpn| alpn.to_vec()).collect();
        let endpoint = runtime.block_on(async {
            builder(key, options)?
                .alpns(alpns)
                .bind()
                .await
                .map_err(other)
        })?;
        {
            let endpoint = endpoint.clone();
            runtime.spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let accept = Arc::clone(&accept);
                    tokio::spawn(async move {
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        let peer = connection.remote_id().to_string();
                        let alpn = connection.alpn().to_vec();
                        while let Ok((send, receive)) = connection.accept_bi().await {
                            let Ok((near, far)) = UnixStream::pair() else {
                                return;
                            };
                            accept(Accepted {
                                peer: peer.clone(),
                                alpn: alpn.clone(),
                                stream: far,
                            });
                            tokio::spawn(bridge(send, receive, near));
                        }
                    });
                }
            });
        }
        Ok(Self {
            endpoint,
            runtime,
            opened: std::sync::Mutex::default(),
        })
    }

    /// The node's id.
    #[must_use]
    pub fn id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// Where the node can be reached now: its relays and direct addresses (waiting up to a few seconds for them).
    #[must_use]
    pub fn address(&self) -> NodeAddress {
        let addr = self.runtime.block_on(async {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), self.endpoint.online())
                .await;
            self.endpoint.addr()
        });
        NodeAddress {
            id: addr.id.to_string(),
            relays: addr.relay_urls().map(ToString::to_string).collect(),
            addrs: addr.ip_addrs().copied().collect(),
        }
    }
}

impl Listener {
    /// Opens a stream to `peer` for `alpn` from this endpoint: a node dials out with the key it listens with, on the
    /// endpoint it listens on (one key, one endpoint). A connection of its own, closed when the stream ends.
    pub fn open(&self, peer: &NodeAddress, alpn: &[u8]) -> io::Result<UnixStream> {
        let addr = peer.endpoint_addr()?;
        let endpoint = self.endpoint.clone();
        let (stream, task) = self.runtime.block_on(async move {
            let connection = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                endpoint.connect(addr, alpn),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the peer didn't answer"))?
            .map_err(other)?;
            let (send, receive) = connection.open_bi().await.map_err(other)?;
            let (near, far) = UnixStream::pair()?;
            let task = tokio::spawn(async move {
                let _ = bridge(send, receive, near).await;
                connection.close(0_u32.into(), b"done");
            });
            Ok::<_, io::Error>((far, task))
        })?;
        let mut opened = self
            .opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        opened.retain(|task| !task.is_finished());
        opened.push(task);
        Ok(stream)
    }

    /// Waits, up to `wait`, for the streams this endpoint opened to end and their last bytes to reach the peer: what
    /// was written to one just before stopping (a node's last word to its push gateway) isn't cut off.
    pub fn finish_opened(&self, wait: std::time::Duration) {
        let tasks: Vec<_> = self
            .opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        self.runtime.block_on(async move {
            let _ = tokio::time::timeout(wait, async move {
                for task in tasks {
                    let _ = task.await;
                }
            })
            .await;
        });
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        self.runtime.block_on(async move { endpoint.close().await });
    }
}

/// A connection to a node: the local end of its stream, and what keeps it open.
pub struct Connected {
    pub stream: UnixStream,
    /// Dropped with the connection: the endpoint and its runtime.
    pub keep: Box<dyn Send>,
}

/// A device's endpoint, shared by all its connections: one key may be on one endpoint only (a relay routes by key, so
/// a second endpoint with the same key takes the first one's traffic). Each node gets one QUIC connection, and each
/// protocol connection a stream of its own on it.
struct Dialer {
    endpoint: Endpoint,
    runtime: tokio::runtime::Runtime,
    connections:
        std::sync::Mutex<std::collections::HashMap<(String, Vec<u8>), iroh::endpoint::Connection>>,
}

/// A dialer's identity: the key and the options (relays, LAN lookup).
type DialerId = ([u8; 32], Vec<String>, bool);
type Dialers = std::sync::Mutex<std::collections::HashMap<DialerId, Arc<Dialer>>>;

/// The dialers of this process.
fn dialers() -> &'static Dialers {
    static DIALERS: std::sync::OnceLock<Dialers> = std::sync::OnceLock::new();
    DIALERS.get_or_init(std::sync::Mutex::default)
}

fn dialer(key: &Key, options: &Options) -> io::Result<Arc<Dialer>> {
    let mut relays = options.relays.clone();
    relays.sort();
    let id = (key.to_bytes(), relays, options.lan);
    let mut all = dialers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(dialer) = all.get(&id) {
        return Ok(Arc::clone(dialer));
    }
    let runtime = runtime("remote-client")?;
    let endpoint =
        runtime.block_on(async { builder(key, options)?.bind().await.map_err(other) })?;
    let dialer = Arc::new(Dialer {
        endpoint,
        runtime,
        connections: std::sync::Mutex::default(),
    });
    all.insert(id, Arc::clone(&dialer));
    Ok(dialer)
}

/// Connects to `node` as `key`, for `alpn`; one stream. Without relays of its own in `options`, the client uses the
/// node's.
pub fn connect(
    key: &Key,
    node: &NodeAddress,
    options: &Options,
    alpn: &[u8],
) -> io::Result<Connected> {
    let addr = node.endpoint_addr()?;
    let mut options = options.clone();
    if options.relays.is_empty() {
        options.relays.clone_from(&node.relays);
    }
    let dialer = dialer(key, &options)?;
    let shared = Arc::clone(&dialer);
    let stream = dialer.runtime.block_on(async move {
        let id = (node.id.clone(), alpn.to_vec());
        let open = shared
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .filter(|c| c.close_reason().is_none())
            .cloned();
        let connection = if let Some(connection) = open {
            connection
        } else {
            let connection = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                shared.endpoint.connect(addr, alpn),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the node didn't answer"))?
            .map_err(other)?;
            shared
                .connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id.clone(), connection.clone());
            connection
        };
        // A connection that died unnoticed opens no stream: it is forgotten, for the next attempt to dial afresh.
        let opened =
            tokio::time::timeout(std::time::Duration::from_secs(10), connection.open_bi()).await;
        let Ok(Ok((send, receive))) = opened else {
            connection.close(0_u32.into(), b"unresponsive");
            shared
                .connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the node didn't answer",
            ));
        };
        let (near, far) = UnixStream::pair()?;
        tokio::spawn(async move {
            let _ = bridge(send, receive, near).await;
        });
        Ok::<_, io::Error>(far)
    })?;
    Ok(Connected {
        stream,
        keep: Box::new(dialer),
    })
}

/// A pairing link (plan §8.3): the node's address and name, a one-time secret, and the role the device gets.
///
/// `snitchhiker://pair?v=1&node=<id>&name=<name>&relays=<url,…>&addrs=<addr,…>&secret=<base32>&role=<role>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairLink {
    pub node: NodeAddress,
    pub name: String,
    pub secret: String,
    pub role: String,
}

const SCHEME: &str = "snitchhiker://pair?";

/// Percent-encodes everything but unreserved characters.
fn encode(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn decode(text: &str) -> Option<String> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hex = [bytes.next()?, bytes.next()?];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else if byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
}

impl std::fmt::Display for PairLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let list = |items: Vec<String>| {
            items
                .iter()
                .map(|i| encode(i))
                .collect::<Vec<_>>()
                .join(",")
        };
        write!(
            f,
            "{SCHEME}v=1&node={}&name={}&relays={}&addrs={}&secret={}&role={}",
            encode(&self.node.id),
            encode(&self.name),
            list(self.node.relays.clone()),
            list(self.node.addrs.iter().map(ToString::to_string).collect()),
            encode(&self.secret),
            encode(&self.role),
        )
    }
}

impl std::str::FromStr for PairLink {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let query = text
            .trim()
            .strip_prefix(SCHEME)
            .ok_or("not a Snitchhiker pairing link")?;
        let mut link = Self {
            node: NodeAddress::default(),
            name: String::new(),
            secret: String::new(),
            role: String::new(),
        };
        let mut version = None;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let list = || -> Option<Vec<String>> {
                value
                    .split(',')
                    .filter(|v| !v.is_empty())
                    .map(decode)
                    .collect()
            };
            let bad = || format!("the link's {key} is malformed");
            match key {
                "v" => version = Some(value.to_owned()),
                "node" => link.node.id = decode(value).ok_or_else(bad)?,
                "name" => link.name = decode(value).ok_or_else(bad)?,
                "relays" => link.node.relays = list().ok_or_else(bad)?,
                "addrs" => {
                    link.node.addrs = list()
                        .ok_or_else(bad)?
                        .iter()
                        .map(|a| a.parse().map_err(|_| bad()))
                        .collect::<Result<_, _>>()?;
                }
                "secret" => link.secret = decode(value).ok_or_else(bad)?,
                "role" => link.role = decode(value).ok_or_else(bad)?,
                _ => {}
            }
        }
        if version.as_deref() != Some("1") {
            return Err("a pairing link of another version: update the app".to_owned());
        }
        if link.node.id.is_empty() || link.secret.is_empty() {
            return Err("the link names no node or no secret".to_owned());
        }
        PublicKey::from_str(&link.node.id)
            .map_err(|_| "the link's node id is malformed".to_owned())?;
        Ok(link)
    }
}

/// A one-time secret: 128 random bits, base32 (lowercase, no padding).
pub fn secret() -> io::Result<String> {
    use std::io::Read as _;
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(base32(&bytes))
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let letter = |index: u32| {
        ALPHABET
            .get((index & 31) as usize)
            .map_or('a', |b| char::from(*b))
    };
    let mut out = String::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(letter(buffer >> bits));
        }
    }
    if bits > 0 {
        out.push(letter(buffer << (5 - bits)));
    }
    out
}

/// A key's fingerprint for people: the first bytes of its id as words would be nicer; a short grouped form will do.
#[must_use]
pub fn fingerprint(id: &str) -> String {
    id.chars()
        .take(16)
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn a_stream_reaches_the_node_and_back() {
        let node_key = Key::generate();
        let (seen, peers) = std::sync::mpsc::channel();
        // No relay, no port mapping: nothing leaves this machine.
        let listener = Listener::bind(&node_key, &Options::default(), move |accepted| {
            let _ = seen.send((accepted.peer.clone(), accepted.alpn.clone()));
            std::thread::spawn(move || {
                let mut stream = accepted.stream;
                let mut buffer = [0; 5];
                if stream.read_exact(&mut buffer).is_ok() {
                    let _ = stream.write_all(&buffer);
                }
            });
        })
        .unwrap();
        let mut address = listener.address();
        // Loopback only: no relay in a unit test.
        address
            .addrs
            .retain(|a| a.ip().is_loopback() || a.ip().is_unspecified());
        if address.addrs.is_empty() {
            address.addrs = listener
                .endpoint
                .bound_sockets()
                .into_iter()
                .filter(SocketAddr::is_ipv4)
                .map(|a| SocketAddr::from(([127, 0, 0, 1], a.port())))
                .collect();
        }
        let client_key = Key::generate();
        let mut connected = connect(&client_key, &address, &Options::default(), ALPN).unwrap();
        connected.stream.write_all(b"hello").unwrap();
        let mut echoed = [0; 5];
        connected.stream.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"hello");
        let (peer, alpn) = peers.recv().unwrap();
        assert_eq!(peer, client_key.id());
        assert_eq!(alpn, ALPN);
    }

    #[test]
    fn links_round_trip() {
        let link = PairLink {
            node: NodeAddress {
                id: Key::generate().id(),
                relays: vec!["https://relay.example.org./".to_owned()],
                addrs: vec![
                    "192.0.2.1:7842".parse().unwrap(),
                    "[2001:db8::1]:7842".parse().unwrap(),
                ],
            },
            name: "web 1 & co".to_owned(),
            secret: secret().unwrap(),
            role: "admin".to_owned(),
        };
        let text = link.to_string();
        assert!(text.starts_with("snitchhiker://pair?v=1&node="));
        assert!(!text.contains(' '));
        assert_eq!(text.parse::<PairLink>().unwrap(), link);
        assert!(
            "snitchhiker://pair?v=2&node=x&secret=y"
                .parse::<PairLink>()
                .is_err()
        );
        assert!("https://example.org".parse::<PairLink>().is_err());
    }

    #[test]
    fn secrets_are_128_bits_of_base32() {
        let a = secret().unwrap();
        assert_eq!(a.len(), 26);
        assert_ne!(a, secret().unwrap());
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
    }
}
