//! Pairing codes (decision 0010): `<nameplate>-<word>-<word>-<word>`, to type where a link can't be pasted or scanned.
//!
//! The nameplate (1 to 999) names a meeting point: an endpoint whose key is derived from it, which anyone can derive
//! too. The node waits there, on the LAN (mDNS) and on its relays, for one attempt. Both sides run SPAKE2 with the whole
//! code as the password: only someone who knows the words derives the same key, and an attacker at the meeting point
//! (or on the relay) gets one online guess, against 2048³ words, after which the code is spent. The device proves it
//! derived the key first; only then does the node send its pairing link, sealed with it. The device then pairs as a
//! link does, with the real node's key proven by TLS.

use std::io;
use std::str::FromStr;

use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayUrl, SecretKey, TransportAddr};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest as _, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::{Options, PairLink, builder, other, runtime};

/// The ALPN of the meeting point.
pub const CODE_ALPN: &[u8] = b"snitchhiker-code/1";

/// BIP-39's English word list (MIT): 2048 words, no word a prefix of another's first four letters.
const WORDS: &str = include_str!("words.txt");

fn words() -> impl Iterator<Item = &'static str> {
    WORDS.lines().filter(|w| !w.is_empty())
}

/// A pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub nameplate: u16,
    pub words: [String; 3],
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c] = &self.words;
        write!(f, "{}-{a}-{b}-{c}", self.nameplate)
    }
}

impl FromStr for Code {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let lower = text.trim().to_ascii_lowercase();
        let mut parts = lower.split(['-', ' ']).filter(|p| !p.is_empty());
        let nameplate: u16 = parts
            .next()
            .and_then(|n| n.parse().ok())
            .filter(|n| (1..=999).contains(n))
            .ok_or("a code starts with a number from 1 to 999")?;
        let mut found = Vec::new();
        for part in parts {
            let word = words()
                .find(|w| *w == part)
                .ok_or_else(|| format!("`{part}` isn't one of the code's words"))?;
            found.push(word.to_owned());
        }
        let words: [String; 3] = found
            .try_into()
            .map_err(|_| "a code is a number and three words".to_owned())?;
        Ok(Self { nameplate, words })
    }
}

fn random(bytes: &mut [u8]) -> io::Result<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

impl Code {
    /// A new code: a random nameplate and three random words (33 bits).
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0_u8; 8];
        random(&mut bytes)?;
        let list: Vec<&str> = words().collect();
        let pick = |pair: [u8; 2]| {
            let index = usize::from(u16::from_le_bytes(pair) & 0x7ff);
            list.get(index).copied().unwrap_or("abandon").to_owned()
        };
        Ok(Self {
            nameplate: 1 + u16::from_le_bytes([bytes[0], bytes[1]]) % 999,
            words: [
                pick([bytes[2], bytes[3]]),
                pick([bytes[4], bytes[5]]),
                pick([bytes[6], bytes[7]]),
            ],
        })
    }
}

/// The meeting point's key: anyone may derive it from the nameplate; it is no secret.
fn meeting_key(nameplate: u16) -> SecretKey {
    let digest: [u8; 32] =
        Sha256::digest(format!("snitchhiker pairing meeting point v1: {nameplate}")).into();
    SecretKey::from_bytes(&digest)
}

/// The meeting point's id, as a device looks for it.
fn meeting_id(nameplate: u16) -> PublicKey {
    meeting_key(nameplate).public()
}

fn subkey(key: &[u8], label: &str) -> LessSafeKey {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(label.as_bytes())
        .chain_update(key)
        .finalize()
        .into();
    // A 32-byte key is what ChaCha20-Poly1305 takes: this can't fail.
    LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &digest).unwrap_or_else(|_| unreachable!()),
    )
}

fn seal(key: &LessSafeKey, mut message: Vec<u8>) -> io::Result<Vec<u8>> {
    // Each key seals one message: a zero nonce is fine.
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key([0; 12]),
        Aad::empty(),
        &mut message,
    )
    .map_err(|_| other("sealing"))?;
    Ok(message)
}

fn open(key: &LessSafeKey, mut sealed: Vec<u8>) -> Option<Vec<u8>> {
    let opened = key
        .open_in_place(
            Nonce::assume_unique_for_key([0; 12]),
            Aad::empty(),
            &mut sealed,
        )
        .ok()?
        .to_vec();
    Some(opened)
}

async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(other)?;
    send.write_all(&length.to_le_bytes()).await.map_err(other)?;
    send.write_all(bytes).await.map_err(other)
}

async fn read_frame(receive: &mut RecvStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    receive.read_exact(&mut length).await.map_err(other)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > 4096 {
        return Err(other("a frame too long"));
    }
    let mut bytes = vec![0; length];
    receive.read_exact(&mut bytes).await.map_err(other)?;
    Ok(bytes)
}

const DEVICE_PROOF: &[u8] = b"snitchhiker: the device knows the code";

fn spake(code: &Code) -> (Password, Identity, Identity) {
    (
        Password::new(code.to_string()),
        Identity::new(b"snitchhiker device"),
        Identity::new(b"snitchhiker node"),
    )
}

/// The node's side: one attempt at the meeting point; its outcome (`true`: the device knew the code and was sent the
/// link).
async fn serve_one(endpoint: &Endpoint, code: &Code, link: &str) -> io::Result<bool> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| other("the meeting point closed"))?;
    let connection = incoming.await.map_err(other)?;
    let (mut send, mut receive) = connection.accept_bi().await.map_err(other)?;
    let (password, device, node) = spake(code);
    let (state, message) = Spake2::<Ed25519Group>::start_b(&password, &device, &node);
    let theirs = read_frame(&mut receive).await?;
    write_frame(&mut send, &message).await?;
    let Ok(key) = state.finish(&theirs) else {
        return Ok(false);
    };
    let proof = read_frame(&mut receive).await?;
    if open(&subkey(&key, "device"), proof).as_deref() != Some(DEVICE_PROOF) {
        return Ok(false);
    }
    write_frame(
        &mut send,
        &seal(&subkey(&key, "node"), link.as_bytes().to_vec())?,
    )
    .await?;
    let _ = send.finish();
    let _ = connection.closed().await;
    Ok(true)
}

/// A code the node offers: its meeting point, open until the one attempt is made (or this is dropped).
pub struct Offer {
    endpoint: Endpoint,
    runtime: tokio::runtime::Runtime,
}

impl Offer {
    /// Opens the meeting point of `code`, on the LAN and on `options`' relays; `link` is what a device that knows the
    /// code is sent. `attempted` is called once, with the attempt's outcome.
    pub fn open(
        code: &Code,
        options: &Options,
        link: String,
        attempted: impl FnOnce(bool) + Send + 'static,
    ) -> io::Result<Self> {
        let runtime = runtime("pairing-code")?;
        let key = crate::Key(meeting_key(code.nameplate));
        let mut options = options.clone();
        options.port = 0;
        let endpoint = runtime.block_on(async {
            builder(&key, &options)?
                .alpns(vec![CODE_ALPN.to_vec()])
                .bind()
                .await
                .map_err(other)
        })?;
        let serving = endpoint.clone();
        let code = code.clone();
        runtime.spawn(async move {
            let outcome = serve_one(&serving, &code, &link).await.unwrap_or(false);
            attempted(outcome);
            serving.close().await;
        });
        Ok(Self { endpoint, runtime })
    }
}

impl Drop for Offer {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        self.runtime.block_on(async move { endpoint.close().await });
    }
}

/// The device's exchange at the meeting point `addr`: proves it knows `code`, and opens the node's link.
async fn exchange(endpoint: &Endpoint, addr: EndpointAddr, code: &Code) -> io::Result<PairLink> {
    let connection = endpoint.connect(addr, CODE_ALPN).await.map_err(other)?;
    let (mut send, mut receive) = connection.open_bi().await.map_err(other)?;
    let (password, device, node) = spake(code);
    let (state, message) = Spake2::<Ed25519Group>::start_a(&password, &device, &node);
    write_frame(&mut send, &message).await?;
    let theirs = read_frame(&mut receive).await?;
    let shared = state
        .finish(&theirs)
        .map_err(|_| other("the pairing exchange failed"))?;
    write_frame(
        &mut send,
        &seal(&subkey(&shared, "device"), DEVICE_PROOF.to_vec())?,
    )
    .await?;
    let wrong = || other("the code is wrong (it is spent now: start pairing again)");
    let sealed = read_frame(&mut receive).await.map_err(|_| wrong())?;
    let link = open(&subkey(&shared, "node"), sealed).ok_or_else(wrong)?;
    connection.close(0_u32.into(), b"paired");
    String::from_utf8(link)
        .map_err(other)?
        .parse::<PairLink>()
        .map_err(other)
}

/// The device's side: finds the meeting point of `code` (on the LAN, or through `options`' relays), proves it knows
/// the code, and returns the node's pairing link.
pub fn redeem(code: &Code, options: &Options) -> io::Result<PairLink> {
    let runtime = runtime("pairing-code")?;
    let key = crate::Key::generate();
    runtime.block_on(async {
        let endpoint = builder(&key, options)?.bind().await.map_err(other)?;
        let mut addrs = Vec::new();
        for relay in &options.relays {
            addrs.push(TransportAddr::Relay(
                RelayUrl::from_str(relay).map_err(|e| other(format!("relay {relay}: {e}")))?,
            ));
        }
        let addr = EndpointAddr::from_parts(meeting_id(code.nameplate), addrs);
        let link = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            exchange(&endpoint, addr, code),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "no node offers this code nearby or on the relay",
            )
        })?;
        endpoint.close().await;
        link
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_reject_nonsense() {
        let code = Code::generate().unwrap();
        assert!((1..=999).contains(&code.nameplate));
        assert_eq!(code.to_string().parse::<Code>().unwrap(), code);
        assert_eq!(
            "7 Orbit VELVET canyon".parse::<Code>().unwrap().to_string(),
            "7-orbit-velvet-canyon"
        );
        assert!("0-orbit-velvet-canyon".parse::<Code>().is_err());
        assert!("7-orbit-velvet".parse::<Code>().is_err());
        assert!("7-orbit-velvet-notaword".parse::<Code>().is_err());
        assert_eq!(words().count(), 2048);
    }

    #[test]
    fn the_right_code_gets_the_link_and_a_wrong_one_spends_it() {
        let options = Options::default();
        let code = Code::generate().unwrap();
        let link = PairLink {
            node: crate::NodeAddress {
                id: crate::Key::generate().id(),
                ..crate::NodeAddress::default()
            },
            name: "node".to_owned(),
            secret: crate::secret().unwrap(),
            role: "admin".to_owned(),
        };
        // Loopback, without mDNS: the device is told where the meeting point is.
        let (done, outcome) = std::sync::mpsc::channel();
        let offer = Offer::open(&code, &options, link.to_string(), move |ok| {
            let _ = done.send(ok);
        })
        .unwrap();
        let port = offer
            .endpoint
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .unwrap()
            .port();
        let redeemed = redeem_at(&code, port).unwrap();
        assert_eq!(redeemed, link);
        assert!(outcome.recv().unwrap());

        let code = Code::generate().unwrap();
        let (done, outcome) = std::sync::mpsc::channel();
        let offer = Offer::open(&code, &options, link.to_string(), move |ok| {
            let _ = done.send(ok);
        })
        .unwrap();
        let port = offer
            .endpoint
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .unwrap()
            .port();
        let wrong = Code {
            words: [
                "abandon".to_owned(),
                "ability".to_owned(),
                "able".to_owned(),
            ],
            ..code.clone()
        };
        assert!(redeem_at(&wrong, port).is_err());
        assert!(!outcome.recv().unwrap());
    }

    /// `redeem`, with the meeting point's address given (no mDNS, no relay in a unit test).
    fn redeem_at(code: &Code, port: u16) -> io::Result<PairLink> {
        let runtime = runtime("test")?;
        let key = crate::Key::generate();
        runtime.block_on(async {
            let endpoint = builder(&key, &Options::default())?
                .bind()
                .await
                .map_err(other)?;
            let addr = EndpointAddr::from_parts(
                meeting_id(code.nameplate),
                [TransportAddr::Ip(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    port,
                )))],
            );
            exchange(&endpoint, addr, code).await
        })
    }
}
