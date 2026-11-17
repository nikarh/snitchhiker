//! The push gateway (plan §8.5), with mock push services on loopback: a `UnifiedPush` endpoint and FCM (its token
//! endpoint and its send API). Two devices paired and asleep (not connected): one woken by `UnifiedPush`, its pushes
//! encrypted to its keys, one by FCM. A prompt wakes both; the node stopped, after its threshold both are told it is
//! offline, with its reason; started again, that it is back.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::{aead, agreement, hkdf};
use snitchhiker_client::remote::{connect, pair};
use snitchhiker_proto::prost::Message as _;
use snitchhiker_proto::v1;
use snitchhiker_remote::{Key, Options, PairLink};

use crate::daemon::Running;
use crate::util::check;

const DIR: &str = "/tmp/snitchhiker-push-test";
const RELAY: &str = "http://127.0.0.1:3340";
const MOCK: &str = "127.0.0.1:3350";

/// A request the mock services got: its path, its `content-encoding`, its body.
type Received = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

/// The mock push services: every request recorded; the token endpoint grants a token.
fn serve_mocks() -> Result<Received, String> {
    let listener = TcpListener::bind(MOCK).map_err(|e| format!("binding the mocks: {e}"))?;
    let received: Received = Arc::default();
    let record = Arc::clone(&received);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Each connection on its own: a client may hold one open idle.
            let record = Arc::clone(&record);
            thread::spawn(move || answer(&stream, &record));
        }
    });
    Ok(received)
}

/// Answers one request on a connection, recording it.
fn answer(stream: &std::net::TcpStream, record: &Received) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let path = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let (mut length, mut encoding) = (0, String::new());
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap_or_default();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().unwrap_or(0),
            "content-encoding" => value.trim().clone_into(&mut encoding),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let answer = if path == "/token" {
        r#"{"access_token":"mock","expires_in":3600}"#
    } else {
        "{}"
    };
    record
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((path, encoding, body));
    let _ = (&*stream).write_all(
        format!(
            "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
            answer.len()
        )
        .as_bytes(),
    );
}

/// A relay with its push gateway, FCM pointed at the mocks.
struct Relay(std::process::Child);

impl Relay {
    fn start() -> Result<(Self, String), String> {
        let _ = std::fs::remove_dir_all(DIR);
        std::fs::create_dir_all(DIR).map_err(|e| e.to_string())?;
        // A service account of a project that doesn't exist, with a key made for the test.
        let key = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .map_err(|e| format!("openssl: {e}"))?;
        let account = serde_json::json!({
            "type": "service_account",
            "project_id": "mock",
            "client_email": "push@mock.iam.gserviceaccount.com",
            "private_key": String::from_utf8_lossy(&key.stdout),
            "token_uri": format!("http://{MOCK}/token"),
        });
        std::fs::write(format!("{DIR}/fcm.json"), account.to_string())
            .map_err(|e| e.to_string())?;
        std::fs::write(
            format!("{DIR}/relay.toml"),
            format!(
                "http_bind = \"127.0.0.1:3340\"\n\n[push]\nurl = \"{RELAY}/\"\nkey = \"{DIR}/push.key\"\nstate = \"{DIR}/push.json\"\nfcm_service_account = \"{DIR}/fcm.json\"\nfcm_api = \"http://{MOCK}\"\n"
            ),
        )
        .map_err(|e| e.to_string())?;
        let config = format!("{DIR}/relay.toml");
        let id = std::process::Command::new("snitchhiker-relay")
            .args(["push-id", "--config", &config])
            .output()
            .map_err(|e| e.to_string())?;
        let id = String::from_utf8_lossy(&id.stdout).trim().to_owned();
        let child = std::process::Command::new("snitchhiker-relay")
            .args(["--config", &config])
            .env("RUST_LOG", "info,snitchhiker_relay=debug")
            // Its log goes to stdout.
            .stdout(std::fs::File::create(format!("{DIR}/relay.log")).map_err(|e| e.to_string())?)
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("starting snitchhiker-relay: {e}"))?;
        thread::sleep(Duration::from_secs(2));
        Ok((Self(child), id))
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A device's Web Push keys: the private key (single use, as ring has it), the public key, the auth secret.
fn web_push_keys() -> (agreement::EphemeralPrivateKey, Vec<u8>, [u8; 16]) {
    let random = SystemRandom::new();
    let private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &random)
        .unwrap_or_else(|_| unreachable!("P-256 key generation"));
    let public = private
        .compute_public_key()
        .map_or_else(|_| Vec::new(), |k| k.as_ref().to_vec());
    let mut auth = [0; 16];
    let _ = ring::rand::SecureRandom::fill(&random, &mut auth);
    (private, public, auth)
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &hkdf::Prk, info: &[&[u8]], out: &mut [u8]) -> Option<()> {
    prk.expand(info, Len(out.len())).ok()?.fill(out).ok()
}

/// Opens a Web Push body (RFC 8291) as the device does.
fn open(
    private: agreement::EphemeralPrivateKey,
    public: &[u8],
    auth: &[u8],
    body: &[u8],
) -> Option<Vec<u8>> {
    let salt = body.get(..16)?;
    let id_len = usize::from(*body.get(20)?);
    let sender = body.get(21..21 + id_len)?;
    let mut record = body.get(21 + id_len..)?.to_vec();
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, sender);
    let mut ikm = [0; 32];
    agreement::agree_ephemeral(private, &peer, |secret| {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, auth).extract(secret);
        expand(&prk, &[b"WebPush: info\0", public, sender], &mut ikm)
    })
    .ok()??;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&ikm);
    let mut cek = [0; 16];
    expand(&prk, &[b"Content-Encoding: aes128gcm\0"], &mut cek)?;
    let mut nonce = [0; 12];
    expand(&prk, &[b"Content-Encoding: nonce\0"], &mut nonce)?;
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).ok()?);
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut record,
        )
        .ok()?;
    let (delimiter, message) = plain.split_last()?;
    (*delimiter == 2).then(|| message.to_vec())
}

fn link(daemon: &Running, name: &str) -> Result<PairLink, String> {
    let printed = daemon.cli(&["pair", "--name", name])?;
    printed
        .lines()
        .find(|l| l.starts_with("snitchhiker://pair?"))
        .ok_or_else(|| format!("no link printed:\n{printed}"))?
        .parse()
}

/// Pairs a device, tells the node its push target, and disconnects.
fn sleeping_device(
    daemon: &Running,
    name: &str,
    target: v1::push_target::Kind,
) -> Result<Key, String> {
    let key = Key::generate();
    let options = Options::default();
    let link = link(daemon, name)?;
    pair(&key, &link, name, &options).map_err(|e| e.to_string())?;
    let mut client = connect(&key, &link.node, &options, "e2e", "0").map_err(|e| e.to_string())?;
    client
        .call(v1::request::Method::SetPushTarget(v1::SetPushTarget {
            target: Some(v1::PushTarget { kind: Some(target) }),
        }))
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// The pushes FCM was asked to send, decoded, in order.
fn fcm_pushes(received: &Received) -> Vec<v1::PushMessage> {
    received
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(path, _, _)| path.ends_with("/messages:send"))
        .filter_map(|(_, _, body)| {
            let json: serde_json::Value = serde_json::from_slice(body).ok()?;
            let data = json.pointer("/message/data/m")?.as_str()?;
            v1::PushMessage::decode(STANDARD.decode(data).ok()?.as_slice()).ok()
        })
        .collect()
}

/// The bodies posted to the `UnifiedPush` endpoint, in order.
fn unified_pushes(received: &Received) -> Vec<(String, Vec<u8>)> {
    received
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(path, _, _)| path == "/up/phone")
        .map(|(_, encoding, body)| (encoding.clone(), body.clone()))
        .collect()
}

fn wait_for(what: impl Fn() -> bool, within: Duration) {
    let deadline = Instant::now() + within;
    while !what() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
    }
}

/// The two devices: a phone woken by `UnifiedPush`, a tablet by FCM.
fn sleeping_devices(daemon: &Running, public: &[u8], auth: &[u8]) -> Result<(), String> {
    sleeping_device(
        daemon,
        "phone",
        v1::push_target::Kind::UnifiedPush(v1::UnifiedPush {
            endpoint: format!("http://{MOCK}/up/phone"),
            p256dh: public.to_vec(),
            auth: auth.to_vec(),
        }),
    )?;
    sleeping_device(
        daemon,
        "tablet",
        v1::push_target::Kind::Fcm(v1::FcmToken {
            token: "tablet-token".to_owned(),
        }),
    )?;
    Ok(())
}

pub fn devices_are_woken_and_told_when_the_node_goes() -> Result<(), String> {
    let received = serve_mocks()?;
    let (relay, gateway) = Relay::start()?;
    // The relay and the mock services are on this machine (elsewhere, in a deployment): with the node stopped, its
    // table must go (fail open) for the relay to reach them.
    let settings = format!(
        "mode = \"enforce\"\nno_match = \"ask\"\nprompt_timeout_secs = 10\n[remote]\nrelays = [\"{RELAY}/\"]\npush_gateway = \"{gateway}\"\noffline_after_secs = 4\n"
    );
    let mut daemon = Running::start("push", &settings)?;
    // The test's connections, and the relay's (on another machine in a deployment), are a program's like any other's.
    for (exe, name) in [
        ("/usr/local/bin/snitchhiker-e2e", "the test"),
        ("/usr/local/bin/snitchhiker-relay", "the relay"),
    ] {
        daemon.cli(&["rules", "add", "allow", "--exe", exe, "--name", name])?;
    }
    let (private, public, auth) = web_push_keys();
    sleeping_devices(&daemon, &public, &auth)?;
    // The node reaches the gateway, the registrations follow, and the devices' connections end.
    let relay_log = || std::fs::read_to_string(format!("{DIR}/relay.log")).unwrap_or_default();
    wait_for(
        || relay_log().contains("a node connected to the push gateway"),
        Duration::from_secs(30),
    );
    thread::sleep(Duration::from_secs(2));

    // Nobody connected, but devices to wake: a connection no rule decides is asked about.
    let _ = std::process::Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "curl",
            "-s",
            "-m",
            "1",
            "http://192.0.2.77:9",
        ])
        .output();
    wait_for(
        || !fcm_pushes(&received).is_empty() && !unified_pushes(&received).is_empty(),
        Duration::from_secs(10),
    );
    let woken_fcm = fcm_pushes(&received);
    let woken_up = unified_pushes(&received);

    let kind = |kind: v1::PushKind| {
        let received = Arc::clone(&received);
        move || fcm_pushes(&received).iter().any(|m| m.kind() == kind)
    };
    daemon.stop()?;
    wait_for(kind(v1::PushKind::Offline), Duration::from_secs(20));
    let offline = fcm_pushes(&received);
    daemon.restart(&settings)?;
    wait_for(kind(v1::PushKind::Online), Duration::from_secs(20));
    let back = fcm_pushes(&received);
    let ups = unified_pushes(&received);
    drop(daemon);
    drop(relay);

    let log = std::fs::read_to_string(format!("{DIR}/relay.log")).unwrap_or_default();
    let found = format!(
        "fcm on waking: {woken_fcm:?}\nunified push on waking: {:?}\nfcm after stopping: {offline:?}\nfcm after starting: {back:?}\nunified pushes: {}\n{log}",
        woken_up
            .iter()
            .map(|(e, b)| (e, b.len()))
            .collect::<Vec<_>>(),
        ups.len(),
    );
    let woke = woken_fcm.first();
    check(
        woke.is_some_and(|m| {
            m.kind() == v1::PushKind::Wake && !m.node.is_empty() && m.reason.is_empty()
        }),
        "the FCM device wasn't woken for the prompt (with nothing but the node's id)",
        &found,
    )?;
    let opened = woken_up
        .first()
        .filter(|(encoding, _)| encoding == "aes128gcm")
        .and_then(|(_, body)| open(private, &public, &auth, body))
        .and_then(|plain| v1::PushMessage::decode(plain.as_slice()).ok());
    check(
        opened.is_some_and(|m| {
            m.kind() == v1::PushKind::Wake && woke.is_some_and(|w| w.node == m.node)
        }),
        "the UnifiedPush device wasn't woken, or the push wasn't encrypted to its keys",
        &found,
    )?;
    check(
        offline.iter().any(|m| {
            m.kind() == v1::PushKind::Offline
                && m.reason.contains("stopped")
                && !m.node_name.is_empty()
        }),
        "the devices weren't told the node went offline, with its reason",
        &found,
    )?;
    check(
        back.iter().any(|m| m.kind() == v1::PushKind::Online)
            && ups.len() >= 3
            && woken_fcm
                .iter()
                .filter(|m| m.kind() == v1::PushKind::Wake)
                .count()
                == 1,
        "the devices weren't told the node is back, or a device was woken more than once at a time",
        &found,
    )
}
