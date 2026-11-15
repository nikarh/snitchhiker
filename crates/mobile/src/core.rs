//! The app's core, in plain Rust (the JNI layer in `lib.rs` only converts): keys, pairing, and connections to nodes
//! held by number. Requests and notices cross as the protocol's own messages, encoded: the app decodes them with
//! classes generated from the same schema, so every request the protocol has is the app's too.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snitchhiker_client::Client;
use snitchhiker_proto::prost::Message as _;
use snitchhiker_proto::v1;
use snitchhiker_remote::code::Code;
use snitchhiker_remote::{Key, NodeAddress, Options, PairLink};

/// What the app is, to nodes.
const APP: &str = "android";

pub type Result<T> = std::result::Result<T, String>;

/// A node paired with this device, as the app keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub id: String,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub addrs: Vec<String>,
    /// The role the node gave this device.
    #[serde(default)]
    pub role: String,
}

impl Node {
    fn address(&self) -> NodeAddress {
        NodeAddress {
            id: self.id.clone(),
            relays: self.relays.clone(),
            addrs: self.addrs.iter().filter_map(|a| a.parse().ok()).collect(),
        }
    }
}

fn key(bytes: &[u8]) -> Result<Key> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "a key is 32 bytes".to_owned())?;
    Ok(Key::from_bytes(&bytes))
}

/// A new device key's 32 bytes.
#[must_use]
pub fn generate_key() -> Vec<u8> {
    Key::generate().to_bytes().to_vec()
}

/// The id a key is known by.
pub fn key_id(bytes: &[u8]) -> Result<String> {
    Ok(key(bytes)?.id())
}

/// Pairs this device (`key`, called `name`) by a link or a code (looked up on the LAN, or through `relays`, those of
/// the nodes already paired); the node, as JSON.
pub fn pair(key_bytes: &[u8], link_or_code: &str, name: &str, relays: &[String]) -> Result<String> {
    let key = key(key_bytes)?;
    let options = Options {
        relays: relays.to_vec(),
        lan: true,
        ..Options::default()
    };
    let (link, response) = match link_or_code.parse::<PairLink>() {
        Ok(link) => {
            let response = snitchhiker_client::remote::pair(&key, &link, name, &options)
                .map_err(|e| e.to_string())?;
            (link, response)
        }
        Err(link_error) => {
            let code: Code = link_or_code
                .parse()
                .map_err(|_| format!("{link_error}, nor a pairing code"))?;
            snitchhiker_client::remote::pair_with_code(&key, &code, name, &options)
                .map_err(|e| e.to_string())?
        }
    };
    let role = response.role();
    let node = Node {
        name: if response.node_name.is_empty() {
            link.name.clone()
        } else {
            response.node_name
        },
        id: link.node.id.clone(),
        relays: link.node.relays.clone(),
        addrs: link.node.addrs.iter().map(ToString::to_string).collect(),
        role: if role == v1::Role::Viewer {
            "viewer"
        } else {
            "admin"
        }
        .to_owned(),
    };
    serde_json::to_string(&node).map_err(|e| e.to_string())
}

/// The connections open, by number.
fn connections() -> &'static Mutex<HashMap<u64, Arc<Mutex<Client>>>> {
    static CONNECTIONS: OnceLock<Mutex<HashMap<u64, Arc<Mutex<Client>>>>> = OnceLock::new();
    CONNECTIONS.get_or_init(Mutex::default)
}

static NEXT: AtomicU64 = AtomicU64::new(1);

fn connection(handle: u64) -> Result<Arc<Mutex<Client>>> {
    connections()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&handle)
        .cloned()
        .ok_or_else(|| "the connection is closed".to_owned())
}

/// Connects to `node` (its JSON) as `key`; the connection's number. The node's `Welcome` is the first notice.
pub fn connect(key_bytes: &[u8], node: &str) -> Result<u64> {
    let key = key(key_bytes)?;
    let node: Node = serde_json::from_str(node).map_err(|e| e.to_string())?;
    let options = Options {
        lan: true,
        ..Options::default()
    };
    let client = snitchhiker_client::remote::connect(
        &key,
        &node.address(),
        &options,
        APP,
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|e| e.to_string())?;
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    connections()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(handle, Arc::new(Mutex::new(client)));
    Ok(handle)
}

/// The node's `Welcome` on a connection, encoded.
pub fn welcome(handle: u64) -> Result<Vec<u8>> {
    let client = connection(handle)?;
    let client = client.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(client.welcome().encode_to_vec())
}

/// A request (an encoded `Request`; its id is ignored): the encoded `Response`, an error included.
pub fn call(handle: u64, request: &[u8]) -> Result<Vec<u8>> {
    let request = v1::Request::decode(request).map_err(|e| e.to_string())?;
    let method = request.method.ok_or("a request without a method")?;
    let client = connection(handle)?;
    let result = client
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .call(method);
    let result = match result {
        Ok(result) => result,
        Err(snitchhiker_client::Error::Remote { code, message }) => {
            v1::response::Result::Error(v1::Error {
                code: code.into(),
                message,
            })
        }
        Err(error) => return Err(error.to_string()),
    };
    Ok(v1::Response {
        id: request.id,
        result: Some(result),
    }
    .encode_to_vec())
}

/// Subscribes a connection to a topic; the subscription's id.
pub fn subscribe(handle: u64, topic: i32) -> Result<u64> {
    let topic = v1::Topic::try_from(topic).map_err(|_| format!("no topic {topic}"))?;
    let client = connection(handle)?;
    let subscribed = client
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .subscribe(topic);
    subscribed.map_err(|e| e.to_string())
}

/// The next notice on a connection (encoded), waiting up to `timeout_ms`; none when none came. A closed connection
/// is an error.
pub fn next_notice(handle: u64, timeout_ms: u64) -> Result<Option<Vec<u8>>> {
    let client = connection(handle)?;
    let mut client = client.lock().unwrap_or_else(PoisonError::into_inner);
    client
        .set_read_timeout(Some(Duration::from_millis(timeout_ms.max(1))))
        .map_err(|e| e.to_string())?;
    match client.notice() {
        Ok(notice) => Ok(Some(notice.encode_to_vec())),
        Err(snitchhiker_client::Error::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Closes a connection.
pub fn close(handle: u64) {
    connections()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_nodes() {
        let key = generate_key();
        assert_eq!(key.len(), 32);
        assert_eq!(key_id(&key).unwrap().len(), 64);
        assert!(key_id(&[0; 3]).is_err());
        let node: Node = serde_json::from_str(
            r#"{"name": "web", "id": "x", "addrs": ["192.0.2.1:9", "nonsense"]}"#,
        )
        .unwrap();
        assert_eq!(node.address().addrs.len(), 1);
        assert!(connect(&key, "{").is_err());
        assert!(call(1234, &[]).is_err());
        assert!(next_notice(1234, 1).is_err());
    }
}
