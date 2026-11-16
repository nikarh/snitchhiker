//! Names from systemd-resolved's monitor (`io.systemd.Resolve.Monitor`): every answer resolved gives, including those
//! from its cache and its `/etc/hosts`, which never cross the network for the DNS queue to see. A program that
//! resolves through resolved's library interface (nss-resolve) sends no DNS packet at all, so without this its
//! connections would have no names.
//!
//! The monitor says what was asked and answered, not who asked: its names count as "recently resolved for this
//! address", like the answers resolved's own upstream queries bring. Only root may subscribe; resolved checks.
//!
//! When resolved isn't running, the thread waits for its socket to appear (inotify), never on a timer.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::dns::Answer;

const SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve.Monitor";

/// Follows the monitor for as long as the daemon runs, giving each answer to `learn`.
pub fn spawn(learn: impl Fn(&Answer) + Send + 'static) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("resolved".to_owned())
        .spawn(move || {
            loop {
                match UnixStream::connect(SOCKET) {
                    Ok(stream) => {
                        info!("following systemd-resolved's answers");
                        if let Err(error) = follow(stream, &learn) {
                            debug!(%error, "systemd-resolved's monitor ended");
                        }
                    }
                    Err(error) => debug!(%error, "systemd-resolved's monitor isn't there"),
                }
                // Gone, or never there: wait until its socket is (re)created.
                if let Err(error) = crate::sockets::wait_for(Path::new(SOCKET)) {
                    warn!(%error, "waiting for systemd-resolved; its answers are no longer followed");
                    return;
                }
            }
        })?;
    Ok(())
}

/// Subscribes and reads answers until resolved closes the connection.
fn follow(mut stream: UnixStream, learn: &impl Fn(&Answer)) -> std::io::Result<()> {
    stream.write_all(
        b"{\"method\":\"io.systemd.Resolve.Monitor.SubscribeQueryResults\",\"more\":true}\0",
    )?;
    let mut reader = BufReader::new(stream);
    let mut message = Vec::new();
    loop {
        message.clear();
        if reader.read_until(0, &mut message)? == 0 {
            return Ok(());
        }
        message.pop_if(|b| *b == 0);
        let Ok(value) = serde_json::from_slice::<Value>(&message) else {
            continue;
        };
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            return Err(std::io::Error::other(error.to_owned()));
        }
        if let Some(answer) = value.get("parameters").and_then(answer) {
            learn(&answer);
        }
    }
}

/// The answer in a monitor message: the name asked, its CNAME chain, and the addresses of the names in the chain.
fn answer(parameters: &Value) -> Option<Answer> {
    if parameters.get("state").and_then(Value::as_str) != Some("success") {
        return None;
    }
    let name = normalize(parameters.get("question")?.get(0)?.get("name")?.as_str()?);
    let records: Vec<&Value> = parameters
        .get("answer")?
        .as_array()?
        .iter()
        .filter_map(|a| a.get("rr"))
        .collect();
    let owner = |rr: &Value| {
        rr.get("key")
            .and_then(|k| k.get("name"))
            .and_then(Value::as_str)
            .map(normalize)
    };
    let kind = |rr: &Value| {
        rr.get("key")
            .and_then(|k| k.get("type"))
            .and_then(Value::as_u64)
    };
    let mut chain = vec![name.clone()];
    while let Some(target) = records.iter().find_map(|rr| {
        (kind(rr) == Some(5) && owner(rr).as_ref() == chain.last())
            .then(|| rr.get("name").and_then(Value::as_str).map(normalize))
            .flatten()
    }) {
        if chain.contains(&target) {
            break;
        }
        chain.push(target);
    }
    let addresses: Vec<(IpAddr, Duration)> = records
        .iter()
        .filter(|rr| owner(rr).is_some_and(|o| chain.contains(&o)))
        .filter_map(|rr| {
            let bytes: Vec<u8> = rr
                .get("address")?
                .as_array()?
                .iter()
                .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect::<Option<_>>()?;
            let address = match (kind(rr)?, bytes.len()) {
                (1, 4) => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
                (28, 16) => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
                _ => return None,
            };
            let ttl = rr.get("ttl").and_then(Value::as_u64).unwrap_or(0);
            Some((address, Duration::from_secs(ttl)))
        })
        .collect();
    (!addresses.is_empty()).then(|| Answer {
        name: Arc::from(name.as_str()),
        addresses,
    })
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read_from_monitor_messages() {
        let message = serde_json::json!({
            "state": "success",
            "question": [{"class": 1, "type": 1, "name": "www.example.com"}],
            "answer": [
                {"rr": {"key": {"class": 1, "type": 5, "name": "www.example.com"}, "name": "edge.example.net"}},
                {"rr": {"key": {"class": 1, "type": 1, "name": "edge.example.net"}, "address": [192, 0, 2, 7]}},
                {"rr": {"key": {"class": 1, "type": 28, "name": "edge.example.net"},
                        "address": [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]}},
                // Not in the chain: never attached to the name.
                {"rr": {"key": {"class": 1, "type": 1, "name": "other.example"}, "address": [198, 51, 100, 1]}}
            ]
        });
        let found = answer(&message).unwrap();
        assert_eq!(&*found.name, "www.example.com");
        let addresses: Vec<IpAddr> = found.addresses.iter().map(|(a, _)| *a).collect();
        assert_eq!(
            addresses,
            vec![
                "192.0.2.7".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert!(answer(&serde_json::json!({"state": "rcode-failure"})).is_none());
    }
}
