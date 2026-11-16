//! Containers' lifecycle from their runtimes' event streams (Docker's API, and rootful Podman's, which speaks it):
//!
//! - a container renamed or removed is forgotten, so its next connection is described as it is now;
//! - a removed container's id is taken out of the rules that name it (`container.id`): ids are never reused, so such a
//!   rule could never match again; a rule left with no id is deleted. The change is recorded in the history, by
//!   `docker` or `podman`, and can be undone.
//!
//! Each stream is followed by a thread of its own, which waits for the runtime's socket when it isn't running.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use snitchhiker_core::rule::Condition;
use tracing::{debug, info, warn};

use crate::runtime::Daemon;

/// The runtimes followed: their name (as the history says who changed rules) and API socket.
const RUNTIMES: &[(&str, &str)] = &[
    ("docker", "/run/docker.sock"),
    ("podman", "/run/podman/podman.sock"),
];

/// Follows every runtime's events for as long as the daemon runs.
pub fn spawn(daemon: &Arc<Daemon>) -> std::io::Result<()> {
    for &(runtime, socket) in RUNTIMES {
        let daemon = Arc::clone(daemon);
        std::thread::Builder::new()
            .name(format!("{runtime}-events"))
            .spawn(move || {
                loop {
                    match follow(&daemon, runtime, socket) {
                        Ok(()) => debug!(runtime, "the event stream ended"),
                        Err(error) => debug!(runtime, %error, "following the events"),
                    }
                    if let Err(error) = crate::sockets::wait_for(Path::new(socket)) {
                        warn!(runtime, %error, "waiting for the runtime; its events are no longer followed");
                        return;
                    }
                }
            })?;
    }
    Ok(())
}

/// One event the daemon acts on.
#[derive(Debug, PartialEq, Eq)]
enum Event {
    Removed(String),
    Renamed(String),
}

fn follow(daemon: &Daemon, runtime: &str, socket: &str) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    // HTTP/1.0: the events come as JSON objects, one per line, until the runtime closes the stream.
    let filters = "%7B%22type%22%3A%5B%22container%22%5D%7D";
    write!(
        stream,
        "GET /events?filters={filters} HTTP/1.0\r\nHost: {runtime}\r\n\r\n"
    )?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    // The response's head.
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line == "\r\n" {
            break;
        }
    }
    info!(runtime, "following the containers' events");
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        match parse(&line) {
            Some(Event::Removed(id)) => {
                daemon.shared.contexts.forget(&id);
                remove_id(daemon, runtime, &id);
            }
            Some(Event::Renamed(id)) => daemon.shared.contexts.forget(&id),
            None => {}
        }
    }
}

/// A container event the daemon acts on, from one line of the stream.
fn parse(line: &str) -> Option<Event> {
    let json: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let action = json
        .get("Action")
        .or_else(|| json.get("status"))?
        .as_str()?;
    let id = json
        .get("Actor")
        .and_then(|a| a.get("ID"))
        .or_else(|| json.get("id"))?
        .as_str()?
        .to_owned();
    match action {
        "destroy" | "remove" => Some(Event::Removed(id)),
        "rename" => Some(Event::Renamed(id)),
        _ => None,
    }
}

/// Takes container `id` out of the rules naming it; a rule left with none is deleted.
fn remove_id(daemon: &Daemon, runtime: &str, id: &str) {
    let changed = {
        let mut store = daemon.store();
        let Ok(rules) = store.rules() else {
            return;
        };
        let bound: Vec<_> = rules
            .into_iter()
            .filter(|rule| {
                rule.conditions.iter().any(|c| {
                    matches!(c, Condition::ContainerId(ids) if ids.iter().any(|i| id.starts_with(i.as_str())))
                })
            })
            .collect();
        if bound.is_empty() {
            return;
        }
        let batch = match store.batch(runtime, crate::runtime::now_ms()) {
            Ok(batch) => batch,
            Err(error) => {
                warn!(%error, "recording a removed container's rules");
                return;
            }
        };
        store.atomically(|store| -> Result<usize, crate::store::Error> {
            for mut rule in bound.iter().cloned() {
                for condition in &mut rule.conditions {
                    if let Condition::ContainerId(ids) = condition {
                        ids.retain(|i| !id.starts_with(i.as_str()));
                    }
                }
                let emptied = rule
                    .conditions
                    .iter()
                    .any(|c| matches!(c, Condition::ContainerId(ids) if ids.is_empty()));
                if emptied {
                    store.remove_rule(rule.id, &batch)?;
                } else {
                    store.put_rule(&rule, &batch)?;
                }
            }
            Ok(bound.len())
        })
    };
    match changed {
        Ok(count) => {
            info!(
                runtime,
                container = id,
                rules = count,
                "a removed container's rules were changed"
            );
            if let Err(error) = daemon.reload_rules() {
                warn!(%error, "compiling the rules after a container was removed");
            }
        }
        Err(error) => warn!(%error, "changing a removed container's rules"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_read_from_docker_and_podman_lines() {
        let docker = r#"{"Type":"container","Action":"destroy","Actor":{"ID":"4f1a","Attributes":{"name":"web"}},"time":1}"#;
        assert_eq!(parse(docker), Some(Event::Removed("4f1a".to_owned())));
        let podman = r#"{"status":"remove","id":"9c0d","Type":"container","Action":"remove","Actor":{"ID":"9c0d"}}"#;
        assert_eq!(parse(podman), Some(Event::Removed("9c0d".to_owned())));
        let renamed = r#"{"Type":"container","Action":"rename","Actor":{"ID":"4f1a"}}"#;
        assert_eq!(parse(renamed), Some(Event::Renamed("4f1a".to_owned())));
        assert_eq!(
            parse(r#"{"Type":"container","Action":"start","Actor":{"ID":"4f1a"}}"#),
            None
        );
        assert_eq!(parse("not json"), None);
    }
}
