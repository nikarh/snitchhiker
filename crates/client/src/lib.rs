//! A blocking client of a Snitchhiker node over its local sockets: the handshake, requests (answered by id) and
//! subscription notices (queued while a request waits for its answer).
//!
//! Before saying anything, a client checks it is talking to the node: the socket is in a directory only root can
//! change, and the process serving it runs as root. A process that bound a socket somewhere else, or got one into a
//! directory it may write, can't pose as the node to answer the client's requests or feed it prompts.

use std::collections::VecDeque;
use std::io::{BufReader, BufWriter, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use nix::sys::socket::{getsockopt, sockopt};

use snitchhiker_proto::{MINOR, frame, v1};

/// The node's sockets.
pub const CLIENT_SOCKET: &str = "/run/snitchhiker/client.sock";
pub const ADMIN_SOCKET: &str = "/run/snitchhiker/admin.sock";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("the node refused the connection: {0}")]
    Refused(String),
    #[error("the node answered something unexpected: {0}")]
    Protocol(&'static str),
    #[error("not a Snitchhiker node's socket: {0}")]
    NotTheNode(String),
    #[error("{message}")]
    Remote {
        code: v1::ErrorCode,
        message: String,
    },
}

/// The socket and every directory above it belong to root, and no one else may write to those directories: no other
/// user can have put the socket there, or swap it for theirs.
fn only_root_can_change(path: &Path) -> Result<(), Error> {
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    for (index, entry) in path.ancestors().enumerate() {
        if entry.as_os_str().is_empty() {
            continue;
        }
        let meta = std::fs::symlink_metadata(entry)
            .map_err(|e| Error::NotTheNode(format!("{}: {e}", entry.display())))?;
        if meta.uid() != 0 {
            return Err(Error::NotTheNode(format!(
                "{} doesn't belong to root",
                entry.display()
            )));
        }
        // The socket's own mode says who may connect, not who may replace it.
        if index > 0 && meta.mode() & GROUP_OR_OTHER_WRITE != 0 {
            return Err(Error::NotTheNode(format!(
                "others than root may write to {}",
                entry.display()
            )));
        }
    }
    Ok(())
}

pub struct Client {
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
    buffer: Vec<u8>,
    next_id: u64,
    notices: VecDeque<v1::Notice>,
    welcome: v1::Welcome,
}

impl Client {
    /// Connects to the node's socket at `path`, introducing itself as `app` (`cli`, `desktop`, ...) at `version`.
    pub fn connect(path: &Path, app: &str, version: &str) -> Result<Self, Error> {
        only_root_can_change(path)?;
        let stream = UnixStream::connect(path)?;
        let peer = getsockopt(&stream, sockopt::PeerCredentials)
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        if peer.uid() != 0 {
            return Err(Error::NotTheNode(format!(
                "{} is served by uid {}, not root",
                path.display(),
                peer.uid()
            )));
        }
        let mut writer = BufWriter::new(stream.try_clone()?);
        let mut reader = BufReader::new(stream);
        let mut buffer = Vec::new();
        frame::write_preamble(&mut writer)?;
        let hello = v1::ClientFrame {
            body: Some(v1::client_frame::Body::Hello(v1::Hello {
                minor: MINOR,
                app: app.to_owned(),
                app_version: version.to_owned(),
                capabilities: vec!["prompts".to_owned()],
            })),
        };
        frame::write(&mut writer, &hello, &mut buffer)?;
        writer.flush()?;
        let answer: v1::ServerFrame = frame::read(&mut reader, &mut buffer)?;
        match answer.body {
            Some(v1::server_frame::Body::Welcome(welcome)) => Ok(Self {
                reader,
                writer,
                buffer,
                next_id: 0,
                notices: VecDeque::new(),
                welcome,
            }),
            Some(v1::server_frame::Body::Refusal(refusal)) => Err(Error::Refused(refusal.reason)),
            _ => Err(Error::Protocol("no welcome")),
        }
    }

    #[must_use]
    pub fn welcome(&self) -> &v1::Welcome {
        &self.welcome
    }

    /// Sends a request and waits for its answer; notices arriving meanwhile are kept for [`Client::notice`]. A node's
    /// error is `Error::Remote`.
    pub fn call(&mut self, method: v1::request::Method) -> Result<v1::response::Result, Error> {
        self.next_id += 1;
        let id = self.next_id;
        let request = v1::ClientFrame {
            body: Some(v1::client_frame::Body::Request(v1::Request {
                id,
                method: Some(method),
            })),
        };
        frame::write(&mut self.writer, &request, &mut self.buffer)?;
        self.writer.flush()?;
        loop {
            let frame: v1::ServerFrame = frame::read(&mut self.reader, &mut self.buffer)?;
            match frame.body {
                Some(v1::server_frame::Body::Response(response)) if response.id == id => {
                    return match response.result {
                        Some(v1::response::Result::Error(error)) => Err(Error::Remote {
                            code: error.code(),
                            message: error.message,
                        }),
                        Some(result) => Ok(result),
                        None => Err(Error::Protocol("an empty answer")),
                    };
                }
                Some(v1::server_frame::Body::Notice(notice)) => self.notices.push_back(notice),
                Some(v1::server_frame::Body::Refusal(refusal)) => {
                    return Err(Error::Refused(refusal.reason));
                }
                _ => {}
            }
        }
    }

    /// The next subscription notice, waiting for one (up to the read timeout, if set).
    pub fn notice(&mut self) -> Result<v1::Notice, Error> {
        if let Some(notice) = self.notices.pop_front() {
            return Ok(notice);
        }
        loop {
            let frame: v1::ServerFrame = frame::read(&mut self.reader, &mut self.buffer)?;
            match frame.body {
                Some(v1::server_frame::Body::Notice(notice)) => return Ok(notice),
                Some(v1::server_frame::Body::Refusal(refusal)) => {
                    return Err(Error::Refused(refusal.reason));
                }
                _ => {}
            }
        }
    }

    /// How long reads wait (for [`Client::notice`]); `None` for ever.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), Error> {
        Ok(self.reader.get_ref().set_read_timeout(timeout)?)
    }

    /// Subscribes to a topic; returns the subscription's id.
    pub fn subscribe(&mut self, topic: v1::Topic) -> Result<u64, Error> {
        match self.call(v1::request::Method::Subscribe(v1::Subscribe {
            topic: topic.into(),
        }))? {
            v1::response::Result::Subscribed(subscribed) => Ok(subscribed.subscription),
            _ => Err(Error::Protocol("not a subscription")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_outside_roots_directories_is_not_the_node() {
        let dir = std::env::temp_dir().join(format!("snitchhiker-client-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let result = Client::connect(&path, "test", "0");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(result, Err(Error::NotTheNode(_))),
            "{:?}",
            result.err()
        );
    }
}
