//! Telling systemd the daemon is ready (`Type=notify`): the `sd_notify` datagram, without libsystemd.

use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Sends `state` (`READY=1`, `STOPPING=1`, ...) to the service manager, if it asked for notifications.
pub fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let path = path.to_string_lossy().into_owned();
    // A leading `@` is an abstract socket.
    let address = match path.strip_prefix('@') {
        Some(name) => SocketAddr::from_abstract_name(name.as_bytes()),
        None => SocketAddr::from_pathname(&path),
    };
    if let (Ok(socket), Ok(address)) = (UnixDatagram::unbound(), address) {
        let _ = socket.send_to_addr(state.as_bytes(), &address);
    }
}
