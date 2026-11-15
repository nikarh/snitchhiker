//! Closing a local socket by its addresses (`sock_diag` `SOCK_DESTROY`): how a rejected connection fails at once
//! instead of timing out. The program's `connect()` or next send returns `ECONNABORTED`.

use std::io;
use std::net::IpAddr;

use netlink_sys::{Socket as RawSocket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

use crate::netlink::{NLM_F_ACK, NLM_F_REQUEST, NLMSG_ERROR, ack_error, messages};

const SOCK_DESTROY: u16 = 21;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// Every TCP state: the socket is found whatever state it is in.
const ALL_STATES: u32 = 0xffff_ffff;
const NO_COOKIE: u32 = 0xffff_ffff;

/// A local socket, as its packets show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketId {
    pub protocol: u8,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// A `sock_diag` netlink socket.
#[derive(Debug)]
pub struct SockDiag {
    socket: RawSocket,
    request: Vec<u8>,
    receive: Vec<u8>,
    sequence: u32,
}

impl SockDiag {
    pub fn open() -> io::Result<Self> {
        let mut socket = RawSocket::new(NETLINK_SOCK_DIAG)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            request: Vec::with_capacity(128),
            receive: Vec::with_capacity(4096),
            sequence: 0,
        })
    }

    /// Closes the socket; `NotFound` when there is none (it may have closed already).
    pub fn destroy(&mut self, id: &SocketId) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        encode_destroy(&mut self.request, id, self.sequence);
        self.socket.send(&self.request, 0)?;
        loop {
            self.receive.clear();
            self.socket.recv(&mut self.receive, 0)?;
            for message in messages(&self.receive) {
                if message.kind == NLMSG_ERROR && message.sequence == self.sequence {
                    return match ack_error(message.body) {
                        0 => Ok(()),
                        code => Err(io::Error::from_raw_os_error(-code)),
                    };
                }
            }
        }
    }
}

/// Writes the `SOCK_DESTROY` request: a netlink header and `struct inet_diag_req_v2`.
pub fn encode_destroy(out: &mut Vec<u8>, id: &SocketId, sequence: u32) {
    out.clear();
    let family = if id.local.is_ipv6() {
        AF_INET6
    } else {
        AF_INET
    };
    let address = |address: IpAddr| -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        match address {
            IpAddr::V4(v4) => {
                if let Some(head) = bytes.get_mut(..4) {
                    head.copy_from_slice(&v4.octets());
                }
            }
            IpAddr::V6(v6) => bytes = v6.octets(),
        }
        bytes
    };
    // Header, filled in below.
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&SOCK_DESTROY.to_ne_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0_u32.to_ne_bytes());
    // inet_diag_req_v2: family, protocol, extensions, padding, states.
    out.extend_from_slice(&[family, id.protocol, 0, 0]);
    out.extend_from_slice(&ALL_STATES.to_ne_bytes());
    // inet_diag_sockid: ports and addresses in network order, interface, cookie.
    out.extend_from_slice(&id.local_port.to_be_bytes());
    out.extend_from_slice(&id.remote_port.to_be_bytes());
    out.extend_from_slice(&address(id.local));
    out.extend_from_slice(&address(id.remote));
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&NO_COOKIE.to_ne_bytes());
    out.extend_from_slice(&NO_COOKIE.to_ne_bytes());
    let length = u32::try_from(out.len()).unwrap_or(u32::MAX);
    if let Some(field) = out.get_mut(0..4) {
        field.copy_from_slice(&length.to_ne_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_an_inet_diag_request() {
        let mut out = Vec::new();
        encode_destroy(
            &mut out,
            &SocketId {
                protocol: 6,
                local: "192.0.2.1".parse().unwrap(),
                local_port: 40000,
                remote: "198.51.100.7".parse().unwrap(),
                remote_port: 443,
            },
            9,
        );
        // 16 bytes of header, 8 of request, 48 of socket id.
        assert_eq!(out.len(), 72);
        let message = messages(&out).next().unwrap();
        assert_eq!(message.kind, SOCK_DESTROY);
        assert_eq!(message.sequence, 9);
        let body = message.body;
        assert_eq!(&body[0..2], &[AF_INET, 6]);
        assert_eq!(&body[8..10], &40000_u16.to_be_bytes());
        assert_eq!(&body[10..12], &443_u16.to_be_bytes());
        assert_eq!(&body[12..16], &[192, 0, 2, 1]);
        assert_eq!(&body[28..32], &[198, 51, 100, 7]);
    }
}
