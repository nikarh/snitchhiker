//! Local sockets through `sock_diag`: listing the live connections (`SOCK_DIAG_BY_FAMILY` dumps), and closing one by its
//! addresses (`SOCK_DESTROY`), which is how a rejected connection fails at once instead of timing out: the program's
//! `connect()` or next send returns `ECONNABORTED`.

use std::io;
use std::net::IpAddr;

use netlink_sys::{Socket as RawSocket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

use crate::netlink::{NLM_F_ACK, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, ack_error, messages};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const NLM_F_DUMP: u16 = 0x300;
/// TCP connections that have, or are getting, a peer: established, opening and closing; not listening sockets nor
/// `TIME_WAIT` ones (no process holds those).
const TCP_LIVE: u32 =
    (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 8) | (1 << 9) | (1 << 11);
/// Connected UDP sockets (established, in the kernel's terms).
const UDP_CONNECTED: u32 = 1 << 1;
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

/// A live socket, as `sock_diag` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveSocket {
    pub id: SocketId,
    /// The kernel's state number (TCP's: 1 established, 2 SYN sent, ...).
    pub state: u8,
    pub uid: u32,
    pub inode: u32,
    /// The kernel's socket cookie: what the attribution programs count bytes by.
    pub cookie: u64,
}

/// A TCP or UDP state's name.
#[must_use]
pub fn state_name(protocol: u8, state: u8) -> &'static str {
    match (protocol, state) {
        (17, 1) => "connected",
        (_, 1) => "established",
        (_, 2) => "opening",
        (_, 3) => "accepted",
        (_, 4 | 5 | 8 | 9 | 11) => "closing",
        _ => "other",
    }
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

    /// The live TCP connections and connected UDP sockets, IPv4 and IPv6.
    pub fn list(&mut self) -> io::Result<Vec<LiveSocket>> {
        let mut found = Vec::new();
        for (protocol, states) in [(6_u8, TCP_LIVE), (17, UDP_CONNECTED)] {
            for family in [AF_INET, AF_INET6] {
                self.sequence = self.sequence.wrapping_add(1);
                encode_dump(&mut self.request, family, protocol, states, self.sequence);
                self.socket.send(&self.request, 0)?;
                'receive: loop {
                    self.receive.clear();
                    self.receive.reserve(64 * 1024);
                    self.socket.recv(&mut self.receive, 0)?;
                    for message in messages(&self.receive) {
                        if message.sequence != self.sequence {
                            continue;
                        }
                        match message.kind {
                            NLMSG_DONE => break 'receive,
                            NLMSG_ERROR => match ack_error(message.body) {
                                0 => break 'receive,
                                code => return Err(io::Error::from_raw_os_error(-code)),
                            },
                            SOCK_DIAG_BY_FAMILY => {
                                if let Some(socket) = decode(message.body, protocol) {
                                    found.push(socket);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(found)
    }

    /// The socket of exactly this flow (local and remote address and port), if there is one: its owner's uid, inode
    /// and cookie.
    pub fn find(&mut self, id: &SocketId) -> io::Result<Option<LiveSocket>> {
        self.sequence = self.sequence.wrapping_add(1);
        encode_destroy(&mut self.request, id, self.sequence);
        // The same request as a destroy, as a lookup: SOCK_DIAG_BY_FAMILY without DUMP.
        if let Some(kind) = self.request.get_mut(4..6) {
            kind.copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        }
        if let Some(flags) = self.request.get_mut(6..8) {
            flags.copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        }
        self.socket.send(&self.request, 0)?;
        loop {
            self.receive.clear();
            self.receive.reserve(4096);
            self.socket.recv(&mut self.receive, 0)?;
            for message in messages(&self.receive) {
                if message.sequence != self.sequence {
                    continue;
                }
                match message.kind {
                    SOCK_DIAG_BY_FAMILY => return Ok(decode(message.body, id.protocol)),
                    NLMSG_ERROR => {
                        return match ack_error(message.body) {
                            0 => Ok(None),
                            code if -code == 2 => Ok(None),
                            code => Err(io::Error::from_raw_os_error(-code)),
                        };
                    }
                    _ => {}
                }
            }
        }
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

/// Writes a `SOCK_DIAG_BY_FAMILY` dump request for one family, protocol and set of states.
pub fn encode_dump(out: &mut Vec<u8>, family: u8, protocol: u8, states: u32, sequence: u32) {
    out.clear();
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&[family, protocol, 0, 0]);
    out.extend_from_slice(&states.to_ne_bytes());
    // An empty inet_diag_sockid: every socket.
    out.extend_from_slice(&[0_u8; 40]);
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&NO_COOKIE.to_ne_bytes());
    out.extend_from_slice(&NO_COOKIE.to_ne_bytes());
    let length = u32::try_from(out.len()).unwrap_or(u32::MAX);
    if let Some(field) = out.get_mut(0..4) {
        field.copy_from_slice(&length.to_ne_bytes());
    }
}

/// Reads a `struct inet_diag_msg`.
fn decode(body: &[u8], protocol: u8) -> Option<LiveSocket> {
    let family = *body.first()?;
    let state = *body.get(1)?;
    let port = |at: usize| Some(u16::from_be_bytes(body.get(at..at + 2)?.try_into().ok()?));
    let address = |at: usize| -> Option<IpAddr> {
        let bytes: [u8; 16] = body.get(at..at + 16)?.try_into().ok()?;
        Some(if family == AF_INET {
            IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            IpAddr::from(bytes)
        })
    };
    let word = |at: usize| Some(u32::from_ne_bytes(body.get(at..at + 4)?.try_into().ok()?));
    let id = SocketId {
        protocol,
        local_port: port(4)?,
        remote_port: port(6)?,
        local: address(8)?,
        remote: address(24)?,
    };
    let cookie = u64::from(word(44)?) | (u64::from(word(48)?) << 32);
    Some(LiveSocket {
        id,
        state,
        uid: word(64)?,
        inode: word(68)?,
        cookie,
    })
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
    fn reads_an_inet_diag_message() {
        let mut body = vec![AF_INET, 1, 0, 0];
        body.extend_from_slice(&40000_u16.to_be_bytes());
        body.extend_from_slice(&443_u16.to_be_bytes());
        let mut local = [0_u8; 16];
        local[..4].copy_from_slice(&[192, 0, 2, 1]);
        let mut remote = [0_u8; 16];
        remote[..4].copy_from_slice(&[198, 51, 100, 7]);
        body.extend_from_slice(&local);
        body.extend_from_slice(&remote);
        body.extend_from_slice(&0_u32.to_ne_bytes());
        body.extend_from_slice(&7_u32.to_ne_bytes());
        body.extend_from_slice(&1_u32.to_ne_bytes());
        // expires, rqueue, wqueue, uid, inode
        for value in [0_u32, 0, 0, 1000, 4242] {
            body.extend_from_slice(&value.to_ne_bytes());
        }
        let socket = decode(&body, 6).unwrap();
        assert_eq!(socket.id.local, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(socket.id.remote_port, 443);
        assert_eq!((socket.state, socket.uid, socket.inode), (1, 1000, 4242));
        assert_eq!(socket.cookie, 7 | (1 << 32));
        assert_eq!(state_name(6, 1), "established");
    }

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
