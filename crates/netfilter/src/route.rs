//! rtnetlink lookups for forwarded packets: which bridge port a source address is behind (the bridge's forwarding
//! database), what that port is (a veth to a container's namespace, a tap of a VM), and which namespace a namespace id
//! names. All exact: the kernel's own tables, nothing inferred.

use std::io;

use netlink_sys::{Socket as RawSocket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::netlink::{attributes, messages};

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;

const AF_UNSPEC: u8 = 0;
const AF_BRIDGE: u8 = 7;

const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_LINK_NETNSID: u16 = 37;

const NDA_LLADDR: u16 = 2;
const NDA_MASTER: u16 = 9;

const NETNSA_NSID: u16 = 1;
const NETNSA_PID: u16 = 2;

/// `struct ifinfomsg`.
const IFINFOMSG_LEN: usize = 16;
/// `struct ndmsg`.
const NDMSG_LEN: usize = 12;
/// `struct rtgenmsg`, padded.
const RTGENMSG_LEN: usize = 4;

/// An interface, as far as forwarded packets need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// Its kind (`veth`, `tun`, `bridge`, ...), if it has one.
    pub kind: Option<String>,
    /// The bridge it is a port of.
    pub master: Option<u32>,
    /// For a veth: the namespace of its peer, as this namespace numbers it.
    pub peer_netns_id: Option<i32>,
}

/// A route netlink socket, with buffers kept between requests.
#[derive(Debug)]
pub struct Route {
    socket: RawSocket,
    send: Vec<u8>,
    receive: Vec<u8>,
    sequence: u32,
}

impl Route {
    pub fn open() -> io::Result<Self> {
        let mut socket = RawSocket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            send: Vec::with_capacity(64),
            receive: Vec::with_capacity(1 << 16),
            sequence: 0,
        })
    }

    /// Sends one request (`header` then `attributes`), and hands each answer's body to `each` until the kernel is done
    /// (one answer, or the end of a dump).
    fn request(
        &mut self,
        kind: u16,
        flags: u16,
        header: &[u8],
        attributes: &[(u16, &[u8])],
        mut each: impl FnMut(u16, &[u8]),
    ) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        self.send.clear();
        self.send.extend_from_slice(&0_u32.to_ne_bytes());
        self.send.extend_from_slice(&kind.to_ne_bytes());
        self.send
            .extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
        self.send.extend_from_slice(&self.sequence.to_ne_bytes());
        self.send.extend_from_slice(&0_u32.to_ne_bytes());
        self.send.extend_from_slice(header);
        for (kind, value) in attributes {
            let length = 4 + value.len();
            self.send
                .extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
            self.send.extend_from_slice(&kind.to_ne_bytes());
            self.send.extend_from_slice(value);
            self.send.resize(self.send.len().next_multiple_of(4), 0);
        }
        let length = u32::try_from(self.send.len()).unwrap_or(u32::MAX);
        if let Some(first) = self.send.get_mut(..4) {
            first.copy_from_slice(&length.to_ne_bytes());
        }
        self.socket.send(&self.send, 0)?;
        loop {
            self.receive.clear();
            self.socket.recv(&mut self.receive, 0)?;
            let mut done = false;
            for message in messages(&self.receive) {
                if message.sequence != self.sequence {
                    continue;
                }
                match message.kind {
                    NLMSG_DONE => done = true,
                    NLMSG_ERROR => {
                        let code = crate::netlink::ack_error(message.body);
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(-code));
                        }
                        done = true;
                    }
                    kind => {
                        each(kind, message.body);
                        if flags & NLM_F_DUMP == 0 {
                            done = true;
                        }
                    }
                }
            }
            if done {
                return Ok(());
            }
        }
    }

    /// The interface with index `index`, if there is one.
    pub fn link(&mut self, index: u32) -> io::Result<Option<Link>> {
        let mut header = [0_u8; IFINFOMSG_LEN];
        header[4..8].copy_from_slice(&index.to_ne_bytes());
        let mut found = None;
        let answer = self.request(RTM_GETLINK, 0, &header, &[], |kind, body| {
            if kind == RTM_NEWLINK {
                found = parse_link(body);
            }
        });
        match answer {
            Ok(()) => Ok(found),
            // ENODEV: no such interface (it went away).
            Err(error) if error.raw_os_error() == Some(19) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The port of bridge `bridge` behind which `mac` was seen, from the bridge's forwarding database.
    pub fn bridge_port(&mut self, bridge: u32, mac: [u8; 6]) -> io::Result<Option<u32>> {
        let header = [AF_BRIDGE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut port = None;
        self.request(RTM_GETNEIGH, NLM_F_DUMP, &header, &[], |kind, body| {
            if kind != RTM_NEWNEIGH || port.is_some() {
                return;
            }
            let Some(ifindex) = body
                .get(4..8)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_ne_bytes)
            else {
                return;
            };
            let (mut address, mut master) = (None, None);
            for (attribute, value) in attributes(body.get(NDMSG_LEN..).unwrap_or_default()) {
                match attribute {
                    NDA_LLADDR => address = Some(value),
                    NDA_MASTER => master = value.try_into().ok().map(u32::from_ne_bytes),
                    _ => {}
                }
            }
            if address == Some(&mac[..]) && master == Some(bridge) {
                port = Some(ifindex);
            }
        })?;
        Ok(port)
    }

    /// The id this namespace gives the network namespace of process `pid`, if it gave it one (a veth's peer's
    /// namespace has one).
    pub fn netns_id_of_pid(&mut self, pid: u32) -> io::Result<Option<i32>> {
        let header = [AF_UNSPEC, 0, 0, 0];
        let mut id = None;
        self.request(
            RTM_GETNSID,
            0,
            &header[..RTGENMSG_LEN],
            &[(NETNSA_PID, &pid.to_ne_bytes())],
            |kind, body| {
                if kind != RTM_NEWNSID {
                    return;
                }
                for (attribute, value) in attributes(body.get(RTGENMSG_LEN..).unwrap_or_default()) {
                    if attribute == NETNSA_NSID {
                        id = value.try_into().ok().map(i32::from_ne_bytes);
                    }
                }
            },
        )?;
        // -1: NETNSA_NSID_NOT_ASSIGNED.
        Ok(id.filter(|id| *id >= 0))
    }
}

fn parse_link(body: &[u8]) -> Option<Link> {
    let index = u32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
    let mut link = Link {
        index,
        name: String::new(),
        kind: None,
        master: None,
        peer_netns_id: None,
    };
    for (attribute, value) in attributes(body.get(IFINFOMSG_LEN..)?) {
        match attribute {
            IFLA_IFNAME => {
                link.name =
                    String::from_utf8_lossy(value.strip_suffix(&[0]).unwrap_or(value)).into_owned();
            }
            IFLA_MASTER => link.master = value.try_into().ok().map(u32::from_ne_bytes),
            IFLA_LINK_NETNSID => link.peer_netns_id = value.try_into().ok().map(i32::from_ne_bytes),
            IFLA_LINKINFO => {
                for (inner, value) in attributes(value) {
                    if inner == IFLA_INFO_KIND {
                        link.kind = Some(
                            String::from_utf8_lossy(value.strip_suffix(&[0]).unwrap_or(value))
                                .into_owned(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    Some(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_are_parsed_with_their_kind_and_peer_namespace() {
        let mut body = vec![0_u8; IFINFOMSG_LEN];
        body[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        let mut attribute = |kind: u16, value: &[u8]| {
            body.extend_from_slice(&u16::try_from(4 + value.len()).unwrap().to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(value);
            body.resize(body.len().next_multiple_of(4), 0);
        };
        attribute(IFLA_IFNAME, b"veth1a2b\0");
        attribute(IFLA_MASTER, &3_u32.to_ne_bytes());
        attribute(IFLA_LINK_NETNSID, &2_i32.to_ne_bytes());
        let mut info = Vec::new();
        info.extend_from_slice(&9_u16.to_ne_bytes());
        info.extend_from_slice(&IFLA_INFO_KIND.to_ne_bytes());
        info.extend_from_slice(b"veth\0");
        info.resize(12, 0);
        attribute(IFLA_LINKINFO, &info);
        assert_eq!(
            parse_link(&body),
            Some(Link {
                index: 7,
                name: "veth1a2b".to_owned(),
                kind: Some("veth".to_owned()),
                master: Some(3),
                peer_netns_id: Some(2),
            })
        );
    }
}
