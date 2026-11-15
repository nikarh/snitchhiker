//! NFQUEUE: packets that the table's `queue` rules hold until the daemon decides.
//!
//! A [`Queue`] is bound to one queue number and is read by one thread. Packets are views into the receive buffer, and
//! verdicts are written into a buffer of their own, so a steady stream of packets allocates nothing.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;

use netlink_sys::{Socket as RawSocket, SocketAddr, protocols::NETLINK_NETFILTER};

use crate::netlink::{
    AF_UNSPEC, NFGENMSG_LEN, NFNL_SUBSYS_QUEUE, NLM_F_ACK, NLMSG_ERROR, Writer, ack_error,
    attributes, messages,
};

const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
const NFQA_CFG_F_FAIL_OPEN: u32 = 0x01;
const NFQA_CFG_F_UID_GID: u32 = 0x08;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_IFINDEX_INDEV: u16 = 5;
const NFQA_IFINDEX_OUTDEV: u16 = 6;
const NFQA_HWADDR: u16 = 9;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_UID: u16 = 16;
const NFQA_GID: u16 = 17;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

/// Enough of a packet for its IP and transport headers (and IPv6 extension headers in front of them).
pub const HEADERS: u32 = 256;
/// Packets the kernel holds for a queue before it drops new ones (never letting them through: see [`Queue::bind`]).
const MAX_LENGTH: u32 = 4096;
/// The socket's receive buffer. `SO_RCVBUF` is capped at `net.core.rmem_max`, so `SO_RCVBUFFORCE` is tried first.
const RECEIVE_BUFFER: usize = 8 << 20;
/// A datagram from the kernel: headers, small attributes, the copied part of the packet.
const RECEIVE_CAPACITY: usize = 1 << 16;

/// What happens to a held packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// A packet the kernel holds, borrowed from the queue's receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    /// The id verdicts refer to.
    pub id: u32,
    /// Ether type: 0x0800 IPv4, 0x86dd IPv6.
    pub protocol: u16,
    pub mark: u32,
    /// The netfilter hook it was queued at (`NF_INET_LOCAL_OUT`, `NF_INET_FORWARD`, ...).
    pub hook: u8,
    pub in_interface: Option<u32>,
    pub out_interface: Option<u32>,
    /// The link-layer source address, for a packet that came in on an interface that has one (a forwarded packet's
    /// sender on a bridge).
    pub source_mac: Option<[u8; 6]>,
    /// The owner of the sending socket, when the kernel knows it (`NFQA_CFG_F_UID_GID`).
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// The packet from its IP header on, as much of it as the queue copies.
    pub payload: &'a [u8],
}

/// A queue bound to one queue number.
#[derive(Debug)]
pub struct Queue {
    socket: RawSocket,
    number: u16,
    receive: Vec<u8>,
    send: Writer,
    sequence: u32,
}

impl Queue {
    /// Binds queue `number`. When the queue is full the kernel drops new packets: overflow never lets traffic
    /// through (`NFQA_CFG_F_FAIL_OPEN` is explicitly cleared), so flooding the queue cannot open the firewall.
    pub fn bind(number: u16) -> io::Result<Self> {
        Self::bind_copying(number, HEADERS)
    }

    /// Like [`Queue::bind`], copying up to `copy_range` bytes of each packet (for queues that read payloads).
    pub fn bind_copying(number: u16, copy_range: u32) -> io::Result<Self> {
        let mut socket = RawSocket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        if socket.set_rx_buf_sz(RECEIVE_BUFFER).is_err() {
            // Best effort: bursts beyond the default buffer are dropped by the kernel, as with a full queue.
        }
        let mut queue = Self {
            socket,
            number,
            receive: Vec::with_capacity(RECEIVE_CAPACITY),
            send: Writer::new(),
            sequence: 0,
        };
        queue.configure(|w| {
            // `struct nfqnl_msg_config_cmd`: command, padding, protocol family (ignored since Linux 3.8).
            let [pf_high, pf_low] = u16::from(AF_UNSPEC).to_be_bytes();
            w.attribute(NFQA_CFG_CMD, &[NFQNL_CFG_CMD_BIND, 0, pf_high, pf_low]);
        })?;
        queue.configure(|w| {
            // `struct nfqnl_msg_config_params`: copy range, copy mode.
            let [a, b, c, d] = copy_range.to_be_bytes();
            w.attribute(NFQA_CFG_PARAMS, &[a, b, c, d, NFQNL_COPY_PACKET]);
            w.u32_be(NFQA_CFG_QUEUE_MAXLEN, MAX_LENGTH);
        })?;
        queue.configure(|w| {
            w.u32_be(NFQA_CFG_MASK, NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_UID_GID);
            w.u32_be(NFQA_CFG_FLAGS, NFQA_CFG_F_UID_GID);
        })?;
        Ok(queue)
    }

    #[must_use]
    pub fn number(&self) -> u16 {
        self.number
    }

    fn configure(&mut self, attributes: impl FnOnce(&mut Writer)) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        self.send.clear();
        let message = self.send.begin(
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            NLM_F_ACK,
            self.sequence,
            AF_UNSPEC,
            self.number,
        );
        attributes(&mut self.send);
        self.send.finish(message);
        self.socket.send(self.send.bytes(), 0)?;
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

    /// Blocks until the kernel sends packets, and returns them (often one, sometimes a burst).
    pub fn receive(&mut self) -> io::Result<impl Iterator<Item = Packet<'_>>> {
        self.receive.clear();
        self.socket.recv(&mut self.receive, 0)?;
        Ok(parse(&self.receive))
    }

    /// A handle that decides this queue's packets from another thread (packets held for a prompt). The kernel takes
    /// verdicts only from the socket the queue is bound to; the handle writes to a duplicate of its descriptor, which
    /// is the same socket.
    pub fn verdict_writer(&self) -> io::Result<VerdictWriter> {
        Ok(VerdictWriter {
            socket: File::from(self.socket.as_fd().try_clone_to_owned()?),
            number: self.number,
            buffer: Writer::new(),
        })
    }

    /// Decides what happens to a held packet.
    pub fn verdict(&mut self, id: u32, verdict: Verdict) -> io::Result<()> {
        encode_verdict(&mut self.send, self.number, id, verdict);
        self.socket.send(self.send.bytes(), 0)?;
        Ok(())
    }
}

/// Decides a queue's packets from another thread: see [`Queue::verdict_writer`].
#[derive(Debug)]
pub struct VerdictWriter {
    socket: File,
    number: u16,
    buffer: Writer,
}

impl VerdictWriter {
    #[must_use]
    pub fn number(&self) -> u16 {
        self.number
    }

    pub fn verdict(&mut self, id: u32, verdict: Verdict) -> io::Result<()> {
        encode_verdict(&mut self.buffer, self.number, id, verdict);
        // One write is one datagram: one netlink message.
        let written = (&self.socket).write(self.buffer.bytes())?;
        if written == self.buffer.bytes().len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink write",
            ))
        }
    }
}

/// The packets in a received buffer.
pub fn parse(buffer: &[u8]) -> impl Iterator<Item = Packet<'_>> {
    messages(buffer)
        .filter(|message| message.kind == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)
        .filter_map(|message| {
            let mut packet = Packet {
                id: 0,
                protocol: 0,
                mark: 0,
                hook: 0,
                in_interface: None,
                out_interface: None,
                source_mac: None,
                uid: None,
                gid: None,
                payload: &[],
            };
            let mut has_header = false;
            for (kind, value) in attributes(message.body.get(NFGENMSG_LEN..)?) {
                match kind {
                    // `struct nfqnl_msg_packet_hdr`: packet id, ether type, hook.
                    NFQA_PACKET_HDR => {
                        packet.id = be_u32(value)?;
                        packet.protocol = u16::from_be_bytes(value.get(4..6)?.try_into().ok()?);
                        packet.hook = *value.get(6)?;
                        has_header = true;
                    }
                    NFQA_MARK => packet.mark = be_u32(value)?,
                    NFQA_IFINDEX_INDEV => packet.in_interface = be_u32(value),
                    NFQA_IFINDEX_OUTDEV => packet.out_interface = be_u32(value),
                    // `struct nfqnl_msg_packet_hw`: address length (big-endian u16), padding, the address.
                    NFQA_HWADDR => {
                        if value.get(0..2) == Some(&[0, 6][..]) {
                            packet.source_mac =
                                value.get(4..10).and_then(|mac| mac.try_into().ok());
                        }
                    }
                    NFQA_UID => packet.uid = be_u32(value),
                    NFQA_GID => packet.gid = be_u32(value),
                    NFQA_PAYLOAD => packet.payload = value,
                    _ => {}
                }
            }
            has_header.then_some(packet)
        })
}

/// Writes the verdict message for one packet.
pub fn encode_verdict(writer: &mut Writer, queue: u16, id: u32, verdict: Verdict) {
    writer.clear();
    let message = writer.begin(
        (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
        0,
        0,
        AF_UNSPEC,
        queue,
    );
    let code = match verdict {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
    };
    // `struct nfqnl_msg_verdict_hdr`: verdict, packet id.
    let [c0, c1, c2, c3] = code.to_be_bytes();
    let [i0, i1, i2, i3] = id.to_be_bytes();
    writer.attribute(NFQA_VERDICT_HDR, &[c0, c1, c2, c3, i0, i1, i2, i3]);
    writer.finish(message);
}

fn be_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(value.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{NFGENMSG_LEN, attributes, messages};

    #[test]
    fn verdicts_name_the_queue_packet_and_decision() {
        let mut writer = Writer::new();
        encode_verdict(&mut writer, 3, 0xabcd, Verdict::Drop);
        let message = messages(writer.bytes()).next().unwrap();
        assert_eq!(message.kind, (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT);
        assert_eq!(&message.body[2..4], &3_u16.to_be_bytes());
        let (kind, header) = attributes(&message.body[NFGENMSG_LEN..]).next().unwrap();
        assert_eq!(kind, NFQA_VERDICT_HDR);
        assert_eq!(header, &[0, 0, 0, 0, 0, 0, 0xab, 0xcd]);
    }

    #[test]
    fn parses_packets_from_a_kernel_message() {
        let mut writer = Writer::new();
        let message = writer.begin(
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET,
            0,
            0,
            AF_UNSPEC,
            0,
        );
        writer.attribute(NFQA_PACKET_HDR, &[0, 0, 0, 7, 0x08, 0x00, 2, 0]);
        writer.u32_be(NFQA_UID, 1001);
        writer.u32_be(NFQA_IFINDEX_INDEV, 5);
        writer.u32_be(NFQA_IFINDEX_OUTDEV, 2);
        writer.attribute(NFQA_HWADDR, &[0, 6, 0, 0, 2, 0x42, 0xac, 0x11, 0, 2, 0, 0]);
        writer.attribute(NFQA_PAYLOAD, &[0x45, 0, 0, 20]);
        writer.finish(message);
        let packets: Vec<_> = parse(writer.bytes()).collect();
        assert_eq!(
            packets,
            vec![Packet {
                id: 7,
                protocol: 0x0800,
                mark: 0,
                hook: 2,
                in_interface: Some(5),
                out_interface: Some(2),
                source_mac: Some([2, 0x42, 0xac, 0x11, 0, 2]),
                uid: Some(1001),
                gid: None,
                payload: &[0x45, 0, 0, 20],
            }]
        );
    }

    #[test]
    fn ignores_messages_without_a_packet_header() {
        let mut writer = Writer::new();
        let message = writer.begin(
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET,
            0,
            0,
            AF_UNSPEC,
            0,
        );
        writer.attribute(NFQA_PAYLOAD, &[0x45]);
        writer.finish(message);
        assert_eq!(parse(writer.bytes()).count(), 0);
    }
}
