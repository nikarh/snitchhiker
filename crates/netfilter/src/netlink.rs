//! Netlink messages for the netfilter subsystems: a writer that builds them into a reused buffer, a parser that reads
//! them in place, and a socket that sends a batch and collects the kernel's answers.
//!
//! Nothing here allocates once the buffers have grown to their working size.

use std::io;

use netlink_sys::{Socket as RawSocket, SocketAddr, protocols::NETLINK_NETFILTER};

/// Length of `struct nlmsghdr`.
pub const NLMSG_HDRLEN: usize = 16;
/// Length of `struct nfgenmsg`, which follows the header of every netfilter message.
pub const NFGENMSG_LEN: usize = 4;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

pub const NFNL_SUBSYS_QUEUE: u16 = 3;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
pub const NFNL_MSG_BATCH_END: u16 = 0x11;

pub const AF_UNSPEC: u8 = 0;
pub const NFPROTO_INET: u8 = 1;

/// Netlink attributes and messages are aligned to four bytes.
#[must_use]
pub const fn align4(length: usize) -> usize {
    (length + 3) & !3
}

/// Builds netlink messages into a buffer that is kept from one batch to the next.
#[derive(Debug, Default)]
pub struct Writer {
    buffer: Vec<u8>,
}

/// A message or nested attribute being written; its length is filled in when it is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Open(usize);

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget what was written, keeping the capacity.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Start a netfilter message: the netlink header, then `nfgenmsg` with the family and resource id.
    pub fn begin(
        &mut self,
        kind: u16,
        flags: u16,
        sequence: u32,
        family: u8,
        resource: u16,
    ) -> Open {
        let start = self.buffer.len();
        self.buffer.extend_from_slice(&0_u32.to_ne_bytes());
        self.buffer.extend_from_slice(&kind.to_ne_bytes());
        self.buffer
            .extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        self.buffer.extend_from_slice(&sequence.to_ne_bytes());
        self.buffer.extend_from_slice(&0_u32.to_ne_bytes());
        self.buffer.extend_from_slice(&[family, 0]);
        self.buffer.extend_from_slice(&resource.to_be_bytes());
        Open(start)
    }

    /// Close a message: write its length.
    pub fn finish(&mut self, message: Open) {
        let length = u32::try_from(self.buffer.len() - message.0).unwrap_or(u32::MAX);
        if let Some(field) = self.buffer.get_mut(message.0..message.0 + 4) {
            field.copy_from_slice(&length.to_ne_bytes());
        }
    }

    /// An attribute with raw bytes as its value, padded to four bytes.
    pub fn attribute(&mut self, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        self.buffer
            .extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
        self.buffer.extend_from_slice(&kind.to_ne_bytes());
        self.buffer.extend_from_slice(value);
        self.buffer
            .resize(self.buffer.len() + align4(length) - length, 0);
    }

    /// A NUL-terminated string attribute.
    pub fn string(&mut self, kind: u16, value: &str) {
        let length = 4 + value.len() + 1;
        self.buffer
            .extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
        self.buffer.extend_from_slice(&kind.to_ne_bytes());
        self.buffer.extend_from_slice(value.as_bytes());
        self.buffer.push(0);
        self.buffer
            .resize(self.buffer.len() + align4(length) - length, 0);
    }

    /// A big-endian `u32` attribute (`nf_tables` numbers are in network order).
    pub fn u32_be(&mut self, kind: u16, value: u32) {
        self.attribute(kind, &value.to_be_bytes());
    }

    /// A big-endian `u16` attribute.
    pub fn u16_be(&mut self, kind: u16, value: u16) {
        self.attribute(kind, &value.to_be_bytes());
    }

    /// Open a nested attribute; close it with [`Writer::end`].
    pub fn nest(&mut self, kind: u16) -> Open {
        let start = self.buffer.len();
        self.buffer.extend_from_slice(&0_u16.to_ne_bytes());
        self.buffer
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        Open(start)
    }

    pub fn end(&mut self, nested: Open) {
        let length = u16::try_from(self.buffer.len() - nested.0).unwrap_or(u16::MAX);
        if let Some(field) = self.buffer.get_mut(nested.0..nested.0 + 2) {
            field.copy_from_slice(&length.to_ne_bytes());
        }
    }
}

/// A netlink message, borrowed from the buffer it was received into.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub sequence: u32,
    /// Everything after the netlink header (for netfilter messages, `nfgenmsg` and the attributes).
    pub body: &'a [u8],
}

/// The messages in a received buffer. Stops at the first malformed one.
pub fn messages(buffer: &[u8]) -> impl Iterator<Item = Message<'_>> {
    let mut rest = buffer;
    std::iter::from_fn(move || {
        let header = rest.get(..NLMSG_HDRLEN)?;
        let length =
            usize::try_from(u32::from_ne_bytes(header.get(0..4)?.try_into().ok()?)).ok()?;
        if length < NLMSG_HDRLEN {
            return None;
        }
        let message = Message {
            kind: u16::from_ne_bytes(header.get(4..6)?.try_into().ok()?),
            flags: u16::from_ne_bytes(header.get(6..8)?.try_into().ok()?),
            sequence: u32::from_ne_bytes(header.get(8..12)?.try_into().ok()?),
            body: rest.get(NLMSG_HDRLEN..length)?,
        };
        rest = rest.get(align4(length)..).unwrap_or_default();
        Some(message)
    })
}

/// The attributes in a buffer, as (type without flags, value). Stops at the first malformed one.
pub fn attributes(buffer: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut rest = buffer;
    std::iter::from_fn(move || {
        let length = usize::from(u16::from_ne_bytes(rest.get(0..2)?.try_into().ok()?));
        let kind = u16::from_ne_bytes(rest.get(2..4)?.try_into().ok()?) & NLA_TYPE_MASK;
        if length < 4 {
            return None;
        }
        let value = rest.get(4..length)?;
        rest = rest.get(align4(length)..).unwrap_or_default();
        Some((kind, value))
    })
}

/// The error code of an `NLMSG_ERROR` message: 0 for an acknowledgement, a negative errno otherwise.
#[must_use]
pub fn ack_error(body: &[u8]) -> i32 {
    body.get(0..4)
        .and_then(|bytes| bytes.try_into().ok())
        // A truncated error message: EINVAL.
        .map_or(-22, i32::from_ne_bytes)
}

/// A netfilter netlink socket with a receive buffer kept between calls.
#[derive(Debug)]
pub struct Socket {
    socket: RawSocket,
    receive: Vec<u8>,
}

impl Socket {
    pub fn open() -> io::Result<Self> {
        let mut socket = RawSocket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            receive: Vec::with_capacity(1 << 16),
        })
    }

    /// Send the messages `writer` holds, numbered `first..=last`, and wait for the kernel's acknowledgement of each.
    /// The first error fails the whole batch (the kernel then discards it).
    pub fn transact(&mut self, writer: &Writer, first: u32, last: u32) -> io::Result<()> {
        self.socket.send(writer.bytes(), 0)?;
        let mut failure = None;
        loop {
            self.receive.clear();
            self.socket.recv(&mut self.receive, 0)?;
            for message in messages(&self.receive) {
                if message.kind != NLMSG_ERROR || !in_range(message.sequence, first, last) {
                    continue;
                }
                let code = ack_error(message.body);
                if code != 0 && failure.is_none() {
                    failure = Some(io::Error::from_raw_os_error(-code));
                }
                if message.sequence == last {
                    return failure.map_or(Ok(()), Err);
                }
            }
        }
    }
}

/// Whether `sequence` is one of `first..=last`, across wrapping.
#[must_use]
pub fn in_range(sequence: u32, first: u32, last: u32) -> bool {
    sequence.wrapping_sub(first) <= last.wrapping_sub(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_back_a_message_with_nested_attributes() {
        let mut writer = Writer::new();
        let message = writer.begin(0x0a00, NLM_F_ACK, 7, NFPROTO_INET, 0);
        writer.string(1, "abc");
        let nested = writer.nest(4);
        writer.u32_be(2, 0x0102_0304);
        writer.end(nested);
        writer.finish(message);

        let read: Vec<_> = messages(writer.bytes()).collect();
        assert_eq!(read.len(), 1);
        let message = read[0];
        assert_eq!(message.kind, 0x0a00);
        assert_eq!(message.flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(message.sequence, 7);
        assert_eq!(message.body[0], NFPROTO_INET);
        let attrs: Vec<_> = attributes(&message.body[NFGENMSG_LEN..]).collect();
        assert_eq!(attrs[0], (1, &b"abc\0"[..]));
        assert_eq!(attrs[1].0, 4);
        let inner: Vec<_> = attributes(attrs[1].1).collect();
        assert_eq!(inner, vec![(2, &[1, 2, 3, 4][..])]);
    }

    #[test]
    fn messages_stop_at_truncated_input() {
        let mut writer = Writer::new();
        let message = writer.begin(1, 0, 1, AF_UNSPEC, 0);
        writer.finish(message);
        let bytes = writer.bytes();
        assert_eq!(messages(&bytes[..bytes.len() - 1]).count(), 0);
    }

    #[test]
    fn ranges_wrap() {
        assert!(in_range(7, 7, 9));
        assert!(in_range(9, 7, 9));
        assert!(!in_range(10, 7, 9));
        assert!(in_range(0, u32::MAX, 1));
    }
}
