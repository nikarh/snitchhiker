//! Messages, each with a stream's descriptor or none, over a `SOCK_SEQPACKET` unix socket: how the daemon and the
//! desktop app talk to `snitchhiker-remote` (`proto/snitchhiker/v1/bridge.proto`). One message per packet, so a
//! descriptor travels with exactly the message naming it, and a sender needs no lock: the kernel keeps packets whole.
//! Each packet starts with a byte of its own (1), so an empty message isn't taken for the end of the connection.

use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, Shutdown, SocketAddrUnix, SocketFlags, SocketType,
};
use snitchhiker_proto::prost::Message;

/// The largest packet.
pub const MAX: usize = 64 * 1024;

/// The first byte of every packet.
const MARK: u8 = 1;

/// One end of a connection.
#[derive(Debug)]
pub struct Packets {
    fd: OwnedFd,
}

/// Whose process is at the other end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Packets {
    /// Two connected ends.
    pub fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        Ok((Self { fd: a }, Self { fd: b }))
    }

    /// Connects to the listener at `path`.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        rustix::net::connect(&fd, &SocketAddrUnix::new(path)?)?;
        Ok(Self { fd })
    }

    /// An end given as a descriptor (a helper's standard input).
    #[must_use]
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Who is at the other end, as the kernel recorded it when the connection was made.
    pub fn peer(&self) -> io::Result<Peer> {
        let credentials = rustix::net::sockopt::socket_peercred(&self.fd)?;
        Ok(Peer {
            pid: u32::try_from(credentials.pid.as_raw_nonzero().get()).unwrap_or(0),
            uid: credentials.uid.as_raw(),
            gid: credentials.gid.as_raw(),
        })
    }

    /// Sends `message`, with `fd` alongside.
    pub fn send(&self, message: &impl Message, fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(1 + message.encoded_len());
        bytes.push(MARK);
        message.encode(&mut bytes).map_err(io::Error::other)?;
        if bytes.len() > MAX {
            return Err(io::Error::other("a message over 64 KiB"));
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fds;
        if let Some(fd) = fd {
            fds = [fd];
            if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
                return Err(io::Error::other("no room for a descriptor"));
            }
        }
        let sent = rustix::net::sendmsg(
            &self.fd,
            &[IoSlice::new(&bytes)],
            &mut control,
            SendFlags::NOSIGNAL,
        )?;
        if sent == bytes.len() {
            Ok(())
        } else {
            Err(io::Error::other("a message sent in part"))
        }
    }

    /// The next message, and the descriptor that came with it; `None` once the other end is closed.
    pub fn receive<M: Message + Default>(&self) -> io::Result<Option<(M, Option<OwnedFd>)>> {
        let mut buffer = vec![0_u8; MAX];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = loop {
            match rustix::net::recvmsg(
                &self.fd,
                &mut [IoSliceMut::new(&mut buffer)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Err(rustix::io::Errno::INTR) => {}
                other => break other?,
            }
        };
        // Taken first, so a descriptor is closed (not leaked) whatever happens next.
        let mut fd = None;
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = message {
                for received in fds {
                    if fd.is_none() {
                        fd = Some(received);
                    }
                }
            }
        }
        if received.bytes == 0 && fd.is_none() {
            return Ok(None);
        }
        if received
            .flags
            .intersects(rustix::net::ReturnFlags::TRUNC | rustix::net::ReturnFlags::CTRUNC)
        {
            return Err(io::Error::other("a message too large"));
        }
        let Some([MARK, bytes @ ..]) = buffer.get(..received.bytes) else {
            return Err(io::Error::other("not a message"));
        };
        let message = M::decode(bytes).map_err(io::Error::other)?;
        Ok(Some((message, fd)))
    }

    /// Ends the connection both ways, for every holder of it (another thread blocked receiving gets `None`).
    pub fn shutdown(&self) {
        let _ = rustix::net::shutdown(&self.fd, Shutdown::Both);
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
    }
}

impl AsFd for Packets {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl From<Packets> for OwnedFd {
    fn from(packets: Packets) -> Self {
        packets.fd
    }
}

/// A listening socket.
#[derive(Debug)]
pub struct PacketListener {
    fd: OwnedFd,
}

impl PacketListener {
    /// Listens at `path` (replacing whatever is there).
    pub fn bind(path: &Path) -> io::Result<Self> {
        let _ = std::fs::remove_file(path);
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        rustix::net::bind(&fd, &SocketAddrUnix::new(path)?)?;
        rustix::net::listen(&fd, 16)?;
        Ok(Self { fd })
    }

    /// The next connection.
    pub fn accept(&self) -> io::Result<Packets> {
        loop {
            match rustix::net::accept_with(&self.fd, SocketFlags::CLOEXEC) {
                Err(rustix::io::Errno::INTR) => {}
                other => return Ok(Packets { fd: other? }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snitchhiker_proto::v1;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_message_brings_its_descriptor() {
        let (a, b) = Packets::pair().unwrap();
        let (mut near, far) = UnixStream::pair().unwrap();
        let accepted = v1::BridgeFrame {
            body: Some(v1::bridge_frame::Body::Accepted(v1::BridgeAccepted {
                peer: "peer".to_owned(),
                kind: v1::StreamKind::Device.into(),
            })),
        };
        a.send(&accepted, Some(far.as_fd())).unwrap();
        drop(far);
        a.send(&v1::BridgeFrame::default(), None).unwrap();
        let (message, fd) = b.receive::<v1::BridgeFrame>().unwrap().unwrap();
        assert_eq!(message, accepted);
        let mut stream = UnixStream::from(fd.unwrap());
        near.write_all(b"hi").unwrap();
        let mut read = [0; 2];
        stream.read_exact(&mut read).unwrap();
        assert_eq!(&read, b"hi");
        // An empty message is still a message; then the end.
        let (empty, fd) = b.receive::<v1::BridgeFrame>().unwrap().unwrap();
        assert_eq!(empty, v1::BridgeFrame::default());
        assert!(fd.is_none());
        drop(a);
        assert!(b.receive::<v1::BridgeFrame>().unwrap().is_none());
    }
}
