//! Frames: a little-endian u32 length and a protobuf message; and the local connection's preamble.

use std::io::{self, Read, Write};

use prost::Message;

use crate::{MAGIC, MAJOR, MAX_FRAME};

/// Writes `message` as one frame, building it in `buffer` (kept between frames) and writing it at once.
pub fn write<M: Message>(
    out: &mut impl Write,
    message: &M,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    buffer.clear();
    let length = message.encoded_len();
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    buffer.reserve(4 + length);
    buffer.extend_from_slice(&u32::try_from(length).unwrap_or(u32::MAX).to_le_bytes());
    message
        .encode(buffer)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    out.write_all(buffer)
}

/// Reads one frame into `buffer` (kept between frames) and decodes it. A frame larger than the limit, or one that
/// doesn't decode, is an `InvalidData` error: the connection is then unusable.
pub fn read<M: Message + Default>(input: &mut impl Read, buffer: &mut Vec<u8>) -> io::Result<M> {
    let mut length = [0_u8; 4];
    input.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    buffer.clear();
    buffer.resize(length, 0);
    input.read_exact(buffer)?;
    M::decode(buffer.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The client's preamble on a local connection.
pub fn write_preamble(out: &mut impl Write) -> io::Result<()> {
    let mut preamble = [0_u8; 6];
    let (magic, major) = preamble.split_at_mut(4);
    magic.copy_from_slice(&MAGIC);
    major.copy_from_slice(&MAJOR.to_le_bytes());
    out.write_all(&preamble)
}

/// Reads the client's preamble; returns the major version it asks for.
pub fn read_preamble(input: &mut impl Read) -> io::Result<u16> {
    let mut preamble = [0_u8; 6];
    input.read_exact(&mut preamble)?;
    let (magic, major) = preamble.split_at(4);
    if magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not the Snitchhiker protocol",
        ));
    }
    Ok(u16::from_le_bytes([
        major.first().copied().unwrap_or(0),
        major.get(1).copied().unwrap_or(0),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1;

    #[test]
    fn frames_round_trip() {
        let frame = v1::ClientFrame {
            body: Some(v1::client_frame::Body::Hello(v1::Hello {
                minor: 3,
                app: "cli".into(),
                app_version: "0.1.0".into(),
                capabilities: vec!["prompts".into()],
            })),
        };
        let mut wire = Vec::new();
        let mut buffer = Vec::new();
        write(&mut wire, &frame, &mut buffer).unwrap();
        write(&mut wire, &frame, &mut buffer).unwrap();
        let mut reader = wire.as_slice();
        let first: v1::ClientFrame = read(&mut reader, &mut buffer).unwrap();
        let second: v1::ClientFrame = read(&mut reader, &mut buffer).unwrap();
        assert_eq!(first, frame);
        assert_eq!(second, frame);
        assert_eq!(reader, &[] as &[u8]);
    }

    #[test]
    fn refuses_oversized_frames_before_reading_them() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::MAX.to_le_bytes());
        let error = read::<v1::ClientFrame>(&mut wire.as_slice(), &mut Vec::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn preamble_names_the_major_version() {
        let mut wire = Vec::new();
        write_preamble(&mut wire).unwrap();
        assert_eq!(read_preamble(&mut wire.as_slice()).unwrap(), MAJOR);
        assert!(read_preamble(&mut &b"HTTP/1"[..]).is_err());
    }
}
