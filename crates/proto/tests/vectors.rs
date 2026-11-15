//! The conformance vectors in `proto/vectors/v1/` (see its README): every text-format message encodes to its frame,
//! and every frame decodes to its message.

#![allow(
    clippy::unwrap_used,
    reason = "a test's helpers: a vector that can't be read fails the test"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage};
use snitchhiker_proto::{frame, v1};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto")
}

fn pool() -> DescriptorPool {
    let files = protox::compile(["snitchhiker/v1/client.proto"], [root()]).unwrap();
    DescriptorPool::from_file_descriptor_set(files).unwrap()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for line in bytes.chunks(32) {
        for byte in line {
            let _ = write!(text, "{byte:02x}");
        }
        text.push('\n');
    }
    text
}

fn from_hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Decodes a frame with the generated types and encodes it again: what the reference implementation makes of it.
fn round_trip(message: &str, frame_bytes: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut input = frame_bytes;
    let encoded = match message {
        "snitchhiker.v1.ClientFrame" => frame::read::<v1::ClientFrame>(&mut input, &mut buffer)
            .unwrap()
            .encode_to_vec(),
        "snitchhiker.v1.ServerFrame" => frame::read::<v1::ServerFrame>(&mut input, &mut buffer)
            .unwrap()
            .encode_to_vec(),
        other => panic!("no vectors of {other}"),
    };
    assert!(input.is_empty(), "bytes after the frame");
    encoded
}

#[test]
fn preamble() {
    let mut preamble = Vec::new();
    frame::write_preamble(&mut preamble).unwrap();
    let expected = fs::read_to_string(root().join("vectors/v1/00-preamble.hex")).unwrap();
    assert_eq!(preamble, from_hex(&expected));
}

#[test]
fn frames() {
    let pool = pool();
    let update = std::env::var_os("SNITCHHIKER_UPDATE_VECTORS").is_some();
    let mut paths: Vec<PathBuf> = fs::read_dir(root().join("vectors/v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "textproto"))
        .collect();
    paths.sort();
    assert!(paths.len() >= 14, "vectors are missing");
    for path in paths {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap();
        let message = text
            .lines()
            .find_map(|line| line.strip_prefix("# message: "))
            .unwrap_or_else(|| panic!("{name}: no `# message:` line"))
            .trim();
        let decode_only = text.lines().any(|line| line.trim() == "# decode-only");
        let descriptor = pool
            .get_message_by_name(message)
            .unwrap_or_else(|| panic!("{name}: unknown message {message}"));
        let parsed = DynamicMessage::parse_text_format(descriptor, &text)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let payload = parsed.encode_to_vec();
        let mut expected = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        expected.extend_from_slice(&payload);

        let hex_path = path.with_extension("hex");
        if !hex_path.exists() {
            assert!(
                update && !decode_only,
                "{name}: no .hex (SNITCHHIKER_UPDATE_VECTORS=1 writes it)"
            );
            fs::write(&hex_path, to_hex(&expected)).unwrap();
        }
        let frame_bytes = from_hex(&fs::read_to_string(&hex_path).unwrap());
        if !decode_only {
            assert_eq!(
                to_hex(&frame_bytes),
                to_hex(&expected),
                "{name}: the message no longer encodes to its frame"
            );
        }
        assert_eq!(
            round_trip(message, &frame_bytes),
            payload,
            "{name}: the frame doesn't decode to the message"
        );
    }
}

/// `blocks/<name>.txt` as rows: `name value` lines, rows separated by blank lines.
fn rows(text: &str) -> Vec<snitchhiker_proto::columns::EventRow> {
    text.split("\n\n")
        .map(|chunk| {
            let mut row = snitchhiker_proto::columns::EventRow::default();
            for line in chunk
                .lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            {
                let (name, value) = line.split_once(' ').unwrap();
                let number = || value.parse::<u64>().unwrap();
                match name {
                    "seq" => row.seq = value.parse().unwrap(),
                    "time_ms" => row.time_ms = number(),
                    "exe" => row.exe = u32::try_from(number()).unwrap(),
                    "host" => row.host = u32::try_from(number()).unwrap(),
                    "uid" => row.uid = u32::try_from(number()).unwrap(),
                    "pid" => row.pid = u32::try_from(number()).unwrap(),
                    "address" => row.address = from_hex(value).try_into().unwrap(),
                    "port" => row.port = u16::try_from(number()).unwrap(),
                    "protocol" => row.protocol = u8::try_from(number()).unwrap(),
                    "context" => row.context = u8::try_from(number()).unwrap(),
                    "action" => row.action = u8::try_from(number()).unwrap(),
                    "source" => row.source = u8::try_from(number()).unwrap(),
                    "rule" => row.rule = number(),
                    "bytes_out" => row.bytes_out = number(),
                    "bytes_in" => row.bytes_in = number(),
                    other => panic!("unknown field {other}"),
                }
            }
            row
        })
        .collect()
}

#[test]
fn event_blocks() {
    let dir = root().join("vectors/v1/blocks");
    let update = std::env::var_os("SNITCHHIKER_UPDATE_VECTORS").is_some();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let expected = rows(&fs::read_to_string(&path).unwrap());
        let mut encoded = Vec::new();
        snitchhiker_proto::columns::encode_events(&expected, &mut encoded).unwrap();
        let hex_path = path.with_extension("hex");
        if !hex_path.exists() {
            assert!(
                update,
                "{}: no .hex (SNITCHHIKER_UPDATE_VECTORS=1 writes it)",
                path.display()
            );
            fs::write(&hex_path, to_hex(&encoded)).unwrap();
        }
        let block = from_hex(&fs::read_to_string(&hex_path).unwrap());
        assert_eq!(
            to_hex(&encoded),
            to_hex(&block),
            "{}: the rows no longer encode to the block",
            path.display()
        );
        let parsed = snitchhiker_proto::columns::EventBlock::parse(&block).unwrap();
        assert_eq!(
            parsed.rows().collect::<Vec<_>>(),
            expected,
            "{}",
            path.display()
        );
    }
}
