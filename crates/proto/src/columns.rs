//! Columnar blocks: bulk data (event pages, live event batches) as columns of fixed-width little-endian values, read in
//! place from the received buffer.
//!
//! ```text
//! offset  size  field
//!      0     4  magic "SNEB" (an event block)
//!      4     2  format version (1)
//!      6     2  columns in the directory (n)
//!      8     4  rows
//!     12     4  reserved, 0
//!     16     8  base seq (i64): seq column values are added to it
//!     24     8  base time (u64, Unix ms): time column values are added to it
//!     32  8 × n directory: per column, its id (u16), the width of one value in bytes (u16), and the offset of its
//!                values from the start of the block (u32)
//!      …        the columns, each `rows × width` bytes
//! ```
//!
//! A reader finds columns by id and skips ids it doesn't know, so a later format can add columns; a known column with
//! another width is an error. Every value is little-endian; nothing needs alignment.

use zerocopy::byteorder::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The first bytes of an event block.
pub const EVENT_MAGIC: [u8; 4] = *b"SNEB";
/// The block format this build writes and reads.
pub const VERSION: u16 = 1;

const HEADER: usize = 32;
const DIRECTORY_ENTRY: usize = 8;

/// The columns of an event block: their ids and widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Column {
    /// u32: seq − base seq.
    Seq = 1,
    /// u32: time − base time, in ms.
    Time = 2,
    /// u32: the executable's string id.
    Exe = 3,
    /// u32: the host name's string id, 0 for none.
    Host = 4,
    Uid = 5,
    Pid = 6,
    /// 16 bytes: IPv6, or IPv4 mapped into IPv6.
    Address = 7,
    /// u16.
    Port = 8,
    /// u8: the IP protocol.
    Protocol = 9,
    /// u8: the protocol's `Context` number.
    Context = 10,
    /// u8: the protocol's `Action` number.
    Action = 11,
    /// u8: the protocol's `Source` number.
    Source = 12,
    /// u64: the deciding rule's id, 0 for none.
    Rule = 13,
    /// u64.
    BytesOut = 14,
    /// u64.
    BytesIn = 15,
}

impl Column {
    const ALL: [Self; 15] = [
        Self::Seq,
        Self::Time,
        Self::Exe,
        Self::Host,
        Self::Uid,
        Self::Pid,
        Self::Address,
        Self::Port,
        Self::Protocol,
        Self::Context,
        Self::Action,
        Self::Source,
        Self::Rule,
        Self::BytesOut,
        Self::BytesIn,
    ];

    #[must_use]
    pub const fn width(self) -> usize {
        match self {
            Self::Seq | Self::Time | Self::Exe | Self::Host | Self::Uid | Self::Pid => 4,
            Self::Address => 16,
            Self::Port => 2,
            Self::Protocol | Self::Context | Self::Action | Self::Source => 1,
            Self::Rule | Self::BytesOut | Self::BytesIn => 8,
        }
    }

    /// Every column of format 1, in the order the encoder writes them.
    #[must_use]
    pub const fn all() -> [Self; 15] {
        Self::ALL
    }

    /// What the column holds, for the documentation.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Seq => "u32: the event's seq minus the base seq",
            Self::Time => "u32: its time minus the base time, in ms",
            Self::Exe => "u32: the executable's string id",
            Self::Host => "u32: the host name's string id; 0 for none",
            Self::Uid => "u32: the user id",
            Self::Pid => "u32: the process id",
            Self::Address => "16 bytes: the destination, IPv6 or IPv4 mapped into IPv6",
            Self::Port => "u16: the destination port",
            Self::Protocol => "u8: the IP protocol number",
            Self::Context => "u8: a `Context` number",
            Self::Action => "u8: an `Action` number",
            Self::Source => "u8: a `Source` number",
            Self::Rule => "u64: the deciding rule's id; 0 for none",
            Self::BytesOut => "u64: bytes sent",
            Self::BytesIn => "u64: bytes received",
        }
    }

    fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|c| *c as u16 == id)
    }
}

/// One event, as a block holds it: strings are ids into the node's dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventRow {
    pub seq: i64,
    pub time_ms: u64,
    pub exe: u32,
    /// 0: no name.
    pub host: u32,
    pub uid: u32,
    pub pid: u32,
    /// IPv6, or IPv4 mapped into IPv6.
    pub address: [u8; 16],
    pub port: u16,
    pub protocol: u8,
    pub context: u8,
    pub action: u8,
    pub source: u8,
    /// 0: none.
    pub rule: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("not an event block")]
    Magic,
    #[error("block format {0}, this build reads {VERSION}")]
    Version(u16),
    #[error("the block is cut short")]
    Truncated,
    #[error("column {0} has width {1}, expected {2}")]
    Width(u16, u16, usize),
    #[error("column {0} is missing")]
    Missing(u16),
    #[error(
        "rows span more than a block can: seq beyond u32 of the first row, or times beyond u32 of the earliest"
    )]
    Span,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    magic: [u8; 4],
    version: U16,
    columns: U16,
    rows: U32,
    reserved: U32,
    base_seq: U64,
    base_time: U64,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned, IntoBytes)]
#[repr(C)]
struct Entry {
    id: U16,
    width: U16,
    offset: U32,
}

/// Encodes `rows` as an event block into `out` (cleared first). The rows must be ordered by seq, and span less than
/// u32 of seq and of milliseconds from the first; callers split larger ranges into several blocks.
pub fn encode_events(rows: &[EventRow], out: &mut Vec<u8>) -> Result<(), BlockError> {
    out.clear();
    let first = rows.first().copied().unwrap_or_default();
    // Times are offsets from the earliest: the clock may have stepped back between two rows (a later row earlier).
    let base_time = rows.iter().map(|r| r.time_ms).min().unwrap_or(0);
    let count = u32::try_from(rows.len()).map_err(|_| BlockError::Span)?;
    let columns = Column::ALL;
    out.extend_from_slice(&EVENT_MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&u16::try_from(columns.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&first.seq.to_le_bytes());
    out.extend_from_slice(&base_time.to_le_bytes());
    let mut offset = HEADER + columns.len() * DIRECTORY_ENTRY;
    for column in columns {
        let entry = Entry {
            id: U16::new(column as u16),
            width: U16::new(u16::try_from(column.width()).unwrap_or(0)),
            offset: U32::new(u32::try_from(offset).map_err(|_| BlockError::Span)?),
        };
        out.extend_from_slice(entry.as_bytes());
        offset += column.width() * rows.len();
    }
    out.reserve(offset - out.len());
    for column in columns {
        for row in rows {
            write_value(out, column, row, &first, base_time)?;
        }
    }
    Ok(())
}

/// Appends one value of `column`, for `row`, to `out`.
fn write_value(
    out: &mut Vec<u8>,
    column: Column,
    row: &EventRow,
    first: &EventRow,
    base_time: u64,
) -> Result<(), BlockError> {
    let delta = |value: u64, base: u64| {
        u32::try_from(value.wrapping_sub(base)).map_err(|_| BlockError::Span)
    };
    match column {
        Column::Seq => out.extend_from_slice(
            &delta(row.seq.cast_unsigned(), first.seq.cast_unsigned())?.to_le_bytes(),
        ),
        Column::Time => out.extend_from_slice(&delta(row.time_ms, base_time)?.to_le_bytes()),
        Column::Exe => out.extend_from_slice(&row.exe.to_le_bytes()),
        Column::Host => out.extend_from_slice(&row.host.to_le_bytes()),
        Column::Uid => out.extend_from_slice(&row.uid.to_le_bytes()),
        Column::Pid => out.extend_from_slice(&row.pid.to_le_bytes()),
        Column::Address => out.extend_from_slice(&row.address),
        Column::Port => out.extend_from_slice(&row.port.to_le_bytes()),
        Column::Protocol => out.push(row.protocol),
        Column::Context => out.push(row.context),
        Column::Action => out.push(row.action),
        Column::Source => out.push(row.source),
        Column::Rule => out.extend_from_slice(&row.rule.to_le_bytes()),
        Column::BytesOut => out.extend_from_slice(&row.bytes_out.to_le_bytes()),
        Column::BytesIn => out.extend_from_slice(&row.bytes_in.to_le_bytes()),
    }
    Ok(())
}

/// An event block, read in place: the columns are slices of the received buffer.
#[derive(Debug, Clone, Copy)]
pub struct EventBlock<'a> {
    rows: usize,
    base_seq: i64,
    base_time: u64,
    seq: &'a [U32],
    time: &'a [U32],
    exe: &'a [U32],
    host: &'a [U32],
    uid: &'a [U32],
    pid: &'a [U32],
    address: &'a [[u8; 16]],
    port: &'a [U16],
    protocol: &'a [u8],
    context: &'a [u8],
    action: &'a [u8],
    source: &'a [u8],
    rule: &'a [U64],
    bytes_out: &'a [U64],
    bytes_in: &'a [U64],
}

impl<'a> EventBlock<'a> {
    /// Reads a block's header and finds its columns; no value is copied.
    pub fn parse(block: &'a [u8]) -> Result<Self, BlockError> {
        let (header, _) = Header::ref_from_prefix(block).map_err(|_| BlockError::Truncated)?;
        if header.magic != EVENT_MAGIC {
            return Err(BlockError::Magic);
        }
        if header.version.get() != VERSION {
            return Err(BlockError::Version(header.version.get()));
        }
        let rows = usize::try_from(header.rows.get()).map_err(|_| BlockError::Truncated)?;
        let count = usize::from(header.columns.get());
        let directory = block
            .get(HEADER..HEADER + count * DIRECTORY_ENTRY)
            .ok_or(BlockError::Truncated)?;
        let entries = <[Entry]>::ref_from_bytes(directory).map_err(|_| BlockError::Truncated)?;
        let find = |column: Column| -> Result<&'a [u8], BlockError> {
            let entry = entries
                .iter()
                .find(|e| Column::from_id(e.id.get()) == Some(column))
                .ok_or(BlockError::Missing(column as u16))?;
            if usize::from(entry.width.get()) != column.width() {
                return Err(BlockError::Width(
                    entry.id.get(),
                    entry.width.get(),
                    column.width(),
                ));
            }
            let start = usize::try_from(entry.offset.get()).map_err(|_| BlockError::Truncated)?;
            block
                .get(start..start + rows * column.width())
                .ok_or(BlockError::Truncated)
        };
        let u32s =
            |c| find(c).and_then(|b| <[U32]>::ref_from_bytes(b).map_err(|_| BlockError::Truncated));
        let u64s =
            |c| find(c).and_then(|b| <[U64]>::ref_from_bytes(b).map_err(|_| BlockError::Truncated));
        Ok(Self {
            rows,
            base_seq: i64::from_le_bytes(header.base_seq.get().to_le_bytes()),
            base_time: header.base_time.get(),
            seq: u32s(Column::Seq)?,
            time: u32s(Column::Time)?,
            exe: u32s(Column::Exe)?,
            host: u32s(Column::Host)?,
            uid: u32s(Column::Uid)?,
            pid: u32s(Column::Pid)?,
            address: <[[u8; 16]]>::ref_from_bytes(find(Column::Address)?)
                .map_err(|_| BlockError::Truncated)?,
            port: <[U16]>::ref_from_bytes(find(Column::Port)?)
                .map_err(|_| BlockError::Truncated)?,
            protocol: find(Column::Protocol)?,
            context: find(Column::Context)?,
            action: find(Column::Action)?,
            source: find(Column::Source)?,
            rule: u64s(Column::Rule)?,
            bytes_out: u64s(Column::BytesOut)?,
            bytes_in: u64s(Column::BytesIn)?,
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.rows
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// Row `index`; `None` past the end.
    #[must_use]
    pub fn row(&self, index: usize) -> Option<EventRow> {
        Some(EventRow {
            seq: self
                .base_seq
                .wrapping_add(i64::from(self.seq.get(index)?.get())),
            time_ms: self
                .base_time
                .wrapping_add(u64::from(self.time.get(index)?.get())),
            exe: self.exe.get(index)?.get(),
            host: self.host.get(index)?.get(),
            uid: self.uid.get(index)?.get(),
            pid: self.pid.get(index)?.get(),
            address: *self.address.get(index)?,
            port: self.port.get(index)?.get(),
            protocol: *self.protocol.get(index)?,
            context: *self.context.get(index)?,
            action: *self.action.get(index)?,
            source: *self.source.get(index)?,
            rule: self.rule.get(index)?.get(),
            bytes_out: self.bytes_out.get(index)?.get(),
            bytes_in: self.bytes_in.get(index)?.get(),
        })
    }

    /// The rows, in order.
    pub fn rows(&self) -> impl Iterator<Item = EventRow> + '_ {
        (0..self.rows).filter_map(|i| self.row(i))
    }

    /// The executables' string ids, without decoding the rest: for filtering and counting in place.
    pub fn exe_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.exe.iter().map(|v| v.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(seq: i64) -> EventRow {
        EventRow {
            seq,
            time_ms: 1_763_200_000_000 + u64::try_from(seq).unwrap() * 7,
            exe: 3,
            host: u32::try_from(seq % 2).unwrap(),
            uid: 1000,
            pid: 4242,
            address: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 443,
            protocol: 6,
            context: 1,
            action: 1,
            source: 1,
            rule: 18,
            bytes_out: 517,
            bytes_in: u64::MAX,
        }
    }

    #[test]
    fn round_trips() {
        let rows: Vec<EventRow> = (100..164).map(row).collect();
        let mut block = Vec::new();
        encode_events(&rows, &mut block).unwrap();
        let parsed = EventBlock::parse(&block).unwrap();
        assert_eq!(parsed.len(), rows.len());
        assert_eq!(parsed.rows().collect::<Vec<_>>(), rows);
        assert!(parsed.exe_ids().all(|id| id == 3));
        assert_eq!(parsed.row(64), None);
        // 70 bytes a row (six u32, the address, a u16, four u8, three u64), and the header and directory.
        assert_eq!(block.len(), HEADER + 15 * DIRECTORY_ENTRY + 64 * 70);
    }

    #[test]
    fn empty_blocks_are_fine() {
        let mut block = Vec::new();
        encode_events(&[], &mut block).unwrap();
        assert!(EventBlock::parse(&block).unwrap().is_empty());
    }

    #[test]
    fn unknown_columns_are_skipped_and_wrong_widths_refused() {
        let mut block = Vec::new();
        encode_events(&[row(1)], &mut block).unwrap();
        // Rename the first column (seq) to an unknown id: it is then missing.
        let mut unknown = block.clone();
        unknown[HEADER..HEADER + 2].copy_from_slice(&99_u16.to_le_bytes());
        assert_eq!(
            EventBlock::parse(&unknown).err(),
            Some(BlockError::Missing(1))
        );
        let mut wide = block.clone();
        wide[HEADER + 2..HEADER + 4].copy_from_slice(&8_u16.to_le_bytes());
        assert_eq!(
            EventBlock::parse(&wide).err(),
            Some(BlockError::Width(1, 8, 4))
        );
        assert_eq!(
            EventBlock::parse(&block[..40]).err(),
            Some(BlockError::Truncated)
        );
        assert_eq!(
            EventBlock::parse(b"nope, not a block at all, really......").err(),
            Some(BlockError::Magic)
        );
    }

    #[test]
    fn a_clock_stepped_back_still_encodes() {
        let mut earlier = row(2);
        earlier.time_ms = row(1).time_ms - 5_000;
        let mut block = Vec::new();
        encode_events(&[row(1), earlier], &mut block).unwrap();
        let rows: Vec<EventRow> = EventBlock::parse(&block).unwrap().rows().collect();
        assert_eq!(rows, vec![row(1), earlier]);
    }

    #[test]
    fn rows_spanning_too_much_are_refused() {
        let mut far = row(2);
        far.time_ms += u64::from(u32::MAX) + 1;
        assert_eq!(
            encode_events(&[row(1), far], &mut Vec::new()),
            Err(BlockError::Span)
        );
    }
}
