# 0007. Bulk data as columnar blocks

Status: accepted (M2)

## Context

The plan (§11.5) puts bulk data, event pages and live event batches, in columnar blocks: fixed-width little-endian
columns read in place, strings as ids into a per-node dictionary sent once per connection. FlatBuffers and rkyv were
to be weighed against them, and the blocks kept unless a benchmark showed a clear win.

## What was measured

`crates/wire-bench` (`cargo run --release -p snitchhiker-wire-bench`) encodes the same 10 000 events four ways: a few
programs, a couple of hundred hosts, ports that repeat, as the history looks. Reading means decoding, then summing one
field and counting distinct programs over every event; each reader is checked to get the same answer. Fastest of 30
runs, on a development machine:

| Format | Bytes/event | With zstd (3) | Encode ns/event | Read ns/event |
| --- | --- | --- | --- | --- |
| columnar block + dictionary | 70.8 | 19.0 | 53 | 16 |
| protobuf messages | 110.7 | 29.9 | 139 | 225 |
| rkyv (validated) | 149.3 | 31.0 | 56 | 38 |
| FlatBuffers (verified) | 172.3 | 34.2 | 95 | 194 |

## Decision

Keep the columnar blocks. They are the smallest, raw and compressed, and the fastest to read, and encode as fast as
rkyv. Both alternatives repeat every string in every event, which is where most of their bytes go. rkyv would also need
an aligned copy of every received buffer and gives weak schema evolution; FlatBuffers needs a schema compiler and
generated unsafe code. The blocks evolve by column ids: a reader skips columns it doesn't know.

Control messages stay protobuf. zstd, in streaming mode over a connection, comes with the remote transport (M5); local
sockets aren't compressed.
