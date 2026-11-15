# Conformance vectors

Frames of the client protocol, for checking an implementation of it against the reference one. `v1/` has major
version 1:

- `NN-name.textproto` is a message in protobuf text format. Its first line names the message type
  (`# message: snitchhiker.v1.ClientFrame` or `ServerFrame`); `# decode-only` marks a vector whose bytes are not what
  an encoder produces (they carry an unknown field, which a decoder must skip).
- `NN-name.hex` is the frame as sent: the little-endian uint32 length, then the encoded message, in hex.
- `00-preamble.hex` is the preamble a client sends first.

An implementation must decode each `.hex` frame to the message of its `.textproto`, and, unless the vector is
decode-only, encode that message to exactly those bytes.

The Rust test is `crates/proto/tests/vectors.rs`. A new vector needs only its `.textproto`: running
`SNITCHHIKER_UPDATE_VECTORS=1 cargo test -p snitchhiker-proto --test vectors` writes its `.hex`. Existing `.hex` files
are never rewritten: an encoding change that alters one is a breaking change.
