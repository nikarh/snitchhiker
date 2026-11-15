//! Generates the protocol's Rust types from `proto/` with protox (a protobuf compiler in Rust: no protoc needed).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=../../proto");
    let descriptors = protox::compile(["snitchhiker/v1/client.proto"], ["../../proto"])?;
    prost_build::Config::new()
        // Blocks are shared between subscribers and sliced in place: reference-counted, never copied.
        .bytes([".snitchhiker.v1.EventBlock.columns"])
        // An explanation carries a whole event: boxed, so every response isn't the size of one.
        .boxed(".snitchhiker.v1.Response.result.explanation")
        // So is a proposal (with its provenance).
        .boxed(".snitchhiker.v1.Response.result.proposal")
        .boxed(".snitchhiker.v1.Notice.body.proposal")
        // A container's identity is rare and large: boxed, so events and prompts without one stay small.
        .boxed(".snitchhiker.v1.ConnectionEvent.container")
        .boxed(".snitchhiker.v1.Prompt.container")
        .boxed(".snitchhiker.v1.LiveConnection.container")
        .compile_fds(descriptors)?;
    Ok(())
}
