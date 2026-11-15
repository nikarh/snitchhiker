//! Generates the protocol's Rust types from `proto/` with protox (a protobuf compiler in Rust: no protoc needed).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-changed=../../proto");
    let descriptors = protox::compile(["snitchhiker/v1/client.proto"], ["../../proto"])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
