//! Compiles the eBPF programs in `bpf/` with clang into `OUT_DIR`, for `include_bytes!`. Needs clang and the libbpf
//! and kernel UAPI headers (`libbpf-dev` and `linux-libc-dev` on Debian and Ubuntu, `libbpf` and
//! `linux-api-headers` on Arch).

use std::path::PathBuf;
use std::process::Command;

const PROGRAMS: &[&str] = &["attribution"];

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default());
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "aarch64" => "arm64",
        _ => "x86",
    };
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".to_owned());
    println!("cargo::rerun-if-env-changed=CLANG");
    for program in PROGRAMS {
        let source = format!("bpf/{program}.bpf.c");
        println!("cargo::rerun-if-changed={source}");
        let object = out.join(format!("{program}.bpf.o"));
        let status = Command::new(&clang)
            .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
            .arg(format!("-D__TARGET_ARCH_{arch}"))
            // The multiarch include directory, where Debian keeps <asm/types.h>.
            .arg(format!(
                "-I/usr/include/{}-linux-gnu",
                std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default()
            ))
            .args(["-c", &source, "-o"])
            .arg(&object)
            .status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => panic!("{clang} failed on {source}: {status}"),
            Err(error) => panic!(
                "running {clang} for {source}: {error} (clang is needed to build the eBPF programs)"
            ),
        }
    }
}
