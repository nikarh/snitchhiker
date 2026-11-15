//! Sets `SNITCHHIKER_VERSION`: the package version plus `SNITCHHIKER_VERSION_SUFFIX` (e.g. `-dev+abc1234` for builds
//! of main), so that every build says what it is.

fn main() {
    println!("cargo::rerun-if-env-changed=SNITCHHIKER_VERSION_SUFFIX");
    let suffix = std::env::var("SNITCHHIKER_VERSION_SUFFIX").unwrap_or_default();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    println!("cargo::rustc-env=SNITCHHIKER_VERSION={version}{suffix}");
}
