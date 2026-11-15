//! The environment, scrubbed. The app runs setgid to the client group, and the kernel doesn't clean a set-id
//! program's environment (only the dynamic loader ignores `LD_*`): whatever the user's session sets reaches it. So the
//! app keeps only what it needs to reach the display and the session bus, and the locale, and drops everything else
//! (`FONTCONFIG_FILE`, `XDG_DATA_DIRS`, `GDK_*`, `RUST_LOG`, ...).
//!
//! Changing the environment of a running process isn't safe Rust (other threads may read it), so the app re-executes
//! itself with the kept variables only, before anything else runs.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

/// Variables the app keeps.
const KEPT: &[&str] = &[
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DBUS_SESSION_BUS_ADDRESS",
    "LANG",
    "LANGUAGE",
];

/// Whether the app keeps `name`.
#[must_use]
pub fn kept(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| KEPT.contains(&name) || name.starts_with("LC_"))
}

/// Whether `vars` hold anything the app doesn't keep.
pub fn needs_scrubbing(mut vars: impl Iterator<Item = (OsString, OsString)>) -> bool {
    vars.any(|(name, _)| !kept(&name))
}

/// Re-executes the running binary (the same file, by `/proc/self/exe`) with the same arguments and only the kept
/// variables. Returns only if that fails.
pub fn reexec_scrubbed() -> io::Error {
    let kept: Vec<(OsString, OsString)> =
        std::env::vars_os().filter(|(name, _)| kept(name)).collect();
    let mut args = std::env::args_os();
    let argv0 = args
        .next()
        .unwrap_or_else(|| OsString::from("snitchhiker-ui"));
    Command::new("/proc/self/exe")
        .arg0(argv0)
        .args(args)
        .env_clear()
        .envs(kept)
        .exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(names: &[&str]) -> impl Iterator<Item = (OsString, OsString)> {
        names
            .iter()
            .map(|name| (OsString::from(name), OsString::from("x")))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn keeps_the_display_the_bus_and_the_locale_only() {
        assert!(!needs_scrubbing(vars(&[
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "LANG",
            "LC_TIME",
            "DBUS_SESSION_BUS_ADDRESS",
        ])));
        for hostile in [
            "LD_PRELOAD",
            "FONTCONFIG_FILE",
            "XDG_DATA_DIRS",
            "GDK_BACKEND",
            "RUST_LOG",
            "HOME",
        ] {
            assert!(
                needs_scrubbing(vars(&["WAYLAND_DISPLAY", hostile])),
                "{hostile}"
            );
        }
    }
}
