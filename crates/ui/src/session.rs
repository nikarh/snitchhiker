//! What about the desktop session weakens the app's protection, shown as a banner (plan §4.4): an X11 session (any
//! client can read the window and inject clicks), a Wayland socket that isn't a known compositor of this user (a
//! proxy could read and inject), and membership in the `input` group (input devices can be written to directly).
//! These are warnings: same-user code controls the session's display, and dangerous actions need step-up anyway.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Compositors whose executables are recognised (their file names).
const COMPOSITORS: [&str; 16] = [
    "sway",
    "Hyprland",
    "kwin_wayland",
    "kwin_wayland_wrapper",
    "gnome-shell",
    "mutter",
    "weston",
    "labwc",
    "wayfire",
    "river",
    "niri",
    "cosmic-comp",
    "gamescope",
    "hikari",
    "dwl",
    "miracle-wm",
];

/// A reason the session is less safe than it could be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    X11,
    /// The Wayland socket's peer: its executable, or why it couldn't be told.
    UnknownCompositor(String),
    InputGroup,
}

impl Warning {
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::X11 => "X11 session: reduced protection. Any program of yours can read this window and click in it. \
                          A Wayland session is safer."
                .to_owned(),
            Self::UnknownCompositor(peer) => format!(
                "The display server isn't a known compositor ({peer}): something may be between this window and the \
                 screen."
            ),
            Self::InputGroup => "You are in the input group: programs of yours can type and click anywhere, in this \
                                 window too."
                .to_owned(),
        }
    }
}

/// The warnings for this session, from its environment, its Wayland socket and the user's groups.
#[must_use]
pub fn check() -> Vec<Warning> {
    let mut warnings = Vec::new();
    match wayland_socket() {
        None if std::env::var_os("DISPLAY").is_some() => warnings.push(Warning::X11),
        None => {}
        Some(path) => {
            if let Some(peer) = unknown_peer(&path) {
                warnings.push(Warning::UnknownCompositor(peer));
            }
        }
    }
    if in_input_group() {
        warnings.push(Warning::InputGroup);
    }
    warnings
}

/// The Wayland socket the app connects to: `$WAYLAND_DISPLAY`, under `$XDG_RUNTIME_DIR` unless absolute.
fn wayland_socket() -> Option<PathBuf> {
    let display = std::env::var_os("WAYLAND_DISPLAY")?;
    let display = PathBuf::from(display);
    if display.is_absolute() {
        return Some(display);
    }
    Some(PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?).join(display))
}

/// The peer of the socket at `path`, when it isn't a known compositor run by this user: what it is, or why it
/// couldn't be told.
fn unknown_peer(path: &Path) -> Option<String> {
    let stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error) => return Some(format!("its socket can't be reached: {error}")),
    };
    let credentials =
        match nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials) {
            Ok(credentials) => credentials,
            Err(error) => return Some(format!("its process can't be told: {error}")),
        };
    let pid = credentials.pid();
    if credentials.uid() != nix::unistd::getuid().as_raw() {
        return Some(format!("pid {pid}, another user's"));
    }
    match exe_of(pid) {
        Ok(exe) => {
            let name = exe
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            (!known(&name)).then(|| exe.display().to_string())
        }
        // The user's own process, yet its executable can't be read: it holds capabilities from its file (sway does,
        // for cap_sys_nice), which made it undumpable. Only root gives a file capabilities, so no proxy of the user's
        // can have them; such a process's name is its own.
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let comm = comm.trim();
            if holds_capabilities(&status) && known(comm) {
                None
            } else {
                Some(format!("pid {pid} ({comm}), whose program can't be told"))
            }
        }
        Err(error) => Some(format!("pid {pid}, whose program can't be told: {error}")),
    }
}

/// Whether a process holds any capability (its `CapPrm` in `/proc/<pid>/status`).
fn holds_capabilities(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapPrm:"))
        .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
        .is_some_and(|caps| caps != 0)
}

/// The executable of the user's process `pid`. The app is setgid to the client group, and the kernel lets a process
/// read another's `exe` only when its filesystem gid is the other's gid: for the read, this thread's filesystem gid is
/// the user's own (it is per thread, and put back at once).
fn exe_of(pid: i32) -> std::io::Result<PathBuf> {
    let own = nix::unistd::getgid();
    let previous = nix::unistd::setfsgid(own);
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"));
    nix::unistd::setfsgid(previous);
    exe
}

fn known(name: &str) -> bool {
    COMPOSITORS.contains(&name)
}

/// Whether the user is in the `input` group.
fn in_input_group() -> bool {
    let Ok(groups) = std::fs::read_to_string("/etc/group") else {
        return false;
    };
    let Some(input) = group_id(&groups, "input") else {
        return false;
    };
    nix::unistd::getgroups().is_ok_and(|gids| gids.iter().any(|g| g.as_raw() == input))
        || nix::unistd::getgid().as_raw() == input
}

fn group_id(groups: &str, name: &str) -> Option<u32> {
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compositors_are_known_by_name() {
        assert!(known("sway"));
        assert!(known("kwin_wayland"));
        assert!(!known("socat"));
        assert!(!known("python3"));
    }

    #[test]
    fn capabilities_are_read_from_the_status() {
        assert!(holds_capabilities(
            "Name:\tsway\nCapPrm:\t0000000000800000\n"
        ));
        assert!(!holds_capabilities(
            "Name:\tsocat\nCapPrm:\t0000000000000000\n"
        ));
        assert!(!holds_capabilities(""));
    }

    #[test]
    fn groups_are_read_by_name() {
        let groups = "root:x:0:\ninput:x:97:ada\nvideo:x:985:\n";
        assert_eq!(group_id(groups, "input"), Some(97));
        assert_eq!(group_id(groups, "audio"), None);
    }

    #[test]
    fn a_socket_nobody_listens_on_is_told() {
        let peer = unknown_peer(Path::new("/nonexistent/wayland-0")).unwrap();
        assert!(peer.starts_with("its socket can't be reached"), "{peer}");
    }

    #[test]
    fn a_proxy_is_not_a_compositor() {
        // This test process listens; it isn't a compositor.
        let dir = std::env::temp_dir().join(format!("snitchhiker-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wayland-test");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let peer = unknown_peer(&path).unwrap();
        assert!(
            peer.contains("snitchhiker_ui") || peer.contains("snitchhiker-ui"),
            "{peer}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
