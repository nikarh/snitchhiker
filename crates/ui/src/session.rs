//! What about the desktop session weakens the app's protection, shown as a banner (plan §4.4): an X11 session (any
//! client can read the window and inject clicks), a Wayland socket that isn't a known compositor of this user (a
//! proxy could read and inject), a compositor offering every client virtual input or control of other windows, a
//! writable `/dev/uinput`, and membership in the `input` group (input devices can be written to directly). These are
//! warnings: same-user code controls the session's display, and the session is what protects the app (decision 0019).

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

/// Protocols with which a Wayland client types and clicks as if it were the user.
const VIRTUAL_INPUT: [&str; 2] = [
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
];

/// The protocol with which a Wayland client raises, focuses, minimises or closes other clients' windows.
const WINDOW_CONTROL: &str = "zwlr_foreign_toplevel_management_v1";

/// A reason the session is less safe than it could be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    X11,
    /// The Wayland socket's peer: its executable, or why it couldn't be told.
    UnknownCompositor(String),
    /// The compositor offers every client these virtual input protocols.
    VirtualInput(Vec<String>),
    /// The compositor offers every client control of other clients' windows.
    WindowControl,
    /// `/dev/uinput` is writable by the user: a program can make a keyboard or mouse the kernel treats as real.
    Uinput,
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
            Self::VirtualInput(protocols) => format!(
                "The compositor lets every program of yours type and click in this window ({}): one could answer \
                 prompts or change the firewall. Compositors that keep virtual input to programs they trust (GNOME, \
                 KDE Plasma) don't offer it to every program.",
                protocols.join(", ")
            ),
            Self::WindowControl => format!(
                "The compositor lets every program of yours raise, focus or close this window ({WINDOW_CONTROL}): with \
                 virtual input, it could bring the window forward and click in it."
            ),
            Self::Uinput => "/dev/uinput is writable by you: programs of yours can make a keyboard or mouse and type \
                             and click anywhere, under any compositor. Make it writable by root alone (a udev rule), \
                             or leave the group that may write it."
                .to_owned(),
            Self::InputGroup => "You are in the input group: programs of yours can type and click anywhere, in this \
                                 window too. Leave the group (log in again after) unless a program of yours needs it."
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
            // What the compositor offers every client: what any program of the user's can do to this window. A
            // compositor that can't be asked is reported above, as unreachable.
            if let Ok(offered) = globals(&path) {
                let input: Vec<String> = VIRTUAL_INPUT
                    .iter()
                    .filter(|p| offered.iter().any(|o| o == *p))
                    .map(|p| (*p).to_owned())
                    .collect();
                if !input.is_empty() {
                    warnings.push(Warning::VirtualInput(input));
                }
                if offered.iter().any(|o| o == WINDOW_CONTROL) {
                    warnings.push(Warning::WindowControl);
                }
            }
        }
    }
    // With the user's own rights (the real ids, not the app's setgid group).
    if nix::unistd::access("/dev/uinput", nix::unistd::AccessFlags::W_OK).is_ok() {
        warnings.push(Warning::Uinput);
    }
    if in_input_group() {
        warnings.push(Warning::InputGroup);
    }
    warnings
}

/// The interfaces the compositor at `path` offers a client, read from its registry over the Wayland wire protocol:
/// `wl_display.get_registry` as object 2, then `wl_display.sync` as object 3, whose `done` comes after every global.
/// Messages are in the host's byte order: an object id, then the size (high 16 bits) and opcode (low 16 bits).
fn globals(path: &Path) -> std::io::Result<Vec<String>> {
    use std::io::{Read as _, Write as _};
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(24);
    for (opcode, new_id) in [(1_u32, 2_u32), (0, 3)] {
        request.extend_from_slice(&1_u32.to_ne_bytes());
        request.extend_from_slice(&((12_u32 << 16) | opcode).to_ne_bytes());
        request.extend_from_slice(&new_id.to_ne_bytes());
    }
    stream.write_all(&request)?;
    let mut buffer: Vec<u8> = Vec::new();
    let mut found = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        while let (Some(object), Some(word)) = (word_at(&buffer, 0), word_at(&buffer, 4)) {
            let size = usize::try_from(word >> 16).unwrap_or(0);
            if size < 8 {
                return Err(std::io::Error::other("a malformed message"));
            }
            let Some(body) = buffer.get(8..size) else {
                break;
            };
            match (object, word & 0xffff) {
                // wl_registry.global: name, interface, version.
                (2, 0) => found.extend(interface(body)),
                // wl_callback.done: every global has been sent.
                (3, 0) => return Ok(found),
                // wl_display.error.
                (1, 0) => return Err(std::io::Error::other("the compositor refused the registry")),
                _ => {}
            }
            buffer.drain(..size);
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
}

/// The 32-bit word at `offset`, in the host's byte order.
fn word_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// The interface name of a `wl_registry.global` event's body: a name, then a string (its length with the NUL, and its
/// bytes padded to 32 bits).
fn interface(body: &[u8]) -> Option<String> {
    let length = usize::try_from(word_at(body, 4)?).ok()?;
    let text = body.get(8..8 + length.checked_sub(1)?)?;
    String::from_utf8(text.to_vec()).ok()
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
        Ok((exe, id)) => {
            let name = exe
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            // A known name isn't enough: a copy of a proxy can have it. The program must be the file at its path
            // here (not one mounted over it in another namespace), and that path root's, which the user can't change.
            (!(known(&name) && is_file(&exe, id) && root_only(&exe)))
                .then(|| exe.display().to_string())
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
fn exe_of(pid: i32) -> std::io::Result<(PathBuf, (u64, u64))> {
    use std::os::unix::fs::MetadataExt as _;
    let own = nix::unistd::getgid();
    let previous = nix::unistd::setfsgid(own);
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).and_then(|path| {
        // The file the process runs, whatever is at its path now.
        let running = std::fs::metadata(format!("/proc/{pid}/exe"))?;
        Ok((path, (running.dev(), running.ino())))
    });
    nix::unistd::setfsgid(previous);
    exe
}

/// Whether `path` is the file `id` (device, inode).
fn is_file(path: &Path, id: (u64, u64)) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).is_ok_and(|m| (m.dev(), m.ino()) == id)
}

/// Whether `path` and every directory above it belong to root, and no one else may write to them.
fn root_only(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    path.is_absolute()
        && path.ancestors().all(|part| {
            std::fs::symlink_metadata(part).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
        })
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

    /// A `wl_registry.global` event for `name`, as a compositor sends it.
    fn global(name: &str, version: u32) -> Vec<u8> {
        let mut text = name.as_bytes().to_vec();
        text.push(0);
        let length = u32::try_from(text.len()).unwrap();
        while !text.len().is_multiple_of(4) {
            text.push(0);
        }
        let size = u32::try_from(8 + 4 + 4 + text.len() + 4).unwrap();
        let mut event = Vec::new();
        for word in [2, size << 16, 7, length] {
            event.extend_from_slice(&u32::to_ne_bytes(word));
        }
        event.extend_from_slice(&text);
        event.extend_from_slice(&version.to_ne_bytes());
        event
    }

    #[test]
    fn the_registry_is_read_to_its_end() {
        use std::io::{Read as _, Write as _};
        let dir = std::env::temp_dir().join(format!("snitchhiker-registry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wayland-test");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut request = [0_u8; 24];
            client.read_exact(&mut request).unwrap();
            let mut answer = Vec::new();
            answer.extend(global("wl_compositor", 6));
            answer.extend(global("zwp_virtual_keyboard_manager_v1", 1));
            answer.extend(global(WINDOW_CONTROL, 3));
            // wl_callback.done for object 3, then something after it that isn't read.
            for word in [3, 12 << 16, 1] {
                answer.extend_from_slice(&u32::to_ne_bytes(word));
            }
            answer.extend(global("zwlr_virtual_pointer_manager_v1", 2));
            // In two writes, the first cutting a message in half.
            let (first, rest) = answer.split_at(30);
            client.write_all(first).unwrap();
            client.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            client.write_all(rest).unwrap();
            request
        });
        let found = globals(&path).unwrap();
        let request = server.join().unwrap();
        assert_eq!(
            found,
            [
                "wl_compositor",
                "zwp_virtual_keyboard_manager_v1",
                WINDOW_CONTROL
            ]
        );
        // get_registry (opcode 1) as object 2, sync (opcode 0) as object 3, both on wl_display.
        assert_eq!(word_at(&request, 4), Some((12 << 16) | 1));
        assert_eq!(word_at(&request, 8), Some(2));
        assert_eq!(word_at(&request, 16), Some(12 << 16));
        assert_eq!(word_at(&request, 20), Some(3));
        std::fs::remove_dir_all(&dir).unwrap();
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

    #[test]
    fn only_root_owned_compositors_count() {
        use std::os::unix::fs::MetadataExt as _;
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        assert!(root_only(&sh));
        let meta = std::fs::metadata(&sh).unwrap();
        assert!(is_file(&sh, (meta.dev(), meta.ino())));
        assert!(!is_file(&sh, (meta.dev(), meta.ino() + 1)));
        // A copy of the user's, named like a compositor.
        let dir =
            std::env::temp_dir().join(format!("snitchhiker-compositor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("sway");
        std::fs::write(&copy, "").unwrap();
        // /tmp is world-writable: never root's alone, whoever made the file.
        assert!(!root_only(&copy));
        assert!(!root_only(Path::new("relative/sway")));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
