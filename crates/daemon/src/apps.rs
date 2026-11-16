//! Stable identities of programs (`process.app`): names that survive updates and moves, from facts only root (or
//! the package manager, Nix or snapd) can set:
//!
//! - `pkg:<name>`: the package that installed the executable (pacman, dpkg, rpm databases);
//! - `nix:<name>`: a program in the Nix store (`/nix/store/<hash>-<name>-<version>/…`);
//! - `unit:<name>.service`: a system service (its cgroup, set by systemd; a user's own units can be named anything,
//!   so they give none);
//! - `snap:<name>`: a snap (its cgroup, set by snapd).
//!
//! Flatpak and `AppImage` markers (`.flatpak-info`, `APPIMAGE`, a FUSE mount) can be made by any user in a namespace of
//! their own, so they name nothing here (decision 0014). Identities are for programs on the host: inside a container,
//! a path names something else.
//!
//! The package index (executables only) is read when the daemon starts and again when a package database changes;
//! looking a program up is a hash lookup.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

const PACMAN: &str = "/var/lib/pacman/local";
const DPKG: &str = "/var/lib/dpkg/info";
const RPM: &str = "/var/lib/rpm";

/// Executables by path, with their package's name.
#[derive(Debug, Default)]
pub struct Packages {
    owners: ArcSwap<HashMap<Box<str>, Arc<str>>>,
}

impl Packages {
    /// Reads the package databases this system has.
    #[must_use]
    pub fn load() -> Self {
        let packages = Self::default();
        packages.reload();
        packages
    }

    fn reload(&self) {
        let started = std::time::Instant::now();
        let mut owners = HashMap::new();
        read_pacman(&mut owners);
        read_dpkg(&mut owners);
        read_rpm(&mut owners);
        info!(executables = owners.len(), elapsed = ?started.elapsed(), "package index read");
        self.owners.store(Arc::new(owners));
    }

    /// The package that installed `exe`.
    #[must_use]
    pub fn owner(&self, exe: &str) -> Option<Arc<str>> {
        self.owners.load().get(exe).cloned()
    }

    /// Reads the index again whenever a package database changes, until the daemon stops.
    pub fn watch(self: &Arc<Self>) -> std::io::Result<()> {
        use rustix::fs::inotify;
        let fd = inotify::init(inotify::CreateFlags::CLOEXEC)?;
        let mut watched = 0;
        for dir in [PACMAN, DPKG, RPM] {
            if Path::new(dir).is_dir() {
                let flags = inotify::WatchFlags::CREATE
                    | inotify::WatchFlags::DELETE
                    | inotify::WatchFlags::MOVED_TO
                    | inotify::WatchFlags::CLOSE_WRITE;
                inotify::add_watch(&fd, dir, flags)?;
                watched += 1;
            }
        }
        if watched == 0 {
            return Ok(());
        }
        let packages = Arc::clone(self);
        std::thread::Builder::new()
            .name("packages".to_owned())
            .spawn(move || {
                let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 8192];
                let mut reader = inotify::Reader::new(&fd, &mut buffer);
                loop {
                    if let Err(error) = reader.next() {
                        warn!(%error, "watching the package databases; the package index is no longer updated");
                        return;
                    }
                    // A transaction changes many entries: read once it has been quiet for two seconds.
                    while readable(&fd, 2) {
                        if reader.next().is_err() {
                            break;
                        }
                    }
                    debug!("a package database changed");
                    packages.reload();
                }
            })?;
        Ok(())
    }
}

/// Whether `fd` becomes readable within `secs` seconds.
fn readable(fd: &impl rustix::fd::AsFd, secs: i64) -> bool {
    rustix::event::poll(
        &mut [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)],
        Some(&rustix::event::Timespec {
            tv_sec: secs,
            tv_nsec: 0,
        }),
    )
    .is_ok_and(|n| n > 0)
}

/// Whether a packaged file may be a program: in a directory programs live in, and an executable regular file now.
fn is_program(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or_default();
    let candidate = path.contains("/bin/")
        || path.contains("/sbin/")
        || path.contains("/libexec/")
        || ((path.starts_with("/usr/lib/") || path.starts_with("/opt/")) && !name.contains(".so"));
    candidate
        && fs::symlink_metadata(path)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn read_pacman(owners: &mut HashMap<Box<str>, Arc<str>>) {
    let Ok(entries) = fs::read_dir(PACMAN) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let (Ok(desc), Ok(files)) = (
            fs::read_to_string(dir.join("desc")),
            fs::read_to_string(dir.join("files")),
        ) else {
            continue;
        };
        let Some(name) = section(&desc, "%NAME%").next() else {
            continue;
        };
        let name: Arc<str> = Arc::from(name);
        for file in section(&files, "%FILES%") {
            let path = format!("/{file}");
            if is_program(&path) {
                owners.insert(path.into_boxed_str(), Arc::clone(&name));
            }
        }
    }
}

/// The lines of a pacman database section (`%NAME%` and the lines up to the next blank one).
fn section<'a>(text: &'a str, header: &str) -> impl Iterator<Item = &'a str> {
    text.lines()
        .skip_while(move |l| *l != header)
        .skip(1)
        .take_while(|l| !l.is_empty())
}

fn read_dpkg(owners: &mut HashMap<Box<str>, Arc<str>>) {
    let Ok(entries) = fs::read_dir(DPKG) else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.file_name();
        let Some(stem) = file.to_str().and_then(|f| f.strip_suffix(".list")) else {
            continue;
        };
        // `name:arch.list` for multi-arch packages.
        let name: Arc<str> = Arc::from(stem.split(':').next().unwrap_or(stem));
        let Ok(list) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for path in list.lines() {
            // Debian's merged /usr: a package lists /bin/x, the system runs /usr/bin/x.
            for path in [path.to_owned(), format!("/usr{path}")] {
                if is_program(&path) {
                    owners.insert(path.into_boxed_str(), Arc::clone(&name));
                }
            }
        }
    }
}

fn read_rpm(owners: &mut HashMap<Box<str>, Arc<str>>) {
    if !Path::new(RPM).is_dir() {
        return;
    }
    let Ok(output) = std::process::Command::new("rpm")
        .args(["-qa", "--queryformat", "[%{FILENAMES}\\t%{=NAME}\\n]"])
        .output()
    else {
        return;
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((path, name)) = line.split_once('\t')
            && is_program(path)
        {
            owners.insert(Box::from(path), Arc::from(name));
        }
    }
}

/// The identities of a host process running `exe`, with cgroup `cgroup` (`/proc/<pid>/cgroup`'s text).
#[must_use]
pub fn identities(packages: &Packages, exe: &str, cgroup: &str) -> Vec<String> {
    let mut found = Vec::new();
    if let Some(package) = packages.owner(exe) {
        found.push(format!("pkg:{package}"));
    }
    if let Some(name) = nix_name(exe) {
        found.push(format!("nix:{name}"));
    }
    // cgroup v2: `0::/system.slice/sshd.service`.
    let path = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap_or_default();
    let components: Vec<&str> = path.split('/').collect();
    if path.starts_with("/system.slice/")
        && let Some(unit) = components.iter().rev().find(|c| c.ends_with(".service"))
    {
        found.push(format!("unit:{unit}"));
    }
    // `snap.<name>.<app>…` scopes and services, wherever snapd puts them.
    if let Some(snap) = components
        .iter()
        .find_map(|c| c.strip_prefix("snap."))
        .and_then(|rest| rest.split('.').next())
        .filter(|name| !name.is_empty())
    {
        found.push(format!("snap:{snap}"));
    }
    found
}

/// `firefox` from `/nix/store/<hash>-firefox-128.0/bin/firefox`: the store path's name, without its version (the
/// first part that starts with a digit, and what follows).
fn nix_name(exe: &str) -> Option<String> {
    let entry = exe.strip_prefix("/nix/store/")?.split('/').next()?;
    let (hash, rest) = entry.split_once('-')?;
    if hash.len() != 32 {
        return None;
    }
    let name: Vec<&str> = rest
        .split('-')
        .take_while(|part| !part.starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    (!name.is_empty()).then(|| name.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_come_from_what_users_cannot_set() {
        let packages = Packages::default();
        packages.owners.store(Arc::new(HashMap::from([(
            Box::from("/usr/bin/curl"),
            Arc::from("curl"),
        )])));
        assert_eq!(
            identities(
                &packages,
                "/usr/bin/curl",
                "0::/system.slice/sshd.service\n"
            ),
            vec!["pkg:curl", "unit:sshd.service"]
        );
        // A user's own unit names nothing.
        assert_eq!(
            identities(
                &packages,
                "/home/ada/bin/tool",
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/sshd.service\n"
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            identities(
                &packages,
                "/snap/firefox/123/usr/lib/firefox/firefox",
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.firefox.firefox-1a2b.scope\n"
            ),
            vec!["snap:firefox"]
        );
        assert_eq!(
            nix_name("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-git-lfs-3.5.1/bin/git-lfs")
                .as_deref(),
            Some("git-lfs")
        );
        assert_eq!(nix_name("/nix/store/short-x-1/bin/x"), None);
    }

    #[test]
    fn pacman_sections_are_read() {
        let desc = "%NAME%\ncurl\n\n%VERSION%\n8.11.0-1\n";
        assert_eq!(section(desc, "%NAME%").collect::<Vec<_>>(), vec!["curl"]);
        let files = "%FILES%\nusr/\nusr/bin/\nusr/bin/curl\n\n%BACKUP%\n";
        assert_eq!(section(files, "%FILES%").count(), 3);
    }
}
