//! Files in places the user controls (the home directory, a directory they pick), read and written as the user alone.
//!
//! The app is setgid to the client group, and the kernel checks file access with the filesystem group, which follows
//! the effective one: a link the user (or a program of theirs) put in their home could otherwise make the app write
//! or read what only the group can, such as the app's state of this or another user. On Linux the filesystem ids are
//! a thread's own, so such work runs on a thread of its own whose filesystem group is the user's real one.

/// Runs `work` with the user's own group for file access.
pub fn as_user<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                nix::unistd::setfsgid(nix::unistd::getgid());
                work()
            })
            .join()
            // The work panicked: resume it here, as if run on this thread.
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Writes `text` to `path` (a link there is refused, never followed): through a temporary file in the same directory,
/// renamed over it.
pub fn write(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let temporary = path.with_extension("new");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_written_without_following_links() {
        let dir = std::env::temp_dir().join(format!("snitchhiker-userfs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, "kept").unwrap();
        // A link in the temporary file's place: refused, and what it points at is untouched.
        std::os::unix::fs::symlink(&target, dir.join("ui.new")).unwrap();
        assert!(as_user(|| write(&dir.join("ui.toml"), "x")).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
        // A link in the file's own place is replaced, not followed.
        std::fs::remove_file(dir.join("ui.new")).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("ui.toml")).unwrap();
        as_user(|| write(&dir.join("ui.toml"), "new")).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
        assert_eq!(std::fs::read_to_string(dir.join("ui.toml")).unwrap(), "new");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
