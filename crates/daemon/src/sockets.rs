//! Waiting for another service's socket to appear (systemd-resolved's, Docker's), by inotify: never on a timer.

use std::path::Path;

/// Blocks until `socket` exists, watching the nearest existing directory above it and following the directories
/// being made down to it.
pub fn wait_for(socket: &Path) -> std::io::Result<()> {
    use rustix::fs::inotify;
    loop {
        if socket.exists() {
            return Ok(());
        }
        let Some(watch) = socket.ancestors().skip(1).find(|dir| dir.is_dir()) else {
            return Err(std::io::Error::other("no directory to watch"));
        };
        let fd = inotify::init(inotify::CreateFlags::CLOEXEC)?;
        inotify::add_watch(
            &fd,
            watch,
            inotify::WatchFlags::CREATE | inotify::WatchFlags::MOVED_TO,
        )?;
        // Made between the check and the watch.
        if socket.exists() {
            return Ok(());
        }
        let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(&fd, &mut buffer);
        // Something was made in the watched directory: the socket, or a directory on the way to it.
        reader.next()?;
    }
}
