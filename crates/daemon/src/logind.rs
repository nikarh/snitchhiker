//! Whether a user is at the machine, from logind: one of their sessions is active, not locked and not idle. For
//! prompt routing (`router`), called from its own thread.

use zbus::OwnedObjectPath;

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    /// (id, uid, user name, seat, object path) of every session.
    fn list_sessions(&self) -> zbus::Result<Vec<(String, u32, String, String, OwnedObjectPath)>>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1"
)]
trait Session {
    #[zbus(property)]
    fn active(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn locked_hint(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn idle_hint(&self) -> zbus::Result<bool>;
}

/// Whether any of `uids` is at the machine. Without logind (or on an error) nobody is taken to be: prompts then go
/// to the remote devices too, rather than to no one.
#[must_use]
pub fn anyone_present(uids: &[u32]) -> bool {
    zbus::block_on(async {
        let connection = zbus::Connection::system().await?;
        let manager = ManagerProxy::new(&connection).await?;
        for (_, uid, _, _, path) in manager.list_sessions().await? {
            if !uids.contains(&uid) {
                continue;
            }
            let session = SessionProxy::builder(&connection)
                .path(path)
                .build()
                .await?;
            if session.active().await?
                && !session.locked_hint().await?
                && !session.idle_hint().await?
            {
                return Ok::<_, zbus::Error>(true);
            }
        }
        Ok(false)
    })
    .unwrap_or(false)
}
