//! Step-up: a dangerous action asked for by a client needs more than the client's session. polkit authorizes the
//! client's process for `org.snitchhiker.manage` (dist/polkit), which by default asks for an administrator's password
//! through the user's polkit agent. The process is named to polkit by its pidfd, so its pid can't be reused meanwhile.

use std::collections::HashMap;
use std::os::fd::OwnedFd;

use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

/// The polkit action of dangerous actions.
pub const ACTION_ID: &str = "org.snitchhiker.manage";

/// Asks polkit whether the process of `pidfd` (running as `uid`) may do what `message` says; this waits while the
/// user authenticates. An error means polkit couldn't be asked (no polkit, no system bus) or couldn't ask the user
/// (no polkit agent in their session): refused, then, with the reason to tell them.
///
/// Called from the API's own threads, never from inside zbus, so `block_on` waits on this thread alone.
pub fn authorize(pidfd: &OwnedFd, uid: u32, message: &str) -> Result<bool, String> {
    zbus::block_on(async {
        let connection = zbus::Connection::system()
            .await
            .map_err(|e| format!("the system bus: {e}"))?;
        let authority = AuthorityProxy::new(&connection)
            .await
            .map_err(|e| format!("polkit: {e}"))?;
        let subject =
            Subject::new_for_owner(pidfd, uid).map_err(|e| format!("polkit subject: {e}"))?;
        let details = HashMap::from([("polkit.message", message)]);
        let result = authority
            .check_authorization(
                &subject,
                ACTION_ID,
                &details,
                CheckAuthorizationFlags::ALLOW_USER_INTERACTION,
                "",
            )
            .await
            .map_err(|e| format!("polkit: {e}"))?;
        // Not authorized, yet authorization could be had by authenticating: no agent was there to ask.
        if !result.is_authorized && result.is_challenge {
            return Err("no polkit agent is running in this session to ask for a password (desktops start one; \
                 under a bare window manager, start one such as polkit-gnome or lxpolkit)"
                .to_owned());
        }
        Ok(result.is_authorized)
    })
}
