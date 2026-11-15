//! Desktop notifications for prompts (`org.freedesktop.Notifications` on the session bus), on a thread of their own.
//!
//! The session bus is open to every process of the user, so a notification is a less trusted way to answer than the
//! app's window: its actions decide only the connections waiting, once (no rule is made), and clicking it opens the
//! app, where lasting rules are made. Action signals are taken only from the notification server that owns the bus
//! name, which the bus enforces for the proxy's match rule.

use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;

use futures_lite::StreamExt as _;
use snitchhiker_proto::v1;
use zbus::Variant as Value;

use crate::backend::{Request, Update};

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;
}

/// What the app asks of the notifications.
#[derive(Debug, Clone)]
pub enum Notice {
    /// A prompt opened: show it.
    Show(v1::Prompt),
    /// A prompt was resolved: take its notification down.
    Close(u64),
    /// An alert was raised.
    Alert(v1::Alert),
    /// An agent proposed rules: only shown, approved in the window alone.
    Proposal(Box<v1::Proposal>),
}

const ALLOW: &str = "allow-once";
const DENY: &str = "deny-once";
const OPEN: &str = "default";

/// Starts the notifications; what to show goes to the returned sender. Actions become requests to the node, and
/// clicking a notification an `Update::ShowPrompts` for the app.
pub fn start(
    requests: mpsc::Sender<Request>,
    updates: async_channel::Sender<Update>,
) -> async_channel::Sender<Notice> {
    let (notices, incoming) = async_channel::unbounded();
    let _ = thread::Builder::new()
        .name("notifications".to_owned())
        .spawn(move || {
            // Without a session bus or a notification server there are simply no notifications.
            let _ = zbus::block_on(run(&incoming, &requests, &updates));
        });
    notices
}

/// The text of a prompt's notification: (summary, body).
#[must_use]
pub fn text(prompt: &v1::Prompt) -> (String, String) {
    let program = if prompt.exe.is_empty() {
        "An unknown program"
    } else {
        prompt.exe.rsplit('/').next().unwrap_or(&prompt.exe)
    };
    let destination = prompt.hosts.first().cloned().unwrap_or_else(|| {
        snitchhiker_proto::convert::address_from(&prompt.address)
            .map_or_else(String::new, |a| a.to_string())
    });
    (
        format!("{program} wants to connect"),
        if prompt.exe.is_empty() {
            format!("to {destination}:{}", prompt.port)
        } else {
            format!("to {destination}:{}\n{}", prompt.port, prompt.exe)
        },
    )
}

/// The text of a proposal's notification: (summary, body).
#[must_use]
pub fn proposal_text(proposal: &v1::Proposal) -> (String, String) {
    let provenance = proposal.provenance.clone().unwrap_or_default();
    let agent = provenance
        .agent_exe
        .rsplit('/')
        .next()
        .unwrap_or("An agent")
        .to_owned();
    let project = provenance
        .cwd
        .rsplit('/')
        .find(|p| !p.is_empty())
        .unwrap_or("/");
    let count = proposal.rules.len();
    (
        format!(
            "{agent} proposes {count} rule{}",
            if count == 1 { "" } else { "s" }
        ),
        format!("for {project}: review it in Snitchhiker"),
    )
}

async fn show_proposal(
    server: &NotificationsProxy<'_>,
    proposal: &v1::Proposal,
) -> zbus::Result<u32> {
    let (summary, body) = proposal_text(proposal);
    let hints = HashMap::from([("urgency", Value::U8(1))]);
    server
        .notify(
            "Snitchhiker",
            0,
            "snitchhiker",
            &summary,
            &body,
            &[OPEN, "Review"],
            hints,
            -1,
        )
        .await
}

async fn show_prompt(server: &NotificationsProxy<'_>, prompt: &v1::Prompt) -> zbus::Result<u32> {
    let (summary, body) = text(prompt);
    let hints = HashMap::from([("urgency", Value::U8(2)), ("resident", Value::Bool(true))]);
    server
        .notify(
            "Snitchhiker",
            0,
            "snitchhiker",
            &summary,
            &body,
            &[OPEN, "Open", ALLOW, "Allow once", DENY, "Deny"],
            hints,
            0,
        )
        .await
}

async fn run(
    incoming: &async_channel::Receiver<Notice>,
    requests: &mpsc::Sender<Request>,
    updates: &async_channel::Sender<Update>,
) -> zbus::Result<()> {
    let connection = zbus::Connection::session().await?;
    let server = NotificationsProxy::new(&connection).await?;
    let mut actions = server.receive_action_invoked().await?;
    // notification id <-> prompt id
    let mut shown: HashMap<u32, u64> = HashMap::new();
    // notifications of alerts
    let mut alerts: std::collections::HashSet<u32> = std::collections::HashSet::new();
    // notifications of proposals
    let mut proposals: std::collections::HashSet<u32> = std::collections::HashSet::new();
    loop {
        enum Next {
            Notice(Notice),
            Action(u32, String),
            Done,
        }
        let next = futures_lite::future::or(
            async { incoming.recv().await.map_or(Next::Done, Next::Notice) },
            async {
                match actions.next().await {
                    Some(signal) => signal
                        .args()
                        .map_or(Next::Action(0, String::new()), |args| {
                            Next::Action(args.id, args.action_key.clone())
                        }),
                    None => Next::Done,
                }
            },
        )
        .await;
        match next {
            Next::Done => return Ok(()),
            Next::Notice(Notice::Show(prompt)) => {
                let id = show_prompt(&server, &prompt).await?;
                shown.insert(id, prompt.id);
            }
            Next::Notice(Notice::Alert(alert)) => {
                let hints = HashMap::from([("urgency", Value::U8(1))]);
                let id = server
                    .notify(
                        "Snitchhiker",
                        0,
                        "snitchhiker",
                        &alert.title,
                        &alert.body,
                        &[OPEN, "Open"],
                        hints,
                        -1,
                    )
                    .await?;
                alerts.insert(id);
            }
            Next::Notice(Notice::Close(prompt)) => {
                let ids: Vec<u32> = shown
                    .iter()
                    .filter(|(_, p)| **p == prompt)
                    .map(|(n, _)| *n)
                    .collect();
                for id in ids {
                    shown.remove(&id);
                    let _ = server.close_notification(id).await;
                }
            }
            Next::Action(id, _) if alerts.remove(&id) => {
                let _ = updates.send(Update::ShowAlerts).await;
            }
            Next::Action(id, _) if proposals.remove(&id) => {
                let _ = updates.send(Update::ShowProposals).await;
            }
            Next::Notice(Notice::Proposal(proposal)) => {
                proposals.insert(show_proposal(&server, &proposal).await?);
            }
            Next::Action(id, action) => {
                let Some(&prompt) = shown.get(&id) else {
                    continue;
                };
                let answer = |action: v1::Action| Request::Answer {
                    id: prompt,
                    action,
                    duration: v1::Duration::Once,
                    suggestion: 0,
                };
                match action.as_str() {
                    ALLOW => {
                        let _ = requests.send(answer(v1::Action::Allow));
                    }
                    DENY => {
                        let _ = requests.send(answer(v1::Action::Deny));
                    }
                    _ => {
                        let _ = updates.send(Update::ShowPrompts).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notification_says_who_connects_where() {
        let prompt = v1::Prompt {
            exe: "/usr/bin/curl".to_owned(),
            hosts: vec!["example.com".to_owned()],
            port: 443,
            ..v1::Prompt::default()
        };
        assert_eq!(
            text(&prompt),
            (
                "curl wants to connect".to_owned(),
                "to example.com:443\n/usr/bin/curl".to_owned()
            )
        );
    }
}
