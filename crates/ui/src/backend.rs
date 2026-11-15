//! The connection to the node, off the UI thread: one connection for requests, one for subscriptions, each on a
//! thread of its own with the blocking client. They reconnect with backoff when the node goes away, and the
//! subscriptions resume from the last event seen, so a restart of the daemon loses nothing.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use snitchhiker_client::{Client, Error as ClientError};
use snitchhiker_proto::columns::{EventBlock, EventRow};
use snitchhiker_proto::v1;

/// What the app asks of the node.
#[derive(Debug, Clone)]
pub enum Request {
    Status,
    Rules,
    /// A page of history older than `before` (0: the newest).
    Events {
        before: i64,
    },
    Answer {
        id: u64,
        action: v1::Action,
        duration: v1::Duration,
        suggestion: u32,
    },
    SetRuleEnabled {
        id: u64,
        enabled: bool,
    },
    DeleteRule {
        id: u64,
    },
}

/// What the node tells the app.
#[derive(Debug, Clone)]
pub enum Update {
    Connected(v1::Welcome),
    /// The subscription connection is gone; the reason, and when the next attempt is.
    Disconnected(String),
    Status(v1::Status),
    Rules(v1::RuleList),
    Prompt(v1::Prompt),
    Resolved(v1::PromptResolved),
    /// Events and the strings they use; `live` from the subscription, otherwise a page of history (`more`: there
    /// may be older ones).
    Events {
        rows: Vec<EventRow>,
        strings: Vec<(u32, String)>,
        live: bool,
        more: bool,
    },
    RulesChanged,
    /// A request failed; for the user.
    Failed(String),
}

/// Events in one page of history.
pub const PAGE: u32 = 500;

const APP: &str = "desktop";
const BACKOFF: [u64; 5] = [1, 2, 5, 10, 30];

/// Starts the connections to the node's socket at `socket`; requests go to the returned sender, updates come out of
/// the returned receiver.
pub fn start(socket: PathBuf) -> (mpsc::Sender<Request>, async_channel::Receiver<Update>) {
    let (updates, received) = async_channel::unbounded();
    let (requests, incoming) = mpsc::channel();
    {
        let socket = socket.clone();
        let updates = updates.clone();
        let _ = thread::Builder::new()
            .name("node-requests".to_owned())
            .spawn(move || serve_requests(&socket, &incoming, &updates));
    }
    let _ = thread::Builder::new()
        .name("node-subscriptions".to_owned())
        .spawn(move || listen(&socket, &updates));
    (requests, received)
}

fn connect(socket: &Path) -> Result<Client, ClientError> {
    Client::connect(socket, APP, env!("CARGO_PKG_VERSION"))
}

/// A block's rows and its dictionary entries.
type Rows = (Vec<EventRow>, Vec<(u32, String)>);

fn block(block: &v1::EventBlock) -> Result<Rows, String> {
    let rows = EventBlock::parse(&block.columns)
        .map_err(|e| e.to_string())?
        .rows()
        .collect();
    let strings = block.dictionary.as_ref().map_or_else(Vec::new, |d| {
        d.ids
            .iter()
            .copied()
            .zip(d.values.iter().cloned())
            .collect()
    });
    Ok((rows, strings))
}

fn serve_requests(
    socket: &Path,
    incoming: &mpsc::Receiver<Request>,
    updates: &async_channel::Sender<Update>,
) {
    let mut client: Option<Client> = None;
    while let Ok(request) = incoming.recv() {
        if client.is_none() {
            client = connect(socket).ok();
        }
        let Some(connected) = client.as_mut() else {
            let _ = updates.send_blocking(Update::Failed("the node isn't reachable".to_owned()));
            continue;
        };
        match perform(connected, &request) {
            Ok(Some(update)) => {
                let _ = updates.send_blocking(update);
            }
            Ok(None) => {}
            Err(ClientError::Remote { message, .. }) => {
                let _ = updates.send_blocking(Update::Failed(message));
            }
            Err(error) => {
                // The connection is broken: the next request connects again.
                client = None;
                let _ = updates.send_blocking(Update::Failed(error.to_string()));
            }
        }
    }
}

fn perform(client: &mut Client, request: &Request) -> Result<Option<Update>, ClientError> {
    use v1::request::Method;
    use v1::response::Result as R;
    let result = match request {
        Request::Status => client.call(Method::GetStatus(v1::GetStatus {}))?,
        Request::Rules => client.call(Method::ListRules(v1::ListRules {}))?,
        Request::Events { before } => client.call(Method::ListEvents(v1::ListEvents {
            before: *before,
            limit: PAGE,
            columnar: true,
        }))?,
        Request::Answer {
            id,
            action,
            duration,
            suggestion,
        } => client.call(Method::AnswerPrompt(v1::AnswerPrompt {
            id: *id,
            action: (*action).into(),
            duration: (*duration).into(),
            suggestion: *suggestion,
            conditions: None,
            folder: None,
        }))?,
        Request::SetRuleEnabled { id, enabled } => {
            client.call(Method::SetRuleEnabled(v1::SetRuleEnabled {
                id: *id,
                enabled: *enabled,
            }))?
        }
        Request::DeleteRule { id } => {
            client.call(Method::DeleteRule(v1::DeleteRule { id: *id }))?
        }
    };
    Ok(match result {
        R::Status(status) => Some(Update::Status(status)),
        R::Rules(rules) => Some(Update::Rules(rules)),
        R::EventBlock(event_block) => {
            let (rows, strings) = block(&event_block).map_err(|e| ClientError::Remote {
                code: v1::ErrorCode::Invalid,
                message: e,
            })?;
            let more = rows.len() >= PAGE as usize;
            Some(Update::Events {
                rows,
                strings,
                live: false,
                more,
            })
        }
        _ => None,
    })
}

/// The subscriptions: prompts, rules and live events, resumed after every reconnect.
fn listen(socket: &Path, updates: &async_channel::Sender<Update>) {
    let mut last_seq: Option<i64> = None;
    let mut attempt = 0;
    loop {
        let mut connected = false;
        let reason = match subscribe(socket, updates, &mut last_seq, &mut connected) {
            Ok(()) => return,
            Err(reason) => reason,
        };
        if connected {
            attempt = 0;
        }
        let wait = BACKOFF
            .get(attempt)
            .or(BACKOFF.last())
            .copied()
            .unwrap_or(30);
        attempt += 1;
        if updates
            .send_blocking(Update::Disconnected(format!(
                "{reason}; trying again in {wait} s"
            )))
            .is_err()
        {
            return;
        }
        thread::sleep(Duration::from_secs(wait));
    }
}

/// One connection's worth of subscriptions. `Ok` when the app is gone, the error when the connection is.
fn subscribe(
    socket: &Path,
    updates: &async_channel::Sender<Update>,
    last_seq: &mut Option<i64>,
    connected: &mut bool,
) -> Result<(), String> {
    let mut client = connect(socket).map_err(|e| e.to_string())?;
    *connected = true;
    let send = |update| updates.send_blocking(update).map_err(|_| ());
    if send(Update::Connected(client.welcome().clone())).is_err() {
        return Ok(());
    }
    client
        .subscribe(v1::Topic::Prompts)
        .and_then(|_| client.subscribe(v1::Topic::Rules))
        .and_then(|_| client.subscribe_with(v1::Topic::Events, *last_seq, true))
        .map_err(|e| e.to_string())?;
    loop {
        let notice = client.notice().map_err(|e| e.to_string())?;
        let update = match notice.body {
            Some(v1::notice::Body::Prompt(prompt)) => Update::Prompt(prompt),
            Some(v1::notice::Body::PromptResolved(resolved)) => Update::Resolved(resolved),
            Some(v1::notice::Body::RulesChanged(_)) => Update::RulesChanged,
            Some(v1::notice::Body::EventBlock(event_block)) => {
                let (rows, strings) = block(&event_block)?;
                if let Some(newest) = rows.iter().map(|r| r.seq).max() {
                    *last_seq = Some(last_seq.map_or(newest, |seq| seq.max(newest)));
                }
                Update::Events {
                    rows,
                    strings,
                    live: true,
                    more: false,
                }
            }
            _ => continue,
        };
        if send(update).is_err() {
            return Ok(());
        }
        if notice.missed {
            // Notices were dropped: start again from the last event seen.
            return Err("fell behind the node".to_owned());
        }
    }
}
