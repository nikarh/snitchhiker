//! The connection to the node, off the UI thread: one connection for requests, one for subscriptions, each on a
//! thread of its own with the blocking client. They reconnect with backoff when the node goes away, and the
//! subscriptions resume from the last event seen, so a restart of the daemon loses nothing.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use snitchhiker_client::{Client, Error as ClientError};
use snitchhiker_proto::columns::{EventBlock, EventRow};

use crate::history::History;
use snitchhiker_proto::v1;

/// What the app asks of the node.
#[derive(Debug, Clone)]
pub enum Request {
    Status,
    Rules,
    /// A page of history older than `before` (0: the newest), of the events `query` matches.
    Events {
        before: i64,
        query: String,
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
    AddRule(v1::Rule),
    /// A rule file (TOML), into a folder of that name.
    ImportRules {
        toml: String,
        folder: String,
    },
    UpdateRule(v1::Rule),
    /// The newest changes to rules and folders.
    Changes,
    Undo {
        change: u64,
    },
    Explore(v1::Explore),
    Connections,
    Kill(v1::KillConnection),
    /// Why event `seq` is decided as it is.
    Explain {
        seq: i64,
    },
    EditRules(v1::EditRules),
    AddFolder(v1::Folder),
    UpdateFolder(v1::Folder),
    DeleteFolder {
        id: u64,
    },
    Policy,
    SetPolicy(v1::SetPolicy),
    SystemFirewall,
    SetSystemFirewall(v1::SetSystemFirewall),
    /// The newest alerts.
    Alerts,
    Acknowledge {
        ids: Vec<u64>,
        all: bool,
    },
    AlertRules,
    PutAlertRule(v1::AlertRule),
    DeleteAlertRule {
        id: u64,
    },
    TrustedClients,
    /// How many events the cache holds.
    CacheSize,
    /// The lint report, with rules unused for `days`.
    Lint {
        days: u32,
    },
    /// Agents' newest proposals.
    Proposals,
    Decide(v1::DecideProposal),
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
        /// A page's: the oldest seq it covers (0: there is nothing older), and the query it was asked for.
        scanned_from: i64,
        query: String,
    },
    RulesChanged,
    /// The history of rules and folders, newest first.
    Changes(Vec<v1::Change>),
    /// The Explorer's groups.
    Explored(Vec<v1::ExploreRow>),
    /// The live connections.
    Connections(Vec<v1::LiveConnection>),
    /// Why an event is decided as it is.
    Explanation(Box<v1::Explanation>),
    Lint(v1::LintReport),
    Policy(v1::NodePolicy),
    SystemFirewall(v1::SystemFirewall),
    /// A page of alerts, and how many are open.
    Alerts(Vec<v1::Alert>, u32),
    /// An alert was raised.
    Alert(v1::Alert),
    /// Alerts were acknowledged; how many are left.
    AlertsChanged(u32),
    AlertRules(Vec<v1::AlertRule>),
    TrustedClients(Vec<v1::TrustedClient>),
    /// Events the cache holds (`None`: no cache).
    CacheSize(Option<u64>),
    /// A request failed; for the user.
    Failed(String),
    /// A prompt's notification was clicked: show the prompts.
    ShowPrompts,
    /// An alert's notification was clicked: show the alerts.
    ShowAlerts,
    /// A proposal's notification was clicked: show the proposals.
    ShowProposals,
    /// Agents' newest proposals.
    Proposals(Vec<v1::Proposal>),
    /// A proposal made or changed.
    Proposal(Box<v1::Proposal>),
}

/// Events in one page of history.
pub const PAGE: u32 = 500;

const APP: &str = "desktop";
const BACKOFF: [u64; 5] = [1, 2, 5, 10, 30];

/// Starts the connections to the node's socket at `socket`; requests go to the returned sender, updates come out of
/// the returned receiver.
pub fn start(
    socket: PathBuf,
) -> (
    mpsc::Sender<Request>,
    async_channel::Receiver<Update>,
    async_channel::Sender<Update>,
) {
    let (updates, received) = async_channel::unbounded();
    let (requests, incoming) = mpsc::channel();
    let history = History::default();
    {
        let socket = socket.clone();
        let updates = updates.clone();
        let history = history.clone();
        let _ = thread::Builder::new()
            .name("node-requests".to_owned())
            .spawn(move || serve_requests(&socket, &incoming, &updates, &history));
    }
    let _ = thread::Builder::new()
        .name("node-subscriptions".to_owned())
        .spawn({
            let updates = updates.clone();
            move || listen(&socket, &updates, &history)
        });
    (requests, received, updates)
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

/// What the cache can answer without the node: a page of history it holds, and its own size.
fn from_history(history: &History, request: &Request) -> Option<Update> {
    match request {
        Request::CacheSize => Some(Update::CacheSize(history.len())),
        Request::Events { before, query } if *before != 0 => {
            let page = history.page(*before, PAGE as usize, query)?;
            Some(Update::Events {
                rows: page.rows,
                strings: page.strings,
                live: false,
                scanned_from: page.scanned_from,
                query: query.clone(),
            })
        }
        _ => None,
    }
}

/// Keeps what the node answered that the cache holds.
fn keep(history: &History, request: &Request, update: &Update) {
    match (request, update) {
        (
            Request::Events { before, query },
            Update::Events {
                rows,
                strings,
                scanned_from,
                ..
            },
        ) => history.add_page(rows, strings, *before, *scanned_from, query),
        (_, Update::Status(status)) => history.clamp(status.oldest_seq),
        _ => {}
    }
}

fn serve_requests(
    socket: &Path,
    incoming: &mpsc::Receiver<Request>,
    updates: &async_channel::Sender<Update>,
    history: &History,
) {
    let mut client: Option<Client> = None;
    while let Ok(request) = incoming.recv() {
        if let Some(update) = from_history(history, &request) {
            let _ = updates.send_blocking(update);
            continue;
        }
        if client.is_none() {
            client = connect(socket).ok();
            if let Some(connected) = &client {
                history.connected(connected.welcome().node_epoch);
            }
        }
        let Some(connected) = client.as_mut() else {
            let _ = updates.send_blocking(Update::Failed("the node isn't reachable".to_owned()));
            continue;
        };
        match perform(connected, &request) {
            Ok(Some(update)) => {
                keep(history, &request, &update);
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

/// The node's method for a request.
fn method(request: &Request) -> v1::request::Method {
    use v1::request::Method;
    match request {
        // The cache's size is answered by the cache (`from_history`) and never reaches the node.
        Request::Status | Request::CacheSize => Method::GetStatus(v1::GetStatus {}),
        Request::Rules => Method::ListRules(v1::ListRules {}),
        Request::Events { before, query } => Method::ListEvents(v1::ListEvents {
            before: *before,
            limit: PAGE,
            columnar: true,
            query: query.clone(),
        }),
        Request::Answer {
            id,
            action,
            duration,
            suggestion,
        } => Method::AnswerPrompt(v1::AnswerPrompt {
            id: *id,
            action: (*action).into(),
            duration: (*duration).into(),
            suggestion: *suggestion,
            conditions: None,
            folder: None,
        }),
        Request::SetRuleEnabled { id, enabled } => Method::SetRuleEnabled(v1::SetRuleEnabled {
            id: *id,
            enabled: *enabled,
        }),
        Request::DeleteRule { id } => Method::DeleteRule(v1::DeleteRule { id: *id }),
        Request::ImportRules { toml, folder } => Method::ImportRules(v1::ImportRules {
            toml: toml.clone(),
            folder: folder.clone(),
        }),
        Request::AddRule(rule) => Method::AddRule(v1::AddRule {
            rule: Some(rule.clone()),
        }),
        Request::UpdateRule(rule) => Method::UpdateRule(v1::UpdateRule {
            rule: Some(rule.clone()),
        }),
        Request::Changes => Method::ListChanges(v1::ListChanges {
            before: 0,
            limit: 500,
        }),
        Request::Undo { change } => Method::Undo(v1::Undo { change: *change }),
        Request::Explore(explore) => Method::Explore(explore.clone()),
        Request::Connections => Method::ListConnections(v1::ListConnections {}),
        Request::Kill(kill) => Method::KillConnection(kill.clone()),
        Request::Explain { seq } => Method::Explain(v1::Explain { seq: *seq }),
        Request::EditRules(edit) => Method::EditRules(edit.clone()),
        Request::AddFolder(folder) => Method::AddFolder(v1::AddFolder {
            folder: Some(folder.clone()),
        }),
        Request::UpdateFolder(folder) => Method::UpdateFolder(v1::UpdateFolder {
            folder: Some(folder.clone()),
        }),
        Request::DeleteFolder { id } => Method::DeleteFolder(v1::DeleteFolder { id: *id }),
        Request::Policy => Method::GetPolicy(v1::GetPolicy {}),
        Request::SystemFirewall => Method::GetSystemFirewall(v1::GetSystemFirewall {}),
        Request::SetSystemFirewall(set) => Method::SetSystemFirewall(set.clone()),
        Request::Alerts => Method::ListAlerts(v1::ListAlerts {
            before: 0,
            limit: 200,
            open_only: false,
        }),
        Request::Acknowledge { ids, all } => Method::AcknowledgeAlerts(v1::AcknowledgeAlerts {
            ids: ids.clone(),
            all: *all,
        }),
        Request::AlertRules => Method::ListAlertRules(v1::ListAlertRules {}),
        Request::PutAlertRule(rule) => Method::PutAlertRule(v1::PutAlertRule {
            rule: Some(rule.clone()),
        }),
        Request::DeleteAlertRule { id } => Method::DeleteAlertRule(v1::DeleteAlertRule { id: *id }),
        Request::SetPolicy(set) => Method::SetPolicy(set.clone()),
        Request::TrustedClients => Method::ListTrustedClients(v1::ListTrustedClients {}),
        Request::Lint { days } => Method::LintRules(v1::LintRules { unused_days: *days }),
        Request::Proposals => Method::ListProposals(v1::ListProposals {
            pending_only: false,
            limit: 100,
        }),
        Request::Decide(decide) => Method::DecideProposal(decide.clone()),
    }
}

fn perform(client: &mut Client, request: &Request) -> Result<Option<Update>, ClientError> {
    use v1::response::Result as R;
    let result = client.call(method(request))?;
    Ok(match result {
        R::Status(status) => Some(Update::Status(status)),
        R::Rules(rules) => Some(Update::Rules(rules)),
        R::Changes(page) => Some(Update::Changes(page.changes)),
        R::Explored(page) => Some(Update::Explored(page.rows)),
        R::Connections(list) => Some(Update::Connections(list.connections)),
        R::Explanation(explanation) => Some(Update::Explanation(explanation)),
        R::LintReport(report) => Some(Update::Lint(report)),
        R::Policy(policy) => Some(Update::Policy(policy)),
        R::SystemFirewall(firewall) => Some(Update::SystemFirewall(firewall)),
        R::Alerts(page) => Some(Update::Alerts(page.alerts, page.open)),
        R::AlertRules(list) => Some(Update::AlertRules(list.rules)),
        R::TrustedClients(list) => Some(Update::TrustedClients(list.clients)),
        R::Proposals(list) => Some(Update::Proposals(list.proposals)),
        R::Proposal(proposal) => Some(Update::Proposal(proposal)),
        R::EventBlock(event_block) => {
            let (rows, strings) = block(&event_block).map_err(|e| ClientError::Remote {
                code: v1::ErrorCode::Invalid,
                message: e,
            })?;
            let query = match request {
                Request::Events { query, .. } => query.clone(),
                _ => String::new(),
            };
            Some(Update::Events {
                rows,
                strings,
                live: false,
                scanned_from: event_block.scanned_from,
                query,
            })
        }
        _ => None,
    })
}

/// The subscriptions: prompts, rules and live events, resumed after every reconnect.
fn listen(socket: &Path, updates: &async_channel::Sender<Update>, history: &History) {
    let mut last_seq: Option<i64> = None;
    let mut attempt = 0;
    loop {
        let mut connected = false;
        let reason = match subscribe(socket, updates, history, &mut last_seq, &mut connected) {
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
    history: &History,
    last_seq: &mut Option<i64>,
    connected: &mut bool,
) -> Result<(), String> {
    let mut client = connect(socket).map_err(|e| e.to_string())?;
    *connected = true;
    history.connected(client.welcome().node_epoch);
    let send = |update| updates.send_blocking(update).map_err(|_| ());
    if send(Update::Connected(client.welcome().clone())).is_err() {
        return Ok(());
    }
    client
        .subscribe(v1::Topic::Prompts)
        .and_then(|_| client.subscribe(v1::Topic::Rules))
        .and_then(|_| client.subscribe(v1::Topic::Alerts))
        .and_then(|_| client.subscribe(v1::Topic::Proposals))
        .and_then(|_| client.subscribe_with(v1::Topic::Events, *last_seq, true))
        .map_err(|e| e.to_string())?;
    loop {
        let notice = client.notice().map_err(|e| e.to_string())?;
        let update = match notice.body {
            Some(v1::notice::Body::Prompt(prompt)) => Update::Prompt(prompt),
            Some(v1::notice::Body::PromptResolved(resolved)) => Update::Resolved(resolved),
            Some(v1::notice::Body::RulesChanged(_)) => Update::RulesChanged,
            Some(v1::notice::Body::Alert(alert)) => Update::Alert(alert),
            Some(v1::notice::Body::AlertsChanged(changed)) => Update::AlertsChanged(changed.open),
            Some(v1::notice::Body::Proposal(proposal)) => Update::Proposal(proposal),
            Some(v1::notice::Body::EventBlock(event_block)) => {
                let (rows, strings) = block(&event_block)?;
                // Every event after the last one seen comes, in order: the cache holds that range whole.
                history.add_live(&rows, &strings, *last_seq);
                if let Some(newest) = rows.iter().map(|r| r.seq).max() {
                    *last_seq = Some(last_seq.map_or(newest, |seq| seq.max(newest)));
                }
                Update::Events {
                    rows,
                    strings,
                    live: true,
                    scanned_from: 0,
                    query: String::new(),
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
