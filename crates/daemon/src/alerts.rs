//! Alerts: raised by the node about itself, and by the user's alert rules over the connections recorded. Every alert is
//! kept, published to the clients subscribed to alerts, and logged (to the journal, under systemd).

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use snitchhiker_core::query::{self, EventFilter, EventView};
use snitchhiker_proto::v1;
use tracing::warn;

use crate::runtime::Shared;
use crate::store::{Event, Recorded, Store};

/// An alert rule, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertRule {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub query: String,
    pub threshold: u32,
    #[serde(default)]
    pub window_secs: u32,
    #[serde(default)]
    pub first_program: bool,
}

impl AlertRule {
    /// The rule a client sent, checked; its query compiles.
    pub fn from_wire(wire: &v1::AlertRule) -> Result<Self, String> {
        let rule = Self {
            id: wire.id,
            name: wire.name.trim().to_owned(),
            enabled: wire.enabled,
            query: wire.query.trim().to_owned(),
            threshold: wire.threshold,
            window_secs: wire.window_secs,
            first_program: wire.first_program,
        };
        if rule.name.is_empty() {
            return Err("an alert rule needs a name".to_owned());
        }
        if rule.threshold == 0 {
            return Err("the threshold is at least 1".to_owned());
        }
        if rule.window_secs > 7 * 86_400 {
            return Err("the window is at most a week".to_owned());
        }
        filter(&rule.query).map_err(|e| format!("query: {e}"))?;
        Ok(rule)
    }

    #[must_use]
    pub fn wire(&self) -> v1::AlertRule {
        v1::AlertRule {
            id: self.id,
            name: self.name.clone(),
            enabled: self.enabled,
            query: self.query.clone(),
            threshold: self.threshold,
            window_secs: self.window_secs,
            first_program: self.first_program,
        }
    }
}

fn filter(text: &str) -> Result<EventFilter, query::QueryError> {
    EventFilter::parse(
        text,
        &query::Context {
            now_ms: crate::runtime::now_ms(),
            uid_of: &crate::process::uid_of,
        },
    )
}

/// An alert to raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAlert {
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    pub rule: Option<u64>,
}

/// An alert as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAlert {
    pub id: u64,
    pub time_ms: u64,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub rule: Option<u64>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
}

impl StoredAlert {
    #[must_use]
    pub fn wire(&self) -> v1::Alert {
        v1::Alert {
            id: self.id,
            time_ms: self.time_ms,
            kind: self.kind.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            rule: self.rule,
            acknowledged: self.acknowledged,
            acknowledged_by: self.acknowledged_by.clone().unwrap_or_default(),
        }
    }
}

/// Keeps `alert`, logs it and publishes it to the clients subscribed to alerts; devices not connected are woken to
/// fetch it.
pub fn raise(shared: &Shared, store: &Store, alert: &NewAlert) {
    warn!(kind = alert.kind, title = %alert.title, body = %alert.body, "alert");
    match store.insert_alert(alert, crate::runtime::now_ms()) {
        Ok(stored) => {
            shared
                .hub
                .publish(v1::Topic::Alerts, &v1::notice::Body::Alert(stored.wire()));
            shared.router.wake_for_alert(&shared.hub);
        }
        Err(error) => warn!(%error, "keeping an alert"),
    }
}

/// The user's alert rules over the connections as they are recorded: run on the writer's thread.
#[derive(Default)]
pub struct Engine {
    rules: Vec<(AlertRule, EventFilter)>,
    /// For each rule, the times (ms) of the matching connections in its window.
    windows: HashMap<u64, VecDeque<u64>>,
    /// For each rule, when it may fire again.
    quiet_until: HashMap<u64, u64>,
}

/// After firing, a rule is quiet for its window, or this long at least.
const QUIET_MS: u64 = 60_000;

impl Engine {
    /// Takes the rules as they now are (a rule whose query no longer compiles, after a user was removed, is skipped).
    pub fn load(&mut self, rules: Vec<AlertRule>) {
        self.rules = rules
            .into_iter()
            .filter(|r| r.enabled)
            .filter_map(|rule| match filter(&rule.query) {
                Ok(compiled) => Some((rule, compiled)),
                Err(error) => {
                    warn!(rule = rule.id, %error, "an alert rule's query doesn't compile");
                    None
                }
            })
            .collect();
        let ids: Vec<u64> = self.rules.iter().map(|(r, _)| r.id).collect();
        self.windows.retain(|id, _| ids.contains(id));
        self.quiet_until.retain(|id, _| ids.contains(id));
    }

    /// The alerts `events` (with what recording them found) raise.
    pub fn check(&mut self, events: &[Event], recorded: &[Recorded]) -> Vec<NewAlert> {
        let mut alerts = Vec::new();
        if self.rules.is_empty() {
            return alerts;
        }
        for (event, recorded) in events.iter().zip(recorded) {
            let view = EventView {
                time_ms: event.time_ms,
                exe: &event.exe,
                host: event.host.as_deref().unwrap_or(""),
                address: event.address,
                port: event.port,
                protocol: event.protocol,
                uid: event.uid,
                action: crate::store::action_code(event.action),
                rule: event.rule.unwrap_or(0),
                context: event.context,
                bytes_out: 0,
                bytes_in: 0,
            };
            for (rule, filter) in &self.rules {
                if rule.first_program && (!recorded.new_exe || event.exe.is_empty()) {
                    continue;
                }
                if !filter.matches(&view) {
                    continue;
                }
                let window_ms = u64::from(rule.window_secs) * 1000;
                let times = self.windows.entry(rule.id).or_default();
                times.push_back(event.time_ms);
                while times
                    .front()
                    .is_some_and(|t| *t + window_ms < event.time_ms)
                {
                    times.pop_front();
                }
                let quiet = self.quiet_until.get(&rule.id).copied().unwrap_or(0);
                if times.len() >= rule.threshold as usize && event.time_ms >= quiet {
                    let count = times.len();
                    times.clear();
                    // Each new program is news of its own: rules on them aren't quieted.
                    if !rule.first_program {
                        self.quiet_until
                            .insert(rule.id, event.time_ms + window_ms.max(QUIET_MS));
                    }
                    alerts.push(NewAlert {
                        kind: "alert_rule",
                        title: rule.name.clone(),
                        body: describe(rule, count, event),
                        rule: Some(rule.id),
                    });
                }
            }
        }
        alerts
    }
}

fn describe(rule: &AlertRule, count: usize, event: &Event) -> String {
    let destination = event.host.as_deref().map_or_else(
        || std::net::SocketAddr::new(event.address, event.port).to_string(),
        |host| format!("{host}:{}", event.port),
    );
    let what = if rule.first_program {
        "A program's first connection"
    } else if count == 1 {
        "A connection"
    } else {
        "connections"
    };
    let mut text = if count == 1 {
        format!("{what}: {} → {destination}", event.exe)
    } else {
        format!(
            "{count} {what} in {} s; the last: {} → {destination}",
            rule.window_secs, event.exe
        )
    };
    if !rule.query.is_empty() {
        let _ = write!(text, " (matching `{}`)", rule.query);
    }
    text
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use snitchhiker_core::rule::Action;

    use super::*;
    use crate::store::Source;

    fn event(time_ms: u64, exe: &str, port: u16) -> Event {
        Event {
            time_ms,
            exe: Arc::from(exe),
            host: Some(Arc::from("example.com")),
            uid: 1000,
            pid: 1,
            protocol: 6,
            address: "198.51.100.7".parse().unwrap(),
            port,
            context: 0,
            action: Action::Deny,
            source: Source::Rule,
            rule: Some(1),
            cookie: None,
            container: None,
        }
    }

    fn recorded(new_exe: bool) -> Recorded {
        Recorded {
            seq: 1,
            exe: 1,
            host: 1,
            new_exe,
            container: 0,
        }
    }

    fn rule(
        id: u64,
        query: &str,
        threshold: u32,
        window_secs: u32,
        first_program: bool,
    ) -> AlertRule {
        AlertRule {
            id,
            name: format!("rule {id}"),
            enabled: true,
            query: query.to_owned(),
            threshold,
            window_secs,
            first_program,
        }
    }

    #[test]
    fn a_threshold_within_a_window_fires_once_then_quiets() {
        let mut engine = Engine::default();
        engine.load(vec![rule(1, "action:deny port:22", 3, 10, false)]);
        let events: Vec<Event> = [0, 1_000, 2_000, 3_000, 4_000]
            .iter()
            .map(|t| event(*t, "/usr/bin/ssh", 22))
            .collect();
        let rec: Vec<Recorded> = events.iter().map(|_| recorded(false)).collect();
        let alerts = engine.check(&events, &rec);
        assert_eq!(alerts.len(), 1);
        assert!(
            alerts[0].body.starts_with("3 connections in 10 s"),
            "{}",
            alerts[0].body
        );
        // Spread out, they never reach the threshold.
        let mut engine = Engine::default();
        engine.load(vec![rule(1, "", 2, 1, false)]);
        let sparse: Vec<Event> = [0, 5_000, 10_000]
            .iter()
            .map(|t| event(*t, "/x", 1))
            .collect();
        assert_eq!(engine.check(&sparse, &rec[..3]), vec![]);
    }

    #[test]
    fn first_program_counts_only_new_programs() {
        let mut engine = Engine::default();
        engine.load(vec![rule(7, "", 1, 0, true)]);
        let events = vec![
            event(0, "/usr/bin/curl", 443),
            event(1_000, "/opt/new", 443),
            event(2_000, "/opt/newer", 443),
        ];
        let alerts = engine.check(&events, &[recorded(false), recorded(true), recorded(true)]);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].rule, Some(7));
        assert!(alerts[0].body.contains("/opt/new"));
        assert!(alerts[1].body.contains("/opt/newer"));
    }

    #[test]
    fn rules_are_checked_when_sent() {
        let wire = |query: &str, threshold| v1::AlertRule {
            name: "x".to_owned(),
            query: query.to_owned(),
            threshold,
            ..v1::AlertRule::default()
        };
        assert!(AlertRule::from_wire(&wire("port:22", 1)).is_ok());
        assert!(AlertRule::from_wire(&wire("colour:red", 1)).is_err());
        assert!(AlertRule::from_wire(&wire("", 0)).is_err());
    }
}
