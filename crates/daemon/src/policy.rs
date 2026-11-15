//! The node's policy: the settings of `daemon.toml` that clients may change while the daemon runs (mode, what happens
//! to connections no rule decides, prompts' timeouts, how long history is kept). What clients changed is kept in the
//! database, recorded in the history like rule changes, and takes precedence over the file; a reset returns a setting
//! to the file's.

use serde::{Deserialize, Serialize};
use snitchhiker_core::rule::Action;
use snitchhiker_proto::{convert, v1};

use crate::config::{Config, Mode, Policy};

/// The settings clients changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_match: Option<Policy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_client: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

/// The policy in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub mode: Mode,
    pub no_match: Policy,
    pub no_client: Action,
    pub prompt_timeout_secs: u64,
    pub on_timeout: Action,
    pub retention_days: u32,
}

impl Effective {
    #[must_use]
    pub fn of(config: &Config, overrides: &Overrides) -> Self {
        Self {
            mode: overrides.mode.unwrap_or(config.mode),
            no_match: overrides.no_match.unwrap_or(config.no_match),
            no_client: overrides.no_client.unwrap_or(config.no_client),
            prompt_timeout_secs: overrides
                .prompt_timeout_secs
                .unwrap_or(config.prompt_timeout_secs),
            on_timeout: overrides.on_timeout.unwrap_or(config.on_timeout),
            retention_days: overrides.retention_days.unwrap_or(config.retention_days),
        }
    }

    /// Whether going from `self` to `after` lets through connections that were blocked: a dangerous action.
    #[must_use]
    pub fn loosened_by(&self, after: &Self) -> bool {
        let opens =
            |before: Action, after: Action| after == Action::Allow && before != Action::Allow;
        (self.mode == Mode::Enforce && after.mode == Mode::Monitor)
            || (after.no_match == Policy::Allow && self.no_match != Policy::Allow)
            || opens(self.no_client, after.no_client)
            || opens(self.on_timeout, after.on_timeout)
    }
}

/// The settings' names, as the protocol's `reset` and `changed` give them.
pub const SETTINGS: [&str; 6] = [
    "mode",
    "no_match",
    "no_client",
    "prompt_timeout_secs",
    "on_timeout",
    "retention_days",
];

/// Prompts wait at least this long, and at most this long: a client must have time to show one, and a connection
/// can't be held forever.
pub const PROMPT_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 5..=3_600;

#[derive(Debug, thiserror::Error)]
pub enum Invalid {
    #[error("unknown setting `{0}`")]
    Unknown(String),
    #[error("no such value for {0}")]
    Value(&'static str),
    #[error("prompts wait 5 to 3600 seconds")]
    Timeout,
    #[error("history is kept 1 to 3650 days")]
    Retention,
}

impl Overrides {
    /// These overrides with `set` applied: its values set, its `reset` settings back to the file's.
    pub fn apply(&self, set: &v1::SetPolicy) -> Result<Self, Invalid> {
        let mut next = self.clone();
        if let Some(mode) = set.mode {
            next.mode = Some(match v1::Mode::try_from(mode) {
                Ok(v1::Mode::Enforce) => Mode::Enforce,
                Ok(v1::Mode::Monitor) => Mode::Monitor,
                _ => return Err(Invalid::Value("mode")),
            });
        }
        if let Some(policy) = set.no_match {
            next.no_match = Some(match v1::Policy::try_from(policy) {
                Ok(v1::Policy::Allow) => Policy::Allow,
                Ok(v1::Policy::Deny) => Policy::Deny,
                Ok(v1::Policy::Reject) => Policy::Reject,
                Ok(v1::Policy::Ask) => Policy::Ask,
                _ => return Err(Invalid::Value("no_match")),
            });
        }
        let action = |value: i32, name| {
            v1::Action::try_from(value)
                .ok()
                .and_then(convert::action_from)
                .ok_or(Invalid::Value(name))
        };
        if let Some(value) = set.no_client {
            next.no_client = Some(action(value, "no_client")?);
        }
        if let Some(value) = set.on_timeout {
            next.on_timeout = Some(action(value, "on_timeout")?);
        }
        if let Some(secs) = set.prompt_timeout_secs {
            let secs = u64::from(secs);
            if !PROMPT_TIMEOUT_SECS.contains(&secs) {
                return Err(Invalid::Timeout);
            }
            next.prompt_timeout_secs = Some(secs);
        }
        if let Some(days) = set.retention_days {
            if !(1..=3650).contains(&days) {
                return Err(Invalid::Retention);
            }
            next.retention_days = Some(days);
        }
        for name in &set.reset {
            match name.as_str() {
                "mode" => next.mode = None,
                "no_match" => next.no_match = None,
                "no_client" => next.no_client = None,
                "prompt_timeout_secs" => next.prompt_timeout_secs = None,
                "on_timeout" => next.on_timeout = None,
                "retention_days" => next.retention_days = None,
                other => return Err(Invalid::Unknown(other.to_owned())),
            }
        }
        Ok(next)
    }

    /// The settings set, by name.
    #[must_use]
    pub fn changed(&self) -> Vec<String> {
        let set = [
            self.mode.is_some(),
            self.no_match.is_some(),
            self.no_client.is_some(),
            self.prompt_timeout_secs.is_some(),
            self.on_timeout.is_some(),
            self.retention_days.is_some(),
        ];
        SETTINGS
            .iter()
            .zip(set)
            .filter(|(_, set)| *set)
            .map(|(name, _)| (*name).to_owned())
            .collect()
    }
}

#[must_use]
pub fn mode(mode: Mode) -> v1::Mode {
    match mode {
        Mode::Enforce => v1::Mode::Enforce,
        Mode::Monitor => v1::Mode::Monitor,
    }
}

#[must_use]
pub fn policy(policy: Policy) -> v1::Policy {
    match policy {
        Policy::Allow => v1::Policy::Allow,
        Policy::Deny => v1::Policy::Deny,
        Policy::Reject => v1::Policy::Reject,
        Policy::Ask => v1::Policy::Ask,
    }
}

/// The policy as the protocol has it.
#[must_use]
pub fn wire(effective: &Effective, overrides: &Overrides) -> v1::NodePolicy {
    v1::NodePolicy {
        mode: mode(effective.mode).into(),
        no_match: policy(effective.no_match).into(),
        no_client: convert::action(effective.no_client).into(),
        prompt_timeout_secs: u32::try_from(effective.prompt_timeout_secs).unwrap_or(u32::MAX),
        on_timeout: convert::action(effective.on_timeout).into(),
        retention_days: effective.retention_days,
        changed: overrides.changed(),
    }
}

/// How a change of policy reads in the history: `no_match ask → deny, mode reset`.
#[must_use]
pub fn describe(before: &Effective, after: &Effective) -> String {
    let lower = |text: String| text.to_lowercase();
    let mut parts = Vec::new();
    let mut part = |name: &str, before: String, after: String| {
        if before != after {
            parts.push(format!("{name} {before} → {after}"));
        }
    };
    part(
        "mode",
        lower(format!("{:?}", before.mode)),
        lower(format!("{:?}", after.mode)),
    );
    part(
        "no_match",
        lower(format!("{:?}", before.no_match)),
        lower(format!("{:?}", after.no_match)),
    );
    part(
        "no_client",
        lower(format!("{:?}", before.no_client)),
        lower(format!("{:?}", after.no_client)),
    );
    part(
        "prompt_timeout_secs",
        before.prompt_timeout_secs.to_string(),
        after.prompt_timeout_secs.to_string(),
    );
    part(
        "on_timeout",
        lower(format!("{:?}", before.on_timeout)),
        lower(format!("{:?}", after.on_timeout)),
    );
    part(
        "retention_days",
        before.retention_days.to_string(),
        after.retention_days.to_string(),
    );
    if parts.is_empty() {
        "policy unchanged".to_owned()
    } else {
        format!("policy: {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_take_precedence_and_reset_to_the_file() {
        let config = Config::default();
        let set = v1::SetPolicy {
            no_match: Some(v1::Policy::Deny.into()),
            prompt_timeout_secs: Some(60),
            ..v1::SetPolicy::default()
        };
        let overrides = Overrides::default().apply(&set).unwrap();
        let effective = Effective::of(&config, &overrides);
        assert_eq!(effective.no_match, Policy::Deny);
        assert_eq!(effective.prompt_timeout_secs, 60);
        assert_eq!(effective.mode, config.mode);
        assert_eq!(overrides.changed(), vec!["no_match", "prompt_timeout_secs"]);
        let reset = overrides
            .apply(&v1::SetPolicy {
                reset: vec!["no_match".to_owned()],
                ..v1::SetPolicy::default()
            })
            .unwrap();
        assert_eq!(Effective::of(&config, &reset).no_match, config.no_match);
        assert!(matches!(
            Overrides::default().apply(&v1::SetPolicy {
                prompt_timeout_secs: Some(1),
                ..v1::SetPolicy::default()
            }),
            Err(Invalid::Timeout)
        ));
        assert!(
            Overrides::default()
                .apply(&v1::SetPolicy {
                    reset: vec!["colour".to_owned()],
                    ..v1::SetPolicy::default()
                })
                .is_err()
        );
    }

    #[test]
    fn loosening_is_told_apart() {
        let config = Config::default();
        let base = Effective::of(&config, &Overrides::default());
        let with = |o: Overrides| Effective::of(&config, &o);
        assert!(base.loosened_by(&with(Overrides {
            mode: Some(Mode::Monitor),
            ..Overrides::default()
        })));
        assert!(base.loosened_by(&with(Overrides {
            no_match: Some(Policy::Allow),
            ..Overrides::default()
        })));
        assert!(!base.loosened_by(&with(Overrides {
            no_match: Some(Policy::Reject),
            retention_days: Some(7),
            ..Overrides::default()
        })));
        assert_eq!(
            describe(
                &base,
                &with(Overrides {
                    retention_days: Some(7),
                    ..Overrides::default()
                })
            ),
            format!("policy: retention_days {} → 7", config.retention_days)
        );
    }
}
