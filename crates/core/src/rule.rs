//! The rule model: folders in a tree, and rules with conditions, as stored, exported and edited.

use serde::{Deserialize, Serialize};

use crate::destination::{HostPattern, Network};
use crate::pattern::PatternSource;

pub type FolderId = u64;
pub type RuleId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    /// Drop the packet: the program sees a timeout.
    Deny,
    /// Drop it and close the socket: the program fails at once.
    Reject,
}

impl Action {
    #[must_use]
    pub fn blocks(self) -> bool {
        matches!(self, Self::Deny | Self::Reject)
    }
}

/// Rules are looked at by tier, highest first; within a tier, blocking beats allowing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Fallback,
    #[default]
    Normal,
    Override,
}

/// When a rule stops applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "at")]
pub enum Expiry {
    #[default]
    Never,
    /// Until the daemon restarts; never written to disk.
    UntilRestart,
    /// Unix time in milliseconds.
    At(u64),
}

/// Where a connection comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextKind {
    #[default]
    Host,
    Container,
    Vm,
    Netns,
    /// In a rule: any of them.
    Any,
}

/// One condition of a rule; all of a rule's conditions must hold. A list inside a condition means any of its items.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "on", content = "is")]
pub enum Condition {
    /// The executable's path (inside its container, for containers).
    Exe(Vec<PatternSource>),
    /// A stable identity of the program (`pkg:firefox`, `flatpak:org.mozilla.firefox`, `unit:sshd.service`, ...).
    App(Vec<PatternSource>),
    Cmdline(Vec<PatternSource>),
    /// The executable of any ancestor process.
    Parent(Vec<PatternSource>),
    Uid(Vec<u32>),
    Host(Vec<HostPattern>),
    Net(Vec<Network>),
    /// Inclusive port ranges.
    Port(Vec<(u16, u16)>),
    /// IP protocol numbers.
    Protocol(Vec<u8>),
    Context(ContextKind),
    /// A process or anything it started (an agent's session, decision 0008).
    Session(Vec<ProcessRef>),
    /// The opposite of the inner condition.
    Not(Box<Condition>),
}

/// A process, as the kernel knows it for its whole life: its pid and when it started (clock ticks since boot), so a
/// pid reused by a later process never counts as it. Written `pid@start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub start: u64,
}

impl std::fmt::Display for ProcessRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.pid, self.start)
    }
}

impl std::str::FromStr for ProcessRef {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, ()> {
        let (pid, start) = text.trim().split_once('@').ok_or(())?;
        Ok(Self {
            pid: pid.parse().map_err(|_| ())?,
            start: start.parse().map_err(|_| ())?,
        })
    }
}

/// Whether a rule with these conditions (its own, and its folders' scopes) allows every program to reach anywhere: an
/// allow rule that names no program and no destination. Asking for one is a dangerous action.
pub fn allows_everything<'a>(
    action: Action,
    conditions: impl IntoIterator<Item = &'a Condition>,
) -> bool {
    action == Action::Allow
        && !conditions.into_iter().any(|condition| {
            matches!(
                condition,
                Condition::Exe(_)
                    | Condition::App(_)
                    | Condition::Cmdline(_)
                    | Condition::Parent(_)
                    | Condition::Host(_)
                    | Condition::Net(_)
            )
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub id: FolderId,
    pub parent: Option<FolderId>,
    pub name: String,
    pub enabled: bool,
    /// Conditions added to every rule in this folder and below.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub folder: Option<FolderId>,
    pub name: String,
    pub enabled: bool,
    pub action: Action,
    #[serde(default)]
    pub tier: Tier,
    #[serde(default)]
    pub expiry: Expiry,
    #[serde(default = "yes")]
    pub log: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    pub conditions: Vec<Condition>,
}

const fn yes() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_rules_without_program_or_destination_allow_everything() {
        let port = Condition::Port(vec![(443, 443)]);
        let exe = Condition::Exe(vec![PatternSource::Exact("/usr/bin/curl".to_owned())]);
        let not_host = Condition::Not(Box::new(Condition::Host(vec![])));
        assert!(allows_everything(Action::Allow, [&port]));
        assert!(allows_everything(Action::Allow, [&port, &not_host]));
        assert!(!allows_everything(Action::Allow, [&port, &exe]));
        assert!(!allows_everything(Action::Deny, [&port]));
    }
}
