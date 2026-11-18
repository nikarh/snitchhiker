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
    /// A container's name.
    ContainerName(Vec<PatternSource>),
    /// The image reference a container was created from (`docker.io/library/node:*`).
    ContainerImage(Vec<PatternSource>),
    /// A container's Compose project and service, `project/service`.
    ContainerCompose(Vec<PatternSource>),
    /// A container's labels: the key, and a pattern for the value.
    ContainerLabel(Vec<(String, PatternSource)>),
    ContainerRuntime(Vec<String>),
    /// The user a rootless container runs as.
    ContainerOwner(Vec<u32>),
    /// Container ids, or their prefixes. They change each time a container is recreated: names, Compose services
    /// and images are the stable choices.
    ContainerId(Vec<String>),
    VmName(Vec<PatternSource>),
    VmUuid(Vec<String>),
    VmHypervisor(Vec<String>),
    /// The name of a network namespace (`ip netns`).
    NetnsName(Vec<PatternSource>),
    /// The destination is on one of these blocklists (by name): its host name or its address.
    List(Vec<String>),
    /// The executable's SHA-256 (lowercase hex) is one of these: the binary pinned.
    Sha256(Vec<String>),
    /// The executable can (`true`) or can't be changed by a user other than root.
    Writable(bool),
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

/// The context a condition implies: one on a container's identity holds only for containers.
#[must_use]
pub fn implied_context(condition: &Condition) -> Option<ContextKind> {
    match condition {
        Condition::Context(kind) => Some(*kind),
        Condition::ContainerName(_)
        | Condition::ContainerImage(_)
        | Condition::ContainerCompose(_)
        | Condition::ContainerLabel(_)
        | Condition::ContainerRuntime(_)
        | Condition::ContainerOwner(_)
        | Condition::ContainerId(_) => Some(ContextKind::Container),
        Condition::VmName(_) | Condition::VmUuid(_) | Condition::VmHypervisor(_) => {
            Some(ContextKind::Vm)
        }
        Condition::NetnsName(_) => Some(ContextKind::Netns),
        _ => None,
    }
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
