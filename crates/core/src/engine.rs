//! Deciding a connection: rules compiled into an immutable, indexed set, evaluated without allocating.
//!
//! Precedence is fixed and explainable:
//! 1. the highest tier with any matching rule decides (`override`, then `normal`, then `fallback`);
//! 2. within it, a blocking rule (deny, reject) beats an allowing one;
//! 3. among those, the most specific rule is the one reported (ties: the lowest id).
//!
//! A rule applies only while it and every folder above it are enabled and it hasn't expired. Folder scopes are added
//! to every rule below them. A rule that says nothing about the context applies to the host only, so allowing
//! `/usr/bin/curl` doesn't allow `curl` in every container.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::blocklist::Blocklist;
use crate::destination::{ALIASES, HostPattern, Network};
use crate::pattern::{Pattern, PatternError};
use crate::rule::{
    Action, Condition, ContextKind, Expiry, Folder, FolderId, ProcessRef, Rule, RuleId, Tier,
};

/// What is known about a connection when it is decided. Everything is borrowed: building one allocates nothing.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub exe: &'a str,
    /// Stable identities of the program, if any are known (`pkg:firefox`, `unit:sshd.service`).
    pub apps: &'a [String],
    pub cmdline: &'a str,
    /// Executables of the ancestor processes, nearest first.
    pub ancestors: &'a [String],
    /// The process and its ancestors, nearest first, for `session` conditions.
    pub lineage: &'a [ProcessRef],
    pub uid: u32,
    /// The user's home directory, for `{home}` patterns.
    pub home: Option<&'a str>,
    /// Names known for the destination address (as resolved by this process first).
    pub hosts: &'a [std::sync::Arc<str>],
    pub address: IpAddr,
    pub port: u16,
    pub protocol: u8,
    pub context: ContextKind,
    /// The container's identity, for a container's connection (when it could be read).
    pub container: Option<&'a crate::context::Container>,
    pub vm: Option<&'a crate::context::Vm>,
    /// The network namespace's name, for one with a name.
    pub netns: Option<&'a str>,
    /// Unix time in milliseconds, for expiring rules.
    pub now_ms: u64,
    /// The executable's SHA-256 (lowercase hex), when a rule asks for it ([`RuleSet::needs_sha256`]).
    pub sha256: Option<&'a str>,
    /// Whether a user other than root can change the executable.
    pub writable: bool,
}

/// Blocklists by name, for [`RuleSet::compile_with`].
pub type Lists = HashMap<Box<str>, Arc<Blocklist>>;

/// The outcome for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub rule: RuleId,
    pub action: Action,
    pub tier: Tier,
}

/// One rule that matched, for explaining a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub rule: RuleId,
    pub action: Action,
    pub tier: Tier,
    pub specificity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error("rule {rule}: {error}")]
    Pattern { rule: RuleId, error: PatternError },
    #[error("folder {folder} is its own ancestor")]
    FolderCycle { folder: FolderId },
}

#[derive(Debug, Clone)]
enum Compiled {
    Exe(Vec<Pattern>),
    App(Vec<Pattern>),
    Cmdline(Vec<Pattern>),
    Parent(Vec<Pattern>),
    Uid(Vec<u32>),
    Host(Vec<HostMatcher>),
    Net(Vec<IpNet>),
    Port(Vec<(u16, u16)>),
    Protocol(Vec<u8>),
    Context(ContextKind),
    Session(Vec<ProcessRef>),
    ContainerName(Vec<Pattern>),
    ContainerImage(Vec<Pattern>),
    ContainerCompose(Vec<Pattern>),
    ContainerLabel(Vec<(String, Pattern)>),
    ContainerRuntime(Vec<String>),
    ContainerOwner(Vec<u32>),
    ContainerId(Vec<String>),
    VmName(Vec<Pattern>),
    VmUuid(Vec<String>),
    VmHypervisor(Vec<String>),
    NetnsName(Vec<Pattern>),
    /// The lists that exist (one not read yet matches nothing).
    List(Vec<Arc<Blocklist>>),
    Sha256(Vec<String>),
    Writable(bool),
    Not(Box<Compiled>),
}

/// A host pattern, ready to match: names and suffixes as they are, regular expressions compiled (case-insensitive,
/// over the whole name).
#[derive(Debug, Clone)]
enum HostMatcher {
    Pattern(HostPattern),
    Regex(Pattern),
}

impl HostMatcher {
    fn compile(pattern: &HostPattern) -> Result<Self, PatternError> {
        Ok(match pattern {
            HostPattern::Regex(regex) => Self::Regex(Pattern::compile(
                &crate::pattern::PatternSource::Regex(format!("(?i){regex}")),
            )?),
            other => Self::Pattern(other.clone()),
        })
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Pattern(pattern) => pattern.matches(host),
            Self::Regex(regex) => regex.matches(host.strip_suffix('.').unwrap_or(host), None),
        }
    }

    fn specificity(&self) -> u32 {
        match self {
            Self::Pattern(pattern) => pattern.specificity(),
            Self::Regex(_) => 0,
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: RuleId,
    action: Action,
    tier: Tier,
    expires_ms: Option<u64>,
    specificity: u32,
    conditions: Vec<Compiled>,
}

/// The rules that apply, compiled and indexed. Built once per change and shared read-only by the deciding threads.
///
/// Each rule is filed under its most selective key: the host names it is limited to (lowercase; `*.example.com`
/// under `example.com`), else the exact programs, else the ports; the rest are checked for every connection. A
/// connection looks only at the rules under its own names (and the domains above them), its program and its port.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    by_host: HashMap<Box<str>, Vec<u32>>,
    /// Every rule in `by_host`, for a name with capitals (looked up without allocating a lowercase copy).
    host_indexed: Vec<u32>,
    by_exe: HashMap<Box<str>, Vec<u32>>,
    /// Rules whose conditions name destination ports, by port.
    by_port: HashMap<u16, Vec<u32>>,
    /// Rules that apply to any connection, as far as the index can tell.
    rest: Vec<u32>,
    /// Whether a rule names a SHA-256: only then are executables hashed.
    sha256: bool,
}

/// Where a rule is filed.
enum Key {
    Hosts(Vec<Box<str>>),
    Exes(Vec<Box<str>>),
    Ports(Vec<u16>),
    Rest,
}

/// A rule's most selective key, from its positive conditions.
fn key(conditions: &[Compiled]) -> Key {
    let hosts = conditions.iter().find_map(|c| match c {
        Compiled::Host(matchers) if !matchers.is_empty() => matchers
            .iter()
            .map(|m| match m {
                HostMatcher::Pattern(HostPattern::Exact(name)) => Some(
                    name.trim_end_matches('.')
                        .to_ascii_lowercase()
                        .into_boxed_str(),
                ),
                HostMatcher::Pattern(HostPattern::Subdomains(suffix)) => Some(
                    suffix
                        .trim_start_matches('.')
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                        .into_boxed_str(),
                ),
                _ => None,
            })
            .collect::<Option<Vec<_>>>(),
        _ => None,
    });
    if let Some(hosts) = hosts {
        return Key::Hosts(hosts);
    }
    let exes = conditions.iter().find_map(|c| match c {
        Compiled::Exe(patterns) if !patterns.is_empty() => patterns
            .iter()
            .map(|p| p.exact().map(Box::from))
            .collect::<Option<Vec<_>>>(),
        _ => None,
    });
    if let Some(exes) = exes {
        return Key::Exes(exes);
    }
    indexed_ports(conditions).map_or(Key::Rest, Key::Ports)
}

/// A port condition with at most this many ports is indexed by port; wider ones are checked for every connection.
const MAX_INDEXED_PORTS: usize = 64;

impl RuleSet {
    /// Compiles the rules that apply: enabled, in enabled folders, with their folders' scopes.
    pub fn compile(folders: &[Folder], rules: &[Rule]) -> Result<Self, CompileError> {
        Self::compile_with(folders, rules, &Lists::new())
    }

    /// [`RuleSet::compile`], with the blocklists `list` conditions name.
    pub fn compile_with(
        folders: &[Folder],
        rules: &[Rule],
        lists: &Lists,
    ) -> Result<Self, CompileError> {
        let folder_by_id: HashMap<FolderId, &Folder> = folders.iter().map(|f| (f.id, f)).collect();
        let mut set = Self::default();
        for rule in rules {
            if !rule.enabled {
                continue;
            }
            let Some(scopes) = folder_chain(rule.folder, &folder_by_id)? else {
                continue;
            };
            let mut conditions = Vec::new();
            let mut has_context = false;
            for condition in scopes
                .iter()
                .flat_map(|scope| scope.iter())
                .chain(&rule.conditions)
            {
                if let Some(implied) = crate::rule::implied_context(condition) {
                    if !matches!(condition, Condition::Context(_)) {
                        conditions.push(Compiled::Context(implied));
                    }
                    has_context = true;
                }
                conditions.push(compile_condition(condition, lists).map_err(|error| {
                    CompileError::Pattern {
                        rule: rule.id,
                        error,
                    }
                })?);
            }
            if !has_context {
                conditions.push(Compiled::Context(ContextKind::Host));
            }
            set.sha256 |= conditions.iter().any(names_sha256);
            let specificity = conditions.iter().map(specificity).sum();
            let index = u32::try_from(set.rules.len()).unwrap_or(u32::MAX);
            match key(&conditions) {
                Key::Hosts(hosts) => {
                    for host in hosts {
                        set.by_host.entry(host).or_default().push(index);
                    }
                    set.host_indexed.push(index);
                }
                Key::Exes(exes) => {
                    for exe in exes {
                        set.by_exe.entry(exe).or_default().push(index);
                    }
                }
                Key::Ports(ports) => {
                    for port in ports {
                        set.by_port.entry(port).or_default().push(index);
                    }
                }
                Key::Rest => set.rest.push(index),
            }
            set.rules.push(CompiledRule {
                id: rule.id,
                action: rule.action,
                tier: rule.tier,
                expires_ms: match rule.expiry {
                    Expiry::At(at) => Some(at),
                    Expiry::Never | Expiry::UntilRestart => None,
                },
                specificity,
                conditions,
            });
        }
        Ok(set)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether a rule names an executable's SHA-256, so deciding needs [`Facts::sha256`].
    #[must_use]
    pub fn needs_sha256(&self) -> bool {
        self.sha256
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules that may match: those filed under the connection's names and the domains above them, its program
    /// and its port, and the rest. A rule may come more than once (under two of the names).
    fn candidates<'s>(&'s self, facts: &'s Facts<'_>) -> impl Iterator<Item = &'s CompiledRule> {
        let bucket = |list: Option<&'s Vec<u32>>| list.map_or(&[][..], Vec::as_slice).iter();
        let by_host = facts.hosts.iter().flat_map(move |host| {
            let host: &str = host.strip_suffix('.').unwrap_or(host);
            let lowercase = !host.bytes().any(|b| b.is_ascii_uppercase());
            // A name with capitals: every rule filed under a name (rare: resolvers answer in lowercase).
            let all = if lowercase {
                &[][..]
            } else {
                self.host_indexed.as_slice()
            };
            let names = std::iter::successors(lowercase.then_some(host), |name| {
                name.split_once('.')
                    .map(|(_, parent)| parent)
                    .filter(|p| !p.is_empty())
            });
            all.iter()
                .chain(names.flat_map(move |name| bucket(self.by_host.get(name))))
        });
        by_host
            .chain(bucket(self.by_exe.get(facts.exe)))
            .chain(bucket(self.by_port.get(&facts.port)))
            .chain(&self.rest)
            .filter_map(|&index| self.rules.get(index as usize))
    }

    /// The decision for a connection, or `None` when no rule matches (the policy then decides: ask, allow, deny).
    #[must_use]
    pub fn decide(&self, facts: &Facts<'_>) -> Option<Decision> {
        let mut best: Option<&CompiledRule> = None;
        for rule in self.candidates(facts) {
            if !rule.matches(facts) {
                continue;
            }
            if best.is_none_or(|best| outranks(rule, best)) {
                best = Some(rule);
            }
        }
        best.map(|rule| Decision {
            rule: rule.id,
            action: rule.action,
            tier: rule.tier,
        })
    }

    /// Every rule that matches, in precedence order: the first is the one [`RuleSet::decide`] picks.
    #[must_use]
    pub fn explain(&self, facts: &Facts<'_>) -> Vec<Match> {
        let mut matched: Vec<&CompiledRule> = self
            .candidates(facts)
            .filter(|r| r.matches(facts))
            .collect();
        // A rule filed under two of the connection's names comes twice.
        matched.sort_by_key(|r| std::ptr::from_ref(*r));
        matched.dedup_by_key(|r| std::ptr::from_ref(*r));
        matched.sort_by(|a, b| {
            if outranks(a, b) {
                std::cmp::Ordering::Less
            } else if outranks(b, a) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        matched
            .into_iter()
            .map(|rule| Match {
                rule: rule.id,
                action: rule.action,
                tier: rule.tier,
                specificity: rule.specificity,
            })
            .collect()
    }
}

/// Whether `a` takes precedence over `b`.
fn outranks(a: &CompiledRule, b: &CompiledRule) -> bool {
    (
        a.tier,
        a.action.blocks(),
        a.specificity,
        std::cmp::Reverse(a.id),
    ) > (
        b.tier,
        b.action.blocks(),
        b.specificity,
        std::cmp::Reverse(b.id),
    )
}

impl CompiledRule {
    fn matches(&self, facts: &Facts<'_>) -> bool {
        self.expires_ms.is_none_or(|at| facts.now_ms < at)
            && self.conditions.iter().all(|c| condition_matches(c, facts))
    }
}

fn condition_matches(condition: &Compiled, facts: &Facts<'_>) -> bool {
    let any =
        |patterns: &[Pattern], value: &str| patterns.iter().any(|p| p.matches(value, facts.home));
    match condition {
        Compiled::Exe(patterns) => any(patterns, facts.exe),
        Compiled::App(patterns) => facts.apps.iter().any(|app| any(patterns, app.as_str())),
        Compiled::Cmdline(patterns) => any(patterns, facts.cmdline),
        Compiled::Parent(patterns) => facts
            .ancestors
            .iter()
            .any(|exe| any(patterns, exe.as_str())),
        Compiled::Uid(uids) => uids.contains(&facts.uid),
        Compiled::Host(patterns) => facts
            .hosts
            .iter()
            .any(|host| patterns.iter().any(|p| p.matches(host))),
        Compiled::Net(nets) => nets.iter().any(|net| net.contains(&facts.address)),
        Compiled::Port(ranges) => ranges
            .iter()
            .any(|&(low, high)| (low..=high).contains(&facts.port)),
        Compiled::Protocol(protocols) => protocols.contains(&facts.protocol),
        Compiled::Context(ContextKind::Any) => true,
        Compiled::Context(kind) => *kind == facts.context,
        Compiled::Session(roots) => facts.lineage.iter().any(|p| roots.contains(p)),
        Compiled::ContainerName(patterns) => {
            facts.container.is_some_and(|c| any(patterns, &c.name))
        }
        Compiled::ContainerImage(patterns) => {
            facts.container.is_some_and(|c| any(patterns, &c.image))
        }
        Compiled::ContainerCompose(patterns) => facts
            .container
            .and_then(|c| c.compose.as_deref())
            .is_some_and(|compose| any(patterns, compose)),
        Compiled::ContainerLabel(labels) => facts.container.is_some_and(|c| {
            labels.iter().any(|(key, value)| {
                c.labels
                    .iter()
                    .any(|(k, v)| k == key && value.matches(v, None))
            })
        }),
        Compiled::ContainerRuntime(runtimes) => facts
            .container
            .is_some_and(|c| runtimes.iter().any(|r| r == &c.runtime)),
        Compiled::ContainerOwner(uids) => facts
            .container
            .and_then(|c| c.owner)
            .is_some_and(|owner| uids.contains(&owner)),
        // Ids as `docker ps` shortens them match too.
        Compiled::ContainerId(ids) => facts.container.is_some_and(|c| {
            !c.id.is_empty() && ids.iter().any(|id| c.id.starts_with(id.as_str()))
        }),
        Compiled::VmName(patterns) => facts.vm.is_some_and(|vm| any(patterns, &vm.name)),
        Compiled::VmUuid(uuids) => facts
            .vm
            .is_some_and(|vm| uuids.iter().any(|u| u.eq_ignore_ascii_case(&vm.uuid))),
        Compiled::VmHypervisor(names) => facts
            .vm
            .is_some_and(|vm| names.iter().any(|n| n == &vm.hypervisor)),
        Compiled::NetnsName(patterns) => facts.netns.is_some_and(|name| any(patterns, name)),
        Compiled::Sha256(hashes) => facts
            .sha256
            .is_some_and(|hash| hashes.iter().any(|h| h.eq_ignore_ascii_case(hash))),
        Compiled::Writable(writable) => facts.writable == *writable,
        Compiled::List(lists) => lists.iter().any(|list| {
            list.has_address(facts.address) || facts.hosts.iter().any(|h| list.has_host(h))
        }),
        Compiled::Not(inner) => !condition_matches(inner, facts),
    }
}

/// The scopes of a rule's folders, outermost first; `None` when one of them is disabled.
fn folder_chain<'a>(
    mut folder: Option<FolderId>,
    folders: &HashMap<FolderId, &'a Folder>,
) -> Result<Option<Vec<&'a [Condition]>>, CompileError> {
    let mut scopes = Vec::new();
    let mut seen = Vec::new();
    while let Some(id) = folder {
        if seen.contains(&id) {
            return Err(CompileError::FolderCycle { folder: id });
        }
        seen.push(id);
        // A rule in a folder that no longer exists doesn't apply.
        let Some(current) = folders.get(&id) else {
            return Ok(None);
        };
        if !current.enabled {
            return Ok(None);
        }
        scopes.push(current.scope.as_slice());
        folder = current.parent;
    }
    scopes.reverse();
    Ok(Some(scopes))
}

fn names_sha256(condition: &Compiled) -> bool {
    match condition {
        Compiled::Sha256(_) => true,
        Compiled::Not(inner) => names_sha256(inner),
        _ => false,
    }
}

fn compile_condition(condition: &Condition, lists: &Lists) -> Result<Compiled, PatternError> {
    let patterns =
        |sources: &[crate::pattern::PatternSource]| -> Result<Vec<Pattern>, PatternError> {
            sources.iter().map(Pattern::compile).collect()
        };
    Ok(match condition {
        Condition::Exe(p) => Compiled::Exe(patterns(p)?),
        Condition::App(p) => Compiled::App(patterns(p)?),
        Condition::Cmdline(p) => Compiled::Cmdline(patterns(p)?),
        Condition::Parent(p) => Compiled::Parent(patterns(p)?),
        Condition::Uid(uids) => Compiled::Uid(uids.clone()),
        Condition::Host(hosts) => Compiled::Host(
            hosts
                .iter()
                .map(HostMatcher::compile)
                .collect::<Result<_, _>>()?,
        ),
        Condition::Net(networks) => Compiled::Net(networks.iter().flat_map(expand).collect()),
        Condition::Port(ranges) => Compiled::Port(ranges.clone()),
        Condition::Protocol(protocols) => Compiled::Protocol(protocols.clone()),
        Condition::Context(kind) => Compiled::Context(*kind),
        Condition::Session(roots) => Compiled::Session(roots.clone()),
        Condition::ContainerName(p) => Compiled::ContainerName(patterns(p)?),
        Condition::ContainerImage(p) => Compiled::ContainerImage(patterns(p)?),
        Condition::ContainerCompose(p) => Compiled::ContainerCompose(patterns(p)?),
        Condition::ContainerLabel(labels) => Compiled::ContainerLabel(
            labels
                .iter()
                .map(|(key, value)| Ok((key.clone(), Pattern::compile(value)?)))
                .collect::<Result<_, PatternError>>()?,
        ),
        Condition::ContainerRuntime(runtimes) => Compiled::ContainerRuntime(runtimes.clone()),
        Condition::ContainerOwner(uids) => Compiled::ContainerOwner(uids.clone()),
        Condition::ContainerId(ids) => Compiled::ContainerId(ids.clone()),
        Condition::VmName(p) => Compiled::VmName(patterns(p)?),
        Condition::VmUuid(uuids) => Compiled::VmUuid(uuids.clone()),
        Condition::VmHypervisor(names) => Compiled::VmHypervisor(names.clone()),
        Condition::NetnsName(p) => Compiled::NetnsName(patterns(p)?),
        Condition::Sha256(hashes) => Compiled::Sha256(hashes.clone()),
        Condition::Writable(writable) => Compiled::Writable(*writable),
        Condition::List(names) => Compiled::List(
            names
                .iter()
                .filter_map(|name| lists.get(name.as_str()).cloned())
                .collect(),
        ),
        Condition::Not(inner) => Compiled::Not(Box::new(compile_condition(inner, lists)?)),
    })
}

fn expand(network: &Network) -> Vec<IpNet> {
    match network {
        Network::Net(net) => vec![*net],
        Network::Alias(index) => ALIASES
            .get(*index)
            .into_iter()
            .flat_map(|(_, nets)| nets.iter().filter_map(|net| net.parse().ok()))
            .collect(),
    }
}

fn specificity(condition: &Compiled) -> u32 {
    match condition {
        Compiled::Exe(p) | Compiled::App(p) | Compiled::Cmdline(p) | Compiled::Parent(p) => {
            p.iter().map(Pattern::specificity).min().unwrap_or(0) * 10
        }
        Compiled::Host(p) => p.iter().map(HostMatcher::specificity).min().unwrap_or(0),
        Compiled::Net(nets) => nets
            .iter()
            .map(|n| u32::from(n.prefix_len()))
            .min()
            .unwrap_or(0),
        Compiled::Port(_) | Compiled::Uid(_) => 5,
        Compiled::Protocol(_) | Compiled::Writable(_) => 1,
        // Who in the container ranks as a program does; the container itself, between the program and nothing.
        Compiled::ContainerName(p)
        | Compiled::ContainerImage(p)
        | Compiled::ContainerCompose(p)
        | Compiled::VmName(p)
        | Compiled::NetnsName(p) => p.iter().map(Pattern::specificity).min().unwrap_or(0) * 5,
        Compiled::ContainerId(_) | Compiled::VmUuid(_) => 50,
        Compiled::ContainerLabel(_) => 20,
        // Like a domain and everything under it.
        Compiled::List(_) => 3,
        // As exact as a program's path.
        Compiled::Sha256(_) => 30,
        Compiled::ContainerRuntime(_) | Compiled::ContainerOwner(_) | Compiled::VmHypervisor(_) => {
            2
        }
        Compiled::Context(_) | Compiled::Session(_) | Compiled::Not(_) => 0,
    }
}

/// The ports a rule is indexed under: those of a (positive) port condition naming few enough of them.
fn indexed_ports(conditions: &[Compiled]) -> Option<Vec<u16>> {
    conditions.iter().find_map(|condition| match condition {
        Compiled::Port(ranges) => {
            let count: usize = ranges
                .iter()
                .map(|&(low, high)| usize::from(high.saturating_sub(low)) + 1)
                .sum();
            (count <= MAX_INDEXED_PORTS)
                .then(|| ranges.iter().flat_map(|&(low, high)| low..=high).collect())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::PatternSource;

    fn rule(id: RuleId, action: Action, conditions: Vec<Condition>) -> Rule {
        Rule {
            id,
            folder: None,
            name: format!("rule {id}"),
            enabled: true,
            action,
            tier: Tier::Normal,
            expiry: Expiry::Never,
            log: true,
            notes: String::new(),
            conditions,
        }
    }

    fn exe(path: &str) -> Condition {
        Condition::Exe(vec![PatternSource::Exact(path.to_owned())])
    }

    fn host(name: &str) -> Condition {
        Condition::Host(vec![HostPattern::try_from(name.to_owned()).unwrap()])
    }

    /// Host names for facts, leaked: tests only.
    fn names(hosts: &[&str]) -> &'static [std::sync::Arc<str>] {
        Box::leak(
            hosts
                .iter()
                .map(|h| std::sync::Arc::from(*h))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    fn facts<'a>(exe: &'a str, hosts: &[&str], port: u16) -> Facts<'a> {
        Facts {
            exe,
            apps: &[],
            sha256: None,
            writable: false,
            cmdline: "",
            ancestors: &[],
            lineage: &[],
            uid: 1000,
            home: Some("/home/ada"),
            hosts: names(hosts),
            address: "198.51.100.7".parse().unwrap(),
            port,
            protocol: 6,
            context: ContextKind::Host,
            now_ms: 1_000,
            container: None,
            vm: None,
            netns: None,
        }
    }

    #[test]
    fn nothing_matches_an_empty_set() {
        let set = RuleSet::compile(&[], &[]).unwrap();
        assert_eq!(set.decide(&facts("/usr/bin/curl", &[], 443)), None);
    }

    #[test]
    fn a_matching_allow_decides() {
        let set = RuleSet::compile(
            &[],
            &[rule(
                1,
                Action::Allow,
                vec![
                    exe("/usr/bin/curl"),
                    host("example.com"),
                    Condition::Port(vec![(443, 443)]),
                ],
            )],
        )
        .unwrap();
        let decision = set
            .decide(&facts("/usr/bin/curl", &["example.com"], 443))
            .unwrap();
        assert_eq!((decision.rule, decision.action), (1, Action::Allow));
        assert_eq!(
            set.decide(&facts("/usr/bin/curl", &["example.com"], 80)),
            None
        );
        assert_eq!(
            set.decide(&facts("/usr/bin/wget", &["example.com"], 443)),
            None
        );
    }

    #[test]
    fn the_index_decides_as_checking_every_rule_does() {
        let mut rules = Vec::new();
        let mut id = 0;
        let mut next = |action, conditions| {
            id += 1;
            rule(id, action, conditions)
        };
        for i in 0..40_u16 {
            let action = if i % 3 == 0 {
                Action::Deny
            } else {
                Action::Allow
            };
            rules.push(next(
                action,
                vec![host(&format!("*.s{}.example.com", i % 7))],
            ));
            rules.push(next(
                action,
                vec![
                    host(&format!("api.s{}.example.com", i % 5)),
                    exe("/usr/bin/curl"),
                ],
            ));
            rules.push(next(action, vec![exe(&format!("/usr/bin/app{}", i % 6))]));
            rules.push(next(
                action,
                vec![Condition::Port(vec![(8000 + i % 4, 8000 + i % 4)])],
            ));
            rules.push(next(action, vec![host(r"re:.*\.s3\.example\.com")]));
            rules.push(next(
                action,
                vec![Condition::Not(Box::new(host("x.example.com")))],
            ));
            rules.push(next(
                action,
                vec![Condition::Net(vec![
                    Network::try_from("lan".to_owned()).unwrap(),
                ])],
            ));
        }
        let set = RuleSet::compile(&[], &rules).unwrap();
        let everything = |facts: &Facts<'_>| {
            let mut best: Option<&CompiledRule> = None;
            for rule in set.rules.iter().filter(|r| r.matches(facts)) {
                if best.is_none_or(|b| outranks(rule, b)) {
                    best = Some(rule);
                }
            }
            best.map(|r| (r.id, r.action))
        };
        let names = [
            "api.s1.example.com",
            "API.S2.Example.com",
            "s3.example.com",
            "deep.a.s4.example.com.",
            "x.example.com",
            "example.com",
            "elsewhere.org",
        ];
        for exe_path in ["/usr/bin/curl", "/usr/bin/app2", "/usr/bin/other"] {
            for name in names {
                for port in [443, 8001, 8003] {
                    let f = facts(exe_path, &[name], port);
                    assert_eq!(
                        set.decide(&f).map(|d| (d.rule, d.action)),
                        everything(&f),
                        "{exe_path} {name} {port}"
                    );
                    assert_eq!(
                        set.explain(&f).first().map(|m| (m.rule, m.action)),
                        everything(&f)
                    );
                }
            }
            let f = facts(exe_path, &[], 8002);
            assert_eq!(set.decide(&f).map(|d| (d.rule, d.action)), everything(&f));
        }
    }

    #[test]
    fn binaries_are_pinned_by_hash_and_writability_is_a_condition() {
        let hash = "ab".repeat(32);
        let pinned = rule(
            1,
            Action::Allow,
            vec![Condition::Sha256(vec![hash.clone()])],
        );
        let writable = rule(2, Action::Deny, vec![Condition::Writable(true)]);
        let set = RuleSet::compile(&[], &[pinned, writable]).unwrap();
        assert!(set.needs_sha256());
        let mut f = facts("/usr/bin/curl", &[], 443);
        assert_eq!(set.decide(&f), None);
        f.sha256 = Some(&hash);
        assert_eq!(set.decide(&f).map(|d| d.rule), Some(1));
        f.writable = true;
        assert_eq!(set.decide(&f).map(|d| d.action), Some(Action::Deny));
        assert!(!RuleSet::compile(&[], &[]).unwrap().needs_sha256());
    }

    #[test]
    fn blocklists_match_names_and_addresses() {
        let lists = Lists::from([(
            Box::from("ads"),
            Arc::new(Blocklist::parse("tracker.example\n198.51.100.0/24\n").list),
        )]);
        let rules = [rule(
            1,
            Action::Deny,
            vec![Condition::List(vec![
                "ads".to_owned(),
                "missing".to_owned(),
            ])],
        )];
        let set = RuleSet::compile_with(&[], &rules, &lists).unwrap();
        // By the name, and by the address.
        let mut elsewhere = facts("/usr/bin/curl", &["a.tracker.example"], 443);
        elsewhere.address = "192.0.2.1".parse().unwrap();
        assert!(set.decide(&elsewhere).is_some());
        assert!(set.decide(&facts("/usr/bin/curl", &[], 443)).is_some());
        elsewhere.hosts = names(&["example.org"]);
        assert!(set.decide(&elsewhere).is_none());
        // Without the lists, nothing is on them.
        assert!(
            RuleSet::compile(&[], &rules)
                .unwrap()
                .decide(&facts("/usr/bin/curl", &[], 443))
                .is_none()
        );
    }

    #[test]
    fn regular_expressions_match_whole_host_names_in_any_case() {
        let set = RuleSet::compile(
            &[],
            &[rule(
                1,
                Action::Allow,
                vec![host(r"re:(.*\.)?example\.(com|org)")],
            )],
        )
        .unwrap();
        for name in ["example.com", "API.Example.org", "a.b.example.com."] {
            assert!(
                set.decide(&facts("/usr/bin/curl", &[name], 443)).is_some(),
                "{name}"
            );
        }
        for name in ["example.net", "notexample.com", "example.com.evil.net"] {
            assert!(
                set.decide(&facts("/usr/bin/curl", &[name], 443)).is_none(),
                "{name}"
            );
        }
        assert!(HostPattern::try_from("re:(".to_owned()).is_err());
    }

    #[test]
    fn deny_beats_allow_in_the_same_tier_and_tiers_beat_both() {
        let mut rules = vec![
            rule(
                1,
                Action::Allow,
                vec![exe("/usr/bin/curl"), host("example.com")],
            ),
            rule(2, Action::Deny, vec![host("example.com")]),
        ];
        let set = RuleSet::compile(&[], &rules).unwrap();
        assert_eq!(
            set.decide(&facts("/usr/bin/curl", &["example.com"], 443))
                .unwrap()
                .rule,
            2
        );

        rules[0].tier = Tier::Override;
        let set = RuleSet::compile(&[], &rules).unwrap();
        assert_eq!(
            set.decide(&facts("/usr/bin/curl", &["example.com"], 443))
                .unwrap()
                .rule,
            1
        );
    }

    #[test]
    fn the_most_specific_rule_is_reported() {
        let set = RuleSet::compile(
            &[],
            &[
                rule(1, Action::Allow, vec![host("*.example.com")]),
                rule(2, Action::Allow, vec![host("api.example.com")]),
            ],
        )
        .unwrap();
        let matched = set.explain(&facts("/usr/bin/curl", &["api.example.com"], 443));
        assert_eq!(
            matched.iter().map(|m| m.rule).collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert_eq!(
            set.decide(&facts("/usr/bin/curl", &["api.example.com"], 443))
                .unwrap()
                .rule,
            2
        );
    }

    #[test]
    fn rules_are_for_the_host_unless_they_say_otherwise() {
        let set =
            RuleSet::compile(&[], &[rule(1, Action::Allow, vec![exe("/usr/bin/curl")])]).unwrap();
        let mut in_container = facts("/usr/bin/curl", &[], 443);
        in_container.context = ContextKind::Container;
        assert_eq!(set.decide(&in_container), None);

        let set = RuleSet::compile(
            &[],
            &[rule(
                1,
                Action::Allow,
                vec![exe("/usr/bin/curl"), Condition::Context(ContextKind::Any)],
            )],
        )
        .unwrap();
        assert!(set.decide(&in_container).is_some());
    }

    #[test]
    fn disabled_folders_disable_everything_below_and_scopes_apply_to_it() {
        let folders = vec![
            Folder {
                id: 10,
                parent: None,
                name: "Apps".into(),
                enabled: true,
                scope: vec![],
            },
            Folder {
                id: 11,
                parent: Some(10),
                name: "Claude".into(),
                enabled: true,
                scope: vec![Condition::Exe(vec![PatternSource::Glob(
                    "{home}/.local/share/claude/versions/*/claude".into(),
                )])],
            },
        ];
        let mut rules = vec![rule(1, Action::Allow, vec![host("api.example.com")])];
        rules[0].folder = Some(11);
        let set = RuleSet::compile(&folders, &rules).unwrap();
        let claude = "/home/ada/.local/share/claude/versions/2.0.31/claude";
        assert!(
            set.decide(&facts(claude, &["api.example.com"], 443))
                .is_some()
        );
        assert!(
            set.decide(&facts("/usr/bin/curl", &["api.example.com"], 443))
                .is_none()
        );

        let mut disabled = folders.clone();
        disabled[0].enabled = false;
        let set = RuleSet::compile(&disabled, &rules).unwrap();
        assert!(
            set.decide(&facts(claude, &["api.example.com"], 443))
                .is_none()
        );
    }

    #[test]
    fn folder_cycles_are_errors() {
        let folders = vec![
            Folder {
                id: 1,
                parent: Some(2),
                name: "a".into(),
                enabled: true,
                scope: vec![],
            },
            Folder {
                id: 2,
                parent: Some(1),
                name: "b".into(),
                enabled: true,
                scope: vec![],
            },
        ];
        let mut rules = vec![rule(1, Action::Allow, vec![])];
        rules[0].folder = Some(1);
        assert!(matches!(
            RuleSet::compile(&folders, &rules),
            Err(CompileError::FolderCycle { .. })
        ));
    }

    #[test]
    fn expired_rules_dont_match() {
        let mut rules = vec![rule(1, Action::Allow, vec![exe("/usr/bin/curl")])];
        rules[0].expiry = Expiry::At(500);
        let set = RuleSet::compile(&[], &rules).unwrap();
        assert!(set.decide(&facts("/usr/bin/curl", &[], 443)).is_none());
    }

    #[test]
    fn networks_aliases_and_negation() {
        let lan = Network::try_from("lan".to_owned()).unwrap();
        let set = RuleSet::compile(
            &[],
            &[rule(
                1,
                Action::Deny,
                vec![Condition::Not(Box::new(Condition::Net(vec![lan])))],
            )],
        )
        .unwrap();
        let mut outside = facts("/usr/bin/curl", &[], 443);
        assert!(set.decide(&outside).is_some());
        outside.address = "192.168.1.5".parse().unwrap();
        assert!(set.decide(&outside).is_none());
    }

    #[test]
    fn port_indexed_and_unindexed_rules_are_both_found() {
        let set = RuleSet::compile(
            &[],
            &[
                rule(1, Action::Allow, vec![Condition::Port(vec![(443, 443)])]),
                rule(2, Action::Allow, vec![Condition::Port(vec![(1024, 65535)])]),
                rule(3, Action::Allow, vec![exe("/usr/bin/curl")]),
            ],
        )
        .unwrap();
        assert_eq!(set.explain(&facts("/usr/bin/curl", &[], 443)).len(), 2);
        assert_eq!(set.explain(&facts("/usr/bin/curl", &[], 5000)).len(), 2);
        assert_eq!(set.explain(&facts("/usr/bin/wget", &[], 80)).len(), 0);
    }

    /// The test facts, in `container` (on the host for none).
    fn in_container(container: Option<&crate::context::Container>, port: u16) -> Facts<'_> {
        Facts {
            context: if container.is_some() {
                ContextKind::Container
            } else {
                ContextKind::Host
            },
            container,
            ..facts("/usr/local/bin/node", &[], port)
        }
    }

    #[test]
    fn container_conditions_hold_for_that_container_only() {
        let web = crate::context::Container {
            runtime: "docker".to_owned(),
            id: "0133794d05ab40d47d94868c4fb19a4d610f6c97e3ee0c5ee5fcf8aa21c03ea9".to_owned(),
            name: "shop-web-1".to_owned(),
            image: "docker.io/library/node:22".to_owned(),
            compose: Some("shop/web".to_owned()),
            labels: vec![("tier".to_owned(), "front".to_owned())],
            owner: None,
        };
        let other = crate::context::Container {
            name: "db".to_owned(),
            compose: Some("shop/db".to_owned()),
            ..web.clone()
        };
        let set = RuleSet::compile(
            &[],
            &[
                rule(
                    1,
                    Action::Allow,
                    vec![
                        Condition::ContainerCompose(vec![PatternSource::Exact(
                            "shop/web".to_owned(),
                        )]),
                        Condition::Exe(vec![PatternSource::Exact(
                            "/usr/local/bin/node".to_owned(),
                        )]),
                    ],
                ),
                rule(
                    2,
                    Action::Allow,
                    vec![
                        Condition::ContainerImage(vec![PatternSource::Glob(
                            "docker.io/library/node:*".to_owned(),
                        )]),
                        Condition::ContainerLabel(vec![(
                            "tier".to_owned(),
                            PatternSource::Exact("front".to_owned()),
                        )]),
                        Condition::ContainerId(vec!["0133794d05ab".to_owned()]),
                        Condition::Port(vec![(8443, 8443)]),
                    ],
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            set.decide(&in_container(Some(&web), 443)).map(|d| d.rule),
            Some(1)
        );
        assert_eq!(
            set.decide(&in_container(Some(&other), 443)),
            None,
            "another service"
        );
        // On the host, the same program: a container condition holds for containers only.
        assert_eq!(set.decide(&in_container(None, 443)), None);
        assert_eq!(
            set.decide(&in_container(Some(&web), 8443)).map(|d| d.rule),
            Some(2)
        );
        let unlabelled = crate::context::Container {
            labels: Vec::new(),
            ..web.clone()
        };
        // Without the label, only the service's rule is left.
        assert_eq!(
            set.decide(&in_container(Some(&unlabelled), 8443))
                .map(|d| d.rule),
            Some(1)
        );
    }
}
