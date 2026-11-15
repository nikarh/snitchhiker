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

use ipnet::IpNet;

use crate::destination::{ALIASES, HostPattern, Network};
use crate::pattern::{Pattern, PatternError};
use crate::rule::{Action, Condition, ContextKind, Expiry, Folder, FolderId, Rule, RuleId, Tier};

/// What is known about a connection when it is decided. Everything is borrowed: building one allocates nothing.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub exe: &'a str,
    /// Stable identities of the program, if any are known (`pkg:firefox`, `unit:sshd.service`).
    pub apps: &'a [String],
    pub cmdline: &'a str,
    /// Executables of the ancestor processes, nearest first.
    pub ancestors: &'a [String],
    pub uid: u32,
    /// The user's home directory, for `{home}` patterns.
    pub home: Option<&'a str>,
    /// Names known for the destination address (as resolved by this process first).
    pub hosts: &'a [std::sync::Arc<str>],
    pub address: IpAddr,
    pub port: u16,
    pub protocol: u8,
    pub context: ContextKind,
    /// Unix time in milliseconds, for expiring rules.
    pub now_ms: u64,
}

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
    Host(Vec<HostPattern>),
    Net(Vec<IpNet>),
    Port(Vec<(u16, u16)>),
    Protocol(Vec<u8>),
    Context(ContextKind),
    Not(Box<Compiled>),
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
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    /// Rules whose conditions name destination ports, by port.
    by_port: HashMap<u16, Vec<u32>>,
    /// Rules that apply to any port.
    any_port: Vec<u32>,
}

/// A port condition with at most this many ports is indexed by port; wider ones are checked for every connection.
const MAX_INDEXED_PORTS: usize = 64;

impl RuleSet {
    /// Compiles the rules that apply: enabled, in enabled folders, with their folders' scopes.
    pub fn compile(folders: &[Folder], rules: &[Rule]) -> Result<Self, CompileError> {
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
                has_context |= matches!(condition, Condition::Context(_));
                conditions.push(compile_condition(condition).map_err(|error| {
                    CompileError::Pattern {
                        rule: rule.id,
                        error,
                    }
                })?);
            }
            if !has_context {
                conditions.push(Compiled::Context(ContextKind::Host));
            }
            let specificity = conditions.iter().map(specificity).sum();
            let index = u32::try_from(set.rules.len()).unwrap_or(u32::MAX);
            match indexed_ports(&conditions) {
                Some(ports) => {
                    for port in ports {
                        set.by_port.entry(port).or_default().push(index);
                    }
                }
                None => set.any_port.push(index),
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

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn candidates(&self, port: u16) -> impl Iterator<Item = &CompiledRule> {
        self.by_port
            .get(&port)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .chain(&self.any_port)
            .filter_map(|&index| self.rules.get(index as usize))
    }

    /// The decision for a connection, or `None` when no rule matches (the policy then decides: ask, allow, deny).
    #[must_use]
    pub fn decide(&self, facts: &Facts<'_>) -> Option<Decision> {
        let mut best: Option<&CompiledRule> = None;
        for rule in self.candidates(facts.port) {
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
            .candidates(facts.port)
            .filter(|r| r.matches(facts))
            .collect();
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

fn compile_condition(condition: &Condition) -> Result<Compiled, PatternError> {
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
        Condition::Host(hosts) => Compiled::Host(hosts.clone()),
        Condition::Net(networks) => Compiled::Net(networks.iter().flat_map(expand).collect()),
        Condition::Port(ranges) => Compiled::Port(ranges.clone()),
        Condition::Protocol(protocols) => Compiled::Protocol(protocols.clone()),
        Condition::Context(kind) => Compiled::Context(*kind),
        Condition::Not(inner) => Compiled::Not(Box::new(compile_condition(inner)?)),
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
        Compiled::Host(p) => p.iter().map(HostPattern::specificity).min().unwrap_or(0),
        Compiled::Net(nets) => nets
            .iter()
            .map(|n| u32::from(n.prefix_len()))
            .min()
            .unwrap_or(0),
        Compiled::Port(_) | Compiled::Uid(_) => 5,
        Compiled::Protocol(_) => 1,
        Compiled::Context(_) | Compiled::Not(_) => 0,
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
            cmdline: "",
            ancestors: &[],
            uid: 1000,
            home: Some("/home/ada"),
            hosts: names(hosts),
            address: "198.51.100.7".parse().unwrap(),
            port,
            protocol: 6,
            context: ContextKind::Host,
            now_ms: 1_000,
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
}
