//! The lint and dedupe report over a rule set: duplicates, rules another one makes redundant, allow rules a deny always
//! beats, expired rules, and, from what the node knows, rules never hit, on binaries any user can replace, or on
//! binaries that are gone (with the pattern that would cover their new version).
//!
//! Every finding is certain: a rule is called redundant only when the other rule matches everything it matches, which
//! is decided on the conditions as written (an exact value inside a pattern, a network inside a network, a port range
//! inside a range), never guessed from names.

use crate::destination::{HostPattern, Network};
use crate::generalize;
use crate::pattern::{HOME, Pattern, PatternSource};
use crate::rule::{Action, Condition, ContextKind, Expiry, Rule, RuleId};

/// What the node knows that the rules don't.
pub trait NodeFacts {
    /// Whether the file exists.
    fn exists(&self, path: &str) -> bool;
    /// Whether a user other than root can replace the file (it, or a directory above it, is writable by one).
    fn writable_by_user(&self, path: &str) -> bool;
    /// Whether some file matches the glob (`*` within one path component).
    fn exists_like(&self, glob: &str) -> bool;
    /// When the rule last decided a connection, and when it was last changed (Unix ms).
    fn last_hit_ms(&self, rule: RuleId) -> Option<u64>;
    fn changed_ms(&self, rule: RuleId) -> Option<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Matches exactly what `other` matches, with the same action.
    Duplicate,
    /// `other` matches everything this one does, with the same action, at the same tier or above.
    Redundant,
    /// An allow rule that a deny or reject (`other`) always beats.
    Shadowed,
    /// Its time is up; it no longer applies.
    Expired,
    /// It decided no connection in the days asked about.
    NeverHit,
    /// An allow rule on a binary that a user other than root can replace.
    WritableBinary,
    /// Its binary is gone; `suggestion` covers the one that took its place, if there is one.
    MissingBinary,
    /// It and `other` differ only in one list of destinations (hosts, networks or ports): `merged` is one rule for
    /// both.
    Mergeable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: Kind,
    pub rule: RuleId,
    pub other: Option<RuleId>,
    /// A pattern to replace the rule's program with.
    pub suggestion: Option<PatternSource>,
    /// For a mergeable rule: the other rule's conditions, with both lists.
    pub merged: Option<Vec<Condition>>,
}

/// A rule as the lint sees it: with its folders' scopes, and whether it is in effect (it and its folders enabled).
pub struct Linted<'a> {
    pub rule: &'a Rule,
    /// Its own conditions and its folders' scopes.
    pub conditions: Vec<&'a Condition>,
    pub effective: bool,
    /// Locked rules can't be changed: they make others redundant but aren't reported themselves.
    pub locked: bool,
}

/// The report: findings in rule order.
pub fn lint(
    rules: &[Linted<'_>],
    facts: &dyn NodeFacts,
    now_ms: u64,
    unused_days: u32,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let finding = |kind, rule: &Rule, other: Option<&Rule>| Finding {
        kind,
        rule: rule.id,
        other: other.map(|o| o.id),
        suggestion: None,
        merged: None,
    };
    for (i, a) in rules.iter().enumerate() {
        if a.locked {
            continue;
        }
        let rule = a.rule;
        if let Expiry::At(at) = rule.expiry
            && at <= now_ms
        {
            findings.push(finding(Kind::Expired, rule, None));
            continue;
        }
        if !a.effective {
            continue;
        }
        // Redundancy and shadowing, against every other rule in effect.
        let mut found = None;
        for (j, b) in rules.iter().enumerate() {
            if i == j || !b.effective || matches!(b.rule.expiry, Expiry::At(at) if at <= now_ms) {
                continue;
            }
            let (other, mine) = (b.rule, rule);
            if !covers(&b.conditions, &a.conditions) {
                continue;
            }
            if other.action == mine.action && other.tier >= mine.tier {
                let mutual = other.tier == mine.tier && covers(&a.conditions, &b.conditions);
                // Of two duplicates, the newer one is reported (unless the older one is locked).
                if mutual && !b.locked && other.id > mine.id {
                    continue;
                }
                found = Some(finding(
                    if mutual {
                        Kind::Duplicate
                    } else {
                        Kind::Redundant
                    },
                    mine,
                    Some(other),
                ));
                break;
            }
            if mine.action == Action::Allow && other.action.blocks() && other.tier >= mine.tier {
                found = Some(finding(Kind::Shadowed, mine, Some(other)));
                break;
            }
        }
        findings.extend(found);
        // What the node knows.
        let since = now_ms.saturating_sub(u64::from(unused_days) * 86_400_000);
        if unused_days > 0
            && facts
                .changed_ms(rule.id)
                .is_some_and(|changed| changed < since)
            && facts.last_hit_ms(rule.id).is_none_or(|hit| hit < since)
        {
            findings.push(finding(Kind::NeverHit, rule, None));
        }
        for path in exact_exes(rule) {
            if !facts.exists(path) {
                let generalized = generalize::executable(path, None);
                let suggestion = match &generalized {
                    PatternSource::Glob(glob) if facts.exists_like(glob) => Some(generalized),
                    _ => None,
                };
                findings.push(Finding {
                    suggestion,
                    ..finding(Kind::MissingBinary, rule, None)
                });
            } else if rule.action == Action::Allow && facts.writable_by_user(path) {
                findings.push(finding(Kind::WritableBinary, rule, None));
            }
        }
    }
    let reported: std::collections::HashSet<RuleId> = findings.iter().map(|f| f.rule).collect();
    findings.extend(mergeable(rules, &reported, now_ms));
    findings
}

/// Pairs of rules that differ only in one list of destinations: the newer one could go, with its list added to the
/// older's. Both in effect, changeable, in the same folder, with the same action, tier, expiry and logging, and
/// neither `reported` with another problem (whose fix comes first).
fn mergeable(
    rules: &[Linted<'_>],
    reported: &std::collections::HashSet<RuleId>,
    now_ms: u64,
) -> Vec<Finding> {
    let mut found = Vec::new();
    let candidates: Vec<&Rule> = rules
        .iter()
        .filter(|l| {
            l.effective
                && !l.locked
                && !reported.contains(&l.rule.id)
                && !matches!(l.rule.expiry, Expiry::At(at) if at <= now_ms)
        })
        .map(|l| l.rule)
        .collect();
    let mut merged_away = std::collections::HashSet::new();
    for (i, older) in candidates.iter().enumerate() {
        if merged_away.contains(&older.id) {
            continue;
        }
        for newer in candidates.iter().skip(i + 1) {
            if merged_away.contains(&newer.id)
                || (
                    older.folder,
                    older.action,
                    older.tier,
                    older.expiry,
                    older.log,
                ) != (
                    newer.folder,
                    newer.action,
                    newer.tier,
                    newer.expiry,
                    newer.log,
                )
            {
                continue;
            }
            if let Some(merged) = merge(&older.conditions, &newer.conditions) {
                merged_away.insert(newer.id);
                found.push(Finding {
                    kind: Kind::Mergeable,
                    rule: newer.id,
                    other: Some(older.id),
                    suggestion: None,
                    merged: Some(merged),
                });
            }
        }
    }
    found
}

/// `a` with `b`'s values of the one condition they differ in, if they differ only in one host, network or port
/// list (and both have it).
fn merge(a: &[Condition], b: &[Condition]) -> Option<Vec<Condition>> {
    if a.len() != b.len() {
        return None;
    }
    let differing: Vec<&Condition> = a.iter().filter(|c| !b.contains(c)).collect();
    let [mine] = differing.as_slice() else {
        return None;
    };
    let theirs = b.iter().find(|c| !a.contains(c))?;
    let union = match (mine, theirs) {
        (Condition::Host(x), Condition::Host(y)) => Condition::Host(
            x.iter()
                .chain(y.iter().filter(|h| !x.contains(h)))
                .cloned()
                .collect(),
        ),
        (Condition::Net(x), Condition::Net(y)) => Condition::Net(
            x.iter()
                .chain(y.iter().filter(|n| !x.contains(n)))
                .cloned()
                .collect(),
        ),
        (Condition::Port(x), Condition::Port(y)) => Condition::Port(
            x.iter()
                .chain(y.iter().filter(|p| !x.contains(p)))
                .copied()
                .collect(),
        ),
        _ => return None,
    };
    Some(
        a.iter()
            .map(|c| if c == *mine { union.clone() } else { c.clone() })
            .collect(),
    )
}

/// A rule's programs given as exact paths (not under `{home}`: whose home it is depends on the connection).
fn exact_exes(rule: &Rule) -> impl Iterator<Item = &str> {
    rule.conditions.iter().flat_map(|c| match c {
        Condition::Exe(patterns) => patterns
            .iter()
            .filter_map(|p| match p {
                PatternSource::Exact(path) if !path.starts_with(HOME) && path.starts_with('/') => {
                    Some(path.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    })
}

/// Whether a rule with conditions `broad` matches every connection one with `narrow` does: each of `broad`'s
/// conditions is implied by one of `narrow`'s. A rule without a context condition is on the host.
#[must_use]
pub fn covers(broad: &[&Condition], narrow: &[&Condition]) -> bool {
    let host = Condition::Context(ContextKind::Host);
    let context = |conditions: &[&Condition]| {
        !conditions
            .iter()
            .any(|c| matches!(c, Condition::Context(_)))
    };
    let narrow_host = context(narrow).then_some(&host);
    let broad_host = context(broad).then_some(&host);
    broad.iter().copied().chain(broad_host).all(|b| {
        narrow
            .iter()
            .copied()
            .chain(narrow_host)
            .any(|n| implies(n, b))
    })
}

/// Whether every connection meeting `narrow` meets `broad`.
fn implies(narrow: &Condition, broad: &Condition) -> bool {
    let all = |narrow: &[PatternSource], broad: &[PatternSource]| {
        narrow
            .iter()
            .all(|n| broad.iter().any(|b| pattern_covers(b, n)))
    };
    match (narrow, broad) {
        (Condition::Exe(n), Condition::Exe(b))
        | (Condition::App(n), Condition::App(b))
        | (Condition::Cmdline(n), Condition::Cmdline(b))
        | (Condition::Parent(n), Condition::Parent(b)) => all(n, b),
        (Condition::Uid(n), Condition::Uid(b)) => n.iter().all(|u| b.contains(u)),
        (Condition::Protocol(n), Condition::Protocol(b)) => n.iter().all(|p| b.contains(p)),
        (Condition::Port(n), Condition::Port(b)) => n
            .iter()
            .all(|(low, high)| b.iter().any(|(l, h)| l <= low && high <= h)),
        (Condition::Host(n), Condition::Host(b)) => {
            n.iter().all(|n| b.iter().any(|b| host_covers(b, n)))
        }
        (Condition::Net(n), Condition::Net(b)) => {
            n.iter().all(|n| b.iter().any(|b| net_covers(b, n)))
        }
        (Condition::Context(n), Condition::Context(b)) => n == b || *b == ContextKind::Any,
        (n @ Condition::Not(_), b @ Condition::Not(_)) => n == b,
        _ => false,
    }
}

fn pattern_covers(broad: &PatternSource, narrow: &PatternSource) -> bool {
    if broad == narrow {
        return true;
    }
    match narrow {
        // An exact value inside a pattern; with `{home}` on both sides or neither.
        PatternSource::Exact(value) => {
            let broad_home = match broad {
                PatternSource::Exact(t) | PatternSource::Glob(t) | PatternSource::Regex(t) => {
                    t.starts_with(HOME)
                }
            };
            match value.strip_prefix(HOME) {
                Some(rest) if broad_home => Pattern::compile(broad)
                    .is_ok_and(|p| p.matches(&format!("/h{rest}"), Some("/h"))),
                None if !broad_home => {
                    Pattern::compile(broad).is_ok_and(|p| p.matches(value, None))
                }
                _ => false,
            }
        }
        PatternSource::Glob(_) | PatternSource::Regex(_) => false,
    }
}

fn host_covers(broad: &HostPattern, narrow: &HostPattern) -> bool {
    match narrow {
        _ if broad == narrow => true,
        HostPattern::Exact(name) => broad.matches(name),
        HostPattern::Subdomains(suffix) => match broad {
            HostPattern::Subdomains(wider) => {
                suffix.len() >= wider.len()
                    && suffix
                        .get(suffix.len() - wider.len()..)
                        .is_some_and(|tail| tail.eq_ignore_ascii_case(wider))
            }
            HostPattern::Exact(_) | HostPattern::Regex(_) => false,
        },
        HostPattern::Regex(_) => false,
    }
}

fn net_covers(broad: &Network, narrow: &Network) -> bool {
    match (broad, narrow) {
        (Network::Net(b), Network::Net(n)) => b.contains(n),
        _ => broad == narrow,
    }
}

impl Kind {
    /// A short explanation, for people.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicates another rule",
            Self::Redundant => {
                "another rule already matches everything it does, with the same action"
            }
            Self::Shadowed => "a deny or reject rule always beats it",
            Self::Expired => "its time is up",
            Self::NeverHit => "decided no connection in the days looked at",
            Self::WritableBinary => "allows a binary that a user other than root can replace",
            Self::MissingBinary => "its binary is gone",
            Self::Mergeable => "it can be merged with another",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::rule::Tier;

    #[derive(Default)]
    struct Facts {
        files: Vec<&'static str>,
        writable: Vec<&'static str>,
        hits: HashMap<RuleId, u64>,
    }

    impl NodeFacts for Facts {
        fn exists(&self, path: &str) -> bool {
            self.files.contains(&path)
        }
        fn writable_by_user(&self, path: &str) -> bool {
            self.writable.contains(&path)
        }
        fn exists_like(&self, glob: &str) -> bool {
            let pattern = Pattern::compile(&PatternSource::Glob(glob.to_owned())).unwrap();
            self.files.iter().any(|f| pattern.matches(f, None))
        }
        fn last_hit_ms(&self, rule: RuleId) -> Option<u64> {
            self.hits.get(&rule).copied()
        }
        fn changed_ms(&self, _: RuleId) -> Option<u64> {
            Some(0)
        }
    }

    fn rule(id: RuleId, action: Action, conditions: Vec<Condition>) -> Rule {
        Rule {
            id,
            folder: None,
            name: format!("r{id}"),
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

    fn host(pattern: &str) -> Condition {
        Condition::Host(vec![HostPattern::try_from(pattern.to_owned()).unwrap()])
    }

    fn report(rules: &[Rule], facts: &Facts) -> Vec<(Kind, RuleId, Option<RuleId>)> {
        let linted: Vec<Linted<'_>> = rules
            .iter()
            .map(|r| Linted {
                rule: r,
                conditions: r.conditions.iter().collect(),
                effective: r.enabled,
                locked: false,
            })
            .collect();
        lint(&linted, facts, 10 * 86_400_000, 0)
            .into_iter()
            .map(|f| (f.kind, f.rule, f.other))
            .collect()
    }

    #[test]
    fn duplicates_redundant_and_shadowed_rules_are_found() {
        let curl = "/usr/bin/curl";
        let facts = Facts {
            files: vec![curl],
            ..Facts::default()
        };
        let rules = vec![
            rule(1, Action::Allow, vec![exe(curl), host("*.example.com")]),
            // The same as 1.
            rule(2, Action::Allow, vec![host("*.example.com"), exe(curl)]),
            // Inside 1: a subdomain of example.com.
            rule(
                3,
                Action::Allow,
                vec![
                    exe(curl),
                    host("api.example.com"),
                    Condition::Port(vec![(443, 443)]),
                ],
            ),
            // Not inside 1: another program.
            rule(
                4,
                Action::Allow,
                vec![exe("/usr/bin/wget"), host("api.example.com")],
            ),
            // A deny on all of example.com for curl beats 5 at the same tier.
            rule(5, Action::Deny, vec![exe(curl), host("*.example.org")]),
            rule(6, Action::Allow, vec![exe(curl), host("www.example.org")]),
        ];
        assert_eq!(
            report(&rules, &facts),
            vec![
                (Kind::Duplicate, 2, Some(1)),
                (Kind::Redundant, 3, Some(1)),
                (Kind::MissingBinary, 4, None),
                (Kind::Shadowed, 6, Some(5)),
            ]
        );
    }

    #[test]
    fn rules_differing_only_in_destinations_can_merge() {
        let curl = "/usr/bin/curl";
        let facts = Facts {
            files: vec![curl],
            ..Facts::default()
        };
        let mut denied = rule(4, Action::Deny, vec![exe(curl), host("c.org")]);
        denied.folder = Some(9);
        let rules = [
            rule(1, Action::Allow, vec![exe(curl), host("a.org")]),
            rule(2, Action::Allow, vec![exe(curl), host("b.org")]),
            // Another program too: two differences.
            rule(3, Action::Allow, vec![exe("/usr/bin/wget"), host("d.org")]),
            denied,
        ];
        let linted: Vec<Linted<'_>> = rules
            .iter()
            .map(|r| Linted {
                rule: r,
                conditions: r.conditions.iter().collect(),
                effective: true,
                locked: false,
            })
            .collect();
        let found: Vec<Finding> = lint(&linted, &facts, 10 * 86_400_000, 0)
            .into_iter()
            .filter(|f| f.kind == Kind::Mergeable)
            .collect();
        assert_eq!(found.len(), 1);
        let finding = &found[0];
        assert_eq!((finding.rule, finding.other), (2, Some(1)));
        assert_eq!(
            finding.merged.as_deref(),
            Some(
                &[
                    exe(curl),
                    Condition::Host(vec![
                        HostPattern::try_from("a.org".to_owned()).unwrap(),
                        HostPattern::try_from("b.org".to_owned()).unwrap(),
                    ]),
                ][..]
            )
        );
        let ports = |p: u16| vec![exe(curl), Condition::Port(vec![(p, p)])];
        assert_eq!(
            merge(&ports(80), &ports(443)),
            Some(vec![exe(curl), Condition::Port(vec![(80, 80), (443, 443)])])
        );
        assert_eq!(merge(&ports(80), &[exe(curl), host("a.org")]), None);
    }

    #[test]
    fn a_higher_tier_allow_isnt_shadowed() {
        let curl = "/usr/bin/curl";
        let facts = Facts {
            files: vec![curl],
            ..Facts::default()
        };
        let mut allow = rule(2, Action::Allow, vec![exe(curl), host("www.example.org")]);
        allow.tier = Tier::Override;
        let rules = vec![rule(1, Action::Deny, vec![exe(curl)]), allow];
        assert_eq!(report(&rules, &facts), vec![]);
    }

    #[test]
    fn coverage_is_decided_on_the_conditions() {
        fn c(conditions: &[Condition]) -> Vec<&Condition> {
            conditions.iter().collect()
        }
        let glob = Condition::Exe(vec![PatternSource::Glob("/opt/app/*/bin".to_owned())]);
        assert!(covers(
            &c(std::slice::from_ref(&glob)),
            &c(&[exe("/opt/app/1.2/bin")])
        ));
        assert!(!covers(
            &c(&[exe("/opt/app/1.2/bin")]),
            &c(std::slice::from_ref(&glob))
        ));
        // Globs aren't compared with each other: only identical ones count.
        let wider = Condition::Exe(vec![PatternSource::Glob("/opt/**".to_owned())]);
        assert!(!covers(&c(&[wider]), &c(&[glob])));
        let net = |n: &str| Condition::Net(vec![Network::try_from(n.to_owned()).unwrap()]);
        assert!(covers(&c(&[net("10.0.0.0/8")]), &c(&[net("10.1.0.0/16")])));
        assert!(!covers(&c(&[net("10.1.0.0/16")]), &c(&[net("10.0.0.0/8")])));
        let ports = |r: Vec<(u16, u16)>| Condition::Port(r);
        assert!(covers(
            &c(&[ports(vec![(1, 1024)])]),
            &c(&[ports(vec![(80, 80), (443, 443)])])
        ));
        // No context means the host; `any` covers every context.
        let any = Condition::Context(ContextKind::Any);
        let container = Condition::Context(ContextKind::Container);
        assert!(covers(&c(std::slice::from_ref(&any)), &c(&[])));
        assert!(!covers(&c(&[]), &c(std::slice::from_ref(&container))));
        assert!(covers(&c(&[any]), &c(&[container])));
        // The empty rule matches everything on the host.
        assert!(covers(&c(&[]), &c(&[exe("/x")])));
        let home = Condition::Exe(vec![PatternSource::Glob("{home}/.local/bin/*".to_owned())]);
        let homed = Condition::Exe(vec![PatternSource::Exact(
            "{home}/.local/bin/tool".to_owned(),
        )]);
        assert!(covers(&c(std::slice::from_ref(&home)), &c(&[homed])));
        assert!(!covers(
            &c(&[home]),
            &c(&[exe("/home/ada/.local/bin/tool")])
        ));
    }

    #[test]
    fn what_the_node_knows_is_reported() {
        let old = "/home/ada/.local/share/claude/versions/2.0.31/claude";
        let new = "/home/ada/.local/share/claude/versions/2.0.40/claude";
        let facts = Facts {
            files: vec![new, "/home/ada/bin/tool"],
            writable: vec!["/home/ada/bin/tool"],
            hits: HashMap::from([(3, 9 * 86_400_000)]),
        };
        let mut expired = rule(4, Action::Allow, vec![host("x.org")]);
        expired.expiry = Expiry::At(1);
        let rules = [
            rule(1, Action::Allow, vec![exe(old)]),
            rule(2, Action::Allow, vec![exe("/home/ada/bin/tool")]),
            rule(3, Action::Deny, vec![host("y.org")]),
            expired,
        ];
        let linted: Vec<Linted<'_>> = rules
            .iter()
            .map(|r| Linted {
                rule: r,
                conditions: r.conditions.iter().collect(),
                effective: true,
                locked: false,
            })
            .collect();
        let found = lint(&linted, &facts, 10 * 86_400_000, 7);
        let kinds: Vec<(Kind, RuleId)> = found.iter().map(|f| (f.kind, f.rule)).collect();
        assert_eq!(
            kinds,
            vec![
                (Kind::NeverHit, 1),
                (Kind::MissingBinary, 1),
                (Kind::NeverHit, 2),
                (Kind::WritableBinary, 2),
                (Kind::Expired, 4),
            ]
        );
        assert_eq!(
            found.get(1).and_then(|f| f.suggestion.clone()),
            Some(PatternSource::Glob(
                "/home/ada/.local/share/claude/versions/*/claude".to_owned()
            ))
        );
    }
}
