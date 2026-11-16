//! Property tests: random rules and connections against simple, independent statements of what must hold.

#![expect(
    clippy::expect_used,
    reason = "the strategies build values known to be valid"
)]

use std::net::IpAddr;
use std::sync::Arc;

use proptest::prelude::*;
use snitchhiker_core::blocklist::Blocklist;
use snitchhiker_core::destination::{HostPattern, Network};
use snitchhiker_core::engine::{Facts, Match, RuleSet};
use snitchhiker_core::pattern::PatternSource;
use snitchhiker_core::rule::{Action, Condition, ContextKind, Expiry, Rule, Tier};

const LABELS: &[&str] = &[
    "a", "api", "s1", "s2", "cdn", "example", "test", "com", "org",
];
const EXES: &[&str] = &["/usr/bin/curl", "/usr/bin/git", "/opt/app/bin/app"];
const PORTS: &[u16] = &[22, 80, 443, 8080];

fn name() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(LABELS), 1..4).prop_map(|labels| labels.join("."))
}

fn host_pattern() -> impl Strategy<Value = HostPattern> {
    (name(), any::<bool>()).prop_map(|(name, wildcard)| {
        let text = if wildcard { format!("*.{name}") } else { name };
        HostPattern::try_from(text).expect("a valid pattern")
    })
}

fn condition() -> impl Strategy<Value = Condition> {
    prop_oneof![
        prop::collection::vec(host_pattern(), 1..3).prop_map(Condition::Host),
        prop::sample::select(EXES)
            .prop_map(|e| Condition::Exe(vec![PatternSource::Exact(e.to_owned())])),
        Just(Condition::Exe(vec![PatternSource::Glob(
            "/usr/bin/*".to_owned()
        )])),
        prop::sample::select(PORTS).prop_map(|p| Condition::Port(vec![(p, p)])),
        Just(Condition::Port(vec![(1, 1024)])),
        Just(Condition::Net(vec![
            Network::try_from("lan".to_owned()).expect("an alias")
        ])),
        Just(Condition::Net(vec![
            Network::try_from("192.0.2.0/24".to_owned()).expect("a network")
        ])),
        host_pattern().prop_map(|h| Condition::Not(Box::new(Condition::Host(vec![h])))),
    ]
}

fn rules() -> impl Strategy<Value = Vec<Rule>> {
    prop::collection::vec(
        (
            prop::collection::vec(condition(), 1..4),
            prop::sample::select(&[Action::Allow, Action::Deny, Action::Reject][..]),
            prop::sample::select(&[Tier::Fallback, Tier::Normal, Tier::Override][..]),
        ),
        0..40,
    )
    .prop_map(|specs| {
        specs
            .into_iter()
            .zip(1..)
            .map(|((conditions, action, tier), id)| Rule {
                id,
                folder: None,
                name: format!("rule {id}"),
                enabled: true,
                action,
                tier,
                expiry: Expiry::Never,
                log: true,
                notes: String::new(),
                conditions,
            })
            .collect()
    })
}

/// A connection: its program, the names known for its address (some with capitals), port and address.
fn connection() -> impl Strategy<Value = (&'static str, Vec<String>, u16, IpAddr)> {
    (
        prop::sample::select(EXES),
        prop::collection::vec((name(), any::<bool>()), 0..3),
        prop::sample::select(PORTS),
        prop::sample::select(&["192.0.2.7", "192.168.1.5", "198.51.100.1"][..]),
    )
        .prop_map(|(exe, names, port, address)| {
            let names = names
                .into_iter()
                .map(|(n, upper)| if upper { n.to_uppercase() } else { n })
                .collect();
            (exe, names, port, address.parse().expect("an address"))
        })
}

/// Precedence, stated on its own: the highest tier, then blocking over allowing, then the most specific, then the
/// lowest id.
fn best(matches: &[Match]) -> Option<(u64, Action)> {
    matches
        .iter()
        .max_by(|a, b| {
            let blocks = |m: &Match| m.action != Action::Allow;
            (a.tier, blocks(a), a.specificity, std::cmp::Reverse(a.rule)).cmp(&(
                b.tier,
                blocks(b),
                b.specificity,
                std::cmp::Reverse(b.rule),
            ))
        })
        .map(|m| (m.rule, m.action))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// The indexed set decides as evaluating each rule alone and applying precedence does.
    #[test]
    fn deciding_agrees_with_each_rule_alone(rules in rules(), (exe, names, port, address) in connection()) {
        let hosts: Vec<Arc<str>> = names.iter().map(|n| Arc::from(n.as_str())).collect();
        let facts = Facts {
            exe,
            apps: &[],
            cmdline: "",
            ancestors: &[],
            lineage: &[],
            uid: 1000,
            home: Some("/home/ada"),
            hosts: &hosts,
            address,
            port,
            protocol: 6,
            context: ContextKind::Host,
            container: None,
            vm: None,
            netns: None,
            now_ms: 0,
        };
        let set = RuleSet::compile(&[], &rules).expect("rules compile");
        let alone: Vec<Match> = rules
            .iter()
            .filter_map(|rule| {
                RuleSet::compile(&[], std::slice::from_ref(rule))
                    .expect("a rule compiles")
                    .explain(&facts)
                    .first()
                    .copied()
            })
            .collect();
        prop_assert_eq!(set.decide(&facts).map(|d| (d.rule, d.action)), best(&alone));
    }

    /// A pattern of a name matches the name in any case and with a trailing dot; `*.` matches only names under it.
    #[test]
    fn host_patterns_match_as_written(name in name(), sub in name()) {
        let exact = HostPattern::try_from(name.clone()).expect("a pattern");
        prop_assert!(exact.matches(&name));
        let upper = format!("{}.", name.to_uppercase());
        prop_assert!(exact.matches(&upper));
        let wildcard = HostPattern::try_from(format!("*.{name}")).expect("a pattern");
        prop_assert!(!wildcard.matches(&name));
        let under = format!("{sub}.{name}");
        prop_assert!(wildcard.matches(&under));
    }

    /// A blocklist has every name it lists and every name under them, and the networks it lists.
    #[test]
    fn blocklists_have_what_they_list(names in prop::collection::vec(name(), 1..20), sub in name(), last in 0..=255_u8) {
        let mut text: String = names.iter().flat_map(|n| ["0.0.0.0 ", n.as_str(), "\n"]).collect();
        text.push_str("198.51.100.0/24\n");
        let list = Blocklist::parse(&text).list;
        for n in &names {
            prop_assert!(list.has_host(n));
            let under = format!("{sub}.{n}");
            prop_assert!(list.has_host(&under));
        }
        prop_assert!(list.has_address(IpAddr::from([198, 51, 100, last])));
        prop_assert!(!list.has_address(IpAddr::from([198, 51, 101, last])));
    }

    /// The query language never panics, whatever it is given.
    #[test]
    fn queries_never_panic(text in ".{0,80}") {
        let _ = snitchhiker_core::query::parse(&text);
    }

    /// Rule files' conditions read back as they were written.
    #[test]
    fn conditions_round_trip(conditions in prop::collection::vec(condition(), 1..4)) {
        let spec = snitchhiker_core::spec::Conditions::from_conditions(&conditions);
        let back = spec.to_conditions().expect("written conditions read back");
        let again = snitchhiker_core::spec::Conditions::from_conditions(&back);
        prop_assert_eq!(spec, again);
    }
}
