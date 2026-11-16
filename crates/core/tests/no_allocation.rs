//! Deciding a connection allocates nothing: it runs for every new connection, on the packet path.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use snitchhiker_core::destination::{HostPattern, Network};
    use snitchhiker_core::engine::{Facts, RuleSet};
    use snitchhiker_core::pattern::PatternSource;
    use snitchhiker_core::rule::{Action, Condition, ContextKind, Expiry, Rule, Tier};

    /// Ten thousand rules of the shapes prompts create: an app, a host, a port.
    fn rules() -> Vec<Rule> {
        (0..10_000_u64)
            .map(|i| Rule {
                id: i + 1,
                folder: None,
                name: format!("rule {i}"),
                enabled: true,
                action: if i % 7 == 0 {
                    Action::Deny
                } else {
                    Action::Allow
                },
                tier: Tier::Normal,
                expiry: Expiry::Never,
                log: true,
                notes: String::new(),
                conditions: vec![
                    Condition::Exe(vec![if i % 3 == 0 {
                        PatternSource::Glob(format!(
                            "{{home}}/.local/share/app{}/versions/*/app",
                            i % 50
                        ))
                    } else {
                        PatternSource::Exact(format!("/usr/bin/app{}", i % 200))
                    }]),
                    Condition::Host(vec![
                        HostPattern::try_from(format!("*.service{}.example.com", i % 500)).unwrap(),
                    ]),
                    Condition::Net(vec![Network::try_from("lan".to_owned()).unwrap()]),
                    Condition::Port(vec![
                        (443, 443),
                        (
                            80 + u16::try_from(i % 20).unwrap(),
                            80 + u16::try_from(i % 20).unwrap(),
                        ),
                    ]),
                ],
            })
            .collect()
    }

    #[test]
    fn deciding_allocates_nothing() {
        let set = RuleSet::compile(&[], &rules()).unwrap();
        let hosts: Vec<Arc<str>> = vec![Arc::from("api.service42.example.com")];
        let ancestors = vec!["/usr/lib/systemd/systemd".to_owned()];
        let apps: Vec<String> = Vec::new();
        let facts = [
            ("/usr/bin/app42", 443, "192.168.1.10"),
            (
                "/home/ada/.local/share/app3/versions/2.0.1/app",
                85,
                "192.168.1.10",
            ),
            ("/usr/bin/unknown", 443, "198.51.100.7"),
        ]
        .map(|(exe, port, address)| Facts {
            exe,
            apps: &apps,
            sha256: None,
            writable: false,
            cmdline: "",
            ancestors: &ancestors,
            lineage: &[],
            uid: 1000,
            home: Some("/home/ada"),
            hosts: &hosts,
            address: address.parse().unwrap(),
            port,
            protocol: 6,
            context: ContextKind::Host,
            now_ms: 0,
            container: None,
            vm: None,
            netns: None,
        });
        // Warm up anything lazily initialised (the regex engines' caches).
        for f in &facts {
            let _ = set.decide(f);
        }
        let info = allocation_counter::measure(|| {
            for _ in 0..100 {
                for f in &facts {
                    std::hint::black_box(set.decide(std::hint::black_box(f)));
                }
            }
        });
        assert_eq!(info.count_total, 0, "deciding allocated: {info:?}");
    }
}
