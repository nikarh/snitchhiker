//! Turning what the daemon saw (connections no rule decided) into rules to review: one rule per program,
//! destination and port, with the program's path generalised so updates don't break it.

use std::collections::{BTreeMap, HashMap};

use snitchhiker_core::generalize;
use snitchhiker_core::pattern::PatternSource;
use snitchhiker_core::rule::Action;
use snitchhiker_core::spec::{Conditions, FolderSpec, RuleFile, RuleSpec};

use crate::store::Undecided;

/// The rules that would have decided `seen`, in a folder named `folder`. `home_of` gives a user's home directory.
pub fn suggest(
    seen: &[Undecided],
    folder: &str,
    home_of: impl Fn(u32) -> Option<String>,
) -> RuleFile {
    let mut homes: HashMap<u32, Option<String>> = HashMap::new();
    // (exe pattern, destination, port, protocol) -> how many connections; ordered for a stable file.
    let mut groups: BTreeMap<(String, String, bool, u16, u8), usize> = BTreeMap::new();
    for connection in seen {
        if connection.exe.is_empty() || connection.port == 0 {
            continue;
        }
        let home = homes
            .entry(connection.uid)
            .or_insert_with(|| home_of(connection.uid));
        let exe = match generalize::executable(&connection.exe, home.as_deref()) {
            PatternSource::Glob(glob) => format!("glob:{glob}"),
            PatternSource::Exact(exact) => exact,
            PatternSource::Regex(regex) => format!("re:{regex}"),
        };
        let (destination, is_host) = connection.host.clone().map_or_else(
            || (connection.address.to_string(), false),
            |host| (host, true),
        );
        *groups
            .entry((
                exe,
                destination,
                is_host,
                connection.port,
                connection.protocol,
            ))
            .or_default() += 1;
    }
    let rule = groups
        .into_iter()
        .map(|((exe, destination, is_host, port, protocol), count)| {
            let program = exe.rsplit('/').next().unwrap_or(&exe).to_owned();
            RuleSpec {
                name: format!("{program} to {destination}:{port}"),
                action: Action::Allow,
                tier: snitchhiker_core::rule::Tier::Normal,
                enabled: true,
                notes: format!("Learned from {count} connection(s)."),
                conditions: Conditions {
                    exe: vec![exe],
                    host: if is_host {
                        vec![destination.clone()]
                    } else {
                        vec![]
                    },
                    net: if is_host { vec![] } else { vec![destination] },
                    port: vec![port.to_string()],
                    protocol: vec![match protocol {
                        6 => "tcp".to_owned(),
                        17 => "udp".to_owned(),
                        other => other.to_string(),
                    }],
                    ..Conditions::default()
                },
            }
        })
        .collect();
    RuleFile {
        folder: Some(FolderSpec {
            name: folder.to_owned(),
            scope: Conditions::default(),
        }),
        rule,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(exe: &str, host: Option<&str>, address: &str, port: u16) -> Undecided {
        Undecided {
            exe: exe.to_owned(),
            host: host.map(str::to_owned),
            uid: 1000,
            protocol: 6,
            address: address.parse().unwrap(),
            port,
        }
    }

    #[test]
    fn one_rule_per_program_destination_and_port() {
        let file = suggest(
            &[
                seen(
                    "/home/ada/.local/share/claude/versions/2.0.31/claude",
                    Some("api.example.com"),
                    "198.51.100.7",
                    443,
                ),
                seen(
                    "/home/ada/.local/share/claude/versions/2.0.32/claude",
                    Some("api.example.com"),
                    "198.51.100.8",
                    443,
                ),
                seen("/usr/bin/curl", None, "203.0.113.9", 80),
                seen("", None, "203.0.113.9", 80),
            ],
            "Learned",
            |_| Some("/home/ada".to_owned()),
        );
        assert_eq!(file.rule.len(), 2);
        let claude = file
            .rule
            .iter()
            .find(|r| r.name.starts_with("claude"))
            .unwrap();
        assert_eq!(
            claude.conditions.exe,
            vec!["glob:{home}/.local/share/claude/versions/*/claude"]
        );
        assert_eq!(claude.conditions.host, vec!["api.example.com"]);
        assert_eq!(claude.notes, "Learned from 2 connection(s).");
        let curl = file
            .rule
            .iter()
            .find(|r| r.name.starts_with("curl"))
            .unwrap();
        assert_eq!(curl.conditions.net, vec!["203.0.113.9"]);
        // The suggestions are valid rules.
        for spec in &file.rule {
            spec.to_rule(1, None).unwrap();
        }
    }
}
