//! Turning what the daemon saw (connections no rule decided) into rules to review: one rule per program,
//! destination and port, where it came from, with the program's path generalised so updates don't break it. A
//! container's connections get rules for that container (its Compose service, else its name, else its image), a VM's
//! for that VM, a named namespace's for it: a rule learned from a container never applies to the host.

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
    // (where, exe pattern, destination, port, protocol) -> how many connections; ordered for a stable file.
    let mut groups: BTreeMap<(Where, String, String, bool, u16, u8), usize> = BTreeMap::new();
    for connection in seen {
        let place = Where::of(connection);
        // A program the node couldn't know: on the host no rule could name it; elsewhere (a VM's traffic, a rootless
        // container's first connection) the rule names the place alone.
        if connection.port == 0 || (connection.exe.is_empty() && place == Where::Host) {
            continue;
        }
        let home = homes
            .entry(connection.uid)
            .or_insert_with(|| home_of(connection.uid));
        let exe = match generalize::executable(&connection.exe, home.as_deref()) {
            _ if connection.exe.is_empty() => String::new(),
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
                place,
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
        .map(
            |((place, exe, destination, is_host, port, protocol), count)| {
                let program = match exe.rsplit('/').next() {
                    Some(name) if !name.is_empty() => name.to_owned(),
                    _ => "anything".to_owned(),
                };
                let mut conditions = Conditions {
                    exe: if exe.is_empty() { vec![] } else { vec![exe] },
                    host: if is_host {
                        vec![destination.clone()]
                    } else {
                        vec![]
                    },
                    net: if is_host {
                        vec![]
                    } else {
                        vec![destination.clone()]
                    },
                    port: vec![port.to_string()],
                    protocol: vec![match protocol {
                        6 => "tcp".to_owned(),
                        17 => "udp".to_owned(),
                        other => other.to_string(),
                    }],
                    ..Conditions::default()
                };
                let within = place.apply(&mut conditions);
                RuleSpec {
                    name: format!("{within}{program} to {destination}:{port}"),
                    action: Action::Allow,
                    tier: snitchhiker_core::rule::Tier::Normal,
                    enabled: true,
                    notes: format!("Learned from {count} connection(s)."),
                    conditions,
                }
            },
        )
        .collect();
    RuleFile {
        folder: Some(FolderSpec {
            name: folder.to_owned(),
            scope: Conditions::default(),
        }),
        rule,
    }
}

/// Where connections came from, as rules name it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Where {
    Host,
    /// A container named by `container.compose`, `.name` or `.image`: (which, value).
    Container(&'static str, String),
    /// A container nothing names (its identity couldn't be read): any container.
    AnyContainer,
    Vm(String),
    Netns(String),
    /// Another context with no name.
    Unnamed(u8),
}

impl Where {
    fn of(connection: &Undecided) -> Self {
        let identity = connection
            .container
            .as_deref()
            .map(snitchhiker_core::context::Container::from_key);
        match (connection.context, identity) {
            (0, _) => Self::Host,
            (1, Some(c)) => {
                if let Some(compose) = c.compose {
                    Self::Container("compose", compose)
                } else if !c.name.is_empty() {
                    Self::Container("name", c.name)
                } else if !c.image.is_empty() {
                    Self::Container("image", c.image)
                } else {
                    Self::AnyContainer
                }
            }
            (1, None) => Self::AnyContainer,
            (2, Some(c)) if !c.name.is_empty() => Self::Vm(c.name),
            (3, Some(c)) if c.runtime == "netns" && !c.name.is_empty() => Self::Netns(c.name),
            (other, _) => Self::Unnamed(other),
        }
    }

    /// Limits `conditions` to this place; the prefix of the rule's name.
    fn apply(&self, conditions: &mut Conditions) -> String {
        use snitchhiker_core::rule::ContextKind;
        match self {
            Self::Host => String::new(),
            Self::Container(which, value) => {
                let field = match *which {
                    "compose" => &mut conditions.container.compose,
                    "name" => &mut conditions.container.name,
                    _ => &mut conditions.container.image,
                };
                *field = vec![value.clone()];
                format!("in {value}: ")
            }
            Self::AnyContainer => {
                conditions.context = Some(ContextKind::Container);
                "in a container: ".to_owned()
            }
            Self::Vm(name) => {
                conditions.vm.name = vec![name.clone()];
                format!("in {name}: ")
            }
            Self::Netns(name) => {
                conditions.netns = vec![name.clone()];
                format!("in {name}: ")
            }
            Self::Unnamed(code) => {
                conditions.context = Some(match code {
                    2 => ContextKind::Vm,
                    3 => ContextKind::Netns,
                    _ => ContextKind::Container,
                });
                "elsewhere: ".to_owned()
            }
        }
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
            context: 0,
            container: None,
        }
    }

    #[test]
    fn containers_vms_and_namespaces_get_rules_of_their_own() {
        let mut web = seen(
            "/usr/local/bin/node",
            Some("api.example.com"),
            "198.51.100.7",
            443,
        );
        web.context = 1;
        web.container = Some("docker\tabc\tshop-web-1\tnode:22\tshop/web\t".to_owned());
        let mut vm = seen("", Some("deb.debian.org"), "198.51.100.8", 80);
        vm.context = 2;
        vm.exe = String::new();
        vm.container = Some("qemu\tuuid\tbuilder\t\t\t".to_owned());
        let mut ns = seen("/usr/bin/curl", None, "203.0.113.9", 443);
        ns.context = 3;
        ns.container = Some("netns\t\tvpn\t\t\t".to_owned());
        let host = seen(
            "/usr/local/bin/node",
            Some("api.example.com"),
            "198.51.100.7",
            443,
        );
        let file = suggest(&[web, vm, ns, host], "Learned", |_| None);
        let names: Vec<&str> = file.rule.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names.len(), 4, "{names:?}");
        let by_name = |prefix: &str| {
            file.rule
                .iter()
                .find(|r| r.name.starts_with(prefix))
                .unwrap()
        };
        assert_eq!(
            by_name("in shop/web").conditions.container.compose,
            vec!["shop/web"]
        );
        assert_eq!(by_name("in builder").conditions.vm.name, vec!["builder"]);
        assert_eq!(by_name("in builder").conditions.exe, Vec::<String>::new());
        assert_eq!(by_name("in vpn").conditions.netns, vec!["vpn"]);
        let on_host = by_name("node to");
        assert!(
            on_host.conditions.container.compose.is_empty() && on_host.conditions.context.is_none()
        );
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
