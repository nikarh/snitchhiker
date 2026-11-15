//! The rules a prompt offers, narrowest first: the first is what a quick answer creates.
//!
//! "This program" is the program's path generalised (so the rule survives updates); "this host" is the name the
//! process resolved, or the address when there is none. Wider choices are marked broad.

use std::net::IpAddr;
use std::sync::Arc;

use crate::generalize;
use crate::pattern::PatternSource;
use crate::spec::Conditions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub label: String,
    pub conditions: Conditions,
    /// It allows more than this destination for this program.
    pub broad: bool,
}

fn protocol_name(protocol: u8) -> String {
    match protocol {
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        1 => "icmp".to_owned(),
        58 => "icmpv6".to_owned(),
        n => n.to_string(),
    }
}

/// The destination as shown, and as conditions: the resolved name, or the address when there is none.
fn destination(hosts: &[Arc<str>], address: IpAddr) -> (String, Conditions) {
    match hosts.first() {
        Some(host) => (
            host.to_string(),
            Conditions {
                host: vec![host.to_string()],
                ..Conditions::default()
            },
        ),
        None => (
            address.to_string(),
            Conditions {
                net: vec![address.to_string()],
                ..Conditions::default()
            },
        ),
    }
}

/// What every suggestion for one connection shares.
struct Ask<'a> {
    name: &'a str,
    exes: &'a [String],
    ports: &'a [String],
    protocol: &'a [String],
    port: u16,
}

impl Ask<'_> {
    fn at_port(&self, what: &str) -> String {
        if self.port == 0 {
            what.to_owned()
        } else {
            format!("{what}:{}", self.port)
        }
    }

    fn to(&self, net: String, broad: bool) -> Suggestion {
        Suggestion {
            label: format!("{} → {}", self.name, self.at_port(&net)),
            conditions: Conditions {
                exe: self.exes.to_vec(),
                net: vec![net],
                port: self.ports.to_vec(),
                protocol: self.protocol.to_vec(),
                ..Conditions::default()
            },
            broad,
        }
    }
}

/// The address itself, when the narrower rules named the host, and its network (a /24, or a /64 for IPv6): for
/// services that move between addresses of one range, or are reached by address.
fn address_rules(out: &mut Vec<Suggestion>, ask: &Ask<'_>, named: bool, address: IpAddr) {
    if named {
        out.push(ask.to(address.to_string(), false));
    }
    let network = match address {
        IpAddr::V4(v4) => ipnet::Ipv4Net::new(v4, 24).map(|n| ipnet::IpNet::V4(n.trunc())),
        IpAddr::V6(v6) => ipnet::Ipv6Net::new(v6, 64).map(|n| ipnet::IpNet::V6(n.trunc())),
    };
    if let Ok(network) = network {
        out.push(ask.to(network.to_string(), true));
    }
}

/// The suggestions for a connection of `exe` (run by a user whose home is `home`) to `address`:`port`.
#[must_use]
pub fn suggestions(
    exe: &str,
    home: Option<&str>,
    hosts: &[Arc<str>],
    address: IpAddr,
    port: u16,
    protocol: u8,
) -> Vec<Suggestion> {
    let program = match generalize::executable(exe, home) {
        PatternSource::Glob(glob) => format!("glob:{glob}"),
        PatternSource::Exact(exact) => exact,
        PatternSource::Regex(regex) => format!("re:{regex}"),
    };
    let name = exe.rsplit('/').next().unwrap_or(exe).to_owned();
    let name = if name.is_empty() {
        "this program".to_owned()
    } else {
        name
    };
    let protocol = vec![protocol_name(protocol)];
    let ports = if port == 0 {
        vec![]
    } else {
        vec![port.to_string()]
    };
    let at_port = |what: &str| {
        if port == 0 {
            what.to_owned()
        } else {
            format!("{what}:{port}")
        }
    };
    let exes = if exe.is_empty() {
        vec![]
    } else {
        vec![program]
    };

    let mut out = Vec::new();
    let (destination, host_conditions) = destination(hosts, address);
    out.push(Suggestion {
        label: format!("{name} → {}", at_port(&destination)),
        conditions: Conditions {
            exe: exes.clone(),
            port: ports.clone(),
            protocol: protocol.clone(),
            ..host_conditions.clone()
        },
        broad: false,
    });
    if port != 0 {
        out.push(Suggestion {
            label: format!("{name} → {destination}, any port"),
            conditions: Conditions {
                exe: exes.clone(),
                protocol: protocol.clone(),
                ..host_conditions.clone()
            },
            broad: false,
        });
    }
    if let Some(host) = hosts.first()
        && let Some(domain) = psl::domain_str(host)
        && domain != &**host
    {
        out.push(Suggestion {
            label: format!("{name} → {}", at_port(&format!("*.{domain}"))),
            conditions: Conditions {
                exe: exes.clone(),
                host: vec![format!("*.{domain}")],
                port: ports.clone(),
                protocol: protocol.clone(),
                ..Conditions::default()
            },
            broad: true,
        });
    }
    address_rules(
        &mut out,
        &Ask {
            name: &name,
            exes: &exes,
            ports: &ports,
            protocol: &protocol,
            port,
        },
        !hosts.is_empty(),
        address,
    );
    if !exes.is_empty() {
        out.push(Suggestion {
            label: format!("{name} → anywhere"),
            conditions: Conditions {
                exe: exes,
                ..Conditions::default()
            },
            broad: true,
        });
    }
    out.push(Suggestion {
        label: format!("any program → {}", at_port(&destination)),
        conditions: Conditions {
            port: ports,
            protocol,
            ..host_conditions
        },
        broad: true,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowest_first_with_the_domain_and_broad_choices_marked() {
        let hosts = [Arc::from("api.eu.example.co.uk")];
        let all = suggestions(
            "/home/ada/.local/share/claude/versions/2.0.31/claude",
            Some("/home/ada"),
            &hosts,
            "198.51.100.7".parse().unwrap(),
            443,
            6,
        );
        let labels: Vec<_> = all.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "claude → api.eu.example.co.uk:443",
                "claude → api.eu.example.co.uk, any port",
                "claude → *.example.co.uk:443",
                "claude → 198.51.100.7:443",
                "claude → 198.51.100.0/24:443",
                "claude → anywhere",
                "any program → api.eu.example.co.uk:443",
            ]
        );
        assert_eq!(
            all[0].conditions.exe,
            vec!["glob:{home}/.local/share/claude/versions/*/claude"]
        );
        assert!(!all[0].broad && all[2].broad && !all[3].broad && all[4].broad && all[5].broad);
        // Every suggestion is a valid rule.
        for suggestion in &all {
            assert!(
                suggestion
                    .conditions
                    .to_conditions()
                    .is_ok_and(|c| !c.is_empty())
            );
        }
    }

    #[test]
    fn the_address_stands_in_for_a_missing_name() {
        let all = suggestions(
            "/usr/bin/curl",
            None,
            &[],
            "203.0.113.9".parse().unwrap(),
            80,
            6,
        );
        assert_eq!(all[0].label, "curl → 203.0.113.9:80");
        assert_eq!(all[0].conditions.net, vec!["203.0.113.9"]);
        assert!(all.iter().all(|s| !s.label.contains("*.")));
        // The address is the destination already: only its network is added.
        assert_eq!(all[2].label, "curl → 203.0.113.0/24:80");
        let v6 = suggestions(
            "/usr/bin/curl",
            None,
            &[],
            "2001:db8::7".parse().unwrap(),
            443,
            6,
        );
        assert!(v6.iter().any(|s| s.conditions.net == vec!["2001:db8::/64"]));
    }
}

/// The suggestions for a connection from a container, a VM or another network namespace: the same rules, made to hold
/// in that context only (a rule made from a container's prompt never applies to the host), and for a container, its
/// own ladder after the first (plan §5.10): any program in it, any container from its image, this exact container.
///
/// A container is named by its most stable identity: its Compose service, else its name, else its image.
#[must_use]
pub fn in_context(
    base: Vec<Suggestion>,
    context: crate::rule::ContextKind,
    container: Option<&crate::context::Container>,
) -> Vec<Suggestion> {
    use crate::rule::ContextKind;
    let within = |suggestion: &Suggestion, who: &str, apply: &dyn Fn(&mut Conditions)| {
        let mut conditions = suggestion.conditions.clone();
        apply(&mut conditions);
        Suggestion {
            label: format!("in {who}: {}", suggestion.label),
            conditions,
            broad: suggestion.broad,
        }
    };
    match (context, container) {
        (ContextKind::Host | ContextKind::Any, _) => base,
        (ContextKind::Container, Some(c)) => container_suggestions(&base, c)
            .unwrap_or_else(|| in_context(base, ContextKind::Container, None)),
        (kind, _) => {
            let name = match kind {
                ContextKind::Vm => "a VM",
                ContextKind::Netns => "another network namespace",
                _ => "a container",
            };
            base.iter()
                .map(|s| within(s, name, &|conditions| conditions.context = Some(kind)))
                .collect()
        }
    }
}

/// A container's suggestions (see [`in_context`]); `None` when it has nothing stable to be named by.
fn container_suggestions(
    base: &[Suggestion],
    c: &crate::context::Container,
) -> Option<Vec<Suggestion>> {
    use crate::spec::ContainerSpec;
    let within = |suggestion: &Suggestion, who: &str, scope: &ContainerSpec| Suggestion {
        label: format!("in {who}: {}", suggestion.label),
        conditions: Conditions {
            container: scope.clone(),
            ..suggestion.conditions.clone()
        },
        broad: suggestion.broad,
    };
    let (who, scope) = if let Some(compose) = &c.compose {
        (
            compose.clone(),
            ContainerSpec {
                compose: vec![compose.clone()],
                ..ContainerSpec::default()
            },
        )
    } else if !c.name.is_empty() {
        (
            c.name.clone(),
            ContainerSpec {
                name: vec![c.name.clone()],
                ..ContainerSpec::default()
            },
        )
    } else if !c.image.is_empty() {
        (
            c.image.clone(),
            ContainerSpec {
                image: vec![c.image.clone()],
                ..ContainerSpec::default()
            },
        )
    } else {
        return None;
    };
    let mut out: Vec<Suggestion> = base.iter().map(|s| within(s, &who, &scope)).collect();
    let Some(first) = base.first() else {
        return Some(out);
    };
    let destination = first
        .label
        .split_once(" → ")
        .map_or("", |(_, d)| d)
        .to_owned();
    let without_program = |conditions: &Conditions| Conditions {
        exe: Vec::new(),
        ..conditions.clone()
    };
    let mut ladder = vec![Suggestion {
        label: format!("any program in {who} → {destination}"),
        conditions: Conditions {
            container: scope.clone(),
            ..without_program(&first.conditions)
        },
        broad: false,
    }];
    if !c.image.is_empty() && scope.image.is_empty() {
        ladder.push(Suggestion {
            label: format!("any container from {} → {destination}", c.image),
            conditions: Conditions {
                container: ContainerSpec {
                    image: vec![c.image.clone()],
                    ..ContainerSpec::default()
                },
                ..without_program(&first.conditions)
            },
            broad: true,
        });
    }
    if !c.id.is_empty() {
        ladder.push(Suggestion {
            label: format!(
                "this container ({}) → {destination}",
                c.id.get(..12).unwrap_or(&c.id)
            ),
            conditions: Conditions {
                container: ContainerSpec {
                    id: vec![c.id.clone()],
                    ..ContainerSpec::default()
                },
                ..without_program(&first.conditions)
            },
            broad: false,
        });
    }
    out.splice(1..1, ladder);
    Some(out)
}

#[cfg(test)]
mod context_tests {
    use super::*;
    use crate::rule::ContextKind;

    #[test]
    fn a_containers_suggestions_hold_in_it_only() {
        let base = suggestions(
            "/usr/local/bin/node",
            None,
            &[Arc::from("api.example.com")],
            "198.51.100.7".parse().unwrap(),
            443,
            6,
        );
        let web = crate::context::Container {
            runtime: "docker".to_owned(),
            id: "0133794d05ab40d47d94868c4fb19a4d610f6c97e3ee0c5ee5fcf8aa21c03ea9".to_owned(),
            name: "shop-web-1".to_owned(),
            image: "node:22".to_owned(),
            compose: Some("shop/web".to_owned()),
            ..crate::context::Container::default()
        };
        let all = in_context(base.clone(), ContextKind::Container, Some(&web));
        assert_eq!(all[0].label, "in shop/web: node → api.example.com:443");
        assert_eq!(
            all[0].conditions.container.compose,
            vec!["shop/web".to_owned()]
        );
        assert_eq!(all[0].conditions.exe, base[0].conditions.exe);
        assert_eq!(
            all[1].label,
            "any program in shop/web → api.example.com:443"
        );
        assert_eq!(all[1].conditions.exe, Vec::<String>::new());
        assert_eq!(
            all[2].conditions.container.image,
            vec!["node:22".to_owned()]
        );
        assert!(all[3].label.starts_with("this container (0133794d05ab)"));
        // Every one is limited to containers.
        assert!(all.iter().all(|s| !s.conditions.container.is_empty()));
        // The host keeps its own.
        assert_eq!(in_context(base.clone(), ContextKind::Host, None), base);
        let netns = in_context(base, ContextKind::Netns, None);
        assert!(
            netns
                .iter()
                .all(|s| s.conditions.context == Some(ContextKind::Netns))
        );
    }
}
