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
                "claude → anywhere",
                "any program → api.eu.example.co.uk:443",
            ]
        );
        assert_eq!(
            all[0].conditions.exe,
            vec!["glob:{home}/.local/share/claude/versions/*/claude"]
        );
        assert!(!all[0].broad && all[2].broad && all[3].broad && all[4].broad);
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
    }
}
