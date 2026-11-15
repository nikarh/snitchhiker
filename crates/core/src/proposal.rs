//! Shaping agents' proposals (plan §5.11). An agent only suggests: what reaches a person is a rule made from what the
//! kernel saw where it can be (the program of the blocked connections, not the one the agent typed), refused when it
//! would allow every program everywhere, and marked wherever it is broad, so that approving it needs a second look
//! (and step-up).

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::destination::ALIASES;
use crate::rule::ContextKind;
use crate::spec::Conditions;

/// A rule as an agent proposed it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposed {
    /// The program's path; empty for any.
    #[serde(default)]
    pub exe: String,
    /// Host names (`*.` for subdomains), addresses or networks; empty for any.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Ports or ranges; empty for any.
    #[serde(default)]
    pub ports: Vec<String>,
    /// tcp, udp; empty for any.
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub context: Option<ContextKind>,
}

/// A connection the node blocked or asked about, from the proposing agent's own processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub exe: String,
    pub host: Option<String>,
    pub address: IpAddr,
    pub port: u16,
}

/// Why a shaped rule is broad: approving it takes step-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "risk", content = "detail", rename_all = "snake_case")]
pub enum Risk {
    /// Any destination.
    AnyHost,
    /// A wildcard on a public suffix (`*.com`, `*.co.uk`): every site under it.
    PublicSuffix(String),
    /// Any program.
    AnyProgram,
    /// Any port, with a broad destination.
    AnyPort,
    /// A network wider than a /24 (a /48 for IPv6).
    WideNetwork(String),
    /// The LAN, the cloud metadata service and the like.
    SensitiveAlias(String),
    /// A binary any user can replace, with a broad destination.
    WritableBinary(String),
    /// No blocked connection of the agent's matches it: the agent guessed.
    Speculative,
}

impl Risk {
    /// For people.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::AnyHost => "any destination".to_owned(),
            Self::PublicSuffix(suffix) => format!("every site under the public suffix {suffix}"),
            Self::AnyProgram => "any program".to_owned(),
            Self::AnyPort => "any port".to_owned(),
            Self::WideNetwork(net) => format!("the wide network {net}"),
            Self::SensitiveAlias(alias) => format!("the sensitive network `{alias}`"),
            Self::WritableBinary(exe) => format!("{exe}, which a user other than root can replace"),
            Self::Speculative => "nothing the agent tried matches it".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("a rule for any program to any destination")]
    Everything,
    #[error("{0}")]
    Invalid(String),
    #[error("too long: {0}")]
    TooLong(&'static str),
}

/// A proposed rule, shaped: its conditions, the program it was grounded in (when observations named one), and its
/// risks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shaped {
    pub conditions: Conditions,
    pub risks: Vec<Risk>,
}

/// Limits on what an agent sends.
const MAX_HOSTS: usize = 32;
const MAX_PORTS: usize = 16;
const MAX_TEXT: usize = 253;

/// Whether `suffix` (`com`, `co.uk`) is a public suffix: anything under it is someone else's.
fn public_suffix(suffix: &str) -> bool {
    psl::suffix_str(suffix).is_some_and(|s| s.eq_ignore_ascii_case(suffix))
}

fn check_limits(proposed: &Proposed) -> Result<(), Refusal> {
    if proposed.hosts.len() > MAX_HOSTS {
        return Err(Refusal::TooLong("hosts"));
    }
    if proposed.ports.len() > MAX_PORTS {
        return Err(Refusal::TooLong("ports"));
    }
    if proposed.exe.len() > 4096
        || proposed
            .hosts
            .iter()
            .chain(&proposed.ports)
            .any(|t| t.len() > MAX_TEXT)
    {
        return Err(Refusal::TooLong("a value"));
    }
    Ok(())
}

/// The destinations into `conditions`; whether any is broad.
fn destinations(
    hosts: &[String],
    conditions: &mut Conditions,
    risks: &mut Vec<Risk>,
) -> Result<bool, Refusal> {
    let mut broad = false;
    for host in hosts.iter().map(|h| h.trim()) {
        if host.starts_with("re:") || host.contains(['/', ' ']) && host.parse::<IpNet>().is_err() {
            return Err(Refusal::Invalid(format!(
                "`{host}`: a host name, `*.` and a name, an address or a network"
            )));
        }
        if host.is_empty() || host == "*" {
            broad = true;
            risks.push(Risk::AnyHost);
            continue;
        }
        if let Some((_, nets)) = ALIASES.iter().find(|(alias, _)| *alias == host) {
            let _ = nets;
            broad = true;
            risks.push(Risk::SensitiveAlias(host.to_owned()));
            conditions.net.push(host.to_owned());
            continue;
        }
        if let Ok(net) = host
            .parse::<IpNet>()
            .or_else(|_| host.parse::<IpAddr>().map(IpNet::from))
        {
            let wide = match net {
                IpNet::V4(n) => n.prefix_len() < 24,
                IpNet::V6(n) => n.prefix_len() < 48,
            };
            if wide {
                broad = true;
                risks.push(Risk::WideNetwork(net.to_string()));
            }
            if ALIASES
                .iter()
                .filter(|(alias, _)| matches!(*alias, "lan" | "imds" | "loopback"))
                .flat_map(|(alias, nets)| nets.iter().map(move |n| (*alias, *n)))
                .any(|(_, n)| {
                    n.parse::<IpNet>()
                        .is_ok_and(|n| n.contains(&net.addr()) || net.contains(&n.addr()))
                })
            {
                broad = true;
                risks.push(Risk::SensitiveAlias(net.to_string()));
            }
            conditions.net.push(net.to_string());
            continue;
        }
        if let Some(suffix) = host.strip_prefix("*.") {
            if public_suffix(suffix) {
                broad = true;
                risks.push(Risk::PublicSuffix(suffix.to_owned()));
            }
        } else if host.contains('*') {
            return Err(Refusal::Invalid(format!(
                "`{host}`: a wildcard only as `*.` and a name"
            )));
        }
        conditions.host.push(host.to_ascii_lowercase());
    }
    Ok(broad)
}

/// Whether the observed connection `o` is one the shaped rule (`conditions`, and the program the agent named, if
/// any) would have let through.
fn grounds(o: &Observation, conditions: &Conditions, exe: &str) -> bool {
    let host_ok = conditions.host.is_empty() && conditions.net.is_empty()
        || o.host.as_deref().is_some_and(|h| {
            conditions.host.iter().any(|p| {
                p.strip_prefix("*.").map_or_else(
                    || h.eq_ignore_ascii_case(p),
                    |suffix| {
                        h.len() > suffix.len()
                            && h.to_ascii_lowercase().ends_with(&format!(".{suffix}"))
                    },
                )
            })
        })
        || conditions
            .net
            .iter()
            .any(|n| n.parse::<IpNet>().is_ok_and(|n| n.contains(&o.address)));
    let port_ok = conditions.port.is_empty() || conditions.port.iter().any(|p| {
        let (a, b) = p.split_once('-').unwrap_or((p, p));
        matches!((a.parse::<u16>(), b.parse::<u16>()), (Ok(a), Ok(b)) if (a..=b).contains(&o.port))
    });
    let exe_ok = exe.is_empty() || o.exe == exe;
    host_ok && port_ok && exe_ok
}

/// Shapes `proposed`, from the agent's `observed` connections; `writable` says whether a user other than root can
/// replace a binary.
pub fn shape(
    proposed: &Proposed,
    observed: &[Observation],
    writable: &dyn Fn(&str) -> bool,
) -> Result<Shaped, Refusal> {
    check_limits(proposed)?;
    let mut risks = Vec::new();
    let mut conditions = Conditions {
        context: proposed.context,
        ..Conditions::default()
    };
    let mut broad = destinations(&proposed.hosts, &mut conditions, &mut risks)?;
    if proposed.hosts.is_empty() {
        broad = true;
        risks.push(Risk::AnyHost);
    }
    // Ports and protocol.
    for port in proposed.ports.iter().map(|p| p.trim()) {
        let valid = port.split_once('-').map_or_else(
            || port.parse::<u16>().is_ok(),
            |(a, b)| a.parse::<u16>().is_ok() && b.parse::<u16>().is_ok(),
        );
        if !valid {
            return Err(Refusal::Invalid(format!("`{port}`: a port or a range")));
        }
        conditions.port.push(port.to_owned());
    }
    if proposed.ports.is_empty() && broad {
        risks.push(Risk::AnyPort);
    }
    match proposed.protocol.trim().to_ascii_lowercase().as_str() {
        "" => {}
        p @ ("tcp" | "udp") => conditions.protocol.push(p.to_owned()),
        other => return Err(Refusal::Invalid(format!("`{other}`: tcp or udp"))),
    }
    // The program: what the kernel saw for these destinations, before what the agent says.
    let grounded: Vec<&Observation> = observed
        .iter()
        .filter(|o| grounds(o, &conditions, &proposed.exe))
        .collect();
    let exe = grounded
        .first()
        .map_or_else(|| proposed.exe.trim().to_owned(), |o| o.exe.clone());
    if grounded.is_empty() {
        risks.push(Risk::Speculative);
    }
    if exe.is_empty() {
        if broad {
            return Err(Refusal::Everything);
        }
        risks.push(Risk::AnyProgram);
    } else {
        if !exe.starts_with('/') {
            return Err(Refusal::Invalid(format!(
                "`{exe}`: a program's path from the root"
            )));
        }
        if broad && writable(&exe) {
            risks.push(Risk::WritableBinary(exe.clone()));
        }
        conditions.exe.push(exe);
    }
    Ok(Shaped { conditions, risks })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(exe: &str, host: &str, port: u16) -> Observation {
        Observation {
            exe: exe.to_owned(),
            host: Some(host.to_owned()),
            address: "203.0.113.5".parse().unwrap(),
            port,
        }
    }

    fn proposed(exe: &str, hosts: &[&str], ports: &[&str]) -> Proposed {
        Proposed {
            exe: exe.to_owned(),
            hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
            ports: ports.iter().map(|p| (*p).to_owned()).collect(),
            ..Proposed::default()
        }
    }

    const NEVER: &dyn Fn(&str) -> bool = &|_| false;

    #[test]
    fn a_narrow_proposal_is_grounded_in_what_was_blocked() {
        let observed = [seen("/home/ada/.cargo/bin/cargo", "static.crates.io", 443)];
        // The agent names a program loosely; the kernel's is used.
        let shaped = shape(
            &proposed("", &["static.crates.io", "crates.io"], &["443"]),
            &observed,
            NEVER,
        )
        .unwrap();
        assert_eq!(shaped.conditions.exe, vec!["/home/ada/.cargo/bin/cargo"]);
        assert_eq!(
            shaped.conditions.host,
            vec!["static.crates.io", "crates.io"]
        );
        assert_eq!(shaped.risks, vec![]);
    }

    #[test]
    fn broad_and_guessed_proposals_are_marked() {
        let observed = [seen("/usr/bin/node", "registry.npmjs.org", 443)];
        let risks = |p: Proposed| shape(&p, &observed, NEVER).unwrap().risks;
        assert_eq!(
            risks(proposed("/usr/bin/node", &["*.com"], &[])),
            vec![
                Risk::PublicSuffix("com".to_owned()),
                Risk::AnyPort,
                Risk::Speculative
            ]
        );
        assert_eq!(
            risks(proposed("/usr/bin/node", &["10.0.0.0/8"], &["443"])),
            vec![
                Risk::WideNetwork("10.0.0.0/8".to_owned()),
                Risk::SensitiveAlias("10.0.0.0/8".to_owned()),
                Risk::Speculative
            ]
        );
        assert_eq!(
            risks(proposed("/usr/bin/node", &["imds"], &["80"])),
            vec![Risk::SensitiveAlias("imds".to_owned()), Risk::Speculative]
        );
        assert_eq!(
            risks(proposed("", &["api.example.com"], &["443"])),
            vec![Risk::Speculative, Risk::AnyProgram]
        );
        // `*.npmjs.org` is under a registrable domain: not broad.
        assert_eq!(
            risks(proposed("/usr/bin/node", &["*.npmjs.org"], &["443"])),
            vec![]
        );
        let writable: &dyn Fn(&str) -> bool = &|_| true;
        assert!(
            shape(&proposed("/tmp/x", &["*"], &["443"]), &[], writable)
                .unwrap()
                .risks
                .contains(&Risk::WritableBinary("/tmp/x".to_owned()))
        );
    }

    #[test]
    fn everything_and_nonsense_are_refused() {
        assert_eq!(
            shape(&proposed("", &[], &[]), &[], NEVER),
            Err(Refusal::Everything)
        );
        assert_eq!(
            shape(&proposed("", &["*"], &["443"]), &[], NEVER),
            Err(Refusal::Everything)
        );
        assert!(matches!(
            shape(&proposed("node", &["x.org"], &[]), &[], NEVER),
            Err(Refusal::Invalid(_))
        ));
        assert!(matches!(
            shape(&proposed("/x", &["re:.*"], &[]), &[], NEVER),
            Err(Refusal::Invalid(_))
        ));
        assert!(matches!(
            shape(&proposed("/x", &["a*.org"], &[]), &[], NEVER),
            Err(Refusal::Invalid(_))
        ));
        assert!(matches!(
            shape(&proposed("/x", &["x.org"], &["http"]), &[], NEVER),
            Err(Refusal::Invalid(_))
        ));
        let many: Vec<String> = (0..40).map(|i| format!("h{i}.org")).collect();
        let p = Proposed {
            exe: "/x".to_owned(),
            hosts: many,
            ..Proposed::default()
        };
        assert_eq!(shape(&p, &[], NEVER), Err(Refusal::TooLong("hosts")));
    }
}
