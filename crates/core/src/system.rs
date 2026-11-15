//! The system firewall: the base packet filter the node keeps beside its application rules (inbound and forward
//! policies, and rules over protocols, addresses, ports, interfaces and connection state), as a form over a fixed set of
//! statements rather than raw nftables text.
//!
//! The defaults are those OpenSnitch ships (written from the list of what they do): ICMP echo and unreachable messages
//! allowed; SSH inbound, loopback, a WireGuard exclusion and queueing forwarded connections present but off.

use std::net::Ipv4Addr;

use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainPolicy {
    #[default]
    Accept,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// Packets to this machine.
    #[default]
    Input,
    /// Packets routed through it (containers, VMs, a router).
    Forward,
    /// Packets from it.
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    #[default]
    Accept,
    Drop,
    /// Refused with an ICMP "port unreachable" (TCP: a reset).
    Reject,
    /// Logged to the kernel log, then on to the next rule.
    Log,
    /// Handed to the daemon to decide as an application connection (for forwarded traffic).
    Queue,
}

/// Connection tracking states a rule can require (any of them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CtState {
    New,
    Established,
    Related,
    Invalid,
}

impl CtState {
    /// The kernel's bit for the state.
    #[must_use]
    pub const fn bit(self) -> u32 {
        match self {
            Self::Invalid => 1,
            Self::Established => 1 << 1,
            Self::Related => 1 << 2,
            Self::New => 1 << 3,
        }
    }
}

/// ICMP messages a rule can name; the numbers depend on the protocol (ICMP or ICMPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
}

impl IcmpType {
    #[must_use]
    pub const fn number(self, v6: bool) -> u8 {
        match (self, v6) {
            (Self::EchoReply, false) => 0,
            (Self::DestinationUnreachable, false) | (Self::TimeExceeded, true) => 3,
            (Self::EchoRequest, false) => 8,
            (Self::TimeExceeded, false) => 11,
            (Self::DestinationUnreachable, true) => 1,
            (Self::EchoRequest, true) => 128,
            (Self::EchoReply, true) => 129,
        }
    }
}

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMP: u8 = 1;
pub const ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub chain: Chain,
    /// None: any protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination: Vec<IpNet>,
    /// An inclusive range (one port: both ends the same).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ports: Option<(u16, u16)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ports: Option<(u16, u16)>,
    /// An interface name, or a prefix ending in `*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ct_state: Vec<CtState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp_types: Vec<IcmpType>,
    pub target: Target,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            enabled: true,
            description: String::new(),
            chain: Chain::Input,
            protocol: None,
            source: Vec::new(),
            destination: Vec::new(),
            source_ports: None,
            destination_ports: None,
            in_interface: None,
            out_interface: None,
            ct_state: Vec::new(),
            icmp_types: Vec::new(),
            target: Target::Accept,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    pub enabled: bool,
    pub input: ChainPolicy,
    pub forward: ChainPolicy,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("rule {0}: ports need TCP or UDP")]
    PortsWithoutProtocol(usize),
    #[error("rule {0}: ICMP types need ICMP or ICMPv6")]
    IcmpWithoutProtocol(usize),
    #[error("rule {0}: a port range goes from low to high")]
    Range(usize),
    #[error("rule {0}: interface names are at most 15 characters")]
    Interface(usize),
    #[error("rule {0}: queueing is for forwarded connections")]
    QueueOutsideForward(usize),
    #[error("rule {0}: the source and destination mix IPv4 and IPv6")]
    Families(usize),
    #[error("rule {0}: {1}")]
    Parse(usize, String),
}

impl Firewall {
    /// Checks what the kernel would refuse, or what would never match.
    pub fn validate(&self) -> Result<(), Invalid> {
        for (i, rule) in self.rules.iter().enumerate() {
            let n = i + 1;
            let ports = rule.source_ports.is_some() || rule.destination_ports.is_some();
            if ports && !matches!(rule.protocol, Some(TCP | UDP)) {
                return Err(Invalid::PortsWithoutProtocol(n));
            }
            if !rule.icmp_types.is_empty() && !matches!(rule.protocol, Some(ICMP | ICMPV6)) {
                return Err(Invalid::IcmpWithoutProtocol(n));
            }
            if [rule.source_ports, rule.destination_ports]
                .iter()
                .flatten()
                .any(|(low, high)| low > high)
            {
                return Err(Invalid::Range(n));
            }
            if [&rule.in_interface, &rule.out_interface]
                .iter()
                .filter_map(|i| i.as_deref())
                .any(|name| name.trim_end_matches('*').len() > 15 || name.is_empty())
            {
                return Err(Invalid::Interface(n));
            }
            if rule.target == Target::Queue && rule.chain != Chain::Forward {
                return Err(Invalid::QueueOutsideForward(n));
            }
            // Each source is paired with each destination of its family: some pair must exist.
            if !rule.source.is_empty()
                && !rule.destination.is_empty()
                && !rule.source.iter().any(|a| {
                    rule.destination
                        .iter()
                        .any(|b| matches!(a, IpNet::V6(_)) == matches!(b, IpNet::V6(_)))
                })
            {
                return Err(Invalid::Families(n));
            }
        }
        Ok(())
    }
}

/// The firewall a node starts with: OpenSnitch's defaults. Off until the user turns it on, so that installing
/// Snitchhiker never changes a machine's inbound filtering by itself.
#[must_use]
pub fn defaults() -> Firewall {
    let icmp = |protocol| Rule {
        description: if protocol == ICMP {
            "ICMP echo and unreachable".to_owned()
        } else {
            "ICMPv6 echo and unreachable".to_owned()
        },
        protocol: Some(protocol),
        icmp_types: vec![
            IcmpType::EchoRequest,
            IcmpType::EchoReply,
            IcmpType::DestinationUnreachable,
        ],
        ..Rule::default()
    };
    Firewall {
        enabled: false,
        input: ChainPolicy::Accept,
        forward: ChainPolicy::Accept,
        rules: vec![
            icmp(ICMP),
            icmp(ICMPV6),
            Rule {
                enabled: false,
                description: "SSH from anywhere".to_owned(),
                protocol: Some(TCP),
                destination_ports: Some((22, 22)),
                ..Rule::default()
            },
            Rule {
                enabled: false,
                description: "Loopback addresses".to_owned(),
                source: Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 0), 8)
                    .map(IpNet::V4)
                    .into_iter()
                    .collect(),
                ..Rule::default()
            },
            Rule {
                enabled: false,
                description: "WireGuard (left to its own routing)".to_owned(),
                protocol: Some(UDP),
                destination_ports: Some((51820, 51820)),
                ..Rule::default()
            },
            Rule {
                enabled: false,
                description: "Forwarded connections decided as applications'".to_owned(),
                chain: Chain::Forward,
                ct_state: vec![CtState::New],
                target: Target::Queue,
                ..Rule::default()
            },
        ],
    }
}

/// Rules a drop policy can't do without, put before the user's: replies to this machine's own connections, loopback,
/// and (for IPv6) neighbour discovery, without which the network stops working. As OpenSnitch's UI adds.
#[must_use]
pub fn implied(firewall: &Firewall) -> Vec<Rule> {
    let mut rules = Vec::new();
    for (chain, policy) in [
        (Chain::Input, firewall.input),
        (Chain::Forward, firewall.forward),
    ] {
        if policy != ChainPolicy::Drop {
            continue;
        }
        rules.push(Rule {
            description: "replies and related".to_owned(),
            chain,
            ct_state: vec![CtState::Established, CtState::Related],
            ..Rule::default()
        });
        if chain == Chain::Input {
            rules.push(Rule {
                description: "loopback".to_owned(),
                chain,
                in_interface: Some("lo".to_owned()),
                ..Rule::default()
            });
            rules.push(Rule {
                description: "ICMPv6 (neighbour discovery and errors)".to_owned(),
                chain,
                protocol: Some(ICMPV6),
                ..Rule::default()
            });
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_valid_and_off() {
        let firewall = defaults();
        assert!(!firewall.enabled);
        firewall.validate().unwrap();
        assert_eq!(implied(&firewall), Vec::new());
        let round = serde_json::to_string(&firewall).unwrap();
        assert_eq!(serde_json::from_str::<Firewall>(&round).unwrap(), firewall);
    }

    #[test]
    fn mistakes_are_refused() {
        let with = |rule: Rule| Firewall {
            rules: vec![rule],
            ..defaults()
        };
        assert_eq!(
            with(Rule {
                destination_ports: Some((22, 22)),
                ..Rule::default()
            })
            .validate(),
            Err(Invalid::PortsWithoutProtocol(1))
        );
        assert_eq!(
            with(Rule {
                protocol: Some(TCP),
                destination_ports: Some((90, 80)),
                ..Rule::default()
            })
            .validate(),
            Err(Invalid::Range(1))
        );
        assert_eq!(
            with(Rule {
                target: Target::Queue,
                ..Rule::default()
            })
            .validate(),
            Err(Invalid::QueueOutsideForward(1))
        );
        assert_eq!(
            with(Rule {
                source: vec!["10.0.0.0/8".parse().unwrap()],
                destination: vec!["2001:db8::/32".parse().unwrap()],
                ..Rule::default()
            })
            .validate(),
            Err(Invalid::Families(1))
        );
    }

    #[test]
    fn a_drop_policy_keeps_replies_loopback_and_neighbours() {
        let firewall = Firewall {
            input: ChainPolicy::Drop,
            ..defaults()
        };
        let implied = implied(&firewall);
        assert_eq!(implied.len(), 3);
        assert!(
            implied
                .iter()
                .all(|r| r.chain == Chain::Input && r.target == Target::Accept)
        );
    }
}
