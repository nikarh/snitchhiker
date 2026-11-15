//! The system firewall on this node: the core model, its protocol form, and the `inet snitchhiker_system` table it
//! becomes.

use std::fmt::Write as _;
use std::str::FromStr as _;

use ipnet::IpNet;
use snitchhiker_core::system::{
    self, Chain, ChainPolicy, CtState, Firewall, ICMP, ICMPV6, IcmpType, Rule, Target,
};
use snitchhiker_netfilter::netlink::{Socket, Writer};
use snitchhiker_netfilter::nftables::{
    Interface, Prefix, SystemChain, SystemRule, SystemTable, SystemTarget, encode_remove,
    encode_system,
};
use snitchhiker_proto::v1;

use crate::config::{Config, Fail};

pub const TABLE: &str = "snitchhiker_system";

/// Makes the kernel's table what `firewall` says: installed when it is on, removed when it is off.
pub fn apply(firewall: &Firewall, config: &Config) -> std::io::Result<()> {
    let mut socket = Socket::open()?;
    let mut writer = Writer::new();
    let batch = if firewall.enabled {
        encode_system(&mut writer, &table(firewall, config), 1)
    } else {
        encode_remove(&mut writer, TABLE, 1)
    };
    socket.transact(&writer, batch.first, batch.last)
}

/// Removes the table (the daemon stops with `fail = open`).
pub fn remove() -> std::io::Result<()> {
    let mut socket = Socket::open()?;
    let mut writer = Writer::new();
    let batch = encode_remove(&mut writer, TABLE, 1);
    socket.transact(&writer, batch.first, batch.last)
}

fn prefix(net: &IpNet) -> Prefix {
    Prefix {
        address: match net.addr() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        },
        length: net.prefix_len(),
    }
}

fn interface(name: Option<&String>) -> Option<Interface> {
    name.map(|name| Interface {
        name: name.trim_end_matches('*').to_owned(),
        prefix: name.ends_with('*'),
    })
}

/// The kernel's rules for the firewall: those a drop policy implies, then each rule that is on, once for each pair of
/// source and destination of one family and each ICMP type.
#[must_use]
pub fn table(firewall: &Firewall, config: &Config) -> SystemTable {
    let mut rules = Vec::new();
    for rule in system::implied(firewall)
        .iter()
        .chain(firewall.rules.iter().filter(|r| r.enabled))
    {
        let sources: Vec<Option<&IpNet>> = if rule.source.is_empty() {
            vec![None]
        } else {
            rule.source.iter().map(Some).collect()
        };
        let destinations: Vec<Option<&IpNet>> = if rule.destination.is_empty() {
            vec![None]
        } else {
            rule.destination.iter().map(Some).collect()
        };
        let v6 = |net: Option<&IpNet>| net.map(|n| matches!(n, IpNet::V6(_)));
        let icmp: Vec<Option<u8>> = if rule.icmp_types.is_empty() {
            vec![None]
        } else {
            rule.icmp_types
                .iter()
                .map(|t| Some(t.number(rule.protocol == Some(ICMPV6))))
                .collect()
        };
        for source in &sources {
            for destination in &destinations {
                if let (Some(a), Some(b)) = (v6(*source), v6(*destination))
                    && a != b
                {
                    continue;
                }
                for icmp_type in &icmp {
                    rules.push(SystemRule {
                        chain: match rule.chain {
                            Chain::Input => SystemChain::Input,
                            Chain::Forward => SystemChain::Forward,
                            Chain::Output => SystemChain::Output,
                        },
                        protocol: rule.protocol,
                        source: source.map(prefix),
                        destination: destination.map(prefix),
                        source_ports: rule.source_ports,
                        destination_ports: rule.destination_ports,
                        in_interface: interface(rule.in_interface.as_ref()),
                        out_interface: interface(rule.out_interface.as_ref()),
                        ct_state: rule.ct_state.iter().fold(0, |bits, s| bits | s.bit()),
                        icmp_type: *icmp_type,
                        target: match rule.target {
                            Target::Accept => SystemTarget::Accept,
                            Target::Drop => SystemTarget::Drop,
                            Target::Reject => SystemTarget::Reject,
                            Target::Log => SystemTarget::Log(format!(
                                "snitchhiker {}: ",
                                if rule.description.is_empty() {
                                    "system"
                                } else {
                                    &rule.description
                                }
                                .chars()
                                .take(100)
                                .collect::<String>()
                            )),
                            Target::Queue => SystemTarget::Queue {
                                number: config.queue,
                                total: config.queues,
                                bypass: config.fail == Fail::Open,
                            },
                        },
                    });
                }
            }
        }
    }
    SystemTable {
        name: TABLE.to_owned(),
        input_drop: firewall.input == ChainPolicy::Drop,
        forward_drop: firewall.forward == ChainPolicy::Drop,
        rules,
    }
}

fn protocol_name(protocol: Option<u8>) -> String {
    match protocol {
        None => String::new(),
        Some(system::TCP) => "tcp".to_owned(),
        Some(system::UDP) => "udp".to_owned(),
        Some(ICMP) => "icmp".to_owned(),
        Some(ICMPV6) => "icmpv6".to_owned(),
        Some(n) => n.to_string(),
    }
}

fn ports(range: Option<(u16, u16)>) -> String {
    match range {
        None => String::new(),
        Some((low, high)) if low == high => low.to_string(),
        Some((low, high)) => format!("{low}-{high}"),
    }
}

fn kebab<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The firewall as the protocol has it.
#[must_use]
pub fn wire(firewall: &Firewall, reverts_at_ms: u64) -> v1::SystemFirewall {
    let policy = |p: ChainPolicy| match p {
        ChainPolicy::Accept => v1::ChainPolicy::Accept,
        ChainPolicy::Drop => v1::ChainPolicy::Drop,
    };
    v1::SystemFirewall {
        enabled: firewall.enabled,
        input: policy(firewall.input).into(),
        forward: policy(firewall.forward).into(),
        rules: firewall
            .rules
            .iter()
            .map(|rule| v1::SystemRule {
                enabled: rule.enabled,
                description: rule.description.clone(),
                chain: match rule.chain {
                    Chain::Input => v1::SystemChain::Input,
                    Chain::Forward => v1::SystemChain::Forward,
                    Chain::Output => v1::SystemChain::Output,
                }
                .into(),
                protocol: protocol_name(rule.protocol),
                source: rule.source.iter().map(ToString::to_string).collect(),
                destination: rule.destination.iter().map(ToString::to_string).collect(),
                source_ports: ports(rule.source_ports),
                destination_ports: ports(rule.destination_ports),
                in_interface: rule.in_interface.clone().unwrap_or_default(),
                out_interface: rule.out_interface.clone().unwrap_or_default(),
                ct_state: rule.ct_state.iter().map(kebab).collect(),
                icmp_types: rule.icmp_types.iter().map(kebab).collect(),
                target: match rule.target {
                    Target::Accept => v1::SystemTarget::Accept,
                    Target::Drop => v1::SystemTarget::Drop,
                    Target::Reject => v1::SystemTarget::Reject,
                    Target::Log => v1::SystemTarget::Log,
                    Target::Queue => v1::SystemTarget::Queue,
                }
                .into(),
            })
            .collect(),
        reverts_at_ms,
    }
}

fn parse_ports(text: &str, n: usize) -> Result<Option<(u16, u16)>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let bad = || format!("rule {n}: `{text}` isn't a port or a range");
    let (low, high) = text.split_once('-').unwrap_or((text, text));
    Ok(Some((
        low.trim().parse().map_err(|_| bad())?,
        high.trim().parse().map_err(|_| bad())?,
    )))
}

fn parse_named<T: serde::de::DeserializeOwned>(
    text: &str,
    what: &str,
    n: usize,
) -> Result<T, String> {
    serde_json::from_value(serde_json::Value::String(text.trim().to_owned()))
        .map_err(|_| format!("rule {n}: `{text}` isn't {what}"))
}

/// The firewall a client sent, checked.
pub fn from_wire(wire: &v1::SystemFirewall) -> Result<Firewall, String> {
    let policy = |p: i32| match v1::ChainPolicy::try_from(p) {
        Ok(v1::ChainPolicy::Drop) => ChainPolicy::Drop,
        _ => ChainPolicy::Accept,
    };
    let mut rules = Vec::with_capacity(wire.rules.len());
    for (i, rule) in wire.rules.iter().enumerate() {
        let n = i + 1;
        let nets = |list: &[String]| {
            list.iter()
                .filter(|t| !t.trim().is_empty())
                .map(|text| {
                    IpNet::from_str(text.trim())
                        .or_else(|_| text.trim().parse::<std::net::IpAddr>().map(IpNet::from))
                        .map_err(|_| format!("rule {n}: `{text}` isn't an address or a network"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let protocol = match rule.protocol.trim().to_ascii_lowercase().as_str() {
            "" => None,
            "tcp" => Some(system::TCP),
            "udp" => Some(system::UDP),
            "icmp" => Some(ICMP),
            "icmpv6" => Some(ICMPV6),
            other => Some(
                other
                    .parse()
                    .map_err(|_| format!("rule {n}: `{other}` isn't a protocol"))?,
            ),
        };
        let interface = |text: &str| {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        };
        rules.push(Rule {
            enabled: rule.enabled,
            description: rule.description.trim().to_owned(),
            chain: match v1::SystemChain::try_from(rule.chain) {
                Ok(v1::SystemChain::Forward) => Chain::Forward,
                Ok(v1::SystemChain::Output) => Chain::Output,
                _ => Chain::Input,
            },
            protocol,
            source: nets(&rule.source)?,
            destination: nets(&rule.destination)?,
            source_ports: parse_ports(&rule.source_ports, n)?,
            destination_ports: parse_ports(&rule.destination_ports, n)?,
            in_interface: interface(&rule.in_interface),
            out_interface: interface(&rule.out_interface),
            ct_state: rule
                .ct_state
                .iter()
                .map(|s| parse_named::<CtState>(s, "a connection state", n))
                .collect::<Result<_, _>>()?,
            icmp_types: rule
                .icmp_types
                .iter()
                .map(|t| parse_named::<IcmpType>(t, "an ICMP type", n))
                .collect::<Result<_, _>>()?,
            target: match v1::SystemTarget::try_from(rule.target) {
                Ok(v1::SystemTarget::Drop) => Target::Drop,
                Ok(v1::SystemTarget::Reject) => Target::Reject,
                Ok(v1::SystemTarget::Log) => Target::Log,
                Ok(v1::SystemTarget::Queue) => Target::Queue,
                _ => Target::Accept,
            },
        });
    }
    let firewall = Firewall {
        enabled: wire.enabled,
        input: policy(wire.input),
        forward: policy(wire.forward),
        rules,
    };
    firewall.validate().map_err(|e| e.to_string())?;
    Ok(firewall)
}

/// Whether going from `before` to `after` lets in what was kept out: a dangerous action.
#[must_use]
pub fn loosened(before: &Firewall, after: &Firewall) -> bool {
    (before.enabled && !after.enabled)
        || (before.enabled
            && before.input == ChainPolicy::Drop
            && after.input == ChainPolicy::Accept)
}

/// How a change reads in the history.
#[must_use]
pub fn describe(before: &Firewall, after: &Firewall) -> String {
    let mut parts = Vec::new();
    if before.enabled != after.enabled {
        parts.push(
            if after.enabled {
                "turned on"
            } else {
                "turned off"
            }
            .to_owned(),
        );
    }
    let name = |p: ChainPolicy| kebab(&p);
    if before.input != after.input {
        parts.push(format!(
            "input {} → {}",
            name(before.input),
            name(after.input)
        ));
    }
    if before.forward != after.forward {
        parts.push(format!(
            "forward {} → {}",
            name(before.forward),
            name(after.forward)
        ));
    }
    if before.rules != after.rules {
        let on = after.rules.iter().filter(|r| r.enabled).count();
        let mut text = format!("{} rules", after.rules.len());
        let _ = write!(text, " ({on} on)");
        parts.push(text);
    }
    if parts.is_empty() {
        "system firewall unchanged".to_owned()
    } else {
        format!("system firewall: {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_form_round_trips() {
        let firewall = system::defaults();
        assert_eq!(from_wire(&wire(&firewall, 0)).unwrap(), firewall);
        let mut bad = wire(&firewall, 0);
        bad.rules[2].destination_ports = "http".to_owned();
        assert!(from_wire(&bad).unwrap_err().contains("rule 3"));
    }

    #[test]
    fn rules_expand_per_family_and_icmp_type() {
        let firewall = Firewall {
            enabled: true,
            input: ChainPolicy::Drop,
            ..system::defaults()
        };
        let table = table(&firewall, &Config::default());
        assert!(table.input_drop);
        // Three implied, then three ICMP types for each of ICMP and ICMPv6.
        assert_eq!(table.rules.len(), 3 + 3 + 3);
        let mixed = Firewall {
            rules: vec![Rule {
                source: vec![
                    "10.0.0.0/8".parse().unwrap(),
                    "2001:db8::/32".parse().unwrap(),
                ],
                destination: vec!["192.168.1.1/32".parse().unwrap()],
                ..Rule::default()
            }],
            ..firewall
        };
        // Only the IPv4 source pairs with the IPv4 destination.
        assert_eq!(table_rules(&mixed), 3 + 1);
    }

    fn table_rules(firewall: &Firewall) -> usize {
        table(firewall, &Config::default()).rules.len()
    }

    #[test]
    fn turning_it_off_or_opening_input_is_loosening() {
        let on = Firewall {
            enabled: true,
            input: ChainPolicy::Drop,
            ..system::defaults()
        };
        assert!(loosened(
            &on,
            &Firewall {
                enabled: false,
                ..on.clone()
            }
        ));
        assert!(loosened(
            &on,
            &Firewall {
                input: ChainPolicy::Accept,
                ..on.clone()
            }
        ));
        assert!(!loosened(&system::defaults(), &on));
        assert_eq!(
            describe(&system::defaults(), &on),
            "system firewall: turned on, input accept → drop"
        );
    }
}
