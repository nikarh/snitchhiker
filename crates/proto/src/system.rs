//! The system firewall between the core model and the protocol: what clients are sent, and what they send, checked.

use snitchhiker_core::system::{
    self, Chain, ChainPolicy, CtState, Firewall, ICMP, ICMPV6, IcmpType, Rule, TCP, Target, UDP,
};

use crate::v1;

fn protocol_name(protocol: Option<u8>) -> String {
    match protocol {
        None => String::new(),
        Some(TCP) => "tcp".to_owned(),
        Some(UDP) => "udp".to_owned(),
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

/// The firewall as the protocol has it.
#[must_use]
pub fn firewall(firewall: &Firewall, reverts_at_ms: u64) -> v1::SystemFirewall {
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
                ct_state: rule.ct_state.iter().map(|s| s.name().to_owned()).collect(),
                icmp_types: rule
                    .icmp_types
                    .iter()
                    .map(|t| t.name().to_owned())
                    .collect(),
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

/// The firewall a client sent, checked.
pub fn firewall_from(wire: &v1::SystemFirewall) -> Result<Firewall, String> {
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
                    system::parse_network(text)
                        .map_err(|_| format!("rule {n}: `{text}` isn't an address or a network"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let protocol = match rule.protocol.trim().to_ascii_lowercase().as_str() {
            "" => None,
            "tcp" => Some(TCP),
            "udp" => Some(UDP),
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
                .map(|s| {
                    CtState::parse(s)
                        .ok_or_else(|| format!("rule {n}: `{s}` isn't a connection state"))
                })
                .collect::<Result<_, _>>()?,
            icmp_types: rule
                .icmp_types
                .iter()
                .map(|t| {
                    IcmpType::parse(t).ok_or_else(|| format!("rule {n}: `{t}` isn't an ICMP type"))
                })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_form_round_trips() {
        let defaults = system::defaults();
        assert_eq!(firewall_from(&firewall(&defaults, 0)).unwrap(), defaults);
        let mut bad = firewall(&defaults, 0);
        bad.rules[2].destination_ports = "http".to_owned();
        assert!(firewall_from(&bad).unwrap_err().contains("rule 3"));
    }
}
