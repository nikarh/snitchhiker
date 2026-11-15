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
    pub const ALL: [Self; 4] = [Self::New, Self::Established, Self::Related, Self::Invalid];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Established => "established",
            Self::Related => "related",
            Self::Invalid => "invalid",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name.trim())
    }

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
    pub const ALL: [Self; 4] = [
        Self::EchoRequest,
        Self::EchoReply,
        Self::DestinationUnreachable,
        Self::TimeExceeded,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EchoRequest => "echo-request",
            Self::EchoReply => "echo-reply",
            Self::DestinationUnreachable => "destination-unreachable",
            Self::TimeExceeded => "time-exceeded",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name.trim())
    }

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

/// OpenSnitch's `system-fw.json`, converted: the firewall, the rules that couldn't be expressed exactly (description,
/// reason), and notes on what converted but behaves differently here.
#[derive(Debug, Default)]
pub struct Imported {
    pub firewall: Option<Firewall>,
    pub skipped: Vec<(String, String)>,
    pub notes: Vec<String>,
}

mod opensnitch {
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Config {
        #[serde(default)]
        pub enabled: bool,
        #[serde(default)]
        pub system_rules: Vec<Entry>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Entry {
        #[serde(default)]
        pub rule: Option<Rule>,
        #[serde(default)]
        pub chains: Vec<Chain>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Chain {
        #[serde(default)]
        pub name: String,
        #[serde(default)]
        pub family: String,
        #[serde(default, rename = "Type")]
        pub kind: String,
        #[serde(default)]
        pub hook: String,
        #[serde(default)]
        pub policy: String,
        #[serde(default)]
        pub rules: Vec<Rule>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Rule {
        #[serde(default)]
        pub enabled: bool,
        #[serde(default)]
        pub description: String,
        #[serde(default)]
        pub parameters: String,
        #[serde(default)]
        pub expressions: Option<Vec<Expression>>,
        #[serde(default)]
        pub target: String,
        #[serde(default)]
        pub target_parameters: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Expression {
        pub statement: Option<Statement>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Statement {
        #[serde(default)]
        pub op: String,
        #[serde(default)]
        pub name: String,
        #[serde(default)]
        pub values: Option<Vec<Value>>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Value {
        #[serde(default)]
        pub key: String,
        #[serde(default)]
        pub value: String,
    }
}

/// Converts OpenSnitch's `system-fw.json`. What it holds beyond this model's statements is listed, never guessed at.
#[must_use]
pub fn import_opensnitch(json: &str) -> Imported {
    let mut imported = Imported::default();
    let config: opensnitch::Config = match serde_json::from_str(json) {
        Ok(config) => config,
        Err(e) => {
            imported.skipped.push((
                "system-fw.json".to_owned(),
                format!("not OpenSnitch's format: {e}"),
            ));
            return imported;
        }
    };
    let mut firewall = Firewall {
        enabled: config.enabled,
        input: ChainPolicy::Accept,
        forward: ChainPolicy::Accept,
        rules: Vec::new(),
    };
    for entry in &config.system_rules {
        if let Some(rule) = &entry.rule
            && (!rule.parameters.is_empty() || !rule.target.is_empty())
        {
            imported.skipped.push((
                label(rule),
                "an iptables rule (OpenSnitch's legacy format)".to_owned(),
            ));
        }
        for chain in &entry.chains {
            let ours = match (chain.hook.as_str(), chain.kind.as_str()) {
                ("input", "filter" | "mangle") => Chain::Input,
                ("forward", "filter" | "mangle") => Chain::Forward,
                ("output", "filter" | "mangle") => Chain::Output,
                _ => {
                    for rule in &chain.rules {
                        imported.skipped.push((
                            label(rule),
                            format!(
                                "in {} ({} {}): only input, forward and output filtering are kept",
                                chain.name, chain.kind, chain.hook
                            ),
                        ));
                    }
                    continue;
                }
            };
            if chain.family != "inet" && !chain.family.is_empty() {
                for rule in &chain.rules {
                    imported.skipped.push((
                        label(rule),
                        format!("family {}: only inet is kept", chain.family),
                    ));
                }
                continue;
            }
            if chain.policy.eq_ignore_ascii_case("drop") {
                match ours {
                    Chain::Input => firewall.input = ChainPolicy::Drop,
                    Chain::Forward => firewall.forward = ChainPolicy::Drop,
                    Chain::Output => imported.skipped.push((
                        chain.name.clone(),
                        "a drop policy for output: application rules decide what goes out"
                            .to_owned(),
                    )),
                }
            }
            for rule in &chain.rules {
                match convert(rule, ours) {
                    Ok(converted) => {
                        if ours == Chain::Output
                            && converted.target == Target::Accept
                            && chain.kind == "mangle"
                        {
                            imported.notes.push(format!(
                                "{}: in OpenSnitch, accepting in mangle output also kept these connections from \
                                 being asked about; here application rules decide those",
                                label(rule)
                            ));
                        }
                        firewall.rules.push(converted);
                    }
                    Err(reason) => imported.skipped.push((label(rule), reason)),
                }
            }
        }
    }
    if let Err(e) = firewall.validate() {
        imported
            .skipped
            .push(("system-fw.json".to_owned(), e.to_string()));
        return imported;
    }
    imported.firewall = Some(firewall);
    imported
}

fn label(rule: &opensnitch::Rule) -> String {
    if rule.description.is_empty() {
        "(no description)".to_owned()
    } else {
        rule.description.clone()
    }
}

fn convert(rule: &opensnitch::Rule, chain: Chain) -> Result<Rule, String> {
    let mut ours = Rule {
        enabled: rule.enabled,
        description: rule.description.clone(),
        chain,
        target: match rule.target.to_ascii_lowercase().as_str() {
            "accept" => Target::Accept,
            "drop" => Target::Drop,
            "reject" => Target::Reject,
            "log" => Target::Log,
            "queue" if chain == Chain::Forward => Target::Queue,
            other => {
                return Err(format!("target `{other}` {}", rule.target_parameters)
                    .trim()
                    .to_owned());
            }
        },
        ..Rule::default()
    };
    for expression in rule.expressions.iter().flatten() {
        let Some(statement) = &expression.statement else {
            continue;
        };
        if !matches!(statement.op.as_str(), "" | "==") {
            return Err(format!("`{}` comparisons aren't kept", statement.op));
        }
        for value in statement.values.iter().flatten() {
            apply(&mut ours, &statement.name, &value.key, value.value.trim())?;
        }
    }
    Ok(ours)
}

fn apply(rule: &mut Rule, name: &str, key: &str, value: &str) -> Result<(), String> {
    let set_protocol = |rule: &mut Rule, protocol: u8| match rule.protocol {
        Some(p) if p != protocol => Err("two protocols in one rule".to_owned()),
        _ => {
            rule.protocol = Some(protocol);
            Ok(())
        }
    };
    match (name, key) {
        ("tcp" | "udp", "dport" | "sport") => {
            set_protocol(rule, if name == "tcp" { TCP } else { UDP })?;
            let range = ports(value)?;
            if key == "dport" {
                rule.destination_ports = Some(range);
            } else {
                rule.source_ports = Some(range);
            }
        }
        ("icmp" | "icmpv6", "type") => {
            set_protocol(rule, if name == "icmp" { ICMP } else { ICMPV6 })?;
            for kind in value.split(',').map(str::trim) {
                rule.icmp_types
                    .push(IcmpType::parse(kind).ok_or_else(|| format!("ICMP type `{kind}`"))?);
            }
        }
        ("ct", "state") => {
            for state in value.split(',').map(str::trim) {
                rule.ct_state.push(
                    CtState::parse(state).ok_or_else(|| format!("connection state `{state}`"))?,
                );
            }
        }
        ("ip" | "ip6", "saddr" | "daddr") => {
            let net = parse_network(value)?;
            if key == "saddr" {
                rule.source.push(net);
            } else {
                rule.destination.push(net);
            }
        }
        ("meta", "l4proto") => {
            set_protocol(
                rule,
                match value {
                    "tcp" => TCP,
                    "udp" => UDP,
                    "icmp" => ICMP,
                    "icmpv6" => ICMPV6,
                    other => other.parse().map_err(|_| format!("protocol `{other}`"))?,
                },
            )?;
        }
        ("iifname" | "meta", "iifname" | "") if name == "iifname" || key == "iifname" => {
            rule.in_interface = Some(value.to_owned());
        }
        ("oifname" | "meta", "oifname" | "") if name == "oifname" || key == "oifname" => {
            rule.out_interface = Some(value.to_owned());
        }
        _ => return Err(format!("`{name} {key}` isn't kept")),
    }
    Ok(())
}

fn ports(value: &str) -> Result<(u16, u16), String> {
    if value.contains(',') {
        return Err(format!(
            "port lists (`{value}`): one port or range per rule"
        ));
    }
    let (low, high) = value.split_once('-').unwrap_or((value, value));
    let parse = |p: &str| {
        p.trim()
            .parse::<u16>()
            .map_err(|_| format!("port `{value}`"))
    };
    Ok((parse(low)?, parse(high)?))
}

/// An address, a network, or a range that is exactly one network (`127.0.0.0-127.255.255.255`).
pub fn parse_network(value: &str) -> Result<IpNet, String> {
    let value = value.trim();
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return Ok(IpNet::from(address));
    }
    let (first, last) = value
        .split_once('-')
        .ok_or_else(|| format!("address `{value}`"))?;
    let (first, last): (std::net::IpAddr, std::net::IpAddr) = (
        first
            .trim()
            .parse()
            .map_err(|_| format!("address `{value}`"))?,
        last.trim()
            .parse()
            .map_err(|_| format!("address `{value}`"))?,
    );
    let bits = if first.is_ipv4() { 32 } else { 128 };
    (0..=bits)
        .filter_map(|length| IpNet::new(first, length).ok())
        .find(|net| net.network() == first && net.broadcast() == last)
        .ok_or_else(|| format!("the range `{value}` isn't one network"))
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
    fn opensnitchs_defaults_import() {
        let json = r#"{"Enabled": true, "Version": 1, "SystemRules": [
          {"Rule": {"Table": "mangle", "Chain": "OUTPUT", "Enabled": false, "Position": "0", "Description": "Allow icmp",
                    "Parameters": "-p icmp", "Expressions": [], "Target": "ACCEPT", "TargetParameters": ""}, "Chains": []},
          {"Chains": [
            {"Name": "filter_input", "Table": "opensnitch", "Family": "inet", "Priority": "", "Type": "filter",
             "Hook": "input", "Policy": "drop", "Rules": [
               {"Enabled": false, "Position": "0", "Description": "SSH", "Parameters": "",
                "Expressions": [{"Statement": {"Op": "", "Name": "tcp", "Values": [{"Key": "dport", "Value": "22"}]}}],
                "Target": "accept", "TargetParameters": ""}]},
            {"Name": "nat_output", "Table": "opensnitch", "Family": "inet", "Type": "natdest", "Hook": "output",
             "Policy": "accept", "Rules": [{"Enabled": true, "Description": "redirect", "Target": "redirect"}]},
            {"Name": "mangle_output", "Table": "opensnitch", "Family": "inet", "Priority": "", "Type": "mangle",
             "Hook": "output", "Policy": "accept", "Rules": [
               {"Enabled": false, "Position": "0", "Description": "localhost",
                "Expressions": [{"Statement": {"Op": "==", "Name": "ip", "Values": [{"Key": "daddr", "Value": "127.0.0.0-127.255.255.255"}]}}],
                "Target": "accept", "TargetParameters": ""},
               {"Enabled": true, "Position": "0", "Description": "ICMP",
                "Expressions": [{"Statement": {"Op": "", "Name": "icmp", "Values": [{"Key": "type", "Value": "echo-request,echo-reply"}]}}],
                "Target": "accept", "TargetParameters": ""},
               {"Enabled": true, "Description": "not https", "Expressions": [{"Statement": {"Op": "!=", "Name": "tcp",
                "Values": [{"Key": "dport", "Value": "443"}]}}], "Target": "drop"}]},
            {"Name": "mangle_forward", "Table": "opensnitch", "Family": "inet", "Type": "mangle", "Hook": "forward",
             "Policy": "accept", "Rules": [{"Enabled": false, "Description": "forwarded",
               "Expressions": [{"Statement": {"Op": "", "Name": "ct", "Values": [{"Key": "state", "Value": "new"}]}}],
               "Target": "queue", "TargetParameters": "num 0"}]}
          ]}]}"#;
        let imported = import_opensnitch(json);
        let firewall = imported.firewall.unwrap();
        assert!(firewall.enabled);
        assert_eq!(firewall.input, ChainPolicy::Drop);
        let names: Vec<&str> = firewall
            .rules
            .iter()
            .map(|r| r.description.as_str())
            .collect();
        assert_eq!(names, vec!["SSH", "localhost", "ICMP", "forwarded"]);
        assert_eq!(firewall.rules[0].destination_ports, Some((22, 22)));
        assert_eq!(
            firewall.rules[1].destination,
            vec!["127.0.0.0/8".parse::<IpNet>().unwrap()]
        );
        assert_eq!(firewall.rules[3].target, Target::Queue);
        let skipped: Vec<&str> = imported
            .skipped
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(skipped, vec!["Allow icmp", "redirect", "not https"]);
        assert_eq!(imported.notes.len(), 2);
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
