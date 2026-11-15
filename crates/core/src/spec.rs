//! Rules as people write them: the TOML (or JSON) of rule files, exports and managed `rules.d` files.
//!
//! ```toml
//! [folder]
//! name = "Claude Code"
//! exe = ["glob:{home}/.local/share/claude/versions/*/claude"]   # a scope: added to every rule below
//!
//! [[rule]]
//! name = "API"
//! action = "allow"
//! host = ["api.example.com", "*.example.org"]
//! port = ["443"]
//! ```
//!
//! Patterns are exact unless prefixed with `glob:` or `re:`. Ports are numbers or `low-high` ranges; protocols are
//! `tcp`, `udp`, `icmp`, `icmpv6` or numbers.

use serde::{Deserialize, Serialize};

use crate::destination::{HostPattern, Network};
use crate::pattern::PatternSource;
use crate::rule::{Action, Condition, ContextKind, Expiry, Rule, Tier};

/// Conditions, as keys; all present ones must hold, and a list means any of its items.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conditions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exe: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmdline: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uid: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub name: String,
    pub action: Action,
    #[serde(default)]
    pub tier: Tier,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(flatten)]
    pub conditions: Conditions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderSpec {
    pub name: String,
    #[serde(flatten)]
    pub scope: Conditions,
}

/// A rule file: an optional folder (name and scope) and its rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<FolderSpec>,
    #[serde(default)]
    pub rule: Vec<RuleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("{0}")]
    Host(#[from] crate::destination::HostPatternError),
    #[error("{0}")]
    Network(#[from] crate::destination::NetworkError),
    #[error("invalid port `{0}`: a number or low-high")]
    Port(String),
    #[error("invalid protocol `{0}`: tcp, udp, icmp, icmpv6 or a number")]
    Protocol(String),
    #[error("rule `{0}` has no conditions: it would match every connection")]
    NoConditions(String),
}

const fn yes() -> bool {
    true
}

fn pattern(text: &str) -> PatternSource {
    if let Some(glob) = text.strip_prefix("glob:") {
        PatternSource::Glob(glob.to_owned())
    } else if let Some(regex) = text.strip_prefix("re:") {
        PatternSource::Regex(regex.to_owned())
    } else {
        PatternSource::Exact(text.to_owned())
    }
}

fn pattern_text(pattern: &PatternSource) -> String {
    match pattern {
        PatternSource::Exact(text) => text.clone(),
        PatternSource::Glob(text) => format!("glob:{text}"),
        PatternSource::Regex(text) => format!("re:{text}"),
    }
}

fn port_range(text: &str) -> Result<(u16, u16), SpecError> {
    let error = || SpecError::Port(text.to_owned());
    let (low, high) = text.split_once('-').unwrap_or((text, text));
    let low: u16 = low.trim().parse().map_err(|_| error())?;
    let high: u16 = high.trim().parse().map_err(|_| error())?;
    if low > high {
        return Err(error());
    }
    Ok((low, high))
}

fn protocol(text: &str) -> Result<u8, SpecError> {
    match text {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        other => other
            .parse()
            .map_err(|_| SpecError::Protocol(text.to_owned())),
    }
}

impl Conditions {
    /// The model's conditions.
    pub fn to_conditions(&self) -> Result<Vec<Condition>, SpecError> {
        let patterns = |texts: &[String]| texts.iter().map(|t| pattern(t)).collect::<Vec<_>>();
        let mut conditions = Vec::new();
        if !self.exe.is_empty() {
            conditions.push(Condition::Exe(patterns(&self.exe)));
        }
        if !self.app.is_empty() {
            conditions.push(Condition::App(patterns(&self.app)));
        }
        if !self.cmdline.is_empty() {
            conditions.push(Condition::Cmdline(patterns(&self.cmdline)));
        }
        if !self.parent.is_empty() {
            conditions.push(Condition::Parent(patterns(&self.parent)));
        }
        if !self.uid.is_empty() {
            conditions.push(Condition::Uid(self.uid.clone()));
        }
        if !self.host.is_empty() {
            let hosts = self
                .host
                .iter()
                .map(|h| HostPattern::try_from(h.clone()))
                .collect::<Result<_, _>>()?;
            conditions.push(Condition::Host(hosts));
        }
        if !self.net.is_empty() {
            let nets = self
                .net
                .iter()
                .map(|n| Network::try_from(n.clone()))
                .collect::<Result<_, _>>()?;
            conditions.push(Condition::Net(nets));
        }
        if !self.port.is_empty() {
            let ports = self
                .port
                .iter()
                .map(|p| port_range(p))
                .collect::<Result<_, _>>()?;
            conditions.push(Condition::Port(ports));
        }
        if !self.protocol.is_empty() {
            let protocols = self
                .protocol
                .iter()
                .map(|p| protocol(p))
                .collect::<Result<_, _>>()?;
            conditions.push(Condition::Protocol(protocols));
        }
        if let Some(context) = self.context {
            conditions.push(Condition::Context(context));
        }
        Ok(conditions)
    }

    /// The written form of model conditions (negations can't be written in this form and are left out).
    #[must_use]
    pub fn from_conditions(conditions: &[Condition]) -> Self {
        let mut spec = Self::default();
        for condition in conditions {
            match condition {
                Condition::Exe(p) => spec.exe.extend(p.iter().map(pattern_text)),
                Condition::App(p) => spec.app.extend(p.iter().map(pattern_text)),
                Condition::Cmdline(p) => spec.cmdline.extend(p.iter().map(pattern_text)),
                Condition::Parent(p) => spec.parent.extend(p.iter().map(pattern_text)),
                Condition::Uid(u) => spec.uid.extend(u),
                Condition::Host(h) => spec.host.extend(h.iter().map(ToString::to_string)),
                Condition::Net(n) => spec.net.extend(n.iter().map(ToString::to_string)),
                Condition::Port(p) => spec.port.extend(p.iter().map(|&(low, high)| {
                    if low == high {
                        low.to_string()
                    } else {
                        format!("{low}-{high}")
                    }
                })),
                Condition::Protocol(p) => spec.protocol.extend(p.iter().map(|&n| match n {
                    6 => "tcp".to_owned(),
                    17 => "udp".to_owned(),
                    1 => "icmp".to_owned(),
                    58 => "icmpv6".to_owned(),
                    n => n.to_string(),
                })),
                Condition::Context(c) => spec.context = Some(*c),
                Condition::Not(_) => {}
            }
        }
        spec
    }
}

impl RuleSpec {
    /// The model's rule, with `id` and in `folder`. A rule without any condition is refused: it would decide every
    /// connection, which a typo shouldn't do.
    pub fn to_rule(&self, id: u64, folder: Option<u64>) -> Result<Rule, SpecError> {
        let conditions = self.conditions.to_conditions()?;
        if conditions.is_empty() {
            return Err(SpecError::NoConditions(self.name.clone()));
        }
        Ok(Rule {
            id,
            folder,
            name: self.name.clone(),
            enabled: self.enabled,
            action: self.action,
            tier: self.tier,
            expiry: Expiry::Never,
            log: true,
            notes: self.notes.clone(),
            conditions,
        })
    }

    #[must_use]
    pub fn from_rule(rule: &Rule) -> Self {
        Self {
            name: rule.name.clone(),
            action: rule.action,
            tier: rule.tier,
            enabled: rule.enabled,
            notes: rule.notes.clone(),
            conditions: Conditions::from_conditions(&rule.conditions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
[folder]
name = "Claude Code"
exe = ["glob:{home}/.local/share/claude/versions/*/claude"]

[[rule]]
name = "API"
action = "allow"
host = ["api.example.com", "*.example.org"]
port = ["443", "8000-8080"]
protocol = ["tcp"]

[[rule]]
name = "Never the metadata service"
action = "deny"
tier = "override"
net = ["imds"]
context = "any"
"#;

    #[test]
    fn reads_a_rule_file() {
        let file: RuleFile = toml::from_str(FILE).unwrap();
        let folder = file.folder.as_ref().unwrap();
        assert_eq!(folder.scope.to_conditions().unwrap().len(), 1);
        let api = file.rule[0].to_rule(1, Some(9)).unwrap();
        assert_eq!(api.action, Action::Allow);
        assert_eq!(
            api.conditions[1],
            Condition::Port(vec![(443, 443), (8000, 8080)])
        );
        let imds = file.rule[1].to_rule(2, None).unwrap();
        assert_eq!(imds.tier, Tier::Override);
        assert_eq!(imds.conditions[1], Condition::Context(ContextKind::Any));
    }

    #[test]
    fn round_trips_through_the_model() {
        let file: RuleFile = toml::from_str(FILE).unwrap();
        for spec in &file.rule {
            let rule = spec.to_rule(1, None).unwrap();
            assert_eq!(&RuleSpec::from_rule(&rule), spec);
        }
    }

    #[test]
    fn refuses_rules_matching_everything_and_bad_values() {
        let empty: RuleFile =
            toml::from_str("[[rule]]\nname = \"x\"\naction = \"allow\"\n").unwrap();
        assert!(matches!(
            empty.rule[0].to_rule(1, None),
            Err(SpecError::NoConditions(_))
        ));
        let bad: RuleFile =
            toml::from_str("[[rule]]\nname = \"x\"\naction = \"allow\"\nport = [\"9-1\"]\n")
                .unwrap();
        assert!(bad.rule[0].to_rule(1, None).is_err());
        assert!(
            toml::from_str::<RuleFile>(
                "[[rule]]\nname = \"x\"\naction = \"allow\"\nhots = [\"a\"]\n"
            )
            .is_err()
        );
    }
}
