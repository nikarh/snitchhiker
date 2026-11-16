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
    /// Processes (`pid@start`) whose session the rule is limited to: they and what they start.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session: Vec<String>,
    /// `container.name = ["web"]` and the like: the rule holds only for containers.
    #[serde(default, skip_serializing_if = "ContainerSpec::is_empty")]
    pub container: ContainerSpec,
    #[serde(default, skip_serializing_if = "VmSpec::is_empty")]
    pub vm: VmSpec,
    /// Names of network namespaces (`ip netns`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub netns: Vec<String>,
    /// Blocklists, by name: the destination's name or address is on one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<String>,
    /// SHA-256s of the executable (hex): the binary pinned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sha256: Vec<String>,
    /// Whether a user other than root can change the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable: Option<bool>,
}

/// A container's identity, as keys of `container`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<String>,
    /// Image references (`docker.io/library/node:*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image: Vec<String>,
    /// Compose services: `project/service`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compose: Vec<String>,
    /// Labels: `key=value`, the value a pattern.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime: Vec<String>,
    /// The user a rootless container runs as.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner: Vec<u32>,
    /// Ids or their prefixes (they change when a container is recreated).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id: Vec<String>,
}

impl ContainerSpec {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A VM's identity, as keys of `vm`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uuid: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hypervisor: Vec<String>,
}

impl VmSpec {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
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
    #[error("invalid session `{0}`: pid@start")]
    Session(String),
    #[error("invalid label `{0}`: key=value")]
    Label(String),
    #[error("rule `{0}` has no conditions: it would match every connection")]
    NoConditions(String),
}

const fn yes() -> bool {
    true
}

/// A pattern as written: `glob:`, `re:` or exact.
#[must_use]
pub fn pattern(text: &str) -> PatternSource {
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
        if !self.session.is_empty() {
            let roots = self
                .session
                .iter()
                .map(|s| s.parse().map_err(|()| SpecError::Session(s.clone())))
                .collect::<Result<_, _>>()?;
            conditions.push(Condition::Session(roots));
        }
        self.identity_conditions(&mut conditions)?;
        Ok(conditions)
    }

    /// The conditions on a container's, a VM's or a namespace's identity.
    fn identity_conditions(&self, conditions: &mut Vec<Condition>) -> Result<(), SpecError> {
        let patterns = |texts: &[String]| texts.iter().map(|t| pattern(t)).collect::<Vec<_>>();
        let c = &self.container;
        if !c.name.is_empty() {
            conditions.push(Condition::ContainerName(patterns(&c.name)));
        }
        if !c.image.is_empty() {
            conditions.push(Condition::ContainerImage(patterns(&c.image)));
        }
        if !c.compose.is_empty() {
            conditions.push(Condition::ContainerCompose(patterns(&c.compose)));
        }
        if !c.label.is_empty() {
            let labels = c
                .label
                .iter()
                .map(|l| {
                    let (key, value) = l
                        .split_once('=')
                        .ok_or_else(|| SpecError::Label(l.clone()))?;
                    Ok((key.to_owned(), pattern(value)))
                })
                .collect::<Result<_, SpecError>>()?;
            conditions.push(Condition::ContainerLabel(labels));
        }
        if !c.runtime.is_empty() {
            conditions.push(Condition::ContainerRuntime(c.runtime.clone()));
        }
        if !c.owner.is_empty() {
            conditions.push(Condition::ContainerOwner(c.owner.clone()));
        }
        if !c.id.is_empty() {
            conditions.push(Condition::ContainerId(c.id.clone()));
        }
        if !self.vm.name.is_empty() {
            conditions.push(Condition::VmName(patterns(&self.vm.name)));
        }
        if !self.vm.uuid.is_empty() {
            conditions.push(Condition::VmUuid(self.vm.uuid.clone()));
        }
        if !self.vm.hypervisor.is_empty() {
            conditions.push(Condition::VmHypervisor(self.vm.hypervisor.clone()));
        }
        if !self.netns.is_empty() {
            conditions.push(Condition::NetnsName(patterns(&self.netns)));
        }
        if !self.list.is_empty() {
            conditions.push(Condition::List(self.list.clone()));
        }
        if !self.sha256.is_empty() {
            conditions.push(Condition::Sha256(
                self.sha256.iter().map(|h| h.to_ascii_lowercase()).collect(),
            ));
        }
        if let Some(writable) = self.writable {
            conditions.push(Condition::Writable(writable));
        }
        Ok(())
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
                Condition::Session(roots) => {
                    spec.session.extend(roots.iter().map(ToString::to_string));
                }
                Condition::ContainerName(p) => {
                    spec.container.name.extend(p.iter().map(pattern_text));
                }
                Condition::ContainerImage(p) => {
                    spec.container.image.extend(p.iter().map(pattern_text));
                }
                Condition::ContainerCompose(p) => {
                    spec.container.compose.extend(p.iter().map(pattern_text));
                }
                Condition::ContainerLabel(labels) => spec.container.label.extend(
                    labels
                        .iter()
                        .map(|(k, v)| format!("{k}={}", pattern_text(v))),
                ),
                Condition::ContainerRuntime(r) => spec.container.runtime.extend(r.iter().cloned()),
                Condition::ContainerOwner(u) => spec.container.owner.extend(u),
                Condition::ContainerId(i) => spec.container.id.extend(i.iter().cloned()),
                Condition::VmName(p) => spec.vm.name.extend(p.iter().map(pattern_text)),
                Condition::VmUuid(u) => spec.vm.uuid.extend(u.iter().cloned()),
                Condition::VmHypervisor(h) => spec.vm.hypervisor.extend(h.iter().cloned()),
                Condition::NetnsName(p) => spec.netns.extend(p.iter().map(pattern_text)),
                Condition::List(names) => spec.list.extend(names.iter().cloned()),
                Condition::Sha256(hashes) => spec.sha256.extend(hashes.iter().cloned()),
                Condition::Writable(writable) => spec.writable = Some(*writable),
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

[[rule]]
name = "The shop's web service"
action = "allow"
exe = ["/usr/local/bin/node"]
host = ["api.example.com"]
container.compose = ["shop/web"]
container.image = ["glob:docker.io/library/node:*"]
container.label = ["tier=front"]

[[rule]]
name = "The test VM"
action = "allow"
vm.name = ["glob:test-*"]
host = ["example.com"]
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
        let web = file.rule[2].to_rule(3, None).unwrap();
        assert!(
            web.conditions
                .contains(&Condition::ContainerCompose(vec![PatternSource::Exact(
                    "shop/web".to_owned()
                )]))
        );
        assert!(web.conditions.contains(&Condition::ContainerLabel(vec![(
            "tier".to_owned(),
            PatternSource::Exact("front".to_owned())
        )])));
        let vm = file.rule[3].to_rule(4, None).unwrap();
        assert!(
            vm.conditions
                .contains(&Condition::VmName(vec![PatternSource::Glob(
                    "test-*".to_owned()
                )]))
        );
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
