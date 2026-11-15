//! Between the wire messages and the core model. Rules travel in the shape of rule files (`spec`), so a rule a client
//! sends is checked exactly like a rule in a file.

use std::net::IpAddr;

use snitchhiker_core::rule::{Action, ContextKind, Expiry, Folder, Rule, Tier};
use snitchhiker_core::spec::{Conditions, RuleSpec, SpecError};

use crate::v1;

#[must_use]
pub fn action(action: Action) -> v1::Action {
    match action {
        Action::Allow => v1::Action::Allow,
        Action::Deny => v1::Action::Deny,
        Action::Reject => v1::Action::Reject,
    }
}

/// `None` for unspecified.
#[must_use]
pub fn action_from(action: v1::Action) -> Option<Action> {
    match action {
        v1::Action::Allow => Some(Action::Allow),
        v1::Action::Deny => Some(Action::Deny),
        v1::Action::Reject => Some(Action::Reject),
        v1::Action::Unspecified => None,
    }
}

#[must_use]
pub fn tier(tier: Tier) -> v1::Tier {
    match tier {
        Tier::Fallback => v1::Tier::Fallback,
        Tier::Normal => v1::Tier::Normal,
        Tier::Override => v1::Tier::Override,
    }
}

#[must_use]
pub fn tier_from(tier: v1::Tier) -> Tier {
    match tier {
        v1::Tier::Fallback => Tier::Fallback,
        v1::Tier::Override => Tier::Override,
        v1::Tier::Normal | v1::Tier::Unspecified => Tier::Normal,
    }
}

#[must_use]
pub fn context(context: ContextKind) -> v1::Context {
    match context {
        ContextKind::Host => v1::Context::Host,
        ContextKind::Container => v1::Context::Container,
        ContextKind::Vm => v1::Context::Vm,
        ContextKind::Netns => v1::Context::Netns,
        ContextKind::Any => v1::Context::Any,
    }
}

#[must_use]
pub fn context_from(context: v1::Context) -> Option<ContextKind> {
    match context {
        v1::Context::Host => Some(ContextKind::Host),
        v1::Context::Container => Some(ContextKind::Container),
        v1::Context::Vm => Some(ContextKind::Vm),
        v1::Context::Netns => Some(ContextKind::Netns),
        v1::Context::Any => Some(ContextKind::Any),
        v1::Context::Unspecified => None,
    }
}

#[must_use]
pub fn conditions(spec: &Conditions) -> v1::Conditions {
    v1::Conditions {
        exe: spec.exe.clone(),
        app: spec.app.clone(),
        cmdline: spec.cmdline.clone(),
        parent: spec.parent.clone(),
        uid: spec.uid.clone(),
        host: spec.host.clone(),
        net: spec.net.clone(),
        port: spec.port.clone(),
        protocol: spec.protocol.clone(),
        context: spec
            .context
            .map_or(v1::Context::Unspecified, context)
            .into(),
    }
}

#[must_use]
pub fn conditions_from(wire: &v1::Conditions) -> Conditions {
    Conditions {
        exe: wire.exe.clone(),
        app: wire.app.clone(),
        cmdline: wire.cmdline.clone(),
        parent: wire.parent.clone(),
        uid: wire.uid.clone(),
        host: wire.host.clone(),
        net: wire.net.clone(),
        port: wire.port.clone(),
        protocol: wire.protocol.clone(),
        context: context_from(wire.context()),
    }
}

/// A rule for the wire; `locked` for default and managed rules.
#[must_use]
pub fn rule(rule: &Rule, locked: bool) -> v1::Rule {
    let spec = RuleSpec::from_rule(rule);
    v1::Rule {
        id: rule.id,
        folder: rule.folder,
        name: rule.name.clone(),
        enabled: rule.enabled,
        action: action(rule.action).into(),
        tier: tier(rule.tier).into(),
        notes: rule.notes.clone(),
        conditions: Some(conditions(&spec.conditions)),
        locked,
        expires_ms: match rule.expiry {
            Expiry::At(at) => Some(at),
            Expiry::Never | Expiry::UntilRestart => None,
        },
        until_restart: rule.expiry == Expiry::UntilRestart,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("the rule has no action")]
    NoAction,
    #[error(transparent)]
    Spec(#[from] SpecError),
}

/// A rule from the wire, checked like a rule in a file. Its id is the wire's (the node replaces it when adding).
pub fn rule_from(wire: &v1::Rule) -> Result<Rule, RuleError> {
    let spec = RuleSpec {
        name: wire.name.clone(),
        action: action_from(wire.action()).ok_or(RuleError::NoAction)?,
        tier: tier_from(wire.tier()),
        enabled: wire.enabled,
        notes: wire.notes.clone(),
        conditions: wire
            .conditions
            .as_ref()
            .map_or_else(Conditions::default, conditions_from),
    };
    let mut rule = spec.to_rule(wire.id, wire.folder)?;
    rule.expiry = match (wire.until_restart, wire.expires_ms) {
        (true, _) => Expiry::UntilRestart,
        (false, Some(at)) => Expiry::At(at),
        (false, None) => Expiry::Never,
    };
    Ok(rule)
}

#[must_use]
pub fn folder(folder: &Folder, locked: bool) -> v1::Folder {
    v1::Folder {
        id: folder.id,
        parent: folder.parent,
        name: folder.name.clone(),
        enabled: folder.enabled,
        scope: Some(conditions(&Conditions::from_conditions(&folder.scope))),
        locked,
    }
}

/// An address for the wire: 4 bytes for IPv4, 16 for IPv6.
#[must_use]
pub fn address(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

#[must_use]
pub fn address_from(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from)
}

#[cfg(test)]
mod tests {
    use snitchhiker_core::spec::RuleFile;

    use super::*;

    #[test]
    fn rules_round_trip_through_the_wire() {
        let file: RuleFile = toml::from_str(
            "[[rule]]\nname = \"api\"\naction = \"reject\"\ntier = \"override\"\nexe = [\"glob:/usr/bin/*\"]\nhost = [\"*.example.com\"]\nport = [\"443\", \"8000-8080\"]\ncontext = \"any\"\n",
        )
        .unwrap();
        let mut original = file.rule[0].to_rule(7, Some(3)).unwrap();
        original.expiry = Expiry::At(1234);
        let back = rule_from(&rule(&original, false)).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn refuses_rules_without_action_or_conditions() {
        let wire = v1::Rule {
            name: "x".into(),
            conditions: Some(v1::Conditions {
                port: vec!["1".into()],
                ..v1::Conditions::default()
            }),
            ..v1::Rule::default()
        };
        assert_eq!(rule_from(&wire), Err(RuleError::NoAction));
        let wire = v1::Rule {
            name: "x".into(),
            action: v1::Action::Allow.into(),
            ..v1::Rule::default()
        };
        assert!(matches!(rule_from(&wire), Err(RuleError::Spec(_))));
    }

    #[test]
    fn addresses_keep_their_family() {
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(address(v4).len(), 4);
        assert_eq!(address_from(&address(v4)), Some(v4));
        assert_eq!(address_from(&address(v6)), Some(v6));
        assert_eq!(address_from(&[1, 2, 3]), None);
    }
}
