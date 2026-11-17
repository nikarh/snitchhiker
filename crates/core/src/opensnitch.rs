//! Importing OpenSnitch's rules (`/etc/opensnitchd/rules/*.json`, its documented format) as a rule file.
//!
//! Each rule converts to one that matches exactly what OpenSnitch's matched, or is reported with the reason it can't:
//!
//! - `simple` operators compare whole values, case-insensitively unless `sensitive`; `regexp` ones match anywhere in
//!   the value (Go's `MatchString`); `network` ones match a CIDR range; `list` ones need all of theirs to hold, as
//!   Snitchhiker's conditions do.
//! - Host names compare without case in Snitchhiker anyway. Other case-insensitive values become `(?i)` regular
//!   expressions; unanchored regular expressions are wrapped so they still match anywhere.
//! - `precedence` rules go in the override tier; others in the normal one.
//! - Temporary rules (any `duration` but `always`) are left out: they were never meant to last.
//! - Operands Snitchhiker has no condition for (environment variables, interfaces, process ids, hashes, block lists)
//!   are reported, not approximated.
//!
//! OpenSnitch can't tell containers apart, so its rules matched their processes too. Imported rules apply to the host
//! only, as every Snitchhiker rule without a context condition does; the report says so.

use serde::Deserialize;

use crate::rule::{Action, Tier};
use crate::spec::{Conditions, FolderSpec, RuleFile, RuleSpec};

// OpenSnitch writes `null` for what a rule doesn't use (`"list": null` in every simple rule): `nullable` takes it as
// the default.
#[derive(Debug, Deserialize)]
struct Rule {
    name: String,
    #[serde(default = "yes", deserialize_with = "enabled")]
    enabled: bool,
    #[serde(default, deserialize_with = "nullable")]
    precedence: bool,
    action: String,
    #[serde(default, deserialize_with = "nullable")]
    duration: String,
    operator: Operator,
}

#[derive(Debug, Deserialize)]
struct Operator {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, deserialize_with = "nullable")]
    operand: String,
    #[serde(default, deserialize_with = "nullable")]
    data: String,
    #[serde(default, deserialize_with = "nullable")]
    sensitive: bool,
    #[serde(default, deserialize_with = "nullable")]
    list: Vec<Operator>,
}

const fn yes() -> bool {
    true
}

fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn enabled<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(true))
}

/// The import: the rules that convert, and why each other one doesn't.
#[derive(Debug, Default)]
pub struct Imported {
    pub file: RuleFile,
    /// (rule name or file, reason).
    pub skipped: Vec<(String, String)>,
}

/// Converts OpenSnitch rule files, given as (file name, JSON), into a rule file with a folder named `folder`.
#[must_use]
pub fn import(files: &[(String, String)], folder: &str) -> Imported {
    let mut imported = Imported {
        file: RuleFile {
            folder: Some(FolderSpec {
                name: folder.to_owned(),
                scope: Conditions::default(),
            }),
            rule: Vec::new(),
        },
        skipped: Vec::new(),
    };
    for (name, json) in files {
        let rule: Rule = match serde_json::from_str(json) {
            Ok(rule) => rule,
            Err(e) => {
                imported
                    .skipped
                    .push((name.clone(), format!("not an OpenSnitch rule: {e}")));
                continue;
            }
        };
        // A rule that converts but isn't valid (a regular expression Snitchhiker's engine doesn't take, say) is
        // reported like one that doesn't convert: one such rule mustn't make the whole import fail.
        match convert(&rule).and_then(|spec| valid(&spec).map(|()| spec)) {
            Ok(spec) => imported.file.rule.push(spec),
            Err(reason) => imported.skipped.push((rule.name, reason)),
        }
    }
    imported
}

/// Whether the rule is one the daemon takes: its conditions parse and its patterns compile (even when it is off).
fn valid(spec: &RuleSpec) -> Result<(), String> {
    let mut rule = spec.to_rule(0, None).map_err(|e| e.to_string())?;
    rule.enabled = true;
    crate::engine::RuleSet::compile(&[], &[rule])
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn convert(rule: &Rule) -> Result<RuleSpec, String> {
    if !(rule.duration.is_empty() || rule.duration == "always") {
        return Err(format!("a temporary rule ({})", rule.duration));
    }
    let action = match rule.action.as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        "reject" => Action::Reject,
        other => return Err(format!("unknown action `{other}`")),
    };
    let mut conditions = Conditions::default();
    let operators: Vec<&Operator> = if rule.operator.kind == "list" {
        rule.operator.list.iter().collect()
    } else {
        vec![&rule.operator]
    };
    for operator in operators {
        add(&mut conditions, operator)?;
    }
    if conditions == Conditions::default() {
        return Err("it matches every connection".to_owned());
    }
    Ok(RuleSpec {
        name: rule.name.clone(),
        action,
        tier: if rule.precedence {
            Tier::Override
        } else {
            Tier::Normal
        },
        enabled: rule.enabled,
        notes: "Imported from OpenSnitch".to_owned(),
        conditions,
    })
}

/// A regular expression matching what OpenSnitch's `regexp` matched: anywhere in the value, unless anchored.
fn unanchored(regex: &str, sensitive: bool) -> String {
    let anchored = regex.starts_with('^') && regex.ends_with('$') && !regex.ends_with("\\$");
    let body = if anchored {
        regex.to_owned()
    } else {
        format!(".*(?:{regex}).*")
    };
    if sensitive {
        format!("re:{body}")
    } else {
        format!("re:(?i){body}")
    }
}

/// A pattern matching what OpenSnitch's `simple` or `regexp` operator matched, for a text value.
fn text_pattern(operator: &Operator) -> Result<String, String> {
    match operator.kind.as_str() {
        "simple" if operator.sensitive => Ok(operator.data.clone()),
        "simple" => Ok(format!("re:(?i){}", regex_escape(&operator.data))),
        "regexp" => Ok(unanchored(&operator.data, operator.sensitive)),
        other => Err(format!("`{other}` on {}", operator.operand)),
    }
}

fn regex_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// Adds one operator's condition; two on the same operand would need both to hold, which Snitchhiker's lists can't say.
fn add(conditions: &mut Conditions, operator: &Operator) -> Result<(), String> {
    let once = |values: &Vec<String>| {
        if values.is_empty() {
            Ok(())
        } else {
            Err(format!("two conditions on {}", operator.operand))
        }
    };
    let simple = operator.kind == "simple";
    match operator.operand.as_str() {
        "process.path" => {
            once(&conditions.exe)?;
            conditions.exe.push(text_pattern(operator)?);
        }
        "process.command" => {
            once(&conditions.cmdline)?;
            conditions.cmdline.push(text_pattern(operator)?);
        }
        "process.parent.path" => {
            once(&conditions.parent)?;
            conditions.parent.push(text_pattern(operator)?);
        }
        "dest.host" => {
            once(&conditions.host)?;
            conditions.host.push(match operator.kind.as_str() {
                "simple" => operator.data.trim_end_matches('.').to_ascii_lowercase(),
                // Host names match without case anyway.
                "regexp" => unanchored(&operator.data, true),
                other => return Err(format!("`{other}` on dest.host")),
            });
        }
        // An address, a network, or a range that is exactly one network (`127.0.0.0-127.255.255.255`, as
        // OpenSnitch's own rules write loopback).
        "dest.ip" | "dest.network" if simple || operator.kind == "network" => {
            once(&conditions.net)?;
            conditions.net.push(
                crate::system::parse_network(&operator.data)
                    .map_err(|e| format!("{}: {e}", operator.operand))?
                    .to_string(),
            );
        }
        "dest.port" if simple => {
            once(&conditions.port)?;
            conditions.port.push(operator.data.clone());
        }
        "user.id" if simple => {
            if !conditions.uid.is_empty() {
                return Err("two conditions on user.id".to_owned());
            }
            conditions.uid.push(
                operator
                    .data
                    .parse()
                    .map_err(|_| format!("user.id `{}` isn't a number", operator.data))?,
            );
        }
        "protocol" if simple => {
            once(&conditions.protocol)?;
            let protocol = match operator.data.to_ascii_lowercase().as_str() {
                "tcp" | "tcp6" => "tcp",
                "udp" | "udp6" => "udp",
                "icmp" => "icmp",
                "icmp6" | "icmpv6" => "icmpv6",
                other => return Err(format!("protocol `{other}`")),
            };
            conditions.protocol.push(protocol.to_owned());
        }
        operand => {
            return Err(format!(
                "Snitchhiker has no condition for `{}` on {operand}",
                operator.kind
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(json: &str) -> Imported {
        import(&[("rule.json".to_owned(), json.to_owned())], "OpenSnitch")
    }

    #[test]
    fn a_list_rule_converts_exactly() {
        let imported = one(
            r#"{"name": "allow-curl-example", "enabled": true, "precedence": true, "action": "allow",
                "duration": "always", "operator": {"type": "list", "operand": "list", "list": [
                  {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl", "sensitive": true},
                  {"type": "regexp", "operand": "dest.host", "data": "^(.*\\.)?example\\.com$"},
                  {"type": "simple", "operand": "dest.port", "data": "443"},
                  {"type": "simple", "operand": "user.id", "data": "1000"},
                  {"type": "simple", "operand": "protocol", "data": "tcp6"}]}}"#,
        );
        assert!(imported.skipped.is_empty(), "{:?}", imported.skipped);
        let rule = &imported.file.rule[0];
        assert_eq!(rule.tier, Tier::Override);
        assert_eq!(rule.conditions.exe, vec!["/usr/bin/curl"]);
        assert_eq!(rule.conditions.host, vec![r"re:^(.*\.)?example\.com$"]);
        assert_eq!(rule.conditions.port, vec!["443"]);
        assert_eq!(rule.conditions.uid, vec![1000]);
        assert_eq!(rule.conditions.protocol, vec!["tcp"]);
        // And it is a valid rule.
        assert!(rule.to_rule(0, None).is_ok());
    }

    #[test]
    fn case_and_anchoring_keep_their_meaning() {
        let imported = one(r#"{"name": "a", "action": "deny", "duration": "always",
                "operator": {"type": "simple", "operand": "process.path", "data": "/opt/App.bin"}}"#);
        assert_eq!(
            imported.file.rule[0].conditions.exe,
            vec![r"re:(?i)/opt/App\.bin"]
        );
        let imported = one(r#"{"name": "b", "action": "deny", "duration": "always",
                "operator": {"type": "regexp", "operand": "process.command", "data": "--remote-debugging", "sensitive": true}}"#);
        assert_eq!(
            imported.file.rule[0].conditions.cmdline,
            vec!["re:.*(?:--remote-debugging).*"]
        );
    }

    #[test]
    fn what_cant_be_expressed_is_reported() {
        let imported = import(
            &[
                (
                    "temp.json".to_owned(),
                    r#"{"name": "temp", "action": "allow", "duration": "30m",
                        "operator": {"type": "simple", "operand": "dest.port", "data": "80"}}"#
                        .to_owned(),
                ),
                (
                    "env.json".to_owned(),
                    r#"{"name": "env", "action": "allow", "duration": "always",
                        "operator": {"type": "simple", "operand": "process.env.FOO", "data": "1"}}"#
                        .to_owned(),
                ),
                ("broken.json".to_owned(), "{".to_owned()),
            ],
            "OpenSnitch",
        );
        assert_eq!(imported.file.rule, Vec::new());
        let names: Vec<&str> = imported.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["temp", "env", "broken.json"]);
    }

    #[test]
    fn rules_as_opensnitch_writes_them_convert() {
        // As the daemon and its UI save a rule: every field there, unused ones null.
        let imported = one(
            r#"{"created": "2026-06-15T12:05:41+03:00", "updated": "2026-06-15T12:05:41+03:00",
                "name": "allow-always-192-168-0-1-53-0", "description": "", "enabled": true,
                "precedence": false, "nolog": false, "action": "allow", "duration": "always",
                "operator": {"operand": "list", "data": "[{\"type\": \"simple\", \"operand\": \"dest.ip\"}]",
                  "type": "list", "list": [
                    {"operand": "dest.ip", "data": "192.168.0.1", "type": "simple", "list": null, "sensitive": false},
                    {"operand": "dest.port", "data": "53", "type": "simple", "list": null, "sensitive": false},
                    {"operand": "user.id", "data": "0", "type": "simple", "list": null, "sensitive": false}],
                  "sensitive": false}}"#,
        );
        assert!(imported.skipped.is_empty(), "{:?}", imported.skipped);
        assert_eq!(imported.file.rule[0].conditions.net, vec!["192.168.0.1/32"]);
    }

    #[test]
    fn ranges_convert_and_invalid_rules_are_reported_not_fatal() {
        let imported = import(
            &[
                (
                    "loopback.json".to_owned(),
                    r#"{"name": "loopback", "action": "allow", "duration": "always",
                        "operator": {"type": "network", "operand": "dest.network", "data": "127.0.0.0-127.255.255.255"}}"#
                        .to_owned(),
                ),
                (
                    "lookahead.json".to_owned(),
                    r#"{"name": "lookahead", "action": "allow", "duration": "always",
                        "operator": {"type": "regexp", "operand": "process.path", "data": "^/usr/(?!bin)", "sensitive": true}}"#
                        .to_owned(),
                ),
                (
                    "ip.json".to_owned(),
                    r#"{"name": "ip", "action": "allow", "duration": "always",
                        "operator": {"type": "simple", "operand": "dest.ip", "data": "192.168.0.1"}}"#
                        .to_owned(),
                ),
            ],
            "OpenSnitch",
        );
        let names: Vec<&str> = imported.file.rule.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["loopback", "ip"]);
        assert_eq!(imported.file.rule[0].conditions.net, vec!["127.0.0.0/8"]);
        assert_eq!(imported.file.rule[1].conditions.net, vec!["192.168.0.1/32"]);
        let skipped: Vec<&str> = imported.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, vec!["lookahead"]);
    }
}
