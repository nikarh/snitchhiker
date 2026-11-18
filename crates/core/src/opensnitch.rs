//! Importing OpenSnitch's rules (`/etc/opensnitchd/rules/*.json`, its documented format) as a rule file.
//!
//! Each rule converts to one that matches exactly what OpenSnitch's matched, or is reported with the reason it can't:
//!
//! - `simple` operators compare whole values, case-insensitively unless `sensitive`; `regexp` ones match anywhere in
//!   the value (Go's `MatchString`); `network` ones match a CIDR range; `list` ones need all of theirs to hold, as
//!   Snitchhiker's conditions do.
//! - Host names compare without case in Snitchhiker anyway. A `simple` path or command line is taken as the exact
//!   text even when not `sensitive` (OpenSnitch's UI writes every condition so; Linux's paths have case); case-
//!   insensitive regular expressions keep `(?i)`, and unanchored ones are wrapped so they still match anywhere.
//! - The patterns OpenSnitch's UI writes become Snitchhiker's own forms: `^(|.*\.)example\.com$` the host names
//!   `example.com` and `*.example.com`; a list of names `^(a.example.com|b.example.com)$` those names; a list of addresses `^(10.1.1.5|10.1.1.6)$` those addresses; an address's first
//!   numbers and `.*` (`192\.168\.1\..*`) their network. Such a pattern without anchors is taken as meant: anchored.
//! - The same condition twice (OpenSnitch's UI writes some so) counts once.
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

/// A pattern matching what OpenSnitch's `simple` or `regexp` operator matched, for a text value. A `simple` one is
/// the exact text even when not `sensitive`: OpenSnitch's UI writes every condition so, and Linux paths and command
/// lines have case.
fn text_pattern(operator: &Operator) -> Result<String, String> {
    match operator.kind.as_str() {
        "simple" => Ok(operator.data.clone()),
        "regexp" => Ok(unanchored(&operator.data, operator.sensitive)),
        other => Err(format!("`{other}` on {}", operator.operand)),
    }
}

/// Puts one operator's values into a condition. Two operators on the same operand both have to hold, which a list
/// (any of its values) can't say, unless they allow the same values: OpenSnitch's UI writes some conditions twice.
fn put<T: PartialEq>(field: &mut Vec<T>, values: Vec<T>, operand: &str) -> Result<(), String> {
    if field.is_empty() {
        *field = values;
        Ok(())
    } else if field.len() == values.len() && values.iter().all(|v| field.contains(v)) {
        Ok(())
    } else {
        Err(format!("two different conditions on {operand}"))
    }
}

/// Adds one operator's condition.
fn add(conditions: &mut Conditions, operator: &Operator) -> Result<(), String> {
    let simple = operator.kind == "simple";
    let operand = operator.operand.as_str();
    match operand {
        "process.path" => put(&mut conditions.exe, vec![text_pattern(operator)?], operand)?,
        "process.command" => put(
            &mut conditions.cmdline,
            vec![text_pattern(operator)?],
            operand,
        )?,
        "process.parent.path" => {
            put(
                &mut conditions.parent,
                vec![text_pattern(operator)?],
                operand,
            )?;
        }
        "dest.host" => {
            let hosts = match operator.kind.as_str() {
                "simple" => vec![operator.data.trim_end_matches('.').to_ascii_lowercase()],
                // Host names match without case anyway.
                "regexp" => host_shape(&operator.data)
                    .unwrap_or_else(|| vec![unanchored(&operator.data, true)]),
                other => return Err(format!("`{other}` on dest.host")),
            };
            put(&mut conditions.host, hosts, operand)?;
        }
        // An address, a network, or a range that is exactly one network (`127.0.0.0-127.255.255.255`, as
        // OpenSnitch's own rules write loopback).
        "dest.ip" | "dest.network" if simple || operator.kind == "network" => {
            let net = crate::system::parse_network(&operator.data)
                .map_err(|e| format!("{operand}: {e}"))?
                .to_string();
            put(&mut conditions.net, vec![net], operand)?;
        }
        "dest.ip" | "dest.network" if operator.kind == "regexp" => {
            let nets = address_shape(&operator.data).ok_or_else(|| {
                format!(
                    "{operand} `{}` is neither a list of addresses nor an address's first numbers followed by `.*`",
                    operator.data
                )
            })?;
            put(&mut conditions.net, nets, operand)?;
        }
        "dest.port" if simple => put(&mut conditions.port, vec![operator.data.clone()], operand)?,
        "user.id" if simple => {
            let uid = operator
                .data
                .parse()
                .map_err(|_| format!("user.id `{}` isn't a number", operator.data))?;
            put(&mut conditions.uid, vec![uid], operand)?;
        }
        "protocol" if simple => {
            let protocol = match operator.data.to_ascii_lowercase().as_str() {
                "tcp" | "tcp6" => "tcp",
                "udp" | "udp6" => "udp",
                "icmp" => "icmp",
                "icmp6" | "icmpv6" => "icmpv6",
                other => return Err(format!("protocol `{other}`")),
            };
            put(&mut conditions.protocol, vec![protocol.to_owned()], operand)?;
        }
        "source.ip" | "source.network" | "source.port" => {
            let loopback = operator
                .data
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
            return Err(if loopback {
                "Snitchhiker doesn't match on the connection's local address; connections to loopback are allowed \
                 by the System folder's Loopback rule"
                    .to_owned()
            } else {
                format!("Snitchhiker doesn't match on the connection's local address ({operand})")
            });
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

/// The pattern without OpenSnitch's anchors. Patterns of the shapes below that lack them are taken as anchored: an
/// unanchored `172\.18\..*` also matched `10.172.18.1`, which no one meant.
fn strip_anchors(regex: &str) -> &str {
    let regex = regex.strip_prefix('^').unwrap_or(regex);
    match regex.strip_suffix('$') {
        Some(rest) if !rest.ends_with('\\') => rest,
        _ => regex,
    }
}

/// Literal text of a pattern made of letters, digits, `-`, `_`, `:` and dots (`\.`, or `.` meant as one); `None` for
/// anything else.
fn literal(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.next()? == '.' => out.push('.'),
            '.' => out.push('.'),
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':') => out.push(c),
            _ => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The host names of a `dest.host` pattern OpenSnitch's UI writes: `^(|.*\.)example\.com$` (the name and its
/// subdomains), `^(.*\.)?example\.com$`, `^.*\.example\.com$` (subdomains only), `^example\.com$`, or a list of
/// names, `^(a.example.com|b.example.com)$`.
fn host_shape(regex: &str) -> Option<Vec<String>> {
    let body = strip_anchors(regex);
    if let Some(names) = body.strip_prefix('(').and_then(|b| b.strip_suffix(')'))
        && !names.contains('(')
        && names.split('|').all(|name| !name.is_empty())
    {
        let mut hosts: Vec<String> = Vec::new();
        for name in names.split('|') {
            for host in one_host(name)? {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        return Some(hosts);
    }
    one_host(body)
}

fn one_host(body: &str) -> Option<Vec<String>> {
    let (apex, subdomains, name) = if let Some(name) = body
        .strip_prefix("(|.*\\.)")
        .or_else(|| body.strip_prefix("(.*\\.|)"))
        .or_else(|| body.strip_prefix("(.*\\.)?"))
    {
        (true, true, name)
    } else if let Some(name) = body.strip_prefix(".*\\.") {
        (false, true, name)
    } else {
        (true, false, body)
    };
    let name = literal(name)?.to_ascii_lowercase();
    if name.contains(':') || name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return None;
    }
    let mut hosts = Vec::new();
    if apex {
        hosts.push(name.clone());
    }
    if subdomains {
        hosts.push(format!("*.{name}"));
    }
    Some(hosts)
}

/// The networks of a `dest.ip` pattern of the shapes people write: a list of addresses, `^(10.1.1.5|10.1.1.6)$`, or
/// an IPv4 address's first numbers followed by anything, `192\.168\.1\..*` (`192.168.1.0/24`).
fn address_shape(regex: &str) -> Option<Vec<String>> {
    let body = strip_anchors(regex);
    for any in [".*", ".+", "\\d+", "[0-9]+", "\\d{1,3}", "[0-9]{1,3}"] {
        if let Some(prefix) = body.strip_suffix(any) {
            let prefix = literal(prefix)?;
            let octets: Vec<u8> = prefix
                .strip_suffix('.')?
                .split('.')
                .map(|octet| octet.parse().ok())
                .collect::<Option<_>>()?;
            if octets.is_empty() || octets.len() > 3 {
                return None;
            }
            let mut address = [0u8; 4];
            for (slot, octet) in address.iter_mut().zip(&octets) {
                *slot = *octet;
            }
            let length = u8::try_from(octets.len() * 8).ok()?;
            let net = ipnet::Ipv4Net::new(address.into(), length).ok()?;
            return Some(vec![net.to_string()]);
        }
    }
    let body = body
        .strip_prefix('(')
        .and_then(|b| b.strip_suffix(')'))
        .unwrap_or(body);
    let mut nets: Vec<String> = Vec::new();
    for alternative in body.split('|') {
        let address: std::net::IpAddr = literal(alternative)?.parse().ok()?;
        let net = ipnet::IpNet::from(address).to_string();
        if !nets.contains(&net) {
            nets.push(net);
        }
    }
    Some(nets)
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
        assert_eq!(rule.conditions.host, vec!["example.com", "*.example.com"]);
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
        assert_eq!(imported.file.rule[0].conditions.exe, vec!["/opt/App.bin"]);
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

    fn list(name: &str, operators: &str) -> String {
        format!(
            r#"{{"name": "{name}", "action": "allow", "duration": "always",
                "operator": {{"type": "list", "operand": "list", "list": [{operators}]}}}}"#
        )
    }

    #[test]
    fn opensnitchs_own_patterns_become_snitchhikers_forms() {
        let rule = |name: &str, operators: &str| (format!("{name}.json"), list(name, operators));
        let imported = import(
            &[
                rule(
                    "domain",
                    r#"{"type": "regexp", "operand": "dest.host", "data": "^(|.*\\.)us\\.sentry\\.io$"},
                       {"type": "simple", "operand": "dest.port", "data": "443"},
                       {"type": "regexp", "operand": "dest.host", "data": "^(|.*\\.)us\\.sentry\\.io$"}"#,
                ),
                rule(
                    "subdomains",
                    r#"{"type": "regexp", "operand": "dest.host", "data": ".*\\.Example\\.com"}"#,
                ),
                rule(
                    "names",
                    r#"{"type": "regexp", "operand": "dest.host", "data": "^(time.cloudflare.com|0.arch.pool.ntp.org)$"}"#,
                ),
                rule(
                    "prefix",
                    r#"{"type": "regexp", "operand": "dest.ip", "data": "172\\.18\\..*"},
                       {"type": "simple", "operand": "process.path", "data": "/usr/bin/docker-proxy", "sensitive": true}"#,
                ),
                rule(
                    "addresses",
                    r#"{"type": "regexp", "operand": "dest.ip", "data": "^(10.1.1.176|10.9.1.76|10.9.1.76)$"}"#,
                ),
                rule(
                    "other",
                    r#"{"type": "regexp", "operand": "dest.ip", "data": "^10\\.[0-5]\\..*"}"#,
                ),
                rule(
                    "different",
                    r#"{"type": "simple", "operand": "dest.host", "data": "a.com"},
                       {"type": "simple", "operand": "dest.host", "data": "b.com"}"#,
                ),
                rule(
                    "source",
                    r#"{"type": "simple", "operand": "source.ip", "data": "127.0.0.1"},
                       {"type": "simple", "operand": "dest.ip", "data": "127.0.0.1"}"#,
                ),
            ],
            "OpenSnitch",
        );
        let conditions: Vec<(&str, &Conditions)> = imported
            .file
            .rule
            .iter()
            .map(|r| (r.name.as_str(), &r.conditions))
            .collect();
        let [
            ("domain", domain),
            ("subdomains", subdomains),
            ("names", names),
            ("prefix", prefix),
            ("addresses", addresses),
        ] = conditions.as_slice()
        else {
            panic!("{conditions:?} {:?}", imported.skipped);
        };
        assert_eq!(domain.host, vec!["us.sentry.io", "*.us.sentry.io"]);
        assert_eq!(subdomains.host, vec!["*.example.com"]);
        assert_eq!(
            names.host,
            vec!["time.cloudflare.com", "0.arch.pool.ntp.org"]
        );
        assert_eq!(prefix.net, vec!["172.18.0.0/16"]);
        assert_eq!(prefix.exe, vec!["/usr/bin/docker-proxy"]);
        assert_eq!(addresses.net, vec!["10.1.1.176/32", "10.9.1.76/32"]);
        let skipped: Vec<&str> = imported.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, vec!["other", "different", "source"]);
        assert!(imported.skipped[2].1.contains("Loopback rule"));
    }
}
