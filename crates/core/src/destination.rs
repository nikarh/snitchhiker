//! Destinations in rules: host name patterns, and networks (CIDR ranges and named aliases).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// A host name pattern: `example.com` (that name only), `*.example.com` (any name under it, at any depth, but not
/// `example.com` itself), or `re:<regular expression>` matched against the whole name. Names compare
/// case-insensitively, without a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum HostPattern {
    Exact(String),
    /// The suffix, with its leading dot: `.example.com`.
    Subdomains(String),
    /// A regular expression over the whole name, as written (without `re:`); the engine compiles it.
    Regex(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid host pattern `{0}`: a name, `*.` and a name, or `re:` and a regular expression")]
pub struct HostPatternError(String);

impl HostPattern {
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host);
        match self {
            Self::Exact(name) => host.eq_ignore_ascii_case(name),
            Self::Subdomains(suffix) => {
                host.len() > suffix.len()
                    && host
                        .get(host.len() - suffix.len()..)
                        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
            }
            // Compiled and matched by the engine; uncompiled, a regular expression matches nothing.
            Self::Regex(_) => false,
        }
    }

    /// Exact names are more specific than wildcards; longer suffixes more than shorter ones.
    #[must_use]
    pub fn specificity(&self) -> u32 {
        match self {
            Self::Exact(_) => 1000,
            Self::Subdomains(suffix) => u32::try_from(suffix.matches('.').count()).unwrap_or(0),
            Self::Regex(_) => 0,
        }
    }
}

impl TryFrom<String> for HostPattern {
    type Error = HostPatternError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if let Some(regex) = text.strip_prefix("re:") {
            return regex::Regex::new(regex)
                .map(|_| Self::Regex(regex.to_owned()))
                .map_err(|_| HostPatternError(text));
        }
        let trimmed = text.trim().trim_end_matches('.').to_ascii_lowercase();
        let (wildcard, name) = match trimmed.strip_prefix("*.") {
            Some(name) => (true, name),
            None => (false, trimmed.as_str()),
        };
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid {
            return Err(HostPatternError(text));
        }
        Ok(if wildcard {
            Self::Subdomains(format!(".{name}"))
        } else {
            Self::Exact(name.to_owned())
        })
    }
}

impl From<HostPattern> for String {
    fn from(pattern: HostPattern) -> Self {
        pattern.to_string()
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => f.write_str(name),
            Self::Subdomains(suffix) => write!(f, "*{suffix}"),
            Self::Regex(regex) => write!(f, "re:{regex}"),
        }
    }
}

/// Named sets of networks usable wherever a network is.
pub const ALIASES: &[(&str, &[&str])] = &[
    ("loopback", &["127.0.0.0/8", "::1/128"]),
    (
        "lan",
        &[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "fc00::/7",
            "fe80::/10",
        ],
    ),
    ("multicast", &["224.0.0.0/4", "ff00::/8"]),
    ("imds", &["169.254.169.254/32", "fd00:ec2::254/128"]),
    ("cgnat", &["100.64.0.0/10"]),
];

/// A network in a rule: a CIDR range (a bare address is a /32 or /128), or an alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Network {
    Net(IpNet),
    /// An index into [`ALIASES`].
    Alias(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid network `{0}`: an address, a CIDR range, or one of the aliases")]
pub struct NetworkError(String);

impl Network {
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match self {
            Self::Net(net) => net.contains(&address),
            Self::Alias(index) => ALIASES.get(*index).is_some_and(|(_, nets)| {
                nets.iter()
                    .any(|net| IpNet::from_str(net).is_ok_and(|net: IpNet| net.contains(&address)))
            }),
        }
    }

    /// Longer prefixes are more specific; aliases count as broad.
    #[must_use]
    pub fn specificity(&self) -> u32 {
        match self {
            Self::Net(net) => u32::from(net.prefix_len()),
            Self::Alias(_) => 1,
        }
    }
}

impl TryFrom<String> for Network {
    type Error = NetworkError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let trimmed = text.trim();
        if let Some(index) = ALIASES.iter().position(|(alias, _)| *alias == trimmed) {
            return Ok(Self::Alias(index));
        }
        if let Ok(net) = IpNet::from_str(trimmed) {
            return Ok(Self::Net(net.trunc()));
        }
        if let Ok(address) = IpAddr::from_str(trimmed) {
            return Ok(Self::Net(IpNet::from(address)));
        }
        Err(NetworkError(text))
    }
}

impl From<Network> for String {
    fn from(network: Network) -> Self {
        network.to_string()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Net(net) => write!(f, "{net}"),
            Self::Alias(index) => f.write_str(ALIASES.get(*index).map_or("?", |(name, _)| name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(text: &str) -> HostPattern {
        HostPattern::try_from(text.to_owned()).unwrap()
    }

    #[test]
    fn exact_hosts_match_only_themselves() {
        let pattern = host("Example.COM.");
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("EXAMPLE.com."));
        assert!(!pattern.matches("www.example.com"));
    }

    #[test]
    fn wildcards_match_subdomains_but_not_the_name_itself() {
        let pattern = host("*.example.com");
        assert!(pattern.matches("api.example.com"));
        assert!(pattern.matches("a.b.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("badexample.com"));
    }

    #[test]
    fn rejects_invalid_host_patterns() {
        for bad in ["", "*.", "a..b", "exa mple.com", "*.*.com", "a/b"] {
            assert!(HostPattern::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn networks_and_aliases() {
        let net = Network::try_from("192.0.2.0/24".to_owned()).unwrap();
        assert!(net.contains("192.0.2.77".parse().unwrap()));
        assert!(!net.contains("192.0.3.1".parse().unwrap()));
        let single = Network::try_from("2001:db8::1".to_owned()).unwrap();
        assert!(single.contains("2001:db8::1".parse().unwrap()));
        assert_eq!(single.specificity(), 128);
        let lan = Network::try_from("lan".to_owned()).unwrap();
        assert!(lan.contains("192.168.1.10".parse().unwrap()));
        assert!(lan.contains("fe80::1".parse().unwrap()));
        assert!(!lan.contains("198.51.100.1".parse().unwrap()));
        let imds = Network::try_from("imds".to_owned()).unwrap();
        assert!(imds.contains("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn serializes_as_written() {
        let json = serde_json::to_string(&(
            host("*.example.com"),
            Network::try_from("lan".to_owned()).unwrap(),
        ))
        .unwrap();
        assert_eq!(json, r#"["*.example.com","lan"]"#);
    }
}
