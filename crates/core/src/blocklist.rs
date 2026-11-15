//! Blocklists: sets of domains and address ranges read from list files, for the `list` condition.
//!
//! One format reader takes the common list formats, line by line:
//! - hosts files (`0.0.0.0 ads.example.com tracker.example.com`; the address is ignored);
//! - a domain per line (`ads.example.com`, `*.ads.example.com`);
//! - adblock domain rules (`||ads.example.com^`; anything with options or exceptions isn't a domain rule);
//! - addresses and networks (`192.0.2.1`, `198.51.100.0/24`, `2001:db8::/32`).
//!
//! `#` starts a comment anywhere, `!` and `[` at the start of a line. A domain matches itself and every name under
//! it, as DNS blockers treat them. Lookups don't allocate: domains are looked up by the name's suffixes, networks by
//! binary search over merged ranges.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

/// A list, ready to match.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Blocklist {
    domains: HashSet<Box<str>>,
    /// Inclusive, sorted, merged ranges.
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

/// What reading a list found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub list: Blocklist,
    /// Domains and networks read.
    pub entries: usize,
    /// Lines that are neither empty, a comment nor an entry.
    pub invalid: usize,
    /// The first of them, to say what the file looks like.
    pub first_invalid: Option<String>,
}

/// Names hosts files map to themselves, which aren't entries.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

impl Blocklist {
    /// Reads a list.
    #[must_use]
    pub fn parse(text: &str) -> Parsed {
        let mut parsed = Parsed::default();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let first = tokens.next().unwrap_or_default();
            let rest: Vec<&str> = tokens.collect();
            let ok = if rest.is_empty() {
                entry(first, &mut parsed.list.domains, &mut v4, &mut v6)
            } else if first.parse::<IpAddr>().is_ok() {
                // A hosts line: every name after the address.
                rest.iter().all(|name| {
                    LOCAL_NAMES.contains(name)
                        || domain(name).is_some_and(|d| {
                            parsed.list.domains.insert(d.into());
                            true
                        })
                })
            } else {
                false
            };
            if !ok {
                parsed.invalid += 1;
                if parsed.first_invalid.is_none() {
                    parsed.first_invalid = Some(line.chars().take(120).collect());
                }
            }
        }
        parsed.list.v4 = merge(v4);
        parsed.list.v6 = merge(v6);
        parsed.entries = parsed.list.domains.len() + parsed.list.v4.len() + parsed.list.v6.len();
        parsed
    }

    /// Whether the list has `host` or a domain above it.
    #[must_use]
    pub fn has_host(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.has_host(&host.to_ascii_lowercase());
        }
        let mut name = host;
        loop {
            if self.domains.contains(name) {
                return true;
            }
            match name.split_once('.') {
                Some((_, parent)) if !parent.is_empty() => name = parent,
                _ => return false,
            }
        }
    }

    /// Whether the list has an address or a network with it.
    #[must_use]
    pub fn has_address(&self, address: IpAddr) -> bool {
        match address.to_canonical() {
            IpAddr::V4(a) => within(&self.v4, u32::from(a)),
            IpAddr::V6(a) => within(&self.v6, u128::from(a)),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.v4.is_empty() && self.v6.is_empty()
    }
}

/// One entry on a line of its own.
fn entry(
    token: &str,
    domains: &mut HashSet<Box<str>>,
    v4: &mut Vec<(u32, u32)>,
    v6: &mut Vec<(u128, u128)>,
) -> bool {
    let net = if token.contains('/') {
        token.parse::<IpNet>().ok()
    } else {
        token.parse::<IpAddr>().ok().map(IpNet::from)
    };
    if let Some(net) = net {
        match net {
            IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()))),
            IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()))),
        }
        return true;
    }
    let name = token
        .strip_prefix("||")
        .and_then(|t| t.strip_suffix('^'))
        .or_else(|| token.strip_prefix("*."))
        .unwrap_or(token);
    if LOCAL_NAMES.contains(&name) {
        return true;
    }
    domain(name).is_some_and(|d| {
        domains.insert(d.into());
        true
    })
}

/// A domain name, lowercased; `None` if it isn't one.
fn domain(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then(|| name.to_ascii_lowercase())
}

fn merge<T: Ord + Copy + num_step::Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (low, high) in ranges {
        match merged.last_mut() {
            Some(last) if low <= last.1.next_or_max() => last.1 = last.1.max(high),
            _ => merged.push((low, high)),
        }
    }
    merged.shrink_to_fit();
    merged
}

fn within<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let after = ranges.partition_point(|&(low, _)| low <= value);
    after
        .checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|&(_, high)| value <= high)
}

mod num_step {
    pub trait Step {
        fn next_or_max(self) -> Self;
    }
    impl Step for u32 {
        fn next_or_max(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl Step for u128 {
        fn next_or_max(self) -> Self {
            self.saturating_add(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_common_formats_are_read() {
        let parsed = Blocklist::parse(
            "# StevenBlack-style hosts\n\
             127.0.0.1 localhost\n\
             0.0.0.0 0.0.0.0\n\
             0.0.0.0 ads.example.com tracker.example.net # inline\n\
             ! adblock comment\n\
             [Adblock Plus 2.0]\n\
             ||metrics.example.org^\n\
             ||cdn.example.org^$third-party\n\
             *.wild.example\n\
             Plain.Example.Com.\n\
             198.51.100.0/24\n\
             198.51.101.0/24\n\
             192.0.2.7\n\
             2001:db8::/32\n\
             <html>\n",
        );
        assert_eq!(parsed.invalid, 2);
        assert_eq!(
            parsed.first_invalid.as_deref(),
            Some("||cdn.example.org^$third-party")
        );
        let list = &parsed.list;
        assert!(list.has_host("ads.example.com"));
        assert!(list.has_host("x.ADS.example.com."));
        assert!(!list.has_host("example.com"));
        assert!(list.has_host("metrics.example.org"));
        assert!(list.has_host("a.wild.example"));
        assert!(list.has_host("plain.example.com"));
        assert!(!list.has_host("localhost"));
        // The two /24s merge into one range.
        assert_eq!(parsed.entries, 5 + 2 + 1);
        assert!(list.has_address("198.51.101.255".parse().unwrap()));
        assert!(!list.has_address("198.51.102.0".parse().unwrap()));
        assert!(list.has_address("192.0.2.7".parse().unwrap()));
        assert!(!list.has_address("192.0.2.8".parse().unwrap()));
        assert!(list.has_address("::ffff:192.0.2.7".parse().unwrap()));
        assert!(list.has_address("2001:db8::1".parse().unwrap()));
        assert!(!list.has_address("2001:db9::1".parse().unwrap()));
    }
}
