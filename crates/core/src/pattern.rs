//! Text patterns of rules: exact strings, globs and regular expressions, matched without allocating.
//!
//! A glob's `*` matches within one path component (no `/`), `**` across components, `?` one character, and
//! `{a,b,c}` any of the alternatives. A pattern may start with `{home}`, the home directory of the user whose process
//! is matched, so that one rule covers `{home}/.local/share/claude/versions/*/claude` for every user.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The placeholder for the matched user's home directory.
pub const HOME: &str = "{home}";

/// A pattern as written in a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum PatternSource {
    Exact(String),
    Glob(String),
    Regex(String),
}

impl fmt::Display for PatternSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(text) => write!(f, "{text}"),
            Self::Glob(text) => write!(f, "glob:{text}"),
            Self::Regex(text) => write!(f, "re:{text}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("unclosed `{{` in glob `{0}`")]
    UnclosedBrace(String),
    #[error("nested `{{` in glob `{0}`")]
    NestedBrace(String),
    #[error("invalid regular expression: {0}")]
    Regex(String),
}

/// A compiled pattern. Globs are translated to regular expressions: matching is linear in the value's length
/// whatever the pattern (the `regex` crate guarantees it), so a pattern can't be crafted to stall the daemon.
#[derive(Debug, Clone)]
pub enum Pattern {
    Exact { home: bool, text: String },
    Glob { home: bool, regex: regex::Regex },
    Regex(regex::Regex),
}

impl Pattern {
    pub fn compile(source: &PatternSource) -> Result<Self, PatternError> {
        match source {
            PatternSource::Exact(text) => {
                let (home, rest) = strip_home(text);
                Ok(Self::Exact {
                    home,
                    text: rest.to_owned(),
                })
            }
            PatternSource::Glob(text) => {
                let (home, rest) = strip_home(text);
                let regex = regex::Regex::new(&glob_to_regex(rest, text)?)
                    .map_err(|e| PatternError::Regex(e.to_string()))?;
                Ok(Self::Glob { home, regex })
            }
            PatternSource::Regex(text) => regex::Regex::new(&format!("^(?:{text})$"))
                .map(Self::Regex)
                .map_err(|e| PatternError::Regex(e.to_string())),
        }
    }

    /// Whether `value` matches. `home` is the matched user's home directory; a pattern starting with `{home}` never
    /// matches when it is unknown.
    #[must_use]
    pub fn matches(&self, value: &str, home: Option<&str>) -> bool {
        match self {
            Self::Exact { home: false, text } => value == text,
            Self::Exact { home: true, text } => {
                strip_prefix_home(value, home).is_some_and(|rest| rest == text)
            }
            Self::Glob { home: false, regex } | Self::Regex(regex) => regex.is_match(value),
            Self::Glob { home: true, regex } => {
                strip_prefix_home(value, home).is_some_and(|rest| regex.is_match(rest))
            }
        }
    }

    /// How specific the pattern is, for choosing among matching rules: exact beats glob beats regex.
    #[must_use]
    pub fn specificity(&self) -> u32 {
        match self {
            Self::Exact { .. } => 3,
            Self::Glob { .. } => 2,
            Self::Regex(_) => 1,
        }
    }

    /// The exact text this pattern matches, if it matches only one (without `{home}`): for indexing.
    #[must_use]
    pub fn exact(&self) -> Option<&str> {
        match self {
            Self::Exact { home: false, text } => Some(text),
            _ => None,
        }
    }
}

/// Whether `source` matches finitely many values (with `{home}`, finitely many in any one home): an exact text, a glob
/// without `*` (`?`, `[..]` and `{a,b}` choose among finitely many), a regular expression without unbounded
/// repetition (`(?i)/usr/bin/curl`, `/usr/bin/(curl|wget)`). Such a pattern names particular things; one that
/// isn't valid names nothing.
#[must_use]
pub fn finite(source: &PatternSource) -> bool {
    let regex = match source {
        PatternSource::Exact(_) => return true,
        PatternSource::Glob(text) => match glob_to_regex(strip_home(text).1, text) {
            Ok(regex) => regex,
            Err(_) => return false,
        },
        PatternSource::Regex(text) => text.clone(),
    };
    regex_syntax::Parser::new()
        .parse(&regex)
        .is_ok_and(|hir| finite_hir(&hir))
}

fn finite_hir(hir: &regex_syntax::hir::Hir) -> bool {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => true,
        HirKind::Repetition(repetition) => repetition.max.is_some() && finite_hir(&repetition.sub),
        HirKind::Capture(capture) => finite_hir(&capture.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => parts.iter().all(finite_hir),
    }
}

fn strip_home(text: &str) -> (bool, &str) {
    text.strip_prefix(HOME)
        .map_or((false, text), |rest| (true, rest))
}

fn strip_prefix_home<'a>(value: &'a str, home: Option<&str>) -> Option<&'a str> {
    let home = home?.trim_end_matches('/');
    if home.is_empty() {
        return None;
    }
    value.strip_prefix(home)
}

/// Translates a glob into an anchored regular expression.
fn glob_to_regex(glob: &str, whole: &str) -> Result<String, PatternError> {
    let mut out = String::from("^");
    let mut chars = glob.chars().peekable();
    let mut buffer = [0_u8; 4];
    while let Some(c) = chars.next() {
        match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                out.push_str(".*");
            }
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            '{' => {
                out.push_str("(?:");
                let mut closed = false;
                for c in chars.by_ref() {
                    match c {
                        '}' => {
                            closed = true;
                            break;
                        }
                        ',' => out.push('|'),
                        '{' => return Err(PatternError::NestedBrace(whole.to_owned())),
                        c => out.push_str(&regex::escape(c.encode_utf8(&mut buffer))),
                    }
                }
                if !closed {
                    return Err(PatternError::UnclosedBrace(whole.to_owned()));
                }
                out.push(')');
            }
            c => out.push_str(&regex::escape(c.encode_utf8(&mut buffer))),
        }
    }
    out.push('$');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(text: &str) -> Pattern {
        Pattern::compile(&PatternSource::Glob(text.to_owned())).unwrap()
    }

    #[test]
    fn star_stays_within_a_path_component() {
        let pattern = glob("/home/a/.local/share/claude/versions/*/claude");
        assert!(pattern.matches("/home/a/.local/share/claude/versions/2.0.31/claude", None));
        assert!(!pattern.matches("/home/a/.local/share/claude/versions/2.0.31/x/claude", None));
        assert!(!pattern.matches("/home/a/.local/share/claude/versions/2.0.31/claude2", None));
    }

    #[test]
    fn double_star_crosses_components() {
        let pattern = glob("/nix/store/**/bin/firefox");
        assert!(pattern.matches("/nix/store/abc-firefox-133/lib/x/bin/firefox", None));
        assert!(!pattern.matches("/usr/bin/firefox", None));
    }

    #[test]
    fn question_mark_and_alternatives() {
        let pattern = glob("/usr/bin/python3.1?");
        assert!(pattern.matches("/usr/bin/python3.12", None));
        assert!(!pattern.matches("/usr/bin/python3.1", None));
        let pattern = glob("/usr/{bin,lib}/x");
        assert!(pattern.matches("/usr/bin/x", None));
        assert!(pattern.matches("/usr/lib/x", None));
        assert!(!pattern.matches("/usr/sbin/x", None));
    }

    #[test]
    fn home_is_the_matched_users() {
        let pattern = glob("{home}/.local/share/claude/versions/*/claude");
        let path = "/home/ada/.local/share/claude/versions/2.0.31/claude";
        assert!(pattern.matches(path, Some("/home/ada")));
        assert!(pattern.matches(path, Some("/home/ada/")));
        assert!(!pattern.matches(path, Some("/home/grace")));
        assert!(!pattern.matches(path, None));
        let exact = Pattern::compile(&PatternSource::Exact("{home}/bin/x".into())).unwrap();
        assert!(exact.matches("/home/ada/bin/x", Some("/home/ada")));
        assert!(exact.exact().is_none());
    }

    #[test]
    fn regexes_match_the_whole_value() {
        let pattern =
            Pattern::compile(&PatternSource::Regex("/usr/bin/(curl|wget)".into())).unwrap();
        assert!(pattern.matches("/usr/bin/curl", None));
        assert!(!pattern.matches("/usr/bin/curl2", None));
    }

    #[test]
    fn rejects_malformed_globs() {
        assert!(Pattern::compile(&PatternSource::Glob("/a/{b,c".into())).is_err());
        assert!(Pattern::compile(&PatternSource::Glob("/a/{b,{c}}".into())).is_err());
        assert!(Pattern::compile(&PatternSource::Regex("(".into())).is_err());
    }

    #[test]
    fn many_stars_do_not_blow_up() {
        let pattern = glob("*a*a*a*a*a*a*a*a*a*a*a*a*b");
        let start = std::time::Instant::now();
        assert!(!pattern.matches(&"a".repeat(10_000), None));
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
    }

    #[test]
    fn regex_metacharacters_in_globs_are_literal() {
        let pattern = glob("/opt/app (1)/bin/a+b.[x]");
        assert!(pattern.matches("/opt/app (1)/bin/a+b.[x]", None));
        assert!(!pattern.matches("/opt/app 1/bin/aab.x", None));
    }

    #[test]
    fn patterns_matching_finitely_many_values_are_told() {
        for finite_one in [
            PatternSource::Exact("/usr/bin/curl".to_owned()),
            PatternSource::Glob("{home}/.cargo/bin/cargo".to_owned()),
            PatternSource::Glob("/usr/bin/{curl,wget}".to_owned()),
            PatternSource::Glob("/usr/bin/python3.1?".to_owned()),
            PatternSource::Regex("(?i)/usr/bin/curl".to_owned()),
            PatternSource::Regex("/usr/bin/(curl|wget)".to_owned()),
            PatternSource::Regex("/usr/bin/x{1,3}".to_owned()),
        ] {
            assert!(finite(&finite_one), "{finite_one}");
        }
        for infinite in [
            PatternSource::Glob("/**".to_owned()),
            PatternSource::Glob("/usr/bin/*".to_owned()),
            PatternSource::Regex(".*".to_owned()),
            PatternSource::Regex("/usr/bin/[a-z]+".to_owned()),
            PatternSource::Regex("/usr/bin/x{2,}".to_owned()),
            PatternSource::Regex("(".to_owned()),
        ] {
            assert!(!finite(&infinite), "{infinite}");
        }
    }
}
