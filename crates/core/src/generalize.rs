//! Turning an executable's path into a pattern that survives updates: path segments that look like versions or
//! content hashes become `*`, and the user's home becomes `{home}`.
//!
//! `/home/ada/.local/share/claude/versions/2.0.31/claude` becomes `{home}/.local/share/claude/versions/*/claude`;
//! `/nix/store/0c7…-firefox-133.0/bin/firefox` becomes `/nix/store/*-firefox-*/bin/firefox`. A path with nothing to
//! generalise stays exact.

use crate::pattern::{HOME, PatternSource};

/// What changes from one version of a program to the next, within a path segment.
fn is_version(text: &str) -> bool {
    // `v12`: a v and digits.
    if let Some(digits) = text.strip_prefix('v')
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    let text = text.strip_prefix('v').unwrap_or(text);
    let mut parts = text.split(['.', '-', '_', '+']);
    let first = parts.next().unwrap_or_default();
    !first.is_empty()
        && first.bytes().all(|b| b.is_ascii_digit())
        && text.contains(['.', '-', '_', '+']).then_some(()).is_some()
        && parts.all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// A content hash: long, hexadecimal or Nix's base32, with digits and letters mixed.
fn is_hash(text: &str) -> bool {
    text.len() >= 12
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        && text.bytes().any(|b| b.is_ascii_digit())
        && text.bytes().any(|b| b.is_ascii_lowercase())
}

/// One path segment, generalised: versions and hashes, alone or as `name-1.2.3` / `hash-name` parts.
fn segment(segment: &str) -> String {
    if is_version(segment) || is_hash(segment) {
        return "*".to_owned();
    }
    // AppImages are mounted at /tmp/.mount_<up to 6 characters of the name><6 random characters>.
    if let Some(name) = segment.strip_prefix(".mount_")
        && name.len() > 6
        && let Some(stem) = name.get(..name.len() - 6)
    {
        return format!(".mount_{stem}*");
    }
    // Dash-separated parts (`firefox-133.0`, `0c7…-firefox-133.0`).
    let parts: Vec<&str> = segment.split('-').collect();
    if parts.len() > 1 {
        let mut changed = false;
        let mut out: Vec<&str> = Vec::with_capacity(parts.len());
        let mut index = 0;
        while let Some(part) = parts.get(index) {
            // A version may itself contain dashes (`1.2.3-beta`): the rest of the segment from here.
            let rest = parts.get(index..).unwrap_or_default().join("-");
            if index > 0 && is_version(&rest) {
                out.push("*");
                changed = true;
                break;
            }
            if is_version(part) || is_hash(part) {
                out.push("*");
                changed = true;
            } else {
                out.push(part);
            }
            index += 1;
        }
        if changed {
            return out.join("-");
        }
    }
    segment.to_owned()
}

/// The pattern for an executable run by a user whose home is `home`.
#[must_use]
pub fn executable(path: &str, home: Option<&str>) -> PatternSource {
    let (prefix, rest) = match home.map(|h| h.trim_end_matches('/')) {
        Some(home)
            if !home.is_empty()
                && path.starts_with(home)
                && path.get(home.len()..).is_some_and(|r| r.starts_with('/')) =>
        {
            (HOME, path.get(home.len()..).unwrap_or_default())
        }
        _ => ("", path),
    };
    let generalised: Vec<String> = rest.split('/').map(segment).collect();
    let pattern = format!("{prefix}{}", generalised.join("/"));
    if pattern.contains('*') {
        PatternSource::Glob(pattern)
    } else {
        PatternSource::Exact(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(text: &str) -> PatternSource {
        PatternSource::Glob(text.to_owned())
    }

    #[test]
    fn version_directories_become_wildcards() {
        assert_eq!(
            executable(
                "/home/ada/.local/share/claude/versions/2.0.31/claude",
                Some("/home/ada")
            ),
            glob("{home}/.local/share/claude/versions/*/claude")
        );
        assert_eq!(
            executable("/opt/app/v12/bin/app", None),
            glob("/opt/app/*/bin/app")
        );
    }

    #[test]
    fn versions_inside_names_become_wildcards() {
        assert_eq!(
            executable(
                "/home/ada/.local/share/JetBrains/Toolbox/apps/idea/2026.2.1/bin/idea",
                Some("/home/ada")
            ),
            glob("{home}/.local/share/JetBrains/Toolbox/apps/idea/*/bin/idea")
        );
        assert_eq!(
            executable("/usr/lib/firefox-133.0b2/firefox", None),
            glob("/usr/lib/firefox-*/firefox")
        );
    }

    #[test]
    fn nix_store_hashes_and_appimage_mounts() {
        assert_eq!(
            executable(
                "/nix/store/0c7k2xzq9yrd1wv5mzh8cl3x9a0b1c2d-firefox-133.0/bin/firefox",
                None
            ),
            glob("/nix/store/*-firefox-*/bin/firefox")
        );
        assert_eq!(
            executable("/tmp/.mount_ObsidiXa8kTq/obsidian", None),
            glob("/tmp/.mount_Obsidi*/obsidian")
        );
    }

    #[test]
    fn stable_paths_stay_exact() {
        assert_eq!(
            executable("/usr/bin/python3.13", None),
            PatternSource::Exact("/usr/bin/python3.13".to_owned())
        );
        assert_eq!(
            executable("/usr/bin/curl", Some("/home/ada")),
            PatternSource::Exact("/usr/bin/curl".to_owned())
        );
        assert_eq!(
            executable("/home/ada/bin/tool", Some("/home/ada")),
            PatternSource::Exact("{home}/bin/tool".to_owned())
        );
    }

    #[test]
    fn a_home_prefix_must_end_at_a_directory() {
        assert_eq!(
            executable("/home/adams/bin/x", Some("/home/ada")),
            PatternSource::Exact("/home/adams/bin/x".to_owned())
        );
    }
}
