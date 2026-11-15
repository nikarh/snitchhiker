//! The documentation's generated parts (`site/src/generated/`): written from the code, and checked to match it, so
//! the reference pages can't drift from what the program does. `SNITCHHIKER_UPDATE_DOCS=1 cargo test -p
//! snitchhiker-daemon --test docs` writes them after a change.

#![allow(
    clippy::unwrap_used,
    reason = "a test's helpers: failing loudly is the point"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use snitchhiker_core::destination::ALIASES;
use snitchhiker_daemon::cli::{DAEMON_HELP, HELP};
use snitchhiker_daemon::config::Config;

fn site() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../site")
}

fn aliases() -> String {
    let mut text = String::from(
        "{/* Generated from ALIASES in crates/core/src/destination.rs by crates/daemon/tests/docs.rs. */}\n\n\
         | Alias | Networks |\n| --- | --- |\n",
    );
    for (alias, networks) in ALIASES {
        let networks: Vec<String> = networks.iter().map(|n| format!("`{n}`")).collect();
        let _ = writeln!(text, "| `{alias}` | {} |", networks.join(", "));
    }
    text
}

fn block_columns() -> String {
    use snitchhiker_proto::columns::Column;
    let mut text = String::from(
        "{/* Generated from Column in crates/proto/src/columns.rs by crates/daemon/tests/docs.rs. */}\n\n\
         | Id | Column | Width | Holds |\n| --- | --- | --- | --- |\n",
    );
    for column in Column::all() {
        let _ = writeln!(
            text,
            "| {} | `{column:?}` | {} | {} |",
            column as u16,
            column.width(),
            column.describe()
        );
    }
    text
}

fn generated() -> Vec<(&'static str, String)> {
    vec![
        ("cli-help.txt", HELP.to_owned()),
        ("daemon-help.txt", DAEMON_HELP.to_owned()),
        ("aliases.mdx", aliases()),
        ("block-columns.mdx", block_columns()),
        (
            "config-defaults.toml",
            format!(
                "# Every setting of daemon.toml with its default (generated from Config::default()).\n{}",
                toml::to_string(&Config::default()).unwrap()
            ),
        ),
    ]
}

#[test]
fn generated_docs_are_current() {
    let update = std::env::var_os("SNITCHHIKER_UPDATE_DOCS").is_some();
    let dir = site().join("src/generated");
    let mut stale = Vec::new();
    for (name, content) in generated() {
        let path = dir.join(name);
        if update {
            fs::create_dir_all(&dir).unwrap();
            fs::write(&path, &content).unwrap();
        } else if fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "site/src/generated/ is stale ({stale:?}): run SNITCHHIKER_UPDATE_DOCS=1 cargo test -p snitchhiker-daemon --test docs"
    );
}

#[test]
fn every_setting_is_documented() {
    let defaults = toml::to_string(&Config::default()).unwrap();
    let table: toml::Table = toml::from_str(&defaults).unwrap();
    let page =
        fs::read_to_string(site().join("src/content/docs/reference/configuration.mdx")).unwrap();
    let missing: Vec<&String> = table
        .keys()
        .filter(|key| !page.contains(&format!("`{key}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "settings missing from the configuration page: {missing:?}"
    );
}

/// Every screenshot a page shows exists (`scripts/screenshots.sh` takes them), so a page never shows a broken image.
#[test]
fn every_screenshot_shown_exists() {
    fn pages(dir: &Path, found: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pages(&path, found);
            } else if path.extension().is_some_and(|e| e == "md" || e == "mdx") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    pages(&site().join("src/content/docs"), &mut found);
    let mut missing = Vec::new();
    for page in found {
        let text = fs::read_to_string(&page).unwrap();
        for (at, _) in text.match_indices("assets/screenshots/") {
            let name: String = text[at + "assets/screenshots/".len()..]
                .chars()
                .take_while(|c| !matches!(c, ')' | '"' | '\'' | ' '))
                .collect();
            if !site().join("src/assets/screenshots").join(&name).exists() {
                missing.push(format!("{}: {name}", page.display()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "screenshots shown but not taken (scripts/screenshots.sh): {missing:?}"
    );
}
