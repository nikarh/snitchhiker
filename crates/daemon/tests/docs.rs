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

fn generated() -> Vec<(&'static str, String)> {
    vec![
        ("cli-help.txt", HELP.to_owned()),
        ("daemon-help.txt", DAEMON_HELP.to_owned()),
        ("aliases.mdx", aliases()),
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
