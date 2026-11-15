//! The app's own preferences, cosmetic only (nothing about what the node does): kept in
//! `~/.config/snitchhiker/ui.toml`. The environment is scrubbed (the app is setgid), so the home directory comes from
//! the user's passwd entry, not `$HOME` or `$XDG_CONFIG_HOME`.

use std::path::PathBuf;

use gpui::{App, Global, Window};
use gpui_component::{Theme, ThemeMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    /// Light or dark as the desktop is.
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub appearance: Appearance,
    /// The Events table's columns hidden, by key.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events_hidden: Vec<String>,
    /// The Explorer's saved views.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub explorer_views: Vec<ExplorerView>,
}

/// A saved Explorer view: what it groups by, over how long, drilled into what, and how it orders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorerView {
    pub name: String,
    /// A protocol `Dimension` number.
    pub group: i32,
    pub hours: u64,
    /// The dimension and value drilled into.
    pub filter: Option<(i32, String)>,
    #[serde(default)]
    pub by_bytes: bool,
}

impl Global for Prefs {}

/// The user's home, from their passwd entry.
fn home() -> Option<PathBuf> {
    let uid = nix::unistd::getuid().as_raw();
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let home = fields.get(5)?;
        (fields.get(2)?.parse::<u32>().ok()? == uid).then(|| PathBuf::from(home))
    })
}

fn path() -> Option<PathBuf> {
    Some(home()?.join(".config/snitchhiker/ui.toml"))
}

impl Prefs {
    /// The preferences kept, or the defaults.
    #[must_use]
    pub fn load() -> Self {
        path()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Keeps them (a failure only loses a cosmetic choice).
    pub fn save(&self) {
        let Some(path) = path() else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = toml::to_string(self) {
            let _ = std::fs::write(path, text);
        }
    }
}

/// Puts the theme the appearance asks for in place.
pub fn apply(appearance: Appearance, window: &mut Window, cx: &mut App) {
    match appearance {
        Appearance::System => Theme::sync_system_appearance(Some(window), cx),
        Appearance::Light => Theme::change(ThemeMode::Light, Some(window), cx),
        Appearance::Dark => Theme::change(ThemeMode::Dark, Some(window), cx),
    }
    window.refresh();
}

/// Changes the appearance: kept, and applied at once.
pub fn set_appearance(appearance: Appearance, window: &mut Window, cx: &mut App) {
    let mut prefs = cx.try_global::<Prefs>().cloned().unwrap_or_default();
    prefs.appearance = appearance;
    prefs.save();
    cx.set_global(prefs);
    apply(appearance, window, cx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_read_and_default() {
        assert_eq!(toml::from_str::<Prefs>("").unwrap(), Prefs::default());
        assert_eq!(
            toml::from_str::<Prefs>("appearance = \"dark\"")
                .unwrap()
                .appearance,
            Appearance::Dark
        );
        assert_eq!(
            toml::to_string(&Prefs {
                appearance: Appearance::Light,
                ..Prefs::default()
            })
            .unwrap(),
            "appearance = \"light\"\n"
        );
    }
}
