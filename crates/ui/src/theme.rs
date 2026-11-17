//! The app's look: its light and dark themes (`assets/theme.json`), drawn in the system's own fonts. The pages read
//! their colours from the theme; the few the components have no name for are here.

use std::rc::Rc;

use gpui::{App, Hsla, SharedString, rgb};
use gpui_component::theme::{Theme, ThemeSet};
use zed_font_kit::source::SystemSource;

/// The signal colour: what waits for the user, and where they are.
#[must_use]
pub fn signal() -> Hsla {
    rgb(0x00ff_cc00).into()
}

/// Text on the signal colour.
#[must_use]
pub fn on_signal() -> Hsla {
    rgb(0x0016_191d).into()
}

/// The family the system gives a generic name (`sans-serif`, `monospace`): fontconfig's choice on Linux, which is
/// what the desktop and the user configured. `None` when it can't be told or the text system doesn't know that
/// family, and the components' own defaults apply.
fn system_family(generic: &str, installed: &[String]) -> Option<SharedString> {
    let family = SystemSource::new().select_family_by_name(generic).ok()?;
    let name = family.fonts().first()?.load().ok()?.family_name();
    installed.contains(&name).then(|| name.into())
}

/// Puts the themes in place, in the system's fonts; the appearance chosen is applied after
/// ([`crate::prefs::apply`]).
pub fn install(cx: &mut App) {
    let Ok(set) = serde_json::from_str::<ThemeSet>(include_str!("../assets/theme.json")) else {
        return;
    };
    let installed = cx.text_system().all_font_names();
    let sans = system_family("sans-serif", &installed);
    let mono = system_family("monospace", &installed);
    Theme::update(cx, |theme| {
        for mut config in set.themes {
            config.font_family = config.font_family.or_else(|| sans.clone());
            config.mono_font_family = config.mono_font_family.or_else(|| mono.clone());
            if config.mode.is_dark() {
                theme.dark_theme = Rc::new(config);
            } else {
                theme.light_theme = Rc::new(config);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_themes_read() {
        let set: ThemeSet = serde_json::from_str(include_str!("../assets/theme.json")).unwrap();
        assert_eq!(set.themes.len(), 2);
        assert!(set.themes.iter().any(|t| t.mode.is_dark()));
        assert!(set.themes.iter().any(|t| !t.mode.is_dark()));
    }
}
