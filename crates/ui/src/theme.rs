//! The app's look: its typefaces (Overpass and Overpass Mono, embedded: the app can't count on any font being
//! installed) and its light and dark themes (`assets/theme.json`). The pages read their colours from the theme; the
//! few the components have no name for are here.

use std::borrow::Cow;
use std::rc::Rc;

use gpui::{App, Hsla, rgb};
use gpui_component::theme::{Theme, ThemeSet};

const FONTS: [&[u8]; 3] = [
    include_bytes!("../assets/fonts/Overpass-Regular.ttf"),
    include_bytes!("../assets/fonts/Overpass-SemiBold.ttf"),
    include_bytes!("../assets/fonts/OverpassMono-Regular.ttf"),
];

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

/// Puts the fonts and themes in place; the appearance chosen is applied after ([`crate::prefs::apply`]).
pub fn install(cx: &mut App) {
    let _ = cx
        .text_system()
        .add_fonts(FONTS.iter().map(|font| Cow::Borrowed(*font)).collect());
    let Ok(set) = serde_json::from_str::<ThemeSet>(include_str!("../assets/theme.json")) else {
        return;
    };
    Theme::update(cx, |theme| {
        for config in set.themes {
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
