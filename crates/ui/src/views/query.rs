//! Help with the query language under a query box: the query's tokens highlighted (the part in error marked), and
//! the keys that complete the word being typed.

use gpui::{
    AnyElement, App, Entity, IntoElement, ParentElement as _, SharedString, Styled as _, Window,
    div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::InputState;
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex};
use snitchhiker_core::query::{self, TokenKind};

/// The keys of event queries, with what they match.
pub const EVENT_KEYS: [(&str, &str); 13] = [
    ("exe", "program"),
    ("host", "host name"),
    ("ip", "address or network"),
    ("port", "port or range"),
    ("proto", "tcp, udp…"),
    ("user", "uid or name"),
    ("action", "allow, deny, reject"),
    ("rule", "rule id, none"),
    ("bytes", "both ways"),
    ("sent", "bytes sent"),
    ("received", "bytes received"),
    ("time", "-1h, 2026-11-15"),
    ("context", "host, container…"),
];

/// The keys of rule searches.
pub const RULE_KEYS: [(&str, &str); 16] = [
    ("name", "rule name"),
    ("notes", "notes"),
    ("folder", "Apps/curl"),
    ("action", "allow, deny, reject"),
    ("tier", "override, normal…"),
    ("enabled", "yes, no"),
    ("locked", "yes, no"),
    ("exe", "program"),
    ("app", "app identity"),
    ("cmdline", "command line"),
    ("parent", "parent program"),
    ("host", "host"),
    ("ip", "network"),
    ("port", "port"),
    ("proto", "protocol"),
    ("user", "uid"),
];

/// Where the word being typed at the end of `text` starts, and the word, when it could be the start of a key: letters
/// only, after whitespace, `(` or `-`.
fn last_word(text: &str) -> Option<(usize, &str)> {
    let start = text
        .rfind(|c: char| c.is_whitespace() || c == '(' || c == '-')
        .map_or(0, |i| i + 1);
    let word = text.get(start..)?;
    (!word.is_empty() && word.chars().all(|c| c.is_ascii_alphabetic())).then_some((start, word))
}

/// The keys that complete the word at the end of `text`.
#[must_use]
pub fn completions<'a>(text: &str, keys: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let Some((_, word)) = last_word(text) else {
        return Vec::new();
    };
    let word = word.to_ascii_lowercase();
    keys.iter()
        .filter(|(key, _)| key.starts_with(&word) && *key != word)
        .copied()
        .collect()
}

/// `text` with the word at its end completed to `key:`.
#[must_use]
pub fn complete(text: &str, key: &str) -> String {
    let start = last_word(text).map_or(text.len(), |(start, _)| start);
    format!("{}{key}:", text.get(..start).unwrap_or(text))
}

/// The query's tokens, coloured by kind, and the error's part underlined in red.
fn highlighted(text: &str, error: Option<&std::ops::Range<usize>>, cx: &App) -> AnyElement {
    let theme = cx.theme();
    let mut line = h_flex().text_sm().font_family("monospace");
    let mut at = 0;
    let piece = |line: gpui::Div, from: usize, to: usize, color: gpui::Hsla, wrong: bool| {
        let part = text.get(from..to).unwrap_or("").replace(' ', "\u{a0}");
        if part.is_empty() {
            return line;
        }
        let span = div().text_color(color).child(part);
        line.child(if wrong {
            span.border_b_2().border_color(theme.danger)
        } else {
            span
        })
    };
    for (span, kind) in query::tokens(text) {
        if span.start > at {
            line = piece(line, at, span.start, theme.muted_foreground, false);
        }
        let color = match kind {
            TokenKind::Key => theme.blue,
            TokenKind::Operator | TokenKind::Syntax => theme.magenta,
            TokenKind::Value => theme.foreground,
            TokenKind::Text => theme.muted_foreground,
        };
        let wrong = error.as_ref().is_some_and(|e| {
            e.start < span.end.max(span.start + 1) && span.start < e.end.max(e.start + 1)
        });
        line = piece(line, span.start, span.end, color, wrong);
        at = span.end;
    }
    line = piece(line, at, text.len(), theme.muted_foreground, false);
    line.into_any_element()
}

/// The help shown under a query box `input`: the highlighted query, and keys completing the word typed (a click puts
/// one in).
pub fn hints(
    input: &Entity<InputState>,
    keys: &'static [(&'static str, &'static str)],
    error: Option<&std::ops::Range<usize>>,
    window: &Window,
    cx: &App,
) -> AnyElement {
    let _ = window;
    let text = input.read(cx).value().to_string();
    let mut row = h_flex().gap_3().flex_wrap();
    if !text.trim().is_empty() {
        row = row.child(highlighted(&text, error, cx));
    }
    for (key, about) in completions(&text, keys) {
        let input = input.clone();
        let text = text.clone();
        row = row.child(
            Button::new(SharedString::from(format!("complete-{key}")))
                .xsmall()
                .ghost()
                .label(format!("{key}: {about}"))
                .on_click(move |_, window, cx| {
                    let completed = complete(&text, key);
                    input.update(cx, |state, cx| {
                        state.set_value(completed, window, cx);
                        state.focus(window, cx);
                    });
                }),
        );
    }
    row.into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_typed_is_completed_to_a_key() {
        let keys = |text| -> Vec<&str> {
            completions(text, &EVENT_KEYS)
                .iter()
                .map(|(k, _)| *k)
                .collect()
        };
        assert_eq!(keys("ho"), vec!["host"]);
        assert_eq!(keys("curl -po"), vec!["port"]);
        assert_eq!(keys("(se"), vec!["sent"]);
        assert_eq!(keys("re"), vec!["received"]);
        assert_eq!(keys("r"), vec!["rule", "received"]);
        // A key already whole, a value, free text with a dot, or nothing: no completion.
        assert_eq!(keys("host"), Vec::<&str>::new());
        assert_eq!(keys("host:ex"), Vec::<&str>::new());
        assert_eq!(keys("a.b"), Vec::<&str>::new());
        assert_eq!(keys("curl "), Vec::<&str>::new());
        assert_eq!(complete("curl -po", "port"), "curl -port:");
        assert_eq!(complete("", "exe"), "exe:");
    }
}
