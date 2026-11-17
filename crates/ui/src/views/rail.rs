//! The rail: the dark column of places on the left (the nodes, a node's pages). Where the user is, and what waits
//! there, is marked in the signal colour.

use gpui::prelude::FluentBuilder as _;
use gpui::{
    App, Div, ElementId, InteractiveElement as _, ParentElement as _, Stateful, Styled as _, div,
    px,
};
use gpui_component::{ActiveTheme as _, Icon, Sizable as _, h_flex};

use crate::theme::{on_signal, signal};

/// The rail's width.
pub const WIDTH: f32 = 212.;

/// One place: its icon, its name and how many things wait there; the caller adds what a click does.
pub fn item(
    id: impl Into<ElementId>,
    icon: Option<Icon>,
    label: impl Into<gpui::SharedString>,
    active: bool,
    count: usize,
    cx: &App,
) -> Stateful<Div> {
    let theme = cx.theme();
    let (hover, foreground) = (theme.sidebar_accent, theme.sidebar_foreground);
    h_flex()
        .id(id)
        .mx_2()
        .px_2p5()
        .h(px(30.))
        .gap_2p5()
        .rounded(theme.radius)
        .cursor_pointer()
        .text_color(foreground)
        .hover(move |row| row.bg(hover).text_color(gpui::white()))
        .when(active, |row| {
            row.bg(hover)
                .text_color(gpui::white())
                .font_weight(gpui::FontWeight::SEMIBOLD)
        })
        .when_some(icon, |row, icon| {
            row.child(
                icon.small()
                    .text_color(if active { signal() } else { foreground }),
            )
        })
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap()
                .child(label.into()),
        )
        .when(count > 0, |row| row.child(badge(count)))
}

/// A count of what waits, in the signal colour.
pub fn badge(count: usize) -> Div {
    div()
        .px_1p5()
        .min_w(px(20.))
        .h(px(18.))
        .flex()
        .items_center()
        .justify_center()
        .rounded_full()
        .bg(signal())
        .text_color(on_signal())
        .text_xs()
        .font_weight(gpui::FontWeight::BOLD)
        .child(count.to_string())
}

/// The space between groups of places.
pub fn gap() -> Div {
    div().flex_none().h(px(12.))
}
