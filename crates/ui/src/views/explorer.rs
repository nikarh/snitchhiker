//! Explorer: the history grouped by program, host, port or user over a time range, busiest first, with what was
//! allowed and blocked; a group drills down into the next dimension. The node answers from hourly rollups, so a
//! month of a million connections groups in tens of milliseconds.

use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use gpui::{
    AnyElement, Context, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, StatefulInteractiveElement as _, Styled as _, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;
use crate::views::events::bytes;

const DIMENSIONS: [(v1::Dimension, &str); 4] = [
    (v1::Dimension::Program, "Program"),
    (v1::Dimension::Host, "Host"),
    (v1::Dimension::Port, "Port"),
    (v1::Dimension::User, "User"),
];

const RANGES: [(u64, &str); 4] = [
    (1, "1 hour"),
    (24, "24 hours"),
    (24 * 7, "7 days"),
    (24 * 30, "30 days"),
];

/// Groups shown.
const LIMIT: u32 = 200;

pub struct Explorer {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    group: v1::Dimension,
    hours: u64,
    /// The group drilled into: its dimension and value.
    filter: Option<(v1::Dimension, String)>,
}

fn name(dimension: v1::Dimension) -> &'static str {
    DIMENSIONS
        .iter()
        .find(|(d, _)| *d == dimension)
        .map_or("", |(_, name)| *name)
}

/// The dimension a group drills into: the next one that isn't the group's own.
fn next(dimension: v1::Dimension) -> v1::Dimension {
    match dimension {
        v1::Dimension::Program => v1::Dimension::Host,
        v1::Dimension::Host => v1::Dimension::Program,
        v1::Dimension::Port | v1::Dimension::User | v1::Dimension::Unspecified => {
            v1::Dimension::Program
        }
    }
}

impl Explorer {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            requests,
            group: v1::Dimension::Program,
            hours: 24,
            filter: None,
        }
    }

    /// Asks the node for the groups as the page is set.
    pub fn query(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let _ = self.requests.send(Request::Explore(v1::Explore {
            from_ms: now.saturating_sub(self.hours * 3_600_000),
            to_ms: now,
            group_by: self.group.into(),
            filter: self
                .filter
                .as_ref()
                .map(|(dimension, value)| v1::ExploreFilter {
                    dimension: (*dimension).into(),
                    value: value.clone(),
                }),
            limit: LIMIT,
        }));
    }

    fn choice<T: Copy + PartialEq + 'static>(
        id: String,
        label: &'static str,
        on: bool,
        value: T,
        set: fn(&mut Self, T),
        cx: &mut Context<Self>,
    ) -> Button {
        let button = Button::new(SharedString::from(id))
            .small()
            .label(label)
            .on_click(cx.listener(move |explorer, _, _, cx| {
                set(explorer, value);
                explorer.query();
                cx.notify();
            }));
        if on { button.primary() } else { button.ghost() }
    }
}

impl Explorer {
    fn controls(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut dimensions = h_flex().gap_1();
        for (dimension, label) in DIMENSIONS {
            if self.filter.as_ref().is_some_and(|(d, _)| *d == dimension) {
                continue;
            }
            dimensions = dimensions.child(Self::choice(
                format!("group-{label}"),
                label,
                self.group == dimension,
                dimension,
                |e, d| e.group = d,
                cx,
            ));
        }
        let mut ranges = h_flex().gap_1();
        for (hours, label) in RANGES {
            ranges = ranges.child(Self::choice(
                format!("range-{hours}"),
                label,
                self.hours == hours,
                hours,
                |e, h| e.hours = h,
                cx,
            ));
        }
        h_flex()
            .gap_4()
            .child(dimensions)
            .child(ranges)
            .into_any_element()
    }

    fn crumbs(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        h_flex()
            .gap_2()
            .text_color(theme.muted_foreground)
            .child(
                Button::new("all")
                    .small()
                    .ghost()
                    .label("All connections")
                    .on_click(cx.listener(|explorer, _, _, cx| {
                        explorer.filter = None;
                        explorer.query();
                        cx.notify();
                    })),
            )
            .when_some(self.filter.clone(), |row, (dimension, value)| {
                row.child("›").child(format!(
                    "{}: {}",
                    name(dimension),
                    if value.is_empty() {
                        "(no name)"
                    } else {
                        &value
                    }
                ))
            })
            .into_any_element()
    }
}

impl Explorer {
    fn header(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        h_flex()
            .gap_3()
            .px_2()
            .text_color(theme.muted_foreground)
            .child(div().w(px(420.)).child(name(self.group)))
            .child(div().w(px(240.)))
            .child(div().w(px(90.)).text_right().child("Allowed"))
            .child(div().w(px(90.)).text_right().child("Blocked"))
            .child(div().w(px(90.)).text_right().child("Sent"))
            .child(div().w(px(90.)).text_right().child("Received"))
            .into_any_element()
    }
}

impl Render for Explorer {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let rows = self.model.read(cx).explored.clone();
        let total: u64 = rows
            .iter()
            .map(|r| r.allowed + r.blocked)
            .max()
            .unwrap_or(1)
            .max(1);
        let controls = self.controls(cx);
        let crumbs = self.crumbs(cx);
        let mut list = v_flex().gap_1();
        for (index, row) in rows.iter().enumerate() {
            let key = row.key.clone();
            let group = self.group;
            let width = |count: u64| {
                px(240. * f32::from(u16::try_from(count * 1000 / total).unwrap_or(1000)) / 1000.)
            };
            list = list.child(
                h_flex()
                    .id(SharedString::from(format!("group-row-{index}")))
                    .gap_3()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .hover(|style| style.bg(theme.muted))
                    .cursor_pointer()
                    .on_click(cx.listener(move |explorer, _, _, cx| {
                        explorer.filter = Some((group, key.clone()));
                        explorer.group = next(group);
                        explorer.query();
                        cx.notify();
                    }))
                    .child(
                        div()
                            .w(px(420.))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(if row.key.is_empty() {
                                "(no name)".to_owned()
                            } else {
                                row.key.clone()
                            }),
                    )
                    .child(
                        h_flex()
                            .w(px(240.))
                            .flex_none()
                            .h(px(10.))
                            .child(div().h_full().w(width(row.allowed)).bg(theme.success))
                            .child(div().h_full().w(width(row.blocked)).bg(theme.danger)),
                    )
                    .child(div().w(px(90.)).text_right().child(row.allowed.to_string()))
                    .child(
                        div()
                            .w(px(90.))
                            .text_right()
                            .text_color(theme.danger)
                            .child(row.blocked.to_string()),
                    )
                    .child(
                        div()
                            .w(px(90.))
                            .text_right()
                            .text_color(theme.muted_foreground)
                            .child(bytes(row.bytes_out)),
                    )
                    .child(
                        div()
                            .w(px(90.))
                            .text_right()
                            .text_color(theme.muted_foreground)
                            .child(bytes(row.bytes_in)),
                    ),
            );
        }
        if rows.is_empty() {
            list = list.child(
                div()
                    .text_color(theme.muted_foreground)
                    .child("No connections in this range."),
            );
        }
        v_flex()
            .size_full()
            .p_4()
            .gap_3()
            .child(controls)
            .child(crumbs)
            .child(self.header(cx))
            .child(
                div()
                    .id("explorer-rows")
                    .flex_1()
                    .overflow_y_scroll()
                    .child(list),
            )
    }
}
