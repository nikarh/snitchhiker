//! Explorer: the history grouped by program, host, port, user or container over a time range, busiest first, with what was
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

const DIMENSIONS: [(v1::Dimension, &str); 5] = [
    (v1::Dimension::Program, "Program"),
    (v1::Dimension::Host, "Host"),
    (v1::Dimension::Port, "Port"),
    (v1::Dimension::User, "User"),
    (v1::Dimension::Container, "Container"),
];

/// A group's key as shown: a container's identity as people know it (its runtime, then its Compose service or name,
/// and its image), the host's connections for none; other keys as they are, and "(no name)" for an empty one.
pub fn shown(dimension: v1::Dimension, key: &str) -> String {
    if dimension == v1::Dimension::Container {
        if key.is_empty() {
            return "(the host)".to_owned();
        }
        let container = snitchhiker_core::context::Container::from_key(key);
        return format!("[{}] {}", container.runtime, container.label());
    }
    if key.is_empty() {
        "(no name)".to_owned()
    } else {
        key.to_owned()
    }
}

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
    /// Busiest by bytes rather than by connections: the top talkers.
    by_bytes: bool,
    /// The period before shown alongside: what changed, and what is new.
    compare: bool,
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
        _ => v1::Dimension::Program,
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
            by_bytes: false,
            compare: false,
        }
    }

    /// Groups by container, from the top: the Containers & VMs page.
    pub fn by_containers(&mut self) {
        self.group = v1::Dimension::Container;
        self.filter = None;
    }

    /// Asks the node for the groups as the page is set.
    pub fn query(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let span = self.hours * 3_600_000;
        let explore = |from_ms: u64, to_ms: u64| v1::Explore {
            from_ms,
            to_ms,
            group_by: self.group.into(),
            filter: self
                .filter
                .as_ref()
                .map(|(dimension, value)| v1::ExploreFilter {
                    dimension: (*dimension).into(),
                    value: value.clone(),
                }),
            limit: LIMIT,
            by_bytes: self.by_bytes,
        };
        let _ = self
            .requests
            .send(Request::Explore(explore(now.saturating_sub(span), now)));
        if self.compare {
            let _ = self.requests.send(Request::ExploreBefore(explore(
                now.saturating_sub(2 * span),
                now.saturating_sub(span),
            )));
        }
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
        let options = h_flex()
            .gap_1()
            .child(Self::choice(
                "by-bytes".to_owned(),
                "By bytes",
                self.by_bytes,
                !self.by_bytes,
                |e, on| e.by_bytes = on,
                cx,
            ))
            .child(Self::choice(
                "compare".to_owned(),
                "Compare with before",
                self.compare,
                !self.compare,
                |e, on| e.compare = on,
                cx,
            ));
        let model = self.model.clone();
        let group = name(self.group);
        h_flex()
            .gap_4()
            .child(dimensions)
            .child(ranges)
            .child(options)
            .child(div().flex_1())
            .child(self.views(cx))
            .child(
                Button::new("explorer-csv")
                    .small()
                    .label("Copy CSV")
                    .on_click(move |_, _, cx| {
                        let rows = model.read(cx).explored.iter().map(|row| {
                            vec![
                                row.key.clone(),
                                row.allowed.to_string(),
                                row.blocked.to_string(),
                                row.bytes_out.to_string(),
                                row.bytes_in.to_string(),
                            ]
                        });
                        let csv = crate::csv::table(
                            &[group, "allowed", "blocked", "sent", "received"],
                            rows,
                        );
                        cx.write_to_clipboard(gpui::ClipboardItem::new_string(csv));
                    }),
            )
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
                row.child("›")
                    .child(format!("{}: {}", name(dimension), shown(dimension, &value)))
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
            .when(self.compare, |row| {
                row.child(div().w(px(110.)).text_right().child("Before"))
            })
            .into_any_element()
    }
}

impl Explorer {
    /// A group's row: its key, its bar, its counts and bytes, and the period before when comparing.
    fn row(
        &self,
        index: usize,
        row: &v1::ExploreRow,
        total: u64,
        before: Option<&Vec<v1::ExploreRow>>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = cx.theme().clone();
        let key = row.key.clone();
        let group = self.group;
        let width = |count: u64| {
            px(240. * f32::from(u16::try_from(count * 1000 / total).unwrap_or(1000)) / 1000.)
        };
        let line = h_flex()
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
                    .child(shown(group, &row.key)),
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
            )
            // The period before: its count, or that the group is new in this one.
            .when_some(before, |line, before| {
                let was = before.iter().find(|b| b.key == row.key);
                line.child(div().w(px(110.)).text_right().child(match was {
                    Some(was) => (was.allowed + was.blocked).to_string(),
                    None => "new".to_owned(),
                }))
            });
        line.into_any_element()
    }
}

impl Explorer {
    /// The view as it is now, to save: named after what it shows.
    fn view(&self) -> crate::prefs::ExplorerView {
        let range = RANGES
            .iter()
            .find(|(h, _)| *h == self.hours)
            .map_or("", |(_, label)| *label);
        let mut label = format!("{} · {range}", name(self.group));
        if let Some((dimension, value)) = &self.filter {
            label = format!("{label} · {}", shown(*dimension, value));
        }
        if self.by_bytes {
            label.push_str(" · by bytes");
        }
        crate::prefs::ExplorerView {
            name: label,
            group: self.group.into(),
            hours: self.hours,
            filter: self
                .filter
                .as_ref()
                .map(|(d, v)| (i32::from(*d), v.clone())),
            by_bytes: self.by_bytes,
        }
    }

    fn apply(&mut self, view: &crate::prefs::ExplorerView) {
        self.group = v1::Dimension::try_from(view.group).unwrap_or(v1::Dimension::Program);
        self.hours = view.hours;
        self.filter = view.filter.as_ref().map(|(d, v)| {
            (
                v1::Dimension::try_from(*d).unwrap_or(v1::Dimension::Program),
                v.clone(),
            )
        });
        self.by_bytes = view.by_bytes;
    }

    /// The saved views: applying one, saving this one, forgetting them.
    fn views(&self, cx: &mut Context<Self>) -> AnyElement {
        use gpui_component::menu::{DropdownMenu as _, PopupMenuItem};
        let explorer = cx.entity();
        let current = self.view();
        Button::new("explorer-views")
            .small()
            .label("Views")
            .dropdown_menu(move |mut menu, _, cx| {
                let saved = cx
                    .try_global::<crate::prefs::Prefs>()
                    .map_or_else(Vec::new, |p| p.explorer_views.clone());
                for view in saved {
                    let explorer = explorer.clone();
                    menu = menu.item(PopupMenuItem::new(view.name.clone()).on_click(
                        move |_, _, cx| {
                            explorer.update(cx, |explorer, cx| {
                                explorer.apply(&view);
                                explorer.query();
                                cx.notify();
                            });
                        },
                    ));
                }
                let current = current.clone();
                menu.separator()
                    .item(
                        PopupMenuItem::new("Save this view").on_click(move |_, _, cx| {
                            let mut prefs = cx
                                .try_global::<crate::prefs::Prefs>()
                                .cloned()
                                .unwrap_or_default();
                            prefs.explorer_views.retain(|v| v.name != current.name);
                            prefs.explorer_views.push(current.clone());
                            prefs.save();
                            cx.set_global(prefs);
                        }),
                    )
                    .item(
                        PopupMenuItem::new("Forget the saved views").on_click(|_, _, cx| {
                            let mut prefs = cx
                                .try_global::<crate::prefs::Prefs>()
                                .cloned()
                                .unwrap_or_default();
                            prefs.explorer_views.clear();
                            prefs.save();
                            cx.set_global(prefs);
                        }),
                    )
            })
            .into_any_element()
    }
}

impl Render for Explorer {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let rows = self.model.read(cx).explored.clone();
        let before = self
            .compare
            .then(|| self.model.read(cx).explored_before.clone())
            .flatten();
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
            list = list.child(self.row(index, row, total, before.as_ref(), cx));
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
