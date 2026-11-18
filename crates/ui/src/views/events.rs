//! Events: every connection the node decided, newest first, in a virtualized table that loads older history as it is
//! scrolled down. Live events arrive at the top.

use std::sync::mpsc;

use chrono::{Local, TimeZone as _};
use gpui::prelude::FluentBuilder as _;
use gpui::{
    App, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render, SharedString,
    Styled as _, Window, div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::menu::{DropdownMenu as _, PopupMenu, PopupMenuItem};
use gpui_component::table::DataTable;
use gpui_component::table::{Column, TableDelegate, TableState};
use gpui_component::v_flex;
use gpui_component::{ActiveTheme as _, IconName, Sizable as _, h_flex};
use snitchhiker_core::query::{self, EventFilter};
use snitchhiker_proto::columns::EventRow;
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::{Model, address};
use crate::views::explain;
use crate::views::text::clipped;

const COLUMNS: [(&str, &str, f32); 12] = [
    ("time", "Time", 176.),
    ("action", "Action", 76.),
    ("why", "", 44.),
    ("rule", "Decided by", 200.),
    ("program", "Program", 240.),
    ("pid", "PID", 72.),
    ("destination", "Destination", 210.),
    ("port", "Port", 84.),
    ("interface", "Interface", 96.),
    ("user", "User", 60.),
    ("out", "Sent", 80.),
    ("in", "Received", 84.),
];

pub struct EventsTable {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    /// The columns shown, as indices into `COLUMNS`.
    shown: Vec<usize>,
}

/// Columns that can be hidden: (key, label).
pub const OPTIONAL: [(&str, &str); 8] = [
    ("rule", "Decided by"),
    ("pid", "PID"),
    ("destination", "Destination"),
    ("port", "Port"),
    ("interface", "Interface"),
    ("user", "User"),
    ("out", "Sent"),
    ("in", "Received"),
];

impl EventsTable {
    #[must_use]
    pub fn new(model: Entity<Model>, requests: mpsc::Sender<Request>, hidden: &[String]) -> Self {
        let mut table = Self {
            model,
            requests,
            shown: Vec::new(),
        };
        table.hide(hidden);
        table
    }

    /// Shows every column but those with these keys.
    pub fn hide(&mut self, hidden: &[String]) {
        self.shown = (0..COLUMNS.len())
            .filter(|i| {
                COLUMNS
                    .get(*i)
                    .is_none_or(|(key, _, _)| !hidden.iter().any(|h| h == key))
            })
            .collect();
    }
}

/// Asks for the next page of history, if there is one not asked for yet.
pub fn request_page(model: &Entity<Model>, requests: &mpsc::Sender<Request>, cx: &mut App) {
    let next = model.update(cx, |model, _| {
        model
            .events
            .next_page()
            .map(|before| (before, model.events.query.clone()))
    });
    if let Some((before, query)) = next {
        let _ = requests.send(Request::Events { before, query });
    }
}

/// The page: a query over the events, and the table of those it matches.
pub struct EventsPage {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    input: Entity<InputState>,
    table: Entity<TableState<EventsTable>>,
    error: Option<String>,
    /// Where the query's error is, for the highlighting.
    error_span: Option<std::ops::Range<usize>>,
}

impl EventsPage {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        table: Entity<TableState<EventsTable>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let input = cx.new(|cx| {
            InputState::new(window, cx).placeholder(
                "Filter, then Enter: curl  host:*.example.com  -action:allow  time>-1h  bytes>10M",
            )
        });
        cx.subscribe_in(&input, window, |page, input, event, _, cx| {
            let empty = input.read(cx).value().is_empty();
            match event {
                InputEvent::PressEnter { .. } => page.apply(cx),
                // The highlighting and completions follow the typing.
                InputEvent::Change if !empty => cx.notify(),
                // Cleared: back to everything.
                InputEvent::Change if empty && !page.model.read(cx).events.query.is_empty() => {
                    page.apply(cx);
                }
                _ => {}
            }
        })
        .detach();
        Self {
            model,
            requests,
            input,
            table,
            error: None,
            error_span: None,
        }
    }

    fn apply(&mut self, cx: &mut Context<Self>) {
        let text = self.input.read(cx).value().trim().to_owned();
        let filter = if text.is_empty() {
            None
        } else {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            let query_cx = query::Context {
                now_ms,
                uid_of: &uid_of,
            };
            match EventFilter::parse(&text, &query_cx) {
                Ok(filter) => Some(filter),
                Err(e) => {
                    self.error_span = Some(e.span.clone());
                    self.error = Some(format!(
                        "{}: {}",
                        text.get(e.span.clone()).unwrap_or(""),
                        e.message
                    ));
                    cx.notify();
                    return;
                }
            }
        };
        self.error = None;
        self.error_span = None;
        self.model
            .update(cx, |model, _| model.events.set_query(text, filter));
        // New rows: the columns stay as they are.
        self.table.update(cx, |_, cx| cx.notify());
        request_page(&self.model, &self.requests, cx);
        cx.notify();
    }
}

impl EventsPage {
    /// The column chooser: optional columns on and off, kept in the preferences.
    fn columns_menu(&self) -> impl IntoElement {
        let table = self.table.clone();
        Button::new("events-columns")
            .small()
            .label("Columns")
            .dropdown_menu(move |mut menu, _, cx| {
                let hidden = cx
                    .try_global::<crate::prefs::Prefs>()
                    .map_or_else(Vec::new, |p| p.events_hidden.clone());
                for (key, label) in OPTIONAL {
                    let shown = !hidden.iter().any(|h| h == key);
                    let table = table.clone();
                    menu = menu.item(PopupMenuItem::new(label).checked(shown).on_click(
                        move |_, _, cx| {
                            let mut prefs = cx
                                .try_global::<crate::prefs::Prefs>()
                                .cloned()
                                .unwrap_or_default();
                            if shown {
                                prefs.events_hidden.push(key.to_owned());
                            } else {
                                prefs.events_hidden.retain(|h| h != key);
                            }
                            prefs.save();
                            let hidden = prefs.events_hidden.clone();
                            cx.set_global(prefs);
                            table.update(cx, |table, cx| {
                                table.delegate_mut().hide(&hidden);
                                table.refresh(cx);
                            });
                        },
                    ));
                }
                menu
            })
    }
}

/// The events loaded, as CSV.
fn events_csv(model: &Model) -> String {
    let rows = (0..model.events.len())
        .filter_map(|i| model.events.get(i))
        .map(|row| {
            let action = v1::Action::try_from(i32::from(row.action)).map_or_else(
                |_| String::new(),
                |a| a.as_str_name().trim_start_matches("ACTION_").to_lowercase(),
            );
            vec![
                time(row.time_ms),
                action,
                model.events.string(row.exe).unwrap_or("").to_owned(),
                row.pid.to_string(),
                if row.host == 0 {
                    String::new()
                } else {
                    model.events.string(row.host).unwrap_or("").to_owned()
                },
                address(row).to_string(),
                row.port.to_string(),
                protocol(row.protocol).to_string(),
                cell(row, "interface", model).to_string(),
                row.uid.to_string(),
                row.bytes_out.to_string(),
                row.bytes_in.to_string(),
                decided_by(row, model),
            ]
        });
    crate::csv::table(
        &[
            "time",
            "action",
            "program",
            "pid",
            "host",
            "address",
            "port",
            "protocol",
            "interface",
            "uid",
            "sent",
            "received",
            "decided by",
        ],
        rows,
    )
}

impl Render for EventsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let hints = crate::views::query::hints(
            &self.input,
            &crate::views::query::EVENT_KEYS,
            self.error_span.as_ref(),
            window,
            cx,
        );
        v_flex()
            .size_full()
            .child(
                v_flex()
                    .px_4()
                    .py_2()
                    .gap_1()
                    .child(
                        h_flex()
                            .flex_wrap()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(gpui::px(280.))
                                    .child(Input::new(&self.input).cleanable(true)),
                            )
                            .child(self.columns_menu())
                            .child({
                                let model = self.model.clone();
                                Button::new("events-csv")
                                    .small()
                                    .label("Copy CSV")
                                    .tooltip("The events loaded, as CSV")
                                    .on_click(move |_, _, cx| {
                                        let csv = events_csv(model.read(cx));
                                        cx.write_to_clipboard(gpui::ClipboardItem::new_string(csv));
                                    })
                            }),
                    )
                    .child(hints)
                    .children(
                        self.error.clone().map(|error| {
                            div().text_sm().text_color(cx.theme().danger).child(error)
                        }),
                    ),
            )
            .child(DataTable::new(&self.table))
    }
}

/// A user's uid, from this machine's `/etc/passwd`.
pub fn uid_of(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

/// A byte count, as people read it.
#[must_use]
pub fn bytes(count: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = count;
    let mut unit = 0;
    while value >= 10 * 1024 && unit + 1 < UNITS.len() {
        value /= 1024;
        unit += 1;
    }
    format!("{value} {}", UNITS.get(unit).copied().unwrap_or("B"))
}

/// A Unix time in ms, in the local time zone.
#[must_use]
pub fn time(ms: u64) -> String {
    i64::try_from(ms)
        .ok()
        .and_then(|ms| Local.timestamp_millis_opt(ms).single())
        .map_or_else(String::new, |t| t.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// The protocol name of an IP protocol number.
#[must_use]
pub fn protocol(number: u8) -> SharedString {
    match number {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        58 => "icmpv6".into(),
        n => n.to_string().into(),
    }
}

/// An action, as a mark and a word in its colour: filled for allow and deny, hollow for reject (a deny that
/// answers the program).
#[must_use]
pub fn action_tag(action: u8, cx: &App) -> gpui::Div {
    let theme = cx.theme();
    let (word, color, filled) = match v1::Action::try_from(i32::from(action)) {
        Ok(v1::Action::Allow) => ("allow", theme.success, true),
        Ok(v1::Action::Deny) => ("deny", theme.danger, true),
        Ok(v1::Action::Reject) => ("reject", theme.danger, false),
        _ => ("?", theme.muted_foreground, false),
    };
    h_flex()
        .gap_1p5()
        .text_color(color)
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .child(
            div()
                .flex_none()
                .size(gpui::px(8.))
                .rounded(gpui::px(2.))
                .border_1()
                .border_color(color)
                .when(filled, |mark| mark.bg(color)),
        )
        .child(word)
}

fn cell(row: &EventRow, column: &str, model: &Model) -> SharedString {
    match column {
        "time" => time(row.time_ms).into(),
        "rule" => decided_by(row, model).into(),
        "pid" => row.pid.to_string().into(),
        "program" => {
            let program = match model.events.string(row.exe) {
                // A socket older than the daemon, or a process gone before it was seen (or a VM's: no program).
                Some("") | None => "(unknown program)",
                Some(exe) => exe,
            };
            // A container's (or VM's, or named namespace's) connection says whose it is first.
            match model
                .events
                .string(row.container)
                .filter(|_| row.container != 0)
            {
                Some(key) => {
                    let context = snitchhiker_core::context::Container::from_key(key);
                    format!(
                        "[{} {}] {program}",
                        context.runtime,
                        context.compose.as_deref().unwrap_or(&context.name)
                    )
                    .into()
                }
                None => program.to_owned().into(),
            }
        }
        "destination" => match model.events.string(row.host) {
            Some(host) if row.host != 0 => host.to_owned().into(),
            _ => address(row).to_string().into(),
        },
        "port" => format!("{}/{}", row.port, protocol(row.protocol)).into(),
        "interface" => model
            .events
            .string(row.interface)
            .filter(|_| row.interface != 0)
            .unwrap_or("")
            .to_owned()
            .into(),
        "user" => row.uid.to_string().into(),
        "out" => bytes(row.bytes_out).into(),
        "in" => bytes(row.bytes_in).into(),
        _ => SharedString::default(),
    }
}

/// What decided a connection: its rule (by folder and name), or what decided when no rule did.
fn decided_by(row: &EventRow, model: &Model) -> String {
    let list = &model.rules;
    match v1::Source::try_from(i32::from(row.source)) {
        Ok(v1::Source::Rule) => list.rules.iter().find(|r| r.id == row.rule).map_or_else(
            || format!("rule {} (deleted)", row.rule),
            |r| {
                format!(
                    "{}{}",
                    crate::views::rules::folder_path(list, r.folder),
                    r.name
                )
            },
        ),
        Ok(v1::Source::Policy) => "no rule: the policy".to_owned(),
        Ok(v1::Source::Monitor) => "passed (monitor mode)".to_owned(),
        Ok(v1::Source::Prompt) => "an answer to a prompt".to_owned(),
        Ok(v1::Source::Timeout) => "a prompt nobody answered".to_owned(),
        Ok(v1::Source::Unspecified) | Err(_) => String::new(),
    }
}

/// Columns whose numbers line up on the right, as their headers do.
fn numeric(key: &str) -> bool {
    matches!(key, "pid" | "out" | "in")
}

impl TableDelegate for EventsTable {
    fn columns_count(&self, _: &App) -> usize {
        self.shown.len()
    }

    fn rows_count(&self, cx: &App) -> usize {
        self.model.read(cx).events.len()
    }

    fn column(&self, col_ix: usize, cx: &App) -> Column {
        let col_ix = self.shown.get(col_ix).copied().unwrap_or(usize::MAX);
        let (key, name, width) = COLUMNS.get(col_ix).copied().unwrap_or(("", "", 100.));
        let column = Column::new(key, name).width(crate::columns::width(cx, "events", key, width));
        if numeric(key) {
            column.text_right()
        } else {
            column
        }
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let col_ix = self.shown.get(col_ix).copied().unwrap_or(usize::MAX);
        let model = self.model.read(cx);
        let Some(row) = model.events.get(row_ix) else {
            return div().into_any_element();
        };
        let key = COLUMNS.get(col_ix).map_or("", |(key, _, _)| *key);
        if key == "action" {
            return action_tag(row.action, cx).into_any_element();
        }
        if key == "why" {
            let (model, requests, seq) = (self.model.clone(), self.requests.clone(), row.seq);
            return Button::new(SharedString::from(format!("why-{seq}")))
                .small()
                .ghost()
                .icon(IconName::Info)
                .tooltip("Why was it decided so?")
                .on_click(move |_, window, cx| {
                    explain::open(model.clone(), requests.clone(), seq, window, cx);
                })
                .into_any_element();
        }
        let text = cell(row, key, model);
        let line = h_flex()
            .w_full()
            .overflow_hidden()
            .text_ellipsis()
            // Times, paths, addresses and counts in the monospace face; the user's name not.
            .when(!matches!(key, "user" | "rule"), |line| {
                line.font_family(cx.theme().mono_font_family.clone())
            });
        if numeric(key) {
            line.justify_end()
        } else {
            line
        }
        .child(clipped(
            SharedString::from(format!("event-{row_ix}-{key}")),
            text,
        ))
        .into_any_element()
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        h_flex()
            .size_full()
            .justify_center()
            .text_color(cx.theme().muted_foreground)
            .child("No connections recorded yet")
    }

    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: PopupMenu,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> PopupMenu {
        let model = self.model.read(cx);
        let Some(row) = model.events.get(row_ix).copied() else {
            return menu;
        };
        let line = crate::csv::table(
            &["time", "program", "destination", "port"],
            [vec![
                time(row.time_ms),
                model.events.string(row.exe).unwrap_or("").to_owned(),
                cell(&row, "destination", model).to_string(),
                cell(&row, "port", model).to_string(),
            ]],
        );
        let (explaining, requests) = (self.model.clone(), self.requests.clone());
        menu.item(
            PopupMenuItem::new("Why was it decided so?").on_click(move |_, window, cx| {
                explain::open(explaining.clone(), requests.clone(), row.seq, window, cx);
            }),
        )
        .item(PopupMenuItem::new("Copy as CSV").on_click(move |_, _, cx| {
            cx.write_to_clipboard(gpui::ClipboardItem::new_string(line.clone()));
        }))
    }

    fn has_more(&self, cx: &App) -> bool {
        self.model.read(cx).events.more
    }

    fn load_more(&mut self, _: &mut Window, cx: &mut Context<TableState<Self>>) {
        request_page(&self.model, &self.requests, cx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_read_well() {
        assert_eq!(bytes(517), "517 B");
        assert_eq!(bytes(10 * 1024), "10 KiB");
        assert_eq!(bytes(25 * 1024 * 1024), "25 MiB");
    }
}
