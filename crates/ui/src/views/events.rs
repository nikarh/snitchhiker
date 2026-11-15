//! Events: every connection the node decided, newest first, in a virtualized table that loads older history as it is
//! scrolled down. Live events arrive at the top.

use std::sync::mpsc;

use chrono::{Local, TimeZone as _};
use gpui::{
    App, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render, SharedString,
    Styled as _, Window, div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::table::DataTable;
use gpui_component::table::{Column, TableDelegate, TableState};
use gpui_component::tag::Tag;
use gpui_component::v_flex;
use gpui_component::{ActiveTheme as _, IconName, Sizable as _, h_flex};
use snitchhiker_core::query::{self, EventFilter};
use snitchhiker_proto::columns::EventRow;
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::{Model, address};
use crate::views::explain;

const COLUMNS: [(&str, &str, f32); 9] = [
    ("time", "Time", 165.),
    ("action", "Action", 76.),
    ("why", "", 44.),
    ("program", "Program", 240.),
    ("destination", "Destination", 210.),
    ("port", "Port", 84.),
    ("user", "User", 60.),
    ("out", "Sent", 80.),
    ("in", "Received", 84.),
];

pub struct EventsTable {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl EventsTable {
    #[must_use]
    pub fn new(model: Entity<Model>, requests: mpsc::Sender<Request>) -> Self {
        Self { model, requests }
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
        self.model
            .update(cx, |model, _| model.events.set_query(text, filter));
        self.table.update(cx, TableState::refresh);
        request_page(&self.model, &self.requests, cx);
        cx.notify();
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
                if row.host == 0 {
                    String::new()
                } else {
                    model.events.string(row.host).unwrap_or("").to_owned()
                },
                address(row).to_string(),
                row.port.to_string(),
                protocol(row.protocol).to_string(),
                row.uid.to_string(),
                row.bytes_out.to_string(),
                row.bytes_in.to_string(),
            ]
        });
    crate::csv::table(
        &[
            "time", "action", "program", "host", "address", "port", "protocol", "uid", "sent",
            "received",
        ],
        rows,
    )
}

impl Render for EventsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .child(
                v_flex()
                    .p_2()
                    .gap_1()
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .child(Input::new(&self.input).cleanable(true)),
                            )
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
fn uid_of(name: &str) -> Option<u32> {
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

/// An action's tag.
#[must_use]
pub fn action_tag(action: u8) -> Tag {
    match v1::Action::try_from(i32::from(action)) {
        Ok(v1::Action::Allow) => Tag::success().child("allow"),
        Ok(v1::Action::Deny) => Tag::danger().child("deny"),
        Ok(v1::Action::Reject) => Tag::warning().child("reject"),
        _ => Tag::secondary().child("?"),
    }
}

fn cell(row: &EventRow, column: usize, model: &Model) -> SharedString {
    match column {
        0 => time(row.time_ms).into(),
        2 => model
            .events
            .string(row.exe)
            .unwrap_or("?")
            .to_owned()
            .into(),
        3 => match model.events.string(row.host) {
            Some(host) if row.host != 0 => host.to_owned().into(),
            _ => address(row).to_string().into(),
        },
        4 => format!("{}/{}", row.port, protocol(row.protocol)).into(),
        5 => row.uid.to_string().into(),
        6 => bytes(row.bytes_out).into(),
        7 => bytes(row.bytes_in).into(),
        _ => SharedString::default(),
    }
}

impl TableDelegate for EventsTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, cx: &App) -> usize {
        self.model.read(cx).events.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (key, name, width) = COLUMNS.get(col_ix).copied().unwrap_or(("", "", 100.));
        let column = Column::new(key, name).width(width);
        if col_ix >= 7 {
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
        let model = self.model.read(cx);
        let Some(row) = model.events.get(row_ix) else {
            return div().into_any_element();
        };
        if col_ix == 1 {
            return action_tag(row.action).into_any_element();
        }
        if col_ix == 2 {
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
        // The columns of `cell`, which doesn't have the info button's.
        let col_ix = if col_ix > 2 { col_ix - 1 } else { col_ix };
        let text = cell(row, col_ix, model);
        let line = h_flex().w_full().overflow_hidden().text_ellipsis();
        // The byte counts line up on the right, as their headers do.
        if col_ix >= 6 {
            line.justify_end()
        } else {
            line
        }
        .child(text)
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
