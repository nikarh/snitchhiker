//! Events: every connection the node decided, newest first, in a virtualized table that loads older history as it is
//! scrolled down. Live events arrive at the top.

use std::sync::mpsc;

use chrono::{Local, TimeZone as _};
use gpui::{
    App, Context, Entity, IntoElement, ParentElement as _, SharedString, Styled as _, Window, div,
};
use gpui_component::table::{Column, TableDelegate, TableState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, h_flex};
use snitchhiker_proto::columns::EventRow;
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::{Model, address};

const COLUMNS: [(&str, &str, f32); 8] = [
    ("time", "Time", 165.),
    ("action", "Action", 76.),
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
    /// The oldest seq a page was asked for, so one isn't asked twice.
    requested: Option<i64>,
}

impl EventsTable {
    #[must_use]
    pub fn new(model: Entity<Model>, requests: mpsc::Sender<Request>) -> Self {
        Self {
            model,
            requests,
            requested: None,
        }
    }
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
        if col_ix >= 6 {
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
        let Some(oldest) = self.model.read(cx).events.oldest() else {
            return;
        };
        if self.requested == Some(oldest) {
            return;
        }
        self.requested = Some(oldest);
        let _ = self.requests.send(Request::Events { before: oldest });
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
