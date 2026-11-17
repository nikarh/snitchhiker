//! Connections: the machine's live TCP connections and connected UDP sockets, with their programs; one can be closed,
//! as a reject would.

use std::sync::mpsc;

use gpui::{
    App, Context, Entity, IntoElement, ParentElement as _, SharedString, Styled as _, Window, div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::table::{Column, ColumnSort, TableDelegate, TableState};
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex};
use snitchhiker_proto::{convert, v1};

use crate::backend::Request;
use crate::model::Model;
use crate::views::events::{bytes, protocol};
use crate::views::text::clipped;

const COLUMNS: [(&str, &str, f32); 7] = [
    ("state", "State", 130.),
    ("program", "Program", 240.),
    ("remote", "Remote", 260.),
    ("user", "User", 60.),
    ("out", "Sent", 80.),
    ("in", "Received", 84.),
    ("close", "", 80.),
];

pub struct ConnectionsTable {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    /// Indices into the model's connections, in the order shown.
    order: Vec<usize>,
    /// The column sorted by, and whether descending.
    sort: Option<(usize, bool)>,
}

impl ConnectionsTable {
    #[must_use]
    pub fn new(model: Entity<Model>, requests: mpsc::Sender<Request>) -> Self {
        Self {
            model,
            requests,
            order: Vec::new(),
            sort: None,
        }
    }

    /// Orders the connections as listed, then by the column chosen.
    pub fn recompute(&mut self, cx: &App) {
        let connections = &self.model.read(cx).connections;
        self.order = (0..connections.len()).collect();
        if let Some((column, descending)) = self.sort {
            self.order.sort_by(|a, b| {
                let (Some(a), Some(b)) = (connections.get(*a), connections.get(*b)) else {
                    return std::cmp::Ordering::Equal;
                };
                let order = match column {
                    0 => (a.protocol, &a.state).cmp(&(b.protocol, &b.state)),
                    1 => a.exe.cmp(&b.exe),
                    2 => (&a.host, &a.remote, a.remote_port).cmp(&(
                        &b.host,
                        &b.remote,
                        b.remote_port,
                    )),
                    3 => a.uid.cmp(&b.uid),
                    4 => a.bytes_out.cmp(&b.bytes_out),
                    _ => a.bytes_in.cmp(&b.bytes_in),
                };
                if descending { order.reverse() } else { order }
            });
        }
    }
}

/// An address and port as people read them.
fn endpoint(address: &[u8], port: u32) -> String {
    convert::address_from(address).map_or_else(String::new, |a| {
        std::net::SocketAddr::new(a, u16::try_from(port).unwrap_or(0)).to_string()
    })
}

/// The connections, as CSV.
#[must_use]
pub fn csv(connections: &[v1::LiveConnection]) -> String {
    let rows = connections.iter().map(|c| {
        vec![
            protocol(u8::try_from(c.protocol).unwrap_or(0)).to_string(),
            c.state.clone(),
            c.exe.clone(),
            endpoint(&c.local, c.local_port),
            endpoint(&c.remote, c.remote_port),
            c.host.clone(),
            c.uid.to_string(),
            c.bytes_out.to_string(),
            c.bytes_in.to_string(),
        ]
    });
    crate::csv::table(
        &[
            "protocol", "state", "program", "local", "remote", "host", "uid", "sent", "received",
        ],
        rows,
    )
}

impl TableDelegate for ConnectionsTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.order.len()
    }

    fn column(&self, col_ix: usize, cx: &App) -> Column {
        let (key, name, width) = COLUMNS.get(col_ix).copied().unwrap_or(("", "", 100.));
        let column =
            Column::new(key, name).width(crate::columns::width(cx, "connections", key, width));
        if col_ix < 6 {
            column.sortable()
        } else {
            column
        }
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        self.sort = match sort {
            ColumnSort::Default => None,
            ColumnSort::Ascending => Some((col_ix, false)),
            ColumnSort::Descending => Some((col_ix, true)),
        };
        self.recompute(cx);
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let Some(c) = self
            .order
            .get(row_ix)
            .and_then(|i| self.model.read(cx).connections.get(*i))
            .cloned()
        else {
            return div().into_any_element();
        };
        let text = |text: String| {
            div()
                .overflow_hidden()
                .text_ellipsis()
                .child(clipped(
                    SharedString::from(format!("connection-{row_ix}-{col_ix}")),
                    text,
                ))
                .into_any_element()
        };
        match col_ix {
            0 => text(format!(
                "{} {}",
                protocol(u8::try_from(c.protocol).unwrap_or(0)),
                c.state
            )),
            1 if c.exe.is_empty() => div()
                .text_color(cx.theme().muted_foreground)
                .child("(inbound, or older than the daemon)")
                .into_any_element(),
            1 => text(c.exe.clone()),
            2 if c.host.is_empty() => text(endpoint(&c.remote, c.remote_port)),
            2 => text(format!("{}:{}", c.host, c.remote_port)),
            3 => text(c.uid.to_string()),
            4 => text(bytes(c.bytes_out)),
            5 => text(bytes(c.bytes_in)),
            6 => {
                let requests = self.requests.clone();
                Button::new(SharedString::from(format!("close-{row_ix}")))
                    .small()
                    .ghost()
                    .label("Close")
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::Kill(v1::KillConnection {
                            protocol: c.protocol,
                            local: c.local.clone(),
                            local_port: c.local_port,
                            remote: c.remote.clone(),
                            remote_port: c.remote_port,
                        }));
                        let _ = requests.send(Request::Connections);
                    })
                    .into_any_element()
            }
            _ => div().into_any_element(),
        }
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
            .child("No live connections")
    }
}
