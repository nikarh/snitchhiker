//! Status: the node, its mode and policy, its counters, and the connection to it.

use gpui::{Context, Entity, IntoElement, ParentElement as _, Render, Styled as _, Window, div};
use gpui_component::{ActiveTheme as _, h_flex, v_flex};

use crate::model::Model;

pub struct Status {
    model: Entity<Model>,
}

impl Status {
    pub fn new(model: Entity<Model>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self { model }
    }
}

fn row(name: &str, value: String, muted: gpui::Hsla) -> impl IntoElement {
    h_flex()
        .gap_4()
        .child(div().w_48().text_color(muted).child(name.to_owned()))
        .child(div().child(value))
}

impl Render for Status {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let model = self.model.read(cx);
        let muted = cx.theme().muted_foreground;
        let mut page = v_flex().p_4().gap_2();
        match (&model.node, &model.disconnected) {
            (_, Some(reason)) => {
                page = page.child(row("Connection", format!("not connected: {reason}"), muted));
            }
            (Some(node), None) => {
                page = page
                    .child(row("Node", node.node_name.clone(), muted))
                    .child(row("Daemon", node.daemon_version.clone(), muted));
            }
            (None, None) => page = page.child(row("Connection", "connecting…".to_owned(), muted)),
        }
        if let Some(status) = &model.status {
            let name = |text: &str, prefix: &str| text.trim_start_matches(prefix).to_lowercase();
            page = page
                .child(row(
                    "Mode",
                    name(status.mode().as_str_name(), "MODE_"),
                    muted,
                ))
                .child(row(
                    "No rule matches",
                    name(status.no_match().as_str_name(), "POLICY_"),
                    muted,
                ))
                .child(row(
                    "When stopped",
                    if status.fail_open { "open" } else { "closed" }.to_owned(),
                    muted,
                ))
                .child(row("Rules", status.rules.to_string(), muted))
                .child(row(
                    "Connections decided",
                    status.decided.to_string(),
                    muted,
                ))
                .child(row(
                    "Prompts waiting",
                    status.pending_prompts.to_string(),
                    muted,
                ))
                .child(row("Clients", status.clients.to_string(), muted));
        }
        if let Some(error) = &model.error {
            page = page.child(row("Last error", error.clone(), muted));
        }
        page
    }
}
