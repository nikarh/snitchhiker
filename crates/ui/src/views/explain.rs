//! Why a recorded connection is decided as it is: every rule that matches it now, the deciding one first.

use std::sync::mpsc;

use gpui::{
    App, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render, SharedString,
    Styled as _, Window, div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_proto::{convert, v1};

use crate::backend::Request;
use crate::model::Model;
use crate::views::editor;
use crate::views::events::{action_tag, protocol};
use crate::views::text::clipped;

pub struct Explain {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    seq: i64,
}

impl Explain {
    fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        seq: i64,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            requests,
            seq,
        }
    }
}

/// A tier's name.
fn tier(tier: v1::Tier) -> &'static str {
    match tier {
        v1::Tier::Override => "override",
        v1::Tier::Fallback => "fallback",
        v1::Tier::Normal | v1::Tier::Unspecified => "normal",
    }
}

impl Render for Explain {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let model = self.model.read(cx);
        let explanation = model
            .explanation
            .as_ref()
            .filter(|e| e.event.as_ref().is_some_and(|e| e.seq == self.seq));
        let Some(explanation) = explanation else {
            return v_flex()
                .text_color(muted)
                .child("Asking the node…")
                .into_any_element();
        };
        let mut list = v_flex().gap_2();
        if let Some(event) = &explanation.event {
            let port = u16::try_from(event.port).unwrap_or(0);
            let destination = if event.host.is_empty() {
                convert::address_from(&event.address).map_or_else(String::new, |a| {
                    std::net::SocketAddr::new(a, port).to_string()
                })
            } else {
                format!("{}:{port}", event.host)
            };
            list = list.child(div().pb_2().child(format!(
                "{} → {destination}/{}",
                if event.exe.is_empty() {
                    "?"
                } else {
                    &event.exe
                },
                protocol(u8::try_from(event.protocol).unwrap_or(0)),
            )));
        }
        if explanation.rules.is_empty() {
            list = list.child(
                "No rule matches this connection now: it would be prompted for, or decided by the default action.",
            );
        }
        for (i, rule) in explanation.rules.iter().enumerate() {
            let full = model.rules.rules.iter().find(|r| r.id == rule.id).cloned();
            let (model, requests) = (self.model.clone(), self.requests.clone());
            list = list.child(
                h_flex()
                    .gap_3()
                    .child(
                        div()
                            .w_24()
                            .flex_none()
                            .whitespace_nowrap()
                            .text_color(muted)
                            .child(if i == 0 { "decides" } else { "outranked" }),
                    )
                    .child(action_tag(u8::try_from(rule.action).unwrap_or(0), cx))
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(clipped(
                                SharedString::from(format!("explain-rule-{}", rule.id)),
                                if rule.name.is_empty() {
                                    format!("rule {}", rule.id)
                                } else {
                                    rule.name.clone()
                                },
                            )),
                    )
                    .child(Tag::secondary().child(tier(rule.tier())))
                    .child(
                        div()
                            .text_color(muted)
                            .child(format!("specificity {}", rule.specificity)),
                    )
                    .children(full.map(|full| {
                        Button::new(SharedString::from(format!("explain-edit-{}", rule.id)))
                            .small()
                            .ghost()
                            .label("Edit")
                            .on_click(move |_, window, cx| {
                                window.close_dialog(cx);
                                editor::open(
                                    model.clone(),
                                    requests.clone(),
                                    Some(full.clone()),
                                    window,
                                    cx,
                                );
                            })
                    })),
            );
        }
        if explanation.partial {
            list = list.child(div().text_color(muted).child(
                "Rules on command lines or parent processes aren't checked: the history doesn't keep them.",
            ));
        }
        list.into_any_element()
    }
}

/// Asks the node why event `seq` is decided as it is, and shows the answer in a dialog.
pub fn open(
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    seq: i64,
    window: &mut Window,
    cx: &mut App,
) {
    let _ = requests.send(Request::Explain { seq });
    let explain = cx.new(|cx| Explain::new(model, requests, seq, cx));
    window.open_dialog(cx, move |dialog, _, _| {
        dialog.title("Why").w(gpui::px(720.)).child(explain.clone())
    });
}
