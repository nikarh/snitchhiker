//! Blocklists: lists of domains and addresses the node fetches on a schedule, for rules' `list` condition.

use std::sync::mpsc;

use gpui::{
    AnyElement, App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, StatefulInteractiveElement as _, Styled as _, Window,
    div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;
use crate::views::events::time;
use crate::views::text::clipped;

pub struct Blocklists {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl Blocklists {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self { model, requests }
    }

    pub fn refresh(&self) {
        let _ = self.requests.send(Request::Blocklists);
    }

    fn list(&self, index: usize, list: &v1::Blocklist, cx: &App) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let every = match list.refresh_secs {
            s if s % 86_400 == 0 => format!("every {} d", s / 86_400),
            s if s % 3600 == 0 => format!("every {} h", s / 3600),
            s => format!("every {} min", s / 60),
        };
        let state = if list.checked_ms == 0 {
            "not fetched yet".to_owned()
        } else {
            format!(
                "{} entries, {} kB{}; changed {}, fetched {}, {every}",
                list.entries,
                list.bytes / 1000,
                if list.invalid > 0 {
                    format!(" ({} lines skipped)", list.invalid)
                } else {
                    String::new()
                },
                if list.updated_ms == 0 {
                    "never".to_owned()
                } else {
                    time(list.updated_ms)
                },
                time(list.checked_ms),
            )
        };
        let used = match list.rules.len() {
            0 => "No rule names it yet: add one with this list as its Blocklist condition."
                .to_owned(),
            n => format!(
                "Named by {n} rule{}; decided {} connections since the daemon started.",
                if n == 1 { "" } else { "s" },
                list.matched
            ),
        };
        let requests = self.requests.clone();
        let name = list.name.clone();
        let refresh = Button::new(SharedString::from(format!("list-refresh-{index}")))
            .small()
            .ghost()
            .label("Fetch now")
            .on_click(move |_, _, _| {
                let _ = requests.send(Request::RefreshBlocklist(name.clone()));
            });
        let requests = self.requests.clone();
        let name = list.name.clone();
        let remove = Button::new(SharedString::from(format!("list-remove-{index}")))
            .small()
            .ghost()
            .label("Remove")
            .on_click(move |_, _, _| {
                let _ = requests.send(Request::DeleteBlocklist(name.clone()));
            });
        v_flex()
            .gap_1()
            .py_2()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(list.name.clone()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .text_color(muted)
                            .child(clipped(
                                SharedString::from(format!("list-source-{index}")),
                                list.source.clone(),
                            )),
                    )
                    .child(refresh)
                    .child(remove),
            )
            .child(div().text_sm().child(state))
            .children((!list.error.is_empty()).then(|| {
                h_flex()
                    .gap_2()
                    .child(Tag::warning().small().child("Last fetch failed"))
                    .child(div().text_sm().child(list.error.clone()))
            }))
            .child(div().text_sm().text_color(muted).child(used))
            .into_any_element()
    }
}

impl Render for Blocklists {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let lists = self.model.read(cx).blocklists.clone();
        let requests = self.requests.clone();
        v_flex()
            .id("blocklists")
            .size_full()
            .overflow_y_scroll()
            .p_4()
            .gap_2()
            .child(
                h_flex()
                    .gap_2()
                    .child(div().flex_1())
                    .child(
                        Button::new("list-add")
                            .small()
                            .primary()
                            .label("Add list")
                            .on_click(move |_, window, cx| open_add(requests.clone(), window, cx)),
                    ),
            )
            .child(div().text_color(muted).child(
                "Lists of domains and addresses (hosts files, a domain per line, adblock ||domain^ rules, \
                 addresses and networks), fetched over HTTPS on a schedule. A rule with a list as its \
                 Blocklist condition decides what is on it: a deny rule blocks it.",
            ))
            .children(match &lists {
                None => vec![div().text_color(muted).child("Loading…").into_any_element()],
                Some(lists) if lists.lists.is_empty() => vec![
                    div()
                        .text_color(muted)
                        .child("No blocklists yet.")
                        .into_any_element(),
                ],
                Some(lists) => lists
                    .lists
                    .iter()
                    .enumerate()
                    .map(|(i, list)| self.list(i, list, cx))
                    .collect(),
            })
    }
}

/// The add dialog.
struct AddForm {
    name: Entity<InputState>,
    source: Entity<InputState>,
    hours: Entity<InputState>,
}

impl Render for AddForm {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let field = |label: &'static str, element: AnyElement| {
            h_flex()
                .gap_3()
                .child(div().w(px(150.)).flex_none().text_color(muted).child(label))
                .child(div().flex_1().child(element))
        };
        v_flex()
            .gap_2()
            .child(field("Name", Input::new(&self.name).into_any_element()))
            .child(field("URL or path", Input::new(&self.source).into_any_element()))
            .child(field("Every (hours)", Input::new(&self.hours).into_any_element()))
            .child(div().text_sm().text_color(muted).child(
                "Rules name the list by its name. The list is fetched now: if it's too large, isn't a list, or the \
                 server can't be reached, it says why.",
            ))
    }
}

fn open_add(requests: mpsc::Sender<Request>, window: &mut Window, cx: &mut App) {
    let input = |placeholder: &'static str, value: &str, window: &mut Window, cx: &mut App| {
        let value = value.to_owned();
        cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(placeholder)
                .default_value(value)
        })
    };
    let form = AddForm {
        name: input("ads", "", window, cx),
        source: input("https://example.com/hosts.txt", "", window, cx),
        hours: input("24", "24", window, cx),
    };
    let form = cx.new(|_| form);
    window.open_dialog(cx, move |dialog, _, _| {
        let (saving, requests) = (form.clone(), requests.clone());
        dialog
            .title("Add a blocklist")
            .w(px(640.))
            .child(form.clone())
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("list-cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(Button::new("list-save").primary().label("Add").on_click(
                        move |_, window, cx| {
                            let form = saving.read(cx);
                            let text =
                                |i: &Entity<InputState>| i.read(cx).value().trim().to_owned();
                            let hours: u64 = text(&form.hours).parse().unwrap_or(24);
                            let _ = requests.send(Request::PutBlocklist(v1::PutBlocklist {
                                name: text(&form.name),
                                source: text(&form.source),
                                refresh_secs: hours.saturating_mul(3600),
                            }));
                            window.close_dialog(cx);
                        },
                    )),
            )
    });
}
