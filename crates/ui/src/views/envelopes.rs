//! Envelopes: bounds within which allow-listed agents' proposals are approved without asking, shown under the
//! proposals. Adding or removing one is a dangerous action (the daemon asks for a password).

use std::sync::mpsc;

use gpui::{
    AnyElement, App, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, Window, div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;

/// The envelopes, with buttons to add and remove them.
pub fn section(
    envelopes: Option<&v1::Envelopes>,
    requests: &mpsc::Sender<Request>,
    cx: &App,
) -> AnyElement {
    let muted = cx.theme().muted_foreground;
    let adding = requests.clone();
    let mut section = v_flex()
        .gap_2()
        .child(
            h_flex()
                .gap_2()
                .child(div().flex_1().text_lg().child("Envelopes"))
                .child(
                    Button::new("envelope-add")
                        .small()
                        .label("Add envelope")
                        .on_click(move |_, window, cx| open_add(adding.clone(), window, cx)),
                ),
        )
        .child(div().text_sm().text_color(muted).child(
            "Proposals from allow-listed agents that stay inside an envelope are approved without asking, for the \
             agent's session, and an alert says so. Anything else waits for you.",
        ));
    let list = envelopes.map_or_default(|e| e.envelopes.as_slice());
    if list.is_empty() {
        section = section.child(
            div()
                .text_color(muted)
                .child("No envelopes: every proposal waits for you."),
        );
    }
    for envelope in list {
        let requests = requests.clone();
        let id = envelope.id;
        let toggled = v1::Envelope {
            enabled: !envelope.enabled,
            ..envelope.clone()
        };
        let toggling = requests.clone();
        section = section.child(
            v_flex()
                .gap_1()
                .py_2()
                .border_b_1()
                .border_color(cx.theme().border)
                .child(
                    h_flex()
                        .gap_2()
                        .child(div().flex_1().child(format!(
                            "{}{}",
                            envelope.name,
                            if envelope.enabled { "" } else { " (off)" }
                        )))
                        .child(
                            Button::new(SharedString::from(format!("envelope-toggle-{id}")))
                                .small()
                                .ghost()
                                .label(if envelope.enabled {
                                    "Turn off"
                                } else {
                                    "Turn on"
                                })
                                .on_click(move |_, _, _| {
                                    let _ = toggling.send(Request::PutEnvelope(toggled.clone()));
                                }),
                        )
                        .child(
                            Button::new(SharedString::from(format!("envelope-remove-{id}")))
                                .small()
                                .ghost()
                                .label("Remove")
                                .on_click(move |_, _, _| {
                                    let _ = requests.send(Request::DeleteEnvelope(id));
                                }),
                        ),
                )
                .child(div().text_sm().child(describe(envelope))),
        );
    }
    section.into_any_element()
}

/// What an envelope lets through, in words.
#[must_use]
pub fn describe(e: &v1::Envelope) -> String {
    format!(
        "{} working in {} may reach {}{}{}",
        if e.agents.is_empty() {
            "Allow-listed agents".to_owned()
        } else {
            format!("Agents {}", e.agents.join(", "))
        },
        e.project,
        e.hosts.join(", "),
        if e.ports.is_empty() {
            String::new()
        } else {
            format!(" on port {}", e.ports.join(", "))
        },
        if e.programs.is_empty() {
            String::new()
        } else {
            format!(", with {}", e.programs.join(", "))
        },
    )
}

struct AddForm {
    name: Entity<InputState>,
    project: Entity<InputState>,
    hosts: Entity<InputState>,
    ports: Entity<InputState>,
    programs: Entity<InputState>,
}

impl AddForm {
    fn envelope(&self, cx: &App) -> v1::Envelope {
        let text = |i: &Entity<InputState>| i.read(cx).value().trim().to_owned();
        let list = |i: &Entity<InputState>| {
            text(i)
                .split([',', ' '])
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        v1::Envelope {
            name: text(&self.name),
            enabled: true,
            project: text(&self.project),
            hosts: list(&self.hosts),
            ports: list(&self.ports),
            programs: list(&self.programs),
            ..v1::Envelope::default()
        }
    }
}

impl Render for AddForm {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let field = |label: &'static str, input: &Entity<InputState>| {
            h_flex()
                .gap_3()
                .child(div().w(px(150.)).flex_none().text_color(muted).child(label))
                .child(div().flex_1().child(Input::new(input)))
        };
        v_flex()
            .gap_2()
            .child(field("Name", &self.name))
            .child(field("Project", &self.project))
            .child(field("Hosts", &self.hosts))
            .child(field("Ports", &self.ports))
            .child(field("Programs", &self.programs))
            .child(div().text_sm().text_color(muted).child(
                "Hosts are names, or *.name for a name's subdomains; no addresses. Empty ports and programs mean any. \
                 Saving asks for a password: an envelope lets agents in without you.",
            ))
    }
}

fn open_add(requests: mpsc::Sender<Request>, window: &mut Window, cx: &mut App) {
    let input =
        |placeholder: &'static str, value: &'static str, window: &mut Window, cx: &mut App| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(placeholder)
                    .default_value(value)
            })
        };
    let form = AddForm {
        name: input("Package registries", "", window, cx),
        project: input(
            "glob:{home}/workspace/**",
            "glob:{home}/workspace/**",
            window,
            cx,
        ),
        hosts: input("registry.npmjs.org, crates.io, *.crates.io", "", window, cx),
        ports: input("443", "443", window, cx),
        programs: input("glob:{home}/.cargo/bin/*", "", window, cx),
    };
    let form = cx.new(|_| form);
    window.open_dialog(cx, move |dialog, _, _| {
        let (saving, requests) = (form.clone(), requests.clone());
        dialog
            .title("Add an envelope")
            .w(px(680.))
            .child(form.clone())
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("envelope-cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(
                        Button::new("envelope-save")
                            .primary()
                            .label("Add")
                            .on_click(move |_, window, cx| {
                                let envelope = saving.read(cx).envelope(cx);
                                let _ = requests.send(Request::PutEnvelope(envelope));
                                window.close_dialog(cx);
                            }),
                    ),
            )
    });
}
