//! The system firewall: the base packet filter beside the application rules (inbound and forward policies, and rules
//! over protocols, addresses, ports, interfaces and connection state). Changes are made to a draft and applied
//! together; the node checks them and records them in the history.

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
use crate::views::text::clipped;

pub struct SystemPage {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    /// The firewall as edited here, until applied or discarded; `None`: as the node has it.
    draft: Option<v1::SystemFirewall>,
}

impl SystemPage {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            requests,
            draft: None,
        }
    }

    pub fn refresh(&self) {
        let _ = self.requests.send(Request::SystemFirewall);
    }

    /// Changes the draft (made from the node's firewall when there is none yet).
    fn edit(&mut self, cx: &mut Context<Self>, change: impl FnOnce(&mut v1::SystemFirewall)) {
        let Some(current) = self
            .draft
            .clone()
            .or_else(|| self.model.read(cx).system.clone())
        else {
            return;
        };
        let mut draft = current;
        change(&mut draft);
        self.draft = Some(draft);
        cx.notify();
    }
}

fn name(text: &str, prefix: &str) -> String {
    text.trim_start_matches(prefix).to_lowercase()
}

/// A firewall as the protocol has it.
#[must_use]
pub fn wire(firewall: &snitchhiker_core::system::Firewall) -> v1::SystemFirewall {
    snitchhiker_proto::system::firewall(firewall, 0)
}

/// A rule on one line: `tcp dport 22 from 10.0.0.0/8`.
#[must_use]
pub fn summary(rule: &v1::SystemRule) -> String {
    let mut parts = Vec::new();
    for (key, value) in [
        ("", rule.protocol.clone()),
        ("from", rule.source.join(", ")),
        ("to", rule.destination.join(", ")),
        ("sport", rule.source_ports.clone()),
        ("dport", rule.destination_ports.clone()),
        ("in", rule.in_interface.clone()),
        ("out", rule.out_interface.clone()),
        ("state", rule.ct_state.join(",")),
        ("", rule.icmp_types.join(", ")),
    ] {
        if !value.is_empty() {
            parts.push(if key.is_empty() {
                value
            } else {
                format!("{key} {value}")
            });
        }
    }
    if parts.is_empty() {
        "everything".to_owned()
    } else {
        parts.join(" ")
    }
}

impl SystemPage {
    fn choice(
        id: String,
        label: &'static str,
        on: bool,
        cx: &mut Context<Self>,
        change: impl Fn(&mut v1::SystemFirewall) + 'static,
    ) -> Button {
        let button = Button::new(SharedString::from(id))
            .small()
            .label(label)
            .on_click(cx.listener(move |page, _, _, cx| page.edit(cx, &change)));
        if on { button.primary() } else { button.ghost() }
    }

    fn header(firewall: &v1::SystemFirewall, cx: &mut Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let row = |title: &'static str, description: &'static str, choices: AnyElement| {
            h_flex()
                .gap_4()
                .py_1()
                .child(
                    v_flex()
                        .w(px(300.))
                        .flex_none()
                        .child(title)
                        .child(div().text_sm().text_color(muted).child(description)),
                )
                .child(choices)
        };
        let enabled = firewall.enabled;
        let input = firewall.input() == v1::ChainPolicy::Drop;
        let forward = firewall.forward() == v1::ChainPolicy::Drop;
        v_flex()
            .child(row(
                "System firewall",
                "The base packet filter, beside the application rules.",
                h_flex()
                    .gap_1()
                    .child(Self::choice("on".into(), "On", enabled, cx, |f| {
                        f.enabled = true;
                    }))
                    .child(Self::choice("off".into(), "Off", !enabled, cx, |f| {
                        f.enabled = false;
                    }))
                    .into_any_element(),
            ))
            .child(row(
                "Inbound",
                "Drop keeps out what no rule lets in (replies and loopback always pass).",
                h_flex()
                    .gap_1()
                    .child(Self::choice(
                        "in-accept".into(),
                        "Accept",
                        !input,
                        cx,
                        |f| {
                            f.input = v1::ChainPolicy::Accept.into();
                        },
                    ))
                    .child(Self::choice("in-drop".into(), "Drop", input, cx, |f| {
                        f.input = v1::ChainPolicy::Drop.into();
                    }))
                    .into_any_element(),
            ))
            .child(row(
                "Forwarded",
                "Packets routed through this machine: containers, VMs, a router.",
                h_flex()
                    .gap_1()
                    .child(Self::choice(
                        "fwd-accept".into(),
                        "Accept",
                        !forward,
                        cx,
                        |f| {
                            f.forward = v1::ChainPolicy::Accept.into();
                        },
                    ))
                    .child(Self::choice("fwd-drop".into(), "Drop", forward, cx, |f| {
                        f.forward = v1::ChainPolicy::Drop.into();
                    }))
                    .into_any_element(),
            ))
            .into_any_element()
    }

    fn rules(firewall: &v1::SystemFirewall, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let mut list = v_flex();
        for (index, rule) in firewall.rules.iter().enumerate() {
            let enabled = rule.enabled;
            let editing = rule.clone();
            let page = cx.entity();
            list = list.child(
                h_flex()
                    .gap_3()
                    .py_1()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        Button::new(SharedString::from(format!("sys-on-{index}")))
                            .small()
                            .label(if enabled { "On" } else { "Off" })
                            .when_primary(enabled)
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.edit(cx, |f| {
                                    if let Some(rule) = f.rules.get_mut(index) {
                                        rule.enabled = !rule.enabled;
                                    }
                                });
                            })),
                    )
                    .child(
                        div()
                            .w(px(64.))
                            .flex_none()
                            .text_color(theme.muted_foreground)
                            .child(name(rule.chain().as_str_name(), "SYSTEM_CHAIN_")),
                    )
                    .child(
                        h_flex()
                            .w(px(70.))
                            .flex_none()
                            .child(target_tag(rule.target())),
                    )
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(clipped(
                                SharedString::from(format!("sys-summary-{index}")),
                                summary(rule),
                            )),
                    )
                    .child(
                        div()
                            .w(px(260.))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .text_color(theme.muted_foreground)
                            .child(clipped(
                                SharedString::from(format!("sys-description-{index}")),
                                rule.description.clone(),
                            )),
                    )
                    .child(
                        Button::new(SharedString::from(format!("sys-edit-{index}")))
                            .small()
                            .ghost()
                            .label("Edit")
                            .on_click(move |_, window, cx| {
                                open_rule(page.clone(), Some((index, editing.clone())), window, cx);
                            }),
                    )
                    .child(
                        Button::new(SharedString::from(format!("sys-delete-{index}")))
                            .small()
                            .ghost()
                            .label("Delete")
                            .on_click(cx.listener(move |page, _, _, cx| {
                                page.edit(cx, |f| {
                                    if index < f.rules.len() {
                                        f.rules.remove(index);
                                    }
                                });
                            })),
                    ),
            );
        }
        list.into_any_element()
    }
}

fn target_tag(target: v1::SystemTarget) -> gpui_component::tag::Tag {
    let label = name(target.as_str_name(), "SYSTEM_TARGET_");
    match target {
        v1::SystemTarget::Accept => Tag::success().small().child(label),
        v1::SystemTarget::Drop | v1::SystemTarget::Reject => Tag::danger().small().child(label),
        _ => Tag::secondary().small().child(label),
    }
}

/// Primary when `on`.
trait WhenPrimary {
    fn when_primary(self, on: bool) -> Self;
}

impl WhenPrimary for Button {
    fn when_primary(self, on: bool) -> Self {
        if on { self.primary() } else { self }
    }
}

impl Render for SystemPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let Some(firewall) = self
            .draft
            .clone()
            .or_else(|| self.model.read(cx).system.clone())
        else {
            return div()
                .p_4()
                .text_color(muted)
                .child("Asking the node…")
                .into_any_element();
        };
        let changed = self.draft.is_some();
        let page = cx.entity();
        let mut toolbar = h_flex().gap_2().child(
            Button::new("sys-add")
                .small()
                .label("Add rule")
                .on_click(move |_, window, cx| open_rule(page.clone(), None, window, cx)),
        );
        if changed {
            let draft = firewall.clone();
            toolbar = toolbar
                .child(div().flex_1())
                .child(div().text_color(muted).child("Not applied yet"))
                .child(
                    Button::new("sys-discard")
                        .small()
                        .ghost()
                        .label("Discard")
                        .on_click(cx.listener(|page, _, _, cx| {
                            page.draft = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("sys-apply")
                        .small()
                        .primary()
                        .label("Apply")
                        .on_click(cx.listener(move |page, _, _, cx| {
                            let _ = page.requests.send(Request::SetSystemFirewall(
                                v1::SetSystemFirewall {
                                    firewall: Some(draft.clone()),
                                    revert_after_secs: 0,
                                },
                            ));
                            page.draft = None;
                            cx.notify();
                        })),
                );
        }
        div()
            .id("system-page")
            .size_full()
            .overflow_y_scroll()
            .child(
                v_flex()
                    .p_4()
                    .gap_3()
                    .child(Self::header(&firewall, cx))
                    .child(toolbar)
                    .child(Self::rules(&firewall, cx)),
            )
            .into_any_element()
    }
}

/// The rule dialog: a new rule, or rule `index` of the draft.
struct RuleForm {
    page: Entity<SystemPage>,
    index: Option<usize>,
    rule: v1::SystemRule,
    description: Entity<InputState>,
    protocol: Entity<InputState>,
    source: Entity<InputState>,
    destination: Entity<InputState>,
    source_ports: Entity<InputState>,
    destination_ports: Entity<InputState>,
    in_interface: Entity<InputState>,
    out_interface: Entity<InputState>,
}

const CT_STATES: [&str; 4] = ["new", "established", "related", "invalid"];
const ICMP_TYPES: [&str; 4] = [
    "echo-request",
    "echo-reply",
    "destination-unreachable",
    "time-exceeded",
];

impl RuleForm {
    /// The rule as the form has it, where it goes, and the page it goes to.
    fn collect(&self, cx: &App) -> (Entity<SystemPage>, Option<usize>, v1::SystemRule) {
        let text = |input: &Entity<InputState>| input.read(cx).value().trim().to_owned();
        let list = |input: &Entity<InputState>| {
            text(input)
                .split([',', ' '])
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let rule = v1::SystemRule {
            description: text(&self.description),
            protocol: text(&self.protocol),
            source: list(&self.source),
            destination: list(&self.destination),
            source_ports: text(&self.source_ports),
            destination_ports: text(&self.destination_ports),
            in_interface: text(&self.in_interface),
            out_interface: text(&self.out_interface),
            ..self.rule.clone()
        };
        (self.page.clone(), self.index, rule)
    }

    fn save(form: &Entity<Self>, cx: &mut App) {
        let (page, index, rule) = form.read(cx).collect(cx);
        page.update(cx, |page, cx| {
            page.edit(cx, |f| match index.and_then(|i| f.rules.get_mut(i)) {
                Some(slot) => *slot = rule,
                None => f.rules.push(rule),
            });
        });
    }

    fn toggles(
        id: &str,
        options: &[&'static str],
        chosen: &[String],
        set: fn(&mut v1::SystemRule) -> &mut Vec<String>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mut row = h_flex().gap_1();
        for &option in options {
            let on = chosen.iter().any(|c| c == option);
            let button = Button::new(SharedString::from(format!("{id}-{option}")))
                .small()
                .label(option)
                .on_click(cx.listener(move |form, _, _, cx| {
                    let list = set(&mut form.rule);
                    if let Some(at) = list.iter().position(|c| c == option) {
                        list.remove(at);
                    } else {
                        list.push(option.to_owned());
                    }
                    cx.notify();
                }));
            row = row.child(if on { button.primary() } else { button.ghost() });
        }
        row.into_any_element()
    }
}

impl Render for RuleForm {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let field = |label: &'static str, element: AnyElement| {
            h_flex()
                .gap_3()
                .child(div().w(px(150.)).flex_none().text_color(muted).child(label))
                .child(div().flex_1().child(element))
        };
        let mut chains = h_flex().gap_1();
        for (label, chain) in [
            ("Input", v1::SystemChain::Input),
            ("Forward", v1::SystemChain::Forward),
            ("Output", v1::SystemChain::Output),
        ] {
            let button = Button::new(SharedString::from(format!("chain-{label}")))
                .small()
                .label(label)
                .on_click(cx.listener(move |form, _, _, cx| {
                    form.rule.chain = chain.into();
                    cx.notify();
                }));
            chains = chains.child(if self.rule.chain() == chain {
                button.primary()
            } else {
                button.ghost()
            });
        }
        let mut targets = h_flex().gap_1();
        for (label, target) in [
            ("Accept", v1::SystemTarget::Accept),
            ("Drop", v1::SystemTarget::Drop),
            ("Reject", v1::SystemTarget::Reject),
            ("Log", v1::SystemTarget::Log),
            ("Queue", v1::SystemTarget::Queue),
        ] {
            let button = Button::new(SharedString::from(format!("target-{label}")))
                .small()
                .label(label)
                .on_click(cx.listener(move |form, _, _, cx| {
                    form.rule.target = target.into();
                    cx.notify();
                }));
            targets = targets.child(if self.rule.target() == target {
                button.primary()
            } else {
                button.ghost()
            });
        }
        let ct = Self::toggles(
            "ct",
            &CT_STATES,
            &self.rule.ct_state.clone(),
            |r| &mut r.ct_state,
            cx,
        );
        let icmp = Self::toggles(
            "icmp",
            &ICMP_TYPES,
            &self.rule.icmp_types.clone(),
            |r| &mut r.icmp_types,
            cx,
        );
        v_flex()
            .gap_2()
            .child(field(
                "Description",
                Input::new(&self.description).into_any_element(),
            ))
            .child(field("Chain", chains.into_any_element()))
            .child(field("Target", targets.into_any_element()))
            .child(field(
                "Protocol",
                Input::new(&self.protocol).into_any_element(),
            ))
            .child(field("Source", Input::new(&self.source).into_any_element()))
            .child(field(
                "Destination",
                Input::new(&self.destination).into_any_element(),
            ))
            .child(field(
                "Source ports",
                Input::new(&self.source_ports).into_any_element(),
            ))
            .child(field(
                "Destination ports",
                Input::new(&self.destination_ports).into_any_element(),
            ))
            .child(field(
                "In interface",
                Input::new(&self.in_interface).into_any_element(),
            ))
            .child(field(
                "Out interface",
                Input::new(&self.out_interface).into_any_element(),
            ))
            .child(field("Connection state", ct))
            .child(field("ICMP types", icmp))
    }
}

fn open_rule(
    page: Entity<SystemPage>,
    editing: Option<(usize, v1::SystemRule)>,
    window: &mut Window,
    cx: &mut App,
) {
    let (index, rule) = match editing {
        Some((index, rule)) => (Some(index), rule),
        None => (
            None,
            v1::SystemRule {
                enabled: true,
                chain: v1::SystemChain::Input.into(),
                target: v1::SystemTarget::Accept.into(),
                ..v1::SystemRule::default()
            },
        ),
    };
    let input = |value: String, placeholder: &'static str, window: &mut Window, cx: &mut App| {
        cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(placeholder)
                .default_value(value)
        })
    };
    let form = RuleForm {
        description: input(rule.description.clone(), "What it is for", window, cx),
        protocol: input(
            rule.protocol.clone(),
            "tcp, udp, icmp, icmpv6 (empty: any)",
            window,
            cx,
        ),
        source: input(
            rule.source.join(", "),
            "192.0.2.0/24, 2001:db8::1",
            window,
            cx,
        ),
        destination: input(
            rule.destination.join(", "),
            "addresses or networks",
            window,
            cx,
        ),
        source_ports: input(
            rule.source_ports.clone(),
            "1024-65535 (one port or range)",
            window,
            cx,
        ),
        destination_ports: input(
            rule.destination_ports.clone(),
            "22, or 8000-8999",
            window,
            cx,
        ),
        in_interface: input(rule.in_interface.clone(), "eth0, wg*", window, cx),
        out_interface: input(rule.out_interface.clone(), "eth0, wg*", window, cx),
        page,
        index,
        rule,
    };
    let form = cx.new(|_| form);
    window.open_dialog(cx, move |dialog, _, _| {
        let saving = form.clone();
        dialog
            .title(if index.is_some() {
                "Edit rule"
            } else {
                "New rule"
            })
            .w(px(720.))
            .child(form.clone())
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("sys-rule-cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(
                        Button::new("sys-rule-save")
                            .primary()
                            .label("Save")
                            .on_click(move |_, window, cx| {
                                RuleForm::save(&saving, cx);
                                window.close_dialog(cx);
                            }),
                    ),
            )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_read_on_one_line() {
        let rule = v1::SystemRule {
            protocol: "tcp".to_owned(),
            source: vec!["10.0.0.0/8".to_owned()],
            destination_ports: "22".to_owned(),
            ..v1::SystemRule::default()
        };
        assert_eq!(summary(&rule), "tcp from 10.0.0.0/8 dport 22");
        assert_eq!(summary(&v1::SystemRule::default()), "everything");
    }
}
