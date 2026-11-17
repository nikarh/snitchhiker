//! Alerts: what the node raised (about itself, or from the alert rules), newest first, acknowledged for every client;
//! and the alert rules, edited here.

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

pub struct Alerts {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl Alerts {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self { model, requests }
    }

    pub fn refresh(&self) {
        let _ = self.requests.send(Request::Alerts);
        let _ = self.requests.send(Request::AlertRules);
    }
}

/// What raised an alert, for people.
fn kind(kind: &str) -> &'static str {
    match kind {
        "alert_rule" => "alert rule",
        "crashed" => "daemon",
        "dropped_events" => "history",
        "queue_overflow" => "queue",
        "table_removed" => "firewall table",
        "rule_files" => "rule files",
        "dangerous_action" => "dangerous action",
        _ => "node",
    }
}

impl Alerts {
    fn alert(&self, alert: &v1::Alert, cx: &Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let requests = self.requests.clone();
        let id = alert.id;
        h_flex()
            .gap_3()
            .py_2()
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .w(px(170.))
                    .flex_none()
                    .whitespace_nowrap()
                    .text_color(theme.muted_foreground)
                    .child(time(alert.time_ms)),
            )
            .child(
                h_flex()
                    .w(px(130.))
                    .flex_none()
                    .child(if alert.acknowledged {
                        Tag::secondary().small().child(kind(&alert.kind))
                    } else {
                        Tag::warning().small().child(kind(&alert.kind))
                    }),
            )
            .child(
                v_flex()
                    .flex_1()
                    .overflow_hidden()
                    .child(
                        div()
                            .when_bold(!alert.acknowledged)
                            .child(alert.title.clone()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(alert.body.clone()),
                    ),
            )
            .child(if alert.acknowledged {
                div()
                    .w(px(150.))
                    .flex_none()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(format!("seen ({})", alert.acknowledged_by))
                    .into_any_element()
            } else {
                Button::new(SharedString::from(format!("ack-{id}")))
                    .small()
                    .label("Acknowledge")
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::Acknowledge {
                            ids: vec![id],
                            all: false,
                        });
                    })
                    .into_any_element()
            })
            .into_any_element()
    }

    fn rules(&self, rules: &[v1::AlertRule], cx: &Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let mut list = v_flex();
        if rules.is_empty() {
            list = list.child(div().text_color(theme.muted_foreground).child(
                "None yet. An alert rule raises an alert when connections a query matches come.",
            ));
        }
        for rule in rules {
            let (requests, editing) = (self.requests.clone(), rule.clone());
            let delete = self.requests.clone();
            let id = rule.id;
            let mut what = if rule.threshold <= 1 {
                if rule.first_program {
                    "Every program's first connection".to_owned()
                } else {
                    "Every connection".to_owned()
                }
            } else {
                format!("{} connections in {} s", rule.threshold, rule.window_secs)
            };
            if !rule.query.is_empty() {
                what = format!("{what} matching {}", rule.query);
            }
            if rule.first_program && rule.threshold > 1 {
                what.push_str(" of programs never seen before");
            }
            list = list.child(
                h_flex()
                    .gap_3()
                    .py_1()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .w(px(280.))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(clipped(
                                SharedString::from(format!("alert-name-{id}")),
                                rule.name.clone(),
                            )),
                    )
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .text_color(theme.muted_foreground)
                            .child(clipped(
                                SharedString::from(format!("alert-what-{id}")),
                                what,
                            )),
                    )
                    .child(if rule.enabled {
                        Tag::success().small().child("on")
                    } else {
                        Tag::secondary().small().child("off")
                    })
                    .child(
                        Button::new(SharedString::from(format!("alert-rule-edit-{id}")))
                            .small()
                            .ghost()
                            .label("Edit")
                            .on_click(move |_, window, cx| {
                                open_rule(requests.clone(), Some(editing.clone()), window, cx);
                            }),
                    )
                    .child(
                        Button::new(SharedString::from(format!("alert-rule-delete-{id}")))
                            .small()
                            .ghost()
                            .label("Delete")
                            .on_click(move |_, _, _| {
                                let _ = delete.send(Request::DeleteAlertRule { id });
                            }),
                    ),
            );
        }
        list.into_any_element()
    }
}

/// Bold when `on`: unacknowledged alerts stand out.
trait WhenBold {
    fn when_bold(self, on: bool) -> Self;
}

impl WhenBold for gpui::Div {
    fn when_bold(self, on: bool) -> Self {
        if on {
            self.font_weight(gpui::FontWeight::SEMIBOLD)
        } else {
            self
        }
    }
}

impl Render for Alerts {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let model = self.model.read(cx);
        let (alerts, open, rules) = (
            model.alerts.clone(),
            model.open_alerts,
            model.alert_rules.clone(),
        );
        let muted = cx.theme().muted_foreground;
        let requests = self.requests.clone();
        let mut list = v_flex();
        if alerts.is_empty() {
            list = list.child(div().text_color(muted).child("No alerts."));
        }
        for alert in &alerts {
            list = list.child(self.alert(alert, cx));
        }
        let adding = self.requests.clone();
        div()
            .id("alerts-page")
            .size_full()
            .overflow_y_scroll()
            .child(
                v_flex()
                    .p_4()
                    .gap_3()
                    .child(
                        h_flex()
                            .gap_3()
                            .child(div().text_lg().child(if open == 0 {
                                "Nothing to look at".to_owned()
                            } else {
                                format!("{open} not acknowledged")
                            }))
                            .child(div().flex_1())
                            .child(
                                Button::new("ack-all")
                                    .small()
                                    .label("Acknowledge all")
                                    .on_click(move |_, _, _| {
                                        let _ = requests.send(Request::Acknowledge {
                                            ids: Vec::new(),
                                            all: true,
                                        });
                                    }),
                            ),
                    )
                    .child(list)
                    .child(
                        h_flex()
                            .pt_4()
                            .gap_3()
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("Alert rules"),
                            )
                            .child(div().flex_1())
                            .child(
                                Button::new("alert-rule-add")
                                    .small()
                                    .label("Add rule")
                                    .on_click(move |_, window, cx| {
                                        open_rule(adding.clone(), None, window, cx);
                                    }),
                            ),
                    )
                    .child(self.rules(&rules, cx)),
            )
    }
}

/// The alert rule dialog.
struct RuleForm {
    rule: v1::AlertRule,
    name: Entity<InputState>,
    query: Entity<InputState>,
    threshold: Entity<InputState>,
    window: Entity<InputState>,
}

impl RuleForm {
    /// The rule as filled in.
    fn rule(&self, cx: &App) -> v1::AlertRule {
        let text = |input: &Entity<InputState>| input.read(cx).value().trim().to_owned();
        v1::AlertRule {
            name: text(&self.name),
            query: text(&self.query),
            threshold: text(&self.threshold).parse().unwrap_or(1),
            window_secs: text(&self.window).parse().unwrap_or(0),
            ..self.rule.clone()
        }
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
        let toggle = |id: &'static str,
                      label: &'static str,
                      on: bool,
                      set: fn(&mut v1::AlertRule),
                      cx: &mut Context<Self>| {
            let button = Button::new(id).small().label(label).on_click(cx.listener(
                move |form, _, _, cx| {
                    set(&mut form.rule);
                    cx.notify();
                },
            ));
            if on { button.primary() } else { button.ghost() }
        };
        let programs = h_flex()
            .gap_1()
            .child(toggle(
                "any-program",
                "Any program",
                !self.rule.first_program,
                |r| r.first_program = false,
                cx,
            ))
            .child(toggle(
                "new-program",
                "Programs never seen before",
                self.rule.first_program,
                |r| r.first_program = true,
                cx,
            ));
        let enabled = h_flex()
            .gap_1()
            .child(toggle(
                "rule-on",
                "On",
                self.rule.enabled,
                |r| r.enabled = true,
                cx,
            ))
            .child(toggle(
                "rule-off",
                "Off",
                !self.rule.enabled,
                |r| r.enabled = false,
                cx,
            ));
        v_flex()
            .gap_2()
            .child(field("Name", Input::new(&self.name).into_any_element()))
            .child(field("Connections", Input::new(&self.query).into_any_element()))
            .child(field("Of", programs.into_any_element()))
            .child(field("At least", Input::new(&self.threshold).into_any_element()))
            .child(field("Within (seconds)", Input::new(&self.window).into_any_element()))
            .child(field("", enabled.into_any_element()))
            .child(
                div()
                    .text_sm()
                    .text_color(muted)
                    .child("Connections are matched with the query language (empty: all of them). After an alert, the rule stays quiet for its window, or a minute."),
            )
    }
}

fn open_rule(
    requests: mpsc::Sender<Request>,
    rule: Option<v1::AlertRule>,
    window: &mut Window,
    cx: &mut App,
) {
    let new = rule.is_none();
    let rule = rule.unwrap_or(v1::AlertRule {
        enabled: true,
        threshold: 1,
        ..v1::AlertRule::default()
    });
    let input = |value: String, placeholder: &'static str, window: &mut Window, cx: &mut App| {
        cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(placeholder)
                .default_value(value)
        })
    };
    let form = RuleForm {
        name: input(rule.name.clone(), "What it watches for", window, cx),
        query: input(
            rule.query.clone(),
            "ip:imds   action:deny   exe:{home}/*",
            window,
            cx,
        ),
        threshold: input(rule.threshold.to_string(), "1", window, cx),
        window: input(rule.window_secs.to_string(), "0", window, cx),
        rule,
    };
    let form = cx.new(|_| form);
    window.open_dialog(cx, move |dialog, _, _| {
        let (saving, requests) = (form.clone(), requests.clone());
        dialog
            .title(if new {
                "New alert rule"
            } else {
                "Edit alert rule"
            })
            .w(px(640.))
            .child(form.clone())
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("alert-rule-cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(
                        Button::new("alert-rule-save")
                            .primary()
                            .label("Save")
                            .on_click(move |_, window, cx| {
                                let rule = saving.read(cx).rule(cx);
                                let _ = requests.send(Request::PutAlertRule(rule));
                                window.close_dialog(cx);
                            }),
                    ),
            )
    });
}
