//! Settings: the node's policy (changed here, it takes precedence over daemon.toml until reset), the client binaries
//! the node trusts, and what this app and the node are.

use std::sync::mpsc;

use gpui::{
    AnyElement, Context, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;

pub struct Settings {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl Settings {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self { model, requests }
    }

    /// Asks the node for what the page shows.
    pub fn refresh(&self) {
        let _ = self.requests.send(Request::Policy);
        let _ = self.requests.send(Request::TrustedClients);
    }
}

/// One setting: its name and description, its choices, and a reset when a client changed it.
struct Setting<'a> {
    key: &'static str,
    title: &'static str,
    description: &'static str,
    /// (label, the change, whether it is the value in effect)
    choices: Vec<(String, v1::SetPolicy, bool)>,
    changed: bool,
    requests: &'a mpsc::Sender<Request>,
}

impl Setting<'_> {
    fn render(self, cx: &Context<Settings>) -> AnyElement {
        let theme = cx.theme();
        let mut choices = h_flex().gap_1();
        for (index, (label, set, on)) in self.choices.into_iter().enumerate() {
            let requests = self.requests.clone();
            let button = Button::new(SharedString::from(format!("{}-{index}", self.key)))
                .small()
                .label(label)
                .on_click(move |_, _, _| {
                    let _ = requests.send(Request::SetPolicy(set.clone()));
                });
            choices = choices.child(if on { button.primary() } else { button.ghost() });
        }
        let reset = self.changed.then(|| {
            let requests = self.requests.clone();
            let key = self.key;
            h_flex()
                .gap_1()
                .child(Tag::secondary().small().child("changed here"))
                .child(
                    Button::new(SharedString::from(format!("{key}-reset")))
                        .small()
                        .ghost()
                        .label("Use daemon.toml's")
                        .on_click(move |_, _, _| {
                            let _ = requests.send(Request::SetPolicy(v1::SetPolicy {
                                reset: vec![key.to_owned()],
                                ..v1::SetPolicy::default()
                            }));
                        }),
                )
        });
        h_flex()
            .gap_4()
            .py_2()
            .border_b_1()
            .border_color(theme.border)
            .child(
                v_flex().w(px(320.)).flex_none().child(self.title).child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(self.description),
                ),
            )
            .child(v_flex().gap_1().child(choices).children(reset))
            .into_any_element()
    }
}

fn modes(current: v1::Mode) -> Vec<(String, v1::SetPolicy, bool)> {
    [
        ("Enforce", v1::Mode::Enforce),
        ("Monitor", v1::Mode::Monitor),
    ]
    .into_iter()
    .map(|(label, mode)| {
        let set = v1::SetPolicy {
            mode: Some(mode.into()),
            ..v1::SetPolicy::default()
        };
        (label.to_owned(), set, current == mode)
    })
    .collect()
}

fn no_match(current: v1::Policy) -> Vec<(String, v1::SetPolicy, bool)> {
    [
        ("Ask", v1::Policy::Ask),
        ("Allow", v1::Policy::Allow),
        ("Deny", v1::Policy::Deny),
        ("Reject", v1::Policy::Reject),
    ]
    .into_iter()
    .map(|(label, value)| {
        let set = v1::SetPolicy {
            no_match: Some(value.into()),
            ..v1::SetPolicy::default()
        };
        (label.to_owned(), set, current == value)
    })
    .collect()
}

fn actions(
    current: v1::Action,
    set: impl Fn(v1::Action) -> v1::SetPolicy,
) -> Vec<(String, v1::SetPolicy, bool)> {
    [
        ("Allow", v1::Action::Allow),
        ("Deny", v1::Action::Deny),
        ("Reject", v1::Action::Reject),
    ]
    .into_iter()
    .map(|(label, action)| (label.to_owned(), set(action), current == action))
    .collect()
}

/// Preset numbers, with the value in effect among them even when it is none of them.
fn numbers(
    current: u32,
    presets: &[u32],
    label: impl Fn(u32) -> String,
    set: impl Fn(u32) -> v1::SetPolicy,
) -> Vec<(String, v1::SetPolicy, bool)> {
    let mut values = presets.to_vec();
    if !values.contains(&current) {
        values.push(current);
        values.sort_unstable();
    }
    values
        .into_iter()
        .map(|value| (label(value), set(value), value == current))
        .collect()
}

impl Settings {
    fn policy(&self, policy: &v1::NodePolicy, cx: &Context<Self>) -> AnyElement {
        let changed = |key: &str| policy.changed.iter().any(|c| c == key);
        let settings = [
            Setting {
                key: "mode",
                title: "Mode",
                description: "Monitor records what would happen without blocking anything.",
                choices: modes(policy.mode()),
                changed: changed("mode"),
                requests: &self.requests,
            },
            Setting {
                key: "no_match",
                title: "When no rule matches",
                description: "Ask holds the connection and asks this app (or another client).",
                choices: no_match(policy.no_match()),
                changed: changed("no_match"),
                requests: &self.requests,
            },
            Setting {
                key: "no_client",
                title: "When no client listens",
                description: "With Ask: what happens while no app is there to ask.",
                choices: actions(policy.no_client(), |a| v1::SetPolicy {
                    no_client: Some(a.into()),
                    ..v1::SetPolicy::default()
                }),
                changed: changed("no_client"),
                requests: &self.requests,
            },
            Setting {
                key: "prompt_timeout_secs",
                title: "Prompts wait",
                description: "With Ask: how long a connection is held for an answer.",
                choices: numbers(
                    policy.prompt_timeout_secs,
                    &[15, 30, 60, 120, 300],
                    |s| format!("{s} s"),
                    |s| v1::SetPolicy {
                        prompt_timeout_secs: Some(s),
                        ..v1::SetPolicy::default()
                    },
                ),
                changed: changed("prompt_timeout_secs"),
                requests: &self.requests,
            },
            Setting {
                key: "on_timeout",
                title: "When nobody answers",
                description: "With Ask: what happens to a prompt that times out.",
                choices: actions(policy.on_timeout(), |a| v1::SetPolicy {
                    on_timeout: Some(a.into()),
                    ..v1::SetPolicy::default()
                }),
                changed: changed("on_timeout"),
                requests: &self.requests,
            },
            Setting {
                key: "retention_days",
                title: "History is kept",
                description: "Connections older than this are deleted (the Explorer's hourly totals too).",
                choices: numbers(
                    policy.retention_days,
                    &[7, 30, 90, 365],
                    |d| format!("{d} days"),
                    |d| v1::SetPolicy {
                        retention_days: Some(d),
                        ..v1::SetPolicy::default()
                    },
                ),
                changed: changed("retention_days"),
                requests: &self.requests,
            },
        ];
        let mut list = v_flex();
        for setting in settings {
            list = list.child(setting.render(cx));
        }
        list.into_any_element()
    }

    fn trusted(clients: &[v1::TrustedClient], cx: &Context<Self>) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let mut list = v_flex().gap_1();
        if clients.is_empty() {
            list = list.child(div().text_color(muted).child("None registered."));
        }
        for client in clients {
            list = list.child(
                h_flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(320.))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(client.path.clone()),
                    )
                    .child(div().w(px(180.)).flex_none().text_color(muted).child(
                        if client.sha256.is_empty() {
                            "by path (daemon.toml)".to_owned()
                        } else {
                            format!(
                                "sha256 {}…",
                                client.sha256.get(..16).unwrap_or(&client.sha256)
                            )
                        },
                    ))
                    .child(if client.current {
                        Tag::success().small().child("trusted")
                    } else {
                        Tag::warning().small().child("binary changed or gone")
                    }),
            );
        }
        list.into_any_element()
    }
}

fn heading(text: &'static str) -> impl IntoElement {
    div().pt_4().pb_1().text_lg().child(text)
}

impl Render for Settings {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let model = self.model.read(cx);
        let mut page = v_flex().p_4().gap_1().child(heading("Policy"));
        match &model.policy {
            Some(policy) => page = page.child(self.policy(&policy.clone(), cx)),
            None => page = page.child(div().text_color(muted).child("Asking the node…")),
        }
        page = page
            .child(heading("Trusted clients"))
            .child(
                div()
                    .text_sm()
                    .text_color(muted)
                    .child("The client apps the node lets connect. Their packages register them; root changes this."),
            )
            .child(Self::trusted(&model.trusted.clone(), cx))
            .child(heading("About"))
            .child(format!("Snitchhiker desktop {}", env!("CARGO_PKG_VERSION")))
            .children(model.node.as_ref().map(|node| {
                format!("Node {}, daemon {}", node.node_name, node.daemon_version)
            }));
        div()
            .id("settings")
            .size_full()
            .overflow_y_scroll()
            .child(page)
    }
}
