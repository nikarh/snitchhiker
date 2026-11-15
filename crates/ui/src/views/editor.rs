//! The rule editor: a rule's name, action, tier, folder and conditions, checked against the history loaded before it
//! is saved ("matches N of the M events loaded").

use std::sync::{Arc, mpsc};

use gpui::{
    App, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render, SharedString,
    Styled as _, Window, div, prelude::FluentBuilder as _,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::searchable_list::SearchableListItem;
use gpui_component::select::{Select, SelectState};
use gpui_component::{ActiveTheme as _, IndexPath, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_core::engine::{Facts, RuleSet};
use snitchhiker_core::rule::ContextKind;
use snitchhiker_proto::{convert, v1};

use crate::backend::Request;
use crate::model::{Model, address};
use crate::views::rules::folder_path;

/// A folder to choose: its path, and its id (`None`: the top level).
#[derive(Debug, Clone, PartialEq)]
pub struct FolderItem {
    label: SharedString,
    id: Option<u64>,
}

impl SearchableListItem for FolderItem {
    type Value = Option<u64>;

    fn title(&self) -> SharedString {
        self.label.clone()
    }

    fn value(&self) -> &Self::Value {
        &self.id
    }
}

/// The condition fields, in the order shown: (key, label, placeholder).
const FIELDS: [(&str, &str, &str); 8] = [
    ("exe", "Program", "/usr/bin/curl, glob:{home}/.cargo/bin/*"),
    ("host", "Host", "example.com, *.example.org, re:..."),
    ("net", "Network", "192.0.2.0/24, lan, loopback"),
    ("port", "Port", "443, 8000-8999"),
    ("protocol", "Protocol", "tcp, udp"),
    ("uid", "User id", "1000"),
    ("cmdline", "Command line", "re:.*--flag.*"),
    ("parent", "Parent program", "/usr/bin/sshd"),
];

pub struct RuleEditor {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    /// The rule edited; id 0 for a new one.
    rule: v1::Rule,
    name: Entity<InputState>,
    fields: Vec<Entity<InputState>>,
    folder: Entity<SelectState<Vec<FolderItem>>>,
    preview: Option<String>,
}

fn values(conditions: &v1::Conditions, key: &str) -> String {
    match key {
        "exe" => conditions.exe.join(", "),
        "host" => conditions.host.join(", "),
        "net" => conditions.net.join(", "),
        "port" => conditions.port.join(", "),
        "protocol" => conditions.protocol.join(", "),
        "uid" => conditions
            .uid
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        "cmdline" => conditions.cmdline.join(", "),
        "parent" => conditions.parent.join(", "),
        _ => String::new(),
    }
}

/// A field's comma-separated values.
fn split(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

impl RuleEditor {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        rule: v1::Rule,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let conditions = rule.conditions.clone().unwrap_or_default();
        let name = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("What it is for")
                .default_value(rule.name.clone())
        });
        let fields = FIELDS
            .iter()
            .map(|(key, _, placeholder)| {
                let value = values(&conditions, key);
                cx.new(|cx| {
                    InputState::new(window, cx)
                        .placeholder(*placeholder)
                        .default_value(value)
                })
            })
            .collect();
        let list = model.read(cx).rules.clone();
        let mut items = vec![FolderItem {
            label: "(top level)".into(),
            id: None,
        }];
        items.extend(
            list.folders
                .iter()
                .filter(|f| !f.locked)
                .map(|f| FolderItem {
                    label: format!("{}{}", folder_path(&list, f.parent), f.name).into(),
                    id: Some(f.id),
                }),
        );
        let selected = items
            .iter()
            .position(|item| item.id == rule.folder)
            .map(IndexPath::new);
        let folder = cx.new(|cx| SelectState::new(items, selected, window, cx));
        Self {
            model,
            requests,
            rule,
            name,
            fields,
            folder,
            preview: None,
        }
    }

    /// The rule as the fields say.
    fn edited(&self, cx: &App) -> v1::Rule {
        let mut conditions = self.rule.conditions.clone().unwrap_or_default();
        for ((key, _, _), field) in FIELDS.iter().zip(&self.fields) {
            let text = field.read(cx).value();
            let values = split(&text);
            match *key {
                "exe" => conditions.exe = values,
                "host" => conditions.host = values,
                "net" => conditions.net = values,
                "port" => conditions.port = values,
                "protocol" => conditions.protocol = values,
                "uid" => conditions.uid = values.iter().filter_map(|v| v.parse().ok()).collect(),
                "cmdline" => conditions.cmdline = values,
                "parent" => conditions.parent = values,
                _ => {}
            }
        }
        v1::Rule {
            name: self.name.read(cx).value().to_string(),
            folder: self.folder.read(cx).selected_value().copied().flatten(),
            conditions: Some(conditions),
            ..self.rule.clone()
        }
    }

    /// How many of the loaded events the edited rule matches (its folders' scopes included).
    fn check(&mut self, cx: &mut Context<Self>) {
        let wire = self.edited(cx);
        let model = self.model.read(cx);
        let rule = match convert::rule_from(&v1::Rule {
            id: 1,
            enabled: true,
            ..wire
        }) {
            Ok(rule) => rule,
            Err(e) => {
                self.preview = Some(format!("Not a valid rule: {e}"));
                cx.notify();
                return;
            }
        };
        let folders: Vec<_> = model
            .rules
            .folders
            .iter()
            .filter_map(|f| convert::folder_from(f).ok())
            .collect();
        let set = match RuleSet::compile(&folders, &[rule]) {
            Ok(set) => set,
            Err(e) => {
                self.preview = Some(format!("Not a valid rule: {e}"));
                cx.notify();
                return;
            }
        };
        let conditions = self.edited(cx).conditions.unwrap_or_default();
        let unknowable = !conditions.cmdline.is_empty() || !conditions.parent.is_empty();
        let events = &model.events;
        let mut matched = 0;
        for index in 0..events.len() {
            let Some(row) = events.get(index) else {
                continue;
            };
            let exe = events.string(row.exe).unwrap_or_default();
            let hosts: Vec<Arc<str>> = events
                .string(row.host)
                .filter(|_| row.host != 0)
                .map(Arc::from)
                .into_iter()
                .collect();
            let context = match v1::Context::try_from(i32::from(row.context)) {
                Ok(v1::Context::Container) => ContextKind::Container,
                Ok(v1::Context::Vm) => ContextKind::Vm,
                Ok(v1::Context::Netns) => ContextKind::Netns,
                _ => ContextKind::Host,
            };
            let facts = Facts {
                exe,
                apps: &[],
                cmdline: "",
                ancestors: &[],
                uid: row.uid,
                home: None,
                hosts: &hosts,
                address: address(row),
                port: row.port,
                protocol: row.protocol,
                context,
                now_ms: row.time_ms,
            };
            if set.decide(&facts).is_some() {
                matched += 1;
            }
        }
        self.preview = Some(if unknowable {
            format!(
                "The history doesn't keep command lines and parents: without those conditions it matches {matched} of the {} events loaded.",
                events.len()
            )
        } else {
            format!("Matches {matched} of the {} events loaded.", events.len())
        });
        cx.notify();
    }

    /// Saves the rule: added if new, replaced otherwise.
    pub fn save(&self, cx: &App) {
        let rule = self.edited(cx);
        let request = if rule.id == 0 {
            Request::AddRule(rule)
        } else {
            Request::UpdateRule(rule)
        };
        let _ = self.requests.send(request);
    }

    fn choice(
        label: &'static str,
        on: bool,
        cx: &mut Context<Self>,
        set: fn(&mut v1::Rule),
    ) -> Button {
        let button = Button::new(SharedString::from(format!("choice-{label}")))
            .small()
            .label(label)
            .on_click(cx.listener(move |editor, _, _, cx| {
                set(&mut editor.rule);
                cx.notify();
            }));
        if on { button.primary() } else { button.ghost() }
    }
}

impl Render for RuleEditor {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let action = self.rule.action();
        let tier = self.rule.tier();
        let label = |text: &str| {
            div()
                .w_40()
                .flex_none()
                .text_color(muted)
                .child(text.to_owned())
        };
        let mut form = v_flex()
            .gap_2()
            .child(
                h_flex()
                    .gap_2()
                    .child(label("Name"))
                    .child(Input::new(&self.name)),
            )
            .child(
                h_flex()
                    .gap_1()
                    .child(label("Action"))
                    .child(Self::choice(
                        "Allow",
                        action == v1::Action::Allow,
                        cx,
                        |r| {
                            r.action = v1::Action::Allow.into();
                        },
                    ))
                    .child(Self::choice("Deny", action == v1::Action::Deny, cx, |r| {
                        r.action = v1::Action::Deny.into();
                    }))
                    .child(Self::choice(
                        "Reject",
                        action == v1::Action::Reject,
                        cx,
                        |r| {
                            r.action = v1::Action::Reject.into();
                        },
                    )),
            )
            .child(
                h_flex()
                    .gap_1()
                    .child(label("Tier"))
                    .child(Self::choice(
                        "Override",
                        tier == v1::Tier::Override,
                        cx,
                        |r| {
                            r.tier = v1::Tier::Override.into();
                        },
                    ))
                    .child(Self::choice("Normal", tier == v1::Tier::Normal, cx, |r| {
                        r.tier = v1::Tier::Normal.into();
                    }))
                    .child(Self::choice(
                        "Fallback",
                        tier == v1::Tier::Fallback,
                        cx,
                        |r| {
                            r.tier = v1::Tier::Fallback.into();
                        },
                    )),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(label("Folder"))
                    .child(Select::new(&self.folder)),
            );
        for ((_, name, _), field) in FIELDS.iter().zip(&self.fields) {
            form = form.child(h_flex().gap_2().child(label(name)).child(Input::new(field)));
        }
        form.child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("check")
                        .small()
                        .label("Check against history")
                        .on_click(cx.listener(|editor, _, _, cx| editor.check(cx))),
                )
                .when_some(self.preview.clone(), |row, text| {
                    row.child(div().text_color(muted).child(text))
                }),
        )
    }
}

/// Opens the editor in a dialog, for `rule` (a new one when `None`).
pub fn open(
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    rule: Option<v1::Rule>,
    window: &mut Window,
    cx: &mut App,
) {
    let new = rule.is_none();
    let rule = rule.unwrap_or_else(|| v1::Rule {
        enabled: true,
        action: v1::Action::Allow.into(),
        tier: v1::Tier::Normal.into(),
        ..v1::Rule::default()
    });
    let editor = cx.new(|cx| RuleEditor::new(model, requests, rule, window, cx));
    window.open_dialog(cx, move |dialog, _, _| {
        let saving = editor.clone();
        dialog
            .title(if new { "New rule" } else { "Edit rule" })
            .w(gpui::px(720.))
            .child(editor.clone())
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(Button::new("save").primary().label("Save").on_click(
                        move |_, window, cx| {
                            saving.read(cx).save(cx);
                            window.close_dialog(cx);
                        },
                    )),
            )
    });
}
