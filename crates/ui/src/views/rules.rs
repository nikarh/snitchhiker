//! Rules: every rule with its folder, action, tier and conditions. Rules can be switched off and on and deleted here;
//! locked ones (the System folder, root's rule files) only shown.

use std::sync::mpsc;

use gpui::{
    App, Context, Entity, IntoElement, ParentElement as _, SharedString, Styled as _, Window, div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::table::{Column, TableDelegate, TableState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;

const COLUMNS: [(&str, &str, f32); 6] = [
    ("on", "On", 70.),
    ("action", "Action", 80.),
    ("tier", "Tier", 90.),
    ("name", "Folder / name", 320.),
    ("conditions", "Conditions", 420.),
    ("actions", "", 100.),
];

pub struct RulesTable {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl RulesTable {
    #[must_use]
    pub fn new(model: Entity<Model>, requests: mpsc::Sender<Request>) -> Self {
        Self { model, requests }
    }
}

/// `Apps/curl/`: the folders a rule is in.
#[must_use]
pub fn folder_path(list: &v1::RuleList, folder: Option<u64>) -> String {
    let mut names = Vec::new();
    let mut next = folder;
    for _ in 0..list.folders.len() {
        let Some(found) = next.and_then(|id| list.folders.iter().find(|f| f.id == id)) else {
            break;
        };
        names.push(found.name.as_str());
        next = found.parent;
    }
    names.iter().rev().fold(String::new(), |mut path, name| {
        path.push_str(name);
        path.push('/');
        path
    })
}

/// A rule's conditions on one line: `exe=/usr/bin/curl host=example.com port=443`.
#[must_use]
pub fn conditions(conditions: Option<&v1::Conditions>) -> String {
    let Some(c) = conditions else {
        return String::new();
    };
    let mut parts = Vec::new();
    for (key, values) in [
        ("exe", &c.exe),
        ("app", &c.app),
        ("cmdline", &c.cmdline),
        ("parent", &c.parent),
        ("host", &c.host),
        ("net", &c.net),
        ("port", &c.port),
        ("protocol", &c.protocol),
    ] {
        if !values.is_empty() {
            parts.push(format!("{key}={}", values.join(",")));
        }
    }
    if !c.uid.is_empty() {
        let uids: Vec<String> = c.uid.iter().map(u32::to_string).collect();
        parts.push(format!("uid={}", uids.join(",")));
    }
    if let Ok(context) = v1::Context::try_from(c.context)
        && context != v1::Context::Unspecified
    {
        parts.push(format!(
            "context={}",
            context
                .as_str_name()
                .trim_start_matches("CONTEXT_")
                .to_lowercase()
        ));
    }
    parts.join(" ")
}

impl TableDelegate for RulesTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, cx: &App) -> usize {
        self.model.read(cx).rules.rules.len()
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (key, name, width) = COLUMNS.get(col_ix).copied().unwrap_or(("", "", 100.));
        Column::new(key, name).width(width)
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let list = self.model.read(cx).rules.clone();
        let Some(rule) = list.rules.get(row_ix) else {
            return div().into_any_element();
        };
        let id = rule.id;
        match col_ix {
            0 if rule.locked => Tag::secondary().small().child("locked").into_any_element(),
            0 => {
                let enabled = rule.enabled;
                let requests = self.requests.clone();
                Button::new(SharedString::from(format!("enable-{id}")))
                    .small()
                    .label(if enabled { "On" } else { "Off" })
                    .when_primary(enabled)
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::SetRuleEnabled {
                            id,
                            enabled: !enabled,
                        });
                    })
                    .into_any_element()
            }
            1 => crate::views::events::action_tag(u8::try_from(rule.action).unwrap_or(0))
                .into_any_element(),
            2 => div()
                .child(
                    rule.tier()
                        .as_str_name()
                        .trim_start_matches("TIER_")
                        .to_lowercase(),
                )
                .into_any_element(),
            3 => div()
                .overflow_hidden()
                .text_ellipsis()
                .child(format!("{}{}", folder_path(&list, rule.folder), rule.name))
                .into_any_element(),
            4 => div()
                .overflow_hidden()
                .text_ellipsis()
                .text_color(cx.theme().muted_foreground)
                .child(conditions(rule.conditions.as_ref()))
                .into_any_element(),
            5 if !rule.locked => {
                let requests = self.requests.clone();
                Button::new(SharedString::from(format!("delete-{id}")))
                    .small()
                    .ghost()
                    .label("Delete")
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::DeleteRule { id });
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
            .child("No rules")
    }
}

/// Primary when `on`: a toggle's look.
trait WhenPrimary {
    fn when_primary(self, on: bool) -> Self;
}

impl WhenPrimary for Button {
    fn when_primary(self, on: bool) -> Self {
        if on { self.primary() } else { self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_read_with_their_folders_and_conditions() {
        let list = v1::RuleList {
            folders: vec![
                v1::Folder {
                    id: 1,
                    name: "Apps".to_owned(),
                    ..v1::Folder::default()
                },
                v1::Folder {
                    id: 2,
                    parent: Some(1),
                    name: "curl".to_owned(),
                    ..v1::Folder::default()
                },
            ],
            rules: Vec::new(),
        };
        assert_eq!(folder_path(&list, Some(2)), "Apps/curl/");
        assert_eq!(folder_path(&list, None), "");
        let c = v1::Conditions {
            host: vec!["example.com".to_owned()],
            port: vec!["443".to_owned()],
            uid: vec![1000],
            context: v1::Context::Any.into(),
            ..v1::Conditions::default()
        };
        assert_eq!(
            conditions(Some(&c)),
            "host=example.com port=443 uid=1000 context=any"
        );
    }
}
