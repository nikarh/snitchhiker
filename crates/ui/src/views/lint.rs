//! The lint report in a dialog: each finding with what can be done about it (edit, delete, or take the pattern that
//! covers a binary's new version).

use std::sync::mpsc;

use gpui::{
    App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, StatefulInteractiveElement as _, Styled as _, Window,
    div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;
use crate::views::editor;
use crate::views::rules::folder_path;

/// Rules that decided nothing in this many days are reported.
const UNUSED_DAYS: u32 = 30;

pub struct Lint {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

fn kind_label(kind: v1::LintKind) -> (&'static str, bool) {
    // (label, whether it may be wrong rather than untidy)
    match kind {
        v1::LintKind::Duplicate => ("duplicate", false),
        v1::LintKind::Redundant => ("redundant", false),
        v1::LintKind::Shadowed => ("never wins", true),
        v1::LintKind::Expired => ("expired", false),
        v1::LintKind::NeverHit => ("unused", false),
        v1::LintKind::WritableBinary => ("replaceable binary", true),
        v1::LintKind::MissingBinary => ("binary gone", true),
        v1::LintKind::Mergeable => ("mergeable", false),
        v1::LintKind::Unspecified => ("?", false),
    }
}

impl Render for Lint {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let model = self.model.read(cx);
        let Some(report) = model.lint.clone() else {
            return div()
                .text_color(muted)
                .child("Checking…")
                .into_any_element();
        };
        let list = model.rules.clone();
        let mut rows = v_flex().gap_2();
        if report.findings.is_empty() {
            rows = rows.child(
                "Nothing to report: no duplicates, no rules that never win, no missing binaries.",
            );
        }
        for (index, finding) in report.findings.iter().enumerate() {
            rows = rows.child(self.finding(index, finding, &list, cx));
        }
        div()
            .id("lint-findings")
            .max_h(px(480.))
            .overflow_y_scroll()
            .child(rows)
            .into_any_element()
    }
}

impl Lint {
    /// Merging: the other rule takes both lists, and this one goes.
    fn merge_button(
        &self,
        index: usize,
        finding: &v1::LintFinding,
        rule: &v1::Rule,
        list: &v1::RuleList,
    ) -> Option<Button> {
        let merged = finding.merged.clone()?;
        let other = finding
            .other
            .and_then(|id| list.rules.iter().find(|r| r.id == id))
            .cloned()?;
        let requests = self.requests.clone();
        let gone = rule.id;
        Some(
            Button::new(SharedString::from(format!("lint-merge-{index}")))
                .small()
                .label("Merge")
                .on_click(move |_, _, _| {
                    let _ = requests.send(Request::UpdateRule(v1::Rule {
                        conditions: Some(merged.clone()),
                        ..other.clone()
                    }));
                    let _ = requests.send(Request::DeleteRule { id: gone });
                    let _ = requests.send(Request::Lint { days: UNUSED_DAYS });
                }),
        )
    }

    fn finding(
        &self,
        index: usize,
        finding: &v1::LintFinding,
        list: &v1::RuleList,
        cx: &App,
    ) -> gpui::AnyElement {
        let muted = cx.theme().muted_foreground;
        let rule = list.rules.iter().find(|r| r.id == finding.rule).cloned();
        let name = rule.as_ref().map_or_else(
            || format!("rule {}", finding.rule),
            |r| format!("{}{}", folder_path(list, r.folder), r.name),
        );
        let (label, serious) = kind_label(finding.kind());
        let mut actions = h_flex().gap_1();
        if let Some(rule) = rule {
            if !finding.suggestion.is_empty() {
                let mut updated = rule.clone();
                let suggestion = finding.suggestion.clone();
                if let Some(conditions) = updated.conditions.as_mut() {
                    conditions.exe = vec![suggestion.clone()];
                }
                let requests = self.requests.clone();
                actions = actions.child(
                    Button::new(SharedString::from(format!("lint-use-{index}")))
                        .small()
                        .label(format!("Use {suggestion}"))
                        .on_click(move |_, _, _| {
                            let _ = requests.send(Request::UpdateRule(updated.clone()));
                            let _ = requests.send(Request::Lint { days: UNUSED_DAYS });
                        }),
                );
            }
            if let Some(merge) = self.merge_button(index, finding, &rule, list) {
                actions = actions.child(merge);
            }
            let (model, requests) = (self.model.clone(), self.requests.clone());
            let editing = rule.clone();
            actions = actions.child(
                Button::new(SharedString::from(format!("lint-edit-{index}")))
                    .small()
                    .ghost()
                    .label("Edit")
                    .on_click(move |_, window, cx| {
                        window.close_dialog(cx);
                        editor::open(
                            model.clone(),
                            requests.clone(),
                            Some(editing.clone()),
                            window,
                            cx,
                        );
                    }),
            );
            let requests = self.requests.clone();
            let id = rule.id;
            actions = actions.child(
                Button::new(SharedString::from(format!("lint-delete-{index}")))
                    .small()
                    .ghost()
                    .label("Delete")
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::DeleteRule { id });
                        let _ = requests.send(Request::Lint { days: UNUSED_DAYS });
                    }),
            );
        }
        h_flex()
            .gap_3()
            .child(div().w(px(150.)).flex_none().child(if serious {
                Tag::warning().small().child(label)
            } else {
                Tag::secondary().small().child(label)
            }))
            .child(
                v_flex()
                    .flex_1()
                    .overflow_hidden()
                    .child(div().overflow_hidden().text_ellipsis().child(name))
                    .child(
                        div()
                            .text_sm()
                            .text_color(muted)
                            .child(finding.description.clone()),
                    ),
            )
            .child(actions)
            .into_any_element()
    }
}

/// Asks the node for the report and shows it.
pub fn open(
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    window: &mut Window,
    cx: &mut App,
) {
    model.update(cx, |model, _| model.lint = None);
    let _ = requests.send(Request::Lint { days: UNUSED_DAYS });
    let lint = cx.new(|cx| {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Lint { model, requests }
    });
    window.open_dialog(cx, move |dialog, _, _| {
        dialog.title("Check rules").w(px(860.)).child(lint.clone())
    });
}
