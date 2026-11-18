//! Rules: the folder tree beside the rules of the folder chosen (and below it), searched with the query language.
//! Rules are selected with their check boxes (Shift for a range) and changed together; folders are switched off and on
//! with their subtree. Locked rules and folders (the defaults, root's rule files) are only shown.

use std::collections::BTreeSet;
use std::sync::mpsc;

use gpui::{
    App, AppContext as _, ClickEvent, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, StatefulInteractiveElement as _, Styled as _, Window,
    div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants};
use gpui_component::input::{Input, InputEvent, InputState};
use gpui_component::menu::{DropdownMenu as _, PopupMenu, PopupMenuItem};
use gpui_component::switch::Switch;
use gpui_component::table::{Column, ColumnSort, DataTable, TableDelegate, TableEvent, TableState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, IconName, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_core::query::{self, RuleFilter, RuleView};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;
use crate::views::text::clipped;

const COLUMNS: [(&str, &str, f32); 6] = [
    ("select", "", 36.),
    ("on", "On", 56.),
    ("action", "Action", 72.),
    ("name", "Folder / name", 230.),
    ("conditions", "Conditions", 300.),
    ("actions", "", 130.),
];

/// Temporary rules (they end at a time, or when the node restarts) or permanent ones, as OpenSnitch lists them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    Temporary,
    Permanent,
}

/// Whether a rule is temporary: it ends at a time, or when the node restarts.
#[must_use]
pub fn temporary(rule: &v1::Rule) -> bool {
    rule.until_restart || rule.expires_ms.is_some()
}

/// Now, in Unix milliseconds.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A time a rule ends at, as people read it: `14:32` today, `2026-11-20 09:00` another day.
#[must_use]
pub fn end_time(ms: u64, now: u64) -> String {
    use chrono::{Local, TimeZone as _};
    let local = |ms: u64| {
        i64::try_from(ms)
            .ok()
            .and_then(|ms| Local.timestamp_millis_opt(ms).single())
    };
    match (local(ms), local(now)) {
        (Some(at), Some(today)) if at.date_naive() == today.date_naive() => {
            at.format("%H:%M").to_string()
        }
        (Some(at), _) => at.format("%Y-%m-%d %H:%M").to_string(),
        (None, _) => String::new(),
    }
}

/// When a rule stops applying, for the Expires column and its CSV: empty for a permanent one.
#[must_use]
pub fn expiry_text(rule: &v1::Rule, now: u64) -> String {
    match rule.expires_ms {
        Some(at) if at <= now => format!("expired {}", end_time(at, now)),
        Some(at) => format!("until {}", end_time(at, now)),
        None if rule.until_restart => "until restart".to_owned(),
        None => String::new(),
    }
}

/// Rules picked for a bulk change, by id, so that a new search or new rules keep the selection.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Selection {
    selected: BTreeSet<u64>,
    /// Where a Shift range starts: the last rule clicked without Shift.
    anchor: Option<u64>,
}

impl Selection {
    /// A click on `id`'s check box, with the rules in the order shown: on its own it toggles the rule; with Shift, the
    /// rules from the last one clicked to this one take that rule's new state.
    pub fn click(&mut self, id: u64, order: &[u64], shift: bool) {
        let range = shift
            .then(|| {
                let from = order.iter().position(|r| Some(*r) == self.anchor)?;
                let to = order.iter().position(|r| *r == id)?;
                order.get(from.min(to)..=from.max(to))
            })
            .flatten();
        if let Some(range) = range {
            let select = self.anchor.is_some_and(|a| self.selected.contains(&a));
            for r in range {
                if select {
                    self.selected.insert(*r);
                } else {
                    self.selected.remove(r);
                }
            }
        } else {
            if !self.selected.remove(&id) {
                self.selected.insert(id);
            }
            self.anchor = Some(id);
        }
    }

    /// Selects all of `ids`, or, when all are selected, none.
    pub fn toggle_all(&mut self, ids: &[u64]) {
        if ids.iter().all(|id| self.selected.contains(id)) {
            for id in ids {
                self.selected.remove(id);
            }
        } else {
            self.selected.extend(ids);
        }
    }

    /// Forgets rules that are gone.
    pub fn retain(&mut self, exists: impl Fn(u64) -> bool) {
        self.selected.retain(|id| exists(*id));
        if self.anchor.is_some_and(|a| !exists(a)) {
            self.anchor = None;
        }
    }

    pub fn clear(&mut self) {
        self.selected.clear();
        self.anchor = None;
    }

    #[must_use]
    pub fn contains(&self, id: u64) -> bool {
        self.selected.contains(&id)
    }

    #[must_use]
    pub fn ids(&self) -> Vec<u64> {
        self.selected.iter().copied().collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }
}

/// Rules being dragged onto a folder: their ids, and what the drag shows.
#[derive(Debug, Clone)]
pub struct DraggedRules {
    ids: Vec<u64>,
    label: String,
}

/// What follows the pointer while rules are dragged.
struct DragPreview(String);

impl Render for DragPreview {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_1()
            .rounded_md()
            .bg(cx.theme().primary)
            .text_color(cx.theme().primary_foreground)
            .child(self.0.clone())
    }
}

pub struct RulesTable {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    filter: Option<RuleFilter>,
    /// The folder chosen in the tree: its rules and those below it (`None`: all).
    folder: Option<u64>,
    /// Only the temporary rules, or only the permanent ones (`None`: both).
    lifetime: Option<Lifetime>,
    /// Indices into the model's rules of those shown, in order.
    visible: Vec<usize>,
    pub selection: Selection,
    /// The column sorted by, and whether descending.
    sort: Option<(usize, bool)>,
}

impl RulesTable {
    #[must_use]
    pub fn new(model: Entity<Model>, requests: mpsc::Sender<Request>) -> Self {
        Self {
            model,
            requests,
            filter: None,
            folder: None,
            lifetime: None,
            visible: Vec::new(),
            selection: Selection::default(),
            sort: None,
        }
    }

    /// Works out which rules are shown, after the rules, the search or the folder changed.
    pub fn recompute(&mut self, cx: &App) {
        let list = &self.model.read(cx).rules;
        let inside = self.folder.map(|folder| subtree(list, folder));
        self.visible = list
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                inside
                    .as_ref()
                    .is_none_or(|inside| rule.folder.is_some_and(|f| inside.contains(&f)))
            })
            .filter(|(_, rule)| match self.lifetime {
                Some(Lifetime::Temporary) => temporary(rule),
                Some(Lifetime::Permanent) => !temporary(rule),
                None => true,
            })
            .filter(|(_, rule)| {
                self.filter.as_ref().is_none_or(|filter| {
                    let path = folder_path(list, rule.folder);
                    filter.matches(&view(rule, path.trim_end_matches('/')))
                })
            })
            .map(|(index, _)| index)
            .collect();
        if let Some((column, descending)) = self.sort {
            let key = |i: &usize| {
                let rule = list.rules.get(*i);
                match column {
                    1 => rule.map_or(String::new(), |r| u8::from(r.enabled).to_string()),
                    2 => rule.map_or(String::new(), |r| r.action.to_string()),
                    3 => rule.map_or(String::new(), |r| {
                        format!("{}{}", folder_path(list, r.folder), r.name).to_lowercase()
                    }),
                    _ => rule.map_or(String::new(), |r| conditions(r.conditions.as_ref())),
                }
            };
            self.visible.sort_by_cached_key(key);
            if descending {
                self.visible.reverse();
            }
        }
        let ids: BTreeSet<u64> = list.rules.iter().map(|r| r.id).collect();
        self.selection.retain(|id| ids.contains(&id));
    }

    /// The ids of the rules shown, in order.
    #[must_use]
    pub fn shown(&self, cx: &App) -> Vec<u64> {
        let list = &self.model.read(cx).rules;
        self.visible
            .iter()
            .filter_map(|i| list.rules.get(*i))
            .filter(|r| !r.locked)
            .map(|r| r.id)
            .collect()
    }
}

/// A folder and every folder below it.
fn subtree(list: &v1::RuleList, folder: u64) -> BTreeSet<u64> {
    let mut inside = BTreeSet::from([folder]);
    loop {
        let before = inside.len();
        for f in &list.folders {
            if f.parent.is_some_and(|p| inside.contains(&p)) {
                inside.insert(f.id);
            }
        }
        if inside.len() == before {
            return inside;
        }
    }
}

/// A rule as the query language sees it.
fn view<'a>(rule: &'a v1::Rule, folder: &'a str) -> RuleView<'a> {
    static EMPTY: v1::Conditions = v1::Conditions {
        exe: Vec::new(),
        app: Vec::new(),
        cmdline: Vec::new(),
        parent: Vec::new(),
        uid: Vec::new(),
        host: Vec::new(),
        net: Vec::new(),
        port: Vec::new(),
        protocol: Vec::new(),
        context: 0,
        session: Vec::new(),
        container: None,
        vm: None,
        netns: Vec::new(),
        list: Vec::new(),
        sha256: Vec::new(),
        writable: None,
    };
    let c = rule.conditions.as_ref().unwrap_or(&EMPTY);
    RuleView {
        name: &rule.name,
        notes: &rule.notes,
        folder,
        action: u8::try_from(rule.action).unwrap_or(0),
        tier: tier_name(rule.tier()),
        enabled: rule.enabled,
        locked: rule.locked,
        exe: &c.exe,
        app: &c.app,
        cmdline: &c.cmdline,
        parent: &c.parent,
        host: &c.host,
        net: &c.net,
        port: &c.port,
        protocol: &c.protocol,
        uid: &c.uid,
    }
}

fn tier_name(tier: v1::Tier) -> &'static str {
    match tier {
        v1::Tier::Override => "override",
        v1::Tier::Fallback => "fallback",
        v1::Tier::Normal | v1::Tier::Unspecified => "normal",
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

impl RulesTable {
    /// A rule's folder and name, which drags it (with the selection, when it is selected) onto a folder.
    fn name_cell(&self, rule: &v1::Rule, list: &v1::RuleList) -> gpui::AnyElement {
        let id = rule.id;
        // The selection moves together when the rule dragged is part of it.
        let ids = if self.selection.contains(id) {
            self.selection.ids()
        } else {
            vec![id]
        };
        let label = if ids.len() == 1 {
            rule.name.clone()
        } else {
            format!("{} rules", ids.len())
        };
        h_flex()
            .id(SharedString::from(format!("drag-{id}")))
            .gap_1()
            .cursor_grab()
            .overflow_hidden()
            .on_drag(DraggedRules { ids, label }, |dragged, _, _, cx| {
                cx.new(|_| DragPreview(dragged.label.clone()))
            })
            .child(div().overflow_hidden().text_ellipsis().child(clipped(
                SharedString::from(format!("rule-name-{id}")),
                format!("{}{}", folder_path(list, rule.folder), rule.name),
            )))
            .children(expiry_tag(rule).map(|tag| div().flex_none().child(tag)))
            .into_any_element()
    }
}

impl RulesTable {
    /// A rule's Edit and Delete.
    fn actions_cell(&self, rule: &v1::Rule) -> gpui::AnyElement {
        let id = rule.id;
        let requests = self.requests.clone();
        let editing = (self.model.clone(), self.requests.clone(), rule.clone());
        h_flex()
            .gap_1()
            .child(
                Button::new(SharedString::from(format!("edit-{id}")))
                    .small()
                    .ghost()
                    .label("Edit")
                    .on_click(move |_, window, cx| {
                        let (model, requests, rule) = editing.clone();
                        crate::views::editor::open(model, requests, Some(rule), window, cx);
                    }),
            )
            .child(
                Button::new(SharedString::from(format!("delete-{id}")))
                    .small()
                    .ghost()
                    .label("Delete")
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::DeleteRule { id });
                    }),
            )
            .into_any_element()
    }
}

impl TableDelegate for RulesTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.visible.len()
    }

    fn column(&self, col_ix: usize, cx: &App) -> Column {
        let (key, name, width) = COLUMNS.get(col_ix).copied().unwrap_or(("", "", 100.));
        let column = Column::new(key, name).width(crate::columns::width(cx, "rules", key, width));
        if (1..=4).contains(&col_ix) {
            column.sortable()
        } else {
            column
        }
    }

    fn perform_sort(
        &mut self,
        col_ix: usize,
        sort: ColumnSort,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) {
        self.sort = match sort {
            ColumnSort::Default => None,
            ColumnSort::Ascending => Some((col_ix, false)),
            ColumnSort::Descending => Some((col_ix, true)),
        };
        self.recompute(cx);
    }

    fn context_menu(
        &mut self,
        row_ix: usize,
        menu: PopupMenu,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> PopupMenu {
        let list = self.model.read(cx).rules.clone();
        let Some(rule) = self
            .visible
            .get(row_ix)
            .and_then(|i| list.rules.get(*i))
            .cloned()
        else {
            return menu;
        };
        if rule.locked {
            return menu
                .item(PopupMenuItem::new("Locked: a default or managed rule").disabled(true));
        }
        let (model, requests) = (self.model.clone(), self.requests.clone());
        let (toggle, delete) = (self.requests.clone(), self.requests.clone());
        let (id, enabled) = (rule.id, rule.enabled);
        menu.item(PopupMenuItem::new("Edit").on_click(move |_, window, cx| {
            crate::views::editor::open(
                model.clone(),
                requests.clone(),
                Some(rule.clone()),
                window,
                cx,
            );
        }))
        .item(
            PopupMenuItem::new(if enabled { "Disable" } else { "Enable" }).on_click(
                move |_, _, _| {
                    let _ = toggle.send(Request::SetRuleEnabled {
                        id,
                        enabled: !enabled,
                    });
                },
            ),
        )
        .separator()
        .item(PopupMenuItem::new("Delete").on_click(move |_, _, _| {
            let _ = delete.send(Request::DeleteRule { id });
        }))
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let list = self.model.read(cx).rules.clone();
        let Some(rule) = self.visible.get(row_ix).and_then(|i| list.rules.get(*i)) else {
            return div().into_any_element();
        };
        let id = rule.id;
        match col_ix {
            0 if rule.locked => div().into_any_element(),
            0 => {
                let table = cx.entity();
                Button::new(SharedString::from(format!("select-{id}")))
                    .xsmall()
                    .ghost()
                    .icon(if self.selection.contains(id) {
                        gpui_kit_assets::IconName::SquareCheck
                    } else {
                        gpui_kit_assets::IconName::Square
                    })
                    .on_click(move |event: &ClickEvent, _, cx| {
                        table.update(cx, |table, cx| {
                            let order = table.delegate().shown(cx);
                            table.delegate_mut().selection.click(
                                id,
                                &order,
                                event.modifiers().shift,
                            );
                            cx.notify();
                        });
                    })
                    .into_any_element()
            }
            1 if rule.locked => Tag::secondary().small().child("locked").into_any_element(),
            1 => {
                let enabled = rule.enabled;
                let requests = self.requests.clone();
                Switch::new(SharedString::from(format!("enable-{id}")))
                    .checked(enabled)
                    .color(cx.theme().success)
                    .tooltip(if enabled {
                        "On: switch it off"
                    } else {
                        "Off: switch it on"
                    })
                    .on_click(move |_, _, _| {
                        let _ = requests.send(Request::SetRuleEnabled {
                            id,
                            enabled: !enabled,
                        });
                    })
                    .into_any_element()
            }
            2 => crate::views::events::action_tag(u8::try_from(rule.action).unwrap_or(0), cx)
                .into_any_element(),
            // The tier, when it isn't the usual one.
            3 if !rule.locked => self.name_cell(rule, &list),
            3 => h_flex()
                .gap_1()
                .overflow_hidden()
                .when(
                    rule.tier() != v1::Tier::Normal && rule.tier() != v1::Tier::Unspecified,
                    |row| row.child(Tag::secondary().small().child(tier_name(rule.tier()))),
                )
                .child(div().overflow_hidden().text_ellipsis().child(clipped(
                    SharedString::from(format!("rule-name-{id}")),
                    format!("{}{}", folder_path(&list, rule.folder), rule.name),
                )))
                .into_any_element(),
            4 => div()
                .overflow_hidden()
                .text_ellipsis()
                .font_family(cx.theme().mono_font_family.clone())
                .text_color(cx.theme().muted_foreground)
                .child(clipped(
                    SharedString::from(format!("rule-conditions-{id}")),
                    conditions(rule.conditions.as_ref()),
                ))
                .into_any_element(),
            5 if !rule.locked => self.actions_cell(rule),
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
            .child("No rules here")
    }
}

/// A temporary rule's tag, beside its name: when it ends, or that it has expired (it no longer applies, and stays
/// listed until it is deleted or given another expiry). `None` for a permanent rule.
fn expiry_tag(rule: &v1::Rule) -> Option<gpui::AnyElement> {
    let now = now_ms();
    let text = expiry_text(rule, now);
    match rule.expires_ms {
        Some(at) if at <= now => Some(Tag::danger().small().child(text).into_any_element()),
        _ if temporary(rule) => Some(Tag::secondary().small().child(text).into_any_element()),
        _ => None,
    }
}

/// The page: the folder tree, the search, the bulk actions and the table.
pub struct RulesPage {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    table: Entity<TableState<RulesTable>>,
    search: Entity<InputState>,
    error: Option<String>,
    error_span: Option<std::ops::Range<usize>>,
    /// When the table is next drawn again by itself: the soonest a shown rule expires.
    wake: Option<u64>,
}

impl RulesPage {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        table: Entity<TableState<RulesTable>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let search = cx.new(|cx| {
            InputState::new(window, cx).placeholder(
                "Search: curl  host:example.com  action:deny  enabled:no  folder:Apps/*",
            )
        });
        cx.subscribe_in(&search, window, |page, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                page.search(cx);
            }
        })
        .detach();
        cx.observe(&table, |_, _, cx| cx.notify()).detach();
        // A double-click on a rule edits it, as its Edit button does.
        cx.subscribe_in(&table, window, |page, table, event, window, cx| {
            if let TableEvent::DoubleClickedRow(row) = event {
                let list = page.model.read(cx).rules.clone();
                let rule = table
                    .read(cx)
                    .delegate()
                    .visible
                    .get(*row)
                    .and_then(|i| list.rules.get(*i))
                    .filter(|r| !r.locked)
                    .cloned();
                if let Some(rule) = rule {
                    crate::views::editor::open(
                        page.model.clone(),
                        page.requests.clone(),
                        Some(rule),
                        window,
                        cx,
                    );
                }
            }
        })
        .detach();
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self {
            model,
            requests,
            table,
            search,
            error: None,
            error_span: None,
            wake: None,
        }
    }

    /// Draws the table again when the soonest rule to expire does, so it shows as expired then.
    fn wake_at_next_expiry(&mut self, cx: &mut Context<Self>) {
        let now = now_ms();
        let next = self
            .model
            .read(cx)
            .rules
            .rules
            .iter()
            .filter_map(|r| r.expires_ms)
            .filter(|at| *at > now)
            .min();
        if next.is_none() || next == self.wake {
            return;
        }
        self.wake = next;
        let delay = std::time::Duration::from_millis(next.unwrap_or(now).saturating_sub(now) + 50);
        cx.spawn(async move |page, cx| {
            cx.background_executor().timer(delay).await;
            let _ = page.update(cx, |page, cx| {
                page.wake = None;
                page.table.update(cx, |_, cx| cx.notify());
                cx.notify();
            });
        })
        .detach();
    }

    fn choose_lifetime(&mut self, lifetime: Option<Lifetime>, cx: &mut Context<Self>) {
        self.table.update(cx, |table, cx| {
            table.delegate_mut().folder = None;
            table.delegate_mut().lifetime = lifetime;
            table.delegate_mut().recompute(cx);
            cx.notify();
        });
        cx.notify();
    }

    /// An entry of the tree that lists the temporary rules, or the permanent ones, of every folder.
    fn lifetime_row(
        lifetime: Lifetime,
        count: usize,
        chosen: bool,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let theme = cx.theme().clone();
        let (key, label, tooltip) = match lifetime {
            Lifetime::Temporary => (
                "temporary",
                "Temporary",
                "Rules that end at a time or when the node restarts",
            ),
            Lifetime::Permanent => ("permanent", "Permanent", "Rules that never expire"),
        };
        h_flex()
            .id(SharedString::from(format!("lifetime-{key}")))
            .gap_1()
            .pl(px(8.))
            .pr_1()
            .py_0p5()
            .rounded_sm()
            .cursor_pointer()
            .when(chosen, |row| row.bg(theme.accent))
            .hover(|row| row.bg(theme.muted))
            .tooltip(move |window, cx| {
                gpui_component::tooltip::Tooltip::new(tooltip).build(window, cx)
            })
            .on_click(cx.listener(move |page, _, _, cx| {
                page.choose_lifetime(Some(lifetime), cx);
            }))
            .child(div().flex_1().child(label))
            .child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(count.to_string()),
            )
            .into_any_element()
    }

    /// Searches as the query is typed: rules are all here, so each keystroke filters them at once.
    fn search(&mut self, cx: &mut Context<Self>) {
        let text = self.search.read(cx).value().trim().to_owned();
        let filter = if text.is_empty() {
            Ok(None)
        } else {
            let query_cx = query::Context {
                now_ms: 0,
                uid_of: &|_| None,
            };
            RuleFilter::parse(&text, &query_cx).map(Some)
        };
        match filter {
            Ok(filter) => {
                self.error = None;
                self.error_span = None;
                self.table.update(cx, |table, cx| {
                    table.delegate_mut().filter = filter;
                    table.delegate_mut().recompute(cx);
                    cx.notify();
                });
            }
            // A query half typed: the rules shown stay until it reads.
            Err(e) => {
                self.error_span = Some(e.span);
                self.error = Some(e.message);
            }
        }
        cx.notify();
    }

    fn choose_folder(&mut self, folder: Option<u64>, cx: &mut Context<Self>) {
        self.table.update(cx, |table, cx| {
            table.delegate_mut().folder = folder;
            table.delegate_mut().lifetime = None;
            table.delegate_mut().recompute(cx);
            cx.notify();
        });
        cx.notify();
    }

    fn tree(&mut self, cx: &mut Context<Self>) -> gpui::AnyElement {
        self.wake_at_next_expiry(cx);
        let theme = cx.theme().clone();
        let list = self.model.read(cx).rules.clone();
        let chosen = self.table.read(cx).delegate().folder;
        let lifetime = self.table.read(cx).delegate().lifetime;
        let temporaries = list.rules.iter().filter(|r| temporary(r)).count();
        let mut column = v_flex()
            .gap_px()
            .child(self.folder_row(
                None,
                "All rules".into(),
                0,
                chosen.is_none() && lifetime.is_none(),
                None,
                cx,
            ))
            .child(Self::lifetime_row(
                Lifetime::Temporary,
                temporaries,
                lifetime == Some(Lifetime::Temporary),
                cx,
            ))
            .child(Self::lifetime_row(
                Lifetime::Permanent,
                list.rules.len() - temporaries,
                lifetime == Some(Lifetime::Permanent),
                cx,
            ))
            .child(div().h_2());
        for (folder, depth) in ordered(&list) {
            column = column.child(self.folder_row(
                Some(folder.id),
                folder.name.clone().into(),
                depth,
                chosen == Some(folder.id),
                Some(folder),
                cx,
            ));
        }
        v_flex()
            .w(px(240.))
            .flex_none()
            .h_full()
            .p_2()
            .gap_2()
            .border_r_1()
            .border_color(theme.border)
            .child(
                h_flex()
                    .justify_between()
                    .child(div().text_color(theme.muted_foreground).child("Folders"))
                    .child({
                        let requests = self.requests.clone();
                        let parent = chosen;
                        Button::new("new-folder")
                            .small()
                            .ghost()
                            .icon(IconName::Plus)
                            .tooltip("New folder here")
                            .on_click(move |_, window, cx| {
                                new_folder(requests.clone(), parent, window, cx);
                            })
                    }),
            )
            .child(
                div()
                    .id("folder-tree")
                    .flex_1()
                    .overflow_y_scroll()
                    .child(column),
            )
            .into_any_element()
    }

    fn folder_row(
        &self,
        id: Option<u64>,
        name: SharedString,
        depth: usize,
        chosen: bool,
        folder: Option<v1::Folder>,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let theme = cx.theme().clone();
        let key = id.map_or_else(|| "all".to_owned(), |id| id.to_string());
        let enabled = folder.as_ref().is_none_or(|f| f.enabled);
        let locked = folder.as_ref().is_some_and(|f| f.locked);
        let requests = self.requests.clone();
        h_flex()
            .id(SharedString::from(format!("folder-{key}")))
            .gap_1()
            .pl(px(8. + 14. * f32::from(u16::try_from(depth).unwrap_or(0))))
            .pr_1()
            .py_0p5()
            .rounded_sm()
            .cursor_pointer()
            .when(chosen, |row| row.bg(theme.accent))
            .hover(|row| row.bg(theme.muted))
            .on_click(cx.listener(move |page, _, _, cx| page.choose_folder(id, cx)))
            // Rules dropped on a folder (or on All rules: the top level) move there; not into locked ones.
            .when(!locked, |row| {
                let requests = requests.clone();
                row.drag_over::<DraggedRules>(|style, _, _, cx| style.bg(cx.theme().accent))
                    .on_drop(move |dragged: &DraggedRules, _, _| {
                        let _ = requests.send(Request::EditRules(v1::EditRules {
                            ids: dragged.ids.clone(),
                            edit: Some(v1::edit_rules::Edit::Move(v1::MoveRules { folder: id })),
                        }));
                    })
            })
            .child(
                div()
                    .flex_1()
                    .overflow_hidden()
                    .text_ellipsis()
                    .when(!enabled, |d| {
                        d.text_color(theme.muted_foreground).line_through()
                    })
                    .child(clipped(SharedString::from(format!("folder-{key}")), name)),
            )
            .when_some(folder.filter(|_| !locked), |row, folder| {
                let toggled = v1::Folder {
                    enabled: !folder.enabled,
                    ..folder.clone()
                };
                let deleting = folder.id;
                let requests_delete = requests.clone();
                row.child(
                    Switch::new(SharedString::from(format!("folder-on-{key}")))
                        .xsmall()
                        .checked(folder.enabled)
                        .color(theme.success)
                        .tooltip("Switch the folder, and everything in it, off or on")
                        .on_click(move |_, _, _| {
                            let _ = requests.send(Request::UpdateFolder(toggled.clone()));
                        }),
                )
                .child(
                    Button::new(SharedString::from(format!("folder-delete-{key}")))
                        .xsmall()
                        .ghost()
                        .icon(IconName::Close)
                        .tooltip("Delete the folder with its folders and rules")
                        .on_click(move |_, _, _| {
                            let _ = requests_delete.send(Request::DeleteFolder { id: deleting });
                        }),
                )
            })
            .into_any_element()
    }

    fn bulk_bar(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let selection = self.table.read(cx).delegate().selection.clone();
        if selection.is_empty() {
            return None;
        }
        let ids = selection.ids();
        let count = ids.len();
        let send: Send = {
            let requests = self.requests.clone();
            std::rc::Rc::new(move |edit: v1::edit_rules::Edit| {
                let _ = requests.send(Request::EditRules(v1::EditRules {
                    ids: ids.clone(),
                    edit: Some(edit),
                }));
            })
        };
        let button = |id: &'static str, label: &'static str, edit: v1::edit_rules::Edit| {
            let send = send.clone();
            Button::new(id)
                .small()
                .ghost()
                .label(label)
                .on_click(move |_, _, _| send(edit))
        };
        let list = self.model.read(cx).rules.clone();
        let move_to = {
            let send = send.clone();
            Button::new("bulk-move")
                .small()
                .ghost()
                .label("Move to…")
                .dropdown_menu(move |menu, _, _| {
                    let mut menu = menu.item(PopupMenuItem::new("(top level)").on_click({
                        let send = send.clone();
                        move |_, _, _| {
                            send(v1::edit_rules::Edit::Move(v1::MoveRules { folder: None }));
                        }
                    }));
                    for (folder, _) in ordered(&list).into_iter().filter(|(f, _)| !f.locked) {
                        let send = send.clone();
                        let path = folder_path(&list, Some(folder.id));
                        menu = menu.item(PopupMenuItem::new(path).on_click(move |_, _, _| {
                            send(v1::edit_rules::Edit::Move(v1::MoveRules {
                                folder: Some(folder.id),
                            }));
                        }));
                    }
                    menu
                })
        };
        let action = action_menu(send.clone());
        let expires = expires_menu(send.clone());
        let table = self.table.clone();
        Some(
            h_flex()
                .px_2()
                .py_1()
                .gap_1()
                .bg(cx.theme().muted)
                .child(div().pr_2().child(format!("{count} selected")))
                .child(button(
                    "bulk-on",
                    "Enable",
                    v1::edit_rules::Edit::Enabled(true),
                ))
                .child(button(
                    "bulk-off",
                    "Disable",
                    v1::edit_rules::Edit::Enabled(false),
                ))
                .child(move_to)
                .child(action)
                .child(expires)
                .child(button(
                    "bulk-delete",
                    "Delete",
                    v1::edit_rules::Edit::Delete(true),
                ))
                .child(div().flex_1())
                .child(
                    Button::new("bulk-clear")
                        .small()
                        .ghost()
                        .label("Clear")
                        .on_click(move |_, _, cx| {
                            table.update(cx, |table, cx| {
                                table.delegate_mut().selection.clear();
                                cx.notify();
                            });
                        }),
                )
                .into_any_element(),
        )
    }
}

/// Sends a bulk change of the rules selected.
type Send = std::rc::Rc<dyn Fn(v1::edit_rules::Edit)>;

fn action_menu(send: Send) -> impl IntoElement {
    Button::new("bulk-action")
        .small()
        .ghost()
        .label("Action…")
        .dropdown_menu(move |menu, _, _| {
            let mut menu = menu;
            for (label, action) in [
                ("Allow", v1::Action::Allow),
                ("Deny", v1::Action::Deny),
                ("Reject", v1::Action::Reject),
            ] {
                let send = send.clone();
                menu = menu.item(PopupMenuItem::new(label).on_click(move |_, _, _| {
                    send(v1::edit_rules::Edit::Action(action.into()));
                }));
            }
            menu
        })
}

fn expires_menu(send: Send) -> impl IntoElement {
    Button::new("bulk-expires")
        .small()
        .ghost()
        .label("Expires…")
        .dropdown_menu(move |menu, _, _| {
            let mut menu = menu;
            for (label, duration) in [
                ("In an hour", v1::Duration::Hour),
                ("In 12 hours", v1::Duration::HalfDay),
                ("When the node restarts", v1::Duration::UntilRestart),
                ("Never", v1::Duration::Forever),
            ] {
                let send = send.clone();
                menu = menu.item(PopupMenuItem::new(label).on_click(move |_, _, _| {
                    send(v1::edit_rules::Edit::Expires(duration.into()));
                }));
            }
            menu
        })
}

/// The rules, as CSV.
fn rules_csv(list: &v1::RuleList) -> String {
    let rows = list.rules.iter().map(|rule| {
        vec![
            folder_path(list, rule.folder)
                .trim_end_matches('/')
                .to_owned(),
            rule.name.clone(),
            if rule.enabled { "on" } else { "off" }.to_owned(),
            v1::Action::try_from(rule.action).map_or_else(
                |_| String::new(),
                |a| a.as_str_name().trim_start_matches("ACTION_").to_lowercase(),
            ),
            tier_name(rule.tier()).to_owned(),
            conditions(rule.conditions.as_ref()),
            expiry_text(rule, now_ms()),
        ]
    });
    crate::csv::table(
        &[
            "folder",
            "name",
            "enabled",
            "action",
            "tier",
            "conditions",
            "expires",
        ],
        rows,
    )
}

/// The folders depth first, by name, with their depth.
fn ordered(list: &v1::RuleList) -> Vec<(v1::Folder, usize)> {
    fn walk(
        list: &v1::RuleList,
        parent: Option<u64>,
        depth: usize,
        out: &mut Vec<(v1::Folder, usize)>,
    ) {
        if depth > list.folders.len() {
            return;
        }
        let mut children: Vec<&v1::Folder> =
            list.folders.iter().filter(|f| f.parent == parent).collect();
        children.sort_by(|a, b| a.name.cmp(&b.name));
        for child in children {
            out.push((child.clone(), depth));
            walk(list, Some(child.id), depth + 1, out);
        }
    }
    let mut out = Vec::new();
    walk(list, None, 0, &mut out);
    out
}

/// Asks for a new folder's name, in `parent`.
fn new_folder(
    requests: mpsc::Sender<Request>,
    parent: Option<u64>,
    window: &mut Window,
    cx: &mut App,
) {
    let name = cx.new(|cx| InputState::new(window, cx).placeholder("Name"));
    window.open_dialog(cx, move |dialog, _, _| {
        let (name, requests) = (name.clone(), requests.clone());
        dialog
            .title("New folder")
            .w(px(420.))
            .child(Input::new(&name))
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("folder-cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(Button::new("folder-add").primary().label("Add").on_click(
                        move |_, window, cx| {
                            let text = name.read(cx).value().trim().to_owned();
                            if !text.is_empty() {
                                let _ = requests.send(Request::AddFolder(v1::Folder {
                                    parent,
                                    name: text,
                                    enabled: true,
                                    ..v1::Folder::default()
                                }));
                            }
                            window.close_dialog(cx);
                        },
                    )),
            )
    });
}

impl RulesPage {
    /// Import from OpenSnitch, with a preview.
    fn import_button(&self) -> Button {
        let (requests, model) = (self.requests.clone(), self.model.clone());
        Button::new("import")
            .small()
            .label("Import…")
            .tooltip("OpenSnitch's rules and system firewall, with a preview")
            .on_click(move |_, window, cx| {
                crate::views::import::open(&model, requests.clone(), window, cx);
            })
    }
}

impl Render for RulesPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let hints = crate::views::query::hints(
            &self.search,
            &crate::views::query::RULE_KEYS,
            self.error_span.as_ref(),
            window,
            cx,
        );
        let tree = self.tree(cx);
        let bulk = self.bulk_bar(cx);
        let (model, requests) = (self.model.clone(), self.requests.clone());
        let (lint_model, lint_requests) = (self.model.clone(), self.requests.clone());
        let table = self.table.clone();
        h_flex()
            .size_full()
            .child(tree)
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .overflow_hidden()
                    .child(
                        h_flex()
                            .w_full()
                            .flex_wrap()
                            .px_4()
                            .py_2()
                            .gap_2()
                            .child(
                                Button::new("select-all")
                                    .small()
                                    .ghost()
                                    .label("Select all")
                                    .on_click(move |_, _, cx| {
                                        table.update(cx, |table, cx| {
                                            let shown = table.delegate().shown(cx);
                                            table.delegate_mut().selection.toggle_all(&shown);
                                            cx.notify();
                                        });
                                    }),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(280.))
                                    .child(Input::new(&self.search).cleanable(true)),
                            )
                            .child(self.import_button())
                            .child({
                                let model = self.model.clone();
                                Button::new("rules-csv")
                                    .small()
                                    .ghost()
                                    .label("Copy CSV")
                                    .on_click(move |_, _, cx| {
                                        let csv = rules_csv(&model.read(cx).rules);
                                        cx.write_to_clipboard(gpui::ClipboardItem::new_string(csv));
                                    })
                            })
                            .child(
                                Button::new("lint")
                                    .small()
                                    .label("Check rules")
                                    .tooltip("Duplicates, redundant and shadowed rules, missing binaries, unused rules")
                                    .on_click(move |_, window, cx| {
                                        crate::views::lint::open(
                                            lint_model.clone(),
                                            lint_requests.clone(),
                                            window,
                                            cx,
                                        );
                                    }),
                            )
                            .child(
                                Button::new("new-rule")
                                    .small()
                                    .primary()
                                    .label("New rule")
                                    .on_click(move |_, window, cx| {
                                        crate::views::editor::open(
                                            model.clone(),
                                            requests.clone(),
                                            None,
                                            window,
                                            cx,
                                        );
                                    }),
                            ),
                    )
                    .child(div().px_4().child(hints))
                    .children(self.error.clone().map(|error| {
                        div()
                            .px_4()
                            .text_sm()
                            .text_color(cx.theme().danger)
                            .child(error)
                    }))
                    .children(bulk)
                    .child(DataTable::new(&self.table)),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_rules_say_when_they_end() {
        let now = now_ms();
        let rule = |expires_ms, until_restart| v1::Rule {
            expires_ms,
            until_restart,
            ..v1::Rule::default()
        };
        assert!(!temporary(&rule(None, false)));
        assert_eq!(expiry_text(&rule(None, false), now), "");
        assert!(temporary(&rule(None, true)));
        assert_eq!(expiry_text(&rule(None, true), now), "until restart");
        let later = rule(Some(now + 60_000), false);
        assert!(temporary(&later));
        assert!(expiry_text(&later, now).starts_with("until "));
        assert!(expiry_text(&rule(Some(now - 1), false), now).starts_with("expired "));
        // Another day: with its date.
        assert_eq!(
            end_time(now + 3 * 86_400_000, now).len(),
            "2026-11-20 09:00".len()
        );
    }

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
        assert_eq!(subtree(&list, 1), BTreeSet::from([1, 2]));
        assert_eq!(
            ordered(&list)
                .iter()
                .map(|(f, depth)| (f.id, *depth))
                .collect::<Vec<_>>(),
            vec![(1, 0), (2, 1)]
        );
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

    #[test]
    fn check_boxes_toggle_and_shift_selects_ranges() {
        let order = [10, 20, 30, 40, 50];
        let mut s = Selection::default();
        s.click(20, &order, false);
        assert_eq!(s.ids(), vec![20]);
        // Shift: from the anchor to here, to the anchor's state.
        s.click(40, &order, true);
        assert_eq!(s.ids(), vec![20, 30, 40]);
        // A plain click toggles one and moves the anchor.
        s.click(30, &order, false);
        assert_eq!(s.ids(), vec![20, 40]);
        // Shift from an unselected anchor clears the range, backwards too.
        s.click(10, &order, true);
        assert_eq!(s.ids(), vec![40]);
        // Shift without an anchor on the list (a search hid it) toggles like a plain click.
        let mut hidden = s.clone();
        hidden.click(50, &[50], true);
        assert_eq!(hidden.ids(), vec![40, 50]);
        // Select all, then all again: none.
        s.toggle_all(&order);
        assert_eq!(s.ids(), order.to_vec());
        s.toggle_all(&order);
        assert!(s.is_empty());
        // Rules that are gone are forgotten, the anchor with them.
        s.click(20, &order, false);
        s.retain(|id| id != 20);
        assert!(s.is_empty());
        s.click(40, &order, true);
        assert_eq!(s.ids(), vec![40]);
    }
}
