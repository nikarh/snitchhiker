//! The window: a sidebar of pages, and the page shown.

use std::collections::HashSet;
use std::sync::mpsc;

use gpui::{
    AnyElement, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, Window, div,
};
use gpui_component::button::Button;
use gpui_component::sidebar::{Sidebar, SidebarGroup, SidebarMenu, SidebarMenuItem};
use gpui_component::table::{DataTable, TableEvent, TableState};
use gpui_component::{ActiveTheme as _, IconName, Sizable as _, h_flex, v_flex};

use crate::backend::{Request, Update};
use crate::model::{Changed, Model};
use crate::notify::{self, Notice};
use crate::views::connections::ConnectionsTable;
use crate::views::events::{self, EventsPage, EventsTable};
use crate::views::explain;
use crate::views::explorer::Explorer;
use crate::views::history::History;
use crate::views::prompts::Prompts;
use crate::views::rules::{RulesPage, RulesTable};
use crate::views::settings::Settings;
use crate::views::status::Status;
use crate::views::system::SystemPage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Prompts,
    Events,
    Explorer,
    Connections,
    Rules,
    History,
    Status,
    Firewall,
    Settings,
}

pub struct App {
    model: Entity<Model>,
    page: Page,
    prompts: Entity<Prompts>,
    events: Entity<TableState<EventsTable>>,
    events_page: Entity<EventsPage>,
    rules: Entity<TableState<RulesTable>>,
    rules_page: Entity<RulesPage>,
    history: Entity<History>,
    explorer: Entity<Explorer>,
    connections: Entity<TableState<ConnectionsTable>>,
    status: Entity<Status>,
    settings: Entity<Settings>,
    system: Entity<SystemPage>,
    requests: mpsc::Sender<Request>,
}

impl App {
    pub fn new(
        requests: mpsc::Sender<Request>,
        updates: async_channel::Receiver<Update>,
        updates_sender: async_channel::Sender<Update>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let model = cx.new(|_| Model::default());
        let prompts = cx.new(|cx| Prompts::new(model.clone(), requests.clone(), cx));
        let events = cx.new(|cx| {
            TableState::new(
                EventsTable::new(model.clone(), requests.clone()),
                window,
                cx,
            )
        });
        let rules = cx.new(|cx| {
            TableState::new(RulesTable::new(model.clone(), requests.clone()), window, cx)
        });
        let status = cx.new(|cx| Status::new(model.clone(), cx));
        let settings = cx.new(|cx| Settings::new(model.clone(), requests.clone(), cx));
        let system = cx.new(|cx| SystemPage::new(model.clone(), requests.clone(), cx));
        let history = cx.new(|cx| History::new(model.clone(), requests.clone(), cx));
        let explorer = cx.new(|cx| Explorer::new(model.clone(), requests.clone(), cx));
        let connections = cx.new(|cx| {
            TableState::new(
                ConnectionsTable::new(model.clone(), requests.clone()),
                window,
                cx,
            )
        });
        Self::explain_on_double_click(&events, window, cx);
        let notices = notify::start(requests.clone(), updates_sender);
        let own_requests = requests.clone();
        for request in [Request::Status, Request::Rules, Request::Changes] {
            let _ = requests.send(request);
        }
        events::request_page(&model, &requests, cx);
        let rules_page =
            cx.new(|cx| RulesPage::new(model.clone(), requests.clone(), rules.clone(), window, cx));
        let events_page = cx
            .new(|cx| EventsPage::new(model.clone(), requests.clone(), events.clone(), window, cx));
        Self::fold_updates(updates, requests, notices, cx);
        Self {
            model,
            page: Page::Events,
            prompts,
            events,
            events_page,
            rules,
            rules_page,
            history,
            explorer,
            connections,
            status,
            settings,
            system,
            requests: own_requests,
        }
    }

    /// The backend's updates, folded into the model on the UI thread.
    fn fold_updates(
        updates: async_channel::Receiver<Update>,
        requests: mpsc::Sender<Request>,
        notices: async_channel::Sender<Notice>,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while let Ok(update) = updates.recv().await {
                let applied = this.update(cx, |app: &mut Self, cx| {
                    let before: HashSet<u64> = app.model.read(cx).prompts.keys().copied().collect();
                    let changed = app.model.update(cx, |model, cx| {
                        let changed = model.apply(update);
                        cx.notify();
                        changed
                    });
                    // A notification for every prompt that opened, and down with those resolved.
                    let prompts = &app.model.read(cx).prompts;
                    for (id, prompt) in prompts {
                        if !before.contains(id) {
                            let _ = notices.try_send(Notice::Show(prompt.clone()));
                        }
                    }
                    for id in before.iter().filter(|id| !prompts.contains_key(id)) {
                        let _ = notices.try_send(Notice::Close(*id));
                    }
                    match changed {
                        Changed::RulesOnNode => {
                            let _ = requests.send(Request::Rules);
                            let _ = requests.send(Request::Status);
                            let _ = requests.send(Request::Changes);
                            let _ = requests.send(Request::Policy);
                            let _ = requests.send(Request::SystemFirewall);
                        }
                        Changed::Events => {
                            app.events.update(cx, TableState::refresh);
                            // A query matching little: older history is looked through until a screenful is found.
                            if app.model.read(cx).events.len() < 100 {
                                events::request_page(&app.model, &requests, cx);
                            }
                            // New connections: the live list is listed again while it is shown.
                            if app.page == Page::Connections {
                                let _ = requests.send(Request::Connections);
                            }
                        }
                        Changed::Connections => app.connections.update(cx, TableState::refresh),
                        Changed::Rules => app.rules.update(cx, |table, cx| {
                            table.delegate_mut().recompute(cx);
                            table.refresh(cx);
                        }),
                        Changed::Prompts if !app.model.read(cx).prompts.is_empty() => {
                            app.page = Page::Prompts;
                        }
                        Changed::ShowPrompts => {
                            app.page = Page::Prompts;
                            cx.activate(true);
                        }
                        Changed::Prompts | Changed::Status | Changed::Nothing => {}
                    }
                    cx.notify();
                });
                if applied.is_err() {
                    break;
                }
            }
        })
        .detach();
    }

    /// A double-click on an event says why it was decided so, as its info button does.
    fn explain_on_double_click(
        events: &Entity<TableState<EventsTable>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        cx.subscribe_in(events, window, |app, _, event, window, cx| {
            if let TableEvent::DoubleClickedRow(row) = event
                && let Some(seq) = app.model.read(cx).events.get(*row).map(|r| r.seq)
            {
                explain::open(app.model.clone(), app.requests.clone(), seq, window, cx);
            }
        })
        .detach();
    }

    fn item(
        &self,
        page: Page,
        label: SharedString,
        icon: impl Into<gpui_component::Icon>,
        cx: &mut Context<Self>,
    ) -> SidebarMenuItem {
        SidebarMenuItem::new(label)
            .icon(icon)
            .active(self.page == page)
            .on_click(cx.listener(move |app, _, _, cx| {
                app.page = page;
                if page == Page::Explorer {
                    app.explorer.read(cx).query();
                }
                if page == Page::Connections {
                    let _ = app.requests.send(Request::Connections);
                }
                if page == Page::Settings {
                    app.settings.read(cx).refresh();
                }
                if page == Page::Firewall {
                    app.system.read(cx).refresh();
                }
                cx.notify();
            }))
    }
}

impl Render for App {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let waiting = self.model.read(cx).prompts.len();
        let prompts_label: SharedString = if waiting == 0 {
            "Prompts".into()
        } else {
            format!("Prompts ({waiting})").into()
        };
        let node = self
            .model
            .read(cx)
            .node
            .as_ref()
            .map_or_else(|| "Snitchhiker".to_owned(), |n| n.node_name.clone());
        let sidebar = Sidebar::new("pages")
            .header(div().p_2().text_lg().child(node))
            .child(
                SidebarGroup::new("Node").child(
                    SidebarMenu::new()
                        .child(self.item(Page::Prompts, prompts_label, IconName::Bell, cx))
                        .child(self.item(
                            Page::Events,
                            "Events".into(),
                            IconName::LayoutDashboard,
                            cx,
                        ))
                        .child(self.item(Page::Explorer, "Explorer".into(), IconName::ChartPie, cx))
                        .child(self.item(
                            Page::Connections,
                            "Connections".into(),
                            IconName::Globe,
                            cx,
                        ))
                        .child(self.item(Page::Rules, "Rules".into(), IconName::BookOpen, cx))
                        .child(self.item(Page::History, "History".into(), IconName::Undo, cx))
                        .child(self.item(Page::Status, "Status".into(), IconName::Info, cx))
                        .child(self.item(
                            Page::Firewall,
                            "Firewall".into(),
                            gpui_kit_assets::IconName::Shield,
                            cx,
                        ))
                        .child(self.item(
                            Page::Settings,
                            "Settings".into(),
                            IconName::Settings,
                            cx,
                        )),
                ),
            );
        let page: AnyElement = match self.page {
            Page::Prompts => self.prompts.clone().into_any_element(),
            Page::Events => self.events_page.clone().into_any_element(),
            Page::Rules => self.rules_page.clone().into_any_element(),
            Page::History => self.history.clone().into_any_element(),
            Page::Explorer => self.explorer.clone().into_any_element(),
            Page::Connections => {
                let requests = self.requests.clone();
                v_flex()
                    .size_full()
                    .child(
                        h_flex().p_2().child(
                            Button::new("refresh-connections")
                                .small()
                                .label("Refresh")
                                .on_click(move |_, _, _| {
                                    let _ = requests.send(Request::Connections);
                                }),
                        ),
                    )
                    .child(DataTable::new(&self.connections))
                    .into_any_element()
            }
            Page::Status => self.status.clone().into_any_element(),
            Page::Settings => self.settings.clone().into_any_element(),
            Page::Firewall => self.system.clone().into_any_element(),
        };
        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar)
            .child(v_flex().flex_1().h_full().overflow_hidden().child(page))
    }
}
