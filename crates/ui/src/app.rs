//! The window: a sidebar of pages, and the page shown.

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
use crate::views::alerts::Alerts;
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
    Proposals,
    Alerts,
    Live,
    Events,
    Explorer,
    Connections,
    Rules,
    History,
    Status,
    Firewall,
    Devices,
    Settings,
}

/// Emitted when a node asks to be shown (a notification or the tray was clicked).
pub struct Activate;

impl gpui::EventEmitter<Activate> for App {}

pub struct App {
    model: Entity<Model>,
    page: Page,
    prompts: Entity<Prompts>,
    proposals: Entity<crate::views::proposals::Proposals>,
    events: Entity<TableState<EventsTable>>,
    events_page: Entity<EventsPage>,
    rules: Entity<TableState<RulesTable>>,
    rules_page: Entity<RulesPage>,
    history: Entity<History>,
    explorer: Entity<Explorer>,
    connections: Entity<TableState<ConnectionsTable>>,
    status: Entity<Status>,
    /// What weakens the session's protection, shown above every page.
    warnings: Vec<crate::session::Warning>,
    settings: Entity<Settings>,
    alerts: Entity<Alerts>,
    live: Entity<crate::views::live::Live>,
    system: Entity<SystemPage>,
    devices: Entity<crate::views::devices::Devices>,
    requests: mpsc::Sender<Request>,
}

impl App {
    pub fn new(
        requests: mpsc::Sender<Request>,
        updates: async_channel::Receiver<Update>,
        updates_sender: async_channel::Sender<Update>,
        tray: crate::tray::Tray,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let model = cx.new(|_| Model::default());
        let prompts = cx.new(|cx| Prompts::new(model.clone(), requests.clone(), cx));
        let proposals = cx
            .new(|cx| crate::views::proposals::Proposals::new(model.clone(), requests.clone(), cx));
        let events = cx.new(|cx| {
            TableState::new(
                EventsTable::new(
                    model.clone(),
                    requests.clone(),
                    &crate::prefs::Prefs::load().events_hidden,
                ),
                window,
                cx,
            )
        });
        let rules = cx.new(|cx| {
            TableState::new(RulesTable::new(model.clone(), requests.clone()), window, cx)
        });
        let status = cx.new(|cx| Status::new(model.clone(), cx));
        let settings = cx.new(|cx| Settings::new(model.clone(), requests.clone(), cx));
        let alerts = cx.new(|cx| Alerts::new(model.clone(), requests.clone(), cx));
        let live = cx.new(|cx| crate::views::live::Live::new(model.clone(), cx));
        let system = cx.new(|cx| SystemPage::new(model.clone(), requests.clone(), cx));
        let devices =
            cx.new(|cx| crate::views::devices::Devices::new(model.clone(), requests.clone(), cx));
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
        // The appearance chosen, or the desktop's (followed as it changes).
        let prefs = crate::prefs::Prefs::load();
        crate::prefs::apply(prefs.appearance, window, cx);
        cx.set_global(prefs);
        cx.observe_window_appearance(window, |_, window, cx| {
            if cx
                .try_global::<crate::prefs::Prefs>()
                .is_none_or(|p| p.appearance == crate::prefs::Appearance::System)
            {
                crate::prefs::apply(crate::prefs::Appearance::System, window, cx);
            }
        })
        .detach();
        let notices = notify::start(requests.clone(), updates_sender);
        let own_requests = requests.clone();
        for request in [
            Request::Status,
            Request::Rules,
            Request::Changes,
            Request::Alerts,
            Request::Proposals,
        ] {
            let _ = requests.send(request);
        }
        events::request_page(&model, &requests, cx);
        let rules_page =
            cx.new(|cx| RulesPage::new(model.clone(), requests.clone(), rules.clone(), window, cx));
        let events_page = cx
            .new(|cx| EventsPage::new(model.clone(), requests.clone(), events.clone(), window, cx));
        Self::fold_updates(updates, requests, notices, tray, cx);
        Self {
            model,
            page: Page::Events,
            prompts,
            proposals,
            events,
            events_page,
            rules,
            rules_page,
            history,
            explorer,
            connections,
            status,
            settings,
            warnings: crate::session::check(),
            alerts,
            live,
            system,
            devices,
            requests: own_requests,
        }
    }

    /// The backend's updates, folded into the model on the UI thread.
    fn fold_updates(
        updates: async_channel::Receiver<Update>,
        requests: mpsc::Sender<Request>,
        notices: async_channel::Sender<Notice>,
        tray: crate::tray::Tray,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |this, cx| {
            while let Ok(update) = updates.recv().await {
                let applied = this.update(cx, |app: &mut Self, cx| {
                    // Each prompt, and whether it was to be notified about.
                    let before: std::collections::HashMap<u64, bool> = app
                        .model
                        .read(cx)
                        .prompts
                        .iter()
                        .map(|(id, p)| (*id, p.notify))
                        .collect();
                    let changed = app.model.update(cx, |model, cx| {
                        let changed = model.apply(update);
                        cx.notify();
                        changed
                    });
                    // A notification for every prompt the node's routing says to notify about (when it opens, or when
                    // it is escalated to this client), and down with those resolved.
                    let prompts = &app.model.read(cx).prompts;
                    for (id, prompt) in prompts {
                        if prompt.notify && before.get(id) != Some(&true) {
                            let _ = notices.try_send(Notice::Show(Box::new(prompt.clone())));
                        }
                    }
                    for id in before.keys().filter(|id| !prompts.contains_key(id)) {
                        let _ = notices.try_send(Notice::Close(*id));
                    }
                    tray.set(u32::try_from(prompts.len()).unwrap_or(u32::MAX));
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
                        Changed::Connections => app.connections.update(cx, |table, cx| {
                            table.delegate_mut().recompute(cx);
                            table.refresh(cx);
                        }),
                        Changed::Rules => app.rules.update(cx, |table, cx| {
                            table.delegate_mut().recompute(cx);
                            table.refresh(cx);
                        }),
                        Changed::Prompts if !app.model.read(cx).prompts.is_empty() => {
                            app.page = Page::Prompts;
                        }
                        Changed::ShowPrompts => {
                            app.page = Page::Prompts;
                            cx.emit(Activate);
                            cx.activate(true);
                        }
                        Changed::ShowAlerts => {
                            app.page = Page::Alerts;
                            app.alerts.read(cx).refresh();
                            cx.emit(Activate);
                            cx.activate(true);
                        }
                        Changed::Alert => {
                            if let Some(alert) = app.model.read(cx).alerts.first() {
                                let _ = notices.try_send(Notice::Alert(alert.clone()));
                            }
                        }
                        Changed::AlertsOnNode => {
                            let _ = requests.send(Request::Alerts);
                        }
                        Changed::Proposal(id) => {
                            if let Some(proposal) = app.model.read(cx).proposals.get(&id) {
                                let _ =
                                    notices.try_send(Notice::Proposal(Box::new(proposal.clone())));
                            }
                        }
                        Changed::ShowProposals => {
                            app.page = Page::Proposals;
                            app.proposals.read(cx).refresh();
                            cx.emit(Activate);
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

    /// How many prompts wait on this node.
    pub fn waiting(&self, cx: &gpui::App) -> usize {
        self.model.read(cx).prompts.len()
    }

    /// Shows the prompts page.
    pub fn show_prompts(&mut self, cx: &mut Context<Self>) {
        self.page = Page::Prompts;
        cx.notify();
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
                if page == Page::Alerts {
                    app.alerts.read(cx).refresh();
                }
                if page == Page::Proposals {
                    app.proposals.read(cx).refresh();
                }
                if page == Page::Devices {
                    app.devices.read(cx).refresh();
                }
                cx.notify();
            }))
    }
}

impl App {
    /// The page shown.
    fn page(&self) -> AnyElement {
        match self.page {
            Page::Prompts => self.prompts.clone().into_any_element(),
            Page::Proposals => self.proposals.clone().into_any_element(),
            Page::Events => self.events_page.clone().into_any_element(),
            Page::Rules => self.rules_page.clone().into_any_element(),
            Page::History => self.history.clone().into_any_element(),
            Page::Explorer => self.explorer.clone().into_any_element(),
            Page::Connections => {
                let requests = self.requests.clone();
                v_flex()
                    .size_full()
                    .child(
                        h_flex()
                            .p_2()
                            .gap_2()
                            .child(
                                Button::new("refresh-connections")
                                    .small()
                                    .label("Refresh")
                                    .on_click(move |_, _, _| {
                                        let _ = requests.send(Request::Connections);
                                    }),
                            )
                            .child({
                                let model = self.model.clone();
                                Button::new("connections-csv")
                                    .small()
                                    .label("Copy CSV")
                                    .on_click(move |_, _, cx| {
                                        let csv = crate::views::connections::csv(
                                            &model.read(cx).connections,
                                        );
                                        cx.write_to_clipboard(gpui::ClipboardItem::new_string(csv));
                                    })
                            }),
                    )
                    .child(DataTable::new(&self.connections))
                    .into_any_element()
            }
            Page::Status => self.status.clone().into_any_element(),
            Page::Settings => self.settings.clone().into_any_element(),
            Page::Alerts => self.alerts.clone().into_any_element(),
            Page::Live => self.live.clone().into_any_element(),
            Page::Firewall => self.system.clone().into_any_element(),
            Page::Devices => self.devices.clone().into_any_element(),
        }
    }
}

impl App {
    /// The pages of this node, with counts of what waits.
    fn sidebar(&self, cx: &mut Context<Self>) -> Sidebar<SidebarGroup<SidebarMenu>> {
        let waiting = self.model.read(cx).prompts.len();
        let open_alerts = self.model.read(cx).open_alerts;
        let alerts_label: SharedString = if open_alerts == 0 {
            "Alerts".into()
        } else {
            format!("Alerts ({open_alerts})").into()
        };
        let proposing = self.model.read(cx).pending_proposals();
        let proposals_label: SharedString = if proposing == 0 {
            "Proposals".into()
        } else {
            format!("Proposals ({proposing})").into()
        };
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
        Sidebar::new("pages")
            .header(div().p_2().text_lg().child(node))
            .child(
                SidebarGroup::new("Node").child(
                    SidebarMenu::new()
                        .child(self.item(Page::Prompts, prompts_label, IconName::Bell, cx))
                        .child(self.item(
                            Page::Proposals,
                            proposals_label,
                            gpui_kit_assets::IconName::Bot,
                            cx,
                        ))
                        .child(self.item(
                            Page::Alerts,
                            alerts_label,
                            gpui_kit_assets::IconName::TriangleAlert,
                            cx,
                        ))
                        .child(self.item(
                            Page::Live,
                            "Live".into(),
                            gpui_kit_assets::IconName::Activity,
                            cx,
                        ))
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
                            Page::Devices,
                            "Devices".into(),
                            gpui_kit_assets::IconName::Smartphone,
                            cx,
                        ))
                        .child(self.item(
                            Page::Settings,
                            "Settings".into(),
                            IconName::Settings,
                            cx,
                        )),
                ),
            )
    }
}

impl Render for App {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let sidebar = self.sidebar(cx);
        let page = self.page();
        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar)
            .child(
                v_flex()
                    .flex_1()
                    .h_full()
                    .overflow_hidden()
                    .children(self.warnings.iter().map(|warning| {
                        div()
                            .px_4()
                            .py_2()
                            .bg(cx.theme().warning)
                            .text_color(cx.theme().warning_foreground)
                            .child(warning.text())
                    }))
                    .child(page),
            )
    }
}
