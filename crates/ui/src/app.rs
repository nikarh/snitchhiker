//! The window: a sidebar of pages, and the page shown.

use std::sync::mpsc;

use gpui::prelude::FluentBuilder as _;
use gpui::{
    AnyElement, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, StatefulInteractiveElement as _, Styled as _, Window,
    div, px,
};
use gpui_component::button::Button;
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
use crate::views::rail;
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
    /// The Explorer, grouped by container (and VM, and named namespace).
    Containers,
    Connections,
    Rules,
    History,
    Status,
    Firewall,
    Devices,
    Blocklists,
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
    blocklists: Entity<crate::views::blocklists::Blocklists>,
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
        // The preferences first: the tables' columns are laid out with the widths kept there.
        let prefs = crate::prefs::Prefs::load();
        cx.set_global(prefs.clone());
        let model = cx.new(|_| Model::default());
        let prompts = cx.new(|cx| Prompts::new(model.clone(), requests.clone(), cx));
        let proposals = cx
            .new(|cx| crate::views::proposals::Proposals::new(model.clone(), requests.clone(), cx));
        let events = cx.new(|cx| {
            TableState::new(
                EventsTable::new(model.clone(), requests.clone(), &prefs.events_hidden),
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
        let blocklists = cx.new(|cx| {
            crate::views::blocklists::Blocklists::new(model.clone(), requests.clone(), cx)
        });
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
        crate::columns::keep("events", &events, cx);
        crate::columns::keep("rules", &rules, cx);
        crate::columns::keep("connections", &connections, cx);
        // The appearance chosen, or the desktop's (followed as it changes).
        crate::prefs::apply(prefs.appearance, window, cx);
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
            blocklists,
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
                            // New rows only: the columns (their widths and sorting) stay as they are.
                            app.events.update(cx, |_, cx| cx.notify());
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
                            cx.notify();
                        }),
                        Changed::Rules => app.rules.update(cx, |table, cx| {
                            table.delegate_mut().recompute(cx);
                            cx.notify();
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

    /// Shows `page`, asking the node for what it lists afresh.
    fn go(&mut self, page: Page, cx: &mut Context<Self>) {
        self.page = page;
        match page {
            Page::Explorer => self.explorer.read(cx).query(),
            Page::Containers => {
                self.explorer
                    .update(cx, |explorer, _| explorer.by_containers());
                self.explorer.read(cx).query();
            }
            Page::Connections => {
                let _ = self.requests.send(Request::Connections);
            }
            Page::Settings => self.settings.read(cx).refresh(),
            Page::Firewall => self.system.read(cx).refresh(),
            Page::Alerts => self.alerts.read(cx).refresh(),
            Page::Proposals => self.proposals.read(cx).refresh(),
            Page::Devices => self.devices.read(cx).refresh(),
            Page::Blocklists => self.blocklists.read(cx).refresh(),
            _ => {}
        }
        cx.notify();
    }
}

impl App {
    /// The name of the page shown, as the rail has it.
    fn title(&self) -> &'static str {
        Self::places(0, 0, 0)
            .into_iter()
            .flatten()
            .find(|(page, ..)| *page == self.page)
            .map_or("", |(_, label, ..)| label)
    }

    /// The page shown.
    fn page(&self) -> AnyElement {
        match self.page {
            Page::Prompts => self.prompts.clone().into_any_element(),
            Page::Proposals => self.proposals.clone().into_any_element(),
            Page::Events => self.events_page.clone().into_any_element(),
            Page::Rules => self.rules_page.clone().into_any_element(),
            Page::History => self.history.clone().into_any_element(),
            Page::Explorer | Page::Containers => self.explorer.clone().into_any_element(),
            Page::Connections => {
                let requests = self.requests.clone();
                v_flex()
                    .size_full()
                    .child(
                        h_flex()
                            .px_4()
                            .py_2()
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
            Page::Blocklists => self.blocklists.clone().into_any_element(),
        }
    }
}

impl App {
    /// The pages, in groups, with how many things wait on each.
    fn places(
        waiting: usize,
        proposing: usize,
        open_alerts: usize,
    ) -> [Vec<(Page, &'static str, gpui_component::Icon, usize)>; 4] {
        [
            vec![
                (Page::Prompts, "Prompts", IconName::Bell.into(), waiting),
                (
                    Page::Proposals,
                    "Proposals",
                    gpui_kit_assets::IconName::Bot.into(),
                    proposing,
                ),
                (
                    Page::Alerts,
                    "Alerts",
                    gpui_kit_assets::IconName::TriangleAlert.into(),
                    open_alerts,
                ),
            ],
            vec![
                (
                    Page::Live,
                    "Live",
                    gpui_kit_assets::IconName::Activity.into(),
                    0,
                ),
                (Page::Events, "Events", IconName::LayoutDashboard.into(), 0),
                (Page::Explorer, "Explorer", IconName::ChartPie.into(), 0),
                (
                    Page::Containers,
                    "Containers & VMs",
                    gpui_kit_assets::IconName::Container.into(),
                    0,
                ),
                (Page::Connections, "Connections", IconName::Globe.into(), 0),
            ],
            vec![
                (Page::Rules, "Rules", IconName::BookOpen.into(), 0),
                (Page::History, "History", IconName::Undo.into(), 0),
                (
                    Page::Firewall,
                    "Firewall",
                    gpui_kit_assets::IconName::Shield.into(),
                    0,
                ),
                (Page::Blocklists, "Blocklists", IconName::CircleX.into(), 0),
            ],
            vec![
                (Page::Status, "Status", IconName::Info.into(), 0),
                (
                    Page::Devices,
                    "Devices",
                    gpui_kit_assets::IconName::Smartphone.into(),
                    0,
                ),
                (Page::Settings, "Settings", IconName::Settings.into(), 0),
            ],
        ]
    }

    /// The pages of this node, in the order of the work: what waits for an answer, what happens, what decides, and
    /// the node itself; with counts of what waits.
    fn rail(&self, cx: &mut Context<Self>) -> AnyElement {
        let model = self.model.read(cx);
        let waiting = model.prompts.len();
        let open_alerts = usize::try_from(model.open_alerts).unwrap_or(usize::MAX);
        let proposing = model.pending_proposals();
        let node = model
            .node
            .as_ref()
            .map_or_else(|| "Snitchhiker".to_owned(), |n| n.node_name.clone());
        let state = match (&model.disconnected, &model.status) {
            (Some(_), _) => "not connected".to_owned(),
            (None, Some(status)) => status
                .mode()
                .as_str_name()
                .trim_start_matches("MODE_")
                .to_lowercase(),
            (None, None) => "connecting…".to_owned(),
        };
        let groups = Self::places(waiting, proposing, open_alerts);
        let theme = cx.theme().clone();
        let mut column = v_flex()
            .id("pages")
            .w(px(rail::WIDTH))
            .flex_none()
            .h_full()
            .overflow_y_scroll()
            .pb_3()
            .bg(theme.sidebar)
            .border_r_1()
            .border_color(theme.sidebar_border)
            .child(
                v_flex()
                    .flex_none()
                    .h(px(64.))
                    .justify_center()
                    .px_4()
                    .mb_2()
                    .border_b_1()
                    .border_color(theme.sidebar_accent)
                    .child(
                        div()
                            .text_color(gpui::white())
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_base()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(node),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.sidebar_foreground)
                            .child(state),
                    ),
            );
        for (index, group) in groups.into_iter().enumerate() {
            if index > 0 {
                column = column.child(rail::gap());
            }
            for (page, label, icon, count) in group {
                column = column.child(
                    rail::item(
                        SharedString::from(format!("page-{label}")),
                        Some(icon),
                        label,
                        self.page == page,
                        count,
                        cx,
                    )
                    .on_click(cx.listener(move |app, _, _, cx| app.go(page, cx))),
                );
            }
        }
        column.into_any_element()
    }

    /// The first prompt waiting, on every page but the prompts': it goes there.
    fn sign(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let prompts = &self.model.read(cx).prompts;
        let prompt = prompts.values().next()?;
        if self.page == Page::Prompts {
            return None;
        }
        let (what, detail) = crate::views::prompts::summary(prompt);
        let more = match prompts.len() {
            1 => String::new(),
            n => format!(" · {} more waiting", n - 1),
        };
        let mono = cx.theme().mono_font_family.clone();
        Some(
            h_flex()
                .id("prompt-sign")
                .flex_none()
                .gap_4()
                .px_5()
                .py_2p5()
                .bg(crate::theme::signal())
                .text_color(crate::theme::on_signal())
                .cursor_pointer()
                .on_click(cx.listener(|app, _, _, cx| app.go(Page::Prompts, cx)))
                .child(
                    gpui_component::Icon::new(gpui_kit_assets::IconName::ArrowRight)
                        .text_color(crate::theme::on_signal()),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .overflow_hidden()
                        .child(
                            div()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap()
                                .child(what),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_family(mono)
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap()
                                .child(format!("{detail}{more}")),
                        ),
                )
                .child(
                    div()
                        .flex_none()
                        .px_3()
                        .py_1()
                        .rounded(cx.theme().radius)
                        .bg(crate::theme::on_signal())
                        .text_color(gpui::white())
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("Answer"),
                )
                .into_any_element(),
        )
    }
}

impl Render for App {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let rail = self.rail(cx);
        let sign = self.sign(cx);
        let page = self.page();
        // A user outside the node's admin groups sees it and changes nothing.
        let viewer = self
            .model
            .read(cx)
            .node
            .as_ref()
            .is_some_and(|node| node.role() == snitchhiker_proto::v1::Role::Viewer);
        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(rail)
            .child(
                v_flex()
                    .flex_1()
                    // As narrow as the window leaves it: what is wider wraps or scrolls, never pushes out.
                    .min_w_0()
                    .h_full()
                    .overflow_hidden()
                    // What weakens the session, in one banner; dismissed until the app starts again.
                    .when(!self.warnings.is_empty(), |page| {
                        page.child(
                            h_flex()
                                .flex_none()
                                .items_start()
                                .gap_2()
                                .px_4()
                                .py_2()
                                .bg(cx.theme().warning)
                                .text_color(cx.theme().warning_foreground)
                                .child(
                                    v_flex()
                                        .flex_1()
                                        .min_w_0()
                                        .gap_1()
                                        .children(self.warnings.iter().map(|w| div().child(w.text()))),
                                )
                                .child(
                                    Button::new("dismiss-session-warnings")
                                        .small()
                                        .label("Dismiss")
                                        .tooltip("Hide these until the app starts again")
                                        .on_click(cx.listener(|app, _, _, cx| {
                                            app.warnings.clear();
                                            cx.notify();
                                        })),
                                ),
                        )
                    })
                    .children(sign)
                    .child(
                        h_flex()
                            .flex_none()
                            .h(px(44.))
                            .px_4()
                            .border_b_1()
                            .border_color(cx.theme().border)
                            .text_xl()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(self.title()),
                    )
                    // What the node refused or couldn't do, until dismissed: a change that didn't happen mustn't go
                    // unnoticed.
                    .children(self.model.read(cx).error.clone().map(|error| {
                        let model = self.model.clone();
                        h_flex()
                            .flex_none()
                            .gap_3()
                            .px_4()
                            .py_2()
                            .bg(cx.theme().danger)
                            .text_color(cx.theme().danger_foreground)
                            .child(div().flex_1().min_w_0().child(error))
                            .child(
                                Button::new("dismiss-error")
                                    .small()
                                    .label("Dismiss")
                                    .on_click(move |_, _, cx| {
                                        model.update(cx, |model, cx| {
                                            model.error = None;
                                            cx.notify();
                                        });
                                    }),
                            )
                    }))
                    .when(viewer, |this| {
                        this.child(
                            div()
                                .px_4()
                                .py_2()
                                .bg(cx.theme().secondary)
                                .text_color(cx.theme().secondary_foreground)
                                .child(
                                    "You can see this node, but not change it: changes are for the users in its \
                                     admin groups (admin_groups in /etc/snitchhiker/daemon.toml).",
                                ),
                        )
                    })
                    .child(page),
            )
    }
}
