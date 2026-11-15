//! The window: a sidebar of pages, and the page shown.

use std::sync::mpsc;

use gpui::{
    AnyElement, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, Window, div,
};
use gpui_component::sidebar::{Sidebar, SidebarGroup, SidebarMenu, SidebarMenuItem};
use gpui_component::table::{DataTable, TableState};
use gpui_component::{ActiveTheme as _, IconName, h_flex, v_flex};

use crate::backend::{Request, Update};
use crate::model::{Changed, Model};
use crate::views::events::EventsTable;
use crate::views::prompts::Prompts;
use crate::views::rules::RulesTable;
use crate::views::status::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Prompts,
    Events,
    Rules,
    Status,
}

pub struct App {
    model: Entity<Model>,
    page: Page,
    prompts: Entity<Prompts>,
    events: Entity<TableState<EventsTable>>,
    rules: Entity<TableState<RulesTable>>,
    status: Entity<Status>,
}

impl App {
    pub fn new(
        requests: mpsc::Sender<Request>,
        updates: async_channel::Receiver<Update>,
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
        for request in [
            Request::Status,
            Request::Rules,
            Request::Events { before: 0 },
        ] {
            let _ = requests.send(request);
        }
        // The backend's updates, folded into the model on the UI thread.
        cx.spawn(async move |this, cx| {
            while let Ok(update) = updates.recv().await {
                let applied = this.update(cx, |app: &mut Self, cx| {
                    let changed = app.model.update(cx, |model, cx| {
                        let changed = model.apply(update);
                        cx.notify();
                        changed
                    });
                    match changed {
                        Changed::RulesOnNode => {
                            let _ = requests.send(Request::Rules);
                            let _ = requests.send(Request::Status);
                        }
                        Changed::Events => app.events.update(cx, TableState::refresh),
                        Changed::Rules => app.rules.update(cx, TableState::refresh),
                        Changed::Prompts if !app.model.read(cx).prompts.is_empty() => {
                            app.page = Page::Prompts;
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
        Self {
            model,
            page: Page::Events,
            prompts,
            events,
            rules,
            status,
        }
    }

    fn item(
        &self,
        page: Page,
        label: SharedString,
        icon: IconName,
        cx: &mut Context<Self>,
    ) -> SidebarMenuItem {
        SidebarMenuItem::new(label)
            .icon(icon)
            .active(self.page == page)
            .on_click(cx.listener(move |app, _, _, cx| {
                app.page = page;
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
                        .child(self.item(Page::Rules, "Rules".into(), IconName::BookOpen, cx))
                        .child(self.item(Page::Status, "Status".into(), IconName::Info, cx)),
                ),
            );
        let page: AnyElement = match self.page {
            Page::Prompts => self.prompts.clone().into_any_element(),
            Page::Events => DataTable::new(&self.events).into_any_element(),
            Page::Rules => DataTable::new(&self.rules).into_any_element(),
            Page::Status => self.status.clone().into_any_element(),
        };
        h_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar)
            .child(v_flex().flex_1().h_full().overflow_hidden().child(page))
    }
}
