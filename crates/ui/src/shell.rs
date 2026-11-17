//! The window: the nodes (this machine's, and the remote ones paired with this device) beside the one shown. Each
//! node has its own app (connection, model and pages), all live at once, so prompts and alerts of every node arrive;
//! the tray counts all of them.

use gpui::{
    AnyElement, AppContext as _, Context, Entity, IntoElement, ParentElement as _, Render,
    SharedString, StatefulInteractiveElement as _, Styled as _, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::{ActiveTheme as _, Disableable as _, Sizable as _, h_flex, v_flex};

use crate::app::{Activate, App};
use crate::backend::Target;
use crate::nodes::{Nodes, RemoteNode};
use crate::tray::Tray;

struct Node {
    name: SharedString,
    app: Entity<App>,
    /// None: this machine's.
    remote: Option<RemoteNode>,
}

/// The "Add node" form: a pairing link from the other node, and what this device is called there.
struct Adding {
    link: Entity<InputState>,
    name: Entity<InputState>,
    error: Option<String>,
    busy: bool,
}

/// What a node's pages ask of the shell.
pub enum Command {
    AddNode,
}

/// The shell's commands, for pages to send.
pub struct Commands(pub async_channel::Sender<Command>);

impl gpui::Global for Commands {}

pub struct Shell {
    nodes: Vec<Node>,
    current: usize,
    tray: Tray,
    adding: Option<Adding>,
}

impl Shell {
    pub fn new(local: Target, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (tray, clicks) = crate::tray::start_shared();
        let (commands, incoming) = async_channel::unbounded();
        cx.set_global(Commands(commands));
        cx.spawn_in(window, async move |shell, cx| {
            while let Ok(Command::AddNode) = incoming.recv().await {
                if shell
                    .update_in(cx, |shell: &mut Self, window, cx| {
                        shell.start_adding(window, cx);
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        // A click on the tray shows the first node with prompts waiting (or the one shown).
        cx.spawn(async move |shell, cx| {
            while clicks.recv().await.is_ok() {
                let shown = shell.update(cx, |shell: &mut Self, cx| {
                    let waiting = shell
                        .nodes
                        .iter()
                        .position(|n| n.app.read(cx).waiting(cx) > 0)
                        .unwrap_or(shell.current);
                    shell.current = waiting;
                    shell.adding = None;
                    if let Some(node) = shell.nodes.get(waiting) {
                        node.app.update(cx, App::show_prompts);
                    }
                    cx.activate(true);
                    cx.notify();
                });
                if shown.is_err() {
                    break;
                }
            }
        })
        .detach();
        let mut shell = Self {
            nodes: Vec::new(),
            current: 0,
            tray,
            adding: None,
        };
        shell.open("This machine".into(), local, None, window, cx);
        for remote in Nodes::load().node {
            if let Ok(key) = crate::nodes::device_key() {
                let target = Target::Remote {
                    node: remote.clone(),
                    key,
                };
                shell.open(remote.name.clone().into(), target, Some(remote), window, cx);
            }
        }
        shell
    }

    fn open(
        &mut self,
        name: SharedString,
        target: Target,
        remote: Option<RemoteNode>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let index = self.nodes.len();
        let tray = self.tray.for_node(index);
        let (requests, updates, sender) = crate::backend::start(target);
        let app = cx.new(|cx| App::new(requests, updates, sender, tray, window, cx));
        // A node's notification or tray click shows that node.
        cx.subscribe(&app, move |shell, _, _: &Activate, cx| {
            shell.current = index;
            shell.adding = None;
            cx.notify();
        })
        .detach();
        self.nodes.push(Node { name, app, remote });
    }

    fn start_adding(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let link = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("snitchhiker://pair?v=1&node=…  or  7-orbit-velvet-canyon")
        });
        let name =
            cx.new(|cx| InputState::new(window, cx).default_value(crate::nodes::device_name()));
        self.adding = Some(Adding {
            link,
            name,
            error: None,
            busy: false,
        });
        cx.notify();
    }

    fn pair(&mut self, cx: &mut Context<Self>) {
        let Some(adding) = self.adding.as_mut() else {
            return;
        };
        let text = adding.link.read(cx).value().to_string();
        let device_name = adding.name.read(cx).value().trim().to_owned();
        if !crate::remote::installed() {
            adding.error = Some(crate::remote::NOT_INSTALLED.to_owned());
            cx.notify();
            return;
        }
        let relays: Vec<String> = self
            .nodes
            .iter()
            .filter_map(|n| n.remote.as_ref())
            .flat_map(|r| r.relays.clone())
            .collect();
        adding.busy = true;
        adding.error = None;
        cx.notify();
        cx.spawn(async move |shell, cx| {
            let paired = cx
                .background_executor()
                .spawn(async move {
                    let key = crate::nodes::device_key().map_err(|e| e.to_string())?;
                    // A link, or a code to look up nearby or through the relays of the nodes already known.
                    let node = crate::remote::pair(&key, &text, &device_name, relays)?;
                    let mut nodes = Nodes::load();
                    nodes.node.retain(|n| n.id != node.id);
                    nodes.node.push(node.clone());
                    nodes.save().map_err(|e| e.to_string())?;
                    Ok::<_, String>((node, key))
                })
                .await;
            let _ = shell.update_in(cx, |shell: &mut Self, window, cx| match paired {
                Ok((node, key)) => {
                    shell.adding = None;
                    let target = Target::Remote {
                        node: node.clone(),
                        key,
                    };
                    shell
                        .nodes
                        .retain(|n| n.remote.as_ref().is_none_or(|r| r.id != node.id));
                    shell.open(node.name.clone().into(), target, Some(node), window, cx);
                    shell.current = shell.nodes.len() - 1;
                    cx.notify();
                }
                Err(error) => {
                    if let Some(adding) = shell.adding.as_mut() {
                        adding.busy = false;
                        adding.error = Some(error);
                    }
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Forgets a remote node (it stays paired on that node until unpaired there).
    fn forget(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(id) = self
            .nodes
            .get(index)
            .and_then(|n| n.remote.as_ref())
            .map(|r| r.id.clone())
        else {
            return;
        };
        let mut nodes = Nodes::load();
        nodes.node.retain(|n| n.id != id);
        let _ = nodes.save();
        self.nodes.remove(index);
        self.current = 0;
        cx.notify();
    }

    fn adding_form(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(adding) = &self.adding else {
            return div().into_any_element();
        };
        let theme = cx.theme().clone();
        v_flex()
            .size_full()
            .max_w(px(640.))
            .gap_3()
            .p_6()
            .child(
                div()
                    .text_xl()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Add a node"),
            )
            .child(div().text_color(theme.muted_foreground).child(
                "On the other node, run `sudo snitchhiker pair` (or Devices → Pair a device in its app), and paste \
                 the link it shows, or type its code.",
            ))
            .child(Input::new(&adding.link))
            .child(div().text_sm().text_color(theme.muted_foreground).child("This device's name there"))
            .child(Input::new(&adding.name))
            .when_some(adding.error.clone(), |form, error| {
                form.child(div().text_color(theme.danger).child(error))
            })
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("pair-node")
                            .primary()
                            .label(if adding.busy { "Pairing…" } else { "Pair" })
                            .disabled(adding.busy)
                            .on_click(cx.listener(|shell, _, _, cx| shell.pair(cx))),
                    )
                    .child(Button::new("cancel-pair-node").ghost().label("Cancel").on_click(cx.listener(
                        |shell, _, _, cx| {
                            shell.adding = None;
                            cx.notify();
                        },
                    ))),
            )
            .into_any_element()
    }
}

impl Render for Shell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        // With this machine's node alone there is nothing to choose: no column (Add node is on the Devices page).
        let column = v_flex()
            .w(px(168.))
            .flex_none()
            .h_full()
            .pt_4()
            .gap_0p5()
            .border_r_1()
            .border_color(theme.sidebar_accent)
            .bg(theme.sidebar)
            .child(
                div()
                    .px_4()
                    .pb_2()
                    .text_xs()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(theme.sidebar_foreground)
                    .child("Nodes"),
            )
            .children(self.nodes.iter().enumerate().map(|(index, node)| {
                let selected = index == self.current && self.adding.is_none();
                let waiting = node.app.read(cx).waiting(cx);
                crate::views::rail::item(
                    SharedString::from(format!("node-{index}")),
                    Some(gpui_component::Icon::new(if node.remote.is_some() {
                        gpui_kit_assets::IconName::Server
                    } else {
                        gpui_kit_assets::IconName::Monitor
                    })),
                    node.name.clone(),
                    selected,
                    waiting,
                    cx,
                )
                .on_click(cx.listener(move |shell, _, _, cx| {
                    shell.current = index;
                    shell.adding = None;
                    cx.notify();
                }))
                .when(node.remote.is_some() && selected, |row| {
                    row.child(
                        Button::new(SharedString::from(format!("forget-node-{index}")))
                            .xsmall()
                            .ghost()
                            .icon(gpui_kit_assets::IconName::X)
                            .tooltip("Forget this node")
                            .on_click(cx.listener(move |shell, _, _, cx| shell.forget(index, cx))),
                    )
                })
            }))
            .child(
                crate::views::rail::item(
                    "add-node",
                    Some(gpui_component::Icon::new(gpui_kit_assets::IconName::Plus)),
                    "Add node",
                    self.adding.is_some(),
                    0,
                    cx,
                )
                .on_click(cx.listener(|shell, _, window, cx| shell.start_adding(window, cx))),
            );
        let main = if self.adding.is_some() {
            self.adding_form(cx)
        } else {
            self.nodes.get(self.current).map_or_else(
                || div().into_any_element(),
                |n| n.app.clone().into_any_element(),
            )
        };
        h_flex()
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .when(self.nodes.len() > 1, |shell| shell.child(column))
            .child(div().flex_1().min_w_0().h_full().child(main))
    }
}
