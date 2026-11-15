//! Devices: the phones and other machines paired with this node (plan §8.3), and pairing another one with a link
//! and its QR code.

use std::sync::mpsc;

use gpui::{
    AnyElement, Context, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    SharedString, StatefulInteractiveElement as _, Styled as _, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;

pub struct Devices {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl Devices {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self { model, requests }
    }

    pub fn refresh(&self) {
        let _ = self.requests.send(Request::Devices);
    }
}

/// A QR code of `text`, drawn as cells.
pub fn qr(text: &str, cell: f32) -> AnyElement {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else {
        return div().into_any_element();
    };
    let width = code.width();
    let colors = code.to_colors();
    // A quiet zone of four cells, white, around the code, whatever the theme.
    v_flex()
        .p(px(cell * 4.))
        .bg(gpui::white())
        .children(colors.chunks(width).map(|row| {
            h_flex().children(row.iter().map(|color| {
                div().size(px(cell)).bg(if *color == qrcode::Color::Dark {
                    gpui::black()
                } else {
                    gpui::white()
                })
            }))
        }))
        .into_any_element()
}

/// Adding another node to manage.
fn other_nodes(theme: &gpui_component::theme::Theme) -> AnyElement {
    v_flex()
        .gap_2()
        .child(div().pt_4().text_lg().child("Other nodes"))
        .child(div().text_color(theme.muted_foreground).child(
            "This app can manage other nodes too (a server, another machine): pair it with one.",
        ))
        .child(
            h_flex().child(
                Button::new("add-node-from-devices")
                    .small()
                    .label("Add node")
                    .on_click(|_, _, cx| {
                        if let Some(commands) = cx.try_global::<crate::shell::Commands>() {
                            let _ = commands.0.try_send(crate::shell::Command::AddNode);
                        }
                    }),
            ),
        )
        .into_any_element()
}

/// One paired device: its name, role, fingerprint, whether it is connected, and Mute and Unpair.
fn device_row(
    device: &v1::Device,
    requests: &mpsc::Sender<Request>,
    theme: &gpui_component::theme::Theme,
) -> AnyElement {
    let id = device.id.clone();
    let requests = requests.clone();
    h_flex()
        .gap_3()
        .py_1()
        .border_b_1()
        .border_color(theme.border)
        .child(div().w_48().child(device.name.clone()))
        .child(div().w_16().child(if device.role() == v1::Role::Viewer {
            "viewer"
        } else {
            "admin"
        }))
        .child(
            div()
                .w_32()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(device.fingerprint.clone()),
        )
        .child(if device.connected {
            Tag::success().small().child("connected").into_any_element()
        } else {
            div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(ago(device.last_seen_ms))
                .into_any_element()
        })
        .child(div().flex_1())
        .child({
            let (id, requests, muted) = (id.clone(), requests.clone(), device.muted);
            Button::new(SharedString::from(format!("mute-{id}")))
                .small()
                .ghost()
                .label(if muted { "Unmute" } else { "Mute" })
                .tooltip("Muted devices aren't notified of prompts (they still list them)")
                .on_click(move |_, _, _| {
                    let _ = requests.send(Request::MuteDevice {
                        id: id.clone(),
                        muted: !muted,
                    });
                    let _ = requests.send(Request::Devices);
                })
        })
        .child(
            Button::new(SharedString::from(format!("unpair-{id}")))
                .small()
                .ghost()
                .label("Unpair")
                .on_click(move |_, _, _| {
                    let _ = requests.send(Request::RemoveDevice(id.clone()));
                    let _ = requests.send(Request::Devices);
                }),
        )
        .into_any_element()
}

fn ago(ms: u64) -> String {
    if ms == 0 {
        return "never connected".to_owned();
    }
    format!("last seen {}", crate::views::events::time(ms))
}

impl Devices {
    /// The pairing started: its QR code and link.
    fn pairing_panel(
        &self,
        pairing: &v1::Pairing,
        requests: mpsc::Sender<Request>,
        theme: &gpui_component::theme::Theme,
    ) -> AnyElement {
        let model = self.model.clone();
        let link = pairing.link.clone();
        v_flex()
            .gap_2()
            .p_4()
            .border_1()
            .border_color(theme.border)
            .rounded_md()
            .child(div().text_lg().child("Pair a device"))
            .child(div().text_color(theme.muted_foreground).child(
                "Scan the code with the phone, or paste the link into Add node on the other machine. It \
                 pairs one device, within 10 minutes.",
            ))
            .child(h_flex().child(qr(&pairing.link, 4.)))
            .child(div().text_sm().child(pairing.link.clone()))
            .child(div().text_sm().text_color(theme.muted_foreground).child(format!(
                "The other device should show this node as {}",
                pairing.fingerprint
            )))
            .child(
                h_flex()
                    .gap_2()
                    .child(Button::new("copy-pairing-link").small().label("Copy the link").on_click(
                        move |_, _, cx| cx.write_to_clipboard(gpui::ClipboardItem::new_string(link.clone())),
                    ))
                    .child(Button::new("close-pairing").small().ghost().label("Done").on_click(
                        move |_, _, cx| {
                            model.update(cx, |model, cx| {
                                model.pairing = None;
                                cx.notify();
                            });
                            let _ = requests.send(Request::Devices);
                        },
                    )),
            )
        .into_any_element()
    }
}

impl Render for Devices {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let model = self.model.read(cx);
        let theme = cx.theme().clone();
        let list = model.devices.clone();
        let pairing = model.pairing.clone();
        let requests = self.requests.clone();
        let mut page = v_flex().gap_3().p_4();
        match &list {
            None => page = page.child(div().text_color(theme.muted_foreground).child("Loading…")),
            Some(list) if !list.remote => {
                page = page.child(div().text_color(theme.muted_foreground).child(
                    "This node doesn't accept devices over the network: set remote = true in its daemon.toml.",
                ));
            }
            Some(list) => {
                page = page
                    .child(
                        h_flex()
                            .gap_3()
                            .child(div().text_lg().child("Paired devices"))
                            .child({
                                let requests = requests.clone();
                                Button::new("pair-device")
                                    .small()
                                    .primary()
                                    .label("Pair a device")
                                    .on_click(move |_, _, _| {
                                        let _ =
                                            requests.send(Request::StartPairing(v1::Role::Admin));
                                    })
                            }),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(format!("This node: {}", list.fingerprint)),
                    )
                    .when(list.devices.is_empty(), |page| {
                        page.child(
                            div()
                                .text_color(theme.muted_foreground)
                                .child("No device is paired."),
                        )
                    })
                    .children(
                        list.devices
                            .iter()
                            .map(|device| device_row(device, &requests, &theme)),
                    );
            }
        }
        if let Some(pairing) = pairing {
            page = page.child(self.pairing_panel(&pairing, requests, &theme));
        }
        page = page.child(other_nodes(&theme));
        div()
            .id("devices")
            .size_full()
            .overflow_y_scroll()
            .child(page)
    }
}
