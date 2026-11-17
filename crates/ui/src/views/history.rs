//! History: every change to rules and folders, newest first, who made it, and undo.

use std::sync::mpsc;

use gpui::{
    Context, Entity, IntoElement, ParentElement as _, Render, SharedString, Styled as _, Window,
    div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};

use crate::backend::Request;
use crate::model::Model;
use crate::views::events::time;
use crate::views::text::clipped;

pub struct History {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
}

impl History {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        Self { model, requests }
    }
}

impl Render for History {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let border = cx.theme().border;
        let changes = self.model.read(cx).changes.clone();
        let mut list = v_flex().p_4().gap_1();
        if changes.is_empty() {
            list = list.child(div().text_color(muted).child("No changes yet."));
        }
        let mut previous_batch = None;
        for change in changes {
            // The undo button goes on the newest change of each batch: it undoes the whole batch.
            let first_of_batch = previous_batch != Some(change.batch);
            previous_batch = Some(change.batch);
            let requests = self.requests.clone();
            let id = change.id;
            list = list.child(
                h_flex()
                    .gap_4()
                    .py_1()
                    .border_b_1()
                    .border_color(border)
                    .child(
                        div()
                            .w_48()
                            .flex_none()
                            .text_color(muted)
                            .child(time(change.time_ms)),
                    )
                    .child(
                        div()
                            .w(px(150.))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .text_color(muted)
                            .child(clipped(
                                SharedString::from(format!("change-app-{id}")),
                                change.app.clone(),
                            )),
                    )
                    .child(div().flex_1().min_w_0().child(change.what.clone()))
                    .child(if first_of_batch {
                        Button::new(SharedString::from(format!("undo-{id}")))
                            .small()
                            .ghost()
                            .label("Undo")
                            .on_click(move |_, _, _| {
                                let _ = requests.send(Request::Undo { change: id });
                            })
                            .into_any_element()
                    } else {
                        div().w_16().into_any_element()
                    }),
            );
        }
        list
    }
}
