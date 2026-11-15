//! Prompts: the connections waiting for an answer. Each shows who connects where and the rules it could leave, narrowest
//! first and chosen by default; the answer buttons arm only after a moment, so a keystroke meant for another window
//! can't answer a prompt that just appeared.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use gpui::{
    AnyElement, Context, Entity, IntoElement, ParentElement as _, Render, SharedString,
    Styled as _, Window, div, prelude::FluentBuilder as _,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Sizable as _, h_flex, v_flex};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;
use crate::views::events::protocol;

/// How long a new prompt's buttons stay disarmed.
pub const ARM_AFTER: Duration = Duration::from_millis(800);

/// Answer durations offered, in order.
const DURATIONS: [(v1::Duration, &str); 5] = [
    (v1::Duration::Once, "Once"),
    (v1::Duration::UntilRestart, "Until restart"),
    (v1::Duration::Hour, "1 hour"),
    (v1::Duration::HalfDay, "12 hours"),
    (v1::Duration::Forever, "Forever"),
];

#[derive(Debug, Clone, Copy)]
struct Choice {
    suggestion: usize,
    duration: usize,
    shown: Instant,
}

pub struct Prompts {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    choices: HashMap<u64, Choice>,
}

impl Prompts {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |this, model, cx| {
            let ids: Vec<u64> = model.read(cx).prompts.keys().copied().collect();
            this.choices.retain(|id, _| ids.contains(id));
            let now = Instant::now();
            for id in ids {
                this.choices.entry(id).or_insert(Choice {
                    suggestion: 0,
                    duration: DURATIONS.len() - 1,
                    shown: now,
                });
            }
            cx.notify();
        })
        .detach();
        Self {
            model,
            requests,
            choices: HashMap::new(),
        }
    }

    fn answer(&mut self, id: u64, action: v1::Action) {
        let Some(choice) = self.choices.get(&id) else {
            return;
        };
        let (duration, _) = DURATIONS
            .get(choice.duration)
            .copied()
            .unwrap_or(DURATIONS[0]);
        let _ = self.requests.send(Request::Answer {
            id,
            action,
            duration,
            suggestion: u32::try_from(choice.suggestion).unwrap_or(0),
        });
    }

    fn card(&self, prompt: &v1::Prompt, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let id = prompt.id;
        let choice = self.choices.get(&id).copied();
        let armed = choice.is_some_and(|c| c.shown.elapsed() >= ARM_AFTER);
        if !armed {
            // Draw again once the buttons arm.
            window.request_animation_frame();
        }
        let destination = prompt.hosts.first().cloned().unwrap_or_else(|| {
            snitchhiker_proto::convert::address_from(&prompt.address)
                .map_or_else(String::new, |a| a.to_string())
        });
        let user = if prompt.user.is_empty() {
            prompt.uid.to_string()
        } else {
            prompt.user.clone()
        };
        let theme = cx.theme().clone();
        let suggestions = prompt
            .suggestions
            .iter()
            .enumerate()
            .map(|(index, suggestion)| {
                let selected = choice.is_some_and(|c| c.suggestion == index);
                let button = Button::new(SharedString::from(format!("suggestion-{id}-{index}")))
                    .label(suggestion.label.clone())
                    .small()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if let Some(choice) = this.choices.get_mut(&id) {
                            choice.suggestion = index;
                        }
                        cx.notify();
                    }));
                let button = if selected {
                    button.primary()
                } else {
                    button.ghost()
                };
                h_flex()
                    .gap_2()
                    .child(button)
                    .when(suggestion.broad, |row| {
                        row.child(Tag::warning().small().child("broad"))
                    })
            });
        let durations = DURATIONS.iter().enumerate().map(|(index, (_, label))| {
            let button = Button::new(SharedString::from(format!("duration-{id}-{index}")))
                .label(*label)
                .small()
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(choice) = this.choices.get_mut(&id) {
                        choice.duration = index;
                    }
                    cx.notify();
                }));
            if choice.is_some_and(|c| c.duration == index) {
                button.primary()
            } else {
                button.ghost()
            }
        });
        let answer = |label: &'static str, action: v1::Action| {
            Button::new(SharedString::from(format!("{label}-{id}")))
                .label(label)
                .disabled(!armed)
                .on_click(cx.listener(move |this, _, _, _| this.answer(id, action)))
        };
        v_flex()
            .gap_3()
            .p_4()
            .border_1()
            .border_color(theme.border)
            .rounded_md()
            .bg(theme.background)
            .child(
                v_flex()
                    .gap_1()
                    .child(div().text_lg().child(program_name(prompt)))
                    .child(div().text_color(theme.muted_foreground).child(format!(
                        "{user} → {destination}:{} ({}), {} waiting",
                        prompt.port,
                        protocol(u8::try_from(prompt.protocol).unwrap_or(0)),
                        prompt.waiting
                    )))
                    .when(prompt.exe_writable, |info| {
                        info.child(
                            Tag::warning()
                                .child("Its executable is writable by a user other than root"),
                        )
                    }),
            )
            .child(v_flex().gap_1().children(suggestions))
            .child(h_flex().gap_1().children(durations))
            .child(
                h_flex()
                    .gap_2()
                    .child(answer("Allow", v1::Action::Allow).primary())
                    .child(answer("Deny", v1::Action::Deny))
                    .child(answer("Reject", v1::Action::Reject).danger()),
            )
            .into_any_element()
    }
}

impl Render for Prompts {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let prompts: Vec<v1::Prompt> = self.model.read(cx).prompts.values().cloned().collect();
        let muted = cx.theme().muted_foreground;
        let cards: Vec<AnyElement> = prompts.iter().map(|p| self.card(p, window, cx)).collect();
        v_flex()
            .size_full()
            .gap_4()
            .p_4()
            .when(cards.is_empty(), |page| {
                page.child(
                    div()
                        .text_color(muted)
                        .child("No connection is waiting for an answer."),
                )
            })
            .children(cards)
    }
}

/// The prompt's program, or what to say when it isn't known: a socket older than the daemon, or a process gone
/// before it was seen.
fn program_name(prompt: &v1::Prompt) -> String {
    if prompt.exe.is_empty() {
        "An unknown program".to_owned()
    } else {
        prompt.exe.clone()
    }
}
