//! Proposals: rules coding agents proposed (decision 0008), for a person to review. Each shows who proposed (as the
//! kernel says), the agent's words marked as unverified, and the rules as the node shaped them: their marks, and the
//! refused connections they would let through. Hosts and ports can be narrowed and rules dropped before approving;
//! the buttons arm only after a moment, as a prompt's do.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Instant;

use gpui::{
    AnyElement, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, SharedString, StatefulInteractiveElement as _, Styled as _, Window,
    div, prelude::FluentBuilder as _,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{Input, InputState};
use gpui_component::tag::Tag;
use gpui_component::{ActiveTheme as _, Disableable as _, Sizable as _, h_flex, v_flex};
use snitchhiker_proto::{convert, v1};

use crate::backend::Request;
use crate::model::Model;
use crate::views::prompts::Focus;

/// Durations offered, in order; the session's first.
const DURATIONS: [(v1::ProposalDuration, &str); 4] = [
    (v1::ProposalDuration::Session, "While the agent runs"),
    (v1::ProposalDuration::Hour, "1 hour"),
    (v1::ProposalDuration::TwelveHours, "12 hours"),
    (v1::ProposalDuration::Forever, "Forever"),
];

/// A proposal being reviewed: what the person changed so far.
struct Draft {
    shown: Instant,
    duration: usize,
    include: Vec<bool>,
    hosts: Vec<Entity<InputState>>,
    ports: Vec<Entity<InputState>>,
    reason: Entity<InputState>,
}

pub struct Proposals {
    model: Entity<Model>,
    requests: mpsc::Sender<Request>,
    drafts: HashMap<u64, Draft>,
    focus: Focus,
}

impl Proposals {
    pub fn new(
        model: Entity<Model>,
        requests: mpsc::Sender<Request>,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&model, |this, model, cx| {
            let pending: Vec<u64> = model
                .read(cx)
                .proposals
                .values()
                .filter(|p| p.state() == v1::ProposalState::Pending)
                .map(|p| p.id)
                .collect();
            this.drafts.retain(|id, _| pending.contains(id));
            cx.notify();
        })
        .detach();
        Self {
            model,
            requests,
            drafts: HashMap::new(),
            focus: Focus::default(),
        }
    }

    /// Lists the proposals again (those answered too).
    pub fn refresh(&self) {
        let _ = self.requests.send(Request::Proposals);
        let _ = self.requests.send(Request::Envelopes);
    }

    fn draft(&mut self, proposal: &v1::Proposal, window: &mut Window, cx: &mut Context<Self>) {
        if self.drafts.contains_key(&proposal.id) {
            return;
        }
        let input = |value: String, window: &mut Window, cx: &mut Context<Self>| {
            cx.new(|cx| InputState::new(window, cx).default_value(value))
        };
        let conditions = |r: &v1::ShapedRule| r.conditions.clone().unwrap_or_default();
        let hosts = proposal
            .rules
            .iter()
            .map(|r| {
                let c = conditions(r);
                input(
                    c.host
                        .iter()
                        .chain(&c.net)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    window,
                    cx,
                )
            })
            .collect();
        let ports = proposal
            .rules
            .iter()
            .map(|r| input(conditions(r).port.join(", "), window, cx))
            .collect();
        let reason = cx.new(|cx| {
            InputState::new(window, cx).placeholder("A reason, told to the agent (optional)")
        });
        self.drafts.insert(
            proposal.id,
            Draft {
                shown: Instant::now(),
                duration: 0,
                include: proposal.rules.iter().map(|r| !r.already_allowed).collect(),
                hosts,
                ports,
                reason,
            },
        );
    }

    fn decide(&self, proposal: &v1::Proposal, approve: bool, mute: bool, cx: &Context<Self>) {
        let Some(draft) = self.drafts.get(&proposal.id) else {
            return;
        };
        let text = |input: &Entity<InputState>| input.read(cx).value().to_string();
        let mut rules = Vec::new();
        let mut edited = false;
        for (index, rule) in proposal.rules.iter().enumerate() {
            let included = draft.include.get(index).copied().unwrap_or(false);
            let original = rule.conditions.clone().unwrap_or_default();
            if included == rule.already_allowed {
                edited = true;
            }
            if !included {
                continue;
            }
            let mut conditions = original.clone();
            conditions.host.clear();
            conditions.net.clear();
            for item in list(&draft.hosts.get(index).map_or_else(String::new, text)) {
                if item.parse::<ipnet::IpNet>().is_ok() || item.parse::<std::net::IpAddr>().is_ok()
                {
                    conditions.net.push(item);
                } else {
                    conditions.host.push(item);
                }
            }
            conditions.port = list(&draft.ports.get(index).map_or_else(String::new, text));
            if conditions != original {
                edited = true;
            }
            rules.push(v1::EditedRule {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                conditions: Some(conditions),
            });
        }
        let (duration, _) = DURATIONS
            .get(draft.duration)
            .copied()
            .unwrap_or(DURATIONS[0]);
        let _ = self.requests.send(Request::Decide(v1::DecideProposal {
            id: proposal.id,
            approve,
            reason: text(&draft.reason).trim().to_owned(),
            duration: duration.into(),
            rules: if edited { rules } else { Vec::new() },
            mute,
        }));
    }

    /// One rule of a pending proposal: whether it is kept, where to (editable), its marks and evidence.
    fn rule(&self, proposal: &v1::Proposal, index: usize, cx: &mut Context<Self>) -> AnyElement {
        let id = proposal.id;
        let theme = cx.theme().clone();
        let (Some(draft), Some(rule)) = (self.drafts.get(&id), proposal.rules.get(index)) else {
            return div().into_any_element();
        };
        let included = draft.include.get(index).copied().unwrap_or(false);
        let conditions = rule.conditions.clone().unwrap_or_default();
        let program = conditions
            .exe
            .first()
            .cloned()
            .unwrap_or_else(|| "Any program".to_owned());
        v_flex()
            .gap_1()
            .p_2()
            .border_1()
            .border_color(theme.border)
            .rounded_md()
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new(SharedString::from(format!("include-{id}-{index}")))
                            .xsmall()
                            .ghost()
                            .icon(if included {
                                gpui_kit_assets::IconName::SquareCheck
                            } else {
                                gpui_kit_assets::IconName::Square
                            })
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(include) = this
                                    .drafts
                                    .get_mut(&id)
                                    .and_then(|d| d.include.get_mut(index))
                                {
                                    *include = !*include;
                                }
                                cx.notify();
                            })),
                    )
                    .child(div().child(program))
                    .when(!conditions.protocol.is_empty(), |row| {
                        row.child(
                            div()
                                .text_color(theme.muted_foreground)
                                .child(conditions.protocol.join(", ")),
                        )
                    })
                    .when(rule.already_allowed, |row| {
                        row.child(Tag::secondary().small().child("already allowed"))
                    })
                    .children(
                        rule.risks
                            .iter()
                            .map(|r| Tag::warning().small().child(r.description.clone())),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(div().w_16().text_color(theme.muted_foreground).child("To"))
                    .child(
                        div()
                            .flex_1()
                            .children(draft.hosts.get(index).map(Input::new)),
                    ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        div()
                            .w_16()
                            .text_color(theme.muted_foreground)
                            .child("Ports"),
                    )
                    .child(
                        div()
                            .flex_1()
                            .children(draft.ports.get(index).map(Input::new)),
                    ),
            )
            .child(evidence(rule, &theme))
            .into_any_element()
    }

    fn card(
        &mut self,
        proposal: &v1::Proposal,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        self.draft(proposal, window, cx);
        let id = proposal.id;
        let theme = cx.theme().clone();
        let Some(draft) = self.drafts.get(&id) else {
            return div().into_any_element();
        };
        let armed = self.focus.armed(draft.shown, window);
        let provenance = proposal.provenance.clone().unwrap_or_default();
        let rules: Vec<AnyElement> = (0..proposal.rules.len())
            .map(|index| self.rule(proposal, index, cx))
            .collect();
        let durations = DURATIONS.iter().enumerate().map(|(index, (_, label))| {
            let button = Button::new(SharedString::from(format!(
                "proposal-duration-{id}-{index}"
            )))
            .label(*label)
            .small()
            .on_click(cx.listener(move |this, _, _, cx| {
                if let Some(draft) = this.drafts.get_mut(&id) {
                    draft.duration = index;
                }
                cx.notify();
            }));
            if draft.duration == index {
                button.primary()
            } else {
                button.ghost()
            }
        });
        let approve = {
            let proposal = proposal.clone();
            Button::new(SharedString::from(format!("approve-{id}")))
                .label(if proposal.broad {
                    "Approve (asks for a password)"
                } else {
                    "Approve"
                })
                .primary()
                .disabled(!armed || !draft.include.iter().any(|i| *i))
                .on_click(
                    cx.listener(move |this, _, _, cx| this.decide(&proposal, true, false, cx)),
                )
        };
        let deny = {
            let proposal = proposal.clone();
            Button::new(SharedString::from(format!("deny-{id}")))
                .label("Deny")
                .disabled(!armed)
                .on_click(
                    cx.listener(move |this, _, _, cx| this.decide(&proposal, false, false, cx)),
                )
        };
        let mute = {
            let proposal = proposal.clone();
            Button::new(SharedString::from(format!("mute-{id}")))
                .label("Deny and mute this agent")
                .ghost()
                .disabled(!armed)
                .on_click(
                    cx.listener(move |this, _, _, cx| this.decide(&proposal, false, true, cx)),
                )
        };
        v_flex()
            .gap_3()
            .p_4()
            .border_1()
            .border_color(theme.border)
            .rounded_md()
            .bg(theme.background)
            .child(header(&provenance, &theme))
            .child(agents_words(
                "The agent says (not verified):",
                &proposal.justification,
                &theme,
            ))
            .child(v_flex().gap_2().children(rules))
            .child(h_flex().gap_1().children(durations))
            .child(Input::new(&draft.reason))
            .child(h_flex().gap_2().child(approve).child(deny).child(mute))
            .into_any_element()
    }
}

/// An agent's words, set apart and labelled as unverified.
pub fn agents_words(
    label: &'static str,
    text: &str,
    theme: &gpui_component::theme::Theme,
) -> AnyElement {
    v_flex()
        .gap_1()
        .p_2()
        .rounded_md()
        .bg(theme.muted)
        .child(
            div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(label),
        )
        .child(div().child(plain(text)))
        .into_any_element()
}

/// Who proposed, as the kernel says.
fn header(provenance: &v1::Provenance, theme: &gpui_component::theme::Theme) -> AnyElement {
    let project = if provenance.cwd.is_empty() {
        "?"
    } else {
        provenance.cwd.as_str()
    };
    let user = if provenance.user.is_empty() {
        provenance.uid.to_string()
    } else {
        provenance.user.clone()
    };
    v_flex()
        .gap_1()
        .child(
            h_flex()
                .gap_2()
                .child(div().text_lg().child(provenance.agent_exe.clone()))
                .when(provenance.known_agent, |row| {
                    row.child(Tag::success().small().child("a listed agent"))
                }),
        )
        .child(div().text_color(theme.muted_foreground).child(format!(
            "in {project} · {user} · pid {}",
            provenance.agent_pid
        )))
        .when(!provenance.ancestors.is_empty(), |info| {
            let chain: Vec<&str> = provenance
                .ancestors
                .iter()
                .take(3)
                .map(String::as_str)
                .collect();
            info.child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(format!("started by {}", chain.join(" ← "))),
            )
        })
        .into_any_element()
}

/// The agent's refused connections a rule would let through.
fn evidence(rule: &v1::ShapedRule, theme: &gpui_component::theme::Theme) -> AnyElement {
    let muted = theme.muted_foreground;
    v_flex()
        .children(rule.evidence.iter().map(|e| {
            let destination = if e.host.is_empty() {
                convert::address_from(&e.address).map_or_else(String::new, |a| a.to_string())
            } else {
                e.host.clone()
            };
            div().text_sm().text_color(muted).child(format!(
                "refused: {} → {destination}:{} ×{}",
                e.exe, e.port, e.count
            ))
        }))
        .when(rule.evidence.is_empty(), |list| {
            list.child(
                div()
                    .text_sm()
                    .text_color(muted)
                    .child("Nothing the agent ran was refused this: it is a guess."),
            )
        })
        .into_any_element()
}

/// Text as it is, without control characters (no escape sequences, no hidden direction changes).
pub fn plain(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .filter(|c| !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .collect()
}

/// Items of a list typed with commas or spaces.
fn list(text: &str) -> Vec<String> {
    text.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn state(state: v1::ProposalState) -> &'static str {
    match state {
        v1::ProposalState::Pending => "waiting",
        v1::ProposalState::Approved => "approved",
        v1::ProposalState::Denied => "denied",
        v1::ProposalState::Withdrawn => "withdrawn",
        v1::ProposalState::Expired => "expired",
        v1::ProposalState::Unspecified => "?",
    }
}

impl Render for Proposals {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.focus.update(window);
        let proposals: Vec<v1::Proposal> = self
            .model
            .read(cx)
            .proposals
            .values()
            .rev()
            .cloned()
            .collect();
        let (pending, answered): (Vec<_>, Vec<_>) = proposals
            .into_iter()
            .partition(|p| p.state() == v1::ProposalState::Pending);
        let muted = cx.theme().muted_foreground;
        let cards: Vec<AnyElement> = pending.iter().map(|p| self.card(p, window, cx)).collect();
        let history = answered.iter().take(50).map(|p| {
            let provenance = p.provenance.clone().unwrap_or_default();
            let agent = provenance
                .agent_exe
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_owned();
            h_flex()
                .gap_3()
                .child(
                    div()
                        .w_40()
                        .text_color(muted)
                        .child(crate::views::events::time(p.created_ms)),
                )
                .child(div().w_24().child(state(p.state())))
                .child(div().w_32().child(agent))
                .child(div().flex_1().text_color(muted).child(format!(
                    "{} rule{} for {}{}",
                    p.rules.len(),
                    if p.rules.len() == 1 { "" } else { "s" },
                    provenance.cwd,
                    if p.reason.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", p.reason)
                    }
                )))
        });
        let page = v_flex()
            .gap_4()
            .p_4()
            .when(cards.is_empty(), |page| {
                page.child(
                    div()
                        .text_color(muted)
                        .child("No agent's proposal is waiting for an answer."),
                )
            })
            .children(cards)
            .when(!answered.is_empty(), |page| {
                page.child(
                    div()
                        .text_lg()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("Answered"),
                )
                .children(history)
            })
            .child(crate::views::envelopes::section(
                self.model.read(cx).envelopes.as_ref(),
                &self.requests,
                cx,
            ));
        div()
            .id("proposals")
            .size_full()
            .overflow_y_scroll()
            .child(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_text_loses_what_could_hide_in_it() {
        assert_eq!(
            plain("ok\u{1b}[31m red\u{202e}gnp.exe\n"),
            "ok[31m redgnp.exe\n"
        );
    }

    #[test]
    fn lists_take_commas_and_spaces() {
        assert_eq!(
            list("crates.io, static.crates.io  443"),
            ["crates.io", "static.crates.io", "443"]
        );
    }
}
