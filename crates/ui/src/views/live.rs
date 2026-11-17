//! Live: connections as they happen. Allowed and blocked each second of the last two minutes, the busiest programs of
//! the last minute, and the newest connections (pausable: the counts go on).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gpui::{
    AnyElement, Context, Entity, InteractiveElement as _, IntoElement, ParentElement as _, Render,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use snitchhiker_proto::columns::EventRow;

use crate::model::{Live as LiveData, Model, address};
use crate::views::events::{action_tag, protocol, time};
use crate::views::text::clipped;

/// Connections shown in the feed.
const FEED: usize = 60;
/// Height of the busiest second's bar.
const CHART_HEIGHT: f32 = 80.;

pub struct Live {
    model: Entity<Model>,
    /// The feed as it was when paused.
    paused: Option<Vec<EventRow>>,
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Live {
    pub fn new(model: Entity<Model>, cx: &mut Context<Self>) -> Self {
        cx.observe(&model, |_, _, cx| cx.notify()).detach();
        // The chart moves with time, connections or not.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                if this.update(cx, |_, cx| cx.notify()).is_err() {
                    break;
                }
            }
        })
        .detach();
        Self {
            model,
            paused: None,
        }
    }

    /// Bars for each second of the last two minutes: allowed below, blocked on top.
    fn chart(live: &LiveData, now: u64, cx: &Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let counts: HashMap<u64, (u32, u32)> = live
            .seconds
            .iter()
            .map(|(s, a, b)| (*s, (*a, *b)))
            .collect();
        let busiest = counts
            .values()
            .map(|(a, b)| a + b)
            .max()
            .unwrap_or(1)
            .max(1);
        let height = |count: u32| {
            px(
                CHART_HEIGHT * f32::from(u16::try_from(count * 1000 / busiest).unwrap_or(1000))
                    / 1000.,
            )
        };
        let mut bars = h_flex().w_full().items_end().gap_px().h(px(CHART_HEIGHT));
        for second in now.saturating_sub(LiveData::SECONDS - 1)..=now {
            let (allowed, blocked) = counts.get(&second).copied().unwrap_or((0, 0));
            bars = bars.child(
                v_flex()
                    .flex_1()
                    .justify_end()
                    .child(div().h(height(blocked)).bg(theme.danger))
                    .child(div().h(height(allowed)).bg(theme.success)),
            );
        }
        v_flex()
            .gap_1()
            .child(bars)
            .child(
                h_flex()
                    .justify_between()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("2 minutes ago")
                    .child(format!("busiest second: {busiest}"))
                    .child("now"),
            )
            .into_any_element()
    }

    /// The programs with most connections in the last minute.
    fn busiest(model: &Model, now: u64, cx: &Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let mut counts: HashMap<u32, (u32, u32)> = HashMap::new();
        for row in model
            .live
            .recent
            .iter()
            .filter(|r| r.time_ms / 1000 + 60 > now)
        {
            let entry = counts.entry(row.exe).or_default();
            if row.action == 1 {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        let mut top: Vec<(u32, (u32, u32))> = counts.into_iter().collect();
        top.sort_by_key(|(_, (a, b))| std::cmp::Reverse(a + b));
        let mut list = v_flex().gap_1();
        if top.is_empty() {
            list = list.child(
                div()
                    .text_color(theme.muted_foreground)
                    .child("Nothing in the last minute."),
            );
        }
        for (exe, (allowed, blocked)) in top.into_iter().take(8) {
            let name = model.events.string(exe).unwrap_or("?").to_owned();
            list = list.child(
                h_flex()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(clipped(
                                gpui::SharedString::from(format!("top-{exe}")),
                                name,
                            )),
                    )
                    .child(div().w(px(70.)).text_right().child(allowed.to_string()))
                    .child(
                        div()
                            .w(px(70.))
                            .text_right()
                            .text_color(theme.danger)
                            .child(blocked.to_string()),
                    ),
            );
        }
        list.into_any_element()
    }

    fn feed(&self, model: &Model, rows: &[EventRow], cx: &Context<Self>) -> AnyElement {
        let theme = cx.theme();
        let _ = self;
        let mut list = v_flex();
        for row in rows {
            let destination = match model.events.string(row.host) {
                Some(host) if row.host != 0 => host.to_owned(),
                _ => address(row).to_string(),
            };
            list = list.child(
                h_flex()
                    .gap_3()
                    .py_0p5()
                    .child(
                        div()
                            .w(px(80.))
                            .flex_none()
                            .whitespace_nowrap()
                            .text_color(theme.muted_foreground)
                            .child(
                                time(row.time_ms)
                                    .split(' ')
                                    .nth(1)
                                    .unwrap_or_default()
                                    .to_owned(),
                            ),
                    )
                    .child(
                        h_flex()
                            .w(px(70.))
                            .flex_none()
                            .child(action_tag(row.action)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(clipped(
                                gpui::SharedString::from(format!("recent-exe-{}", row.seq)),
                                model.events.string(row.exe).unwrap_or("?").to_owned(),
                            )),
                    )
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .text_ellipsis()
                            .child(clipped(
                                gpui::SharedString::from(format!("recent-to-{}", row.seq)),
                                format!("{destination}:{}/{}", row.port, protocol(row.protocol)),
                            )),
                    ),
            );
        }
        list.into_any_element()
    }
}

impl Render for Live {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let now = now_s();
        let model = self.model.read(cx);
        let (allowed, blocked) = model.live.totals(now, 60);
        let rows: Vec<EventRow> = self
            .paused
            .clone()
            .unwrap_or_else(|| model.live.recent.iter().take(FEED).copied().collect());
        let chart = Self::chart(&model.live, now, cx);
        let busiest = Self::busiest(model, now, cx);
        let feed = self.feed(model, &rows, cx);
        let theme = cx.theme().clone();
        let paused = self.paused.is_some();
        div().id("live-page").size_full().overflow_y_scroll().child(
            v_flex()
                .p_4()
                .gap_4()
                .child(
                    h_flex()
                        .gap_6()
                        .child(div().text_lg().child(format!("{allowed} allowed")))
                        .child(
                            div()
                                .text_lg()
                                .text_color(theme.danger)
                                .child(format!("{blocked} blocked")),
                        )
                        .child(
                            div()
                                .text_color(theme.muted_foreground)
                                .child("in the last minute"),
                        ),
                )
                .child(chart)
                .child(
                    h_flex()
                        .items_start()
                        .gap_6()
                        .child(
                            v_flex()
                                .w(px(360.))
                                .flex_none()
                                .gap_2()
                                .child(
                                    div()
                                        .text_color(theme.muted_foreground)
                                        .child("Busiest programs, last minute"),
                                )
                                .child(busiest),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_2()
                                .child(
                                    h_flex()
                                        .gap_3()
                                        .child(
                                            div()
                                                .text_color(theme.muted_foreground)
                                                .child("Newest connections"),
                                        )
                                        .child(
                                            Button::new("live-pause")
                                                .small()
                                                .label(if paused { "Resume" } else { "Pause" })
                                                .when_primary(paused)
                                                .on_click(cx.listener(|live, _, _, cx| {
                                                    live.paused = match live.paused.take() {
                                                        Some(_) => None,
                                                        None => Some(
                                                            live.model
                                                                .read(cx)
                                                                .live
                                                                .recent
                                                                .iter()
                                                                .take(FEED)
                                                                .copied()
                                                                .collect(),
                                                        ),
                                                    };
                                                    cx.notify();
                                                })),
                                        ),
                                )
                                .child(feed),
                        ),
                ),
        )
    }
}

/// Primary when `on`.
trait WhenPrimary {
    fn when_primary(self, on: bool) -> Self;
}

impl WhenPrimary for Button {
    fn when_primary(self, on: bool) -> Self {
        if on { self.primary() } else { self }
    }
}
