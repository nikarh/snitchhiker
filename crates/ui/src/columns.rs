//! Column widths the user set, kept per table and column in the preferences: a table's delegate asks [`width`] for
//! each column, and [`keep`] records a resize as it happens. New rows only re-render a table (its columns stay as
//! they are); a table's columns are rebuilt only when the set of columns changes, and they come back at the widths
//! kept.

use gpui::{App, Entity};
use gpui_component::table::{TableDelegate, TableEvent, TableState};

use crate::prefs::Prefs;

/// The width of `table`'s column `key`: the one the user gave it, or `default`.
pub fn width(cx: &App, table: &str, key: &str, default: f32) -> f32 {
    cx.try_global::<Prefs>()
        .and_then(|prefs| prefs.widths.get(table)?.get(key).copied())
        .map_or(default, f32::from)
}

/// A width in whole pixels: a fraction is nothing anyone set.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to the range of u16 first"
)]
fn whole(width: f32) -> u16 {
    width.round().clamp(0., f32::from(u16::MAX)) as u16
}

/// Keeps `state`'s column widths as the user resizes them, under `table`.
pub fn keep<D: TableDelegate>(table: &'static str, state: &Entity<TableState<D>>, cx: &mut App) {
    cx.subscribe(state, move |state, event, cx| {
        let TableEvent::ColumnWidthsChanged(widths) = event else {
            return;
        };
        let keys: Vec<String> = {
            let state = state.read(cx);
            (0..widths.len())
                .map(|ix| state.delegate().column(ix, cx).key.to_string())
                .collect()
        };
        let mut prefs = cx.try_global::<Prefs>().cloned().unwrap_or_default();
        let kept = prefs.widths.entry(table.to_owned()).or_default();
        for (key, width) in keys.into_iter().zip(widths) {
            if !key.is_empty() {
                kept.insert(key, whole(f32::from(*width)));
            }
        }
        prefs.save();
        cx.set_global(prefs);
    })
    .detach();
}
