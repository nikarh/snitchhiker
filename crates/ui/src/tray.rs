//! The tray icon (a `StatusNotifierItem` on the session bus): a shield, with the number of prompts waiting on a red
//! badge, and "needs attention" while there are any. Clicking it shows the app. Without a tray (no
//! `StatusNotifierWatcher`) there is simply no icon; one that starts later finds the item when it registers.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use futures_lite::StreamExt as _;
use zbus::OwnedObjectPath;
use zbus::object_server::SignalEmitter;

use crate::backend::Update;

/// What the item shows: how many prompts wait, and whether alerts are open.
#[derive(Clone)]
pub struct Tray {
    prompts: Arc<AtomicU32>,
    changed: async_channel::Sender<()>,
}

impl Tray {
    /// Shows `count` prompts waiting.
    pub fn set(&self, count: u32) {
        if self.prompts.swap(count, Ordering::Relaxed) != count {
            let _ = self.changed.try_send(());
        }
    }
}

struct Item {
    prompts: Arc<AtomicU32>,
    updates: async_channel::Sender<Update>,
}

/// Icons in sizes: (width, height, ARGB32 pixels).
type Pixmaps = Vec<(i32, i32, Vec<u8>)>;
/// A tooltip: icon name, icon pixmaps, title, text.
type ToolTip = (String, Pixmaps, String, String);

/// Icon sizes offered; the tray picks the closest.
const SIZES: [i32; 2] = [22, 32];

// The protocol's properties and methods are methods of the item, constant or not.
#[allow(clippy::unused_self, clippy::unnecessary_literal_bound)]
#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        "snitchhiker"
    }

    #[zbus(property)]
    fn title(&self) -> String {
        title(self.prompts.load(Ordering::Relaxed))
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        if self.prompts.load(Ordering::Relaxed) > 0 {
            "NeedsAttention"
        } else {
            "Active"
        }
    }

    #[zbus(property)]
    fn icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Pixmaps {
        let count = self.prompts.load(Ordering::Relaxed);
        SIZES
            .iter()
            .map(|size| (*size, *size, icon(*size, count)))
            .collect()
    }

    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Pixmaps {
        self.icon_pixmap()
    }

    #[zbus(property)]
    fn tool_tip(&self) -> ToolTip {
        (
            String::new(),
            Vec::new(),
            "Snitchhiker".to_owned(),
            title(self.prompts.load(Ordering::Relaxed)),
        )
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from("/NO_DBUSMENU").unwrap_or_default()
    }

    async fn activate(&self, x: i32, y: i32) {
        let _ = (x, y);
        let _ = self.updates.send(Update::ShowPrompts).await;
    }

    async fn secondary_activate(&self, x: i32, y: i32) {
        let _ = (x, y);
        let _ = self.updates.send(Update::ShowPrompts).await;
    }

    async fn context_menu(&self, x: i32, y: i32) {
        let _ = (x, y);
        let _ = self.updates.send(Update::ShowPrompts).await;
    }

    fn scroll(&self, delta: i32, orientation: &str) {
        let _ = (delta, orientation);
    }

    #[zbus(signal)]
    async fn new_status(emitter: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_attention_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_title(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.kde.StatusNotifierWatcher",
    default_service = "org.kde.StatusNotifierWatcher",
    default_path = "/StatusNotifierWatcher"
)]
trait Watcher {
    fn register_status_notifier_item(&self, service: &str) -> zbus::Result<()>;
}

fn title(count: u32) -> String {
    match count {
        0 => "Snitchhiker".to_owned(),
        1 => "Snitchhiker: a connection is waiting".to_owned(),
        n => format!("Snitchhiker: {n} connections are waiting"),
    }
}

/// Starts the tray icon on a thread of its own; clicks become `Update::ShowPrompts`.
pub fn start(updates: async_channel::Sender<Update>) -> Tray {
    let (changed, incoming) = async_channel::unbounded();
    let tray = Tray {
        prompts: Arc::new(AtomicU32::new(0)),
        changed,
    };
    let prompts = Arc::clone(&tray.prompts);
    let _ = thread::Builder::new()
        .name("tray".to_owned())
        .spawn(move || {
            // Without a session bus there is no tray.
            let _ = zbus::block_on(run(prompts, updates, &incoming));
        });
    tray
}

const PATH: &str = "/StatusNotifierItem";

async fn run(
    prompts: Arc<AtomicU32>,
    updates: async_channel::Sender<Update>,
    changed: &async_channel::Receiver<()>,
) -> zbus::Result<()> {
    let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    let connection = zbus::connection::Builder::session()
        .name(name.as_str())
        .serve_at(PATH, Item { prompts, updates })
        .build()
        .await?;
    let register = || async {
        if let Ok(watcher) = WatcherProxy::new(&connection).await {
            let _ = watcher.register_status_notifier_item(&name).await;
        }
    };
    register().await;
    // A tray that starts (or restarts) later: register with it.
    let bus = zbus::fdo::DBusProxy::new(&connection).await?;
    let mut owners = bus
        .receive_name_owner_changed_with_args(&[(0, "org.kde.StatusNotifierWatcher")])
        .await?;
    let emitter = SignalEmitter::new(&connection, PATH)?;
    loop {
        enum Next {
            Changed,
            Watcher,
            Done,
        }
        let next = futures_lite::future::or(
            async { changed.recv().await.map_or(Next::Done, |()| Next::Changed) },
            async { owners.next().await.map_or(Next::Done, |_| Next::Watcher) },
        )
        .await;
        match next {
            Next::Done => return Ok(()),
            Next::Watcher => register().await,
            Next::Changed => {
                let item = connection
                    .object_server()
                    .interface::<_, Item>(PATH)
                    .await?;
                let status = item.get().await.status().to_owned();
                Item::new_status(&emitter, &status).await?;
                Item::new_icon(&emitter).await?;
                Item::new_attention_icon(&emitter).await?;
                Item::new_tool_tip(&emitter).await?;
                Item::new_title(&emitter).await?;
            }
        }
    }
}

/// Digits 0-9 and `+`, 3 by 5 pixels, a row per entry, the top bit the left pixel.
const FONT: [[u8; 5]; 11] = [
    [0b111, 0b101, 0b101, 0b101, 0b111],
    [0b010, 0b110, 0b010, 0b010, 0b111],
    [0b111, 0b001, 0b111, 0b100, 0b111],
    [0b111, 0b001, 0b111, 0b001, 0b111],
    [0b101, 0b101, 0b111, 0b001, 0b001],
    [0b111, 0b100, 0b111, 0b001, 0b111],
    [0b111, 0b100, 0b111, 0b101, 0b111],
    [0b111, 0b001, 0b010, 0b010, 0b010],
    [0b111, 0b101, 0b111, 0b101, 0b111],
    [0b111, 0b101, 0b111, 0b001, 0b111],
    [0b000, 0b010, 0b111, 0b010, 0b000],
];

const SHIELD: [u8; 4] = [0xff, 0x2a, 0x6f, 0x97];
const BADGE: [u8; 4] = [0xff, 0xd9, 0x2d, 0x20];
const WHITE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

/// The icon at `size` pixels square, ARGB32 in network byte order (as the protocol has it).
#[must_use]
pub fn icon(size: i32, count: u32) -> Vec<u8> {
    let n = usize::try_from(size).unwrap_or(0);
    let mut pixels = vec![0_u8; n * n * 4];
    let scale = f32::from(u16::try_from(size).unwrap_or(32)) / 32.0;
    let mut put = |x: usize, y: usize, color: [u8; 4]| {
        if x < n && y < n {
            let at = (y * n + x) * 4;
            if let Some(slot) = pixels.get_mut(at..at + 4) {
                slot.copy_from_slice(&color);
            }
        }
    };
    for y in 0..n {
        for x in 0..n {
            // In the 32-pixel design's coordinates, at the pixel's centre.
            let (fx, fy) = ((float(x) + 0.5) / scale, (float(y) + 0.5) / scale);
            if in_shield(fx, fy) {
                put(x, y, SHIELD);
            }
        }
    }
    if count == 0 {
        return pixels;
    }
    // The badge: a circle at the bottom right, with the count (or 9+).
    let (cx, cy, r) = (23.0 * scale, 23.0 * scale, 9.0 * scale);
    let centre = 23 * n / 32;
    for y in 0..n {
        for x in 0..n {
            let (dx, dy) = (float(x) + 0.5 - cx, float(y) + 0.5 - cy);
            if dx * dx + dy * dy <= r * r {
                put(x, y, BADGE);
            }
        }
    }
    let glyphs: Vec<usize> = if count > 9 {
        vec![9, 10]
    } else {
        vec![usize::try_from(count).unwrap_or(0)]
    };
    // Each font pixel is `dot` pixels; glyphs 3 dots wide, one dot apart.
    let dot = ((n + 8) / 16).max(1);
    let width = glyphs.len() * 3 * dot + (glyphs.len() - 1) * dot;
    let left = centre.saturating_sub(width / 2);
    let top = centre.saturating_sub(5 * dot / 2);
    for (i, glyph) in glyphs.iter().enumerate() {
        let Some(rows) = FONT.get(*glyph) else {
            continue;
        };
        let origin = left + i * 4 * dot;
        for (row, bits) in rows.iter().enumerate() {
            for column in 0..3 {
                if bits & (0b100 >> column) != 0 {
                    for py in 0..dot {
                        for px in 0..dot {
                            put(origin + column * dot + px, top + row * dot + py, WHITE);
                        }
                    }
                }
            }
        }
    }
    pixels
}

/// A pixel coordinate as a float (icons are small: exact).
fn float(value: usize) -> f32 {
    f32::from(u16::try_from(value).unwrap_or(u16::MAX))
}

/// The shield's outline in a 32-pixel square: straight sides down to the middle, then curving to a point.
fn in_shield(x: f32, y: f32) -> bool {
    if !(3.0..=30.0).contains(&y) {
        return false;
    }
    let half = if y <= 16.0 {
        12.0
    } else {
        let t = (y - 16.0) / 14.0;
        12.0 * (1.0 - t * t).max(0.0).sqrt()
    };
    // A shallow notch at the top middle.
    let top_dip = y < 5.0 && (x - 16.0).abs() < 4.0 - (y - 3.0) * 2.0;
    (x - 16.0).abs() <= half && !top_dip
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(icon: &[u8], size: usize, x: usize, y: usize) -> [u8; 4] {
        let at = (y * size + x) * 4;
        icon[at..at + 4].try_into().unwrap()
    }

    #[test]
    fn the_icon_is_a_shield_with_a_badge_for_prompts() {
        let quiet = icon(32, 0);
        assert_eq!(quiet.len(), 32 * 32 * 4);
        assert_eq!(pixel(&quiet, 32, 16, 12), SHIELD);
        assert_eq!(pixel(&quiet, 32, 1, 1), [0; 4]);
        let waiting = icon(32, 3);
        // The badge's edge is red, its middle has the digit's white.
        assert_eq!(pixel(&waiting, 32, 23, 15), BADGE);
        assert!((0..32 * 32).any(|i| pixel(&waiting, 32, i % 32, i / 32) == WHITE));
        assert_ne!(icon(32, 3), icon(32, 4));
        // More than nine: 9+.
        assert_eq!(icon(32, 12), icon(32, 40));
        // Smaller sizes are drawn too.
        assert_eq!(icon(22, 1).len(), 22 * 22 * 4);
    }

    #[test]
    fn the_title_says_how_many_wait() {
        assert_eq!(title(0), "Snitchhiker");
        assert_eq!(title(2), "Snitchhiker: 2 connections are waiting");
    }
}
