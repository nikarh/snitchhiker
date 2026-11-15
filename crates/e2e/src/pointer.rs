//! Clicks in a Wayland session (`snitchhiker-e2e --click <x> <y>`), through the wlroots virtual-pointer protocol: how
//! the desktop scenarios press the app's buttons under a headless sway, which has no pointer of its own. A test tool,
//! run as the session's user; nothing in the app knows of it.

use std::time::{SystemTime, UNIX_EPOCH};

use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_pointer::ButtonState;
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1;
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1;

/// The left button (`BTN_LEFT` in linux/input-event-codes.h).
const BTN_LEFT: u32 = 0x110;
/// The size of the headless output: absolute positions are in its coordinates.
const WIDTH: u32 = 1280;
const HEIGHT: u32 = 720;

struct State;

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as wayland_client::Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSeat, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlSeat,
        _: <WlSeat as wayland_client::Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrVirtualPointerManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZwlrVirtualPointerManagerV1,
        _: <ZwlrVirtualPointerManagerV1 as wayland_client::Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrVirtualPointerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZwlrVirtualPointerV1,
        _: <ZwlrVirtualPointerV1 as wayland_client::Proxy>::Event,
        (): &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

fn millis() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        u32::try_from(d.as_millis() % u128::from(u32::MAX)).unwrap_or(0)
    })
}

/// The right button (`linux/input-event-codes.h`).
const BTN_RIGHT: u32 = 0x111;

/// Moves the pointer to (`x`, `y`) of the output and clicks the left button there (the right one with `right`).
pub fn click(x: u32, y: u32, right: bool) -> Result<(), String> {
    let button = if right { BTN_RIGHT } else { BTN_LEFT };
    let connection =
        Connection::connect_to_env().map_err(|e| format!("the Wayland session: {e}"))?;
    let (globals, mut queue) =
        registry_queue_init::<State>(&connection).map_err(|e| e.to_string())?;
    let handle = queue.handle();
    let seat: WlSeat = globals
        .bind(&handle, 1..=7, ())
        .map_err(|e| format!("wl_seat: {e}"))?;
    let manager: ZwlrVirtualPointerManagerV1 = globals
        .bind(&handle, 1..=2, ())
        .map_err(|e| format!("the virtual pointer protocol: {e}"))?;
    let pointer = manager.create_virtual_pointer(Some(&seat), &handle, ());
    let mut state = State;
    pointer.motion_absolute(millis(), x, y, WIDTH, HEIGHT);
    pointer.frame();
    queue.roundtrip(&mut state).map_err(|e| e.to_string())?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    pointer.button(millis(), button, ButtonState::Pressed);
    pointer.frame();
    queue.roundtrip(&mut state).map_err(|e| e.to_string())?;
    pointer.button(millis(), button, ButtonState::Released);
    pointer.frame();
    queue.roundtrip(&mut state).map_err(|e| e.to_string())?;
    pointer.destroy();
    queue.roundtrip(&mut state).map_err(|e| e.to_string())?;
    Ok(())
}
