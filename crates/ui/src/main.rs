//! `snitchhiker-ui`: Snitchhiker's desktop app. It is installed setgid to the client group, which is what lets it
//! connect to the daemon's client socket; see the security documentation.

mod app;
mod backend;
mod csv;
mod env;
mod history;
mod model;
mod notify;
mod prefs;
mod session;
mod tray;
mod views;

use std::path::PathBuf;
use std::process::ExitCode;

use gpui::{AppContext as _, Bounds, WindowBounds, WindowOptions, px, size};
use gpui_component::Root;

fn main() -> ExitCode {
    // Before anything else: nothing of the session's environment but the display, the bus and the locale.
    if env::needs_scrubbing(std::env::vars_os()) {
        let error = env::reexec_scrubbed();
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            format!("snitchhiker-ui: re-executing with a clean environment: {error}\n").as_bytes(),
        );
        return ExitCode::FAILURE;
    }
    // What the banners would say, for scripts and tests: one line each.
    if std::env::args().nth(1).as_deref() == Some("--session-warnings") {
        let text = session::check()
            .iter()
            .fold(String::new(), |mut text, warning| {
                text.push_str(&warning.text());
                text.push('\n');
                text
            });
        let _ = std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes());
        return ExitCode::SUCCESS;
    }
    let socket = PathBuf::from(snitchhiker_client::CLIENT_SOCKET);
    // The components' icons.
    gpui_platform::application()
        .with_assets(gpui_kit_assets::AllAssets)
        .run(move |cx| {
            gpui_component::init(cx);
            let (requests, updates, updates_sender) = backend::start(socket);
            let bounds = Bounds::centered(None, size(px(1200.), px(780.)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..WindowOptions::default()
            };
            let _ = cx.open_window(options, |window, cx| {
                let view =
                    cx.new(|cx| app::App::new(requests, updates, updates_sender, window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            });
        });
    ExitCode::SUCCESS
}
