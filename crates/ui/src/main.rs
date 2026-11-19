//! `snitchhiker-ui`: Snitchhiker's desktop app. It is installed setgid to the client group, which is what lets it
//! connect to the daemon's client socket; see the security documentation.

mod app;
mod backend;
mod columns;
mod csv;
mod env;
mod history;
mod model;
mod nodes;
mod notify;
mod prefs;
mod remote;
mod session;
mod shell;
mod theme;
mod tray;
mod userfs;
mod views;

use std::path::PathBuf;
use std::process::ExitCode;

use gpui::{AppContext as _, Bounds, TitlebarOptions, WindowBounds, WindowOptions, px, size};
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
                text.push_str(&warning.line());
                text.push('\n');
                text
            });
        let _ = std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes());
        return ExitCode::SUCCESS;
    }
    let local = backend::Target::Local(PathBuf::from(snitchhiker_client::CLIENT_SOCKET));
    // The components' icons.
    gpui_platform::application()
        .with_assets(gpui_kit_assets::AllAssets)
        .run(move |cx| {
            gpui_component::init(cx);
            theme::install(cx);
            let bounds = Bounds::centered(None, size(px(1200.), px(780.)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("Snitchhiker".into()),
                    ..TitlebarOptions::default()
                }),
                // The desktop entry's name (snitchhiker.desktop): the window manager groups the window under its icon.
                app_id: Some("snitchhiker".to_owned()),
                ..WindowOptions::default()
            };
            let _ = cx.open_window(options, |window, cx| {
                let view = cx.new(|cx| shell::Shell::new(local, window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            });
        });
    ExitCode::SUCCESS
}
