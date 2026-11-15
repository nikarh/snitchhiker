//! A stand-in for a desktop's tray (`snitchhiker-e2e --tray <log>`): an `org.kde.StatusNotifierWatcher` on the session
//! bus that appends the service name of each item registering to the log, so a scenario can find the app's item and
//! read its properties with `busctl`.

use std::io::Write as _;

struct Watcher {
    log: String,
}

#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl Watcher {
    fn register_status_notifier_item(&self, service: &str) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
        {
            let _ = writeln!(file, "{service}");
        }
    }

    #[zbus(property)]
    fn is_status_notifier_host_registered(&self) -> bool {
        let _ = self;
        true
    }
}

/// Serves the watcher until killed.
pub fn serve(log: &str) -> Result<(), String> {
    zbus::block_on(async {
        let _connection = zbus::connection::Builder::session()
            .name("org.kde.StatusNotifierWatcher")
            .serve_at(
                "/StatusNotifierWatcher",
                Watcher {
                    log: log.to_owned(),
                },
            )
            .build()
            .await
            .map_err(|e| e.to_string())?;
        std::future::pending::<()>().await;
        Ok(())
    })
}
