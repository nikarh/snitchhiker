//! Performance in the VM: another firewall's large, churning sets must not slow Snitchhiker down (libnftables reads
//! every interval set of every table before any element change; Snitchhiker must never pay for what isn't its own).

use std::fmt::Write as _;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::daemon::Running;
use crate::util::{check, run};

const RANGES: usize = 60_000;

/// Average milliseconds per connection for `count` connections to `port`, made by one python process as mallory.
fn average_connect_ms(port: u16, count: u32) -> Result<f64, String> {
    let script = format!(
        "import socket, time\nt = time.monotonic()\nfor _ in range({count}):\n    socket.create_connection(('127.0.0.1', {port}), timeout=5).close()\nprint((time.monotonic() - t) * 1000 / {count})"
    );
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .output()
        .map_err(|e| e.to_string())?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| {
            format!(
                "connections failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

/// A table that isn't ours, with an interval set of `RANGES` ranges.
fn foreign_table() -> Result<(), String> {
    let mut script = String::from(
        "add table inet foreign\nadd set inet foreign ranges { type ipv4_addr; flags interval; }\nadd element inet foreign ranges { ",
    );
    for i in 0..RANGES {
        let (a, b) = (i / 256, i % 256);
        let separator = if i == 0 { "" } else { ", " };
        let _ = write!(
            script,
            "{separator}100.{}.{a}.{b}-100.{}.{a}.{b}",
            64 + a / 256,
            64 + a / 256
        );
    }
    script.push_str(" }\n");
    let path = "/tmp/foreign.nft";
    std::fs::write(path, script).map_err(|e| e.to_string())?;
    run("nft", &["-f", path]).map(|_| ())
}

pub fn foreign_sets_dont_slow_us_down() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    thread::spawn(move || for _ in listener.incoming() {});
    let mut daemon = Running::start("perf", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--port",
        &port.to_string(),
    ])?;
    thread::sleep(Duration::from_millis(300));
    // Warm up, then the baseline.
    average_connect_ms(port, 20)?;
    let baseline = average_connect_ms(port, 100)?;

    foreign_table()?;
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let mut i = 0_u32;
            while !stop.load(Ordering::Relaxed) {
                let element = format!("{{ 100.127.255.{} }}", i % 250);
                let _ = run(
                    "nft",
                    &["add", "element", "inet", "foreign", "ranges", &element],
                );
                let _ = run(
                    "nft",
                    &["delete", "element", "inet", "foreign", "ranges", &element],
                );
                i += 1;
            }
        })
    };
    let with_foreign = average_connect_ms(port, 100);
    stop.store(true, Ordering::Relaxed);
    let _ = churn.join();
    let _ = run("nft", &["delete", "table", "inet", "foreign"]);
    daemon.stop()?;
    let with_foreign = with_foreign?;
    let found = format!(
        "baseline {baseline:.2} ms, with a churning {RANGES}-range set elsewhere {with_foreign:.2} ms"
    );
    // Generous for VM noise; the libnftables problem made each change cost over 100 ms.
    check(
        with_foreign < baseline * 2.0 + 2.0,
        "another table's sets slowed connections down",
        &found,
    )
}
