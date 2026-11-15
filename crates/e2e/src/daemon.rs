//! The daemon itself, as installed: rules decide, monitor mode only records, rule changes apply at once, and stopping
//! follows the fail policy.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::util::{check, run};

const DIR: &str = "/tmp/snitchhiker-daemon-test";
const PIDFILE: &str = "/run/snitchhiker/snitchhikerd.pid";

/// A daemon started with its own configuration and database; stopped (and its table removed) when dropped.
pub struct Running {
    child: Option<Child>,
    config: String,
}

impl Running {
    pub fn start(name: &str, settings: &str) -> Result<Self, String> {
        let dir = format!("{DIR}/{name}");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let config = format!("{dir}/daemon.toml");
        std::fs::write(
            &config,
            format!("database = \"{dir}/state.db\"\nqueues = 2\n{settings}"),
        )
        .map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(PIDFILE);
        let child = Command::new("snitchhikerd")
            .args(["--config", &config])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(format!("{dir}/daemon.log")).map_err(|e| e.to_string())?)
            .spawn()
            .map_err(|e| format!("starting snitchhikerd: {e}"))?;
        let running = Self {
            child: Some(child),
            config,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Path::new(PIDFILE).exists() {
            if Instant::now() > deadline {
                return Err(format!(
                    "the daemon didn't start:\n{}",
                    std::fs::read_to_string(format!("{dir}/daemon.log")).unwrap_or_default()
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(running)
    }

    pub fn cli(&self, args: &[&str]) -> Result<String, String> {
        let mut all = vec!["--config", &self.config];
        all.extend_from_slice(args);
        run("snitchhiker", &all)
    }

    /// Stops the daemon with SIGTERM and waits for it.
    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id().to_string();
            run("kill", &["-TERM", &pid])?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while child.try_wait().map_err(|e| e.to_string())?.is_none() {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    return Err("the daemon didn't stop on SIGTERM".to_owned());
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop();
        let _ = run("nft", &["delete", "table", "inet", "snitchhiker"]);
    }
}

fn listener() -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok((listener, port))
}

/// Whether mallory can connect to 127.0.0.1:`port` within 2 seconds.
fn mallory_connects(port: u16) -> Result<bool, String> {
    let script = format!(
        "import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
    );
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).contains("connected"))
}

pub fn enforces_rules() -> Result<(), String> {
    let mut daemon = Running::start("enforce", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let (_allowed_listener, allowed) = listener()?;
    let (_other_listener, other) = listener()?;
    let added = daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--port",
        &allowed.to_string(),
        "--name",
        "python to the test port",
    ])?;
    check(added.contains("added rule"), "adding a rule failed", &added)?;
    // The CLI asked the daemon to reload; give it a moment to swap the rules in.
    thread::sleep(Duration::from_millis(300));
    let allowed_ok = mallory_connects(allowed)?;
    let other_ok = mallory_connects(other)?;
    thread::sleep(Duration::from_millis(500));
    let events = daemon.cli(&["events", "--limit", "20"])?;
    daemon.stop()?;
    check(allowed_ok, "the allowed connection was blocked", &events)?;
    check(
        !other_ok,
        "a connection no rule allows went through",
        &events,
    )?;
    check(
        events.lines().any(|l| {
            l.contains("allow") && l.contains("python3") && l.contains(&format!(":{allowed}"))
        }),
        "the allowed connection isn't in the history, attributed to python",
        &events,
    )?;
    check(
        events.lines().any(|l| {
            l.contains("deny") && l.contains("uid 1001") && l.contains(&format!(":{other}"))
        }),
        "the denied connection isn't in the history, with mallory's uid",
        &events,
    )
}

pub fn monitor_records_but_never_blocks() -> Result<(), String> {
    let mut daemon = Running::start("monitor", "mode = \"monitor\"\nno_match = \"deny\"\n")?;
    let (_listener, port) = listener()?;
    let connected = mallory_connects(port)?;
    thread::sleep(Duration::from_millis(500));
    let events = daemon.cli(&["events"])?;
    daemon.stop()?;
    check(connected, "monitor mode blocked a connection", &events)?;
    check(
        events
            .lines()
            .any(|l| l.contains("deny") && l.contains(&format!(":{port}"))),
        "monitor mode didn't record what it would have decided",
        &events,
    )
}

pub fn fail_closed_keeps_the_table() -> Result<(), String> {
    let mut daemon = Running::start("closed", "fail = \"closed\"\n")?;
    daemon.stop()?;
    let tables = run("nft", &["list", "tables"])?;
    let (_listener, port) = listener()?;
    let connected = mallory_connects(port)?;
    check(
        tables.contains("snitchhiker"),
        "the table was removed",
        &tables,
    )?;
    check(
        !connected,
        "a connection went through with the daemon stopped",
        &tables,
    )
}

pub fn fail_open_removes_the_table() -> Result<(), String> {
    let mut daemon = Running::start("open", "fail = \"open\"\n")?;
    daemon.stop()?;
    let tables = run("nft", &["list", "tables"])?;
    let (_listener, port) = listener()?;
    let connected = mallory_connects(port)?;
    check(!tables.contains("snitchhiker"), "the table stayed", &tables)?;
    check(
        connected,
        "a connection was blocked with the daemon stopped",
        &tables,
    )
}
