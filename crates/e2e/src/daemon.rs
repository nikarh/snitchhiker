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
        // The scenarios probe 127.0.0.1, which the System folder allows: it is off unless a scenario says otherwise.
        let defaults = if settings.contains("default_rules") {
            ""
        } else {
            "default_rules = false\n"
        };
        std::fs::write(
            &config,
            format!(
                "database = \"{dir}/state.db\"\nrules_dir = \"{dir}/rules.d\"\nqueues = 2\n{defaults}{settings}"
            ),
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

pub fn reject_fails_at_once() -> Result<(), String> {
    let mut daemon = Running::start("reject", "mode = \"enforce\"\nno_match = \"allow\"\n")?;
    let (_listener, port) = listener()?;
    daemon.cli(&[
        "rules",
        "add",
        "reject",
        "--exe",
        "glob:/usr/bin/python3*",
        "--port",
        &port.to_string(),
    ])?;
    thread::sleep(Duration::from_millis(300));
    let script = format!(
        "import socket, time\nt = time.monotonic()\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=5)\n    print('connected')\nexcept OSError as e:\n    print('failed after', round(time.monotonic() - t, 2), 'errno', e.errno)"
    );
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .output()
        .map_err(|e| e.to_string())?;
    daemon.stop()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let seconds: f64 = text
        .split_whitespace()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(f64::MAX);
    check(
        !text.contains("connected"),
        "a rejected connection went through",
        &text,
    )?;
    // ECONNABORTED is 103.
    check(
        seconds < 1.0 && text.contains("errno 103"),
        "a rejected connection didn't fail at once with ECONNABORTED",
        &text,
    )
}

/// The packaged service: systemd reports it active only once the table is in place, and it stops cleanly.
pub fn service_starts_ready_and_stops() -> Result<(), String> {
    let _ = std::fs::remove_file(PIDFILE);
    run("systemctl", &["start", "snitchhikerd"])?;
    // `systemctl start` of a Type=notify unit returns once the daemon said READY=1.
    let tables = run("nft", &["list", "tables"]);
    let status = run(
        "systemctl",
        &["show", "-p", "ActiveState,SubState", "snitchhikerd"],
    );
    let log = run(
        "journalctl",
        &["-u", "snitchhikerd", "--no-pager", "-n", "20"],
    )
    .unwrap_or_default();
    run("systemctl", &["stop", "snitchhikerd"])?;
    let after = run("systemctl", &["show", "-p", "ActiveState", "snitchhikerd"])?;
    let _ = run("nft", &["delete", "table", "inet", "snitchhiker"]);
    let tables = tables?;
    let status = status?;
    check(
        status.contains("ActiveState=active") && status.contains("SubState=running"),
        "the service isn't running",
        &format!("{status}\n{log}"),
    )?;
    check(
        tables.contains("snitchhiker"),
        "the service was reported ready before its table was in place",
        &format!("{tables}\n{log}"),
    )?;
    check(
        after.contains("ActiveState=inactive"),
        "the service didn't stop",
        &after,
    )
}

pub fn loopback_is_allowed_by_default() -> Result<(), String> {
    let mut daemon = Running::start(
        "defaults",
        "mode = \"enforce\"\nno_match = \"deny\"\ndefault_rules = true\n",
    )?;
    let (_listener, port) = listener()?;
    let connected = mallory_connects(port)?;
    let rules = daemon.cli(&["rules"])?;
    daemon.stop()?;
    check(
        connected,
        "loopback isn't allowed by the System folder",
        &rules,
    )?;
    check(
        rules.contains("(locked) Loopback"),
        "the default rule isn't listed as locked",
        &rules,
    )
}

pub fn managed_rules_apply_and_are_locked() -> Result<(), String> {
    let (_listener, port) = listener()?;
    let mut daemon = Running::start("managed", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let rules_dir = format!("{DIR}/managed/rules.d");
    std::fs::create_dir_all(&rules_dir).map_err(|e| e.to_string())?;
    std::fs::write(
        format!("{rules_dir}/baseline.toml"),
        format!(
            "[folder]\nname = \"Baseline\"\n\n[[rule]]\nname = \"python to the test port\"\naction = \"allow\"\nexe = [\"glob:/usr/bin/python3*\"]\nport = [\"{port}\"]\n"
        ),
    )
    .map_err(|e| e.to_string())?;
    run("pkill", &["-HUP", "-x", "snitchhikerd"])?;
    thread::sleep(Duration::from_millis(300));
    let connected = mallory_connects(port)?;
    let rules = daemon.cli(&["rules"])?;
    let removal = daemon.cli(&["rules", "rm", &((1_u64 << 62) | 1).to_string()]);
    daemon.stop()?;
    check(connected, "a managed rule didn't apply", &rules)?;
    check(
        rules.contains("(locked) python to the test port"),
        "the managed rule isn't listed as locked",
        &rules,
    )?;
    check(
        removal.is_err(),
        "a managed rule could be deleted",
        &format!("{removal:?}"),
    )
}

pub fn bytes_are_counted() -> Result<(), String> {
    use std::io::{Read as _, Write as _};

    let (listener, port) = listener()?;
    // The server reads 100 000 bytes and answers with 50 000.
    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = vec![0_u8; 100_000];
            if stream.read_exact(&mut buffer).is_ok() {
                let _ = stream.write_all(&vec![7_u8; 50_000]);
            }
        }
    });
    let mut daemon = Running::start("bytes", "mode = \"enforce\"\nno_match = \"allow\"\n")?;
    let script = format!(
        "import socket\ns = socket.create_connection(('127.0.0.1', {port}), timeout=5)\ns.sendall(b'x' * 100000)\nn = 0\nwhile n < 50000:\n    d = s.recv(65536)\n    if not d:\n        break\n    n += len(d)\nprint('read', n)"
    );
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .output()
        .map_err(|e| e.to_string())?;
    let _ = server.join();
    // Counts reach the history every few seconds.
    thread::sleep(Duration::from_secs(7));
    let events = daemon.cli(&["events", "--limit", "10"])?;
    daemon.stop()?;
    let client = String::from_utf8_lossy(&output.stdout).into_owned();
    check(
        client.contains("read 50000"),
        "the exchange didn't complete",
        &client,
    )?;
    let line = events
        .lines()
        .find(|l| l.contains(&format!(":{port} ")))
        .ok_or_else(|| format!("the connection isn't in the history:\n{events}"))?;
    let number_after = |word: &str| -> u64 {
        line.split_whitespace()
            .skip_while(|w| *w != word)
            .nth(1)
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    };
    check(
        number_after("out") >= 100_000 && number_after("in") >= 50_000,
        "the connection's bytes weren't counted",
        line,
    )
}
