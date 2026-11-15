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
        // The packaged service must not run next to a test daemon (they would share queues and the table).
        let _ = run("systemctl", &["stop", "snitchhikerd"]);
        let _ = run("systemctl", &["reset-failed", "snitchhikerd"]);
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

    /// The command line, which talks to the running daemon (there is one at a time).
    pub fn cli(&self, args: &[&str]) -> Result<String, String> {
        debug_assert!(self.child.is_some(), "the daemon isn't running");
        run("snitchhiker", args)
    }

    /// `snitchhikerd --config <its config> <args>`: the daemon's own commands (trust-client and the like).
    pub fn daemon_command(&self, args: &[&str]) -> Result<String, String> {
        let mut all = vec!["--config", self.config.as_str()];
        all.extend_from_slice(args);
        run("snitchhikerd", &all)
    }

    /// Stops the daemon and starts it again with `settings` instead, keeping its database.
    pub fn restart(&mut self, settings: &str) -> Result<(), String> {
        self.stop()?;
        let dir = Path::new(&self.config)
            .parent()
            .ok_or("no config directory")?
            .display()
            .to_string();
        std::fs::write(
            &self.config,
            format!(
                "database = \"{dir}/state.db\"\nrules_dir = \"{dir}/rules.d\"\nqueues = 2\ndefault_rules = false\n{settings}"
            ),
        )
        .map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(PIDFILE);
        let child = Command::new("snitchhikerd")
            .args(["--config", &self.config])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("starting snitchhikerd: {e}"))?;
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Path::new(PIDFILE).exists() {
            if Instant::now() > deadline {
                return Err("the daemon didn't start again".to_owned());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Kills the daemon with SIGKILL, as a crash would end it.
    pub fn kill(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.child.take() {
            child.kill().map_err(|e| e.to_string())?;
            child.wait().map_err(|e| e.to_string())?;
        }
        Ok(())
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
    let queried = daemon.cli(&[
        "events",
        "--query",
        &format!("port:{allowed} -action:deny exe:*/python3*"),
    ])?;
    // Explained with the rules as they are now: a broader rule added since matches too, but is outranked.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--name",
        "python anywhere",
    ])?;
    thread::sleep(Duration::from_millis(300));
    let explained = match events
        .lines()
        .find(|l| l.contains("allow") && l.contains(&format!(":{allowed}")))
        .and_then(|l| l.split_whitespace().next())
    {
        Some(seq) => daemon.cli(&["explain", seq])?,
        None => String::new(),
    };
    daemon.stop()?;
    check(allowed_ok, "the allowed connection was blocked", &events)?;
    check(
        !queried.is_empty()
            && queried
                .lines()
                .all(|l| l.contains(&format!(":{allowed} ")) && l.contains("allow")),
        "a query over the history doesn't give just the events it matches",
        &format!("{events}{queried}"),
    )?;
    let decides = explained.lines().find(|l| l.contains("decides"));
    check(
        decides.is_some_and(|l| l.contains("python to the test port") && l.contains("allow"))
            && explained.contains("\"python anywhere\": allow"),
        "explain doesn't put the specific rule first with the broader one after it",
        &format!("{events}{explained}"),
    )?;
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
    let started = run("systemctl", &["start", "snitchhikerd"]);
    if let Err(error) = started {
        let log = run(
            "journalctl",
            &["-u", "snitchhikerd", "--no-pager", "-n", "20"],
        )
        .unwrap_or_default();
        // A failing service restarts itself: stop it, so it doesn't run next to the other scenarios' daemons.
        let _ = run("systemctl", &["stop", "snitchhikerd"]);
        let _ = run("nft", &["delete", "table", "inet", "snitchhiker"]);
        return Err(format!("{error}\n{log}"));
    }
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
        rules.contains("(locked) System/Loopback"),
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
        rules.contains("(locked) Baseline/python to the test port"),
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

/// Monitor a while, learn rules from what was seen, import them, enforce: what was seen still works, the rest doesn't.
pub fn learn_then_enforce() -> Result<(), String> {
    let (_a, port_a) = listener()?;
    let (_b, port_b) = listener()?;
    let (_c, port_c) = listener()?;
    let mut daemon = Running::start("learn", "mode = \"monitor\"\nno_match = \"deny\"\n")?;
    check(
        mallory_connects(port_a)?,
        "monitor mode blocked a connection",
        "",
    )?;
    check(
        mallory_connects(port_b)?,
        "monitor mode blocked a connection",
        "",
    )?;
    thread::sleep(Duration::from_millis(500));
    let learned = daemon.cli(&["learn", "--hours", "1", "--folder", "Seen while monitoring"])?;
    check(
        learned.contains(&format!("\"{port_a}\"")) && learned.contains(&format!("\"{port_b}\"")),
        "learn didn't suggest rules for what was seen",
        &learned,
    )?;
    let file = format!("{DIR}/learned.toml");
    std::fs::write(&file, &learned).map_err(|e| e.to_string())?;
    let imported = daemon.cli(&["rules", "import", &file])?;
    daemon.restart("mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let a = mallory_connects(port_a)?;
    let b = mallory_connects(port_b)?;
    let c = mallory_connects(port_c)?;
    let rules = daemon.cli(&["rules"])?;
    daemon.stop()?;
    check(
        a && b,
        "a learned destination was blocked",
        &format!("{imported}\n{rules}"),
    )?;
    check(!c, "a destination nobody learned went through", &rules)
}

/// OpenSnitch's rules, imported: what converts decides connections as it did in OpenSnitch, and what can't be
/// expressed is reported, not approximated.
pub fn opensnitch_rules_import_and_apply() -> Result<(), String> {
    let (_allowed, allowed) = listener()?;
    let (_other, other) = listener()?;
    let dir = "/tmp/snitchhiker-opensnitch-rules";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let rules = [
        (
            "allow-python.json",
            format!(
                r#"{{"name": "allow-python", "enabled": true, "precedence": false, "action": "allow",
                    "duration": "always", "operator": {{"type": "list", "operand": "list", "list": [
                      {{"type": "regexp", "operand": "process.path", "data": "^/usr/bin/python3", "sensitive": true}},
                      {{"type": "simple", "operand": "dest.port", "data": "{allowed}"}},
                      {{"type": "network", "operand": "dest.network", "data": "127.0.0.0/8"}}]}}}}"#
            ),
        ),
        (
            "env.json",
            r#"{"name": "by-environment", "action": "allow", "duration": "always",
                "operator": {"type": "simple", "operand": "process.env.HOME", "data": "/root"}}"#
                .to_owned(),
        ),
    ];
    for (name, json) in &rules {
        std::fs::write(format!("{dir}/{name}"), json).map_err(|e| e.to_string())?;
    }
    let mut daemon = Running::start("opensnitch", "mode = \"enforce\"\nno_match = \"reject\"\n")?;
    let report = daemon.cli(&["rules", "import-opensnitch", dir])?;
    thread::sleep(Duration::from_millis(300));
    let allowed_ok = mallory_connects(allowed)?;
    let other_ok = mallory_connects(other)?;
    let listed = daemon.cli(&["rules"])?;
    daemon.stop()?;
    let _ = std::fs::remove_dir_all(dir);
    let found = format!("{report}{listed}allowed: {allowed_ok}, other: {other_ok}");
    check(
        report.contains("imported 1 of 2") && report.contains("skipped by-environment"),
        "the import didn't report what it couldn't convert",
        &found,
    )?;
    check(
        listed.contains("OpenSnitch/allow-python"),
        "the imported rule isn't in the OpenSnitch folder",
        &found,
    )?;
    check(
        allowed_ok && !other_ok,
        "the imported rule doesn't decide connections as OpenSnitch's did",
        &found,
    )
}

/// Changes are recorded and undone: a folder deleted with its rule comes back with an undo, and its rule decides
/// connections again.
pub fn changes_are_recorded_and_undone() -> Result<(), String> {
    let (_target, port) = listener()?;
    let mut daemon = Running::start("history", "mode = \"enforce\"\nno_match = \"reject\"\n")?;
    let added = daemon.cli(&["folders", "add", "Tools"])?;
    let folder = added
        .trim()
        .strip_prefix("added folder ")
        .ok_or("no folder id")?
        .to_owned();
    let rule = daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--port",
        &port.to_string(),
        "--name",
        "python",
    ])?;
    let id = rule
        .trim()
        .strip_prefix("added rule ")
        .ok_or("no rule id")?
        .to_owned();
    daemon.cli(&["rules", "move", &id, &folder])?;
    thread::sleep(Duration::from_millis(300));
    let before = mallory_connects(port)?;
    daemon.cli(&["folders", "rm", &folder])?;
    thread::sleep(Duration::from_millis(300));
    let deleted = mallory_connects(port)?;
    let history = daemon.cli(&["history"])?;
    let last = history
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or("no history")?
        .to_owned();
    daemon.cli(&["undo", &last])?;
    thread::sleep(Duration::from_millis(300));
    let undone = mallory_connects(port)?;
    let rules = daemon.cli(&["rules"])?;
    daemon.stop()?;
    let found = format!("{history}{rules}before {before}, deleted {deleted}, undone {undone}");
    check(
        history.contains("deleted folder \"Tools\"")
            && history.contains("deleted rule \"python\"")
            && history.contains("rule \"python\": moved")
            && history.contains("cli"),
        "the history doesn't record the changes and who made them",
        &found,
    )?;
    check(
        before && !deleted && undone,
        "deleting and undoing didn't take the rule away and bring it back",
        &found,
    )?;
    check(
        rules.contains("Tools/python"),
        "the undone rule isn't back in its folder",
        &found,
    )
}

/// A live connection is listed with its program, and killing it makes the program's next send fail.
pub fn connections_are_listed_and_killed() -> Result<(), String> {
    let (listener, port) = listener()?;
    let mut daemon = Running::start("connections", "mode = \"monitor\"\n")?;
    let script = format!(
        "import socket, time, sys\ns = socket.create_connection(('127.0.0.1', {port}))\nprint(s.getsockname()[1], flush=True)\n\
         time.sleep(3)\ntry:\n    s.send(b'x')\n    s.send(b'y')\n    print('alive', flush=True)\nexcept OSError as e:\n    print('killed', e, flush=True)"
    );
    let mut python = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let _accepted = listener.accept().map_err(|e| e.to_string())?;
    let mut lines = std::io::BufRead::lines(std::io::BufReader::new(
        python.stdout.take().ok_or("no stdout")?,
    ));
    let local_port = lines.next().and_then(Result::ok).unwrap_or_default();
    let listed = daemon.cli(&["connections"])?;
    let killed = daemon.cli(&[
        "kill",
        "tcp",
        &format!("127.0.0.1:{local_port}"),
        &format!("127.0.0.1:{port}"),
    ]);
    let outcome = lines.next().and_then(Result::ok).unwrap_or_default();
    let _ = python.wait();
    daemon.stop()?;
    let found = format!("{listed}kill: {killed:?}\npython: {outcome}");
    let line = listed
        .lines()
        // The connecting end: python's port on the local side (the listener's end has it on the remote side).
        .find(|line| {
            line.split("->")
                .next()
                .is_some_and(|local| local.contains(&format!("127.0.0.1:{local_port} ")))
        })
        .unwrap_or_default();
    check(
        line.contains("established") && line.contains("python3") && line.contains("uid 1001"),
        "the connection isn't listed with its program and user",
        &found,
    )?;
    check(
        killed.is_ok() && outcome.starts_with("killed"),
        "killing the connection didn't make the program's next send fail",
        &found,
    )
}

/// Rules are changed in bulk as one batch that one undo reverts, and the lint finds duplicates and rules on binaries
/// that are gone.
pub fn rules_are_edited_in_bulk_and_linted() -> Result<(), String> {
    let (_target, port) = listener()?;
    let mut daemon = Running::start("bulk", "mode = \"enforce\"\nno_match = \"reject\"\n")?;
    let add = |name: &str, exe: &str| -> Result<String, String> {
        let added = daemon.cli(&[
            "rules",
            "add",
            "allow",
            "--exe",
            exe,
            "--port",
            &port.to_string(),
            "--name",
            name,
        ])?;
        added
            .trim()
            .strip_prefix("added rule ")
            .map(str::to_owned)
            .ok_or_else(|| format!("no rule id: {added}"))
    };
    let a = add("a", "glob:/usr/bin/python3*")?;
    let b = add("b", "glob:/usr/bin/python3*")?;
    let gone = add("gone", "/usr/bin/no-such-program")?;
    thread::sleep(Duration::from_millis(300));
    let before = mallory_connects(port)?;
    let lint = daemon.cli(&["rules", "lint"])?;
    daemon.cli(&["rules", "edit", &format!("{a},{b}"), "disable"])?;
    thread::sleep(Duration::from_millis(300));
    let disabled = mallory_connects(port)?;
    let history = daemon.cli(&["history"])?;
    let last = history
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or("no history")?
        .to_owned();
    daemon.cli(&["undo", &last])?;
    thread::sleep(Duration::from_millis(300));
    let undone = mallory_connects(port)?;
    daemon.cli(&["rules", "edit", &format!("{a},{b}"), "action", "deny"])?;
    thread::sleep(Duration::from_millis(300));
    let denied = mallory_connects(port)?;
    let refused = daemon
        .cli(&["rules", "edit", "1,999999", "enable"])
        .is_err();
    daemon.stop()?;
    let found = format!(
        "{lint}{history}before {before}, disabled {disabled}, undone {undone}, denied {denied}, refused {refused}"
    );
    check(
        lint.contains(&format!("rule {b}: duplicates \"a\""))
            && lint.contains(&format!("rule {gone}: its binary is gone")),
        "the lint doesn't report the duplicate and the missing binary",
        &found,
    )?;
    check(
        before && !disabled && undone && !denied,
        "bulk edits and their undo don't take effect",
        &found,
    )?;
    check(
        refused,
        "a bulk edit with an unknown rule went through",
        &found,
    )
}

/// The policy changes while the daemon runs: `no_match = allow` lets a connection no rule decides through at once, the
/// change is in the history and an undo puts the file's policy back.
pub fn policy_changes_apply_at_once_and_undo() -> Result<(), String> {
    let (_target, port) = listener()?;
    let mut daemon = Running::start("policy", "mode = \"enforce\"\nno_match = \"reject\"\n")?;
    let before = mallory_connects(port)?;
    let set = daemon.cli(&["policy", "set", "no_match=allow", "retention_days=7"])?;
    thread::sleep(Duration::from_millis(200));
    let allowed = mallory_connects(port)?;
    let status = daemon.cli(&["status"])?;
    let history = daemon.cli(&["history"])?;
    let last = history
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or("no history")?
        .to_owned();
    daemon.cli(&["undo", &last])?;
    thread::sleep(Duration::from_millis(200));
    let undone = mallory_connects(port)?;
    let shown = daemon.cli(&["policy"])?;
    let invalid = daemon
        .cli(&["policy", "set", "prompt_timeout_secs=1"])
        .is_err();
    daemon.stop()?;
    let found = format!(
        "{set}{status}{history}{shown}before {before}, allowed {allowed}, undone {undone}, invalid refused {invalid}"
    );
    check(
        set.contains("no_match             allow  (changed by a client)")
            && set.contains("retention_days       7  (changed by a client)")
            && status.to_lowercase().contains("allow"),
        "the policy set isn't the one in effect",
        &found,
    )?;
    check(
        history.contains("policy: no_match reject → allow, retention_days 30 → 7"),
        "the history doesn't record the policy change",
        &found,
    )?;
    check(
        !before && allowed && !undone && !shown.contains("changed by a client"),
        "the policy didn't apply at once, or the undo didn't put the file's back",
        &found,
    )?;
    check(invalid, "an out-of-range timeout was accepted", &found)
}

/// A network namespace joined to this one by a veth pair: another host, as far as the input chain can tell.
struct Neighbour;

impl Neighbour {
    const NETNS: &'static str = "shfw";

    fn create() -> Result<Self, String> {
        let _ = run("ip", &["netns", "del", Self::NETNS]);
        let _ = run("ip", &["link", "del", "shv0"]);
        for args in [
            &["netns", "add", Self::NETNS][..],
            &[
                "link", "add", "shv0", "type", "veth", "peer", "name", "shv1",
            ],
            &["link", "set", "shv1", "netns", Self::NETNS],
            &["addr", "add", "10.213.0.1/24", "dev", "shv0"],
            &["link", "set", "shv0", "up"],
            &[
                "-n",
                Self::NETNS,
                "addr",
                "add",
                "10.213.0.2/24",
                "dev",
                "shv1",
            ],
            &["-n", Self::NETNS, "link", "set", "shv1", "up"],
            &["-n", Self::NETNS, "link", "set", "lo", "up"],
        ] {
            run("ip", args)?;
        }
        Ok(Self)
    }

    /// Whether the neighbour can connect to 10.213.0.1:`port` within 2 seconds.
    fn connects(port: u16) -> Result<bool, String> {
        let script = format!(
            "import socket\ntry:\n    socket.create_connection(('10.213.0.1', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
        );
        let output = Command::new("ip")
            .args(["netns", "exec", Self::NETNS, "python3", "-c", &script])
            .output()
            .map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&output.stdout).contains("connected"))
    }
}

impl Drop for Neighbour {
    fn drop(&mut self) {
        let _ = run("ip", &["netns", "del", Self::NETNS]);
        let _ = run("ip", &["link", "del", "shv0"]);
    }
}

/// The system firewall filters what comes in: a drop policy keeps a neighbour out, a rule lets it in, and a change on
/// trial that isn't confirmed reverts by itself. SSH stays allowed throughout (the harness's way in).
pub fn system_firewall_filters_inbound() -> Result<(), String> {
    let _neighbour = Neighbour::create()?;
    let listener = TcpListener::bind("10.213.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut daemon = Running::start("system", "mode = \"enforce\"\nno_match = \"allow\"\n")?;
    let ssh = "[[rules]]\nenabled = true\nchain = \"input\"\nprotocol = 6\ndestination_ports = [22, 22]\ntarget = \"accept\"\n";
    let closed = format!("enabled = true\ninput = \"drop\"\nforward = \"accept\"\n{ssh}");
    let open = format!(
        "{closed}\n[[rules]]\nenabled = true\nchain = \"input\"\nprotocol = 6\nsource = [\"10.213.0.0/24\"]\ndestination_ports = [{port}, {port}]\ntarget = \"accept\"\n"
    );
    let write = |name: &str, text: &str| -> Result<String, String> {
        let path = format!("/tmp/snitchhiker-system-{name}.toml");
        std::fs::write(&path, text).map_err(|e| e.to_string())?;
        Ok(path)
    };
    let before = Neighbour::connects(port)?;
    daemon.cli(&["system", "import", &write("closed", &closed)?])?;
    let dropped = Neighbour::connects(port)?;
    let shown = daemon.cli(&["system"])?;
    daemon.cli(&["system", "import", &write("open", &open)?])?;
    let allowed = Neighbour::connects(port)?;
    // On trial and never confirmed: back to `open` after 10 s.
    let trial = daemon.cli(&[
        "system",
        "import",
        "--trial",
        "10",
        &write("closed", &closed)?,
    ])?;
    let during = Neighbour::connects(port)?;
    thread::sleep(Duration::from_secs(12));
    let reverted = Neighbour::connects(port)?;
    let history = daemon.cli(&["history", "--limit", "3"])?;
    let refused = daemon
        .cli(&["system", "import", &write("bad", "enabled = true\ninput = \"drop\"\nforward = \"accept\"\n[[rules]]\nenabled = true\nchain = \"input\"\ndestination_ports = [1, 2]\ntarget = \"accept\"\n")?])
        .is_err();
    daemon.cli(&["system", "off"])?;
    let off = Neighbour::connects(port)?;
    let table_gone = !run("nft", &["list", "tables"])?.contains("snitchhiker_system");
    daemon.stop()?;
    drop(listener);
    let found = format!(
        "{shown}{trial}{history}before {before}, dropped {dropped}, allowed {allowed}, during trial {during}, reverted {reverted}, invalid refused {refused}, off {off}, table gone {table_gone}"
    );
    check(
        before && !dropped && allowed,
        "the drop policy and the rule didn't filter the neighbour",
        &found,
    )?;
    check(
        trial.contains("reverts in") && !during && reverted && history.contains("not confirmed"),
        "the change on trial didn't revert by itself",
        &found,
    )?;
    check(refused, "ports without a protocol were accepted", &found)?;
    check(
        off && table_gone,
        "turning it off didn't remove the table",
        &found,
    )
}

/// Alerts: an alert rule's threshold, a program never seen before, a dangerous action, the daemon's table removed by
/// someone else (and put back), a crash noticed at the next start; acknowledging them for everyone.
pub fn alerts_are_raised_and_acknowledged() -> Result<(), String> {
    let (_target, port) = listener()?;
    let settings = "mode = \"enforce\"\nno_match = \"reject\"\n";
    let mut daemon = Running::start("alerts", settings)?;
    daemon.cli(&[
        "alerts",
        "rules",
        "add",
        "rejected twice",
        "--query",
        &format!("port:{port} action:reject"),
        "--threshold",
        "2",
        "--window",
        "60",
    ])?;
    daemon.cli(&[
        "alerts",
        "rules",
        "add",
        "new program",
        "--first-program",
        "--query",
        &format!("port:{port}"),
    ])?;
    // The rules reach the writer with the next batch: one connection first.
    mallory_connects(port)?;
    thread::sleep(Duration::from_millis(1500));
    mallory_connects(port)?;
    mallory_connects(port)?;
    // A copy of python under a new path: a program never seen before.
    let copy = format!("/tmp/snitchhiker-new-program-{}", std::process::id());
    std::fs::copy("/usr/bin/python3", &copy).map_err(|e| e.to_string())?;
    let script = format!(
        "import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\nexcept OSError:\n    pass"
    );
    let _ = Command::new("runuser")
        .args(["-u", "mallory", "--", &copy, "-c", &script])
        .output();
    daemon.cli(&["policy", "set", "retention_days=7"])?;
    daemon.cli(&["policy", "set", "no_match=allow"])?;
    run("nft", &["delete", "table", "inet", "snitchhiker"])?;
    thread::sleep(Duration::from_secs(12));
    let table_back = run("nft", &["list", "tables"])?.contains("inet snitchhiker\n");
    let raised = daemon.cli(&["alerts"])?;
    let status = daemon.cli(&["status"])?;
    daemon.cli(&["alerts", "ack", "--all"])?;
    let after_ack = daemon.cli(&["alerts"])?;
    daemon.kill()?;
    daemon.restart(settings)?;
    let after_crash = daemon.cli(&["alerts"])?;
    daemon.stop()?;
    let _ = std::fs::remove_file(&copy);
    let found = format!("{raised}{status}{after_ack}{after_crash}table back {table_back}");
    check(
        raised.contains("alert_rule rejected twice: 2 connections in 60 s")
            && raised.contains(&format!(
                "alert_rule new program: A program's first connection: {copy}"
            )),
        "the alert rules didn't raise their alerts",
        &found,
    )?;
    check(
        raised.contains("dangerous_action cli was allowed to change the policy")
            && !raised.contains("retention_days 30 → 7"),
        "a dangerous action (and only that) wasn't alerted",
        &found,
    )?;
    check(
        raised.contains("table_removed Something removed the daemon's nftables table")
            && table_back,
        "the table removed by someone else wasn't put back with an alert",
        &found,
    )?;
    check(
        after_ack.trim_end().ends_with("0 not acknowledged")
            && after_crash.contains("crashed The daemon stopped unexpectedly"),
        "acknowledging or noticing the crash didn't work",
        &found,
    )
}

/// What a mock webhook received: each request's signature header and body.
type Hooked = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

/// A mock webhook on loopback: its port, and what it received.
fn webhook_server() -> Result<(u16, Hooked), String> {
    use std::io::{BufRead as _, Read as _, Write as _};
    let hook = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let hook_port = hook.local_addr().map_err(|e| e.to_string())?.port();
    let received: Hooked = std::sync::Arc::default();
    {
        let received = std::sync::Arc::clone(&received);
        thread::spawn(move || {
            for stream in hook.incoming().flatten() {
                let mut reader = std::io::BufReader::new(&stream);
                let (mut length, mut signature) = (0, String::new());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap_or_default();
                    match name.trim().to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap_or(0),
                        "x-snitchhiker-signature" => value.trim().clone_into(&mut signature),
                        _ => {}
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                received
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((signature, body));
                let _ =
                    (&stream).write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n");
            }
        });
    }
    Ok((hook_port, received))
}

/// Alerts reach the webhook as JSON, signed with the secret: HMAC-SHA256 of the body.
pub fn alerts_reach_the_webhook_signed() -> Result<(), String> {
    let (_target, port) = listener()?;
    let (hook_port, received) = webhook_server()?;
    let secret = format!("{DIR}/webhook-secret");
    let _ = std::fs::create_dir_all(DIR);
    std::fs::write(&secret, "s3cret\n").map_err(|e| e.to_string())?;
    let settings = format!(
        "mode = \"enforce\"\nno_match = \"reject\"\nalert_webhook = \"http://127.0.0.1:{hook_port}/hook\"\nalert_webhook_secret_file = \"{secret}\"\n"
    );
    let daemon = Running::start("webhook", &settings)?;
    // The daemon's own delivery is to loopback, which the test's rules leave undecided: let it through.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--net",
        "127.0.0.1",
        "--port",
        &hook_port.to_string(),
        "--name",
        "the hook",
    ])?;
    daemon.cli(&[
        "alerts",
        "rules",
        "add",
        "rejected",
        "--query",
        &format!("port:{port} action:reject"),
        "--threshold",
        "1",
    ])?;
    mallory_connects(port)?;
    thread::sleep(Duration::from_millis(1500));
    mallory_connects(port)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while received
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_empty()
        && std::time::Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(200));
    }
    let deliveries = received
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let found = format!(
        "{:?}",
        deliveries
            .iter()
            .map(|(s, b)| (s, String::from_utf8_lossy(b)))
            .collect::<Vec<_>>()
    );
    let expected = |body: &[u8]| {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"s3cret");
        let tag = ring::hmac::sign(&key, body);
        let hex = tag.as_ref().iter().fold(String::new(), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        });
        format!("sha256={hex}")
    };
    check(
        deliveries.iter().any(|(signature, body)| {
            String::from_utf8_lossy(body).contains("\"kind\":\"alert_rule\"")
                && *signature == expected(body)
        }),
        "no alert reached the webhook, or its signature doesn't verify",
        &found,
    )
}
