//! The escape suite, control side: an ordinary user (mallory) trying to stop the firewall, change what it decides, or
//! reach into the daemon. Every attempt must fail; where it makes sense, a control shows the same thing works for root
//! or for the genuine client.

use std::fmt::Write as _;
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::daemon::Running;
use crate::local_auth::{CLIENT, as_mallory, install_clients};
use crate::util::{check, run};

const PIDFILE: &str = "/run/snitchhiker/snitchhikerd.pid";

/// Runs a shell command as mallory; returns whether it succeeded, and what it printed.
fn mallory(command: &str) -> Result<(bool, String), String> {
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "sh", "-c", command])
        .output()
        .map_err(|e| e.to_string())?;
    Ok((
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

/// Every command must fail; the found text lists what each printed.
fn all_fail(commands: &[&str]) -> Result<(), String> {
    let mut succeeded = Vec::new();
    let mut found = String::new();
    for command in commands {
        let (ok, text) = mallory(command)?;
        let _ = write!(found, "$ {command}\n{text}");
        if ok {
            succeeded.push(*command);
        }
    }
    check(
        succeeded.is_empty(),
        &format!("mallory succeeded at: {succeeded:?}"),
        &found,
    )
}

fn daemon_pid() -> Result<String, String> {
    Ok(std::fs::read_to_string(PIDFILE)
        .map_err(|e| e.to_string())?
        .trim()
        .to_owned())
}

pub fn admin_socket_refuses_ordinary_users() -> Result<(), String> {
    let mut daemon = Running::start("tamper-admin", "mode = \"monitor\"\n")?;
    let (ok, text) = mallory("snitchhiker status")?;
    let root = daemon.cli(&["status"]);
    daemon.stop()?;
    check(
        root.is_ok(),
        "root's command line didn't work",
        &format!("{root:?}"),
    )?;
    check(
        !ok && text.contains("Permission denied"),
        "an ordinary user reached the admin socket",
        &text,
    )
}

pub fn disguised_clients_are_refused() -> Result<(), String> {
    install_clients()?;
    let mut daemon = Running::start(
        "tamper-disguise",
        &format!("mode = \"monitor\"\ntrusted_clients = [\"{CLIENT}\"]\n"),
    )?;
    let socket = "/run/snitchhiker/client.sock";
    // The control: the genuine client gets in.
    let (genuine_ok, genuine) = as_mallory(CLIENT, &["--protocol-client", socket])?;
    // A hard link of mallory's own to the setgid client, in a directory of hers on the client's own mount (the home
    // directory may be another one, as on Fedora): fs.protected_hardlinks forbids it.
    let dir = std::path::Path::new(CLIENT)
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("the client has no directory above its own")?
        .join("e2e-mallory");
    let dir = dir.display();
    crate::util::run("install", &["-d", "-o", "mallory", &dir.to_string()])?;
    let (link_ok, link) = mallory(&format!("ln {CLIENT} {dir}/mallory-link"))?;
    let _ = std::fs::remove_dir_all(dir.to_string());
    // The client run inside a user namespace mallory owns, where its setgid bit gives nothing. It connects without
    // checking the daemon (--hand-off), so its own check isn't what refuses it.
    let (userns_ok, userns) = mallory(&format!(
        "unshare --user --map-root-user {CLIENT} --hand-off {socket}"
    ))?;
    daemon.stop()?;
    check(genuine_ok, "the genuine client didn't get in", &genuine)?;
    check(
        !link_ok && link.contains("Operation not permitted"),
        "mallory hard-linked the setgid client",
        &link,
    )?;
    check(
        // The kernel refuses it by the socket's group, or the daemon by its checks.
        !userns_ok && (userns.contains("Permission denied") || userns.contains("no welcome")),
        "the client got in from inside a user namespace",
        &userns,
    )
}

pub fn configuration_state_and_runtime_are_root_only() -> Result<(), String> {
    let mut daemon = Running::start("tamper-files", "mode = \"monitor\"\n")?;
    let _ = std::fs::create_dir_all("/etc/snitchhiker/rules.d");
    let result = all_fail(&[
        "touch /run/snitchhiker/client.sock.mallory",
        "rm -f /run/snitchhiker/client.sock",
        "echo 'mode = \"monitor\"' >> /etc/snitchhiker/daemon.toml",
        "touch /etc/snitchhiker/rules.d/mallory.toml",
        "touch /var/lib/snitchhiker/mallory",
        // The test daemons keep their database outside the service's 0700 state directory: it must be private anyway.
        "cat /tmp/snitchhiker-daemon-test/tamper-files/state.db > /dev/null",
        "cat /tmp/snitchhiker-daemon-test/tamper-files/state.db-wal > /dev/null",
        "cat /var/lib/snitchhiker/trusted-clients.toml",
    ]);
    daemon.stop()?;
    result
}

pub fn the_service_cannot_be_stopped_or_changed() -> Result<(), String> {
    run("systemctl", &["start", "snitchhikerd"])?;
    let result = all_fail(&[
        "systemctl stop snitchhikerd",
        "systemctl kill snitchhikerd",
        "systemctl mask snitchhikerd",
        "systemctl disable snitchhikerd",
        "mkdir -p /etc/systemd/system/snitchhikerd.service.d",
        "echo '[Service]' > /etc/systemd/system/snitchhikerd.service",
        "systemctl daemon-reload",
    ]);
    let active = run("systemctl", &["is-active", "snitchhikerd"]);
    let _ = run("systemctl", &["stop", "snitchhikerd"]);
    result?;
    check(
        active.as_deref().map(str::trim) == Ok("active"),
        "the service isn't running after mallory's attempts",
        &format!("{active:?}"),
    )
}

pub fn the_daemon_cannot_be_signalled_or_traced() -> Result<(), String> {
    let mut daemon = Running::start("tamper-process", "mode = \"monitor\"\n")?;
    let pid = daemon_pid()?;
    let result = all_fail(&[
        &format!("kill -STOP {pid}"),
        &format!("kill -TERM {pid}"),
        &format!("kill -HUP {pid}"),
        &format!(
            "strace -p {pid} -e trace=none -o /dev/null & sleep 1; kill $! 2>/dev/null; wait $!"
        ),
        &format!("cat /proc/{pid}/mem"),
        &format!("ls /proc/{pid}/fd"),
        &format!("cat /proc/{pid}/environ"),
    ]);
    let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
    let status = daemon.cli(&["status"]);
    daemon.stop()?;
    result?;
    check(
        alive && status.is_ok(),
        "the daemon isn't running and answering after mallory's attempts",
        &format!("{status:?}"),
    )
}

pub fn bpf_programs_and_maps_are_out_of_reach() -> Result<(), String> {
    let mut daemon = Running::start("tamper-bpf", "mode = \"monitor\"\n")?;
    // The control: root sees the programs.
    let programs = run("bpftool", &["prog", "show"]).unwrap_or_default();
    let result = all_fail(&[
        "bpftool prog show",
        "bpftool map show",
        "bpftool map dump name flows",
        "ls /sys/fs/bpf/snitchhiker",
    ]);
    daemon.stop()?;
    check(
        programs.contains("tcp_connect") || programs.contains("tracing"),
        "root doesn't see the attribution programs (the control)",
        &programs,
    )?;
    result
}

/// Connecting again and again while the rules are reloaded again and again: nothing a rule doesn't allow gets through
/// in between.
pub fn connecting_while_rules_reload() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut daemon = Running::start(
        "tamper-reload",
        "mode = \"enforce\"\nno_match = \"reject\"\n",
    )?;
    let pid = daemon_pid()?;
    let script = format!(
        "import socket, time\nend = time.monotonic() + 4\nn = ok = 0\nwhile time.monotonic() < end:\n    n += 1\n    \
         try:\n        socket.create_connection(('127.0.0.1', {port}), timeout=0.2).close()\n        ok += 1\n    \
         except OSError:\n        pass\nprint(n, ok)"
    );
    let attacker = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    // The rules are reloaded every 20 ms while mallory connects.
    let started = Instant::now();
    let mut reloads = 0;
    while started.elapsed() < Duration::from_secs(4) {
        if run("kill", &["-HUP", &pid]).is_ok() {
            reloads += 1;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let attacker = attacker.wait_with_output().map_err(|e| e.to_string())?;
    let status = daemon.cli(&["status"]);
    daemon.stop()?;
    let mut accepted = 0;
    while listener.accept().is_ok() {
        accepted += 1;
    }
    let out = String::from_utf8_lossy(&attacker.stdout).into_owned();
    let found =
        format!("{reloads} reloads; attempts, connected: {out}accepted: {accepted}; {status:?}");
    check(
        reloads > 50 && status.is_ok(),
        "the reloads didn't happen, or the daemon didn't survive them",
        &found,
    )?;
    check(
        accepted == 0 && out.split_whitespace().nth(1) == Some("0"),
        "a connection no rule allows got through while the rules reloaded",
        &found,
    )
}
