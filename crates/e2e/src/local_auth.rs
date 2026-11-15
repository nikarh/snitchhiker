//! Local client authentication: only a registered setgid client binary, running as such, is let in; nothing a process
//! of the same user can do gets it the same.
//!
//! This binary doubles as the test client (`snitchhiker-e2e --client <socket> [--hold]`): installed setgid to the
//! client group, it is a client the way the desktop app will be.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use snitchhiker_daemon::peer::{ClientPolicy, TrustedExe, identify, verify};

use crate::util::{check, run};

const GROUP: &str = "snitchhiker-ui";
const DIR: &str = "/run/snitchhiker-test";
/// The registered client: this binary, root-owned, setgid to the client group.
const CLIENT: &str = "/usr/local/libexec/snitchhiker-test-client";
/// Root-owned and setgid to the client group too, but not registered.
const UNREGISTERED: &str = "/usr/local/libexec/snitchhiker-test-other";
/// A copy mallory owns: no setgid bit, nothing root vouches for.
const MALLORY_COPY: &str = "/tmp/mallory-client";

/// The client side against the daemon itself: the protocol's handshake on its client socket, then a rule listing.
pub fn protocol_client(socket: &str) -> std::process::ExitCode {
    let mut out = std::io::stdout().lock();
    match snitchhiker_client::Client::connect(Path::new(socket), "e2e", "0") {
        Ok(mut client) => {
            let role = client.welcome().role();
            let listed = client.call(snitchhiker_proto::v1::request::Method::ListRules(
                snitchhiker_proto::v1::ListRules {},
            ));
            let _ = writeln!(out, "welcome {role:?}, rules listed: {}", listed.is_ok());
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(out, "connect: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Against the daemon: the registered setgid client gets in with the admin role; a plain copy can't connect.
pub fn daemon_client_socket() -> Result<(), String> {
    // Installs the clients (serve() does), then runs the daemon with the registered one as a trusted client.
    let _ = serve("daemon-setup", 0o660)?;
    let mut daemon = crate::daemon::Running::start(
        "client-socket",
        &format!("mode = \"monitor\"\ntrusted_clients = [\"{CLIENT}\"]\n"),
    )?;
    let socket = "/run/snitchhiker/client.sock";
    let (registered_ok, registered) = as_mallory(CLIENT, &["--protocol-client", socket])?;
    let (copy_ok, copy) = as_mallory(MALLORY_COPY, &["--protocol-client", socket])?;
    daemon.stop()?;
    check(
        registered_ok && registered.contains("welcome Admin, rules listed: true"),
        "the registered client didn't get in",
        &registered,
    )?;
    check(
        !copy_ok && copy.contains("Permission denied"),
        "a plain copy could connect to the client socket",
        &copy,
    )
}

/// The client side: connects, says what the server answered, and exits 0 only when accepted.
pub fn client(socket: &str, hold: bool) -> std::process::ExitCode {
    let mut out = std::io::stdout().lock();
    let stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(error) => {
            let _ = writeln!(out, "connect: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    if hold {
        let _ = writeln!(out, "holding {}", std::process::id());
        let _ = out.flush();
        thread::sleep(Duration::from_secs(20));
    }
    let mut answer = String::new();
    let _ = BufReader::new(stream).read_line(&mut answer);
    let _ = write!(out, "{answer}");
    if answer.starts_with("accepted") {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

fn group_id() -> Result<u32, String> {
    run("groupadd", &["-f", "--system", GROUP])?;
    run("getent", &["group", GROUP])?
        .split(':')
        .nth(2)
        .and_then(|gid| gid.trim().parse().ok())
        .ok_or_else(|| "no gid for the client group".to_owned())
}

/// Installs the clients, and serves `socket` (mode `mode`, group the client group) with the peer checks, answering
/// each connection with the verdict.
fn serve(name: &str, mode: u32) -> Result<String, String> {
    let gid = group_id()?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let me = me.to_string_lossy();
    run("install", &["-d", "-m", "755", "/usr/local/libexec"])?;
    for (path, mode) in [(CLIENT, "2755"), (UNREGISTERED, "2755")] {
        run(
            "install",
            &["-o", "root", "-g", GROUP, "-m", mode, &me, path],
        )?;
    }
    run(
        "install",
        &["-o", "mallory", "-m", "755", &me, MALLORY_COPY],
    )?;
    run("install", &["-d", "-m", "755", DIR])?;

    let socket = format!("{DIR}/{name}.sock");
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).map_err(|e| format!("bind {socket}: {e}"))?;
    std::os::unix::fs::chown(&socket, Some(0), Some(gid)).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(mode))
        .map_err(|e| e.to_string())?;
    let policy = ClientPolicy {
        group: gid,
        trusted: vec![TrustedExe {
            path: CLIENT.into(),
        }],
    };
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let answer = match identify(&stream) {
                Ok(peer) => match verify(&peer, &policy) {
                    Ok(()) => "accepted\n".to_owned(),
                    Err(refusal) => format!("refused: {refusal}\n"),
                },
                Err(error) => format!("refused: {error}\n"),
            };
            let _ = (&stream).write_all(answer.as_bytes());
        }
    });
    Ok(socket)
}

/// Runs `program args` as mallory; returns (succeeded, output).
fn as_mallory(program: &str, args: &[&str]) -> Result<(bool, String), String> {
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", program])
        .args(args)
        .output()
        .map_err(|e| format!("runuser: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((output.status.success(), text))
}

pub fn setgid_client_accepted() -> Result<(), String> {
    let socket = serve("accepted", 0o660)?;
    let (ok, text) = as_mallory(CLIENT, &["--client", &socket])?;
    check(
        ok && text.contains("accepted"),
        "the registered client was refused",
        &text,
    )
}

pub fn plain_process_cannot_connect() -> Result<(), String> {
    let socket = serve("plain", 0o660)?;
    let (ok, text) = as_mallory(MALLORY_COPY, &["--client", &socket])?;
    check(
        !ok && text.contains("connect: Permission denied"),
        "a process without the client group could connect",
        &text,
    )
}

pub fn open_socket_still_refuses_plain_process() -> Result<(), String> {
    let socket = serve("open", 0o666)?;
    let (ok, text) = as_mallory(MALLORY_COPY, &["--client", &socket])?;
    check(
        !ok && text.contains("refused: the process doesn't have the client group"),
        "an ordinary process was let in",
        &text,
    )
}

pub fn unregistered_setgid_binary_refused() -> Result<(), String> {
    let socket = serve("unregistered", 0o660)?;
    let (ok, text) = as_mallory(UNREGISTERED, &["--client", &socket])?;
    check(
        !ok && text.contains("is not a trusted client binary"),
        "an unregistered binary was let in",
        &text,
    )
}

pub fn traced_client_refused() -> Result<(), String> {
    let socket = serve("traced", 0o660)?;
    // Under an unprivileged tracer the kernel doesn't apply the setgid bit, so the client lacks the group (and the
    // socket's permissions already stop it).
    let (ok, text) = as_mallory(
        "strace",
        &["-f", "-o", "/dev/null", CLIENT, "--client", &socket],
    )?;
    check(
        !ok && !text.contains("accepted"),
        "a traced client was let in",
        &text,
    )
}

pub fn same_user_cannot_attach_or_read_memory() -> Result<(), String> {
    let socket = serve("memory", 0o660)?;
    let mut child = Command::new("runuser")
        .args(["-u", "mallory", "--", CLIENT, "--client", &socket, "--hold"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    let stdout = child.stdout.take().ok_or("no stdout")?;
    BufReader::new(stdout)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let pid = line
        .trim()
        .strip_prefix("holding ")
        .ok_or_else(|| format!("unexpected client output: {line}"))?
        .to_owned();
    let mem = as_mallory(
        "python3",
        &["-c", &format!("open('/proc/{pid}/mem','rb').read(1)")],
    );
    let environ = as_mallory("cat", &[&format!("/proc/{pid}/environ")]);
    let attach = as_mallory("strace", &["-p", &pid, "-o", "/dev/null"]);
    let _ = child.kill();
    let _ = child.wait();
    let (mem_ok, mem_text) = mem?;
    let (environ_ok, environ_text) = environ?;
    let (attach_ok, attach_text) = attach?;
    check(!mem_ok, "mallory read the client's memory", &mem_text)?;
    check(
        !environ_ok,
        "mallory read the client's environment",
        &environ_text,
    )?;
    check(!attach_ok, "mallory attached to the client", &attach_text)?;
    check(
        Path::new(&format!("/proc/{pid}")).exists() || attach_text.contains("ermission"),
        "the client wasn't running during the attempts",
        &attach_text,
    )
}

/// A fake node: mallory serves a socket from a directory of their own. The client refuses it before saying anything.
pub fn client_refuses_a_fake_node() -> Result<(), String> {
    let _ = serve("fake-node-setup", 0o660)?;
    let dir = "/tmp/mallory-node";
    let socket = format!("{dir}/client.sock");
    let mut server = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "python3",
            "-c",
            &format!(
                "import os, socket\nos.makedirs('{dir}', exist_ok=True)\ns = socket.socket(socket.AF_UNIX)\n\
                 s.settimeout(10)\ns.bind('{socket}')\nos.chmod('{socket}', 0o666)\ns.listen()\n\
                 print('ready', flush=True)\nc, _ = s.accept()\nprint('accepted', flush=True)"
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(server.stdout.take().ok_or("no stdout")?).lines();
    let ready = lines.next().and_then(Result::ok).unwrap_or_default();
    let (ok, text) = as_mallory(CLIENT, &["--protocol-client", &socket])?;
    // runuser waits for its child rather than handing over to it: end the server itself.
    let _ = run("pkill", &["-u", "mallory", "-f", "mallory-node"]);
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(dir);
    check(ready == "ready", "the fake node didn't start", &ready)?;
    check(
        !ok && text.contains("not a Snitchhiker node's socket"),
        "the client talked to a fake node",
        &text,
    )
}
