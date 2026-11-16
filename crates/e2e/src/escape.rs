//! The escape suite, packet side: an ordinary user trying to get packets out that no rule allows. Every attempt must
//! fail; a control connection that a rule allows shows the setup itself works.

use std::net::{TcpListener, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::daemon::Running;
use crate::util::{check, run};

/// Runs python as mallory; returns what it printed (stdout and stderr).
fn python(script: &str) -> Result<String, String> {
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", script])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// The daemon enforcing, denying what no rule allows, with one rule: python may reach `allowed` over TCP.
fn guarded(name: &str, allowed: u16) -> Result<Running, String> {
    let daemon = Running::start(name, "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--port",
        &allowed.to_string(),
        "--protocol",
        "tcp",
    ])?;
    thread::sleep(Duration::from_millis(300));
    Ok(daemon)
}

fn tcp_listener(address: &str) -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind(format!("{address}:0")).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok((listener, port))
}

/// The control: what a rule allows still gets through.
fn control(port: u16) -> Result<(), String> {
    let out = python(&format!(
        "import socket\nsocket.create_connection(('127.0.0.1', {port}), timeout=2)\nprint('connected')"
    ))?;
    check(
        out.contains("connected"),
        "the allowed control connection failed",
        &out,
    )
}

pub fn tcp_fast_open() -> Result<(), String> {
    let (_allowed, allowed) = tcp_listener("127.0.0.1")?;
    let (listener, port) = tcp_listener("127.0.0.1")?;
    let _daemon = guarded("tfo", allowed)?;
    control(allowed)?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let out = python(&format!(
        "import socket\ns = socket.socket()\ns.settimeout(2)\ntry:\n    s.sendto(b'leak', socket.MSG_FASTOPEN, ('127.0.0.1', {port}))\n    print('sent')\nexcept OSError as e:\n    print('failed', e)"
    ))?;
    thread::sleep(Duration::from_millis(300));
    let accepted = listener.accept().is_ok();
    check(
        !accepted,
        "data sent with TCP Fast Open reached the listener",
        &out,
    )
}

pub fn udp_sendto() -> Result<(), String> {
    let (_allowed, allowed) = tcp_listener("127.0.0.1")?;
    let receiver = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = receiver.local_addr().map_err(|e| e.to_string())?.port();
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;
    let _daemon = guarded("udp", allowed)?;
    let out = python(&format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nfor _ in range(5):\n    s.sendto(b'leak', ('127.0.0.1', {port}))\nprint('sent')"
    ))?;
    let mut buffer = [0_u8; 16];
    let received = receiver.recv(&mut buffer).is_ok();
    check(!received, "a UDP datagram no rule allows arrived", &out)
}

pub fn ipv6_and_mapped_ipv4() -> Result<(), String> {
    let (_allowed, allowed) = tcp_listener("127.0.0.1")?;
    let (_v4, v4_port) = tcp_listener("127.0.0.1")?;
    let (_v6, v6_port) = tcp_listener("[::1]")?;
    let _daemon = guarded("ipv6", allowed)?;
    let out = python(&format!(
        "import socket\nfor host, port in (('::1', {v6_port}), ('::ffff:127.0.0.1', {v4_port})):\n    s = socket.socket(socket.AF_INET6)\n    s.settimeout(2)\n    try:\n        s.connect((host, port))\n        print('connected', host)\n    except OSError as e:\n        print('failed', host, e)"
    ))?;
    check(
        !out.contains("connected"),
        "an IPv6 or IPv4-mapped connection got through",
        &out,
    )
}

pub fn icmp_ping_socket() -> Result<(), String> {
    let (_allowed, allowed) = tcp_listener("127.0.0.1")?;
    let _daemon = guarded("icmp", allowed)?;
    // An unprivileged ICMP echo (ping sockets): no reply may come back, since the request must not get out.
    let out = python(
        "import socket\ntry:\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)\nexcept OSError as e:\n    print('unavailable', e)\n    raise SystemExit\ns.settimeout(1)\ns.sendto(b'\\x08\\x00\\x00\\x00\\x12\\x34\\x00\\x01leak', ('127.0.0.1', 0))\ntry:\n    s.recv(64)\n    print('reply')\nexcept OSError as e:\n    print('no reply', e)",
    )?;
    // Ping sockets may be disabled for the user (`unavailable`): then nothing can get out that way either.
    check(
        out.contains("no reply") || out.contains("unavailable"),
        "an ICMP echo got out",
        &out,
    )
}

/// The kernel's own ICMP (here "port unreachable", about a datagram a rule allowed) isn't a program's: it passes
/// undecided, so the sender learns the port is closed rather than waiting, and no prompt asks about "no program".
pub fn the_kernels_own_icmp_passes() -> Result<(), String> {
    let closed = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = closed.local_addr().map_err(|e| e.to_string())?.port();
    drop(closed);
    let daemon = Running::start("kernel-icmp", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--port",
        &port.to_string(),
        "--protocol",
        "udp",
    ])?;
    thread::sleep(Duration::from_millis(300));
    let out = python(&format!(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(2)\ns.connect(('127.0.0.1', {port}))\ns.send(b'hello')\ntry:\n    s.recv(64)\n    print('answered')\nexcept ConnectionRefusedError:\n    print('refused')\nexcept OSError as e:\n    print('no answer', e)"
    ))?;
    check(
        out.contains("refused"),
        "the kernel's port unreachable didn't reach the sender",
        &out,
    )
}

pub fn raw_sockets_need_privileges() -> Result<(), String> {
    let out = python(
        "import socket\nfor kind in (socket.SOCK_RAW,):\n    try:\n        socket.socket(socket.AF_INET, kind, socket.IPPROTO_TCP)\n        print('opened raw')\n    except OSError as e:\n        print('refused', e.errno)\ntry:\n    socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n    print('opened packet')\nexcept OSError as e:\n    print('refused', e.errno)",
    )?;
    check(
        !out.contains("opened"),
        "an ordinary user opened a raw or packet socket",
        &out,
    )
}

pub fn spoofed_process_name() -> Result<(), String> {
    let (_target, port) = tcp_listener("127.0.0.1")?;
    let daemon = Running::start("spoofed-name", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    // A rule for curl; python pretends to be curl in argv[0] and in its process name.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/usr/bin/curl",
        "--port",
        &port.to_string(),
    ])?;
    thread::sleep(Duration::from_millis(300));
    let script = format!(
        "import ctypes, socket\nctypes.CDLL(None).prctl(15, b'curl', 0, 0, 0)\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
    );
    let output = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "bash",
            "-c",
            "exec -a /usr/bin/curl python3 -c \"$0\"",
            &script,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let out = String::from_utf8_lossy(&output.stdout).into_owned();
    check(
        !out.contains("connected"),
        "a process passed for curl by its name",
        &out,
    )
}

pub fn allowed_path_in_a_private_mount_namespace() -> Result<(), String> {
    let (_target, port) = tcp_listener("127.0.0.1")?;
    let daemon = Running::start("mountns", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/usr/bin/curl",
        "--port",
        &port.to_string(),
    ])?;
    thread::sleep(Duration::from_millis(300));
    // Inside a user and mount namespace mallory can put python at /usr/bin/curl: /proc then shows /usr/bin/curl as the
    // executable. It runs in another mount namespace, so host rules don't apply to it.
    let python = run("bash", &["-c", "readlink -f $(command -v python3)"])?;
    let script = format!(
        "mount --bind {} /usr/bin/curl && exec /usr/bin/curl -c \"import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)\"",
        python.trim()
    );
    let output = Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "bash",
            "-c",
            &script,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // `failed` only comes from python running as /usr/bin/curl inside the namespace: anything else means the
    // attempt wasn't made, which must not pass for a refusal.
    check(
        out.contains("failed") && !out.contains("connected"),
        "a binary at an allowed path in a private mount namespace got the host's rule (or the namespace couldn't \
         be set up)",
        &out,
    )
}

/// A service systemd sandboxes (a mount namespace of its own, made by root, as `ProtectSystem` and `PrivateTmp` make
/// one) is the host's: host rules apply to it.
pub fn sandboxed_service_is_the_host() -> Result<(), String> {
    let (_target, port) = tcp_listener("127.0.0.1")?;
    let daemon = Running::start("sandboxed", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
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
    let script = format!(
        "import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
    );
    let output = Command::new("unshare")
        .args([
            "--mount",
            "--propagation",
            "private",
            "runuser",
            "-u",
            "mallory",
            "--",
            "python3",
            "-c",
            &script,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    check(
        out.contains("connected"),
        "a process in a mount namespace root made (as a systemd sandbox) didn't get the host's rule",
        &out,
    )
}

pub fn non_dumpable_process_is_not_root() -> Result<(), String> {
    let (_target, port) = tcp_listener("127.0.0.1")?;
    let daemon = Running::start("non-dumpable", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    // A rule for root's connections; the kernel makes /proc/<pid> root's for a process that isn't dumpable.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--uid",
        "0",
        "--port",
        &port.to_string(),
    ])?;
    thread::sleep(Duration::from_millis(300));
    let root = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    );
    let out = python(&format!(
        "import ctypes, socket\nctypes.CDLL(None).prctl(4, 0, 0, 0, 0)\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
    ))?;
    check(
        root.is_ok(),
        "root's control connection failed",
        &format!("{root:?}"),
    )?;
    check(
        !out.contains("connected"),
        "a non-dumpable process passed for root",
        &out,
    )
}
