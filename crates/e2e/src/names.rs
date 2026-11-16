//! Host rules: the daemon learns names from the DNS answers processes receive, and only from answers to queries they
//! sent.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::daemon::Running;
use crate::util::check;

const RESOLVER: &str = "127.0.0.2:53";
const NAME: &str = "app.example.test";
const ADDRESS: &str = "127.0.0.9";

/// A resolver answering every A query for `NAME` with `ADDRESS`, until dropped.
struct Resolver {
    stop: Arc<AtomicBool>,
}

impl Resolver {
    fn start() -> Result<Self, String> {
        let socket = UdpSocket::bind(RESOLVER).map_err(|e| format!("resolver: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            while !stopping.load(Ordering::Relaxed) {
                let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                let Some(query) = buffer.get(..length).and_then(|b| Message::from_vec(b).ok())
                else {
                    continue;
                };
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                for question in &query.queries {
                    response.add_query(question.clone());
                    if question.name().to_utf8().trim_end_matches('.') == NAME {
                        response.add_answer(answer(NAME, ADDRESS));
                    }
                }
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, from);
                }
            }
        });
        Ok(Self { stop })
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn answer(name: &str, address: &str) -> Record {
    Record::from_rdata(
        Name::from_str(&format!("{name}.")).unwrap_or_default(),
        60,
        RData::A(A(address
            .parse()
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED))),
    )
}

/// Runs python as mallory: optionally resolves `NAME` through the test resolver first, then connects to `address`.
fn mallory(resolve: bool, address: &str, port: u16) -> Result<String, String> {
    let resolve = if resolve {
        format!(
            "q = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(l)]) + l.encode() for l in '{NAME}'.split('.')) + b'\\x00' + struct.pack('>HH', 1, 1)\n\
             u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nu.settimeout(2)\nu.sendto(q, ('127.0.0.2', 53))\n\
             print('resolved', socket.inet_ntoa(u.recv(512)[-4:]))\n"
        )
    } else {
        String::new()
    };
    let script = format!(
        "import socket, struct\n{resolve}try:\n    socket.create_connection(('{address}', {port}), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
    );
    let output = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn listen(address: &str) -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind(format!("{address}:0")).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok((listener, port))
}

fn start_with_rules(name: &str, port: u16) -> Result<Running, String> {
    let daemon = Running::start(name, "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--net",
        "127.0.0.2",
        "--port",
        "53",
        "--protocol",
        "udp",
        "--name",
        "python to the test resolver",
    ])?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "glob:/usr/bin/python3*",
        "--host",
        NAME,
        "--port",
        &port.to_string(),
        "--name",
        "python to the test host",
    ])?;
    thread::sleep(Duration::from_millis(300));
    Ok(daemon)
}

pub fn host_rules_match_resolved_names() -> Result<(), String> {
    let _resolver = Resolver::start()?;
    let (_named, port) = listen(ADDRESS)?;
    let (_unnamed, other_port) = listen("127.0.0.10")?;
    let mut daemon = start_with_rules("names", port)?;
    let named = mallory(true, ADDRESS, port)?;
    let unnamed = mallory(false, "127.0.0.10", other_port)?;
    thread::sleep(Duration::from_millis(500));
    let events = daemon.cli(&["events", "--limit", "20"])?;
    daemon.stop()?;
    check(
        named.contains("resolved 127.0.0.9") && named.contains("connected"),
        "a connection to a name a host rule allows was blocked",
        &format!("{named}\n{events}"),
    )?;
    check(
        !unnamed.contains("connected"),
        "a connection with no name went through",
        &unnamed,
    )?;
    check(
        events
            .lines()
            .any(|l| l.contains("allow") && l.contains(&format!("{NAME}:{port}"))),
        "the history doesn't show the connection's host name",
        &events,
    )
}

pub fn unsolicited_answers_teach_nothing() -> Result<(), String> {
    let (_spoofed, port) = listen("127.0.0.11")?;
    let mut daemon = start_with_rules("spoofed", port)?;
    // An answer from the resolver's address to a port that never asked, claiming 127.0.0.11 is the allowed name.
    let resolver = UdpSocket::bind(RESOLVER).map_err(|e| format!("spoofing resolver: {e}"))?;
    let mut message = Message::new(7, MessageType::Response, OpCode::Query);
    message.add_query(Query::query(
        Name::from_str(&format!("{NAME}.")).map_err(|e| e.to_string())?,
        RecordType::A,
    ));
    message.add_answer(answer(NAME, "127.0.0.11"));
    let bytes = message.to_vec().map_err(|e| e.to_string())?;
    for port in [40_000_u16, 40_001, 40_002] {
        let _ = resolver.send_to(&bytes, SocketAddr::from(([127, 0, 0, 1], port)));
    }
    thread::sleep(Duration::from_millis(300));
    let spoofed = mallory(false, "127.0.0.11", port)?;
    daemon.stop()?;
    check(
        !spoofed.contains("connected"),
        "a spoofed DNS answer made a connection count as an allowed host",
        &spoofed,
    )
}

/// A name systemd-resolved answers from its own data (here `/etc/hosts`; its cache is the same) crosses no network:
/// the daemon learns it from resolved's monitor, and the connection to its address carries it.
pub fn names_from_systemd_resolved() -> Result<(), String> {
    const RESOLVED_NAME: &str = "monitored.snitchhiker.test";
    const RESOLVED_ADDRESS: &str = "127.0.0.12";
    let hosts = std::fs::read_to_string("/etc/hosts").map_err(|e| e.to_string())?;
    let line = format!("{RESOLVED_ADDRESS} {RESOLVED_NAME}\n");
    if !hosts.contains(&line) {
        std::fs::write("/etc/hosts", format!("{hosts}{line}")).map_err(|e| e.to_string())?;
    }
    crate::util::run("systemctl", &["start", "systemd-resolved"])?;
    let (_listener, port) = listen(RESOLVED_ADDRESS)?;
    let mut daemon = Running::start("resolved", "mode = \"monitor\"\n")?;
    // The daemon subscribes as it starts; give it a moment.
    thread::sleep(Duration::from_millis(500));
    let resolved = crate::util::run("resolvectl", &["query", RESOLVED_NAME])?;
    let connected = mallory(false, RESOLVED_ADDRESS, port)?;
    thread::sleep(Duration::from_millis(500));
    let events = daemon.cli(&["events", "--limit", "20"])?;
    daemon.stop()?;
    let _ = crate::util::run("systemctl", &["stop", "systemd-resolved"]);
    check(
        events
            .lines()
            .any(|l| l.contains(&format!("{RESOLVED_NAME}:{port}"))),
        "a name systemd-resolved gave isn't on the connection",
        &format!("{resolved}\n{connected}\n{events}"),
    )
}
