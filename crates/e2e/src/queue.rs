//! NFQUEUE: new connections are held until a verdict, and nothing passes when nobody decides (unless the table says
//! to fail open).

use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use snitchhiker_netfilter::netlink::{Socket, Writer};
use snitchhiker_netfilter::nftables::{Table, encode_install, encode_remove};
use snitchhiker_netfilter::queue::{Queue, Verdict};

use crate::util::check;

/// The test VMs' unprivileged user (see e2e/vm.sh).
pub const MALLORY_UID: u32 = 1001;

/// The table, installed for the life of the value and removed when it is dropped.
pub struct Installed;

impl Installed {
    pub fn new(bypass: bool) -> Result<Self, String> {
        let table = Table {
            queues: 1,
            bypass,
            ..Table::default()
        };
        let mut socket = Socket::open().map_err(|e| format!("netlink socket: {e}"))?;
        let mut writer = Writer::new();
        let batch = encode_install(&mut writer, &table, 1);
        socket
            .transact(&writer, batch.first, batch.last)
            .map_err(|e| format!("installing the table: {e}"))?;
        Ok(Self)
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        if let Ok(mut socket) = Socket::open() {
            let mut writer = Writer::new();
            let batch = encode_remove(&mut writer, "snitchhiker", 1);
            let _ = socket.transact(&writer, batch.first, batch.last);
        }
    }
}

/// Connects to 127.0.0.1:`port` as mallory, giving up after `timeout`; returns how long it took and whether it
/// connected.
fn connect_as_mallory(port: u16, timeout: Duration) -> Result<(Duration, bool), String> {
    let script = format!(
        "import socket\ns = socket.create_connection(('127.0.0.1', {port}), timeout={})\nprint('connected')",
        timeout.as_secs_f32()
    );
    let start = Instant::now();
    let Output { status, stdout, .. } = Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .output()
        .map_err(|e| format!("runuser: {e}"))?;
    let connected = status.success() && String::from_utf8_lossy(&stdout).contains("connected");
    Ok((start.elapsed(), connected))
}

/// What the queue thread saw of the first packet.
#[derive(Debug)]
struct Seen {
    uid: Option<u32>,
    destination_port: Option<u16>,
    syn_only: bool,
}

/// Binds queue 0 and gives every packet `verdict` after `hold`, reporting the first one to `port`, until `stop`.
/// Packets to other ports (the VM's own NTP or DNS) get the verdict too but aren't reported.
fn serve(
    port: u16,
    verdict: Verdict,
    hold: Duration,
    stop: Arc<AtomicBool>,
    seen: mpsc::Sender<Seen>,
) -> Result<thread::JoinHandle<Result<(), String>>, String> {
    let mut queue = Queue::bind(0).map_err(|e| format!("binding queue 0: {e}"))?;
    Ok(thread::spawn(move || {
        let mut first = true;
        while !stop.load(Ordering::Relaxed) {
            let mut decided = Vec::new();
            for packet in queue.receive().map_err(|e| format!("receive: {e}"))? {
                let tcp = packet.payload.get(20..);
                let destination_port = tcp
                    .and_then(|t| t.get(2..4))
                    .and_then(|p| p.try_into().ok())
                    .map(u16::from_be_bytes);
                if first && destination_port == Some(port) {
                    first = false;
                    let _ = seen.send(Seen {
                        uid: packet.uid,
                        destination_port,
                        syn_only: tcp
                            .and_then(|t| t.get(13))
                            .is_some_and(|f| f & 0x17 == 0x02),
                    });
                }
                decided.push(packet.id);
            }
            thread::sleep(hold);
            for id in decided {
                queue
                    .verdict(id, verdict)
                    .map_err(|e| format!("verdict: {e}"))?;
            }
        }
        Ok(())
    }))
}

fn listener() -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("listen: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok((listener, port))
}

/// Wakes a queue thread blocked in `receive` by making one more connection, after `stop` was set.
fn wake(port: u16) {
    let _ = std::net::TcpStream::connect_timeout(
        &([127, 0, 0, 1], port).into(),
        Duration::from_millis(200),
    );
}

pub fn holds_until_accepted() -> Result<(), String> {
    let _table = Installed::new(false)?;
    let (_listener, port) = listener()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, seen) = mpsc::channel();
    let worker = serve(
        port,
        Verdict::Accept,
        Duration::from_secs(2),
        Arc::clone(&stop),
        sender,
    )?;
    let (took, connected) = connect_as_mallory(port, Duration::from_secs(10))?;
    stop.store(true, Ordering::Relaxed);
    wake(port);
    let _ = worker.join();
    let seen = seen
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| "no packet was queued".to_owned())?;
    let found = format!("{seen:?}, took {took:?}, connected: {connected}");
    check(connected, "the connection didn't go through", &found)?;
    check(took >= Duration::from_secs(2), "it wasn't held", &found)?;
    check(seen.uid == Some(MALLORY_UID), "wrong socket owner", &found)?;
    check(
        seen.destination_port == Some(port),
        "wrong destination port",
        &found,
    )?;
    check(seen.syn_only, "the queued packet isn't a SYN", &found)
}

pub fn dropped_never_connects() -> Result<(), String> {
    let _table = Installed::new(false)?;
    let (_listener, port) = listener()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, _seen) = mpsc::channel();
    let worker = serve(
        port,
        Verdict::Drop,
        Duration::ZERO,
        Arc::clone(&stop),
        sender,
    )?;
    let (took, connected) = connect_as_mallory(port, Duration::from_secs(3))?;
    stop.store(true, Ordering::Relaxed);
    wake(port);
    let _ = worker.join();
    check(
        !connected,
        "a dropped connection went through",
        &format!("{took:?}"),
    )
}

pub fn unbound_fails_closed() -> Result<(), String> {
    let _table = Installed::new(false)?;
    let (_listener, port) = listener()?;
    let (took, connected) = connect_as_mallory(port, Duration::from_secs(3))?;
    check(
        !connected,
        "a connection went through with no daemon and no bypass",
        &format!("{took:?}"),
    )
}

pub fn unbound_with_bypass_fails_open() -> Result<(), String> {
    let _table = Installed::new(true)?;
    let (_listener, port) = listener()?;
    let (took, connected) = connect_as_mallory(port, Duration::from_secs(3))?;
    check(
        connected,
        "with bypass, a connection didn't go through with no daemon",
        &format!("{took:?}"),
    )
}
