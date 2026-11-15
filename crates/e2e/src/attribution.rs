//! eBPF attribution: when NFQUEUE hands over a flow's first packet, its owner is already known, exactly, by the flow.

use std::os::unix::fs::MetadataExt as _;
use std::process::Command;
use std::thread;
use std::time::Duration;

use snitchhiker_ebpf::{Attribution, FlowKey, FlowOwner};
use snitchhiker_netfilter::packet;
use snitchhiker_netfilter::queue::{Queue, Verdict};

use crate::queue::{Installed, MALLORY_UID};
use crate::util::check;

/// What the daemon would know about the first queued packet's owner.
#[derive(Debug)]
struct Owner {
    owner: Option<FlowOwner>,
    exe: Option<String>,
    protocol: u8,
}

/// Runs `script` with python3 as mallory, and looks up the owner of the first packet it queues (at once, without
/// waiting), accepting everything.
fn first_owner(script: &str) -> Result<Owner, String> {
    let _table = Installed::new(false)?;
    let attribution = Attribution::load().map_err(|e| e.to_string())?;
    let mut queue = Queue::bind(0).map_err(|e| format!("binding queue 0: {e}"))?;
    let netns = u32::try_from(
        std::fs::metadata("/proc/self/ns/net")
            .map_err(|e| e.to_string())?
            .ino(),
    )
    .map_err(|e| e.to_string())?;

    let script = script.to_owned();
    let client = thread::spawn(move || {
        Command::new("runuser")
            .args(["-u", "mallory", "--", "python3", "-c", &script])
            .output()
    });

    let mut found = None;
    while found.is_none() {
        let mut ids = Vec::new();
        for queued in queue.receive().map_err(|e| format!("receive: {e}"))? {
            ids.push(queued.id);
            let Some(headers) = packet::parse(queued.payload) else {
                continue;
            };
            if found.is_some() {
                continue;
            }
            let key = FlowKey {
                netns,
                protocol: headers.protocol,
                source_port: headers.source_port,
                destination: headers.destination,
                destination_port: headers.destination_port,
            };
            let owner = attribution.owner(&key);
            let exe = owner.and_then(|o| {
                std::fs::read_link(format!("/proc/{}/exe", o.pid))
                    .ok()
                    .map(|p| p.display().to_string())
            });
            found = Some(Owner {
                owner,
                exe,
                protocol: headers.protocol,
            });
        }
        for id in ids {
            queue
                .verdict(id, Verdict::Accept)
                .map_err(|e| format!("verdict: {e}"))?;
        }
    }
    // Let anything else the client sends through until it is done.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = client.join();
    found.ok_or_else(|| "nothing was queued".to_owned())
}

fn check_owner(found: &Owner, protocol: u8) -> Result<(), String> {
    let text = format!("{found:?}");
    let owner = found.owner.ok_or_else(|| {
        format!("the flow's owner wasn't known when its packet was queued: {text}")
    })?;
    check(found.protocol == protocol, "wrong protocol", &text)?;
    check(owner.uid == MALLORY_UID, "wrong uid", &text)?;
    check(
        owner.comm().starts_with(b"python"),
        "wrong process name",
        &text,
    )?;
    check(
        found
            .exe
            .as_deref()
            .is_some_and(|exe| exe.contains("python")),
        "wrong executable",
        &text,
    )
}

pub fn tcp_v4() -> Result<(), String> {
    let found = first_owner(
        "import socket\ntry:\n    socket.create_connection(('127.0.0.1', 9), timeout=3)\nexcept OSError:\n    pass",
    )?;
    check_owner(&found, packet::IPPROTO_TCP)
}

pub fn tcp_v6() -> Result<(), String> {
    let found = first_owner(
        "import socket\ntry:\n    socket.create_connection(('::1', 9), timeout=3)\nexcept OSError:\n    pass",
    )?;
    check_owner(&found, packet::IPPROTO_TCP)
}

pub fn udp_sendto() -> Result<(), String> {
    let found = first_owner(
        "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.sendto(b'x', ('127.0.0.1', 9))",
    )?;
    check_owner(&found, packet::IPPROTO_UDP)
}
