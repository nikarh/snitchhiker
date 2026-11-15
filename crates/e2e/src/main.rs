//! Snitchhiker's end-to-end scenarios. This program changes the firewall, loads BPF and runs the daemon: it refuses
//! to run anywhere but in the disposable test VMs of `e2e/` (`e2e/run.sh` copies it there and runs it as root).
//!
//! Usage: `snitchhiker-e2e [filter]`, running every scenario whose name contains `filter`.

use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

mod attribution;
mod local_auth;
mod nftables;
mod queue;
mod util;

/// A scenario: a name and a function that fails with a message.
type Scenario = (&'static str, fn() -> Result<(), String>);

const SCENARIOS: &[Scenario] = &[
    ("nftables/install", nftables::install),
    ("nftables/reinstall-is-atomic", nftables::reinstall_replaces),
    ("nftables/remove", nftables::remove),
    (
        "nftables/other-tables-untouched",
        nftables::other_tables_untouched,
    ),
    ("queue/holds-until-accepted", queue::holds_until_accepted),
    (
        "queue/dropped-never-connects",
        queue::dropped_never_connects,
    ),
    ("queue/unbound-fails-closed", queue::unbound_fails_closed),
    (
        "queue/unbound-with-bypass-fails-open",
        queue::unbound_with_bypass_fails_open,
    ),
    ("attribution/tcp-v4", attribution::tcp_v4),
    ("attribution/tcp-v6", attribution::tcp_v6),
    ("attribution/udp-sendto", attribution::udp_sendto),
    (
        "local-auth/setgid-client-accepted",
        local_auth::setgid_client_accepted,
    ),
    (
        "local-auth/plain-process-cannot-connect",
        local_auth::plain_process_cannot_connect,
    ),
    (
        "local-auth/open-socket-still-refuses-plain-process",
        local_auth::open_socket_still_refuses_plain_process,
    ),
    (
        "local-auth/unregistered-setgid-binary-refused",
        local_auth::unregistered_setgid_binary_refused,
    ),
    (
        "local-auth/traced-client-refused",
        local_auth::traced_client_refused,
    ),
    (
        "local-auth/same-user-cannot-attach-or-read-memory",
        local_auth::same_user_cannot_attach_or_read_memory,
    ),
];

/// The marker `e2e/vm.sh` leaves in every test VM.
const VM_MARKER: &str = "/var/lib/snitchhiker-e2e-ready";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let (Some("--client"), Some(socket)) = (args.get(1).map(String::as_str), args.get(2)) {
        return local_auth::client(socket, args.get(3).is_some_and(|a| a == "--hold"));
    }
    let mut out = io::stdout().lock();
    if !std::path::Path::new(VM_MARKER).exists() {
        let _ = writeln!(
            out,
            "refusing to run: this is not a test VM ({VM_MARKER} is missing)"
        );
        return ExitCode::FAILURE;
    }
    let filter = std::env::args().nth(1).unwrap_or_default();
    let mut failed = 0_u32;
    let mut ran = 0_u32;
    for (name, scenario) in SCENARIOS.iter().filter(|(name, _)| name.contains(&filter)) {
        ran += 1;
        let start = Instant::now();
        let result = scenario();
        let took = start.elapsed().as_millis();
        match result {
            Ok(()) => {
                let _ = writeln!(out, "ok    {name} ({took} ms)");
            }
            Err(message) => {
                failed += 1;
                let _ = writeln!(
                    out,
                    "FAIL  {name} ({took} ms)\n      {}",
                    message.replace('\n', "\n      ")
                );
            }
        }
    }
    let _ = writeln!(out, "\n{ran} scenarios, {failed} failed");
    if failed == 0 && ran > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
