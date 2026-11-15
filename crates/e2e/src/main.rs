//! Snitchhiker's end-to-end scenarios. This program changes the firewall, loads BPF and runs the daemon: it refuses
//! to run anywhere but in the disposable test VMs of `e2e/` (`e2e/run.sh` copies it there and runs it as root).
//!
//! Usage: `snitchhiker-e2e [filter]`, running every scenario whose name contains `filter`.

use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

mod attribution;
mod daemon;
mod escape;
mod local_auth;
mod names;
mod nftables;
mod perf;
mod pointer;
mod prompts;
mod queue;
mod stepup;
mod subscriptions;
mod tamper;
mod tray;
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
    (
        "local-auth/daemon-client-socket",
        local_auth::daemon_client_socket,
    ),
    (
        "local-auth/registered-clients-are-pinned",
        local_auth::registered_clients_are_pinned,
    ),
    (
        "local-auth/connection-ends-with-its-process",
        local_auth::connection_ends_with_its_process,
    ),
    (
        "local-auth/client-refuses-a-fake-node",
        local_auth::client_refuses_a_fake_node,
    ),
    (
        "tamper/admin-socket-refuses-ordinary-users",
        tamper::admin_socket_refuses_ordinary_users,
    ),
    (
        "tamper/disguised-clients-are-refused",
        tamper::disguised_clients_are_refused,
    ),
    (
        "tamper/configuration-state-and-runtime-are-root-only",
        tamper::configuration_state_and_runtime_are_root_only,
    ),
    (
        "tamper/the-service-cannot-be-stopped-or-changed",
        tamper::the_service_cannot_be_stopped_or_changed,
    ),
    (
        "tamper/the-daemon-cannot-be-signalled-or-traced",
        tamper::the_daemon_cannot_be_signalled_or_traced,
    ),
    (
        "tamper/bpf-programs-and-maps-are-out-of-reach",
        tamper::bpf_programs_and_maps_are_out_of_reach,
    ),
    (
        "tamper/connecting-while-rules-reload",
        tamper::connecting_while_rules_reload,
    ),
    (
        "subscriptions/events-resume-from-a-sequence-number",
        subscriptions::events_resume_from_a_sequence_number,
    ),
    (
        "subscriptions/events-come-as-columnar-blocks",
        subscriptions::events_come_as_columnar_blocks,
    ),
    (
        "subscriptions/waiting-prompts-are-sent-on-subscribing",
        subscriptions::waiting_prompts_are_sent_on_subscribing,
    ),
    (
        "step-up/allow-everything-needs-authorization",
        stepup::allow_everything_needs_authorization,
    ),
    ("daemon/enforces-rules", daemon::enforces_rules),
    (
        "daemon/monitor-records-but-never-blocks",
        daemon::monitor_records_but_never_blocks,
    ),
    (
        "daemon/fail-closed-keeps-the-table",
        daemon::fail_closed_keeps_the_table,
    ),
    (
        "daemon/fail-open-removes-the-table",
        daemon::fail_open_removes_the_table,
    ),
    ("daemon/reject-fails-at-once", daemon::reject_fails_at_once),
    (
        "daemon/service-starts-ready-and-stops",
        daemon::service_starts_ready_and_stops,
    ),
    (
        "daemon/loopback-is-allowed-by-default",
        daemon::loopback_is_allowed_by_default,
    ),
    (
        "daemon/managed-rules-apply-and-are-locked",
        daemon::managed_rules_apply_and_are_locked,
    ),
    ("daemon/bytes-are-counted", daemon::bytes_are_counted),
    ("daemon/learn-then-enforce", daemon::learn_then_enforce),
    (
        "daemon/changes-are-recorded-and-undone",
        daemon::changes_are_recorded_and_undone,
    ),
    (
        "daemon/alerts-are-raised-and-acknowledged",
        daemon::alerts_are_raised_and_acknowledged,
    ),
    (
        "daemon/system-firewall-filters-inbound",
        daemon::system_firewall_filters_inbound,
    ),
    (
        "daemon/policy-changes-apply-at-once-and-undo",
        daemon::policy_changes_apply_at_once_and_undo,
    ),
    (
        "daemon/rules-are-edited-in-bulk-and-linted",
        daemon::rules_are_edited_in_bulk_and_linted,
    ),
    (
        "daemon/connections-are-listed-and-killed",
        daemon::connections_are_listed_and_killed,
    ),
    (
        "daemon/opensnitch-rules-import-and-apply",
        daemon::opensnitch_rules_import_and_apply,
    ),
    (
        "perf/foreign-sets-dont-slow-us-down",
        perf::foreign_sets_dont_slow_us_down,
    ),
    (
        "prompts/an-answer-decides-and-leaves-a-rule",
        prompts::an_answer_decides_and_leaves_a_rule,
    ),
    (
        "prompts/unanswered-prompts-time-out",
        prompts::unanswered_prompts_time_out,
    ),
    (
        "prompts/the-same-connections-share-a-prompt",
        prompts::the_same_connections_share_a_prompt,
    ),
    (
        "prompts/without-listeners-no-client-decides",
        prompts::without_listeners_no_client_decides,
    ),
    ("escape/tcp-fast-open", escape::tcp_fast_open),
    ("escape/udp-sendto", escape::udp_sendto),
    ("escape/ipv6-and-mapped-ipv4", escape::ipv6_and_mapped_ipv4),
    ("escape/icmp-ping-socket", escape::icmp_ping_socket),
    (
        "escape/raw-sockets-need-privileges",
        escape::raw_sockets_need_privileges,
    ),
    ("escape/spoofed-process-name", escape::spoofed_process_name),
    (
        "escape/non-dumpable-process-is-not-root",
        escape::non_dumpable_process_is_not_root,
    ),
    (
        "escape/allowed-path-in-a-private-mount-namespace",
        escape::allowed_path_in_a_private_mount_namespace,
    ),
    (
        "names/host-rules-match-resolved-names",
        names::host_rules_match_resolved_names,
    ),
    (
        "names/unsolicited-answers-teach-nothing",
        names::unsolicited_answers_teach_nothing,
    ),
];

/// The marker `e2e/vm.sh` leaves in every test VM.
const VM_MARKER: &str = "/var/lib/snitchhiker-e2e-ready";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let (Some("--protocol-client"), Some(socket)) =
        (args.get(1).map(String::as_str), args.get(2))
    {
        return local_auth::protocol_client(socket);
    }
    if let (Some("--add-rule"), Some(socket), Some(kind)) =
        (args.get(1).map(String::as_str), args.get(2), args.get(3))
    {
        return stepup::add_rule(socket, kind);
    }
    if args.get(1).map(String::as_str) == Some("--drag") {
        let coordinates: Vec<u32> = args.iter().skip(2).filter_map(|a| a.parse().ok()).collect();
        if let [x1, y1, x2, y2] = coordinates.as_slice() {
            return match pointer::drag(*x1, *y1, *x2, *y2) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(error) => {
                    let _ = writeln!(io::stderr(), "drag: {error}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
    }
    if let (Some("--tray"), Some(log)) = (args.get(1).map(String::as_str), args.get(2)) {
        return match tray::serve(log) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr(), "tray: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    if let (Some("--click"), Some(x), Some(y)) = (
        args.get(1).map(String::as_str),
        args.get(2).and_then(|x| x.parse().ok()),
        args.get(3).and_then(|y| y.parse().ok()),
    ) {
        let right = args.get(4).is_some_and(|b| b == "right");
        return match pointer::click(x, y, right) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr(), "click: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    if let (Some("--hand-off"), Some(socket)) = (args.get(1).map(String::as_str), args.get(2)) {
        return local_auth::hand_off(socket);
    }
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
