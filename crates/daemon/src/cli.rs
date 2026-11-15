//! The command line (`snitchhiker`): a client of the running daemon over its admin socket (root only, so `sudo`).

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::Path;

use snitchhiker_client::{ADMIN_SOCKET, Client};
use snitchhiker_core::rule::Action;
use snitchhiker_core::spec::{Conditions, RuleSpec};
use snitchhiker_proto::{convert, v1};

/// `snitchhikerd --help`.
pub const DAEMON_HELP: &str = "\
snitchhikerd: Snitchhiker's interactive application firewall daemon

Usage: snitchhikerd [--config <path>]
       snitchhikerd [--config <path>] trust-client <path>
       snitchhikerd [--config <path>] untrust-client <path>
       snitchhikerd [--config <path>] trusted-clients
       snitchhikerd cli <command> [options]   (the same as `snitchhiker <command>`)

Commands:
  trust-client <path>    Trust a client binary on the client socket, pinned to its SHA-256 (again after an
                         upgrade). It must be root's, in directories only root can write, and setgid to the
                         client group. Applies to the next connection; the daemon needn't run.
  untrust-client <path>  Stop trusting it
  trusted-clients        List the trusted client binaries

Options:
  --config <path>  Configuration file (default /etc/snitchhiker/daemon.toml)
  -h, --help       Print this help
  -V, --version    Print the version

Signals: SIGHUP reloads the rules; SIGTERM and SIGINT stop the daemon.
";

pub const HELP: &str = "\
snitchhiker: command line of the Snitchhiker application firewall (run as root)

Usage: snitchhiker <command> [options]

Commands:
  status                          The daemon's mode, policy and counters
  rules                           List the folders and rules
  rules add <allow|deny|reject> [conditions] [--name <n>] [--tier <override|normal|fallback>]
                                  Add a rule. Conditions (all must hold; repeat for alternatives):
                                    --exe <path>      the executable (glob: --exe 'glob:/usr/bin/*')
                                    --host <name>     a host name or *.domain
                                    --net <cidr>      an address, a range, or an alias (lan, loopback, imds, ...)
                                    --port <n[-m]>    a port or range
                                    --uid <n>         a user id
                                    --protocol <tcp|udp|n>
                                    --any-context     also for containers, VMs and other namespaces
  rules rm <id>                   Delete a rule
  rules enable <id>, rules disable <id>
  rules move <id> <folder>        Move a rule to a folder (0: the top level)
  rules edit <id,id,...> <enable|disable|delete|move <folder>|action <a>|expires <d>>
                                  Change many rules in one batch (one undo); expires: hour, half-day,
                                  until-restart or never
  rules lint [--days <n>]         Duplicate, redundant and shadowed rules, expired ones, ones on missing or
                                  user-writable binaries, and with --days, ones that decided nothing in n days
  rules import <file>             Add the rules of a rule file (TOML), in a folder
  rules export                    Print the stored rules as a rule file
  rules import-opensnitch [<dir>] [--dry-run]
                                  Import OpenSnitch's rules (default /etc/opensnitchd/rules) into a folder
                                  OpenSnitch, listing those that can't be expressed exactly; --dry-run prints the
                                  rule file instead
  policy                          The policy in effect, and which settings clients changed
  policy set <setting>=<value>... Change settings while the daemon runs (they take precedence over daemon.toml):
                                    mode=enforce|monitor  no_match=ask|allow|deny|reject
                                    no_client=allow|deny|reject  on_timeout=allow|deny|reject
                                    prompt_timeout_secs=<5-3600>  retention_days=<1-3650>
  policy reset [<setting>...]     Return settings (all by default) to daemon.toml's
  system                          The system firewall: whether it is on, its policies and rules
  system on, system off           Turn it on or off
  system input <accept|drop>, system forward <accept|drop>
                                  The policy for packets to this machine, or routed through it
  system export                   Print it as TOML
  system import <file> [--trial <secs>]
                                  Replace it with a file's; with --trial, it reverts after that many seconds
                                  unless `system confirm` comes first
  system confirm                  Keep a change made with --trial
  system import-opensnitch [<file>] [--dry-run]
                                  Replace it with OpenSnitch's (default /etc/opensnitchd/system-fw.json), listing
                                  what can't be expressed exactly; --dry-run prints it as TOML instead
  alerts [--all]                  Alerts not acknowledged yet (--all: the newest 50 of every kind)
  alerts ack <id>... | --all      Acknowledge alerts
  alerts rules                    The alert rules
  alerts rules add <name> [--query <q>] [--threshold <n>] [--window <secs>] [--first-program]
                                  Raise an alert when n connections the query matches come within the window;
                                  --first-program counts only programs never seen before
  alerts rules rm <id>            Delete an alert rule
  folders                         List the folders
  folders add <name> [--parent <id>], folders rm <id>
                                  Add a folder; delete one with the folders and rules in it
  explore [--by <program|host|port|user>] [--hours <n>] [--where <dimension>=<value>]
                                  Connections of the last n hours (default 24), allowed and blocked, and their bytes,
                                  grouped by program (default), host, port or user, busiest first; --where narrows
                                  them to one program, host, port or user
  connections                     The live TCP connections and connected UDP sockets, with their programs
  kill <tcp|udp> <local address:port> <remote address:port>
                                  Close a live connection, as a reject does
  history [--limit <n>]           The changes to rules and folders, newest first, and who made them
  undo <change>                   Undo the changes of a change's batch (refused if changed again since)
  events [--limit <n>] [--query <q>]
                                  The newest connections; with a query, those it matches among the newest 100000
  explain <seq>                   Which rules match a recorded connection now, the deciding one first
  learn [--hours <n>] [--folder <name>]
                                  Rules for the connections no rule decided in the last n hours (default 24), as a
                                  rule file to review and import
  prompts                         The connections waiting for an answer
  prompts watch                   Print prompts as they open and close (until interrupted)
  prompts answer <id> <allow|deny|reject> [--suggestion <n>] [--duration <once|restart|hour|12h|forever>]
                [--folder <id>]   Answer a prompt: the rule is made from suggestion n (0, the narrowest, by default),
                                  in the program's folder (Apps/<program>) or the folder given
  proposals [--all]               Agents' proposals waiting for an answer (--all: the newest 50 of every state)
  proposals show <id>             A proposal: who made it, the agent's words, its rules, their marks and evidence
  proposals approve <id> [--duration <session|hour|12h|forever>] [--reason <text>]
                                  Make its rules (for the agent's session by default), in Agents/<agent>/<project>
  proposals deny <id> [--reason <text>]
                                  Deny it; the agent is told the reason
  mcp                             An MCP server on stdin and stdout, for coding agents (run as the user, by the
                                  agent: `claude mcp add snitchhiker -- snitchhiker mcp`)
  audit [--limit <n>]             The dangerous actions clients asked for (allow-everything rules), who asked,
                                  and whether step-up authorized them
  version                         Print the version

Options:
  -h, --help        Print this help
";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Args(#[from] pico_args::Error),
    #[error("{0}")]
    Usage(String),
    #[error("{0} (is the daemon running, and is this root?)")]
    Connect(snitchhiker_client::Error),
    #[error(transparent)]
    Client(#[from] snitchhiker_client::Error),
    #[error("writing to stdout: {0}")]
    Stdout(io::Error),
}

fn out(text: &str) -> Result<(), Error> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(Error::Stdout)
}

fn connect(version: &str) -> Result<Client, Error> {
    Client::connect(Path::new(ADMIN_SOCKET), "cli", version).map_err(Error::Connect)
}

fn reject_rest(args: pico_args::Arguments) -> Result<(), Error> {
    let rest = args.finish();
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Error::Usage(format!("unexpected arguments: {rest:?}")))
    }
}

fn unexpected() -> Error {
    Error::Usage("the daemon answered something unexpected".to_owned())
}

/// Runs a command; `version` is the binary's version string.
pub fn run(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    if args.contains(["-h", "--help"]) {
        return out(HELP);
    }
    match args.subcommand()?.as_deref() {
        None => out(HELP),
        Some("version") => out(&format!("snitchhiker {version}\n")),
        Some("status") => {
            reject_rest(args)?;
            let mut client = connect(version)?;
            match client.call(Method::GetStatus(v1::GetStatus {}))? {
                v1::response::Result::Status(status) => out(&format_status(&status)),
                _ => Err(unexpected()),
            }
        }
        Some("rules") => rules(args, version),
        Some("policy") => policy(args, version),
        Some("system") => system(args, version),
        Some("proposals") => proposals(args, version),
        Some("mcp") => {
            reject_rest(args)?;
            crate::mcp::serve(version).map_err(Error::Stdout)
        }
        Some("alerts") => alerts(args, version),
        Some("folders") => folders(args, version),
        Some("explore") => explore(args, version),
        Some("history") => history(args, version),
        Some("connections") => connections(args, version),
        Some("kill") => kill_connection(args, version),
        Some("explain") => {
            let seq: i64 = args.free_from_str()?;
            reject_rest(args)?;
            match connect(version)?.call(Method::Explain(v1::Explain { seq }))? {
                v1::response::Result::Explanation(explanation) => {
                    out(&format_explanation(&explanation))
                }
                _ => Err(unexpected()),
            }
        }
        Some("undo") => {
            let change: u64 = args.free_from_str()?;
            reject_rest(args)?;
            connect(version)?.call(Method::Undo(v1::Undo { change }))?;
            out(&format!("undid the changes of change {change}'s batch\n"))
        }
        Some("audit") => {
            let limit: u32 = args.opt_value_from_str("--limit")?.unwrap_or(50);
            reject_rest(args)?;
            let mut client = connect(version)?;
            match client.call(Method::ListAudit(v1::ListAudit { before: 0, limit }))? {
                v1::response::Result::Audit(page) => out(&format_audit(&page.entries)),
                _ => Err(unexpected()),
            }
        }
        Some("events") => {
            let limit: u32 = args.opt_value_from_str("--limit")?.unwrap_or(50);
            let query: String = args.opt_value_from_str("--query")?.unwrap_or_default();
            reject_rest(args)?;
            let mut client = connect(version)?;
            match client.call(Method::ListEvents(v1::ListEvents {
                before: 0,
                limit,
                columnar: false,
                query,
            }))? {
                v1::response::Result::Events(page) => out(&format_events(&page.events)),
                _ => Err(unexpected()),
            }
        }
        Some("learn") => {
            let hours: u32 = args.opt_value_from_str("--hours")?.unwrap_or(24);
            let folder: String = args
                .opt_value_from_str("--folder")?
                .unwrap_or_else(|| "Learned".to_owned());
            reject_rest(args)?;
            let mut client = connect(version)?;
            print_file(client.call(Method::Learn(v1::Learn { hours, folder }))?)
        }
        Some("prompts") => prompts(args, version),
        Some(other) => Err(Error::Usage(format!(
            "unknown command `{other}`; see --help"
        ))),
    }
}

fn format_lint(report: &v1::LintReport) -> String {
    let mut text = String::new();
    for finding in &report.findings {
        let _ = writeln!(
            text,
            "rule {}: {}{}",
            finding.rule,
            finding.description,
            if finding.suggestion.is_empty() {
                String::new()
            } else {
                format!(" (the program now matches {})", finding.suggestion)
            }
        );
    }
    if report.findings.is_empty() {
        text.push_str("nothing to report\n");
    }
    text
}

/// The rules and the change of `rules edit`.
fn rules_edit(args: &mut pico_args::Arguments) -> Result<v1::EditRules, Error> {
    use v1::edit_rules::Edit;
    let ids: String = args.free_from_str()?;
    let ids = ids
        .split(',')
        .map(|id| {
            id.trim()
                .parse()
                .map_err(|_| Error::Usage(format!("`{id}` isn't a rule id")))
        })
        .collect::<Result<Vec<u64>, _>>()?;
    let what: String = args.free_from_str()?;
    let edit = match what.as_str() {
        "enable" => Edit::Enabled(true),
        "disable" => Edit::Enabled(false),
        "delete" => Edit::Delete(true),
        "move" => {
            let folder: u64 = args.free_from_str()?;
            Edit::Move(v1::MoveRules {
                folder: (folder != 0).then_some(folder),
            })
        }
        "action" => {
            let action: String = args.free_from_str()?;
            Edit::Action(
                match action.as_str() {
                    "allow" => v1::Action::Allow,
                    "deny" => v1::Action::Deny,
                    "reject" => v1::Action::Reject,
                    other => return Err(Error::Usage(format!("unknown action `{other}`"))),
                }
                .into(),
            )
        }
        "expires" => {
            let when: String = args.free_from_str()?;
            Edit::Expires(
                match when.as_str() {
                    "hour" => v1::Duration::Hour,
                    "half-day" => v1::Duration::HalfDay,
                    "until-restart" => v1::Duration::UntilRestart,
                    "never" => v1::Duration::Forever,
                    other => return Err(Error::Usage(format!("unknown expiry `{other}`"))),
                }
                .into(),
            )
        }
        other => return Err(Error::Usage(format!("unknown edit `{other}`"))),
    };
    Ok(v1::EditRules {
        ids,
        edit: Some(edit),
    })
}

/// `alerts` and its subcommands.
fn alerts(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let all = args.contains("--all");
    let command = args.subcommand()?;
    let mut client = connect(version)?;
    let print_rules = |result| match result {
        v1::response::Result::AlertRules(list) => {
            let mut text = String::new();
            for rule in &list.rules {
                let _ = writeln!(
                    text,
                    "{:>4} {} {:?}: {} in {} s{}{}",
                    rule.id,
                    if rule.enabled { "on " } else { "off" },
                    rule.name,
                    rule.threshold,
                    rule.window_secs,
                    if rule.query.is_empty() {
                        String::new()
                    } else {
                        format!(" matching `{}`", rule.query)
                    },
                    if rule.first_program {
                        ", programs never seen before"
                    } else {
                        ""
                    },
                );
            }
            out(&text)
        }
        _ => Err(unexpected()),
    };
    match command.as_deref() {
        None | Some("list") => {
            reject_rest(args)?;
            match client.call(Method::ListAlerts(v1::ListAlerts {
                before: 0,
                limit: 50,
                open_only: !all,
            }))? {
                v1::response::Result::Alerts(page) => {
                    let mut text = String::new();
                    for alert in &page.alerts {
                        let _ = writeln!(
                            text,
                            "{:>6} {} {}{}: {}",
                            alert.id,
                            alert.kind,
                            alert.title,
                            if alert.acknowledged {
                                format!(" (acknowledged by {})", alert.acknowledged_by)
                            } else {
                                String::new()
                            },
                            alert.body,
                        );
                    }
                    let _ = writeln!(text, "{} not acknowledged", page.open);
                    out(&text)
                }
                _ => Err(unexpected()),
            }
        }
        Some("ack") => {
            let ids: Vec<u64> = args
                .finish()
                .iter()
                .map(|a| {
                    a.to_string_lossy().parse().map_err(|_| {
                        Error::Usage(format!("`{}` isn't an alert id", a.to_string_lossy()))
                    })
                })
                .collect::<Result<_, _>>()?;
            if ids.is_empty() && !all {
                return Err(Error::Usage("alerts ack <id>... | --all".to_owned()));
            }
            client.call(Method::AcknowledgeAlerts(v1::AcknowledgeAlerts {
                ids,
                all,
            }))?;
            out("acknowledged\n")
        }
        Some("rules") => alert_rules(args, &mut client, print_rules),
        Some(other) => Err(Error::Usage(format!("unknown command `alerts {other}`"))),
    }
}

/// `alerts rules` and its subcommands.
fn alert_rules(
    mut args: pico_args::Arguments,
    client: &mut Client,
    print_rules: impl Fn(v1::response::Result) -> Result<(), Error>,
) -> Result<(), Error> {
    use v1::request::Method;
    match args.subcommand()?.as_deref() {
        None => {
            reject_rest(args)?;
            print_rules(client.call(Method::ListAlertRules(v1::ListAlertRules {}))?)
        }
        Some("add") => {
            let query: String = args.opt_value_from_str("--query")?.unwrap_or_default();
            let threshold: u32 = args.opt_value_from_str("--threshold")?.unwrap_or(1);
            let window_secs: u32 = args.opt_value_from_str("--window")?.unwrap_or(0);
            let first_program = args.contains("--first-program");
            let name: String = args.free_from_str()?;
            reject_rest(args)?;
            print_rules(client.call(Method::PutAlertRule(v1::PutAlertRule {
                rule: Some(v1::AlertRule {
                    id: 0,
                    name,
                    enabled: true,
                    query,
                    threshold,
                    window_secs,
                    first_program,
                }),
            }))?)
        }
        Some("rm") => {
            let id: u64 = args.free_from_str()?;
            reject_rest(args)?;
            print_rules(client.call(Method::DeleteAlertRule(v1::DeleteAlertRule { id }))?)
        }
        Some(other) => Err(Error::Usage(format!(
            "unknown command `alerts rules {other}`"
        ))),
    }
}

/// `system` and its subcommands.
fn system(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let command = args.subcommand()?;
    let mut client = connect(version)?;
    let current = |client: &mut Client| -> Result<v1::SystemFirewall, Error> {
        match client.call(Method::GetSystemFirewall(v1::GetSystemFirewall {}))? {
            v1::response::Result::SystemFirewall(firewall) => Ok(firewall),
            _ => Err(unexpected()),
        }
    };
    let set = |client: &mut Client, firewall, revert_after_secs| -> Result<(), Error> {
        match client.call(Method::SetSystemFirewall(v1::SetSystemFirewall {
            firewall: Some(firewall),
            revert_after_secs,
        }))? {
            v1::response::Result::SystemFirewall(firewall) => out(&format_system(&firewall)),
            _ => Err(unexpected()),
        }
    };
    match command.as_deref() {
        None | Some("show") => {
            reject_rest(args)?;
            out(&format_system(&current(&mut client)?))
        }
        Some(which @ ("on" | "off")) => {
            reject_rest(args)?;
            let firewall = v1::SystemFirewall {
                enabled: which == "on",
                ..current(&mut client)?
            };
            set(&mut client, firewall, 0)
        }
        Some(chain @ ("input" | "forward")) => {
            let policy: String = args.free_from_str()?;
            reject_rest(args)?;
            let policy = match policy.as_str() {
                "accept" => v1::ChainPolicy::Accept,
                "drop" => v1::ChainPolicy::Drop,
                other => return Err(Error::Usage(format!("unknown policy `{other}`"))),
            };
            let mut firewall = current(&mut client)?;
            if chain == "input" {
                firewall.input = policy.into();
            } else {
                firewall.forward = policy.into();
            }
            set(&mut client, firewall, 0)
        }
        Some("export") => {
            reject_rest(args)?;
            let firewall =
                crate::system::from_wire(&current(&mut client)?).map_err(Error::Usage)?;
            out(&toml::to_string(&firewall).map_err(|e| Error::Usage(e.to_string()))?)
        }
        Some("import") => {
            let trial: u32 = args.opt_value_from_str("--trial")?.unwrap_or(0);
            let path: std::path::PathBuf = args.free_from_str()?;
            reject_rest(args)?;
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Usage(format!("{}: {e}", path.display())))?;
            let firewall: snitchhiker_core::system::Firewall = toml::from_str(&text)
                .map_err(|e| Error::Usage(format!("{}: {e}", path.display())))?;
            set(&mut client, crate::system::wire(&firewall, 0), trial)
        }
        Some("confirm") => {
            reject_rest(args)?;
            client.call(Method::ConfirmSystemFirewall(v1::ConfirmSystemFirewall {}))?;
            out("kept\n")
        }
        Some("import-opensnitch") => system_import_opensnitch(args, &mut client, set),
        Some(other) => Err(Error::Usage(format!("unknown command `system {other}`"))),
    }
}

/// `system import-opensnitch`.
fn system_import_opensnitch(
    mut args: pico_args::Arguments,
    client: &mut Client,
    set: impl Fn(&mut Client, v1::SystemFirewall, u32) -> Result<(), Error>,
) -> Result<(), Error> {
    let dry_run = args.contains("--dry-run");
    let path: String = args
        .opt_free_from_str()?
        .unwrap_or_else(|| "/etc/opensnitchd/system-fw.json".to_owned());
    reject_rest(args)?;
    let text = std::fs::read_to_string(&path).map_err(|e| Error::Usage(format!("{path}: {e}")))?;
    let imported = snitchhiker_core::system::import_opensnitch(&text);
    let mut report = String::new();
    for (name, reason) in &imported.skipped {
        let _ = writeln!(report, "skipped {name}: {reason}");
    }
    for note in &imported.notes {
        let _ = writeln!(report, "note: {note}");
    }
    let Some(firewall) = imported.firewall else {
        return Err(Error::Usage(format!("nothing to import:\n{report}")));
    };
    if dry_run {
        let toml = toml::to_string(&firewall).map_err(|e| Error::Usage(e.to_string()))?;
        let comments = report.lines().fold(String::new(), |mut text, line| {
            let _ = writeln!(text, "# {line}");
            text
        });
        return out(&format!("{toml}{comments}"));
    }
    let rules = firewall.rules.len();
    set(client, crate::system::wire(&firewall, 0), 0)?;
    let _ = writeln!(
        report,
        "imported {rules} rules of OpenSnitch's system firewall"
    );
    out(&report)
}

fn format_system(firewall: &v1::SystemFirewall) -> String {
    let policy = |p: v1::ChainPolicy| {
        p.as_str_name()
            .trim_start_matches("CHAIN_POLICY_")
            .to_lowercase()
    };
    let mut text = format!(
        "system firewall {}, input {}, forward {}\n",
        if firewall.enabled { "on" } else { "off" },
        policy(firewall.input()),
        policy(firewall.forward()),
    );
    if firewall.reverts_at_ms != 0 {
        let _ = writeln!(
            text,
            "a change reverts in {} s unless confirmed (snitchhiker system confirm)",
            firewall
                .reverts_at_ms
                .saturating_sub(crate::runtime::now_ms())
                / 1000
        );
    }
    for (i, rule) in firewall.rules.iter().enumerate() {
        let mut parts = vec![
            rule.chain()
                .as_str_name()
                .trim_start_matches("SYSTEM_CHAIN_")
                .to_lowercase(),
        ];
        for (key, value) in [
            ("proto", rule.protocol.clone()),
            ("from", rule.source.join(",")),
            ("to", rule.destination.join(",")),
            ("sport", rule.source_ports.clone()),
            ("dport", rule.destination_ports.clone()),
            ("in", rule.in_interface.clone()),
            ("out", rule.out_interface.clone()),
            ("ct", rule.ct_state.join(",")),
            ("icmp", rule.icmp_types.join(",")),
        ] {
            if !value.is_empty() {
                parts.push(format!("{key} {value}"));
            }
        }
        let _ = writeln!(
            text,
            "{:>3} {} {:<7} {}  {}",
            i + 1,
            if rule.enabled { "on " } else { "off" },
            rule.target()
                .as_str_name()
                .trim_start_matches("SYSTEM_TARGET_")
                .to_lowercase(),
            parts.join(" "),
            rule.description,
        );
    }
    text
}

/// `policy`, `policy set`, `policy reset`.
fn policy(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let command = args.subcommand()?;
    let rest: Vec<String> = args
        .finish()
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let method = match command.as_deref() {
        None | Some("show") if rest.is_empty() => Method::GetPolicy(v1::GetPolicy {}),
        Some("set") if !rest.is_empty() => Method::SetPolicy(policy_set(&rest)?),
        Some("reset") => Method::SetPolicy(v1::SetPolicy {
            reset: if rest.is_empty() {
                crate::policy::SETTINGS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect()
            } else {
                rest
            },
            ..v1::SetPolicy::default()
        }),
        _ => {
            return Err(Error::Usage(
                "policy [show | set <setting>=<value>... | reset [<setting>...]]".to_owned(),
            ));
        }
    };
    match connect(version)?.call(method)? {
        v1::response::Result::Policy(policy) => out(&format_policy(&policy)),
        _ => Err(unexpected()),
    }
}

fn policy_set(pairs: &[String]) -> Result<v1::SetPolicy, Error> {
    let action = |value: &str| match value {
        "allow" => Ok(v1::Action::Allow.into()),
        "deny" => Ok(v1::Action::Deny.into()),
        "reject" => Ok(v1::Action::Reject.into()),
        other => Err(Error::Usage(format!("unknown action `{other}`"))),
    };
    let number = |value: &str| {
        value
            .parse::<u32>()
            .map_err(|_| Error::Usage(format!("`{value}` isn't a number")))
    };
    let mut set = v1::SetPolicy::default();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| Error::Usage(format!("`{pair}`: expected <setting>=<value>")))?;
        match key {
            "mode" => {
                set.mode = Some(match value {
                    "enforce" => v1::Mode::Enforce.into(),
                    "monitor" => v1::Mode::Monitor.into(),
                    other => return Err(Error::Usage(format!("unknown mode `{other}`"))),
                });
            }
            "no_match" => {
                set.no_match = Some(match value {
                    "ask" => v1::Policy::Ask.into(),
                    "allow" => v1::Policy::Allow.into(),
                    "deny" => v1::Policy::Deny.into(),
                    "reject" => v1::Policy::Reject.into(),
                    other => return Err(Error::Usage(format!("unknown policy `{other}`"))),
                });
            }
            "no_client" => set.no_client = Some(action(value)?),
            "on_timeout" => set.on_timeout = Some(action(value)?),
            "prompt_timeout_secs" => set.prompt_timeout_secs = Some(number(value)?),
            "retention_days" => set.retention_days = Some(number(value)?),
            other => return Err(Error::Usage(format!("unknown setting `{other}`"))),
        }
    }
    Ok(set)
}

fn format_policy(policy: &v1::NodePolicy) -> String {
    let name = |text: &str, prefix: &str| text.trim_start_matches(prefix).to_lowercase();
    let mark = |setting: &str| {
        if policy.changed.iter().any(|c| c == setting) {
            "  (changed by a client)"
        } else {
            ""
        }
    };
    let mut text = String::new();
    for (setting, value) in [
        ("mode", name(policy.mode().as_str_name(), "MODE_")),
        ("no_match", name(policy.no_match().as_str_name(), "POLICY_")),
        (
            "no_client",
            name(policy.no_client().as_str_name(), "ACTION_"),
        ),
        (
            "prompt_timeout_secs",
            policy.prompt_timeout_secs.to_string(),
        ),
        (
            "on_timeout",
            name(policy.on_timeout().as_str_name(), "ACTION_"),
        ),
        ("retention_days", policy.retention_days.to_string()),
    ] {
        let _ = writeln!(text, "{setting:<20} {value}{}", mark(setting));
    }
    text
}

fn print_file(result: v1::response::Result) -> Result<(), Error> {
    match result {
        v1::response::Result::RuleFile(file) => out(&file.toml),
        _ => Err(unexpected()),
    }
}

/// `snitchhiker rules ...`.
/// `explore`.
fn explore(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let by: String = args
        .opt_value_from_str("--by")?
        .unwrap_or_else(|| "program".to_owned());
    let hours: u64 = args.opt_value_from_str("--hours")?.unwrap_or(24);
    let filter: Option<String> = args.opt_value_from_str("--where")?;
    reject_rest(args)?;
    let dimension = |name: &str| match name {
        "program" => Ok(v1::Dimension::Program),
        "host" => Ok(v1::Dimension::Host),
        "port" => Ok(v1::Dimension::Port),
        "user" => Ok(v1::Dimension::User),
        other => Err(Error::Usage(format!(
            "unknown dimension `{other}` (program, host, port, user)"
        ))),
    };
    let filter = match filter {
        None => None,
        Some(text) => {
            let (name, value) = text
                .split_once('=')
                .ok_or_else(|| Error::Usage("--where <dimension>=<value>".to_owned()))?;
            Some(v1::ExploreFilter {
                dimension: dimension(name)?.into(),
                value: value.to_owned(),
            })
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mut client = connect(version)?;
    match client.call(Method::Explore(v1::Explore {
        from_ms: now.saturating_sub(hours * 3_600_000),
        to_ms: now,
        group_by: dimension(&by)?.into(),
        filter,
        limit: 50,
    }))? {
        v1::response::Result::Explored(page) => {
            let mut text = format!(
                "{:>9} {:>9} {:>11} {:>11}  {by}\n",
                "allowed", "blocked", "sent", "received"
            );
            for row in &page.rows {
                let _ = writeln!(
                    text,
                    "{:>9} {:>9} {:>11} {:>11}  {}",
                    row.allowed,
                    row.blocked,
                    row.bytes_out,
                    row.bytes_in,
                    if row.key.is_empty() {
                        "(no name)"
                    } else {
                        &row.key
                    }
                );
            }
            out(&text)
        }
        _ => Err(unexpected()),
    }
}

/// `history`.
fn history(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let limit: u32 = args.opt_value_from_str("--limit")?.unwrap_or(50);
    reject_rest(args)?;
    let mut client = connect(version)?;
    match client.call(Method::ListChanges(v1::ListChanges { before: 0, limit }))? {
        v1::response::Result::Changes(page) => {
            let mut text = String::new();
            for change in &page.changes {
                let _ = writeln!(
                    text,
                    "{:>6}  batch {:<5} {}  {:<8} {}",
                    change.id, change.batch, change.time_ms, change.app, change.what
                );
            }
            out(&text)
        }
        _ => Err(unexpected()),
    }
}

/// `connections`.
fn connections(args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    reject_rest(args)?;
    match connect(version)?.call(Method::ListConnections(v1::ListConnections {}))? {
        v1::response::Result::Connections(list) => {
            let mut text = String::new();
            for c in &list.connections {
                let address = |bytes: &[u8], port: u32| {
                    convert::address_from(bytes).map_or_else(String::new, |a| {
                        std::net::SocketAddr::new(a, u16::try_from(port).unwrap_or(0)).to_string()
                    })
                };
                let _ = writeln!(
                    text,
                    "{:<4} {:<11} {:<22} -> {:<22} uid {:<6} {}{}  out {} in {}",
                    if c.protocol == 6 { "tcp" } else { "udp" },
                    c.state,
                    address(&c.local, c.local_port),
                    address(&c.remote, c.remote_port),
                    c.uid,
                    if c.exe.is_empty() { "?" } else { &c.exe },
                    if c.host.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", c.host)
                    },
                    c.bytes_out,
                    c.bytes_in,
                );
            }
            out(&text)
        }
        _ => Err(unexpected()),
    }
}

/// `kill`.
fn kill_connection(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let protocol: String = args.free_from_str()?;
    let local: std::net::SocketAddr = args.free_from_str()?;
    let remote: std::net::SocketAddr = args.free_from_str()?;
    reject_rest(args)?;
    let protocol = match protocol.as_str() {
        "tcp" => 6,
        "udp" => 17,
        other => {
            return Err(Error::Usage(format!(
                "unknown protocol `{other}` (tcp, udp)"
            )));
        }
    };
    connect(version)?.call(Method::KillConnection(v1::KillConnection {
        protocol,
        local: convert::address(local.ip()),
        local_port: u32::from(local.port()),
        remote: convert::address(remote.ip()),
        remote_port: u32::from(remote.port()),
    }))?;
    out("closed\n")
}

/// `folders`: list, add, rename and delete folders.
fn folders(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let mut client = connect(version)?;
    match args.subcommand()?.as_deref() {
        None => {
            reject_rest(args)?;
            let v1::response::Result::Rules(list) =
                client.call(Method::ListRules(v1::ListRules {}))?
            else {
                return Err(unexpected());
            };
            let mut text = String::new();
            for folder in &list.folders {
                let count = list
                    .rules
                    .iter()
                    .filter(|r| r.folder == Some(folder.id))
                    .count();
                let _ = writeln!(
                    text,
                    "{:>5}  {}{}  ({count} rules){}{}",
                    if folder.locked {
                        "-".to_owned()
                    } else {
                        folder.id.to_string()
                    },
                    folder_path(&list, folder.parent),
                    folder.name,
                    if folder.enabled { "" } else { " (disabled)" },
                    if folder.locked { " (locked)" } else { "" },
                );
            }
            out(&text)
        }
        Some("add") => {
            let name: String = args.free_from_str()?;
            let parent: Option<u64> = args.opt_value_from_str("--parent")?;
            reject_rest(args)?;
            match client.call(Method::AddFolder(v1::AddFolder {
                folder: Some(v1::Folder {
                    name,
                    parent,
                    enabled: true,
                    ..v1::Folder::default()
                }),
            }))? {
                v1::response::Result::FolderAdded(added) => {
                    out(&format!("added folder {}\n", added.id))
                }
                _ => Err(unexpected()),
            }
        }
        Some("rm" | "delete") => {
            let id: u64 = args.free_from_str()?;
            reject_rest(args)?;
            client.call(Method::DeleteFolder(v1::DeleteFolder { id }))?;
            out(&format!(
                "deleted folder {id}, the folders in it and their rules\n"
            ))
        }
        Some(other) => Err(Error::Usage(format!("unknown folders command `{other}`"))),
    }
}

/// `rules import-opensnitch`: OpenSnitch's rule files in `dir`, converted and imported (or printed, `dry_run`).
fn import_opensnitch(dir: &str, dry_run: bool, version: &str) -> Result<(), Error> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| Error::Usage(format!("{dir}: {e}")))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Usage(format!("{}: {e}", path.display())))?;
            files.push((path.display().to_string(), text));
        }
    }
    files.sort();
    let imported = snitchhiker_core::opensnitch::import(&files, "OpenSnitch");
    let mut report = String::new();
    for (name, reason) in &imported.skipped {
        let _ = writeln!(report, "skipped {name}: {reason}");
    }
    let toml = toml::to_string(&imported.file)
        .map_err(|e| Error::Usage(format!("writing the rule file: {e}")))?;
    if dry_run {
        // The rule file, and what was skipped as comments: the output stays a valid rule file.
        let comments = report.lines().fold(String::new(), |mut text, line| {
            let _ = writeln!(text, "# {line}");
            text
        });
        return out(&format!("{toml}{comments}"));
    }
    let mut client = connect(version)?;
    if !imported.file.rule.is_empty() {
        client.call(v1::request::Method::ImportRules(v1::ImportRules {
            toml,
            folder: "OpenSnitch".to_owned(),
        }))?;
    }
    let _ = writeln!(
        report,
        "imported {} of {} rules into the folder OpenSnitch; they apply to the host only \
         (add context = \"any\" to a rule for containers too)",
        imported.file.rule.len(),
        imported.file.rule.len() + imported.skipped.len()
    );
    out(&report)
}

fn rules(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let command = args.subcommand()?;
    let mut client = connect(version)?;
    match command.as_deref() {
        None | Some("list" | "ls") => {
            reject_rest(args)?;
            match client.call(Method::ListRules(v1::ListRules {}))? {
                v1::response::Result::Rules(list) => out(&format_rules(&list)),
                _ => Err(unexpected()),
            }
        }
        Some("add") => {
            let spec = spec_from_args(&mut args)?;
            reject_rest(args)?;
            let rule = spec
                .to_rule(0, None)
                .map_err(|e| Error::Usage(e.to_string()))?;
            match client.call(Method::AddRule(v1::AddRule {
                rule: Some(convert::rule(&rule, false)),
            }))? {
                v1::response::Result::RuleAdded(added) => {
                    out(&format!("added rule {}\n", added.id))
                }
                _ => Err(unexpected()),
            }
        }
        Some("rm" | "delete") => {
            let id: u64 = args.free_from_str()?;
            reject_rest(args)?;
            client.call(Method::DeleteRule(v1::DeleteRule { id }))?;
            out(&format!("deleted rule {id}\n"))
        }
        Some("move") => {
            let id: u64 = args.free_from_str()?;
            let folder: u64 = args.free_from_str()?;
            reject_rest(args)?;
            let v1::response::Result::Rules(list) =
                client.call(Method::ListRules(v1::ListRules {}))?
            else {
                return Err(unexpected());
            };
            let mut rule = list
                .rules
                .into_iter()
                .find(|r| r.id == id)
                .ok_or_else(|| Error::Usage(format!("no rule {id}")))?;
            rule.folder = (folder != 0).then_some(folder);
            client.call(Method::UpdateRule(v1::UpdateRule { rule: Some(rule) }))?;
            out(&format!("moved rule {id}\n"))
        }
        Some("edit") => {
            let edit = rules_edit(&mut args)?;
            reject_rest(args)?;
            let count = edit.ids.len();
            client.call(Method::EditRules(edit))?;
            out(&format!("changed {count} rules\n"))
        }
        Some("lint") => {
            let unused_days: u32 = args.opt_value_from_str("--days")?.unwrap_or(0);
            reject_rest(args)?;
            match client.call(Method::LintRules(v1::LintRules { unused_days }))? {
                v1::response::Result::LintReport(report) => out(&format_lint(&report)),
                _ => Err(unexpected()),
            }
        }
        Some(which @ ("enable" | "disable")) => {
            let id: u64 = args.free_from_str()?;
            reject_rest(args)?;
            client.call(Method::SetRuleEnabled(v1::SetRuleEnabled {
                id,
                enabled: which == "enable",
            }))?;
            out(&format!("{which}d rule {id}\n"))
        }
        Some("import-opensnitch") => {
            let dry_run = args.contains("--dry-run");
            let dir: String = args
                .opt_free_from_str()?
                .unwrap_or_else(|| "/etc/opensnitchd/rules".to_owned());
            reject_rest(args)?;
            import_opensnitch(&dir, dry_run, version)
        }
        Some("import") => {
            let path: String = args.free_from_str()?;
            reject_rest(args)?;
            let toml =
                std::fs::read_to_string(&path).map_err(|e| Error::Usage(format!("{path}: {e}")))?;
            let folder = Path::new(&path).file_stem().map_or_else(
                || "Imported".to_owned(),
                |s| s.to_string_lossy().into_owned(),
            );
            client.call(Method::ImportRules(v1::ImportRules { toml, folder }))?;
            out(&format!("imported {path}\n"))
        }
        Some("export") => {
            reject_rest(args)?;
            print_file(client.call(Method::ExportRules(v1::ExportRules {}))?)
        }
        Some(other) => Err(Error::Usage(format!("unknown rules command `{other}`"))),
    }
}

/// `snitchhiker prompts ...`.
fn prompts(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let command = args.subcommand()?;
    let mut client = connect(version)?;
    match command.as_deref() {
        None | Some("list" | "ls") => {
            reject_rest(args)?;
            match client.call(Method::ListPrompts(v1::ListPrompts {}))? {
                v1::response::Result::Prompts(list) => {
                    out(&list.prompts.iter().map(format_prompt).collect::<String>())
                }
                _ => Err(unexpected()),
            }
        }
        Some("watch") => {
            reject_rest(args)?;
            client.subscribe(v1::Topic::Prompts)?;
            loop {
                match client.notice()?.body {
                    Some(v1::notice::Body::Prompt(prompt)) => out(&format_prompt(&prompt))?,
                    Some(v1::notice::Body::PromptResolved(resolved)) => {
                        out(&format_resolved(&resolved))?;
                    }
                    _ => {}
                }
            }
        }
        Some("answer") => {
            let id: u64 = args.free_from_str()?;
            let action = action(&args.free_from_str::<String>()?)?;
            let suggestion: u32 = args.opt_value_from_str("--suggestion")?.unwrap_or(0);
            let folder: Option<u64> = args.opt_value_from_str("--folder")?;
            let duration = match args
                .opt_value_from_str::<_, String>("--duration")?
                .as_deref()
            {
                None | Some("forever") => v1::Duration::Forever,
                Some("once") => v1::Duration::Once,
                Some("restart") => v1::Duration::UntilRestart,
                Some("hour") => v1::Duration::Hour,
                Some("12h") => v1::Duration::HalfDay,
                Some(other) => return Err(Error::Usage(format!("unknown duration `{other}`"))),
            };
            reject_rest(args)?;
            client.call(Method::AnswerPrompt(v1::AnswerPrompt {
                id,
                action: convert::action(action).into(),
                duration: duration.into(),
                suggestion,
                conditions: None,
                folder,
            }))?;
            out(&format!("answered prompt {id}\n"))
        }
        Some(other) => Err(Error::Usage(format!("unknown prompts command `{other}`"))),
    }
}

fn action(text: &str) -> Result<Action, Error> {
    match text {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "reject" => Ok(Action::Reject),
        other => Err(Error::Usage(format!("unknown action `{other}`"))),
    }
}

fn spec_from_args(args: &mut pico_args::Arguments) -> Result<RuleSpec, Error> {
    let action = action(&args.free_from_str::<String>()?)?;
    let name: Option<String> = args.opt_value_from_str("--name")?;
    let tier = match args.opt_value_from_str::<_, String>("--tier")?.as_deref() {
        None | Some("normal") => snitchhiker_core::rule::Tier::Normal,
        Some("override") => snitchhiker_core::rule::Tier::Override,
        Some("fallback") => snitchhiker_core::rule::Tier::Fallback,
        Some(other) => return Err(Error::Usage(format!("unknown tier `{other}`"))),
    };
    let conditions = Conditions {
        exe: args.values_from_str("--exe")?,
        host: args.values_from_str("--host")?,
        net: args.values_from_str("--net")?,
        port: args.values_from_str("--port")?,
        uid: args.values_from_str("--uid")?,
        protocol: args.values_from_str("--protocol")?,
        context: args
            .contains("--any-context")
            .then_some(snitchhiker_core::rule::ContextKind::Any),
        ..Conditions::default()
    };
    Ok(RuleSpec {
        name: name.unwrap_or_else(|| format!("{action:?}").to_lowercase()),
        action,
        tier,
        enabled: true,
        notes: String::new(),
        conditions,
    })
}

fn format_status(status: &v1::Status) -> String {
    format!(
        "version          {}\nmode             {:?}\nno match         {:?}\nfail open        {}\nrules            {}\n\
         decided          {}\ndropped events   {}\npending prompts  {}\nclients          {}\nopen alerts      {}\n",
        status.daemon_version,
        status.mode(),
        status.no_match(),
        status.fail_open,
        status.rules,
        status.decided,
        status.dropped_events,
        status.pending_prompts,
        status.clients,
        status.open_alerts,
    )
}

/// `Apps/curl/`: the folders a rule is in, from the top.
fn folder_path(list: &v1::RuleList, folder: Option<u64>) -> String {
    let mut names = Vec::new();
    let mut next = folder;
    for _ in 0..list.folders.len() {
        let Some(found) = next.and_then(|id| list.folders.iter().find(|f| f.id == id)) else {
            break;
        };
        names.push(found.name.as_str());
        next = found.parent;
    }
    names.reverse();
    names.iter().fold(String::new(), |mut path, name| {
        path.push_str(name);
        path.push('/');
        path
    })
}

fn format_rules(list: &v1::RuleList) -> String {
    let mut text = String::new();
    for rule in &list.rules {
        let spec = rule
            .conditions
            .as_ref()
            .map_or_else(Conditions::default, convert::conditions_from);
        let _ = writeln!(
            text,
            "{:>5}  {:<7} {:<8} {}{}{}{}  {}",
            if rule.locked {
                "-".to_owned()
            } else {
                rule.id.to_string()
            },
            format!("{:?}", rule.action()).to_lowercase(),
            format!("{:?}", rule.tier()).to_lowercase(),
            if rule.enabled { "" } else { "(disabled) " },
            if rule.locked { "(locked) " } else { "" },
            folder_path(list, rule.folder),
            rule.name,
            toml::to_string(&spec)
                .unwrap_or_default()
                .replace('\n', " "),
        );
    }
    text
}

fn format_audit(entries: &[v1::AuditEntry]) -> String {
    let mut text = String::new();
    for entry in entries {
        let _ = writeln!(
            text,
            "{:>6}  {}  {:<10} {} uid {} pid {}: {}",
            entry.id,
            entry.time_ms,
            format!("{:?}", entry.outcome()).to_lowercase(),
            entry.app,
            entry.uid,
            entry.pid,
            entry.action,
        );
    }
    text
}

fn format_events(events: &[v1::ConnectionEvent]) -> String {
    let mut text = String::new();
    for event in events {
        let address =
            convert::address_from(&event.address).map_or_else(String::new, |a| a.to_string());
        let _ = writeln!(
            text,
            "{:>8}  {:<6} uid {:<6} {} -> {}:{} proto {} out {} in {}{}",
            event.seq,
            format!("{:?}", event.action()).to_lowercase(),
            event.uid,
            if event.exe.is_empty() {
                "?"
            } else {
                &event.exe
            },
            if event.host.is_empty() {
                &address
            } else {
                &event.host
            },
            event.port,
            event.protocol,
            event.bytes_out,
            event.bytes_in,
            event
                .rule
                .map_or_else(String::new, |r| format!(" (rule {r})")),
        );
    }
    text
}

fn format_explanation(explanation: &v1::Explanation) -> String {
    let mut text = format_events(explanation.event.as_slice());
    if explanation.rules.is_empty() {
        text.push_str("  no rule matches it now: it would be prompted for (or decided by the default action)\n");
    }
    for (i, rule) in explanation.rules.iter().enumerate() {
        let _ = writeln!(
            text,
            "  {} rule {} {:?}: {} ({:?}, specificity {})",
            if i == 0 { "decides" } else { "        " },
            rule.id,
            rule.name,
            format!("{:?}", rule.action()).to_lowercase(),
            rule.tier(),
            rule.specificity,
        );
    }
    if explanation.partial {
        text.push_str(
            "  rules on command lines or parent processes aren't checked: the history doesn't keep them\n",
        );
    }
    text
}

fn format_prompt(prompt: &v1::Prompt) -> String {
    let address =
        convert::address_from(&prompt.address).map_or_else(String::new, |a| a.to_string());
    let mut text = format!(
        "prompt {}: {} (uid {}{}) -> {}:{} proto {}, {} waiting{}\n",
        prompt.id,
        prompt.exe,
        prompt.uid,
        if prompt.user.is_empty() {
            String::new()
        } else {
            format!(" {}", prompt.user)
        },
        prompt.hosts.first().unwrap_or(&address),
        prompt.port,
        prompt.protocol,
        prompt.waiting,
        if prompt.exe_writable {
            " (its executable is writable by a user)"
        } else {
            ""
        },
    );
    for (index, suggestion) in prompt.suggestions.iter().enumerate() {
        let _ = writeln!(
            text,
            "  {index}: {}{}",
            suggestion.label,
            if suggestion.broad { " (broad)" } else { "" }
        );
    }
    text
}

fn format_resolved(resolved: &v1::PromptResolved) -> String {
    format!(
        "prompt {} resolved: {:?}{}\n",
        resolved.id,
        resolved.action(),
        if resolved.timed_out {
            " (timed out)".to_owned()
        } else {
            format!(" by {}", resolved.by)
        }
    )
}

fn proposals(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    use v1::request::Method;
    let command = args.subcommand()?;
    let mut client = connect(version)?;
    let get = |client: &mut Client, id: u64| -> Result<v1::Proposal, Error> {
        match client.call(Method::GetProposal(v1::GetProposal { id, wait_secs: 0 }))? {
            v1::response::Result::Proposal(proposal) => Ok(*proposal),
            _ => Err(unexpected()),
        }
    };
    match command.as_deref() {
        None | Some("--all") => {
            let all = command.is_some() || args.contains("--all");
            reject_rest(args)?;
            match client.call(Method::ListProposals(v1::ListProposals {
                pending_only: !all,
                limit: 50,
            }))? {
                v1::response::Result::Proposals(list) => {
                    let mut text = String::new();
                    for p in &list.proposals {
                        text.push_str(&format_proposal_line(p));
                    }
                    if list.proposals.is_empty() {
                        text.push_str(if all {
                            "no proposals\n"
                        } else {
                            "no proposals wait\n"
                        });
                    }
                    out(&text)
                }
                _ => Err(unexpected()),
            }
        }
        Some("show") => {
            let id: u64 = args.free_from_str()?;
            reject_rest(args)?;
            out(&format_proposal(&get(&mut client, id)?))
        }
        Some(verb @ ("approve" | "deny")) => {
            let id: u64 = args.free_from_str()?;
            let reason: String = args.opt_value_from_str("--reason")?.unwrap_or_default();
            let duration: Option<String> = args.opt_value_from_str("--duration")?;
            reject_rest(args)?;
            let duration = match duration.as_deref() {
                None | Some("session") => v1::ProposalDuration::Session,
                Some("hour") => v1::ProposalDuration::Hour,
                Some("12h") => v1::ProposalDuration::TwelveHours,
                Some("forever") => v1::ProposalDuration::Forever,
                Some(other) => return Err(Error::Usage(format!("unknown duration `{other}`"))),
            };
            match client.call(Method::DecideProposal(v1::DecideProposal {
                id,
                approve: verb == "approve",
                reason,
                duration: duration.into(),
                rules: Vec::new(),
            }))? {
                v1::response::Result::Proposal(proposal) => out(&format_proposal(&proposal)),
                _ => Err(unexpected()),
            }
        }
        Some(other) => Err(Error::Usage(format!("unknown proposals command `{other}`"))),
    }
}

fn proposal_state(state: v1::ProposalState) -> &'static str {
    match state {
        v1::ProposalState::Pending => "pending",
        v1::ProposalState::Approved => "approved",
        v1::ProposalState::Denied => "denied",
        v1::ProposalState::Withdrawn => "withdrawn",
        v1::ProposalState::Expired => "expired",
        v1::ProposalState::Unspecified => "?",
    }
}

fn format_proposal_line(p: &v1::Proposal) -> String {
    let provenance = p.provenance.clone().unwrap_or_default();
    format!(
        "proposal {}: {} {} rule(s){} from {} in {} (user {})\n",
        p.id,
        proposal_state(p.state()),
        p.rules.len(),
        if p.broad { ", marked" } else { "" },
        provenance.agent_exe,
        provenance.cwd,
        provenance.user,
    )
}

/// A proposal for people; the agent's words are quoted and marked as such.
fn format_proposal(p: &v1::Proposal) -> String {
    let provenance = p.provenance.clone().unwrap_or_default();
    let mut text = format_proposal_line(p);
    let _ = writeln!(
        text,
        "  agent: pid {} {} {}{}",
        provenance.agent_pid,
        provenance.agent_exe,
        provenance.agent_cmdline,
        if provenance.known_agent {
            " (a known agent)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        text,
        "  MCP server: pid {} {}",
        provenance.server_pid, provenance.server_exe
    );
    let _ = writeln!(text, "  the agent says (unverified):");
    for line in p.justification.lines() {
        let _ = writeln!(
            text,
            "  | {}",
            line.chars().filter(|c| !c.is_control()).collect::<String>()
        );
    }
    for (index, rule) in p.rules.iter().enumerate() {
        let conditions = convert::conditions_from(
            rule.conditions
                .as_ref()
                .unwrap_or(&v1::Conditions::default()),
        );
        let _ = writeln!(
            text,
            "  {}. {}{}",
            index + 1,
            toml::to_string(&conditions)
                .unwrap_or_default()
                .trim()
                .replace('\n', " "),
            if rule.already_allowed {
                "  (already allowed)"
            } else if rule.included {
                "  (made)"
            } else {
                ""
            }
        );
        for risk in &rule.risks {
            let _ = writeln!(text, "     marked: {}", risk.description);
        }
        for e in &rule.evidence {
            let _ = writeln!(
                text,
                "     refused: {} → {}:{} ×{}",
                e.exe,
                if e.host.is_empty() {
                    convert::address_from(&e.address).map_or_else(String::new, |a| a.to_string())
                } else {
                    e.host.clone()
                },
                e.port,
                e.count
            );
        }
    }
    if !p.reason.is_empty() {
        let _ = writeln!(text, "  reason: {}", p.reason);
    }
    if !p.folder.is_empty() {
        let _ = writeln!(text, "  rules {:?} in {}", p.rule_ids, p.folder);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> pico_args::Arguments {
        pico_args::Arguments::from_vec(list.iter().map(Into::into).collect())
    }

    #[test]
    fn builds_rules_from_flags() {
        let spec = spec_from_args(&mut args(&[
            "allow",
            "--exe",
            "glob:/usr/bin/*",
            "--host",
            "*.example.com",
            "--port",
            "443",
            "--port",
            "8000-8080",
            "--protocol",
            "tcp",
            "--name",
            "web",
        ]))
        .unwrap();
        assert_eq!(spec.action, Action::Allow);
        assert_eq!(spec.name, "web");
        let rule = spec.to_rule(0, None).unwrap();
        assert_eq!(rule.conditions.len(), 4);
    }

    #[test]
    fn rejects_unknown_actions() {
        assert!(spec_from_args(&mut args(&["maybe"])).is_err());
    }
}
