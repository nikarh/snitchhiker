//! The command line (`snitchhiker`): a client of the running daemon over its admin socket (root only, so `sudo`).

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::Path;

use snitchhiker_client::{ADMIN_SOCKET, Client};
use snitchhiker_core::rule::Action;
use snitchhiker_core::spec::{Conditions, RuleSpec};
use snitchhiker_proto::{convert, v1};

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
  rules import <file>             Add the rules of a rule file (TOML), in a folder
  rules export                    Print the stored rules as a rule file
  events [--limit <n>]            The newest connections
  learn [--hours <n>] [--folder <name>]
                                  Rules for the connections no rule decided in the last n hours (default 24), as a
                                  rule file to review and import
  prompts                         The connections waiting for an answer
  prompts watch                   Print prompts as they open and close (until interrupted)
  prompts answer <id> <allow|deny|reject> [--suggestion <n>] [--duration <once|restart|hour|12h|forever>]
                                  Answer a prompt: the rule is made from suggestion n (0, the narrowest, by default)
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
            reject_rest(args)?;
            let mut client = connect(version)?;
            match client.call(Method::ListEvents(v1::ListEvents { before: 0, limit }))? {
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

fn print_file(result: v1::response::Result) -> Result<(), Error> {
    match result {
        v1::response::Result::RuleFile(file) => out(&file.toml),
        _ => Err(unexpected()),
    }
}

/// `snitchhiker rules ...`.
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
        Some(which @ ("enable" | "disable")) => {
            let id: u64 = args.free_from_str()?;
            reject_rest(args)?;
            client.call(Method::SetRuleEnabled(v1::SetRuleEnabled {
                id,
                enabled: which == "enable",
            }))?;
            out(&format!("{which}d rule {id}\n"))
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
         decided          {}\ndropped events   {}\npending prompts  {}\nclients          {}\n",
        status.daemon_version,
        status.mode(),
        status.no_match(),
        status.fail_open,
        status.rules,
        status.decided,
        status.dropped_events,
        status.pending_prompts,
        status.clients,
    )
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
            "{:>5}  {:<7} {:<8} {}{}{}  {}",
            if rule.locked {
                "-".to_owned()
            } else {
                rule.id.to_string()
            },
            format!("{:?}", rule.action()).to_lowercase(),
            format!("{:?}", rule.tier()).to_lowercase(),
            if rule.enabled { "" } else { "(disabled) " },
            if rule.locked { "(locked) " } else { "" },
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
