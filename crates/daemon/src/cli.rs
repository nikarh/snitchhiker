//! The command line (`snitchhiker`). For now it works on the daemon's database directly, as root, and asks the
//! running daemon to reload; the authenticated protocol (M2) will take its place, with the same commands.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::Path;

use snitchhiker_core::destination::{HostPattern, Network};
use snitchhiker_core::pattern::PatternSource;
use snitchhiker_core::rule::{Action, Condition, ContextKind, Expiry, Rule, Tier};

use crate::config::Config;
use crate::store::Store;

/// Where the daemon writes its pid, for the CLI to ask it to reload.
pub const PIDFILE: &str = "/run/snitchhiker/snitchhikerd.pid";

pub const HELP: &str = "\
snitchhiker: command line of the Snitchhiker application firewall

Usage: snitchhiker [--config <path>] <command> [options]

Commands:
  rules                           List the rules
  rules add <allow|deny|reject> [conditions] [--name <n>] [--tier <override|normal|fallback>]
                                  Add a rule. Conditions (all must hold; repeat for alternatives):
                                    --exe <path>      the executable (glob: --exe 'glob:/usr/bin/*')
                                    --host <name>     a host name or *.domain
                                    --net <cidr>      an address, a range, or an alias (lan, loopback, imds, ...)
                                    --port <n[-m]>    a port or range
                                    --uid <n>         a user id
                                    --protocol <tcp|udp|n>
                                    --any-context     also for containers, VMs and other namespaces
  rules add --json <rule>         Add a rule given as JSON
  rules rm <id>                   Delete a rule
  events [--limit <n>]            The newest connections
  version                         Print the version

Options:
  --config <path>   The daemon's configuration (default /etc/snitchhiker/daemon.toml)
  -h, --help        Print this help
";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Args(#[from] pico_args::Error),
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Store(#[from] crate::store::Error),
    #[error(transparent)]
    Config(#[from] crate::config::Error),
    #[error("writing to stdout: {0}")]
    Stdout(io::Error),
}

fn out(text: &str) -> Result<(), Error> {
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(Error::Stdout)
}

/// Runs a command; `version` is the binary's version string.
pub fn run(mut args: pico_args::Arguments, version: &str) -> Result<(), Error> {
    if args.contains(["-h", "--help"]) {
        return out(HELP);
    }
    let config_path: Option<String> = args.opt_value_from_str("--config")?;
    let config_path = config_path.unwrap_or_else(|| crate::config::DEFAULT_PATH.to_owned());
    match args.subcommand()?.as_deref() {
        None => out(HELP),
        Some("version") => out(&format!("snitchhiker {version}\n")),
        Some("rules") => {
            let config = Config::load(Path::new(&config_path))?;
            let mut store = Store::open(&config.database)?;
            match args.subcommand()?.as_deref() {
                None | Some("list" | "ls") => {
                    let managed =
                        crate::managed::Managed::load(config.default_rules, &config.rules_dir)
                            .map_err(|e| Error::Usage(e.to_string()))?;
                    list_rules(&store, &managed)
                }
                Some("add") => {
                    let rule = rule_from_args(&mut args)?;
                    reject_rest(args)?;
                    let id = store.insert_rule(&rule, crate::runtime::now_ms())?;
                    reload();
                    out(&format!("added rule {id}\n"))
                }
                Some("rm" | "delete") => {
                    let id: u64 = args.free_from_str()?;
                    reject_rest(args)?;
                    if id & crate::managed::MANAGED_ID != 0 {
                        return Err(Error::Usage(format!(
                            "rule {id} is a default or managed rule: it is changed in its file (or switched off with \
                             default_rules = false)"
                        )));
                    }
                    if store.delete_rule(id)? {
                        reload();
                        out(&format!("deleted rule {id}\n"))
                    } else {
                        Err(Error::Usage(format!("no rule {id}")))
                    }
                }
                Some(other) => Err(Error::Usage(format!("unknown rules command `{other}`"))),
            }
        }
        Some("events") => {
            let limit: u32 = args.opt_value_from_str("--limit")?.unwrap_or(50);
            reject_rest(args)?;
            let config = Config::load(Path::new(&config_path))?;
            let store = Store::open(&config.database)?;
            list_events(&store, limit)
        }
        Some(other) => Err(Error::Usage(format!(
            "unknown command `{other}`; see --help"
        ))),
    }
}

fn reject_rest(args: pico_args::Arguments) -> Result<(), Error> {
    let rest = args.finish();
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Error::Usage(format!("unexpected arguments: {rest:?}")))
    }
}

/// Asks the running daemon to reload its rules (SIGHUP); nothing to do when none runs.
fn reload() {
    let Ok(pid) = std::fs::read_to_string(PIDFILE) else {
        return;
    };
    if let Ok(pid) = pid.trim().parse::<i32>() {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGHUP,
        );
    }
}

fn pattern(text: String) -> PatternSource {
    if let Some(glob) = text.strip_prefix("glob:") {
        PatternSource::Glob(glob.to_owned())
    } else if let Some(regex) = text.strip_prefix("re:") {
        PatternSource::Regex(regex.to_owned())
    } else {
        PatternSource::Exact(text)
    }
}

fn rule_from_args(args: &mut pico_args::Arguments) -> Result<Rule, Error> {
    if let Some(json) = args.opt_value_from_str::<_, String>("--json")? {
        return serde_json::from_str(&json).map_err(|e| Error::Usage(format!("--json: {e}")));
    }
    let action = match args.free_from_str::<String>()?.as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        "reject" => Action::Reject,
        other => return Err(Error::Usage(format!("unknown action `{other}`"))),
    };
    let name: Option<String> = args.opt_value_from_str("--name")?;
    let tier = match args.opt_value_from_str::<_, String>("--tier")?.as_deref() {
        None | Some("normal") => Tier::Normal,
        Some("override") => Tier::Override,
        Some("fallback") => Tier::Fallback,
        Some(other) => return Err(Error::Usage(format!("unknown tier `{other}`"))),
    };
    let mut conditions = Vec::new();
    let exes: Vec<String> = args.values_from_str("--exe")?;
    if !exes.is_empty() {
        conditions.push(Condition::Exe(exes.into_iter().map(pattern).collect()));
    }
    let hosts: Vec<String> = args.values_from_str("--host")?;
    if !hosts.is_empty() {
        let hosts = hosts
            .into_iter()
            .map(|h| HostPattern::try_from(h).map_err(|e| Error::Usage(e.to_string())))
            .collect::<Result<_, _>>()?;
        conditions.push(Condition::Host(hosts));
    }
    let nets: Vec<String> = args.values_from_str("--net")?;
    if !nets.is_empty() {
        let nets = nets
            .into_iter()
            .map(|n| Network::try_from(n).map_err(|e| Error::Usage(e.to_string())))
            .collect::<Result<_, _>>()?;
        conditions.push(Condition::Net(nets));
    }
    let ports: Vec<String> = args.values_from_str("--port")?;
    if !ports.is_empty() {
        let ranges = ports
            .iter()
            .map(|p| port_range(p).ok_or_else(|| Error::Usage(format!("invalid port `{p}`"))))
            .collect::<Result<_, _>>()?;
        conditions.push(Condition::Port(ranges));
    }
    let uids: Vec<u32> = args.values_from_str("--uid")?;
    if !uids.is_empty() {
        conditions.push(Condition::Uid(uids));
    }
    let protocols: Vec<String> = args.values_from_str("--protocol")?;
    if !protocols.is_empty() {
        let protocols = protocols
            .iter()
            .map(|p| match p.as_str() {
                "tcp" => Ok(6),
                "udp" => Ok(17),
                n => n
                    .parse()
                    .map_err(|_| Error::Usage(format!("invalid protocol `{n}`"))),
            })
            .collect::<Result<_, _>>()?;
        conditions.push(Condition::Protocol(protocols));
    }
    if args.contains("--any-context") {
        conditions.push(Condition::Context(ContextKind::Any));
    }
    let mut summary = String::new();
    let _ = write!(summary, "{action:?}");
    Ok(Rule {
        id: 0,
        folder: None,
        name: name.unwrap_or(summary),
        enabled: true,
        action,
        tier,
        expiry: Expiry::Never,
        log: true,
        notes: String::new(),
        conditions,
    })
}

fn port_range(text: &str) -> Option<(u16, u16)> {
    match text.split_once('-') {
        Some((low, high)) => {
            let (low, high) = (low.parse().ok()?, high.parse().ok()?);
            (low <= high).then_some((low, high))
        }
        None => text.parse().ok().map(|port| (port, port)),
    }
}

fn list_rules(store: &Store, managed: &crate::managed::Managed) -> Result<(), Error> {
    let mut text = String::new();
    for rule in store.rules()?.iter().chain(&managed.rules) {
        let _ = writeln!(
            text,
            "{:>5}  {:<7} {:<8} {}{}{}  {}",
            if rule.id & crate::managed::MANAGED_ID != 0 {
                "-".to_owned()
            } else {
                rule.id.to_string()
            },
            format!("{:?}", rule.action).to_lowercase(),
            format!("{:?}", rule.tier).to_lowercase(),
            if rule.enabled { "" } else { "(disabled) " },
            if rule.id & crate::managed::MANAGED_ID != 0 {
                "(locked) "
            } else {
                ""
            },
            rule.name,
            serde_json::to_string(&rule.conditions).unwrap_or_default(),
        );
    }
    out(&text)
}

fn list_events(store: &Store, limit: u32) -> Result<(), Error> {
    let mut text = String::new();
    for event in store.events(i64::MAX, limit)? {
        let _ = writeln!(
            text,
            "{:>8}  {:<6} uid {:<6} {} -> {}:{} proto {} out {} in {}{}",
            event.seq,
            format!("{:?}", event.action).to_lowercase(),
            event.uid,
            if event.exe.is_empty() {
                "?"
            } else {
                &event.exe
            },
            event.host.as_deref().unwrap_or(&event.address.to_string()),
            event.port,
            event.protocol,
            event.bytes_out,
            event.bytes_in,
            event
                .rule
                .map_or_else(String::new, |r| format!(" (rule {r})")),
        );
    }
    out(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> pico_args::Arguments {
        pico_args::Arguments::from_vec(list.iter().map(Into::into).collect())
    }

    #[test]
    fn builds_rules_from_flags() {
        let rule = rule_from_args(&mut args(&[
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
        assert_eq!(rule.action, Action::Allow);
        assert_eq!(rule.name, "web");
        assert_eq!(rule.conditions.len(), 4);
        assert_eq!(
            rule.conditions[2],
            Condition::Port(vec![(443, 443), (8000, 8080)])
        );
    }

    #[test]
    fn rejects_bad_ports_and_actions() {
        assert!(rule_from_args(&mut args(&["maybe"])).is_err());
        assert!(rule_from_args(&mut args(&["allow", "--port", "9-1"])).is_err());
    }
}
