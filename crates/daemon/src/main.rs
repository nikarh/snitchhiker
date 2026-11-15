//! `snitchhikerd`, the root daemon, and `snitchhiker`, its command line, are one binary. Which one runs is decided by
//! the name it was started as (a `snitchhiker` symlink to `snitchhikerd` is the command line), or explicitly with
//! `snitchhikerd cli ...`.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nix::sys::signal::{SigSet, Signal};
use snitchhiker_daemon::cli;
use snitchhiker_daemon::config::{self, Config};
use snitchhiker_daemon::runtime::Daemon;
use tracing::{error, info};

/// The version, with the suffix of development builds (`0.1.0-dev+abc1234`).
const VERSION: &str = env!("SNITCHHIKER_VERSION");

const DAEMON_HELP: &str = "\
snitchhikerd: Snitchhiker's interactive application firewall daemon

Usage: snitchhikerd [--config <path>]
       snitchhikerd cli <command> [options]   (the same as `snitchhiker <command>`)

Options:
  --config <path>  Configuration file (default /etc/snitchhiker/daemon.toml)
  -h, --help       Print this help
  -V, --version    Print the version

Signals: SIGHUP reloads the rules; SIGTERM and SIGINT stop the daemon.
";

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Args(#[from] pico_args::Error),
    #[error(transparent)]
    Cli(#[from] cli::Error),
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Runtime(#[from] snitchhiker_daemon::runtime::Error),
    #[error("unknown command `{0}`; see --help")]
    UnknownCommand(String),
    #[error("signals: {0}")]
    Signals(#[from] nix::Error),
    #[error("writing to stdout: {0}")]
    Stdout(#[source] io::Error),
}

/// Which personality of the binary runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Personality {
    Daemon,
    Cli,
}

fn personality(argv0: Option<&OsString>) -> Personality {
    let name = argv0
        .and_then(|arg| Path::new(arg).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if name == "snitchhiker" {
        Personality::Cli
    } else {
        Personality::Daemon
    }
}

fn out(text: &str) -> Result<(), Error> {
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(Error::Stdout)
}

fn run_daemon(mut args: pico_args::Arguments) -> Result<(), Error> {
    if args.contains(["-h", "--help"]) {
        return out(DAEMON_HELP);
    }
    if args.contains(["-V", "--version"]) {
        return out(&format!("snitchhikerd {VERSION}\n"));
    }
    let config_path: Option<PathBuf> = args.opt_value_from_str("--config")?;
    if let Some(command) = args.subcommand()? {
        return match command.as_str() {
            "cli" => Ok(cli::run(args, VERSION)?),
            other => Err(Error::UnknownCommand(other.to_owned())),
        };
    }
    let config = Config::load(&config_path.unwrap_or_else(|| PathBuf::from(config::DEFAULT_PATH)))?;

    // Signals are taken synchronously in this thread; blocked before any thread starts, so none of them gets one.
    let mut signals = SigSet::empty();
    for signal in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        signals.add(signal);
    }
    signals.thread_block()?;

    info!(version = VERSION, "starting");
    let daemon = Daemon::start(config)?;
    write_pidfile();
    // SIGHUP reloads; SIGTERM or SIGINT end the loop.
    while signals.wait()? == Signal::SIGHUP {
        match daemon.reload_rules() {
            Ok(count) => info!(rules = count, "rules reloaded"),
            Err(error) => error!(%error, "reloading the rules; keeping the previous ones"),
        }
    }
    let _ = std::fs::remove_file(cli::PIDFILE);
    daemon.stop();
    Ok(())
}

fn write_pidfile() {
    let path = Path::new(cli::PIDFILE);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(error) = std::fs::write(path, format!("{}\n", std::process::id())) {
        error!(%error, "writing the pidfile; the command line can't ask for reloads");
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(io::stderr)
        .init();

    let mut raw: Vec<OsString> = std::env::args_os().collect();
    let argv0 = if raw.is_empty() {
        None
    } else {
        Some(raw.remove(0))
    };
    let args = pico_args::Arguments::from_vec(raw);
    let result = match personality(argv0.as_ref()) {
        Personality::Daemon => run_daemon(args),
        Personality::Cli => cli::run(args, VERSION).map_err(Error::from),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personality_follows_the_program_name() {
        let cli = OsString::from("/usr/bin/snitchhiker");
        let daemon = OsString::from("/usr/bin/snitchhikerd");
        assert_eq!(personality(Some(&cli)), Personality::Cli);
        assert_eq!(personality(Some(&daemon)), Personality::Daemon);
        assert_eq!(personality(None), Personality::Daemon);
    }

    #[test]
    fn version_has_the_package_version() {
        assert!(VERSION.starts_with(env!("CARGO_PKG_VERSION")));
    }
}
