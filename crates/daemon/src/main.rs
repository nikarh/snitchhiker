//! `snitchhikerd`, the root daemon, and `snitchhiker`, its command line, are one binary. Which one runs is decided by
//! the name it was started as (a `snitchhiker` symlink to `snitchhikerd` is the command line), or explicitly with
//! `snitchhikerd cli ...`.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::ExitCode;

/// The version, with the suffix of development builds (`0.1.0-dev+abc1234`).
const VERSION: &str = env!("SNITCHHIKER_VERSION");

const DAEMON_HELP: &str = "\
snitchhikerd: Snitchhiker's interactive application firewall daemon

Usage: snitchhikerd [options]
       snitchhikerd cli <command> [options]   (the same as `snitchhiker <command>`)

Options:
  -h, --help       Print this help
  -V, --version    Print the version
";

const CLI_HELP: &str = "\
snitchhiker: command line of the Snitchhiker application firewall

Usage: snitchhiker <command> [options]

Commands:
  version          Print the version

Options:
  -h, --help       Print this help
  -V, --version    Print the version
";

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Args(#[from] pico_args::Error),
    #[error("unknown command `{0}`; see --help")]
    UnknownCommand(String),
    #[error("unexpected arguments: {0:?}")]
    UnexpectedArguments(Vec<OsString>),
    #[error("the daemon is not implemented yet")]
    NotImplemented,
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

fn finish(args: pico_args::Arguments) -> Result<(), Error> {
    let rest = args.finish();
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Error::UnexpectedArguments(rest))
    }
}

fn run_cli(mut args: pico_args::Arguments) -> Result<(), Error> {
    if args.contains(["-h", "--help"]) {
        return out(CLI_HELP);
    }
    if args.contains(["-V", "--version"]) {
        return out(&format!("snitchhiker {VERSION}\n"));
    }
    match args.subcommand()?.as_deref() {
        Some("version") => {
            finish(args)?;
            out(&format!("snitchhiker {VERSION}\n"))
        }
        None => out(CLI_HELP),
        Some(other) => Err(Error::UnknownCommand(other.to_owned())),
    }
}

fn run_daemon(mut args: pico_args::Arguments) -> Result<(), Error> {
    if args.contains(["-h", "--help"]) {
        return out(DAEMON_HELP);
    }
    if args.contains(["-V", "--version"]) {
        return out(&format!("snitchhikerd {VERSION}\n"));
    }
    if let Some(command) = args.subcommand()? {
        return match command.as_str() {
            "cli" => run_cli(args),
            other => Err(Error::UnknownCommand(other.to_owned())),
        };
    }
    finish(args)?;
    Err(Error::NotImplemented)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
        Personality::Cli => run_cli(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
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
