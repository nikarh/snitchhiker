//! `snitchhiker-remote`: Snitchhiker's remote access, installed only where it is wanted (decision 0016).
//!
//! - On a node, as the `snitchhiker-remote` service: the iroh endpoint paired devices connect to, beside the daemon,
//!   as an unprivileged user of its own ([`node`]).
//! - For the desktop app: `snitchhiker-remote client`, which the app starts to reach remote nodes ([`helper`]).
//!
//! Without it, the daemon and the app work locally as ever, and neither carries the network stack.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use nix::sys::signal::{SigSet, Signal};

mod config;
mod helper;
mod node;

const VERSION: &str = env!("SNITCHHIKER_VERSION");

/// The name of the node's key as a systemd credential, once sealed (`snitchhiker-remote seal-key`).
pub const KEY_CREDENTIAL: &str = "snitchhiker.node-key";

const HELP: &str = "\
snitchhiker-remote: Snitchhiker's remote access, for paired phones and desktops

Usage: snitchhiker-remote [--config <path>]            The node's endpoint (the snitchhiker-remote service)
       snitchhiker-remote seal-key [--config <path>]   Seal the node's key to this machine (TPM, or the host key)
                                                       with systemd-creds, and delete the plaintext
       snitchhiker-remote client                       The desktop app's helper (the app starts it)

Options:
  --config <path>  Configuration file (default /etc/snitchhiker/remote.toml)
  -h, --help       Print this help
  -V, --version    Print the version
";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Args(#[from] pico_args::Error),
    #[error("the node's key: {0}")]
    Key(String),
    #[error("the daemon's remote socket: {0} (is snitchhikerd running?)")]
    Daemon(String),
    #[error("the endpoint: {0}")]
    Endpoint(String),
    #[error("the app's helper: {0}")]
    Helper(String),
    #[error("sealing the key: {0}")]
    Seal(String),
    #[error("signals: {0}")]
    Signals(#[from] nix::Error),
}

fn out(text: &str) {
    let _ = std::io::stdout().lock().write_all(text.as_bytes());
}

/// Seals the node's key with `systemd-creds` (to the TPM when the machine has one, else to the host's own key), into
/// systemd's credential store, and deletes the plaintext: from the next start, the service's `ImportCredential=`
/// gives the bridge the key, and the file is gone from the disk.
fn seal_key(config: &config::Config) -> Result<(), Error> {
    use std::process::Command;
    let key = &config.key;
    if !key.exists() {
        return Err(Error::Seal(format!(
            "{} doesn't exist (it is made the first time the service starts)",
            key.display()
        )));
    }
    let store = PathBuf::from("/etc/credstore.encrypted");
    std::fs::create_dir_all(&store).map_err(|e| Error::Seal(e.to_string()))?;
    let sealed = store.join(KEY_CREDENTIAL);
    let tpm = Command::new("systemd-creds")
        .arg("has-tpm2")
        .output()
        .is_ok_and(|o| o.status.success());
    let status = Command::new("systemd-creds")
        .args(["encrypt", "--with-key=auto"])
        .arg(format!("--name={KEY_CREDENTIAL}"))
        .arg(key)
        .arg(&sealed)
        .status()
        .map_err(|e| Error::Seal(format!("running systemd-creds: {e}")))?;
    if !status.success() {
        return Err(Error::Seal(format!("systemd-creds encrypt: {status}")));
    }
    // The plaintext overwritten, then removed.
    std::fs::write(key, [0_u8; 32]).map_err(|e| Error::Seal(e.to_string()))?;
    std::fs::remove_file(key).map_err(|e| Error::Seal(e.to_string()))?;
    out(&format!(
        "sealed the node's key to {} in {}; restart the service (systemctl restart snitchhiker-remote)\n",
        if tpm {
            "this machine's TPM"
        } else {
            "this machine's host key (no TPM)"
        },
        sealed.display()
    ));
    Ok(())
}

/// The node's endpoint until SIGTERM or SIGINT, or until the daemon goes.
fn serve(config: config::Config) -> Result<ExitCode, Error> {
    // Blocked before any thread starts, so every thread inherits the mask and only the signal thread takes them.
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGTERM);
    signals.add(Signal::SIGINT);
    signals.thread_block()?;
    let ended = node::run(config, move |stop| {
        let _ = std::thread::Builder::new()
            .name("signals".to_owned())
            .spawn(move || {
                if signals.wait().is_ok() {
                    tracing::info!("stopping");
                    stop();
                    // A daemon that doesn't answer doesn't keep the bridge.
                    std::thread::sleep(std::time::Duration::from_secs(8));
                    std::process::exit(0);
                }
            });
    })?;
    Ok(match ended {
        node::Ended::Stopped => ExitCode::SUCCESS,
        // Not on purpose: the service restarts it, to connect to the daemon again.
        node::Ended::DaemonGone => {
            tracing::warn!("the daemon closed the connection");
            ExitCode::FAILURE
        }
    })
}

fn run() -> Result<ExitCode, Error> {
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        out(HELP);
        return Ok(ExitCode::SUCCESS);
    }
    if args.contains(["-V", "--version"]) {
        out(&format!("snitchhiker-remote {VERSION}\n"));
        return Ok(ExitCode::SUCCESS);
    }
    let path: Option<PathBuf> = args.opt_value_from_str("--config")?;
    let path = path.unwrap_or_else(|| PathBuf::from(config::DEFAULT_PATH));
    match args.subcommand()?.as_deref() {
        Some("client") => {
            helper::run()?;
            Ok(ExitCode::SUCCESS)
        }
        Some("seal-key") => {
            seal_key(&config::Config::load(&path)?)?;
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(Error::Args(pico_args::Error::ArgumentParsingFailed {
            cause: format!("unknown command {other} (see --help)"),
        })),
        None => {
            let config = config::Config::load(&path)?;
            tracing::info!(version = VERSION, "starting");
            serve(config)
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match run() {
        Ok(code) => code,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}
