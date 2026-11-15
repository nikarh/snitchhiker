//! `snitchhiker-relay`: the relay a user's nodes and devices meet through when no direct path exists (plan §8.4). It
//! is iroh's relay server, configured from a TOML file: TLS by ACME, by certificate files, or none behind a reverse
//! proxy that terminates it; optionally only listed endpoint ids may use it. Traffic through it stays end-to-end
//! encrypted between node and device: the relay sees endpoint ids and opaque packets.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

mod fcm;
mod push;
mod webpush;

use iroh_relay::server::{
    self as relay, Access, AccessControl, AcmeConfig, CertConfig, ClientRequest, QuicConfig,
    RelayConfig, ServerConfig,
};
use serde::Deserialize;
use tracing::{error, info};

const HELP: &str = "\
snitchhiker-relay: the relay Snitchhiker nodes and devices meet through behind NAT

Usage: snitchhiker-relay [--config <path>]
       snitchhiker-relay push-id [--config <path>]   Print the push gateway's id (for nodes' push_gateway)

Options:
  --config <path>  Configuration file (default /etc/snitchhiker/relay.toml)
  -h, --help       Print this help
  -V, --version    Print the version
";

/// How TLS is done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Tls {
    /// Plain HTTP: a reverse proxy in front terminates TLS (or a test).
    #[default]
    None,
    /// Certificates from an ACME CA (Let's Encrypt), for `domains`.
    Acme,
    /// Certificates from files (`cert`, `key`).
    Files,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    /// Where plain HTTP is served (the relay protocol, and ACME's challenges).
    http_bind: SocketAddr,
    tls: Tls,
    /// Where HTTPS is served, with TLS.
    https_bind: SocketAddr,
    /// QUIC address discovery (devices learn their public address), with TLS.
    quic_bind: Option<SocketAddr>,
    /// The relay's names, for ACME.
    domains: Vec<String>,
    /// An e-mail address for the ACME account.
    contact: String,
    /// Where ACME's account and certificates are kept.
    cert_dir: PathBuf,
    /// Let's Encrypt's staging CA instead of production (for trying the setup).
    acme_staging: bool,
    /// Certificate chain and key files (PEM), with `tls = "files"`.
    cert: PathBuf,
    key: PathBuf,
    /// Endpoint ids (nodes and devices) that may use the relay; none: any.
    allow: Vec<String>,
    /// Prometheus metrics, if set.
    metrics_bind: Option<SocketAddr>,
    /// The push gateway (presence and push notifications), if set.
    push: Option<push::Config>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_bind: SocketAddr::from(([0; 16], 80)),
            tls: Tls::None,
            https_bind: SocketAddr::from(([0; 16], 443)),
            quic_bind: None,
            domains: Vec::new(),
            contact: String::new(),
            cert_dir: PathBuf::from("/var/lib/snitchhiker-relay/certs"),
            acme_staging: false,
            cert: PathBuf::new(),
            key: PathBuf::new(),
            allow: Vec::new(),
            metrics_bind: None,
            push: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Args(#[from] pico_args::Error),
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Relay(String),
}

/// Only the listed endpoint ids.
#[derive(Debug)]
struct Allowed(Vec<String>);

impl AccessControl for Allowed {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait's method is async"
    )]
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let id = request.endpoint_id().to_string();
        if self.0.contains(&id) {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("not allowed on this relay".to_owned()),
            }
        }
    }
}

fn load(path: &Path) -> Result<Config, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::Config(format!("{}: {e}", path.display()))),
    };
    toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

fn tls_server_config()
-> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>, Error> {
    Ok(rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Config(e.to_string()))?
    .with_no_client_auth())
}

fn cert_config(config: &Config) -> Result<Option<CertConfig>, Error> {
    use rustls_pki_types::pem::PemObject as _;
    Ok(match config.tls {
        Tls::None => None,
        Tls::Acme => {
            if config.domains.is_empty() || config.contact.is_empty() {
                return Err(Error::Config(
                    "tls = \"acme\" needs domains and contact".to_owned(),
                ));
            }
            let acme = AcmeConfig::letsencrypt(!config.acme_staging)
                .domains(config.domains.clone())
                .contact(vec![format!("mailto:{}", config.contact)])
                .cache_path(config.cert_dir.clone());
            Some(CertConfig::LetsEncrypt {
                acme_config: acme,
                server_config_builder: tls_server_config()?,
            })
        }
        Tls::Files => {
            let certs = rustls_pki_types::CertificateDer::pem_file_iter(&config.cert)
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map_err(|e| Error::Config(format!("{}: {e}", config.cert.display())))?;
            let key = rustls_pki_types::PrivateKeyDer::from_pem_file(&config.key)
                .map_err(|e| Error::Config(format!("{}: {e}", config.key.display())))?;
            let server_config = tls_server_config()?
                .with_single_cert(certs, key)
                .map_err(|e| Error::Config(e.to_string()))?;
            Some(CertConfig::Manual { server_config })
        }
    })
}

async fn run(config: Config) -> Result<(), Error> {
    let cert = cert_config(&config)?;
    let mut relay_config = RelayConfig::new(config.http_bind);
    if !config.allow.is_empty() {
        let mut allowed = config.allow.clone();
        // The gateway's own endpoint is homed here.
        if let Some(push) = &config.push {
            allowed.push(
                push::id(push)
                    .map_err(|e| Error::Config(format!("{}: {e}", push.key.display())))?,
            );
        }
        relay_config.access = Arc::new(Allowed(allowed));
    }
    let quic = match (&cert, config.quic_bind) {
        (Some(CertConfig::Manual { server_config }), Some(bind)) => {
            let mut quic = QuicConfig::new(bind);
            quic.server_config = Some(server_config.clone());
            Some(quic)
        }
        (_, Some(_)) => {
            return Err(Error::Config(
                "quic_bind needs tls = \"files\" (QUIC needs the certificate at start)".to_owned(),
            ));
        }
        _ => None,
    };
    if let Some(cert) = cert {
        relay_config.tls = Some(relay::TlsConfig::new(config.https_bind, cert));
    }
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay_config);
    server_config.quic = quic;
    server_config.metrics_addr = config.metrics_bind;
    let mut server = relay::Server::spawn(server_config)
        .await
        .map_err(|e| Error::Relay(e.to_string()))?;
    info!(
        http = ?server.http_addr(),
        https = ?server.https_addr(),
        allowed = config.allow.len(),
        "relay serving"
    );
    tokio::select! {
        biased;
        () = shutdown() => info!("stopping"),
        _ = server.join() => error!("the relay stopped"),
    }
    server
        .shutdown()
        .await
        .map_err(|e| Error::Relay(e.to_string()))
}

async fn shutdown() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // The HTTP client of the push gateway takes the process's provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        let _ = std::io::Write::write_all(&mut std::io::stdout(), HELP.as_bytes());
        return ExitCode::SUCCESS;
    }
    if args.contains(["-V", "--version"]) {
        let _ = std::io::Write::write_all(
            &mut std::io::stdout(),
            format!("snitchhiker-relay {}\n", env!("CARGO_PKG_VERSION")).as_bytes(),
        );
        return ExitCode::SUCCESS;
    }
    let result = (|| -> Result<(), Error> {
        let path: PathBuf = args
            .opt_value_from_str("--config")?
            .unwrap_or_else(|| PathBuf::from("/etc/snitchhiker/relay.toml"));
        let config = load(&path)?;
        if args.subcommand()?.as_deref() == Some("push-id") {
            let push = config
                .push
                .ok_or_else(|| Error::Config("no [push] section".to_owned()))?;
            let id = push::id(&push)
                .map_err(|e| Error::Config(format!("{}: {e}", push.key.display())))?;
            let _ = std::io::Write::write_all(&mut std::io::stdout(), format!("{id}\n").as_bytes());
            return Ok(());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Relay(e.to_string()))?;
        // The gateway's endpoint runs on a runtime of its own (outside this one), and homes on the relay once it
        // serves.
        let gateway = config
            .push
            .as_ref()
            .map(|push| push::Gateway::start(push, runtime.handle().clone()))
            .transpose()
            .map_err(Error::Config)?;
        let served = runtime.block_on(run(config));
        if let Some(gateway) = gateway {
            gateway.stop();
        }
        served
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "snitchhiker-relay");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_reads_and_refuses_unknown_keys() {
        let config: Config = toml::from_str(
            "tls = \"acme\"\ndomains = [\"relay.example.org\"]\ncontact = \"a@example.org\"\nallow = [\"x\"]\n",
        )
        .unwrap();
        assert_eq!(config.tls, Tls::Acme);
        assert_eq!(config.http_bind.port(), 80);
        assert!(toml::from_str::<Config>("tsl = \"acme\"\n").is_err());
        assert!(cert_config(&Config::default()).unwrap().is_none());
    }
}
