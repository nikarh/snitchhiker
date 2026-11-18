//! `/etc/snitchhiker/daemon.toml`: what root decides about the daemon. Clients can't change any of it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use snitchhiker_core::rule::Action;

pub const DEFAULT_PATH: &str = "/etc/snitchhiker/daemon.toml";

/// Whether the daemon enforces its decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Rules and the policy decide.
    #[default]
    Enforce,
    /// Everything passes; decisions are only recorded (to learn what a machine does before enforcing).
    Monitor,
}

/// What happens to a connection no rule decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Allow,
    Deny,
    Reject,
    /// Hold it and ask the connected clients; `no_client` decides when nobody listens, `on_timeout` when nobody
    /// answers in time.
    Ask,
}

/// What confirms a dangerous action asked for by a client (not root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StepUp {
    /// polkit authorizes the client's process (`org.snitchhiker.manage`): the user's password, usually.
    #[default]
    Polkit,
    /// Nothing: the client's session is enough. Dangerous actions are still audited.
    Off,
}

/// What happens to new connections while the daemon isn't running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fail {
    /// They pass: the tables are removed whenever the daemon stops, and pass packets nothing is there to decide.
    #[default]
    Open,
    /// They don't, after a clean stop (the tables stay until the daemon is back) and for a crash or two; a failed start,
    /// an error, or a daemon that keeps crashing still removes them ([`crate::cleanup`]).
    Closed,
}

/// A setting that moved elsewhere: whatever its value, it is accepted and ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moved;

impl<'de> Deserialize<'de> for Moved {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer).map(|_| Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    /// What happens to a connection no rule decides.
    pub no_match: Policy,
    /// With `no_match = "ask"`: what happens when no client is listening for prompts.
    pub no_client: Action,
    /// With `no_match = "ask"`: how long a prompt waits for an answer, and what happens then.
    pub prompt_timeout_secs: u64,
    pub on_timeout: Action,
    /// The group the client binaries are setgid to, and the client socket belongs to.
    pub client_group: String,
    /// Client binaries allowed on the client socket by path alone, besides those registered with
    /// `snitchhikerd trust-client` (which are also pinned to their digest).
    pub trusted_clients: Vec<PathBuf>,
    /// What confirms dangerous actions asked for by clients.
    pub step_up: StepUp,
    /// The local users who administer the node through the desktop app: members of these groups (those who may
    /// become root, usually). Other users' apps see the node and its history, and change nothing.
    pub admin_groups: Vec<String>,
    pub fail: Fail,
    /// NFQUEUE queues, one deciding thread each.
    pub queues: u16,
    /// The first queue number.
    pub queue: u16,
    /// Learn the names of addresses from the DNS answers processes receive (on the queue after the deciding ones),
    /// so rules can name hosts.
    pub learn_dns: bool,
    /// Bridges whose forwarded traffic is decided too: containers on bridge networks and VMs on taps send through
    /// them, never through the host's own sockets. Names, or prefixes ending in `*`. Empty: forwarded traffic is left
    /// alone (a router's, for one).
    pub forward_from: Vec<String>,
    pub database: PathBuf,
    /// The built-in System folder (loopback and the like).
    pub default_rules: bool,
    /// Rule files root keeps, read-only for clients (provisioning).
    pub rules_dir: PathBuf,
    /// How long connection history is kept.
    pub retention_days: u32,
    /// Programs that may propose rules on the agent socket (patterns as rules write them). Empty: any program, its
    /// proposals marked as not from a known agent.
    pub agent_programs: Vec<String>,
    /// Which clients are notified of a prompt (all of them can answer it).
    pub prompt_routing: Routing,
    /// With `escalate`: how long a prompt waits for the clients on this machine before remote devices are notified.
    pub escalate_after_secs: u64,
    /// Moved to `/etc/snitchhiker/remote.toml` (`snitchhiker-remote`, decision 0016): accepted, so a configuration
    /// written before doesn't stop the daemon, and ignored with a warning.
    #[serde(skip_serializing)]
    pub remote: Option<Moved>,
    #[serde(skip_serializing)]
    pub relays: Option<Moved>,
    #[serde(skip_serializing)]
    pub remote_port: Option<Moved>,
    #[serde(skip_serializing)]
    pub lan_discovery: Option<Moved>,
    #[serde(skip_serializing)]
    pub push_gateway: Option<Moved>,
    #[serde(skip_serializing)]
    pub offline_after_secs: Option<Moved>,
    /// Where alerts are sent (an HTTP POST of JSON), besides the clients and devices. Empty: nowhere.
    pub alert_webhook: String,
    /// A file with a secret that signs each webhook delivery (HMAC-SHA256 of the body, `X-Snitchhiker-Signature`).
    pub alert_webhook_secret_file: Option<PathBuf>,
    /// The largest blocklist fetched, in bytes: a larger one is refused.
    pub blocklist_max_bytes: u64,
}

/// Who is notified of prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Routing {
    /// Every client, local and remote.
    #[default]
    All,
    /// The clients on this machine first; remote devices when none listens, when the users' sessions are locked or
    /// idle, or after `escalate_after_secs`.
    Escalate,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            no_match: Policy::Ask,
            no_client: Action::Deny,
            prompt_timeout_secs: 30,
            on_timeout: Action::Deny,
            client_group: "snitchhiker-ui".to_owned(),
            trusted_clients: Vec::new(),
            step_up: StepUp::Polkit,
            admin_groups: ["wheel", "sudo", "admin"].map(str::to_owned).to_vec(),
            fail: Fail::Open,
            queues: 4,
            queue: 0,
            learn_dns: true,
            forward_from: [
                "docker0", "br-*", "podman*", "cni-*", "virbr*", "lxdbr*", "incusbr*",
            ]
            .map(str::to_owned)
            .to_vec(),
            database: PathBuf::from("/var/lib/snitchhiker/state.db"),
            default_rules: true,
            rules_dir: PathBuf::from("/etc/snitchhiker/rules.d"),
            retention_days: 30,
            agent_programs: Vec::new(),
            prompt_routing: Routing::All,
            escalate_after_secs: 20,
            remote: None,
            relays: None,
            remote_port: None,
            lan_discovery: None,
            push_gateway: None,
            offline_after_secs: None,
            alert_webhook: String::new(),
            alert_webhook_secret_file: None,
            blocklist_max_bytes: 64 << 20,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("{0}")]
    Invalid(&'static str),
}

impl Config {
    /// The settings given that moved to `remote.toml`.
    #[must_use]
    pub fn moved(&self) -> Vec<&'static str> {
        [
            ("remote", self.remote.is_some()),
            ("relays", self.relays.is_some()),
            ("remote_port", self.remote_port.is_some()),
            ("lan_discovery", self.lan_discovery.is_some()),
            ("push_gateway", self.push_gateway.is_some()),
            ("offline_after_secs", self.offline_after_secs.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, given)| given.then_some(name))
        .collect()
    }

    /// Reads the configuration; a missing file at the default path means the defaults.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && path == Path::new(DEFAULT_PATH) =>
            {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(Error::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        Self::parse(&text).map_err(|e| match e {
            Error::Parse { source, .. } => Error::Parse {
                path: path.to_owned(),
                source,
            },
            other => other,
        })
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text).map_err(|e| Error::Parse {
            path: PathBuf::new(),
            source: Box::new(e),
        })?;
        if config.prompt_timeout_secs == 0 || config.prompt_timeout_secs > 3600 {
            return Err(Error::Invalid(
                "prompt_timeout_secs must be between 1 and 3600",
            ));
        }
        if config.queues == 0 || config.queues > 64 {
            return Err(Error::Invalid("queues must be between 1 and 64"));
        }
        if config
            .queue
            .checked_add(config.queues)
            .is_none_or(|end| end == u16::MAX)
        {
            return Err(Error::Invalid("queue + queues must fit in 16 bits"));
        }
        Ok(config)
    }

    /// The queue DNS answers go to, when learned.
    #[must_use]
    pub fn dns_queue(&self) -> Option<u16> {
        self.learn_dns.then_some(self.queue + self.queues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_means_defaults() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn reads_every_setting() {
        let config = Config::parse(
            "mode = \"monitor\"\nno_match = \"allow\"\nfail = \"closed\"\nqueues = 2\nqueue = 10\n\
             database = \"/tmp/x.db\"\nretention_days = 7\n",
        )
        .unwrap();
        assert_eq!(config.mode, Mode::Monitor);
        assert_eq!(config.no_match, Policy::Allow);
        assert_eq!(config.fail, Fail::Closed);
        assert_eq!((config.queue, config.queues), (10, 2));
        assert_eq!(config.retention_days, 7);
    }

    #[test]
    fn the_packaged_file_parses() {
        let config = Config::parse(include_str!("../../../dist/daemon.toml")).unwrap();
        assert_eq!(config.mode, Mode::Monitor);
    }

    #[test]
    fn rejects_nonsense() {
        assert!(Config::parse("queues = 0").is_err());
        assert!(Config::parse("typo = 1").is_err());
        assert!(Config::parse("queue = 65535\nqueues = 2").is_err());
    }
}
