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

/// What happens to new connections while the daemon isn't running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fail {
    /// They pass (and the daemon's table is removed when it stops).
    Open,
    /// They don't (and the table stays when the daemon stops).
    #[default]
    Closed,
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
    pub fail: Fail,
    /// NFQUEUE queues, one deciding thread each.
    pub queues: u16,
    /// The first queue number.
    pub queue: u16,
    /// Learn the names of addresses from the DNS answers processes receive (on the queue after the deciding ones),
    /// so rules can name hosts.
    pub learn_dns: bool,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            no_match: Policy::Deny,
            no_client: Action::Deny,
            prompt_timeout_secs: 30,
            on_timeout: Action::Deny,
            client_group: "snitchhiker-ui".to_owned(),
            trusted_clients: Vec::new(),
            step_up: StepUp::Polkit,
            fail: Fail::Closed,
            queues: 4,
            queue: 0,
            learn_dns: true,
            database: PathBuf::from("/var/lib/snitchhiker/state.db"),
            default_rules: true,
            rules_dir: PathBuf::from("/etc/snitchhiker/rules.d"),
            retention_days: 30,
            agent_programs: Vec::new(),
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
            "mode = \"monitor\"\nno_match = \"allow\"\nfail = \"open\"\nqueues = 2\nqueue = 10\n\
             database = \"/tmp/x.db\"\nretention_days = 7\n",
        )
        .unwrap();
        assert_eq!(config.mode, Mode::Monitor);
        assert_eq!(config.no_match, Policy::Allow);
        assert_eq!(config.fail, Fail::Open);
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
