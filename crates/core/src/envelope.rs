//! Pre-authorized envelopes (plan §5.11): bounds within which an allow-listed agent's proposals are approved without
//! asking, for the agent's session. "Agents working under `~/workspace` may reach `registry.npmjs.org`, `crates.io`
//! and `*.crates.io`." Setting one is a dangerous action; a proposal that leaves the bounds in any way goes to a person.

use serde::{Deserialize, Serialize};

use crate::destination::HostPattern;
use crate::lint::covers;
use crate::pattern::Pattern;
use crate::rule::Condition;
use crate::spec::{Conditions, pattern};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Envelope {
    #[serde(skip)]
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    /// The agent's working directory (its project): a pattern, `glob:{home}/workspace/**`.
    pub project: String,
    /// The agents' programs (patterns); empty: any of the node's allow-listed agents.
    pub agents: Vec<String>,
    /// The programs rules may be for (patterns); empty: any.
    pub programs: Vec<String>,
    /// The destinations: names, and `*.` names for their subdomains. At least one.
    pub hosts: Vec<String>,
    /// Ports and ranges; empty: any.
    pub ports: Vec<String>,
}

impl Envelope {
    /// Why it can't be used as written.
    pub fn check(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("an envelope needs a name".to_owned());
        }
        if self.project.trim().is_empty() {
            return Err("an envelope needs a project directory".to_owned());
        }
        if self.hosts.is_empty() {
            return Err("an envelope needs at least one host".to_owned());
        }
        for host in &self.hosts {
            match HostPattern::try_from(host.clone()) {
                Ok(HostPattern::Regex(_)) => {
                    return Err(format!("{host}: an envelope's hosts are names or *.names"));
                }
                Ok(_) => {}
                Err(e) => return Err(format!("{host}: {e}")),
            }
        }
        for text in std::iter::once(&self.project)
            .chain(&self.agents)
            .chain(&self.programs)
        {
            Pattern::compile(&pattern(text)).map_err(|e| format!("{text}: {e}"))?;
        }
        self.bounds().map(|_| ())
    }

    fn bounds(&self) -> Result<Vec<Condition>, String> {
        let spec = Conditions {
            host: self.hosts.clone(),
            port: self.ports.clone(),
            exe: self.programs.clone(),
            ..Conditions::default()
        };
        spec.to_conditions().map_err(|e| e.to_string())
    }

    /// Whether a rule with `rule`'s conditions, proposed by the agent `agent_exe` working in `cwd` (its user's home
    /// `home`), is inside: an allow to some of the envelope's hosts (no addresses), on its ports, for its programs.
    #[must_use]
    pub fn admits(
        &self,
        agent_exe: &str,
        cwd: &str,
        home: Option<&str>,
        rule: &Conditions,
    ) -> bool {
        let matches = |text: &str, value: &str| {
            Pattern::compile(&pattern(text)).is_ok_and(|p| p.matches(value, home))
        };
        if !self.enabled
            || !matches(&self.project, cwd)
            || !(self.agents.is_empty() || self.agents.iter().any(|a| matches(a, agent_exe)))
        {
            return false;
        }
        // Only destinations by name, and nothing about where the rule applies but its program.
        let plain = Conditions {
            exe: rule.exe.clone(),
            host: rule.host.clone(),
            port: rule.port.clone(),
            protocol: rule.protocol.clone(),
            ..Conditions::default()
        };
        if rule.host.is_empty() || *rule != plain {
            return false;
        }
        let (Ok(bounds), Ok(conditions)) = (self.bounds(), rule.to_conditions()) else {
            return false;
        };
        let narrow: Vec<&Condition> = conditions
            .iter()
            .filter(|c| !matches!(c, Condition::Protocol(_)))
            .collect();
        covers(&bounds.iter().collect::<Vec<_>>(), &narrow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope {
            name: "package registries".to_owned(),
            enabled: true,
            project: "glob:{home}/workspace/**".to_owned(),
            hosts: vec!["registry.npmjs.org".to_owned(), "*.crates.io".to_owned()],
            ports: vec!["443".to_owned()],
            ..Envelope::default()
        }
    }

    fn rule(exe: &str, hosts: &[&str], port: &str) -> Conditions {
        Conditions {
            exe: vec![exe.to_owned()],
            host: hosts.iter().map(|h| (*h).to_owned()).collect(),
            port: vec![port.to_owned()],
            protocol: vec!["tcp".to_owned()],
            ..Conditions::default()
        }
    }

    #[test]
    fn only_what_is_inside_is_admitted() {
        let envelope = envelope();
        assert!(envelope.check().is_ok());
        let home = Some("/home/ada");
        let cwd = "/home/ada/workspace/shop";
        let agent = "/home/ada/.local/bin/claude";
        let cargo = "/home/ada/.cargo/bin/cargo";
        assert!(envelope.admits(agent, cwd, home, &rule(cargo, &["static.crates.io"], "443")));
        assert!(envelope.admits(
            agent,
            cwd,
            home,
            &rule(cargo, &["*.crates.io", "registry.npmjs.org"], "443")
        ));
        // Another host, another port, another project, an address.
        assert!(!envelope.admits(agent, cwd, home, &rule(cargo, &["evil.example"], "443")));
        assert!(!envelope.admits(agent, cwd, home, &rule(cargo, &["static.crates.io"], "22")));
        assert!(!envelope.admits(
            agent,
            "/tmp/x",
            home,
            &rule(cargo, &["static.crates.io"], "443")
        ));
        let mut by_address = rule(cargo, &["static.crates.io"], "443");
        by_address.net = vec!["192.0.2.1".to_owned()];
        assert!(!envelope.admits(agent, cwd, home, &by_address));
        // A rule for any port is wider than the envelope's 443.
        let mut any_port = rule(cargo, &["static.crates.io"], "443");
        any_port.port.clear();
        assert!(!envelope.admits(agent, cwd, home, &any_port));
        // Off, or for other agents.
        let off = Envelope {
            enabled: false,
            ..envelope.clone()
        };
        assert!(!off.admits(agent, cwd, home, &rule(cargo, &["static.crates.io"], "443")));
        let codex_only = Envelope {
            agents: vec!["glob:**/codex".to_owned()],
            ..envelope
        };
        assert!(!codex_only.admits(agent, cwd, home, &rule(cargo, &["static.crates.io"], "443")));
    }

    #[test]
    fn envelopes_are_checked() {
        assert!(
            Envelope {
                hosts: vec![],
                ..envelope()
            }
            .check()
            .is_err()
        );
        assert!(
            Envelope {
                hosts: vec!["re:.*".to_owned()],
                ..envelope()
            }
            .check()
            .is_err()
        );
        assert!(
            Envelope {
                project: String::new(),
                ..envelope()
            }
            .check()
            .is_err()
        );
    }
}
