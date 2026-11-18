//! What a change to the policy or system firewall loosens, judged on the state it leaves rather than on the request:
//! any path to the same state is the same dangerous action.
//!
//! A change loosens when, after it:
//!
//! - the policy lets through what it blocked, or keeps less history;
//! - the system firewall lets in what it kept out.
//!
//! What rules say is not judged (decision 0018): a process that can drive the app can add a rule for a program of its
//! own as easily as a broad one, so asking for a password for some rules protects nothing.

use crate::config::Config;
use crate::policy::Effective;
use crate::store::{Error, Store};

/// The state a change is judged on.
pub struct State {
    policy: Effective,
    system: snitchhiker_core::system::Firewall,
}

impl State {
    pub fn of(store: &Store, config: &Config) -> Result<Self, Error> {
        Ok(Self {
            policy: Effective::of(config, &store.policy()?),
            system: store.system_firewall()?,
        })
    }

    /// What going from `self` to `after` loosens, as the action to authorize; `None` when nothing.
    #[must_use]
    pub fn loosened_by(&self, after: &Self) -> Option<String> {
        let mut what = Vec::new();
        if self.policy.loosened_by(&after.policy) {
            what.push(format!(
                "change the policy so that blocked connections get through ({})",
                crate::policy::describe(&self.policy, &after.policy)
            ));
        }
        if after.policy.retention_days < self.policy.retention_days {
            what.push(format!(
                "keep {} days of history instead of {}",
                after.policy.retention_days, self.policy.retention_days
            ));
        }
        if crate::system::loosened(&self.system, &after.system) {
            what.push(format!(
                "change the system firewall so that it lets in what it kept out ({})",
                crate::system::describe(&self.system, &after.system)
            ));
        }
        (!what.is_empty()).then(|| what.join("; "))
    }
}
