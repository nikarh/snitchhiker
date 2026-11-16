//! What a change to the rules, folders, policy or system firewall loosens, judged on the state it leaves rather than
//! on the request: any path to the same state (a rule added narrow and its folder's scope removed after, a rule
//! imported disabled and enabled after, a change undone) is the same dangerous action.
//!
//! A change loosens when, after it:
//!
//! - an enabled rule, in enabled folders, allows broadly with its folders' scopes ([`allows_broadly`]) that didn't;
//! - more than [`TURNED_OFF`] rules that were in force aren't (deleted, disabled, or in a disabled folder);
//! - the policy lets through what it blocked, or keeps less history;
//! - the system firewall lets in what it kept out.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use snitchhiker_core::rule::{Folder, FolderId, Rule, RuleId, allows_broadly};

use crate::config::Config;
use crate::policy::Effective;
use crate::store::{Error, Store};

/// How many rules can stop being in force in one change without authorization.
pub const TURNED_OFF: usize = 20;

/// The state a change is judged on.
pub struct State {
    /// The rules in force (enabled, in enabled folders), with their names.
    in_force: BTreeMap<RuleId, String>,
    /// Those of them that allow broadly.
    broad: BTreeSet<RuleId>,
    policy: Effective,
    system: snitchhiker_core::system::Firewall,
}

impl State {
    pub fn of(store: &Store, config: &Config) -> Result<Self, Error> {
        let folders: HashMap<FolderId, Folder> =
            store.folders()?.into_iter().map(|f| (f.id, f)).collect();
        let mut in_force = BTreeMap::new();
        let mut broad = BTreeSet::new();
        for rule in store.rules()? {
            if let Some(scope) = in_force_scope(&rule, &folders) {
                if allows_broadly(rule.action, rule.conditions.iter().chain(&scope)) {
                    broad.insert(rule.id);
                }
                in_force.insert(rule.id, rule.name);
            }
        }
        Ok(Self {
            in_force,
            broad,
            policy: Effective::of(config, &store.policy()?),
            system: store.system_firewall()?,
        })
    }

    /// What going from `self` to `after` loosens, as the action to authorize; `None` when nothing.
    #[must_use]
    pub fn loosened_by(&self, after: &Self) -> Option<String> {
        let mut what = Vec::new();
        let broad: Vec<&str> = after
            .broad
            .difference(&self.broad)
            .filter_map(|id| after.in_force.get(id).map(String::as_str))
            .collect();
        if !broad.is_empty() {
            what.push(format!(
                "make {} allow programs to connect broadly (naming no particular program or destination)",
                names(&broad)
            ));
        }
        let off = self
            .in_force
            .keys()
            .filter(|id| !after.in_force.contains_key(id))
            .count();
        if off > TURNED_OFF {
            what.push(format!("turn off {off} rules"));
        }
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

/// The conditions a rule's folders add, when it is in force: enabled, and every folder above it enabled.
fn in_force_scope(
    rule: &Rule,
    folders: &HashMap<FolderId, Folder>,
) -> Option<Vec<snitchhiker_core::rule::Condition>> {
    if !rule.enabled {
        return None;
    }
    let mut scope = Vec::new();
    let mut next = rule.folder;
    // A cycle can't be stored, but the walk is bounded anyway.
    for _ in 0..=folders.len() {
        let Some(id) = next else {
            return Some(scope);
        };
        let folder = folders.get(&id)?;
        if !folder.enabled {
            return None;
        }
        scope.extend(folder.scope.iter().cloned());
        next = folder.parent;
    }
    None
}

/// `"a"`, `"a" and "b"`, `"a", "b" and 3 more rules`.
fn names(names: &[&str]) -> String {
    let quoted: Vec<String> = names.iter().take(2).map(|n| format!("\"{n}\"")).collect();
    match names.len() {
        1 => format!("the rule {}", quoted.join("")),
        2 => format!("the rules {}", quoted.join(" and ")),
        n => format!("the rules {} and {} more", quoted.join(", "), n - 2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_listed_shortly() {
        assert_eq!(names(&["a"]), "the rule \"a\"");
        assert_eq!(names(&["a", "b"]), "the rules \"a\" and \"b\"");
        assert_eq!(
            names(&["a", "b", "c", "d"]),
            "the rules \"a\", \"b\" and 2 more"
        );
    }
}
