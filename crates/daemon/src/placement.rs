//! Where a rule made by answering a prompt goes: the folder the client chose, or the program's own folder.
//!
//! A program's folder is `Apps/<program>`, scoped to the program (its `exe` condition), so its rules hold only their
//! destinations. If an enabled folder already scopes exactly this program, the rule goes there; otherwise the folder is
//! made. A rule that names no program (any program → this host) stays at the top level.

use snitchhiker_core::rule::{Condition, Folder, FolderId, Rule};

use crate::managed::MANAGED_ID;
use crate::store::{Error as StoreError, Store};

/// The folder programs' folders are made in.
pub const APPS: &str = "Apps";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no folder {0}")]
    NoFolder(FolderId),
    #[error("folder {0} is a default or managed one: rules can't be added to it")]
    Locked(FolderId),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Puts `rule` in a folder: `chosen`, or the folder of the program it names (made if needed), and leaves out the
/// conditions the folder's scope already adds. `program` names a folder that has to be made (the executable's name).
pub fn place(
    store: &mut Store,
    rule: &mut Rule,
    chosen: Option<FolderId>,
    program: &str,
) -> Result<(), Error> {
    let folders = store.folders()?;
    if let Some(id) = chosen {
        if id & MANAGED_ID != 0 {
            return Err(Error::Locked(id));
        }
        if !folders.iter().any(|f| f.id == id) {
            return Err(Error::NoFolder(id));
        }
        rule.folder = Some(id);
        strip_scopes(rule, &folders, id);
        return Ok(());
    }
    let Some(exe) = rule
        .conditions
        .iter()
        .find(|c| matches!(c, Condition::Exe(_)))
        .cloned()
    else {
        return Ok(());
    };
    let scope = vec![exe];
    let id = if let Some(folder) = folders.iter().find(|f| f.enabled && f.scope == scope) {
        folder.id
    } else {
        let apps = match folders
            .iter()
            .find(|f| f.parent.is_none() && f.name == APPS && f.scope.is_empty())
        {
            Some(apps) => apps.id,
            None => store.insert_folder(&Folder {
                id: 0,
                parent: None,
                name: APPS.to_owned(),
                enabled: true,
                scope: Vec::new(),
            })?,
        };
        let name = free_name(&folders, apps, program);
        store.insert_folder(&Folder {
            id: 0,
            parent: Some(apps),
            name,
            enabled: true,
            scope,
        })?
    };
    rule.folder = Some(id);
    let folders = store.folders()?;
    strip_scopes(rule, &folders, id);
    Ok(())
}

/// `program`, or `program 2`, `program 3`, ... : a name no folder under `parent` has.
fn free_name(folders: &[Folder], parent: FolderId, program: &str) -> String {
    let program = if program.is_empty() {
        "Unknown program"
    } else {
        program
    };
    let taken = |name: &str| {
        folders
            .iter()
            .any(|f| f.parent == Some(parent) && f.name == name)
    };
    if !taken(program) {
        return program.to_owned();
    }
    // Among n folders, one of the n + 1 names after `program` is free.
    (2..folders.len() + 3)
        .map(|n| format!("{program} {n}"))
        .find(|name| !taken(name))
        .unwrap_or_else(|| program.to_owned())
}

/// Removes from `rule` the conditions that `folder` and the folders above it add anyway.
fn strip_scopes(rule: &mut Rule, folders: &[Folder], folder: FolderId) {
    let mut scope: Vec<&Condition> = Vec::new();
    let mut next = Some(folder);
    for _ in 0..folders.len() {
        let Some(found) = next.and_then(|id| folders.iter().find(|f| f.id == id)) else {
            break;
        };
        scope.extend(&found.scope);
        next = found.parent;
    }
    rule.conditions.retain(|c| !scope.contains(&c));
}

#[cfg(test)]
mod tests {
    use snitchhiker_core::destination::HostPattern;
    use snitchhiker_core::pattern::PatternSource;
    use snitchhiker_core::rule::{Action, Expiry, Tier};

    use super::*;

    fn exe(path: &str) -> Condition {
        Condition::Exe(vec![PatternSource::Exact(path.to_owned())])
    }

    fn rule(conditions: Vec<Condition>) -> Rule {
        Rule {
            id: 0,
            folder: None,
            name: "answer".to_owned(),
            enabled: true,
            action: Action::Allow,
            tier: Tier::Normal,
            expiry: Expiry::Never,
            log: true,
            notes: String::new(),
            conditions,
        }
    }

    fn host() -> Condition {
        Condition::Host(vec![
            HostPattern::try_from("example.com".to_owned()).unwrap(),
        ])
    }

    #[test]
    fn a_program_gets_its_folder_once() {
        let mut store = Store::in_memory().unwrap();
        let mut first = rule(vec![exe("/usr/bin/curl"), host()]);
        place(&mut store, &mut first, None, "curl").unwrap();
        let mut second = rule(vec![
            exe("/usr/bin/curl"),
            Condition::Port(vec![(443, 443)]),
        ]);
        place(&mut store, &mut second, None, "curl").unwrap();
        let folders = store.folders().unwrap();
        let apps = folders.iter().find(|f| f.name == APPS).unwrap();
        let curl = folders.iter().find(|f| f.name == "curl").unwrap();
        assert_eq!(curl.parent, Some(apps.id));
        assert_eq!(curl.scope, vec![exe("/usr/bin/curl")]);
        assert_eq!(folders.len(), 2);
        assert_eq!(
            (first.folder, second.folder),
            (Some(curl.id), Some(curl.id))
        );
        assert_eq!(first.conditions, vec![host()]);
    }

    #[test]
    fn programs_of_the_same_name_get_folders_of_their_own() {
        let mut store = Store::in_memory().unwrap();
        let mut system = rule(vec![exe("/usr/bin/python3"), host()]);
        let mut venv = rule(vec![exe("/opt/venv/bin/python3"), host()]);
        place(&mut store, &mut system, None, "python3").unwrap();
        place(&mut store, &mut venv, None, "python3").unwrap();
        let names: Vec<String> = store
            .folders()
            .unwrap()
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert!(names.contains(&"python3 2".to_owned()), "{names:?}");
        assert_ne!(system.folder, venv.folder);
    }

    #[test]
    fn rules_for_any_program_stay_at_the_top_and_chosen_folders_are_checked() {
        let mut store = Store::in_memory().unwrap();
        let mut any = rule(vec![host()]);
        place(&mut store, &mut any, None, "curl").unwrap();
        assert_eq!(any.folder, None);
        assert_eq!(store.folders().unwrap(), Vec::new());
        let mut chosen = rule(vec![exe("/usr/bin/curl")]);
        assert!(matches!(
            place(&mut store, &mut chosen, Some(42), "curl"),
            Err(Error::NoFolder(42))
        ));
        assert!(matches!(
            place(&mut store, &mut chosen, Some(MANAGED_ID | 1), "curl"),
            Err(Error::Locked(_))
        ));
    }
}
