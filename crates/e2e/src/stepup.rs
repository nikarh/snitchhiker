//! Step-up: a client's request to loosen the policy (connections no rule decides allowed) needs polkit's authorization
//! of the client's process; tightening it doesn't, and neither does root. What rules say needs none (decision 0018).
//! Every dangerous attempt is audited.

use std::path::Path;
use std::thread;
use std::time::Duration;

use snitchhiker_client::Client;
use snitchhiker_proto::v1;

use crate::local_auth::{CLIENT, as_mallory, install_clients};
use crate::util::check;

const RULES: &str = "/etc/polkit-1/rules.d/49-snitchhiker-e2e.rules";

/// The client side (`snitchhiker-e2e --add-rule <socket> <broad|narrow>`): adds an allow rule for port 9 to any
/// destination for any program (broad), or for one program (narrow); prints `added` or the error.
pub fn add_rule(socket: &str, kind: &str) -> std::process::ExitCode {
    let mut conditions = v1::Conditions {
        port: vec!["9".to_owned()],
        ..v1::Conditions::default()
    };
    if kind == "narrow" {
        conditions.exe = vec!["/usr/bin/curl".to_owned()];
    }
    let rule = v1::Rule {
        name: format!("e2e {kind}"),
        enabled: true,
        action: v1::Action::Allow.into(),
        tier: v1::Tier::Normal.into(),
        conditions: Some(conditions),
        ..v1::Rule::default()
    };
    call(
        socket,
        v1::request::Method::AddRule(v1::AddRule { rule: Some(rule) }),
        "added",
    )
}

/// The client side (`snitchhiker-e2e --set-policy <socket> <loosen|tighten>`): lets connections no rule decides
/// through (loosen) or rejects them (tighten); prints `set` or the error.
pub fn set_policy(socket: &str, kind: &str) -> std::process::ExitCode {
    let no_match = if kind == "loosen" {
        v1::Policy::Allow
    } else {
        v1::Policy::Reject
    };
    call(
        socket,
        v1::request::Method::SetPolicy(v1::SetPolicy {
            no_match: Some(no_match.into()),
            ..v1::SetPolicy::default()
        }),
        "set",
    )
}

/// Makes one request as a client; prints `done` or the error.
fn call(socket: &str, method: v1::request::Method, done: &str) -> std::process::ExitCode {
    use std::io::Write as _;
    let result =
        Client::connect(Path::new(socket), "e2e", "0").and_then(|mut client| client.call(method));
    let mut out = std::io::stdout().lock();
    match result {
        Ok(v1::response::Result::Error(error)) => {
            let _ = writeln!(out, "error: {}", error.message);
            std::process::ExitCode::FAILURE
        }
        Ok(_) => {
            let _ = writeln!(out, "{done}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(out, "error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The client side (`snitchhiker-e2e --approve <socket> <id>`): approves a proposal for the agent's session; prints
/// `approved` or the error.
pub fn approve(socket: &str, id: &str) -> std::process::ExitCode {
    use std::io::Write as _;
    let id: u64 = id.parse().unwrap_or(0);
    let result = Client::connect(Path::new(socket), "e2e", "0").and_then(|mut client| {
        client.call(v1::request::Method::DecideProposal(v1::DecideProposal {
            id,
            approve: true,
            ..v1::DecideProposal::default()
        }))
    });
    let mut out = std::io::stdout().lock();
    match result {
        Ok(_) => {
            let _ = writeln!(out, "approved");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(out, "error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Approves proposal `id` as a trusted client of mallory's.
pub fn approve_as_client(id: u64) -> Result<String, String> {
    let (_, text) = as_mallory(
        CLIENT,
        &["--approve", "/run/snitchhiker/client.sock", &id.to_string()],
    )?;
    Ok(text)
}

/// Makes polkit answer `result` (`YES`, `NO`) for mallory and the Snitchhiker action, or removes the rule.
pub fn polkit_answers(result: Option<&str>) -> Result<(), String> {
    match result {
        Some(result) => std::fs::write(
            RULES,
            format!(
                "polkit.addRule(function(action, subject) {{\n  if (action.id == \"org.snitchhiker.manage\" && \
                 subject.user == \"mallory\") {{ return polkit.Result.{result}; }}\n}});\n"
            ),
        )
        .map_err(|e| e.to_string())?,
        None => {
            let _ = std::fs::remove_file(RULES);
        }
    }
    // polkit reads rules.d again when it changes.
    thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn as_client(flag: &str, kind: &str) -> Result<String, String> {
    let (_, text) = as_mallory(CLIENT, &[flag, "/run/snitchhiker/client.sock", kind])?;
    Ok(text)
}

/// Loosening the policy takes polkit's authorization (none answering is a refusal); tightening it doesn't, nor does
/// root; and a rule allowing every program anywhere is a rule like any other.
pub fn loosening_the_policy_needs_authorization() -> Result<(), String> {
    install_clients()?;
    let mut daemon = crate::daemon::Running::start(
        "step-up",
        &format!("mode = \"monitor\"\ntrusted_clients = [\"{CLIENT}\"]\n"),
    )?;
    // No answer from polkit (no rule, and no agent to ask the user through): refused.
    polkit_answers(None)?;
    let unanswered = as_client("--set-policy", "loosen")?;
    let tightened = as_client("--set-policy", "tighten")?;
    let broad = as_client("--add-rule", "broad")?;
    polkit_answers(Some("NO"))?;
    let refused = as_client("--set-policy", "loosen")?;
    polkit_answers(Some("YES"))?;
    let authorized = as_client("--set-policy", "loosen")?;
    polkit_answers(None)?;
    let root = daemon.cli(&["policy", "set", "on_timeout=allow"]);
    let audit = daemon.cli(&["audit"])?;
    daemon.stop()?;
    let found = format!(
        "unanswered: {unanswered}tightened: {tightened}broad: {broad}refused: {refused}authorized: {authorized}\
         root: {root:?}\n{audit}"
    );
    check(
        unanswered.contains("not authorized") && refused.contains("not authorized"),
        "the policy was loosened without authorization",
        &found,
    )?;
    check(
        tightened.trim() == "set",
        "tightening the policy needed authorization",
        &found,
    )?;
    check(
        broad.trim() == "added",
        "a rule allowing every program anywhere needed authorization",
        &found,
    )?;
    check(
        authorized.trim() == "set",
        "an authorized loosening didn't happen",
        &found,
    )?;
    check(root.is_ok(), "root couldn't loosen the policy", &found)?;
    let outcomes: Vec<&str> = audit
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .collect();
    check(
        outcomes == ["unchecked", "authorized", "refused", "refused"],
        "the audit doesn't record each attempt and its outcome, newest first",
        &found,
    )
}

/// The client side (`snitchhiker-e2e --request <socket> <step> [id]`): one request of the ways around step-up; prints
/// `ok` and the id made, if any, or the error.
pub fn request(socket: &str, step: &str, id: Option<&str>) -> std::process::ExitCode {
    use std::io::Write as _;
    use v1::request::Method;
    let id: u64 = id.and_then(|id| id.parse().ok()).unwrap_or(0);
    let curl = || v1::Conditions {
        exe: vec!["/usr/bin/curl".to_owned()],
        ..v1::Conditions::default()
    };
    let rule = |name: &str, conditions: v1::Conditions, folder: Option<u64>| v1::Rule {
        name: name.to_owned(),
        enabled: true,
        action: v1::Action::Allow.into(),
        tier: v1::Tier::Normal.into(),
        conditions: Some(conditions),
        folder,
        ..v1::Rule::default()
    };
    let port = |port: u16| v1::Conditions {
        port: vec![port.to_string()],
        ..v1::Conditions::default()
    };
    let folder = |id: u64, enabled: bool, scope: v1::Conditions| v1::Folder {
        id,
        name: "e2e scoped".to_owned(),
        enabled,
        scope: Some(scope),
        ..v1::Folder::default()
    };
    let method = match step {
        // A folder for curl, and a rule in it naming nothing itself.
        "scoped-folder" => Method::AddFolder(v1::AddFolder {
            folder: Some(folder(0, true, curl())),
        }),
        "rule-in" => Method::AddRule(v1::AddRule {
            rule: Some(rule("e2e in the folder", port(9), Some(id))),
        }),
        "unscope" => Method::UpdateFolder(v1::UpdateFolder {
            folder: Some(folder(id, true, v1::Conditions::default())),
        }),
        "disable-folder" => Method::UpdateFolder(v1::UpdateFolder {
            folder: Some(folder(id, false, curl())),
        }),
        "move-out" => Method::EditRules(v1::EditRules {
            ids: vec![id],
            edit: Some(v1::edit_rules::Edit::Move(v1::MoveRules { folder: None })),
        }),
        "import-disabled" => Method::ImportRules(v1::ImportRules {
            toml: "[[rule]]\nname = \"e2e imported\"\naction = \"allow\"\nenabled = false\nport = [\"9\"]\n"
                .to_owned(),
            folder: "e2e imported".to_owned(),
        }),
        "enable" => Method::SetRuleEnabled(v1::SetRuleEnabled { id, enabled: true }),
        "wildcard" => Method::AddRule(v1::AddRule {
            rule: Some(rule(
                "e2e any program, anywhere",
                v1::Conditions {
                    exe: vec!["glob:/**".to_owned()],
                    net: vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()],
                    ..v1::Conditions::default()
                },
                None,
            )),
        }),
        "undo" => Method::Undo(v1::Undo { change: id }),
        "list" => Method::ListRules(v1::ListRules {}),
        _ => Method::AddRule(v1::AddRule {
            rule: Some(rule(&format!("e2e curl {id}"), curl(), Some(id))),
        }),
    };
    // Listening for prompts for a while, as an app does.
    if step == "watch-prompts" {
        let watched = Client::connect(Path::new(socket), "e2e", "0").and_then(|mut client| {
            client.subscribe(v1::Topic::Prompts)?;
            std::thread::sleep(std::time::Duration::from_secs(15));
            Ok(())
        });
        let _ = writeln!(std::io::stdout().lock(), "{watched:?}");
        return std::process::ExitCode::SUCCESS;
    }
    let result =
        Client::connect(Path::new(socket), "e2e", "0").and_then(|mut client| client.call(method));
    let mut out = std::io::stdout().lock();
    match result {
        Ok(v1::response::Result::RuleAdded(added)) => {
            let _ = writeln!(out, "ok {}", added.id);
        }
        Ok(v1::response::Result::FolderAdded(added)) => {
            let _ = writeln!(out, "ok {}", added.id);
        }
        Ok(v1::response::Result::Error(error)) => {
            let _ = writeln!(out, "error: {}", error.message);
            return std::process::ExitCode::FAILURE;
        }
        Ok(_) => {
            let _ = writeln!(out, "ok");
        }
        Err(error) => {
            let _ = writeln!(out, "error: {error}");
            return std::process::ExitCode::FAILURE;
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Runs one `request` step as a trusted client of mallory's; its output.
fn step(step: &str, id: Option<u64>) -> Result<String, String> {
    let id = id.map(|id| id.to_string());
    let mut args = vec!["--request", "/run/snitchhiker/client.sock", step];
    args.extend(id.as_deref());
    let (_, text) = as_mallory(CLIENT, &args)?;
    Ok(text.trim().to_owned())
}

fn made(output: &str) -> Result<u64, String> {
    output
        .strip_prefix("ok ")
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| format!("nothing was made: {output}"))
}

/// What rules say takes no authorization, whatever the path to it (decision 0018): a narrow rule whose folder's scope
/// is removed or that is moved out of it, a rule imported disabled and enabled after, a rule naming every program by a
/// wildcard, a folder of many rules turned off. All of them happen with polkit refusing, and nothing is audited.
pub fn rule_changes_need_no_authorization() -> Result<(), String> {
    use std::fmt::Write as _;
    install_clients()?;
    let mut daemon = crate::daemon::Running::start(
        "step-up-rules",
        &format!("mode = \"monitor\"\ntrusted_clients = [\"{CLIENT}\"]\n"),
    )?;
    polkit_answers(Some("NO"))?;
    let mut log = String::new();
    let mut run = |name: &str, id: Option<u64>| -> Result<String, String> {
        let out = step(name, id)?;
        let _ = writeln!(log, "{name} {id:?}: {out}");
        Ok(out)
    };
    let folder = made(&run("scoped-folder", None)?)?;
    let inside = made(&run("rule-in", Some(folder))?)?;
    let unscoped = run("unscope", Some(folder))?;
    let moved = run("move-out", Some(inside))?;
    let imported = run("import-disabled", None)?;
    let rules = daemon.cli(&["rules"])?;
    let imported_id = rules
        .lines()
        .find(|line| line.contains("e2e imported") && !line.contains("folder"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|id| id.trim_end_matches(':').parse::<u64>().ok());
    let enabled = run("enable", imported_id)?;
    let wildcard = run("wildcard", None)?;
    for _ in 0..21 {
        made(&run("narrow", Some(folder))?)?;
    }
    let disabled = run("disable-folder", Some(folder))?;
    polkit_answers(None)?;
    let audit = daemon.cli(&["audit"])?;
    daemon.stop()?;
    let found = format!("{log}\nrules:\n{rules}\naudit:\n{audit}");
    check(
        imported.starts_with("ok") && imported_id.is_some(),
        "a disabled rule couldn't be imported, or isn't listed",
        &found,
    )?;
    for (what, out) in [
        ("removing the folder's scope", &unscoped),
        ("moving the rule out of its folder", &moved),
        ("enabling an imported rule", &enabled),
        ("naming every program by a wildcard", &wildcard),
        ("turning off a folder of 21 rules", &disabled),
    ] {
        check(
            out.starts_with("ok"),
            &format!("{what} didn't happen"),
            &found,
        )?;
    }
    check(
        !audit.contains("refused"),
        "a change to the rules asked for authorization",
        &found,
    )
}

/// A local user outside `admin_groups` sees the node and changes nothing: their app is a viewer. Nor is a viewer
/// someone to ask: with only a viewer listening, a connection no rule decides isn't held for a prompt.
pub fn other_local_users_are_viewers() -> Result<(), String> {
    install_clients()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut daemon = crate::daemon::Running::start(
        "viewers",
        &format!(
            "mode = \"enforce\"\nno_match = \"ask\"\nno_client = \"reject\"\nprompt_timeout_secs = 30\n\
             trusted_clients = [\"{CLIENT}\"]\nadmin_groups = [\"wheel\"]\n"
        ),
    )?;
    let listed = step("list", None)?;
    let added = step("import-disabled", None)?;
    let mut watcher = std::process::Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            CLIENT,
            "--request",
            "/run/snitchhiker/client.sock",
            "watch-prompts",
        ])
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_secs(2));
    let started = std::time::Instant::now();
    let connected = std::process::Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c"])
        .arg(format!(
            "import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=10)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)"
        ))
        .output()
        .map_err(|e| e.to_string())?;
    let waited = started.elapsed();
    let _ = watcher.kill();
    let _ = watcher.wait();
    daemon.stop()?;
    let connected = String::from_utf8_lossy(&connected.stdout).into_owned();
    let found = format!("list: {listed}\nimport: {added}\nconnect: {connected} after {waited:?}");
    check(
        waited < Duration::from_secs(5) && !connected.contains("connected"),
        "a connection was held for a prompt only a viewer could see",
        &found,
    )?;
    check(listed == "ok", "a viewer couldn't read the rules", &found)?;
    check(
        added.contains("not allowed"),
        "a user outside the admin groups changed the rules",
        &found,
    )
}
