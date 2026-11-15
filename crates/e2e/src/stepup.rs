//! Step-up: a client's request for an allow-everything rule needs polkit's authorization of the client's process; a
//! narrow rule doesn't, and neither does root. Every dangerous attempt is audited.

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
    use std::io::Write as _;
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
    let result = Client::connect(Path::new(socket), "e2e", "0").and_then(|mut client| {
        client.call(v1::request::Method::AddRule(v1::AddRule {
            rule: Some(rule),
        }))
    });
    let mut out = std::io::stdout().lock();
    match result {
        Ok(_) => {
            let _ = writeln!(out, "added");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(out, "error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Makes polkit answer `result` (`YES`, `NO`) for mallory and the Snitchhiker action, or removes the rule.
fn polkit_answers(result: Option<&str>) -> Result<(), String> {
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

fn as_client(kind: &str) -> Result<String, String> {
    let (_, text) = as_mallory(
        CLIENT,
        &["--add-rule", "/run/snitchhiker/client.sock", kind],
    )?;
    Ok(text)
}

pub fn allow_everything_needs_authorization() -> Result<(), String> {
    install_clients()?;
    let mut daemon = crate::daemon::Running::start(
        "step-up",
        &format!("mode = \"monitor\"\ntrusted_clients = [\"{CLIENT}\"]\n"),
    )?;
    // No answer from polkit (no rule, and no agent to ask the user through): refused.
    polkit_answers(None)?;
    let unanswered = as_client("broad")?;
    let narrow = as_client("narrow")?;
    polkit_answers(Some("NO"))?;
    let refused = as_client("broad")?;
    polkit_answers(Some("YES"))?;
    let authorized = as_client("broad")?;
    polkit_answers(None)?;
    let root = daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--port",
        "9",
        "--name",
        "root broad",
    ]);
    let audit = daemon.cli(&["audit"])?;
    daemon.stop()?;
    let found = format!(
        "unanswered: {unanswered}narrow: {narrow}refused: {refused}authorized: {authorized}root: {root:?}\n{audit}"
    );
    check(
        unanswered.contains("not authorized") && refused.contains("not authorized"),
        "an allow-everything rule was added without authorization",
        &found,
    )?;
    check(
        narrow.trim() == "added",
        "a narrow rule needed authorization",
        &found,
    )?;
    check(
        authorized.trim() == "added",
        "an authorized allow-everything rule wasn't added",
        &found,
    )?;
    check(
        root.is_ok(),
        "root's allow-everything rule wasn't added",
        &found,
    )?;
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
