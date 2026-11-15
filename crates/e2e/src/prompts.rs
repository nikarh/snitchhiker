//! Prompts: a connection no rule decides waits while a client is asked; the answer (or the timeout) decides it, and
//! an answer can leave a rule behind.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use snitchhiker_client::{ADMIN_SOCKET, Client};
use snitchhiker_proto::v1;

use crate::daemon::Running;
use crate::util::check;

const ASK: &str =
    "mode = \"enforce\"\nno_match = \"ask\"\nno_client = \"deny\"\non_timeout = \"deny\"\n";

fn listener() -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok((listener, port))
}

/// mallory connecting to 127.0.0.1:`port` in the background; prints `connected` or `failed` and how long it took.
fn mallory_connect(port: u16, timeout_secs: u32) -> Result<Child, String> {
    let script = format!(
        "import socket, time\nt = time.monotonic()\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout={timeout_secs})\n    print('connected', round(time.monotonic() - t, 2))\nexcept OSError as e:\n    print('failed', round(time.monotonic() - t, 2), e)"
    );
    Command::new("runuser")
        .args(["-u", "mallory", "--", "python3", "-c", &script])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())
}

fn output(child: Child) -> Result<String, String> {
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A client of the admin socket, subscribed to prompts.
fn listening() -> Result<Client, String> {
    let mut client = Client::connect(Path::new(ADMIN_SOCKET), "e2e", "0")
        .map_err(|e| format!("connecting: {e}"))?;
    client
        .subscribe(v1::Topic::Prompts)
        .map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    Ok(client)
}

/// The next prompt notice (resolutions of other prompts are skipped).
fn next_prompt(client: &mut Client) -> Result<v1::Prompt, String> {
    loop {
        let notice = client
            .notice()
            .map_err(|e| format!("waiting for a prompt: {e}"))?;
        if let Some(v1::notice::Body::Prompt(prompt)) = notice.body {
            return Ok(prompt);
        }
    }
}

fn next_resolution(client: &mut Client) -> Result<v1::PromptResolved, String> {
    loop {
        let notice = client
            .notice()
            .map_err(|e| format!("waiting for a resolution: {e}"))?;
        if let Some(v1::notice::Body::PromptResolved(resolved)) = notice.body {
            return Ok(resolved);
        }
    }
}

pub fn an_answer_decides_and_leaves_a_rule() -> Result<(), String> {
    let (_listener, port) = listener()?;
    let mut daemon = Running::start("prompt-answer", ASK)?;
    let mut client = listening()?;
    let connecting = mallory_connect(port, 10)?;
    let prompt = next_prompt(&mut client)?;
    // The connection waits while nobody has answered.
    thread::sleep(Duration::from_millis(500));
    client
        .call(v1::request::Method::AnswerPrompt(v1::AnswerPrompt {
            id: prompt.id,
            action: v1::Action::Allow.into(),
            duration: v1::Duration::Forever.into(),
            suggestion: 0,
            conditions: None,
        }))
        .map_err(|e| format!("answering: {e}"))?;
    let first = output(connecting)?;
    let resolution = next_resolution(&mut client)?;
    // The rule decides the next connection, without a prompt.
    let second = output(mallory_connect(port, 3)?)?;
    let rules = daemon.cli(&["rules"])?;
    daemon.stop()?;
    let found = format!("{prompt:?}\nfirst: {first}second: {second}{rules}");
    check(
        prompt.uid == 1001 && prompt.port == u32::from(port),
        "the prompt doesn't describe the connection",
        &found,
    )?;
    check(
        prompt
            .suggestions
            .first()
            .is_some_and(|s| !s.broad && s.label.contains(&port.to_string())),
        "the first suggestion isn't the narrow rule",
        &found,
    )?;
    check(
        first.starts_with("connected"),
        "the answered connection didn't go through",
        &found,
    )?;
    check(
        resolution.rule.is_some() && resolution.by == "e2e",
        "the resolution doesn't name the rule and who answered",
        &found,
    )?;
    check(
        second.starts_with("connected"),
        "the rule the answer made didn't decide the next connection",
        &found,
    )?;
    check(
        rules.contains(&format!(":{port}")),
        "the rule isn't listed",
        &rules,
    )
}

pub fn unanswered_prompts_time_out() -> Result<(), String> {
    let (_listener, port) = listener()?;
    let mut daemon = Running::start(
        "prompt-timeout",
        "mode = \"enforce\"\nno_match = \"ask\"\nno_client = \"allow\"\non_timeout = \"deny\"\nprompt_timeout_secs = 2\n",
    )?;
    let mut client = listening()?;
    let start = Instant::now();
    let connecting = mallory_connect(port, 6)?;
    let prompt = next_prompt(&mut client)?;
    let resolution = next_resolution(&mut client)?;
    let waited = start.elapsed();
    let result = output(connecting)?;
    daemon.stop()?;
    let found = format!("{prompt:?}\n{resolution:?}\nafter {waited:?}: {result}");
    check(
        resolution.timed_out && resolution.id == prompt.id,
        "the prompt didn't time out",
        &found,
    )?;
    check(
        waited >= Duration::from_secs(2),
        "it timed out early",
        &found,
    )?;
    check(
        !result.starts_with("connected"),
        "a connection went through after its prompt timed out",
        &found,
    )
}

pub fn the_same_connections_share_a_prompt() -> Result<(), String> {
    let (_listener, port) = listener()?;
    let mut daemon = Running::start("prompt-coalesce", ASK)?;
    let mut client = listening()?;
    let first = mallory_connect(port, 10)?;
    let second = mallory_connect(port, 10)?;
    let prompt = next_prompt(&mut client)?;
    thread::sleep(Duration::from_millis(500));
    let listed = client
        .call(v1::request::Method::ListPrompts(v1::ListPrompts {}))
        .map_err(|e| e.to_string())?;
    client
        .call(v1::request::Method::AnswerPrompt(v1::AnswerPrompt {
            id: prompt.id,
            action: v1::Action::Allow.into(),
            duration: v1::Duration::Once.into(),
            suggestion: 0,
            conditions: None,
        }))
        .map_err(|e| e.to_string())?;
    let (first, second) = (output(first)?, output(second)?);
    let rules = daemon.cli(&["rules"])?;
    daemon.stop()?;
    let v1::response::Result::Prompts(listed) = listed else {
        return Err("not a prompt list".to_owned());
    };
    let found = format!("{listed:?}\n{first}{second}{rules}");
    check(
        listed.prompts.len() == 1,
        "the connections got separate prompts",
        &found,
    )?;
    check(
        listed.prompts.first().is_some_and(|p| p.waiting >= 2),
        "the prompt doesn't count both",
        &found,
    )?;
    check(
        first.starts_with("connected") && second.starts_with("connected"),
        "one answer didn't decide both connections",
        &found,
    )?;
    check(
        !rules.contains(&format!(":{port}")),
        "an answer for once left a rule",
        &rules,
    )
}

pub fn without_listeners_no_client_decides() -> Result<(), String> {
    let (_listener, port) = listener()?;
    let mut daemon = Running::start(
        "prompt-nobody",
        "mode = \"enforce\"\nno_match = \"ask\"\nno_client = \"allow\"\n",
    )?;
    let result = output(mallory_connect(port, 3)?)?;
    daemon.stop()?;
    let seconds: f64 = result
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(f64::MAX);
    check(
        result.starts_with("connected") && seconds < 1.0,
        "with nobody to ask, no_client didn't decide at once",
        &result,
    )
}
