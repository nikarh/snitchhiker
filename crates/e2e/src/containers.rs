//! Containers (plan §5.10): their traffic is decided with their identity, and host rules don't apply to them. The
//! images are made here from the distribution's static busybox: nothing is pulled from a registry.

use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::daemon::Running;
use crate::util::{check, run};

const IMAGE: &str = "snitchhiker-e2e/busybox";

/// Docker running, with the test image.
fn docker() -> Result<(), String> {
    run("systemctl", &["start", "docker"])?;
    if run("docker", &["image", "inspect", IMAGE]).is_ok() {
        return Ok(());
    }
    let busybox = run("sh", &["-c", "command -v busybox"])?;
    let script = format!(
        "set -e; d=$(mktemp -d); mkdir -p $d/bin; cp {busybox} $d/bin/busybox; \
         for a in sh wget nc sleep; do ln -s busybox $d/bin/$a; done; \
         tar -C $d -c . | docker import - {IMAGE} >/dev/null; rm -rf $d",
        busybox = busybox.trim()
    );
    run("sh", &["-c", &script]).map(|_| ())
}

/// Runs `wget` to `url` in a fresh container on the default bridge network; whether it got an answer doesn't matter
/// (nothing listens there): the decision is what the test looks at.
fn wget_in_container(url: &str) {
    wget_in("e2e-anonymous", &[], url);
}

/// The same in a container named `name`, with `labels`.
fn wget_in(name: &str, labels: &[&str], url: &str) {
    let mut args = vec!["run", "--rm", "--name", name];
    for label in labels {
        args.extend(["--label", label]);
    }
    let _ = Command::new("docker")
        .args(args)
        .args([IMAGE, "wget", "-T", "2", "-q", "-O", "/dev/null", url])
        .output();
}

/// The recorded decisions about `destination`, as the command line prints them.
fn decisions(daemon: &Running, destination: &str) -> Result<Vec<String>, String> {
    Ok(daemon
        .cli(&["events", "--limit", "1000"])?
        .lines()
        .filter(|l| l.contains(destination))
        .map(str::to_owned)
        .collect())
}

/// A container on a bridge network: its connection, forwarded rather than sent from a host socket, is seen and
/// attributed to its program (as the container sees it). A host rule for that program doesn't let it out; a rule for
/// containers does.
pub fn a_bridged_containers_traffic_is_decided_by_its_program() -> Result<(), String> {
    docker()?;
    let daemon = Running::start("containers", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    // Host-only (no context): it must not apply to the container.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/bin/busybox",
        "--name",
        "busybox on the host",
    ])?;
    wget_in_container("http://203.0.113.70:8080/");
    thread::sleep(Duration::from_millis(500));
    let denied = decisions(&daemon, "203.0.113.70:8080")?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/bin/busybox",
        "--any-context",
        "--name",
        "busybox anywhere",
    ])?;
    wget_in_container("http://203.0.113.71:8080/");
    thread::sleep(Duration::from_millis(500));
    let allowed = decisions(&daemon, "203.0.113.71:8080")?;
    let found = format!(
        "with a host rule:\n{}\nwith a rule for any context:\n{}",
        denied.join("\n"),
        allowed.join("\n")
    );
    check(
        denied
            .iter()
            .any(|l| l.contains("deny") && l.contains("/bin/busybox -> 203.0.113.70:8080")),
        "the container's connection wasn't seen with its program, or the host rule let it out",
        &found,
    )?;
    check(
        allowed
            .iter()
            .any(|l| l.contains("allow") && l.contains("/bin/busybox -> 203.0.113.71:8080")),
        "a rule for any context didn't apply to the container",
        &found,
    )
}

/// Rules naming a container, by its name, its image or its Compose service (the labels Compose sets), hold for that
/// container only.
pub fn rules_name_containers_by_name_image_and_compose_service() -> Result<(), String> {
    docker()?;
    let daemon = Running::start(
        "containers-named",
        "mode = \"enforce\"\nno_match = \"deny\"\n",
    )?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--container",
        "e2e-web",
        "--port",
        "8081",
        "--name",
        "web by name",
    ])?;
    daemon.cli(&[
        "rules", "add", "allow", "--image", IMAGE, "--port", "8082", "--name", "by image",
    ])?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--compose",
        "shop/api",
        "--port",
        "8083",
        "--name",
        "api by service",
    ])?;
    let compose = [
        "com.docker.compose.project=shop",
        "com.docker.compose.service=api",
    ];
    wget_in("e2e-web", &[], "http://203.0.113.72:8081/");
    wget_in("e2e-other", &[], "http://203.0.113.73:8081/");
    wget_in("e2e-other", &[], "http://203.0.113.74:8082/");
    wget_in("e2e-api", &compose, "http://203.0.113.75:8083/");
    wget_in("e2e-other", &[], "http://203.0.113.76:8083/");
    thread::sleep(Duration::from_millis(500));
    let mut seen = Vec::new();
    for address in [
        "203.0.113.72",
        "203.0.113.73",
        "203.0.113.74",
        "203.0.113.75",
        "203.0.113.76",
    ] {
        let decided = decisions(&daemon, address)?;
        seen.push((
            address,
            decided.iter().any(|l| l.contains(" allow ")),
            decided,
        ));
    }
    let found = format!("{seen:#?}");
    let allowed: Vec<&str> = seen
        .iter()
        .filter(|(_, allowed, _)| *allowed)
        .map(|(a, _, _)| *a)
        .collect();
    check(
        allowed == ["203.0.113.72", "203.0.113.74", "203.0.113.75"],
        "rules on a container's name, image or Compose service didn't hold for exactly that container",
        &found,
    )
}

/// A container's prompt names the container, its suggestions hold for its Compose service, and the rule an answer
/// leaves lets another container of the service through, but not a container of another.
pub fn a_containers_prompt_names_it_and_its_answer_holds_for_its_service() -> Result<(), String> {
    use snitchhiker_client::{ADMIN_SOCKET, Client};
    use snitchhiker_proto::v1;
    docker()?;
    let daemon = Running::start(
        "containers-prompt",
        "mode = \"enforce\"\nno_match = \"ask\"\nno_client = \"deny\"\non_timeout = \"deny\"\n",
    )?;
    let mut client = Client::connect(std::path::Path::new(ADMIN_SOCKET), "e2e", "0")
        .map_err(|e| format!("connecting: {e}"))?;
    client
        .subscribe(v1::Topic::Prompts)
        .map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    let service = [
        "com.docker.compose.project=shop",
        "com.docker.compose.service=api",
    ];
    let first = thread::spawn(move || wget_in("e2e-api-1", &service, "http://203.0.113.80:8090/"));
    let prompt = loop {
        let notice = client
            .notice()
            .map_err(|e| format!("waiting for a prompt: {e}"))?;
        if let Some(v1::notice::Body::Prompt(prompt)) = notice.body
            && prompt.container.is_some()
        {
            break prompt;
        }
    };
    client
        .call(v1::request::Method::AnswerPrompt(v1::AnswerPrompt {
            id: prompt.id,
            action: v1::Action::Allow.into(),
            duration: v1::Duration::Forever.into(),
            suggestion: 0,
            conditions: None,
            folder: None,
        }))
        .map_err(|e| format!("answering: {e}"))?;
    let _ = first.join();
    // Another container of the service: the rule decides, without a prompt.
    wget_in("e2e-api-2", &service, "http://203.0.113.80:8090/");
    // Nobody listening any more: a container of no service is decided by the policy (deny).
    drop(client);
    wget_in("e2e-other", &[], "http://203.0.113.80:8090/");
    thread::sleep(Duration::from_millis(500));
    let decided = decisions(&daemon, "203.0.113.80:8090")?;
    let rules = daemon.cli(&["rules"])?;
    let found = format!("{prompt:#?}\n{}\n{rules}", decided.join("\n"));
    let container = prompt.container.as_deref();
    check(
        container.is_some_and(|c| {
            c.runtime == "docker"
                && c.name == "e2e-api-1"
                && c.image == IMAGE
                && c.compose == "shop/api"
        }),
        "the prompt doesn't name the container",
        &found,
    )?;
    check(
        prompt.suggestions.first().is_some_and(|s| {
            s.label.starts_with("in shop/api: ")
                && s.conditions
                    .as_ref()
                    .and_then(|c| c.container.as_ref())
                    .is_some_and(|c| c.compose == ["shop/api"])
        }),
        "the first suggestion isn't for the container's service",
        &found,
    )?;
    let service: Vec<&String> = decided
        .iter()
        .filter(|l| l.contains("[docker shop/api]"))
        .collect();
    let other: Vec<&String> = decided
        .iter()
        .filter(|l| l.contains("[docker e2e-other]"))
        .collect();
    check(
        service.len() >= 2
            && service.iter().all(|l| l.contains(" allow "))
            && !other.is_empty()
            && other.iter().all(|l| l.contains(" deny ")),
        "the answer's rule didn't let the service's other container through, or let another container through",
        &found,
    )
}

/// Podman, rootful (as root) and rootless (as mallory, with pasta), with the test image.
fn podman() -> Result<(), String> {
    let build = |import: &str| {
        let busybox = run("sh", &["-c", "command -v busybox"])?;
        let script = format!(
            "set -e; d=$(mktemp -d); mkdir -p $d/bin; cp {busybox} $d/bin/busybox; \
             for a in sh wget nc sleep; do ln -s busybox $d/bin/$a; done; chmod -R a+rX $d; \
             tar -C $d -c . | {import} >/dev/null; rm -rf $d",
            busybox = busybox.trim()
        );
        run("sh", &["-c", &script]).map(|_| ())
    };
    if run("podman", &["image", "exists", IMAGE]).is_err() {
        build(&format!("podman import - {IMAGE}"))?;
    }
    run("loginctl", &["enable-linger", "mallory"])?;
    if rootless(&["image", "exists", IMAGE]).is_err() {
        build(&format!(
            "runuser -l mallory -c 'XDG_RUNTIME_DIR=/run/user/1001 podman import - {IMAGE}'"
        ))?;
    }
    Ok(())
}

/// `podman <args>` as mallory.
fn rootless(args: &[&str]) -> Result<String, String> {
    run(
        "runuser",
        &[
            "-l",
            "mallory",
            "-c",
            &format!("XDG_RUNTIME_DIR=/run/user/1001 podman {}", args.join(" ")),
        ],
    )
}

/// Rules on a container and on a program: `--container <name> --port <port>` and the program by any context.
fn podman_rules(daemon: &Running) -> Result<(), String> {
    for (container, port) in [("e2e-rootful", "8091"), ("e2e-rootless", "8092")] {
        daemon.cli(&[
            "rules",
            "add",
            "allow",
            "--container",
            container,
            "--port",
            port,
            "--name",
            container,
        ])?;
    }
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/bin/busybox",
        "--any-context",
        "--port",
        "8093",
        "--name",
        "the program",
    ])?;
    Ok(())
}

const WGET: &str = "wget -T 2 -q -O /dev/null";

/// A rootful Podman container on its bridge is decided by its program and name, as Docker's.
pub fn a_rootful_podman_container_is_decided_by_its_program() -> Result<(), String> {
    podman()?;
    let daemon = Running::start(
        "containers-podman",
        "mode = \"enforce\"\nno_match = \"deny\"\n",
    )?;
    podman_rules(&daemon)?;
    let _ = run(
        "podman",
        &[
            "run",
            "--rm",
            "--name",
            "e2e-rootful",
            IMAGE,
            "sh",
            "-c",
            &format!("{WGET} http://203.0.113.90:8091/"),
        ],
    );
    thread::sleep(Duration::from_millis(500));
    let rootful = decisions(&daemon, "203.0.113.90:8091")?;
    check(
        rootful
            .iter()
            .any(|l| l.contains(" allow ") && l.contains("[podman e2e-rootful] /bin/busybox")),
        "the rootful container wasn't decided by its name and program",
        &rootful.join("\n"),
    )
}

/// A rootless Podman container's connections are made by its network helper (pasta) on the host. The first is
/// decided as the container's, the program inside unknown (a rule on the container holds); from then on the daemon
/// decides inside the container's namespace, where the program is known (a rule on it holds). Something in there
/// deleting the daemon's table gets it put back, and an alert.
pub fn a_rootless_podman_container_is_decided_inside_its_namespace() -> Result<(), String> {
    podman()?;
    let daemon = Running::start(
        "containers-rootless",
        "mode = \"enforce\"\nno_match = \"deny\"\n",
    )?;
    podman_rules(&daemon)?;
    let _ = rootless(&["rm", "-f", "e2e-rootless"]);
    rootless(&["run", "-d", "--name", "e2e-rootless", IMAGE, "sleep", "120"])?;
    let exec = |address: &str, port: u16| {
        let _ = rootless(&[
            "exec",
            "e2e-rootless",
            "sh",
            "-c",
            &format!("'{WGET} http://{address}:{port}/'"),
        ]);
    };
    exec("203.0.113.91", 8092);
    thread::sleep(Duration::from_secs(1));
    exec("203.0.113.92", 8093);
    let pid = rootless(&["inspect", "-f", "'{{.State.Pid}}'", "e2e-rootless"])?;
    let nft = |args: &[&str]| {
        let mut all = vec!["-t", pid.trim(), "-n", "nft"];
        all.extend(args);
        run("nsenter", &all)
    };
    let deleted = nft(&["delete", "table", "inet", "snitchhiker"]);
    thread::sleep(Duration::from_millis(500));
    let restored = nft(&["list", "table", "inet", "snitchhiker"]);
    let alerts = daemon.cli(&["alerts"])?;
    let _ = rootless(&["rm", "-f", "e2e-rootless"]);
    thread::sleep(Duration::from_millis(500));
    let named = decisions(&daemon, "203.0.113.91:8092")?;
    let program = decisions(&daemon, "203.0.113.92:8093")?;
    let found = format!(
        "a rule on its name:\n{}\na rule on the program:\n{}",
        named.join("\n"),
        program.join("\n")
    );
    check(
        named
            .iter()
            .any(|l| l.contains(" allow ") && l.contains("[podman e2e-rootless]")),
        "the rootless container's connection (made by pasta) wasn't decided as the container's",
        &found,
    )?;
    check(
        program
            .iter()
            .any(|l| l.contains(" allow ") && l.contains("[podman e2e-rootless] /bin/busybox")),
        "inside a rootless container's namespace, a rule on the program didn't hold",
        &found,
    )?;
    check(
        deleted.is_ok()
            && restored.is_ok()
            && alerts
                .contains("Something in a container removed the daemon's nftables table there"),
        "the table deleted inside the container's namespace wasn't put back, or nobody was told",
        &format!("deleted: {deleted:?}\nrestored: {restored:?}\n{alerts}"),
    )
}

/// A named network namespace (`ip netns`): nothing in it passes the host's tables, so the daemon decides inside it,
/// from when it is mounted: its connections carry its name, a rule on the namespace holds, and when it is deleted
/// the daemon lets it go.
pub fn a_named_namespaces_traffic_is_decided_inside_it() -> Result<(), String> {
    let daemon = Running::start("netns", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let _ = run("ip", &["netns", "del", "e2e-ns"]);
    run("ip", &["netns", "add", "e2e-ns"])?;
    run(
        "ip",
        &["netns", "exec", "e2e-ns", "ip", "link", "set", "lo", "up"],
    )?;
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--netns",
        "e2e-ns",
        "--port",
        "9101",
        "--name",
        "the namespace",
    ])?;
    thread::sleep(Duration::from_secs(1));
    let curl = |port: u16| {
        let _ = run(
            "ip",
            &[
                "netns",
                "exec",
                "e2e-ns",
                "runuser",
                "-u",
                "mallory",
                "--",
                "curl",
                "-s",
                "-m",
                "2",
                &format!("http://127.0.0.1:{port}/"),
            ],
        );
    };
    curl(9100);
    curl(9101);
    run("ip", &["netns", "del", "e2e-ns"])?;
    thread::sleep(Duration::from_millis(500));
    let denied = decisions(&daemon, "127.0.0.1:9100")?;
    let allowed = decisions(&daemon, "127.0.0.1:9101")?;
    let log = std::fs::read_to_string("/tmp/snitchhiker-daemon-test/netns/daemon.log")
        .unwrap_or_default();
    let found = format!("{}\n{}\n{log}", denied.join("\n"), allowed.join("\n"));
    check(
        denied
            .iter()
            .any(|l| l.contains(" deny ") && l.contains("[netns e2e-ns] /usr/bin/curl")),
        "a connection in the named namespace wasn't decided inside it, with its name",
        &found,
    )?;
    check(
        allowed
            .iter()
            .any(|l| l.contains(" allow ") && l.contains("[netns e2e-ns] /usr/bin/curl")),
        "a rule on the namespace didn't hold",
        &found,
    )?;
    check(
        log.contains("a network namespace is let go")
            || log.contains("deciding inside a network namespace"),
        "the daemon didn't start deciding inside the namespace",
        &found,
    )
}
