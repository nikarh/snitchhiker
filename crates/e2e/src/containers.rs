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
