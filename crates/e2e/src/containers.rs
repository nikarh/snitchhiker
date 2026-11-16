//! Containers (plan §5.10): their traffic is decided with their identity, and host rules don't apply to them. The
//! images are made here from the distribution's static busybox: nothing is pulled from a registry.

use std::os::unix::process::CommandExt as _;
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
    let contexts = daemon.cli(&["contexts"])?;
    let service = daemon.cli(&["contexts", "shop/api"])?;
    check(
        contexts.contains("[docker] shop/api (snitchhiker-e2e/busybox)")
            && service.contains("/bin/busybox"),
        "`snitchhiker contexts` doesn't list the service, or its program",
        &format!("{contexts}\n{service}"),
    )?;
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
    check(
        rules.contains("Containers/shop/api/"),
        "the answer's rule isn't in the service's folder",
        &rules,
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

/// What stands in for a VM: a process holding a tap on a bridge, sending a TCP SYN through it as a guest would, and
/// started with QEMU's command line (its name and UUID), as libvirt starts QEMU.
const TAP_VM: &str = r#"
import fcntl, os, socket, struct, sys, time
tap, src_mac, dst_mac, src, dst, port = sys.argv[sys.argv.index("--") + 1:]
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", tap.encode(), 0x0002 | 0x1000))  # TUNSETIFF: IFF_TAP | IFF_NO_PI
print("ready", flush=True)
sys.stdin.readline()
def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF
s, d = socket.inet_aton(src), socket.inet_aton(dst)
tcp = struct.pack("!HHIIBBHHH", 40000, int(port), 1, 0, 5 << 4, 0x02, 64240, 0, 0)
tcp = tcp[:16] + struct.pack("!H", checksum(s + d + struct.pack("!BBH", 0, 6, len(tcp)) + tcp)) + tcp[18:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, s, d)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
frame = bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00" + ip + tcp
# As a guest's TCP does: again until it gives up (the port may still be coming up for the first ones).
for _ in range(10):
    os.write(fd, frame)
    time.sleep(0.3)
"#;

/// A VM on a bridge (as libvirt's default network has it) is decided as the VM, named by its hypervisor's command
/// line: a rule on the VM's name holds, and its traffic has no program.
pub fn a_vm_on_a_bridge_is_decided_by_its_name() -> Result<(), String> {
    use std::io::{BufRead as _, Write as _};
    let daemon = Running::start("vm", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let _ = run("ip", &["link", "del", "virbr-e2e"]);
    for args in [
        // Its address fixed: a bridge otherwise takes its ports' lowest, which may change when the tap joins.
        &[
            "link",
            "add",
            "virbr-e2e",
            "address",
            "02:00:00:00:00:01",
            "type",
            "bridge",
        ][..],
        &["addr", "add", "192.168.199.1/24", "dev", "virbr-e2e"],
        &["link", "set", "virbr-e2e", "up"],
    ] {
        run("ip", args)?;
    }
    run("sysctl", &["-qw", "net.ipv4.ip_forward=1"])?;
    daemon.cli(&[
        "rules", "add", "allow", "--vm", "e2e-vm", "--port", "8095", "--name", "the VM",
    ])?;
    let bridge_mac =
        std::fs::read_to_string("/sys/class/net/virbr-e2e/address").map_err(|e| e.to_string())?;
    let send = |port: &str| -> Result<(), String> {
        let mut vm = Command::new("python3")
            .args([
                "-c",
                TAP_VM,
                "-name",
                "guest=e2e-vm,debug-threads=on",
                "-uuid",
                "6c9d4e4a-2f1b-4d33-9a51-0b7c2e1f4a10",
                "--",
                "tap-e2e",
                "02:00:00:00:00:10",
                bridge_mac.trim(),
                "192.168.199.10",
                "203.0.113.95",
                port,
            ])
            // As libvirt starts it: argv[0] is QEMU's.
            .arg0("qemu-system-x86_64")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut ready = String::new();
        std::io::BufReader::new(vm.stdout.take().ok_or("no stdout")?)
            .read_line(&mut ready)
            .map_err(|e| e.to_string())?;
        run(
            "ip",
            &["link", "set", "tap-e2e", "master", "virbr-e2e", "up"],
        )?;
        // Until the port forwards and the bridge has carrier: frames sent before are lost.
        for _ in 0..50 {
            let port = run("bridge", &["link", "show", "dev", "tap-e2e"]).unwrap_or_default();
            let bridge =
                std::fs::read_to_string("/sys/class/net/virbr-e2e/carrier").unwrap_or_default();
            if port.contains("state forwarding") && bridge.trim() == "1" {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        vm.stdin
            .take()
            .ok_or("no stdin")?
            .write_all(b"go\n")
            .map_err(|e| e.to_string())?;
        vm.wait().map_err(|e| e.to_string())?;
        Ok(())
    };
    send("8095")?;
    send("8096")?;
    let _ = run("ip", &["link", "del", "virbr-e2e"]);
    thread::sleep(Duration::from_millis(300));
    let allowed = decisions(&daemon, "203.0.113.95:8095")?;
    let denied = decisions(&daemon, "203.0.113.95:8096")?;
    let found = format!("{}\n{}", allowed.join("\n"), denied.join("\n"));
    check(
        allowed
            .iter()
            .any(|l| l.contains(" allow ") && l.contains("[qemu e2e-vm] ?")),
        "the VM's connection wasn't decided as the VM's, by its name",
        &found,
    )?;
    check(
        !denied.is_empty()
            && denied
                .iter()
                .all(|l| l.contains(" deny ") && l.contains("[qemu e2e-vm]")),
        "the rule on the VM held for another port",
        &found,
    )
}

/// A rule naming a container by its id goes when Docker removes the container (its id can never come back); a
/// container started with `CAP_NET_ADMIN` is flagged, once, with an alert.
pub fn removed_containers_take_their_id_rules_and_net_admin_is_flagged() -> Result<(), String> {
    docker()?;
    let daemon = Running::start("container-ids", "mode = \"enforce\"\nno_match = \"deny\"\n")?;
    let id = run(
        "docker",
        &["run", "-d", "--name", "e2e-bound", IMAGE, "sleep", "60"],
    )?
    .trim()
    .to_owned();
    let short = id.get(..12).unwrap_or(&id).to_owned();
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--container-id",
        &short,
        "--port",
        "8090",
        "--name",
        "this one",
    ])?;
    let before = daemon.cli(&["rules"])?;
    run("docker", &["rm", "-f", "e2e-bound"])?;
    let mut after = String::new();
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(250));
        after = daemon.cli(&["rules"])?;
        if !after.contains("this one") {
            break;
        }
    }
    let _ = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--cap-add",
            "NET_ADMIN",
            "--name",
            "e2e-admin",
            IMAGE,
        ])
        .args([
            "wget",
            "-T",
            "2",
            "-q",
            "-O",
            "/dev/null",
            "http://203.0.113.90:8080/",
        ])
        .output();
    thread::sleep(Duration::from_millis(1500));
    let alerts = daemon.cli(&["alerts"])?;
    let found = format!("before:\n{before}\nafter:\n{after}\nalerts:\n{alerts}");
    check(
        before.contains("this one") && !after.contains("this one"),
        "the removed container's rule stayed",
        &found,
    )?;
    check(
        alerts.contains("e2e-admin (") && alerts.contains("can change its network"),
        "a container with CAP_NET_ADMIN wasn't flagged",
        &found,
    )
}

/// Docker programming its firewall with nftables (`"firewall-backend": "nftables"`, Docker 28 and later) rather than
/// iptables: a bridged container's connection is still queued in the forward chain and decided by its program.
pub fn docker_on_its_nftables_backend_is_decided_too() -> Result<(), String> {
    docker()?;
    let version = run("docker", &["version", "--format", "{{.Server.Version}}"])?;
    let major: u32 = version
        .trim()
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    if major < 28 {
        // This distribution's Docker has no nftables backend: nothing to test here.
        return Ok(());
    }
    std::fs::create_dir_all("/etc/docker").map_err(|e| e.to_string())?;
    std::fs::write(
        "/etc/docker/daemon.json",
        "{\"firewall-backend\": \"nftables\"}\n",
    )
    .map_err(|e| e.to_string())?;
    let restore = || {
        let _ = std::fs::remove_file("/etc/docker/daemon.json");
        let _ = run("systemctl", &["restart", "docker"]);
    };
    let result = (|| {
        run("systemctl", &["restart", "docker"])?;
        let backend = run(
            "docker",
            &["info", "--format", "{{.FirewallBackend.Driver}}"],
        )?;
        check(
            backend.trim().starts_with("nftables"),
            "Docker didn't switch to its nftables backend",
            &backend,
        )?;
        let daemon = Running::start(
            "docker-nftables",
            "mode = \"enforce\"\nno_match = \"deny\"\n",
        )?;
        wget_in_container("http://203.0.113.80:8080/");
        thread::sleep(Duration::from_millis(500));
        daemon.cli(&[
            "rules",
            "add",
            "allow",
            "--exe",
            "/bin/busybox",
            "--any-context",
        ])?;
        wget_in_container("http://203.0.113.81:8080/");
        thread::sleep(Duration::from_millis(500));
        let denied = decisions(&daemon, "203.0.113.80:8080")?;
        let allowed = decisions(&daemon, "203.0.113.81:8080")?;
        let found = format!("{}\n{}", denied.join("\n"), allowed.join("\n"));
        check(
            denied
                .iter()
                .any(|l| l.contains("deny") && l.contains("/bin/busybox -> 203.0.113.80:8080")),
            "with Docker on nftables, the container's connection wasn't decided by its program",
            &found,
        )?;
        check(
            allowed
                .iter()
                .any(|l| l.contains("allow") && l.contains("/bin/busybox -> 203.0.113.81:8080")),
            "with Docker on nftables, a rule for the container's program didn't apply",
            &found,
        )
    })();
    restore();
    result
}
