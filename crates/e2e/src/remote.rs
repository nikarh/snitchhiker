//! Paired devices over the network (iroh, through the node's remote service `snitchhiker-remote`): a device pairs
//! with a link's one-time secret and then connects with its key; an unpaired key is refused, a secret works once, and
//! unpairing closes the device's connections. The daemon serves the remote service's user alone, and that service's
//! traffic is the node's own.

use std::thread;
use std::time::Duration;

use snitchhiker_client::remote::{connect, pair};
use snitchhiker_proto::v1;
use snitchhiker_remote::{Key, Options, PairLink};

use crate::daemon::Running;
use crate::util::{check, run};

fn link(daemon: &Running, name: &str) -> Result<PairLink, String> {
    let printed = daemon.cli(&["pair", "--name", name])?;
    printed
        .lines()
        .find(|l| l.starts_with("snitchhiker://pair?"))
        .ok_or_else(|| format!("no link printed:\n{printed}"))?
        .parse()
}

fn status(client: &mut snitchhiker_client::Client) -> Result<v1::Status, String> {
    match client
        .call(v1::request::Method::GetStatus(v1::GetStatus {}))
        .map_err(|e| e.to_string())?
    {
        v1::response::Result::Status(status) => Ok(status),
        _ => Err("not a status".to_owned()),
    }
}

pub fn a_paired_device_connects_and_is_unpaired() -> Result<(), String> {
    let daemon = Running::start("remote", "mode = \"monitor\"\n[remote]\n")?;
    let options = Options::default();
    let device = Key::generate();
    let first = link(&daemon, "laptop")?;
    let printed_qr = daemon.cli(&["pair"])?;
    // The link's secret pairs once.
    let paired = pair(&device, &first, "my laptop", &options).map_err(|e| e.to_string())?;
    let reused = pair(&Key::generate(), &first, "intruder", &options);
    let mut client =
        connect(&device, &first.node, &options, "e2e", "0").map_err(|e| e.to_string())?;
    let role = client.welcome().role();
    let remote_status = status(&mut client)?;
    let stranger = connect(&Key::generate(), &first.node, &options, "e2e", "0")
        .and_then(|mut c| c.call(v1::request::Method::GetStatus(v1::GetStatus {})));
    let devices = daemon.cli(&["devices"])?;
    daemon.cli(&["devices", "rm", &device.id()])?;
    thread::sleep(Duration::from_millis(500));
    let after = status(&mut client);
    let alerts = daemon.cli(&["alerts"])?;
    let found = format!(
        "paired: {paired:?}\nreused: {reused:?}\nrole: {role:?}\nstranger: {:?}\n{devices}\nafter: {after:?}\n{alerts}",
        stranger.as_ref().map(|_| "connected")
    );
    check(
        printed_qr.contains('█') || printed_qr.contains('▀'),
        "pair doesn't print a QR code",
        &printed_qr,
    )?;
    check(
        paired.role() == v1::Role::Admin
            && role == v1::Role::Admin
            && remote_status.daemon_version.len() > 1,
        "the paired device didn't connect as an admin",
        &found,
    )?;
    check(
        reused.is_err() && alerts.contains("tried to pair with a wrong secret"),
        "a used pairing secret paired again, or wasn't reported",
        &found,
    )?;
    check(stranger.is_err(), "an unpaired key was served", &found)?;
    check(
        devices.contains(&device.id())
            && devices.contains("laptop")
            && devices.contains("connected"),
        "the device isn't listed as paired and connected, with the name the node gave it",
        &found,
    )?;
    check(
        after.is_err(),
        "unpairing didn't close the device's connection",
        &found,
    )
}

/// A relay of the user's, plain HTTP on loopback (TLS is a reverse proxy's job, or ACME's, in a deployment).
struct Relay(std::process::Child);

impl Relay {
    fn start(allow: &[String]) -> Result<Self, String> {
        let dir = "/tmp/snitchhiker-relay-test";
        let _ = std::fs::create_dir_all(dir);
        let allow: Vec<String> = allow.iter().map(|a| format!("\"{a}\"")).collect();
        std::fs::write(
            format!("{dir}/relay.toml"),
            format!(
                "http_bind = \"127.0.0.1:3340\"\nallow = [{}]\n",
                allow.join(", ")
            ),
        )
        .map_err(|e| e.to_string())?;
        let child = std::process::Command::new("snitchhiker-relay")
            .args(["--config", &format!("{dir}/relay.toml")])
            .stdout(std::process::Stdio::null())
            .stderr(std::fs::File::create(format!("{dir}/relay.log")).map_err(|e| e.to_string())?)
            .spawn()
            .map_err(|e| format!("starting snitchhiker-relay: {e}"))?;
        thread::sleep(Duration::from_secs(1));
        Ok(Self(child))
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const RELAY: &str = "http://127.0.0.1:3340";

/// With no direct address known, a device reaches the node through the relay; a relay with an allow-list turns
/// away keys it doesn't list.
pub fn a_device_connects_through_the_relay() -> Result<(), String> {
    let relay = Relay::start(&[])?;
    let mut daemon = Running::start(
        "remote-relay",
        &format!("mode = \"monitor\"\n[remote]\nrelays = [\"{RELAY}\"]\n"),
    )?;
    let options = Options::default();
    let device = Key::generate();
    let mut link = link(&daemon, "phone")?;
    let relays = link.node.relays.clone();
    // Only the relay: no direct address.
    link.node.addrs.clear();
    let paired = pair(&device, &link, "phone", &options).map_err(|e| e.to_string());
    let connected = connect(&device, &link.node, &options, "e2e", "0")
        .map_err(|e| e.to_string())
        .and_then(|mut c| status(&mut c));
    drop(relay);
    // Restarted with an allow-list that has the node but not the device: the device can't reach it.
    let node_id = link.node.id.clone();
    let relay = Relay::start(&[node_id])?;
    daemon.restart(&format!(
        "mode = \"monitor\"\n[remote]\nrelays = [\"{RELAY}\"]\n"
    ))?;
    thread::sleep(Duration::from_secs(2));
    let refused = connect(&device, &link.node, &options, "e2e", "0")
        .map_err(|e| e.to_string())
        .and_then(|mut c| status(&mut c));
    drop(relay);
    let log = std::fs::read_to_string("/tmp/snitchhiker-relay-test/relay.log").unwrap_or_default();
    let found = format!(
        "relays in the link: {relays:?}\npaired: {paired:?}\nconnected: {:?}\nrefused: {:?}\n{log}",
        connected.as_ref().map(|s| &s.daemon_version),
        refused.as_ref().map(|s| &s.daemon_version)
    );
    check(
        relays.iter().any(|r| r.starts_with(RELAY)),
        "the link doesn't name the node's relay",
        &found,
    )?;
    check(
        paired.is_ok() && connected.is_ok(),
        "the device didn't pair and connect through the relay",
        &found,
    )?;
    check(
        refused.is_err(),
        "a key the relay doesn't allow got through it",
        &found,
    )
}

/// `snitchhiker-e2e --remote-device <link>`: pairs a new device with the link's node and asks it for its status;
/// prints `connected <daemon version>` or the error. Run inside the client's network namespace.
pub fn device(link: &str) -> std::process::ExitCode {
    use std::io::Write as _;
    let result = (|| -> Result<String, String> {
        let link: PairLink = link.parse()?;
        let key = Key::generate();
        let options = Options::default();
        pair(&key, &link, "behind nat", &options).map_err(|e| format!("pairing: {e}"))?;
        let mut client = connect(&key, &link.node, &options, "e2e", "0")
            .map_err(|e| format!("connecting: {e}"))?;
        Ok(status(&mut client)?.daemon_version)
    })();
    let mut out = std::io::stdout().lock();
    match result {
        Ok(version) => {
            let _ = writeln!(out, "connected {version}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(out, "error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Network namespaces: a client behind a NAT router; the node and the relay on the "internet" side.
struct Nat;

const NAT_SETUP: &str = "
set -e
ip netns add sh-router
ip netns add sh-client
ip link add sh-up type veth peer name sh-r-up
ip link set sh-r-up netns sh-router
ip addr add 10.200.0.1/24 dev sh-up
ip link set sh-up up
ip -n sh-router addr add 10.200.0.2/24 dev sh-r-up
ip -n sh-router link set sh-r-up up
ip -n sh-router link set lo up
ip link add sh-r-in netns sh-router type veth peer name sh-c-out netns sh-client
ip -n sh-router addr add 10.201.0.1/24 dev sh-r-in
ip -n sh-router link set sh-r-in up
ip -n sh-client addr add 10.201.0.2/24 dev sh-c-out
ip -n sh-client link set sh-c-out up
ip -n sh-client link set lo up
ip -n sh-client route add default via 10.201.0.1
ip -n sh-router route add default via 10.200.0.1
ip netns exec sh-router sysctl -qw net.ipv4.ip_forward=1
ip netns exec sh-router nft -f - <<NFT
table ip nat {
  chain postrouting { type nat hook postrouting priority srcnat; oifname \"sh-r-up\" masquerade; }
}
NFT
";

impl Nat {
    fn start() -> Result<Self, String> {
        Self::remove();
        crate::util::run("bash", &["-c", NAT_SETUP])?;
        Ok(Self)
    }

    fn remove() {
        let _ = crate::util::run("ip", &["netns", "del", "sh-client"]);
        let _ = crate::util::run("ip", &["netns", "del", "sh-router"]);
        let _ = crate::util::run("ip", &["link", "del", "sh-up"]);
    }
}

impl Drop for Nat {
    fn drop(&mut self) {
        Self::remove();
    }
}

/// A device behind NAT reaches a node that drops unsolicited inbound traffic (its system firewall), through the
/// node's relay or a path punched through both.
pub fn a_device_behind_nat_reaches_a_firewalled_node() -> Result<(), String> {
    let _nat = Nat::start()?;
    let relay_url = "http://10.200.0.1:3340";
    let relay = {
        let dir = "/tmp/snitchhiker-relay-test";
        let _ = std::fs::create_dir_all(dir);
        std::fs::write(
            format!("{dir}/relay.toml"),
            "http_bind = \"10.200.0.1:3340\"\n",
        )
        .map_err(|e| e.to_string())?;
        let child = std::process::Command::new("snitchhiker-relay")
            .args(["--config", &format!("{dir}/relay.toml")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_secs(1));
        Relay(child)
    };
    let daemon = Running::start(
        "remote-nat",
        &format!("mode = \"monitor\"\n[remote]\nrelays = [\"{relay_url}/\"]\n"),
    )?;
    // Inbound dropped but for SSH (the harness's way in) and the relay (here on the same machine; a deployment's is
    // elsewhere), as OpenSnitch's file says it.
    crate::util::run(
        "bash",
        &[
            "-c",
            "printf '%s' '{\"Enabled\": true, \"SystemRules\": [{\"Chains\": [{\"Name\": \"filter_input\", \"Family\": \"inet\", \"Type\": \"filter\", \"Hook\": \"input\", \"Policy\": \"drop\", \"Rules\": [{\"Enabled\": true, \"Description\": \"SSH\", \"Expressions\": [{\"Statement\": {\"Op\": \"\", \"Name\": \"tcp\", \"Values\": [{\"Key\": \"dport\", \"Value\": \"22\"}]}}], \"Target\": \"accept\"}, {\"Enabled\": true, \"Description\": \"the relay\", \"Expressions\": [{\"Statement\": {\"Op\": \"\", \"Name\": \"tcp\", \"Values\": [{\"Key\": \"dport\", \"Value\": \"3340\"}]}}], \"Target\": \"accept\"}]}]}]}' | snitchhiker system import-opensnitch /dev/stdin",
        ],
    )?;
    let firewall = daemon.cli(&["system"])?;
    let link = link(&daemon, "")?;
    let reached = crate::util::run(
        "ip",
        &[
            "netns",
            "exec",
            "sh-client",
            "snitchhiker-e2e",
            "--remote-device",
            &link.to_string(),
        ],
    );
    let _ = daemon.cli(&["system", "off"]);
    drop(relay);
    let found = format!("link: {link}\n{firewall}\nreached: {reached:?}");
    check(
        firewall.contains("system firewall on, input drop"),
        "the node's system firewall isn't dropping inbound traffic",
        &found,
    )?;
    check(
        reached.as_ref().is_ok_and(|r| r.starts_with("connected ")),
        "the device behind NAT didn't reach the node",
        &found,
    )
}

/// A remote device's dangerous request waits for a local approval: approved, it goes ahead; denied, it is refused.
pub fn a_devices_dangerous_request_waits_for_approval() -> Result<(), String> {
    let daemon = Running::start("remote-approval", "mode = \"monitor\"\n[remote]\n")?;
    let options = Options::default();
    let device = Key::generate();
    let link = link(&daemon, "phone")?;
    pair(&device, &link, "phone", &options).map_err(|e| e.to_string())?;
    // Letting through what the policy blocks: a dangerous action. Each request loosens a different setting, so the
    // second still loosens after the first went ahead.
    let ask = {
        let device = device.clone();
        let node = link.node.clone();
        move |no_match: bool| {
            let mut client = connect(&device, &node, &Options::default(), "e2e", "0")
                .map_err(|e| e.to_string())?;
            let set = if no_match {
                v1::SetPolicy {
                    no_match: Some(v1::Policy::Allow.into()),
                    ..v1::SetPolicy::default()
                }
            } else {
                v1::SetPolicy {
                    on_timeout: Some(v1::Action::Allow.into()),
                    ..v1::SetPolicy::default()
                }
            };
            match client.call(v1::request::Method::SetPolicy(set)) {
                Ok(v1::response::Result::Error(error)) => Err(error.message),
                Ok(_) => Ok("set".to_owned()),
                Err(e) => Err(e.to_string()),
            }
        }
    };
    let mut outcomes = Vec::new();
    let mut listed = String::new();
    for (verb, no_match) in [("approve", true), ("deny", false)] {
        let waiting = thread::spawn({
            let ask = ask.clone();
            move || ask(no_match)
        });
        let mut id = None;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(200));
            let list = daemon.cli(&["approvals"])?;
            id = list.lines().find_map(|l| {
                l.strip_prefix("request ")?
                    .split(':')
                    .next()?
                    .parse::<u64>()
                    .ok()
            });
            if id.is_some() {
                listed.push_str(&list);
                break;
            }
        }
        let id = id.ok_or_else(|| format!("no request waited\n{listed}"))?;
        daemon.cli(&["approvals", verb, &id.to_string()])?;
        outcomes.push(
            waiting
                .join()
                .map_err(|_| "the request panicked")?
                .unwrap_or_else(|e| e),
        );
    }
    let audit = daemon.cli(&["audit"])?;
    let found = format!("{listed}\noutcomes: {outcomes:?}\n{audit}");
    check(
        listed.contains("phone") && listed.contains("change the policy"),
        "the request didn't say which device asked for what",
        &found,
    )?;
    check(
        outcomes.first().is_some_and(|o| o == "set")
            && outcomes
                .get(1)
                .is_some_and(|o| o.contains("not authorized")),
        "an approved request didn't go ahead, or a denied one did",
        &found,
    )
}

/// The prompts a remote client gets within `wait`, with their notify flags.
fn prompts_seen(client: &mut snitchhiker_client::Client, wait: Duration) -> Vec<(u64, bool)> {
    let deadline = std::time::Instant::now() + wait;
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        if client
            .set_read_timeout(Some(left.max(Duration::from_millis(10))))
            .is_err()
        {
            break;
        }
        match client.notice() {
            Ok(notice) => {
                if let Some(v1::notice::Body::Prompt(prompt)) = notice.body {
                    seen.push((prompt.id, prompt.notify));
                }
            }
            Err(_) => break,
        }
    }
    seen
}

/// With escalation, a device gets a prompt quietly, then (no one being at the node) escalated with a notification; a
/// muted device is never notified.
pub fn prompts_escalate_to_devices_and_not_to_muted_ones() -> Result<(), String> {
    let daemon = Running::start(
        "remote-routing",
        "mode = \"enforce\"\nno_match = \"ask\"\nprompt_timeout_secs = 20\nprompt_routing = \"escalate\"\nescalate_after_secs = 2\n[remote]\n",
    )?;
    // This test's own connections to the node are a program's like any other's.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/usr/local/bin/snitchhiker-e2e",
        "--name",
        "the test",
    ])?;
    let options = Options::default();
    let (loud, quiet) = (Key::generate(), Key::generate());
    let first = link(&daemon, "loud")?;
    pair(&loud, &first, "loud", &options).map_err(|e| e.to_string())?;
    let second = link(&daemon, "quiet")?;
    pair(&quiet, &second, "quiet", &options).map_err(|e| e.to_string())?;
    daemon.cli(&["devices"])?;
    let mut loud_client =
        connect(&loud, &first.node, &options, "e2e", "0").map_err(|e| e.to_string())?;
    let mut quiet_client =
        connect(&quiet, &first.node, &options, "e2e", "0").map_err(|e| e.to_string())?;
    for client in [&mut loud_client, &mut quiet_client] {
        client
            .subscribe(v1::Topic::Prompts)
            .map_err(|e| e.to_string())?;
    }
    quiet_client
        .call(v1::request::Method::SetDeviceMuted(v1::SetDeviceMuted {
            id: quiet.id(),
            muted: true,
        }))
        .map_err(|e| e.to_string())?;
    // A connection no rule decides: a prompt.
    let _ = std::process::Command::new("runuser")
        .args([
            "-u",
            "mallory",
            "--",
            "curl",
            "-s",
            "-m",
            "1",
            "http://192.0.2.88:9",
        ])
        .output();
    let loud_seen = prompts_seen(&mut loud_client, Duration::from_secs(4));
    let quiet_seen = prompts_seen(&mut quiet_client, Duration::from_secs(1));
    let devices = daemon.cli(&["devices"])?;
    let found = format!("loud: {loud_seen:?}\nquiet: {quiet_seen:?}\n{devices}");
    check(
        loud_seen.first().is_some_and(|(_, notify)| !notify)
            && loud_seen.iter().any(|(_, notify)| *notify),
        "the device didn't get the prompt quietly, then escalated",
        &found,
    )?;
    check(
        !quiet_seen.is_empty() && quiet_seen.iter().all(|(_, notify)| !notify),
        "the muted device was notified, or didn't get the prompt to list",
        &found,
    )
}

fn code_of(printed: &str) -> Result<snitchhiker_remote::code::Code, String> {
    printed
        .lines()
        .find_map(|l| l.split_once("this code").map(|(_, rest)| rest))
        .and_then(|rest| rest.rsplit(' ').next())
        .ok_or_else(|| format!("no code printed:\n{printed}"))?
        .trim()
        .parse()
}

/// A device pairs by typing the node's code (found on the LAN by mDNS); a wrong code is spent, and reported.
pub fn a_device_pairs_by_code_on_the_lan() -> Result<(), String> {
    use snitchhiker_client::remote::pair_with_code;
    let daemon = Running::start("remote-code", "mode = \"monitor\"\n[remote]\n")?;
    let options = Options {
        lan: true,
        ..Options::default()
    };
    let device = Key::generate();
    let printed = daemon.cli(&["pair", "--name", "tablet"])?;
    let code = code_of(&printed)?;
    let paired = pair_with_code(&device, &code, "tablet", &options).map_err(|e| e.to_string());
    let connected = paired
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|(link, _)| {
            connect(&device, &link.node, &options, "e2e", "0").map_err(|e| e.to_string())
        })
        .and_then(|mut c| status(&mut c));
    // A wrong guess spends the code: the right one fails after it.
    let second = code_of(&daemon.cli(&["pair"])?)?;
    let mut wrong = second.clone();
    let replacement = if wrong.words[0] == "zoo" {
        "zone"
    } else {
        "zoo"
    };
    replacement.clone_into(&mut wrong.words[0]);
    let guessed =
        pair_with_code(&Key::generate(), &wrong, "intruder", &options).map_err(|e| e.to_string());
    let after =
        pair_with_code(&Key::generate(), &second, "late", &options).map_err(|e| e.to_string());
    let alerts = daemon.cli(&["alerts"])?;
    let devices = daemon.cli(&["devices"])?;
    let found = format!(
        "{printed}\npaired: {:?}\nconnected: {:?}\nguessed: {guessed:?}\nafter: {after:?}\n{alerts}\n{devices}",
        paired
            .as_ref()
            .map(|(link, response)| (&link.name, response.role())),
        connected.as_ref().map(|s| &s.daemon_version)
    );
    check(
        paired.is_ok() && connected.is_ok() && devices.contains("tablet"),
        "the device didn't pair by the code and connect",
        &found,
    )?;
    check(
        guessed.is_err() && after.is_err() && alerts.contains("pairing code with the wrong words"),
        "a wrong code wasn't refused, didn't spend the code, or wasn't reported",
        &found,
    )
}

/// A client of another major version of the protocol is refused at the handshake (its ALPN), before anything else.
pub fn another_major_version_is_refused() -> Result<(), String> {
    let daemon = Running::start("remote-version", "mode = \"monitor\"\n[remote]\n")?;
    let device = Key::generate();
    let link = link(&daemon, "")?;
    pair(&device, &link, "old", &Options::default()).map_err(|e| e.to_string())?;
    let other =
        snitchhiker_remote::connect(&device, &link.node, &Options::default(), b"snitchhiker/2")
            .and_then(|mut c| {
                use std::io::{Read as _, Write as _};
                c.stream.write_all(b"SNHK\x02\x00")?;
                let mut buffer = [0; 1];
                c.stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                match c.stream.read(&mut buffer)? {
                    0 => Err(std::io::Error::other("closed")),
                    _ => Ok(()),
                }
            });
    let same =
        connect(&device, &link.node, &Options::default(), "e2e", "0").map_err(|e| e.to_string());
    let found = format!(
        "other: {other:?}\nsame: {:?}",
        same.as_ref().map(|_| "connected")
    );
    check(
        other.is_err(),
        "a client of another major version was served",
        &found,
    )?;
    check(
        same.is_ok(),
        "a client of this version wasn't served",
        &found,
    )
}

/// The node's key sealed with `snitchhiker-remote seal-key`: the plaintext is gone, the packaged service gets the key
/// from systemd (`ImportCredential=`), and the node keeps its id.
pub fn the_node_key_is_sealed_and_keeps_its_id() -> Result<(), String> {
    const KEY: &str = "/var/lib/snitchhiker-remote/node.key";
    const SEALED: &str = "/etc/credstore.encrypted/snitchhiker.node-key";
    let result = (|| {
        let _ = std::fs::remove_file(KEY);
        let _ = std::fs::remove_file(SEALED);
        run(
            "systemctl",
            &["restart", "snitchhikerd", "snitchhiker-remote"],
        )?;
        let before = wait_for_node_id()?;
        let sealed = run("snitchhiker-remote", &["seal-key"])?;
        let plaintext = std::path::Path::new(KEY).exists();
        run("systemctl", &["restart", "snitchhiker-remote"])?;
        let after = wait_for_node_id()?;
        let log = run(
            "journalctl",
            &["-u", "snitchhiker-remote", "--no-pager", "-n", "30"],
        )
        .unwrap_or_default();
        let found = format!("{sealed}\nbefore: {before}\nafter: {after}\n{log}");
        check(!plaintext, "the plaintext key is still on the disk", &found)?;
        check(
            !before.is_empty() && before == after,
            "the node's id changed across sealing",
            &found,
        )?;
        check(
            log.contains("the node's key is the sealed credential"),
            "the service didn't use the sealed key",
            &found,
        )
    })();
    let _ = run("systemctl", &["stop", "snitchhiker-remote", "snitchhikerd"]);
    let _ = std::fs::remove_file(SEALED);
    result
}

/// The node's id, once the packaged remote service has connected to the packaged daemon.
fn wait_for_node_id() -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let devices = run("snitchhiker", &["devices"]).unwrap_or_default();
        if let Some(id) = devices
            .lines()
            .find(|l| l.contains("node"))
            .and_then(|l| l.split_whitespace().find(|w| w.len() == 64))
        {
            return Ok(id.to_owned());
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("the remote service didn't connect:\n{devices}"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Runs `snitchhiker-remote` as `user` with a configuration and key of its own; its exit status and log.
fn bridge_as(user: &str, name: &str) -> Result<(bool, String), String> {
    use std::os::unix::process::CommandExt as _;
    let user = nix::unistd::User::from_name(user)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no user {user}"))?;
    let dir = format!("/tmp/snitchhiker-bridge-{name}");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::os::unix::fs::chown(&dir, Some(user.uid.as_raw()), Some(user.gid.as_raw()))
        .map_err(|e| e.to_string())?;
    std::fs::write(
        format!("{dir}/remote.toml"),
        format!("key = \"{dir}/node.key\"\n"),
    )
    .map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new("snitchhiker-remote")
        .args(["--config", &format!("{dir}/remote.toml")])
        .uid(user.uid.as_raw())
        .gid(user.gid.as_raw())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while child.try_wait().map_err(|e| e.to_string())?.is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// The daemon's remote socket serves the remote service's user alone, and one service at a time: another user's
/// process (root's too) or a second service is refused, and the node's devices stay with the first.
pub fn only_the_remote_service_is_served() -> Result<(), String> {
    let daemon = Running::start("remote-socket", "mode = \"monitor\"\n[remote]\n")?;
    let devices_before = daemon.cli(&["devices"])?;
    let (mallory_ok, mallory) = bridge_as("mallory", "mallory")?;
    let (root_ok, root) = bridge_as("root", "root")?;
    let (second_ok, second) = bridge_as("snitchhiker-remote", "second")?;
    let devices_after = daemon.cli(&["devices"])?;
    let log = std::fs::read_to_string("/tmp/snitchhiker-daemon-test/remote-socket/daemon.log")
        .unwrap_or_default();
    let found = format!(
        "mallory's: {mallory}\nroot's: {root}\nsecond: {second}\nbefore: {devices_before}\nafter: {devices_after}\n{log}"
    );
    check(
        !mallory_ok && mallory.contains("refused") && !mallory.contains("remote endpoint started"),
        "another user's process was served as the remote service",
        &found,
    )?;
    check(
        !root_ok && root.contains("refused") && !root.contains("remote endpoint started"),
        "root's process was served as the remote service",
        &found,
    )?;
    check(
        !second_ok && second.contains("refused"),
        "a second remote service was served beside the first",
        &found,
    )?;
    check(
        log.contains("isn't snitchhiker-remote's")
            && log.contains("another remote service is connected"),
        "the daemon didn't say why it refused them",
        &found,
    )?;
    check(
        devices_before == devices_after,
        "the node changed its id when the others were refused",
        &found,
    )
}

/// With nothing allowed (`no_match = "deny"`, no rules), the remote service still reaches the relay and devices
/// through it: its traffic is the node's own, by its process. Another process of the same user is decided as any.
pub fn the_remote_services_traffic_is_the_nodes_own() -> Result<(), String> {
    use std::os::unix::process::CommandExt as _;
    let relay = Relay::start(&[])?;
    let daemon = Running::start(
        "remote-own",
        &format!("mode = \"enforce\"\nno_match = \"deny\"\n[remote]\nrelays = [\"{RELAY}\"]\n"),
    )?;
    // The device (this program) is let out to the relay; the node's remote service isn't, by any rule.
    daemon.cli(&[
        "rules",
        "add",
        "allow",
        "--exe",
        "/usr/local/bin/snitchhiker-e2e",
        "--name",
        "the test device",
    ])?;
    let device = Key::generate();
    let options = Options::default();
    let mut link = link(&daemon, "phone")?;
    link.node.addrs.clear();
    let connected = pair(&device, &link, "phone", &options)
        .map_err(|e| e.to_string())
        .and_then(|_| connect(&device, &link.node, &options, "e2e", "0").map_err(|e| e.to_string()))
        .and_then(|mut c| status(&mut c));
    let user = nix::unistd::User::from_name("snitchhiker-remote")
        .map_err(|e| e.to_string())?
        .ok_or("no snitchhiker-remote user")?;
    let other = std::process::Command::new("python3")
        .args([
            "-c",
            "import socket\ntry:\n    socket.create_connection(('127.0.0.1', 3340), timeout=2)\n    print('connected')\nexcept OSError as e:\n    print('failed', e)",
        ])
        .uid(user.uid.as_raw())
        .gid(user.gid.as_raw())
        .output()
        .map_err(|e| e.to_string())?;
    let other = String::from_utf8_lossy(&other.stdout).into_owned();
    let events = daemon.cli(&["events", "--limit", "20"]).unwrap_or_default();
    drop(relay);
    let found = format!(
        "connected: {:?}\nanother process of the user: {other}\n{events}\n{}",
        connected.as_ref().map(|s| &s.daemon_version),
        daemon.remote_log()
    );
    check(
        connected.is_ok(),
        "the device didn't reach the node through the relay with nothing allowed",
        &found,
    )?;
    check(
        other.contains("failed"),
        "another process of the remote service's user wasn't decided",
        &found,
    )
}
