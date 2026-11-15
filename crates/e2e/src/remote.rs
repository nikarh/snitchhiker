//! Paired devices over the network (iroh): a device pairs with a link's one-time secret and then connects with its
//! key; an unpaired key is refused, a secret works once, and unpairing closes the device's connections.

use std::thread;
use std::time::Duration;

use snitchhiker_client::remote::{connect, pair};
use snitchhiker_proto::v1;
use snitchhiker_remote::{Key, Options, PairLink};

use crate::daemon::Running;
use crate::util::check;

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
    let daemon = Running::start("remote", "mode = \"monitor\"\nremote = true\n")?;
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
        &format!("mode = \"monitor\"\nremote = true\nrelays = [\"{RELAY}\"]\n"),
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
        "mode = \"monitor\"\nremote = true\nrelays = [\"{RELAY}\"]\n"
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
        &format!("mode = \"monitor\"\nremote = true\nrelays = [\"{relay_url}/\"]\n"),
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
