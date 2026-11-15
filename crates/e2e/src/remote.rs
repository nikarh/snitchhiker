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
