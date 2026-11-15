//! Synthetic history for screenshots (`snitchhiker-e2e --seed <database> <connections> <days>`): believable programs
//! connecting to their usual destinations over the last days, a few blocked, written straight into a stopped daemon's
//! database. Deterministic, so screenshots change only when the app does.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use snitchhiker_core::rule::Action;
use snitchhiker_daemon::store::{Event, Source, Store};

/// (program, uid, destinations with their address, ports, weight, whether it is blocked).
type Program = (
    &'static str,
    u32,
    &'static [(&'static str, &'static str)],
    &'static [u16],
    u64,
    bool,
);

const PROGRAMS: [Program; 10] = [
    (
        "/usr/lib/firefox/firefox",
        1000,
        &[
            ("www.mozilla.org", "203.0.113.10"),
            ("github.com", "203.0.113.11"),
            ("docs.rs", "203.0.113.12"),
            ("crates.io", "203.0.113.13"),
            ("en.wikipedia.org", "203.0.113.14"),
        ],
        &[443],
        40,
        false,
    ),
    (
        "{home}/.cargo/bin/cargo",
        1000,
        &[
            ("static.crates.io", "203.0.113.20"),
            ("index.crates.io", "203.0.113.21"),
        ],
        &[443],
        15,
        false,
    ),
    (
        "/usr/bin/git",
        1000,
        &[
            ("github.com", "203.0.113.11"),
            ("gitlab.com", "203.0.113.22"),
        ],
        &[22, 443],
        10,
        false,
    ),
    (
        "/usr/bin/ssh",
        1000,
        &[
            ("build.example.net", "198.51.100.30"),
            ("backup.example.net", "198.51.100.31"),
        ],
        &[22],
        6,
        false,
    ),
    (
        "/usr/lib/systemd/systemd-resolved",
        974,
        &[("", "9.9.9.9"), ("", "149.112.112.112")],
        &[53, 853],
        20,
        false,
    ),
    (
        "/usr/lib/systemd/systemd-timesyncd",
        973,
        &[("time.cloudflare.com", "162.159.200.1")],
        &[123],
        3,
        false,
    ),
    (
        "/usr/bin/pacman",
        0,
        &[("geo.mirror.pkgbuild.com", "203.0.113.40")],
        &[443],
        4,
        false,
    ),
    (
        "/opt/spotify/spotify",
        1000,
        &[
            ("apresolve.spotify.com", "203.0.113.50"),
            ("spclient.wg.spotify.com", "203.0.113.51"),
        ],
        &[443, 4070],
        8,
        false,
    ),
    (
        "/opt/spotify/spotify",
        1000,
        &[
            ("log.spotify.com", "203.0.113.52"),
            ("telemetry.example.com", "203.0.113.53"),
        ],
        &[443],
        3,
        true,
    ),
    (
        "/usr/share/code/code",
        1000,
        &[
            ("dc.services.visualstudio.com", "203.0.113.60"),
            ("marketplace.visualstudio.com", "203.0.113.61"),
        ],
        &[443],
        6,
        true,
    ),
];

/// Writes `count` connections over the last `days` into the database at `path`.
pub fn seed(path: &str, count: u64, days: u64) -> Result<(), String> {
    let mut store = Store::open(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let start = now.saturating_sub(days * 86_400_000);
    let total: u64 = PROGRAMS.iter().map(|p| p.4).sum();
    let mut state: u64 = 0x5eed_cafe;
    let mut next = move |n: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % n.max(1)
    };
    let mut batch = Vec::with_capacity(5000);
    let mut recorded = Vec::new();
    for i in 0..count {
        // Spread over the days, busier in the day than at night.
        let mut time = start + (now - start) * i / count.max(1) + next(60_000);
        let hour = (time / 3_600_000) % 24;
        if !(7..=23).contains(&hour) && next(3) != 0 {
            time = time.saturating_add(8 * 3_600_000).min(now);
        }
        let mut pick = next(total);
        let program = PROGRAMS
            .iter()
            .find(|p| {
                if pick < p.4 {
                    true
                } else {
                    pick -= p.4;
                    false
                }
            })
            .unwrap_or(&PROGRAMS[0]);
        let (exe, uid, destinations, ports, _, blocked) = *program;
        let at = |n: usize, r: u64| usize::try_from(r).unwrap_or(0).min(n.saturating_sub(1));
        let (host, address) = destinations
            .get(at(destinations.len(), next(destinations.len() as u64)))
            .copied()
            .unwrap_or(("", "203.0.113.1"));
        let port = ports
            .get(at(ports.len(), next(ports.len() as u64)))
            .copied()
            .unwrap_or(443);
        batch.push(Event {
            time_ms: time,
            exe: Arc::from(exe.replace("{home}", "/home/ada")),
            host: (!host.is_empty()).then(|| Arc::from(host)),
            uid,
            pid: 1000 + u32::try_from(next(30_000)).unwrap_or(0),
            protocol: if port == 53 || port == 123 { 17 } else { 6 },
            address: address.parse::<IpAddr>().map_err(|e| e.to_string())?,
            port,
            context: 0,
            action: if blocked { Action::Deny } else { Action::Allow },
            source: Source::Rule,
            rule: None,
            cookie: None,
            container: None,
        });
        if batch.len() == 5000 {
            store
                .record(&batch, &mut recorded)
                .map_err(|e| e.to_string())?;
            batch.clear();
        }
    }
    store
        .record(&batch, &mut recorded)
        .map_err(|e| e.to_string())?;
    Ok(())
}
