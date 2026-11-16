//! The performance budgets of plan §11.1, measured and enforced: `cargo bench -p snitchhiker-daemon --bench budgets`
//! fails when one is over.
//!
//! - deciding a connection against 10 000 rules: p99 under 50 µs;
//! - ingesting events on one writer: at least 50 000 a second;
//! - every kind of history query on a large database: under 20 ms.
//!
//! The database has `SNITCHHIKER_BENCH_EVENTS` events (1 000 000 by default; `mise run bench:full` uses 10 000 000)
//! spread over 30 days, of a few thousand programs and hosts. It is built in a temporary directory and removed.

#![expect(clippy::print_stdout, reason = "a benchmark reports on stdout")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a benchmark fails loudly"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "synthetic data and rates: the numbers are small and approximate"
)]
#![expect(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "one table of queries"
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use snitchhiker_core::destination::{HostPattern, Network};
use snitchhiker_core::engine::{Facts, RuleSet};
use snitchhiker_core::pattern::PatternSource;
use snitchhiker_core::query::{Context, EventFilter};
use snitchhiker_core::rule::{Action, Condition, ContextKind, Expiry, Rule, Tier};
use snitchhiker_daemon::store::{Dimension, Event, Source, Store};

const DECIDE_P99: Duration = Duration::from_micros(50);
const INGEST_PER_SEC: f64 = 50_000.0;
const QUERY: Duration = Duration::from_millis(20);
const DAY_MS: u64 = 86_400_000;
/// When the history starts: 2026-01-01.
const START_MS: u64 = 1_767_225_600_000;

fn main() {
    // `cargo test` runs benches with `--bench`-less arguments in test mode: nothing to do then.
    if std::env::args().any(|a| a == "--test" || a == "--list") {
        return;
    }
    let events: u64 = std::env::var("SNITCHHIKER_BENCH_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);
    let mut over = Vec::new();
    over.extend(decide());
    over.extend(store(events));
    if over.is_empty() {
        println!("every budget is met");
    } else {
        println!("over budget:");
        for line in &over {
            println!("  {line}");
        }
        std::process::exit(1);
    }
}

/// Ten thousand rules of the shapes prompts make.
fn rules() -> Vec<Rule> {
    (0..10_000_u64)
        .map(|i| Rule {
            id: i + 1,
            folder: None,
            name: format!("rule {i}"),
            enabled: true,
            action: if i % 7 == 0 {
                Action::Deny
            } else {
                Action::Allow
            },
            tier: Tier::Normal,
            expiry: Expiry::Never,
            log: true,
            notes: String::new(),
            conditions: vec![
                Condition::Exe(vec![if i % 3 == 0 {
                    PatternSource::Glob(format!(
                        "{{home}}/.local/share/app{}/versions/*/app",
                        i % 50
                    ))
                } else {
                    PatternSource::Exact(format!("/usr/bin/app{}", i % 200))
                }]),
                Condition::Host(vec![
                    HostPattern::try_from(format!("*.service{}.example.com", i % 500)).unwrap(),
                ]),
                Condition::Net(vec![Network::try_from("lan".to_owned()).unwrap()]),
                Condition::Port(vec![
                    (443, 443),
                    (80 + (i % 20) as u16, 80 + (i % 20) as u16),
                ]),
            ],
        })
        .collect()
}

fn decide() -> Vec<String> {
    let set = RuleSet::compile(&[], &rules()).unwrap();
    let hosts: Vec<Vec<Arc<str>>> = (0..1000)
        .map(|i| vec![Arc::from(format!("api.service{i}.example.com").as_str())])
        .collect();
    let exes: Vec<String> = (0..300).map(|i| format!("/usr/bin/app{i}")).collect();
    let mut samples = Vec::with_capacity(200_000);
    for round in 0..200_000_usize {
        let facts = Facts {
            exe: &exes[round % exes.len()],
            apps: &[],
            cmdline: "",
            ancestors: &[],
            lineage: &[],
            uid: 1000,
            home: Some("/home/ada"),
            hosts: &hosts[round % hosts.len()],
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, (round % 250) as u8)),
            port: if round % 2 == 0 {
                443
            } else {
                80 + (round % 30) as u16
            },
            protocol: 6,
            context: ContextKind::Host,
            container: None,
            vm: None,
            netns: None,
            now_ms: START_MS,
        };
        let started = Instant::now();
        std::hint::black_box(set.decide(std::hint::black_box(&facts)));
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    println!("decide, 10 000 rules: p50 {p50:?}, p99 {p99:?} (budget {DECIDE_P99:?})");
    if p99 > DECIDE_P99 {
        vec![format!("deciding: p99 {p99:?} > {DECIDE_P99:?}")]
    } else {
        Vec::new()
    }
}

/// The `i`th event of the history, shaped like a busy workstation's: 300 programs, each talking to its own few of
/// 3000 hosts, the busiest program and hosts taking most of the traffic (a Zipf-like spread), and one connection in
/// a hundred to a name never seen before (CDN shards, trackers): 10 000 new names a million events.
fn event(i: u64, count: u64, exes: &[Arc<str>], hosts: &[Arc<str>]) -> Event {
    let mix = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 17;
    // Squaring a uniform number favours the low end: a few values get most of the draws.
    let zipf = |n: u64, len: usize| -> usize {
        let unit = (n % 10_000) as f64 / 10_000.0;
        ((unit * unit * unit) * len as f64) as usize
    };
    let program = zipf(mix, exes.len());
    let host: Option<Arc<str>> = match mix % 100 {
        0 => Some(Arc::from(format!("t{i}.shard.example.org").as_str())),
        1..=9 => None,
        _ => Some(Arc::clone(
            &hosts[(program * 10 + zipf(mix >> 20, 10)) % hosts.len()],
        )),
    };
    Event {
        time_ms: START_MS + i * (30 * DAY_MS) / count,
        exe: Arc::clone(&exes[program]),
        host,
        uid: 1000 + (program % 3) as u32,
        pid: (mix % 30_000) as u32,
        protocol: if mix.is_multiple_of(20) { 17 } else { 6 },
        address: IpAddr::V4(Ipv4Addr::from((mix as u32) | 0x0100_0000)),
        port: [443, 443, 443, 80, 53, 22, 8080][(mix % 7) as usize],
        context: 0,
        action: if mix.is_multiple_of(9) {
            Action::Deny
        } else {
            Action::Allow
        },
        source: Source::Rule,
        rule: Some(program as u64 + 1),
        cookie: None,
        container: (program % 50 == 7).then(|| Arc::from("docker\tabc\tweb\tnode:22\tshop/web\t")),
    }
}

fn store(count: u64) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!("snitchhiker-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = Store::open(&dir.join("state.db")).unwrap();
    let exes: Vec<Arc<str>> = (0..300)
        .map(|i| Arc::from(format!("/usr/bin/program{i}").as_str()))
        .collect();
    let hosts: Vec<Arc<str>> = (0..3000)
        .map(|i| Arc::from(format!("host{i}.example.net").as_str()))
        .collect();
    let mut over = Vec::new();

    // Ingestion: in the writer's batches.
    let started = Instant::now();
    let mut recorded = Vec::new();
    let mut batch = Vec::with_capacity(snitchhiker_daemon::runtime::BATCH);
    for i in 0..count {
        batch.push(event(i, count, &exes, &hosts));
        if batch.len() == snitchhiker_daemon::runtime::BATCH {
            store.record(&batch, &mut recorded).unwrap();
            batch.clear();
        }
        if (i + 1) % 1_000_000 == 0 {
            let rate = (i + 1) as f64 / started.elapsed().as_secs_f64();
            println!("  {} M events: {rate:.0}/s so far", (i + 1) / 1_000_000);
        }
    }
    store.record(&batch, &mut recorded).unwrap();
    let rate = count as f64 / started.elapsed().as_secs_f64();
    println!("ingest {count} events: {rate:.0}/s (budget {INGEST_PER_SEC}/s)");
    if rate < INGEST_PER_SEC {
        over.push(format!("ingestion: {rate:.0}/s < {INGEST_PER_SEC}/s"));
    }

    let size = std::fs::metadata(dir.join("state.db")).map_or(0, |m| m.len());
    println!(
        "database: {} MB, {} bytes an event",
        size >> 20,
        size / count.max(1)
    );

    let newest = recorded.last().map_or(1, |r| r.seq);
    let last_hour = (START_MS + (count - 1) * (30 * DAY_MS) / count) / 3_600_000;
    // As the API asks for "the last n hours" at the time of the newest event: buckets [last - n, last].
    let to_hour = last_hour + 1;
    let cx = Context {
        now_ms: START_MS + 30 * DAY_MS,
        uid_of: &|_| None,
    };
    let filter = |text: &str| EventFilter::parse(text, &cx).unwrap();
    let rare = filter("exe:/usr/bin/program299");
    let denied = filter("action:deny port:22");
    let host_id = store
        .string_id(
            snitchhiker_daemon::store::StringKind::Host,
            "host7.example.net",
        )
        .unwrap()
        .unwrap_or(0);
    let queries: Vec<(&str, Box<dyn Fn(&Store)>)> = vec![
        (
            "newest page of events",
            Box::new(|s: &Store| drop(s.event_rows(i64::MAX, 200).unwrap())),
        ),
        (
            "a page in the middle",
            Box::new(move |s: &Store| drop(s.event_rows(newest / 2, 200).unwrap())),
        ),
        (
            "events after a sequence number",
            Box::new(move |s: &Store| drop(s.event_rows_after(newest - 500, 200).unwrap())),
        ),
        (
            "a query matching few events",
            Box::new(move |s: &Store| drop(s.event_rows_matching(i64::MAX, 200, &rare).unwrap())),
        ),
        (
            "a query matching some events",
            Box::new(move |s: &Store| drop(s.event_rows_matching(i64::MAX, 200, &denied).unwrap())),
        ),
        (
            "explore: programs, last day",
            Box::new(move |s: &Store| {
                drop(
                    s.explore(last_hour - 24, to_hour, Dimension::Exe, None, (100, false))
                        .unwrap(),
                );
            }),
        ),
        (
            "explore: hosts, last 30 days, by bytes",
            Box::new(move |s: &Store| {
                drop(
                    s.explore(last_hour - 720, to_hour, Dimension::Host, None, (100, true))
                        .unwrap(),
                );
            }),
        ),
        (
            "explore: one host's programs, 7 days",
            Box::new(move |s: &Store| {
                drop(
                    s.explore(
                        last_hour - 168,
                        to_hour,
                        Dimension::Exe,
                        Some((Dimension::Host, host_id)),
                        (100, false),
                    )
                    .unwrap(),
                );
            }),
        ),
        (
            "explore: containers, 7 days",
            Box::new(move |s: &Store| {
                drop(
                    s.explore(
                        last_hour - 168,
                        to_hour,
                        Dimension::Container,
                        None,
                        (100, false),
                    )
                    .unwrap(),
                );
            }),
        ),
        (
            "rules' last hits",
            Box::new(|s: &Store| drop(s.rule_times().unwrap())),
        ),
        (
            "changes",
            Box::new(|s: &Store| drop(s.changes(u64::MAX, 100).unwrap())),
        ),
    ];
    for (name, run) in &queries {
        let mut times: Vec<Duration> = (0..5)
            .map(|_| {
                let started = Instant::now();
                run(&store);
                started.elapsed()
            })
            .collect();
        times.sort_unstable();
        // The median of five: the first run warms the page cache.
        let median = times[2];
        println!("query, {name}: {median:?} (budget {QUERY:?})");
        if median > QUERY {
            over.push(format!("query {name}: {median:?} > {QUERY:?}"));
        }
    }
    drop(store);
    let _ = std::fs::remove_dir_all(dir);
    over
}
