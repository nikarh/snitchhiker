//! Subscriptions that resume: events from a sequence number on, then live; prompts that wait, sent on subscribing.

use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::Duration;

use snitchhiker_client::{ADMIN_SOCKET, Client};
use snitchhiker_proto::v1;

use crate::daemon::Running;
use crate::util::check;

fn connect(port: u16) {
    let _ = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    );
}

fn client() -> Result<Client, String> {
    let client = Client::connect(Path::new(ADMIN_SOCKET), "e2e", "0").map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    Ok(client)
}

/// The seq of each event notice, until `count` are in.
fn event_seqs(client: &mut Client, count: usize) -> Result<Vec<i64>, String> {
    let mut seqs = Vec::new();
    while seqs.len() < count {
        let notice = client
            .notice()
            .map_err(|e| format!("after {seqs:?}: {e}"))?;
        if let Some(v1::notice::Body::Event(event)) = notice.body {
            seqs.push(event.seq);
        }
    }
    Ok(seqs)
}

pub fn events_resume_from_a_sequence_number() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut daemon = Running::start("resume-events", "mode = \"monitor\"\n")?;
    for _ in 0..4 {
        connect(port);
    }
    thread::sleep(Duration::from_secs(1));
    let mut client = client()?;
    let stored = match client
        .call(v1::request::Method::ListEvents(v1::ListEvents {
            before: 0,
            limit: 100,
        }))
        .map_err(|e| e.to_string())?
    {
        v1::response::Result::Events(page) => {
            let mut seqs: Vec<i64> = page.events.iter().map(|e| e.seq).collect();
            seqs.sort_unstable();
            seqs
        }
        _ => return Err("not an event page".to_owned()),
    };
    let Some(&first) = stored.first() else {
        return Err("no events were recorded".to_owned());
    };
    let missed: Vec<i64> = stored.iter().copied().filter(|seq| *seq > first).collect();
    // The client saw `first` before it lost its connection: it resumes after it.
    client
        .subscribe_after(v1::Topic::Events, Some(first))
        .map_err(|e| e.to_string())?;
    let backfilled = event_seqs(&mut client, missed.len())?;
    connect(port);
    let live = event_seqs(&mut client, 1)?;
    let too_far = client.subscribe_after(v1::Topic::Events, Some(-1_000_000));
    daemon.stop()?;
    let found = format!("stored {stored:?}, backfilled {backfilled:?}, live {live:?}");
    check(
        backfilled == missed,
        "resuming didn't send the events after the last one seen, in order",
        &found,
    )?;
    check(
        live.first().is_some_and(|seq| Some(seq) > stored.last()),
        "a live event didn't follow the backfill",
        &found,
    )?;
    // Fewer than the limit are stored here, so even from far back this one fits.
    check(
        too_far.is_ok(),
        "a resume within the limit was refused",
        &format!("{too_far:?}"),
    )
}

pub fn waiting_prompts_are_sent_on_subscribing() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut daemon = Running::start(
        "resume-prompts",
        "mode = \"enforce\"\nno_match = \"ask\"\nno_client = \"deny\"\nprompt_timeout_secs = 20\n",
    )?;
    // A client listening, so connections are held for prompts.
    let mut first = client()?;
    first
        .subscribe(v1::Topic::Prompts)
        .map_err(|e| e.to_string())?;
    let connecting = thread::spawn(move || connect(port));
    let prompt = loop {
        let notice = first.notice().map_err(|e| e.to_string())?;
        if let Some(v1::notice::Body::Prompt(prompt)) = notice.body {
            break prompt;
        }
    };
    // A second client (another device, or the first after reconnecting) subscribes now.
    let mut second = client()?;
    second
        .subscribe(v1::Topic::Prompts)
        .map_err(|e| e.to_string())?;
    let sent = second.notice().map_err(|e| e.to_string())?;
    drop(first);
    drop(second);
    daemon.stop()?;
    let _ = connecting.join();
    check(
        matches!(&sent.body, Some(v1::notice::Body::Prompt(p)) if p.id == prompt.id),
        "the waiting prompt wasn't sent to a client subscribing after it opened",
        &format!("{sent:?}"),
    )
}
