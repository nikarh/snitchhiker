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
            columnar: false,
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

/// Events as columnar blocks: a page and a live batch, read in place, agree with the same events as messages, and the
/// strings they use come with them once.
pub fn events_come_as_columnar_blocks() -> Result<(), String> {
    use snitchhiker_proto::columns::EventBlock;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut daemon = Running::start("columnar", "mode = \"monitor\"\n")?;
    for _ in 0..3 {
        connect(port);
    }
    thread::sleep(Duration::from_secs(1));
    let mut client = client()?;
    let list = |columnar| {
        v1::request::Method::ListEvents(v1::ListEvents {
            before: 0,
            limit: 100,
            columnar,
        })
    };
    let plain = match client.call(list(false)).map_err(|e| e.to_string())? {
        v1::response::Result::Events(page) => page.events,
        _ => return Err("not an event page".to_owned()),
    };
    let block = match client.call(list(true)).map_err(|e| e.to_string())? {
        v1::response::Result::EventBlock(block) => block,
        other => return Err(format!("not a block: {other:?}")),
    };
    let parsed = EventBlock::parse(&block.columns).map_err(|e| e.to_string())?;
    let mut from_block: Vec<(i64, String, u32)> = parsed
        .rows()
        .map(|row| {
            (
                row.seq,
                client.string(row.exe).unwrap_or("?").to_owned(),
                u32::from(row.port),
            )
        })
        .collect();
    from_block.sort_unstable();
    let mut from_messages: Vec<(i64, String, u32)> = plain
        .iter()
        .map(|e| (e.seq, e.exe.clone(), e.port))
        .collect();
    from_messages.sort_unstable();
    // A live batch, as a block, after subscribing with blocks.
    client
        .subscribe_with(v1::Topic::Events, None, true)
        .map_err(|e| e.to_string())?;
    connect(port);
    let live = loop {
        let notice = client.notice().map_err(|e| e.to_string())?;
        if let Some(v1::notice::Body::EventBlock(block)) = notice.body {
            break block;
        }
    };
    let live_rows: Vec<_> = EventBlock::parse(&live.columns)
        .map_err(|e| e.to_string())?
        .rows()
        .collect();
    daemon.stop()?;
    let found = format!(
        "messages {from_messages:?}\nblock {from_block:?}\nlive {live_rows:?} {:?}",
        live.dictionary
    );
    check(
        !from_messages.is_empty() && from_block == from_messages,
        "the block doesn't hold the same events as the messages",
        &found,
    )?;
    check(
        live_rows
            .iter()
            .any(|row| row.port == port && client.string(row.exe).is_some()),
        "the live block doesn't hold the new connection, or its program's name never came",
        &found,
    )?;
    // The program's name was sent with the page: the live block doesn't repeat it.
    check(
        live.dictionary.as_ref().is_some_and(|d| {
            d.ids
                .iter()
                .all(|id| live_rows.iter().all(|r| r.exe != *id))
        }),
        "the live block repeated a string this connection was sent already",
        &found,
    )
}
