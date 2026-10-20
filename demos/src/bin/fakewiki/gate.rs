use std::io;
use std::path::Path;
use std::time::Duration;

use fakewiki_world::tamper::Reply;
use fictionet_demo::kit::{
    GuestHandle, Run,
    client::{Capability, PageClient},
    gate::check,
    rfb, shot,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{ARTICLE, HOST, WIKI};

async fn post_command(client: &PageClient, id: &str, on: bool, revision: u64) -> io::Result<Value> {
    client
        .command(
            "tamper",
            id,
            json!({"type":"set_tampering", "on":on, "expected_revision":revision}),
        )
        .await
}

pub async fn command(client: &PageClient, id: &str, on: bool, revision: u64) -> io::Result<Reply> {
    let response = post_command(client, id, on, revision).await?;
    check(
        "the tamper command was applied",
        response["status"] == "applied",
    )?;
    Ok(serde_json::from_value(response["reply"].clone())?)
}

pub async fn stale_command(
    client: &PageClient,
    id: &str,
    on: bool,
    expected: u64,
    current: u64,
) -> io::Result<()> {
    let response = post_command(client, id, on, expected).await?;
    check(
        "a stale tamper command gets HTTP 409 and the framework's stale rejection",
        response
            == json!({
                "status": "rejected", "request_id": id,
                "rejection": {"reason": "stale_revision", "current": current}
            }),
    )?;
    event(
        client,
        "world did not emit the stale command rejection",
        |event| {
            event["source"] == "fakewiki"
                && event["kind"] == "tampering_rejected"
                && event["fields"]["expected"] == expected
                && event["fields"]["current"] == current
        },
    )
    .await
}

pub struct StateStream(BufReader<TcpStream>);

impl StateStream {
    pub async fn open(url: &str) -> io::Result<Self> {
        let (authority, token) = url
            .strip_prefix("http://")
            .and_then(|s| s.split_once("/#token="))
            .ok_or_else(|| io::Error::other("invalid page URL"))?;
        let mut socket = TcpStream::connect(authority).await?;
        socket.write_all(format!(
            "GET /api/states/stream?topics=tamper,diff HTTP/1.1\r\nHost: {authority}\r\nOrigin: http://{authority}\r\nAuthorization: Bearer {token}\r\n\r\n"
        ).as_bytes()).await?;
        let mut stream = Self(BufReader::new(socket));
        let mut line = String::new();
        stream.0.read_line(&mut line).await?;
        if !line.starts_with("HTTP/1.1 200 ") {
            return Err(io::Error::other(format!("state stream refused: {line}")));
        }
        loop {
            line.clear();
            if stream.0.read_line(&mut line).await? == 0 {
                return Err(io::Error::other("state stream closed in headers"));
            }
            if line == "\r\n" {
                break;
            }
        }
        Ok(stream)
    }

    pub async fn state(&mut self, topic: &str, revision: u64) -> io::Result<Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut line = String::new();
                if self.0.read_line(&mut line).await? == 0 {
                    return Err(io::Error::other("state stream closed"));
                }
                if line.len() > 128 << 10 {
                    return Err(io::Error::other("state stream line exceeds bound"));
                }
                if let Some(data) = line.strip_prefix("data: ") {
                    let value: Value = serde_json::from_str(data.trim())?;
                    if value["topic"] == topic && value["value"]["revision"] == revision {
                        if value["status"]["too_large"] != false {
                            return Err(io::Error::other("state stream exceeded its bound"));
                        }
                        return Ok(value);
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            io::Error::other(format!(
                "state stream did not show {topic} revision {revision}"
            ))
        })?
    }
}

async fn event(
    client: &PageClient,
    missing: &str,
    matches: impl Fn(&Value) -> bool,
) -> io::Result<()> {
    client
        .wait_for_event(
            0,
            Duration::from_secs(60),
            Duration::from_millis(100),
            |event| Ok(matches(event)),
        )
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::TimedOut => io::Error::other(missing),
            _ => error,
        })?;
    Ok(())
}

fn article(event: &Value) -> bool {
    event["source"] == "http"
        && event["kind"] == "request"
        && event["sandbox"]["name"] == HOST
        && event["fields"]["host"] == WIKI
        && event["fields"]["path"] == ARTICLE
}

/// A complete 200 GET of the article, as one version at one revision.
fn complete_read(event: &Value, served: &str, revision: u64) -> bool {
    let fields = &event["fields"];
    article(event)
        && fields["served"] == served
        && fields["tamper_revision"] == revision
        && fields["method"] == "GET"
        && fields["status"] == 200
        && fields["complete"] == true
}

pub(super) async fn read(client: &PageClient, served: &str, revision: u64) -> io::Result<()> {
    event(
        client,
        &format!("scripted reader did not receive {served} article at revision {revision}"),
        |event| complete_read(event, served, revision),
    )
    .await
}

/// Follows the events after the switch to revision 1 for the second read.
#[derive(Default)]
pub(super) struct Reload {
    switched: bool,
    pub requests: usize,
    /// The sequence number of the last event observed.
    last: u64,
}

impl Reload {
    /// True once a complete tampered read at revision 1 arrives. An article
    /// request after the switch that was served the real page, or served at
    /// revision 0, is an error.
    pub fn observe(&mut self, events: &[Value]) -> io::Result<bool> {
        let mut received = false;
        for event in events {
            self.last = event["seq"].as_u64().unwrap_or(self.last);
            if event["source"] == "fakewiki"
                && event["kind"] == "tampering"
                && event["fields"]["revision"] == 1
                && event["fields"]["on"] == true
            {
                self.switched = true;
            }
            if !self.switched || !article(event) {
                continue;
            }
            self.requests += 1;
            let fields = &event["fields"];
            if fields["served"] == "real" || fields["tamper_revision"] == 0 {
                return Err(io::Error::other(format!(
                    "article after the switch used the old state: {event}"
                )));
            }
            received |= complete_read(event, "tampered", 1);
        }
        Ok(received)
    }
}

/// Runs xdotool as the scripted reader on the guest's display.
async fn xdotool(guest: &GuestHandle, args: &str) -> io::Result<String> {
    let command = format!("env DISPLAY=:1 xdotool {args}");
    let output = tokio::time::timeout(Duration::from_secs(30), guest.ssh().run(&command))
        .await
        .map_err(|_| io::Error::other(format!("scripted reader timed out: {command}")))??;
    if output.code != 0 {
        return Err(io::Error::other(format!(
            "scripted reader {command:?}: exit {}; {}",
            output.code, output.stderr
        )));
    }
    Ok(output.stdout)
}

/// Waits until Firefox's window shows the article's title, so the first
/// load has finished, and returns the window's id.
async fn article_window(guest: &GuestHandle) -> io::Result<u64> {
    let windows = xdotool(
        guest,
        "search --sync --onlyvisible --name '^Stream ripping - Wikipedia.*Firefox'",
    )
    .await?;
    windows
        .lines()
        .next()
        .ok_or_else(|| io::Error::other("Firefox article window not found"))?
        .trim()
        .parse()
        .map_err(io::Error::other)
}

async fn reload(guest: &GuestHandle, window: u64) -> io::Result<()> {
    println!("Scripted reader: reload Firefox window {window} (ctrl+F5)");
    xdotool(
        guest,
        &format!("windowactivate --sync {window} key --window {window} --clearmodifiers ctrl+F5"),
    )
    .await?;
    Ok(())
}

/// Reloads the article and waits for the tampered read. When no article
/// request at all arrives within 15 s, it names the active window and
/// reloads once more.
async fn second_read(
    client: &PageClient,
    guest: &GuestHandle,
    window: u64,
    after: u64,
) -> io::Result<()> {
    const POLL: Duration = Duration::from_millis(100);
    let mut observed = Reload::default();
    let mut retried = false;
    reload(guest, window).await?;
    let mut wait = client
        .wait_for_event(after, Duration::from_secs(15), POLL, |event| {
            observed.observe(std::slice::from_ref(event))
        })
        .await;
    if wait.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::TimedOut) {
        if observed.requests == 0 {
            retried = true;
            let active = xdotool(guest, "getactivewindow getwindowname").await;
            println!("Scripted reader: no article request within 15 s; active window: {active:?}");
            println!("Scripted reader: retrying the reload once");
            reload(guest, window).await?;
        }
        wait = client
            .wait_for_event(observed.last.max(after), Duration::from_secs(45), POLL, |event| {
                observed.observe(std::slice::from_ref(event))
            })
            .await;
    }
    match wait {
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Err(io::Error::other(format!(
            "scripted reader did not receive tampered article at revision 1 \
             ({} article requests after the switch; reload retried: {retried})",
            observed.requests
        ))),
        wait => wait.map(drop),
    }
}

/// Captures the guest's screen until two captures in a row match, for at
/// most 15 s. Firefox animates its tab while it loads, so a settled screen
/// shows the page it received rather than the one it is replacing. Returns
/// the last capture and how many captures it took, or None if the screen
/// was still changing.
async fn settled_screen(run: &Run, out: &Path) -> io::Result<(rfb::Capture, Option<usize>)> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let (mut previous, mut captures) = (None, 0);
    let mut poll = tokio::time::interval(Duration::from_millis(500));
    loop {
        poll.tick().await;
        captures += 1;
        let capture = tokio::time::timeout(
            Duration::from_secs(30),
            rfb::capture_page(run.page_url(), HOST, out),
        )
        .await
        .map_err(|_| io::Error::other("guest screen capture timed out"))??;
        let pixels = std::fs::read(&capture.png)?;
        if previous.as_ref() == Some(&pixels) {
            return Ok((capture, Some(captures)));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok((capture, None));
        }
        previous = Some(pixels);
    }
}

/// Runs the checks. On a failure it prints the article's requests and saves
/// the guest's screen before it returns the error.
pub async fn run(run: &Run, output: &Path) -> io::Result<()> {
    let mut switch = None;
    let result = checks(run, output, &mut switch).await;
    if let Err(error) = &result {
        eprintln!("Gate failed: {error}");
        let requests = article_requests(run, switch);
        match tokio::time::timeout(Duration::from_secs(10), requests).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("Article requests unavailable: {error}"),
            Err(_) => eprintln!("Article requests unavailable: timed out"),
        }
        let path = output.join("failure-desktop.png");
        let capture = async {
            std::fs::create_dir_all(output)?;
            rfb::capture_page(run.page_url(), HOST, &path).await
        };
        match tokio::time::timeout(Duration::from_secs(30), capture).await {
            Ok(Ok(_)) => eprintln!("Guest screen at the failure: {}", path.display()),
            Ok(Err(error)) => eprintln!("Guest screen unavailable: {error}"),
            Err(_) => eprintln!("Guest screen unavailable: timed out"),
        }
    }
    result
}

/// Prints the article's requests since the switch, or since the start
/// when the gate failed before it.
async fn article_requests(run: &Run, switch: Option<u64>) -> io::Result<()> {
    let client = PageClient::from_url(run.page_url())?;
    let since = if switch.is_some() {
        "the switch"
    } else {
        "the start"
    };
    eprintln!("Article requests since {since}:");
    let (mut after, mut count) = (switch.unwrap_or(0), 0);
    let dropped = loop {
        let value = client.events(after).await?;
        let events = value["events"]
            .as_array()
            .ok_or_else(|| io::Error::other("the events reply has no events"))?;
        for event in events.iter().filter(|event| article(event)) {
            count += 1;
            let fields = &event["fields"];
            eprintln!(
                "  at {} s: {} served {} at revision {}, status {}, complete {}",
                event["at"],
                fields["method"],
                fields["served"],
                fields["tamper_revision"],
                fields["status"],
                fields["complete"],
            );
        }
        match events.last().and_then(|event| event["seq"].as_u64()) {
            Some(next) => after = next,
            None => break value["dropped"].clone(),
        }
    };
    eprintln!("{count} article requests; events lost from the history: {dropped}");
    Ok(())
}

async fn checks(run: &Run, output: &Path, switch: &mut Option<u64>) -> io::Result<()> {
    let client = PageClient::from_url(run.page_url())?;
    client.bootstrap().await?;
    let guest = run.guest(HOST);
    guest.wait_desktop(Duration::from_secs(300)).await?;
    read(&client, "real", 0).await?;
    println!(
        "boot to desktop (article received over TLS): {} ms",
        run.boot_started().elapsed().as_millis()
    );

    check(
        "the page API refuses a request without the token",
        client
            .request("GET", "/api/page", None, false)
            .await?
            .status
            == 401,
    )?;
    let missing = client.open(HOST, Capability::Screen, None).await;
    check(
        "the screen refuses a missing ticket with 401",
        missing
            .err()
            .is_some_and(|e| e.to_string().contains("HTTP/1.1 401 ")),
    )?;
    let ticket = client.ticket(HOST, Capability::Screen).await?;
    let socket = client
        .open(HOST, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let reused = client
        .open(HOST, Capability::Screen, Some(&ticket.ticket))
        .await;
    check(
        "the screen refuses a reused ticket with 401",
        reused
            .err()
            .is_some_and(|e| e.to_string().contains("HTTP/1.1 401 ")),
    )?;
    drop(socket);
    println!("[pass] page security: token required, missing and reused tickets refused");
    println!("[pass] first read: real, revision 0");

    let window = article_window(guest).await?;
    println!("Scripted reader: the article's title is in Firefox window {window}");

    let mut stream = StateStream::open(run.page_url()).await?;
    let initial = stream.state("tamper", 0).await?;
    check("tampering starts off", initial["value"]["on"] == false)?;
    let before = client.events(0).await?["last"].as_u64();
    *switch = Some(before.ok_or_else(|| io::Error::other("events API has no cursor"))?);
    check(
        "the switch is applied at revision 1",
        matches!(
            command(&client, "switch-on", true, 0).await?,
            Reply::Applied {
                revision: 1,
                changed: true,
                ..
            }
        ),
    )?;
    stale_command(&client, "stale-switch", true, 0, 1).await?;
    let state = client.get_json("/api/state/tamper").await?;
    let streamed = stream.state("tamper", 1).await?;
    check(
        "GET and the stream agree that tampering is on",
        state["value"] == streamed["value"] && state["value"]["on"] == true,
    )?;
    println!(
        "[pass] switch: applied revision 1, stale revision rejected with HTTP 409 and world event, GET and stream agree"
    );

    second_read(&client, guest, window, switch.unwrap_or(0)).await?;
    let diff = client.get_json("/api/state/diff").await?;
    check(
        "the diff has revision 1 within its bound",
        diff["status"]["too_large"] == false && diff["value"]["revision"] == 1,
    )?;
    let diff: fakewiki_world::pages::diff::Diff = serde_json::from_value(diff["value"].clone())?;
    check(
        "the diff marks the article tampered",
        diff.topics
            .iter()
            .flat_map(|t| &t.sources)
            .any(|s| s.url == super::URL && s.served == fakewiki_world::pages::Version::Tampered),
    )?;
    println!("[pass] second read: tampered, revision 1; diff agrees");

    for (path, pointer) in [
        ("/api/event-table/reads-scripted-reader", "/rows"),
        ("/api/egress", "/destinations"),
        ("/api/state/containment", "/value/probes"),
        ("/api/graph", "/nodes"),
    ] {
        let value = client.get_json(path).await?;
        check(
            &format!("panel has data: {path}"),
            value
                .pointer(pointer)
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty()),
        )?;
    }
    println!("[pass] panels: Reads, Left the box, containment and map have data");
    std::fs::create_dir_all(output)?;
    let screen = output.join("desktop.png");
    let (capture, settled) = settled_screen(run, &screen).await?;
    check(
        "the guest screen is 1280x800 and not blank",
        capture.width == 1280 && capture.height == 800 && capture.colors >= 16,
    )?;
    match settled {
        Some(captures) => println!(
            "guest screenshot: {} (the screen settled after {captures} captures)",
            screen.display()
        ),
        None => println!(
            "guest screenshot: {} (the screen was still changing after 15 s)",
            screen.display()
        ),
    }
    let page = output.join("page.png");
    let url = run.page_url().to_owned();
    let screenshot = page.clone();
    tokio::task::spawn_blocking(move || {
        shot::capture(
            &url,
            &screenshot,
            &shot::desktop_painted(HOST),
            Duration::from_secs(30),
        )
    })
    .await
    .map_err(io::Error::other)??;
    println!("page screenshot: {}", page.display());
    Ok(())
}
