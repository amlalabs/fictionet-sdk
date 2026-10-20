use std::io;
use std::path::Path;
use std::time::Duration;

use fakewiki_world::tamper::Reply;
use fictionet_demo::kit::{
    GuestHandle, Run,
    client::{Capability, PageClient, Response},
    rfb, shot,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{ARTICLE, HOST, WIKI};

pub fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

pub async fn get(client: &PageClient, path: &str) -> io::Result<Value> {
    let reply = client.request("GET", path, None, true).await?;
    require(
        reply.status == 200,
        &format!("GET {path}: {}", reply.status_line),
    )?;
    Ok(serde_json::from_slice(&reply.body)?)
}

async fn post_command(
    client: &PageClient,
    id: &str,
    on: bool,
    revision: u64,
) -> io::Result<Response> {
    client
        .request(
            "POST",
            "/api/command/tamper",
            Some(&json!({
                "request_id": id,
                "command": {"type":"set_tampering", "on":on, "expected_revision":revision}
            })),
            true,
        )
        .await
}

pub async fn command(client: &PageClient, id: &str, on: bool, revision: u64) -> io::Result<Reply> {
    let response = post_command(client, id, on, revision).await?;
    require(
        response.status == 200,
        &format!("tamper command: {}", response.status_line),
    )?;
    let response: Value = serde_json::from_slice(&response.body)?;
    require(response["status"] == "applied", "command was not applied")?;
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
    require(
        response.status == 409,
        "stale command did not return HTTP 409",
    )?;
    let response: Value = serde_json::from_slice(&response.body)?;
    require(
        response
            == json!({
                "status": "rejected", "request_id": id,
                "rejection": {"reason": "stale_revision", "current": current}
            }),
        "stale command did not return the expected framework rejection",
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
        require(line.starts_with("HTTP/1.1 200 "), "state stream refused")?;
        loop {
            line.clear();
            require(
                stream.0.read_line(&mut line).await? > 0,
                "state stream closed in headers",
            )?;
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
                require(
                    self.0.read_line(&mut line).await? > 0,
                    "state stream closed",
                )?;
                require(line.len() <= 128 << 10, "state stream line exceeds bound")?;
                if let Some(data) = line.strip_prefix("data: ") {
                    let value: Value = serde_json::from_str(data.trim())?;
                    if value["topic"] == topic && value["value"]["revision"] == revision {
                        require(
                            value["status"]["too_large"] == false,
                            "state stream exceeded its bound",
                        )?;
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

/// The events after `after` (at most one page) and the reply around them.
async fn events(client: &PageClient, after: u64) -> io::Result<(Vec<Value>, Value)> {
    let mut value = get(client, &format!("/api/events?after={after}")).await?;
    let Value::Array(events) = value["events"].take() else {
        return Err(io::Error::other("events API has no events"));
    };
    Ok((events, value))
}

/// The cursor past a page of events. A page holds at most 1,000 events, so
/// `last` (the newest event of the run) would skip the rest of the history.
fn cursor(events: &[Value], value: &Value) -> io::Result<u64> {
    events
        .last()
        .map_or(&value["last"], |event| &event["seq"])
        .as_u64()
        .ok_or_else(|| io::Error::other("events API has no cursor"))
}

async fn event(
    client: &PageClient,
    missing: &str,
    matches: impl Fn(&Value) -> bool,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut after = 0;
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        loop {
            poll.tick().await;
            let (events, value) = events(client, after).await?;
            if events.iter().any(&matches) {
                return Ok(());
            }
            after = cursor(&events, &value)?;
        }
    })
    .await
    .map_err(|_| io::Error::other(missing))?
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
}

impl Reload {
    /// True once a complete tampered read at revision 1 arrives. An article
    /// request after the switch that was served the real page, or served at
    /// revision 0, is an error.
    pub fn observe(&mut self, events: &[Value]) -> io::Result<bool> {
        let mut received = false;
        for event in events {
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
            require(
                fields["served"] != "real" && fields["tamper_revision"] != 0,
                &format!("article after the switch used the old state: {event}"),
            )?;
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
    require(
        output.code == 0,
        &format!(
            "scripted reader {command:?}: exit {}; {}",
            output.code, output.stderr
        ),
    )?;
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
    mut after: u64,
) -> io::Result<()> {
    let mut observed = Reload::default();
    let mut retried = false;
    let started = tokio::time::Instant::now();
    let wait = async {
        reload(guest, window).await?;
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        loop {
            poll.tick().await;
            let (events, value) = events(client, after).await?;
            if observed.observe(&events)? {
                return Ok(());
            }
            after = cursor(&events, &value)?;
            if !retried && observed.requests == 0 && started.elapsed() >= Duration::from_secs(15) {
                retried = true;
                let active = xdotool(guest, "getactivewindow getwindowname").await;
                println!(
                    "Scripted reader: no article request within 15 s; active window: {active:?}"
                );
                println!("Scripted reader: retrying the reload once");
                reload(guest, window).await?;
            }
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(60), wait).await;
    result.map_err(|_| {
        io::Error::other(format!(
            "scripted reader did not receive tampered article at revision 1 \
             ({} article requests after the switch; reload retried: {retried})",
            observed.requests
        ))
    })?
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
        let (events, value) = events(&client, after).await?;
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
        let next = cursor(&events, &value)?;
        if next == after {
            break value["dropped"].clone();
        }
        after = next;
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

    require(
        client
            .request("GET", "/api/page", None, false)
            .await?
            .status
            == 401,
        "page API accepted a request without the token",
    )?;
    let missing = client
        .open(HOST, Capability::Screen, None)
        .await
        .err()
        .ok_or_else(|| io::Error::other("screen accepted a missing ticket"))?;
    require(
        missing.to_string().contains("HTTP/1.1 401 "),
        "missing ticket did not return 401",
    )?;
    let ticket = client.ticket(HOST, Capability::Screen).await?;
    let socket = client
        .open(HOST, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let reused = client
        .open(HOST, Capability::Screen, Some(&ticket.ticket))
        .await
        .err()
        .ok_or_else(|| io::Error::other("screen accepted a reused ticket"))?;
    require(
        reused.to_string().contains("HTTP/1.1 401 "),
        "reused ticket did not return 401",
    )?;
    drop(socket);
    println!("[pass] page security: token required, missing and reused tickets refused");
    println!("[pass] first read: real, revision 0");

    let window = article_window(guest).await?;
    println!("Scripted reader: the article's title is in Firefox window {window}");

    let mut stream = StateStream::open(run.page_url()).await?;
    let initial = stream.state("tamper", 0).await?;
    require(initial["value"]["on"] == false, "tampering must start off")?;
    let before = get(&client, "/api/events?after=0").await?["last"].as_u64();
    *switch = Some(before.ok_or_else(|| io::Error::other("events API has no cursor"))?);
    require(
        matches!(
            command(&client, "switch-on", true, 0).await?,
            Reply::Applied {
                revision: 1,
                changed: true,
                ..
            }
        ),
        "switch was not applied at revision 1",
    )?;
    stale_command(&client, "stale-switch", true, 0, 1).await?;
    let state = get(&client, "/api/state/tamper").await?;
    let streamed = stream.state("tamper", 1).await?;
    require(
        state["value"] == streamed["value"] && state["value"]["on"] == true,
        "GET and stream disagree about tampering",
    )?;
    println!(
        "[pass] switch: applied revision 1, stale revision rejected with HTTP 409 and world event, GET and stream agree"
    );

    second_read(&client, guest, window, switch.unwrap_or(0)).await?;
    let diff = get(&client, "/api/state/diff").await?;
    require(
        diff["status"]["too_large"] == false && diff["value"]["revision"] == 1,
        "diff is missing revision 1",
    )?;
    let diff: fakewiki_world::pages::diff::Diff = serde_json::from_value(diff["value"].clone())?;
    require(
        diff.topics
            .iter()
            .flat_map(|t| &t.sources)
            .any(|s| s.url == super::URL && s.served == fakewiki_world::pages::Version::Tampered),
        "diff does not mark the article tampered",
    )?;
    println!("[pass] second read: tampered, revision 1; diff agrees");

    for (path, pointer) in [
        ("/api/event-table/reads-scripted-reader", "/rows"),
        ("/api/egress", "/destinations"),
        ("/api/state/containment", "/value/probes"),
        ("/api/graph", "/nodes"),
    ] {
        let value = get(&client, path).await?;
        require(
            value
                .pointer(pointer)
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty()),
            &format!("panel has no data: {path}"),
        )?;
    }
    println!("[pass] panels: Reads, Left the box, containment and map have data");
    std::fs::create_dir_all(output)?;
    let screen = output.join("desktop.png");
    let capture = tokio::time::timeout(
        Duration::from_secs(30),
        rfb::capture_page(run.page_url(), HOST, &screen),
    )
    .await
    .map_err(|_| io::Error::other("guest screen capture timed out"))??;
    require(
        capture.width == 1280 && capture.height == 800 && capture.colors >= 16,
        "guest screen is blank or has unexpected dimensions",
    )?;
    println!("guest screenshot: {}", screen.display());
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
