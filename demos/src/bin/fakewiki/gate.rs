use std::io;
use std::path::Path;
use std::time::Duration;

use fakewiki_world::tamper::Reply;
use fictionet_demo::kit::{
    Run,
    client::{Capability, PageClient},
    gate::check,
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

pub(super) async fn read(client: &PageClient, served: &str, revision: u64) -> io::Result<()> {
    event(
        client,
        &format!("scripted reader did not receive {served} article at revision {revision}"),
        |event| {
            let fields = &event["fields"];
            event["source"] == "http"
                && event["kind"] == "request"
                && event["sandbox"]["name"] == HOST
                && fields["host"] == WIKI
                && fields["path"] == ARTICLE
                && fields["served"] == served
                && fields["tamper_revision"] == revision
                && fields["status"] == 200
                && fields["complete"] == true
        },
    )
    .await
}

pub async fn run(run: &Run, output: &Path) -> io::Result<()> {
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

    let mut stream = StateStream::open(run.page_url()).await?;
    let initial = stream.state("tamper", 0).await?;
    check("tampering starts off", initial["value"]["on"] == false)?;
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

    let reload = tokio::time::timeout(Duration::from_secs(30), guest.ssh().run(
        "env DISPLAY=:1 xdotool search --sync --onlyvisible --class firefox windowactivate --sync key --clearmodifiers ctrl+F5"
    )).await.map_err(|_| io::Error::other("scripted Firefox reload timed out"))??;
    if reload.code != 0 {
        println!("{}", reload.stderr);
    }
    check("scripted Firefox reloads the article", reload.code == 0)?;
    read(&client, "tampered", 1).await?;
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
    let shots = run
        .screenshots(HOST, &output.join("desktop.png"), &output.join("page.png"))
        .await?;
    check(
        "the guest screen is 1280x800",
        shots.screen.width == 1280 && shots.screen.height == 800,
    )?;
    Ok(())
}
