use std::io;
use std::path::Path;
use std::time::Duration;

use fakewiki_world::tamper::Reply;
use fictionet_demo::kit::{
    GuestHandle, Run,
    checks::{self, check},
    client::{Capability, PageClient},
    shot,
};
use serde_json::{Value, json};

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
            missing,
            |event| Ok(matches(event)),
        )
        .await?;
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
        .wait_for_event(
            after,
            Duration::from_secs(15),
            POLL,
            "no tampered article read arrived",
            |event| observed.observe(std::slice::from_ref(event)),
        )
        .await;
    if wait
        .as_ref()
        .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut)
    {
        if observed.requests == 0 {
            retried = true;
            let active = xdotool(guest, "getactivewindow getwindowname").await;
            println!("Scripted reader: no article request within 15 s; active window: {active:?}");
            println!("Scripted reader: retrying the reload once");
            reload(guest, window).await?;
        }
        wait = client
            .wait_for_event(
                observed.last.max(after),
                Duration::from_secs(45),
                POLL,
                "no tampered article read arrived",
                |event| observed.observe(std::slice::from_ref(event)),
            )
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

/// Runs the checks. On a failure it prints the article's requests and saves
/// the guest's screen before it returns the error.
pub async fn run(run: &Run, output: &Path) -> io::Result<()> {
    let mut switch = None;
    let result = checks(run, output, &mut switch).await;
    if let Err(error) = &result {
        eprintln!("Checks failed: {error}");
        let requests = article_requests(run, switch);
        match tokio::time::timeout(Duration::from_secs(10), requests).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("Article requests unavailable: {error}"),
            Err(_) => eprintln!("Article requests unavailable: timed out"),
        }
        let path = output.join("failure-desktop.png");
        let capture = async {
            std::fs::create_dir_all(output)?;
            run.screen(HOST, &path).await
        };
        if let Err(error) = capture.await {
            eprintln!("Guest screen unavailable: {error}");
        }
    }
    result
}

/// Prints the article's requests since the switch, or since the start
/// when the checks failed before it.
async fn article_requests(run: &Run, switch: Option<u64>) -> io::Result<()> {
    let client = PageClient::from_url(run.page_url())?;
    let since = if switch.is_some() {
        "the switch"
    } else {
        "the start"
    };
    eprintln!("Article requests since {since}:");
    let (mut after, mut count) = (switch.unwrap_or(0), 0);
    client
        .find_event(&mut after, |event| {
            if article(event) {
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
            Ok(false)
        })
        .await?;
    let dropped = client.events(0).await?["dropped"].clone();
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

    checks::bearer_required(&client).await?;
    checks::single_use_ticket(&client, HOST, Capability::Screen).await?;
    println!("[pass] first read: real, revision 0");

    let window = article_window(guest).await?;
    println!("Scripted reader: the article's title is in Firefox window {window}");

    let mut stream = client.state_stream(&["tamper", "diff"]).await?;
    let initial = stream
        .next("tamper", |s| s["value"]["revision"] == 0)
        .await?;
    check("tampering starts off", initial["value"]["on"] == false)?;
    *switch = Some(client.last_event().await?);
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
    let streamed = stream
        .next("tamper", |s| s["value"]["revision"] == 1)
        .await?;
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

    run.containment().await?;
    for (path, pointer) in [
        ("/api/event-table/reads-scripted-reader", "/rows"),
        ("/api/egress", "/destinations"),
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
    println!("[pass] panels: Reads, Left the box and map have data");
    std::fs::create_dir_all(output)?;
    let screen = output.join("desktop.png");
    let (capture, _) = run.settled_screen(HOST, &screen).await?;
    check(
        "the guest screen is 1280x800",
        capture.width == 1280 && capture.height == 800,
    )?;
    run.page_shot(
        &output.join("page.png"),
        &shot::desktop_painted(HOST),
        Duration::from_secs(30),
    )
    .await?;
    Ok(())
}
