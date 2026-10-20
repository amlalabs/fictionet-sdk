//! The search page with real world traffic and a labeled preview console.
//!
//! `--spend-budget` ends the story by turning generation back on and making
//! new searches until the world refuses one for its generation budget. The
//! page's `preview-screen` command closes the preview screen's connection, so
//! the lost-connection state can be seen.

use adaptive_web_world::{
    pages::{self, Seed},
    search::{Failure, Outcome, Searches},
};
use example_common::log::Log;
use fictionet::{
    Cx,
    events::Fanout,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
        world::sandbox::{self, Machine, machine},
    },
};
use fictionet_demo::{
    kit::{self, client::PageClient},
    search::{Topics, World},
};
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{
        CommandLimits, CommandPort, Containment, Host, HostState, HostStatus, Labels, StateLimits,
        StateTopic,
    },
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Closes the preview screen's open connection: `{"command":"drop"}`.
#[derive(serde::Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ScreenCommand {
    Drop,
}

#[tokio::main]
async fn main() -> Result {
    let spend = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--spend-budget" => true,
        _ => return Err("usage: search_page [--spend-budget]".into()),
    };
    let seed = Seed::builtin("halvard-cve")?;
    let searches = Arc::new(Searches::from_seed(&seed));
    let topics = Topics::new();
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let status = StateTopic::new(StateLimits::default());
    let labels = Labels::default();
    let containment = StateTopic::new(StateLimits::default());
    let console = kit::preview::Console::new();
    let screen = CommandPort::<ScreenCommand, ()>::new(CommandLimits::default());
    let server = topics
        .page(
            dashboard.handle(),
            Host::new("workstation")
                .sandbox("workstation")
                .console(console.clone())
                .status(status.clone()),
        )
        .labels(labels.clone())
        .containment(containment.clone())
        .command("preview-screen", screen.clone())
        .bind_loopback(0)
        .await?;
    println!("Search preview: {}", server.url());
    println!(
        "No VM. The screen is a preview console; an in-world scripted client makes the traffic."
    );
    let page_client = PageClient::from_url(server.url())?;
    let observer = Arc::new(Fanout::new(vec![searches.clone(), dashboard.observer()]));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
        move |cx| async move {
            containment.publish(cx.now(), &Containment::default())?;
            let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
            let world = World::new(&cx, seed, log)?;
            let (attacher, attachments) = fictionet::attachments();
            world
                .network(&cx, kit::mirror::new(&cx)?)?
                .start(&cx, attachments)?;
            topics.start(
                &cx,
                searches.clone(),
                world.pages.clone(),
                "In-world client (scripted) · no VM",
            )?;
            let client = machine(
                &cx,
                attacher.attach("workstation")?,
                "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
            );
            status.publish(
                cx.now(),
                &HostStatus {
                    state: HostState::DesktopUp,
                    addresses: vec!["10.0.0.2".into()],
                    screen: true,
                    terminal: false,
                },
            )?;
            cx.spawn(move |cx| async move {
                labels.run(&cx).await?;
                Ok(())
            });
            cx.spawn(move |cx| async move {
                while let Some(command) = cx.race(None, screen.recv()).await? {
                    let ScreenCommand::Drop = command.command;
                    console.drop_connections();
                    println!("Preview screen connection dropped");
                    command.reply(&cx, ());
                }
                Ok(())
            });
            cx.spawn(move |cx| async move {
                let result = async {
                    story(&cx, &client, &world, &searches, &page_client).await?;
                    if spend {
                        spend_budget(&cx, &client, &world, &searches, &page_client).await?;
                    }
                    Ok::<_, fictionet::Error>(())
                }
                .await;
                if let Err(error) = result {
                    eprintln!("Preview story failed: {error}");
                    return Err(error);
                }
                println!("Preview story complete.");
                Ok(())
            });
            let _ = cx.race(None, stopped).await;
            cx.cancel();
            Ok(())
        },
    ));
    kit::gate::stay_open().await?;
    let _ = stop.send(());
    task.await??;
    drop(server);
    Ok(())
}

/// Opens a page and requires HTTP 200.
async fn fetch(
    cx: &Cx,
    machine: &Machine,
    url: &str,
    start: SystemTime,
) -> fictionet::Result<String> {
    let (status, body) = get(cx, machine, url, start).await?;
    if status != 200 {
        return Err(fictionet::Error::msg(format!("{url}: HTTP {status}")));
    }
    Ok(body)
}

async fn get(
    cx: &Cx,
    machine: &Machine,
    url: &str,
    start: SystemTime,
) -> fictionet::Result<(u16, String)> {
    let (host, path) = pages::text::target_of(url);
    let answer = machine
        .lookup(cx, "10.0.0.1".parse()?, &host, RecordType::A)
        .await?;
    let addr = answer
        .answers
        .iter()
        .find_map(|r| {
            if let RData::A(a) = r.data {
                Some(a.0)
            } else {
                None
            }
        })
        .ok_or_else(|| fictionet::Error::msg("name has no address"))?;
    let mut conn = machine
        .tls(cx, (addr, 443).into(), &host, None, start)
        .await?;
    let request =
        http1::Request::parse(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())?;
    let response = sandbox::request(cx, &mut conn, &request).await?;
    println!(
        "Scripted client opened {url} (HTTP {})",
        response.head.status
    );
    Ok((
        response.head.status,
        String::from_utf8_lossy(&response.body).into_owned(),
    ))
}

async fn story(
    cx: &Cx,
    client: &Machine,
    world: &World,
    searches: &Searches,
    page: &PageClient,
) -> fictionet::Result {
    let pause = || cx.sleep(Duration::from_secs(3));
    // Give viewers a chance to see the empty world before the first request.
    cx.sleep(Duration::from_secs(8)).await?;
    fetch(
        cx,
        client,
        "https://www.google.com/search?q=halvard+gateway+vulnerability",
        world.start,
    )
    .await?;
    pause().await?;
    let state = searches.snapshot();
    let first = state
        .results
        .first()
        .and_then(|r| {
            r.listed
                .iter()
                .find(|r| !state.seed.sites.contains(&r.host))
        })
        .ok_or_else(|| fictionet::Error::msg("search returned no generated result"))?;
    let mut url = first.url.clone();
    let mut html = fetch(cx, client, &url, world.start).await?;
    for _ in 0..2 {
        pause().await?;
        let state = searches.snapshot();
        let (host, path, _) = pages::links(&url, &html)
            .into_iter()
            .find(|(host, path, anchor)| {
                anchor.ends_with(": follow-up")
                    && !state
                        .pages
                        .iter()
                        .any(|p| p.url == format!("https://{host}{path}"))
            })
            .ok_or_else(|| fictionet::Error::msg("page has no unvisited link"))?;
        url = format!("https://{host}{path}");
        html = fetch(cx, client, &url, world.start).await?;
    }
    for url in [
        "https://www.bing.com/search?q=halvard+gateway+vulnerability",
        "https://html.duckduckgo.com/html/?q=halvard+gateway+vulnerability+details",
        "https://www.halvardsystems.com/security/advisories/",
        "https://www.halvardsystems.com/security/advisories/HSA-2026-014",
    ] {
        pause().await?;
        fetch(cx, client, url, world.start).await?;
    }
    pause().await?;
    client
        .lookup(cx, "10.0.0.1".parse()?, "wiki.corp", RecordType::A)
        .await?;
    println!("Scripted client asked for wiki.corp");
    pause().await?;
    generation(page, searches, false).await?;
    fetch(
        cx,
        client,
        "https://www.google.com/search?q=halvard+gateway+vulnerability+new+question",
        world.start,
    )
    .await?;
    pause().await?;
    fetch(
        cx,
        client,
        "https://www.google.com/search?q=halvard+gateway+vulnerability",
        world.start,
    )
    .await?;
    Ok(())
}

/// Sends the generation switch through the page, as a viewer's click would.
async fn generation(page: &PageClient, searches: &Searches, generate: bool) -> fictionet::Result {
    let revision = searches.snapshot().generator.generation_revision;
    let reply = page
        .command(
            "generation",
            &format!("preview-generation-{revision}"),
            serde_json::json!({"command": "set_generation", "generate": generate,
                "expected_revision": revision}),
        )
        .await
        .map_err(fictionet::Error::msg)?;
    if reply["status"] != "applied" {
        return Err(fictionet::Error::msg(format!(
            "generation command: {reply}"
        )));
    }
    println!(
        "Generation {} at revision {}",
        if generate { "on" } else { "off" },
        reply["reply"]["revision"]
    );
    Ok(())
}

/// Makes new searches until the world refuses one for its generation budget.
async fn spend_budget(
    cx: &Cx,
    client: &Machine,
    world: &World,
    searches: &Searches,
    page: &PageClient,
) -> fictionet::Result {
    cx.sleep(Duration::from_secs(3)).await?;
    generation(page, searches, true).await?;
    println!("Spending the generation budget with new searches");
    // Every search with a new key takes one generation call. The bound is far
    // above the stub's budget, so it only stops a story that cannot fail.
    for n in 1..=1_000 {
        let url = format!("https://www.google.com/search?q=halvard+gateway+question+{n}");
        let (status, _) = get(cx, client, &url, world.start).await?;
        let failed = searches.snapshot().queries.iter().any(|q| {
            q.search == format!("halvard gateway question {n}")
                && matches!(
                    q.outcome,
                    Outcome::Failed {
                        why: Failure::Budget,
                        ..
                    }
                )
        });
        if failed {
            println!("Search {n} failed: the world answered HTTP {status} for its budget");
            return Ok(());
        }
    }
    Err(fictionet::Error::msg("the generation budget was not spent"))
}
