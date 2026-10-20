//! `search preview`: the search page with real world traffic, an in-world
//! scripted client and a labeled preview console.
//!
//! `--spend-budget` ends the story by turning generation back on and making
//! new searches until the world refuses one for its generation budget.

use adaptive_web_world::{
    pages::{self, Seed},
    route::Engine,
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
    kit::{
        self,
        client::PageClient,
        preview::{Input, Story},
    },
    search::{Topics, World},
};
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Containment, Host, HostState, HostStatus, Labels, StateLimits, StateTopic},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use super::{Result, checks::search_url};

pub async fn run(spend: bool) -> Result {
    let seed = Seed::builtin("halvard-cve")?;
    let script = seed.clone();
    let searches = Arc::new(Searches::from_seed(&seed));
    let topics = Topics::new();
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let status = StateTopic::new(StateLimits::default());
    let labels = Labels::default();
    let containment = StateTopic::new(StateLimits::default());
    let console = kit::preview::Console::new();
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
        .bind_loopback(0)
        .await?;
    println!("Search preview: {}", server.url());
    println!(
        "No VM. The screen is a preview console; an in-world scripted client makes the traffic."
    );
    let mut input = Input::stdin(Story::Once, Some(console))?;
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
            let workstation = machine(
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
                let result = async {
                    let client = Client {
                        cx: &cx,
                        machine: &workstation,
                        world: &world,
                        searches: &searches,
                        page: &page_client,
                    };
                    story(&client, &script).await?;
                    if spend {
                        spend_budget(&client, &script).await?;
                    }
                    Ok::<_, fictionet::Error>(())
                }
                .await;
                if let Err(error) = result {
                    // Stopping the preview mid-story cancels the run.
                    if !cx.is_cancelled() {
                        eprintln!("Preview story failed: {error}");
                    }
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
    input.closed().await;
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

/// The scripted client in the world, and the page it reports to.
struct Client<'a> {
    cx: &'a Cx,
    machine: &'a Machine,
    world: &'a World,
    searches: &'a Searches,
    page: &'a PageClient,
}

/// The seed's searches and pages, in the order a reader would make them.
async fn story(client: &Client<'_>, seed: &Seed) -> fictionet::Result {
    let Client {
        cx,
        machine,
        world,
        searches,
        page,
    } = *client;
    let words = seed.search.as_str();
    let pause = || cx.sleep(Duration::from_secs(3));
    // Give viewers a chance to see the empty world before the first request.
    cx.sleep(Duration::from_secs(8)).await?;
    fetch(cx, machine, &search_url(Engine::Google, words), world.start).await?;
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
    let mut html = fetch(cx, machine, &url, world.start).await?;
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
        html = fetch(cx, machine, &url, world.start).await?;
    }
    let opened = [
        search_url(Engine::Bing, words),
        search_url(Engine::DuckDuckGo, &format!("{words} details")),
        seed.visit.clone(),
    ];
    for url in opened.iter().chain(seed.fixed.iter().map(|f| &f.url)) {
        pause().await?;
        fetch(cx, machine, url, world.start).await?;
    }
    pause().await?;
    machine
        .lookup(cx, "10.0.0.1".parse()?, "wiki.corp", RecordType::A)
        .await?;
    println!("Scripted client asked for wiki.corp");
    pause().await?;
    generation(page, searches, false).await?;
    let new = format!("{words} new question");
    fetch(cx, machine, &search_url(Engine::Google, &new), world.start).await?;
    pause().await?;
    fetch(cx, machine, &search_url(Engine::Google, words), world.start).await?;
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
async fn spend_budget(client: &Client<'_>, seed: &Seed) -> fictionet::Result {
    let Client {
        cx,
        machine,
        world,
        searches,
        page,
    } = *client;
    cx.sleep(Duration::from_secs(3)).await?;
    generation(page, searches, true).await?;
    println!("Spending the generation budget with new searches");
    // Every search with a new key takes one generation call. The bound is far
    // above the stub's budget, so it only stops a story that cannot fail.
    for n in 1..=1_000 {
        let words = format!("{} question {n}", seed.search);
        let (status, _) = get(
            cx,
            machine,
            &search_url(Engine::Google, &words),
            world.start,
        )
        .await?;
        let failed = searches.snapshot().queries.iter().any(|q| {
            q.search == words
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
