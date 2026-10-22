//! `search preview`: the search page with real world traffic, an in-world
//! scripted client and a labeled preview console.

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
use fictionet_demo::kit::{
    self,
    preview::{Input, Story},
};
use fictionet_extras::search::Engine;
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Containment, Host, HostState, HostStatus, Labels, StateLimits, StateTopic},
};
use fictionet_search_demo::{network, page::Topics};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use web_world::{
    Addresses, Ca, World,
    pages::{self, Seed},
    search::Searches,
};

use super::Result;

fn search_url(engine: Engine, words: &str) -> String {
    let host = match engine {
        Engine::Google => "www.google.com/search?q=",
        Engine::Bing => "www.bing.com/search?q=",
        Engine::DuckDuckGo => "html.duckduckgo.com/html/?q=",
        Engine::YouTube => "www.youtube.com/results?search_query=",
    };
    format!("https://{host}{}", pages::text::quote(words, ""))
}

fn preview_pages(seed: Seed) -> Result<Arc<pages::Pages>> {
    Ok(Arc::new(super::app_pages(
        seed,
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../downloads/cloudimage"),
    )?))
}

pub async fn run() -> Result {
    let seed = Seed::builtin(super::SEED)?;
    let script = seed.clone();
    let pages = preview_pages(seed.clone())?;
    let searches = Arc::new(Searches::of(&pages));
    let topics = Topics::new();
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
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
        .bind_loopback(kit::PAGE_PORT)
        .await?;
    let _access = fictionet_demo::kit::PageAccess::new(server.url())?;
    println!(
        "No VM. The screen is a preview console; an in-world scripted client makes the traffic."
    );
    let mut input = Input::stdin(Story::Once, Some(console))?;
    let audit = Arc::new(example_common::guest_content::Audit::default());
    let observer = Arc::new(Fanout::new(vec![
        audit.clone(),
        searches.clone(),
        dashboard.observer(),
    ]));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
        move |cx| async move {
            containment.publish(cx.now(), &Containment::default())?;
            let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
            let start = web_world::world_start(&seed.date)?;
            let world = World {
                ca: Arc::new(Ca::in_memory(&cx, start)?),
                addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
                pages,
                start,
            };
            let (attacher, attachments) = fictionet::attachments();
            network::build(&world, &cx, log, kit::mirror::new(&cx)?)?.start(&cx, attachments)?;
            topics.start(&cx, searches.clone(), world.pages.clone())?;
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
                    };
                    story(&client, &script).await?;
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
    audit.check()?;
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
}

/// The seed's searches and pages, in the order a reader would make them.
async fn story(client: &Client<'_>, seed: &Seed) -> fictionet::Result {
    let Client {
        cx,
        machine,
        world,
        searches,
    } = *client;
    let words = "black hole";
    let pause = || cx.sleep(Duration::from_secs(3));
    // Give viewers a chance to see the empty world before the first request.
    cx.sleep(Duration::from_secs(8)).await?;
    fetch(cx, machine, &search_url(Engine::Google, words), world.start).await?;
    pause().await?;
    let state = searches.snapshot();
    let list = state
        .results
        .first()
        .ok_or_else(|| fictionet::Error::msg("search returned no stored results"))?;
    for result in list.listed.iter().take(3) {
        pause().await?;
        fetch(cx, machine, &result.url, world.start).await?;
    }
    let opened = [
        search_url(Engine::Bing, words),
        search_url(Engine::DuckDuckGo, &format!("{words} details")),
        "https://en.wikipedia.org/wiki/Astronomy".to_owned(),
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
    let new = "dishwasher repair";
    fetch(cx, machine, &search_url(Engine::Google, new), world.start).await?;
    pause().await?;
    fetch(cx, machine, &search_url(Engine::Google, words), world.start).await?;
    Ok(())
}
