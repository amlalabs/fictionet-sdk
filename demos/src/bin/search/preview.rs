//! `search preview`: the search page with real world traffic, an in-world
//! scripted client and a labeled preview console.

use adaptive_web_world::{
    Addresses, Ca, World,
    pages::{self, Seed},
    search::Searches,
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
    search::{self as page, Topics},
};
use fictionet_extras::search::Engine;
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Containment, Host, HostState, HostStatus, Labels, StateLimits, StateTopic},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use super::{Result, checks::search_url};

fn preview_pages(seed: Seed) -> Result<Arc<pages::Pages>> {
    Ok(Arc::new(super::app_pages(seed)?))
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
    let page_client = PageClient::from_url(server.url())?;
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
            let start = adaptive_web_world::world_start(&seed.date)?;
            let world = World {
                ca: Arc::new(Ca::in_memory(&cx, start)?),
                addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
                pages,
                start,
            };
            let (attacher, attachments) = fictionet::attachments();
            page::network(&world, &cx, log, kit::mirror::new(&cx)?, None)?
                .start(&cx, attachments)?;
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
                        page: &page_client,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_supports_every_page_mode() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)),
            |cx| async move {
                let seed = Seed::builtin(super::super::SEED)?;
                let pages = preview_pages(seed).unwrap();
                assert_eq!(pages.new_pages(), pages::NewPages::Canned);
                let searches = Searches::of(&pages);
                assert!(searches.snapshot().generator.canned);
                for new_pages in [
                    pages::NewPages::Canned,
                    pages::NewPages::Stub,
                    pages::NewPages::Off,
                ] {
                    pages
                        .apply(
                            &cx,
                            pages::Command::SetNewPages {
                                new_pages,
                                expected_revision: pages.generation().revision,
                            },
                        )
                        .unwrap();
                    assert_eq!(pages.new_pages(), new_pages);
                }
                Ok(())
            },
        ))
        .unwrap();
    }
}
