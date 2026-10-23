//! A VM-free page backed by requests made inside the Search world.

use super::Result;
use fictionet::{
    Cx,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
    },
};
use fictionet_demo::kit;
use fictionet_search_demo::{network, page};
use fictionet_test_support::sandbox::{self, Machine, machine};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use web_world::{
    World,
    pages::{self, Seed},
};

pub async fn run() -> Result {
    let seed = Seed::builtin(super::SEED)?;
    let downloads =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../downloads/cloudimage");
    let sample = kit::RunDir::new(&std::env::temp_dir(), "search-preview")?;
    let captured = seed
        .corpus
        .as_ref()
        .is_some_and(|corpus| downloads.parent().unwrap().join(&corpus.directory).is_dir());
    let query = if captured {
        "supply chain"
    } else {
        "black hole"
    };
    let pages = if captured {
        Arc::new(super::app_pages(seed.clone(), &downloads)?)
    } else {
        println!("No corpus downloads found. Preview uses the small bundled sky.org capture.");
        std::fs::write(
            sample.path().join("sky.warc.gz"),
            include_bytes!("../../../../extras/tests/fixtures/sky.warc.gz"),
        )?;
        Arc::new(pages::Pages::copied(
            seed.clone(),
            sample.path(),
            &["https://sky.org/".into()],
            None,
        )?)
    };
    let (page, (observations, commands)) = page::Page::new(&pages, true);
    let (stories, mut story_requests) = tokio::sync::mpsc::channel::<()>(1);
    let route = stories.clone();
    let router = page.router().route(
        "/story",
        axum::routing::post(move || {
            let route = route.clone();
            async move {
                match route.try_send(()) {
                    Ok(()) => http::StatusCode::ACCEPTED,
                    Err(_) => http::StatusCode::CONFLICT,
                }
            }
        }),
    );
    let server = page::serve(router, kit::PAGE_PORT).await?;
    let _access = kit::PageAccess::new(&server.url)?;
    let view = page.clone();
    let records =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../downloads/search-preview");
    let mut observe = tokio::spawn(async move { view.record(observations, &records).await });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(fictionet::run(
        fictionet::Seed::from_u64(7),
        move |cx| async move {
            let start = web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
            let world = World { pages, ..world };
            let (attacher, attachments) = fictionet::attachments();
            let log = Arc::new(fictionet_extras::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let net = network::build(&world, &cx, log, kit::mirror::new(&cx)?, None)?;
            net.start(&cx, attachments)?;
            page.run_commands(&cx, world.pages.clone(), commands);
            let workstation = machine(
                &cx,
                attacher.attach("workstation")?,
                "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
            );
            cx.spawn(move |cx| async move {
                loop {
                    story(&cx, &workstation, &world, query).await?;
                    println!("Preview story complete. Use Run story again on the page.");
                    if cx.race(None, story_requests.recv()).await?.is_none() {
                        break;
                    }
                }
                Ok(())
            });
            let _ = cx.race(None, stopped).await;
            cx.cancel();
            Ok(())
        },
    ));
    println!(
        "No VM. The preview client searches and opens pages inside the world. Press Ctrl-C to stop."
    );
    let result = tokio::select! {
        result = tokio::signal::ctrl_c() => { result?; let _=stop.send(()); task.await },
        result = &mut task => result,
        result = &mut observe => {
            let _ = stop.send(());
            let _ = task.await;
            server.shutdown().await;
            return Err(super::recording_error(result).into());
        },
    };
    server.shutdown().await;
    observe.await.map_err(std::io::Error::other)??;
    result??;
    Ok(())
}
async fn fetch(
    cx: &Cx,
    machine: &Machine,
    host: &str,
    path: &str,
    start: SystemTime,
) -> fictionet::Result {
    let answer = machine
        .lookup(cx, "10.0.0.1".parse()?, host, RecordType::A)
        .await?;
    let addr = answer
        .answers
        .iter()
        .find_map(|record| match record.data {
            RData::A(addr) => Some(addr.0),
            _ => None,
        })
        .ok_or_else(|| fictionet::Error::msg("name has no address"))?;
    let mut conn = machine
        .tls(cx, (addr, 443).into(), host, None, start)
        .await?;
    let request =
        http1::Request::parse(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())?;
    let response = sandbox::request(cx, &mut conn, &request).await?;
    if response.head.status != 200 {
        return Err(fictionet::Error::msg(format!(
            "{host}{path}: HTTP {}",
            response.head.status
        )));
    }
    println!("Preview opened https://{host}{path}");
    Ok(())
}
async fn story(cx: &Cx, machine: &Machine, world: &World, query: &str) -> fictionet::Result {
    use fictionet_extras::models::Engine;
    // These pauses pace the presentation; tests drive the same services without them.
    cx.sleep(Duration::from_secs(1)).await?;
    fetch(cx, machine, "api.anthropic.com", "/api/hello", world.start).await?;
    fetch(
        cx,
        machine,
        "www.google.com",
        &format!("/search?q={}", query.replace(' ', "+")),
        world.start,
    )
    .await?;
    cx.sleep(Duration::from_millis(800)).await?;
    let hits = world
        .pages
        .clone()
        .search(
            cx.clone(),
            query.into(),
            "claude_web_search",
            serde_json::json!({}),
        )
        .await?;
    for hit in hits.iter().take(3) {
        let (host, path) = pages::text::target_of(&hit.url);
        fetch(cx, machine, &host, &path, world.start).await?;
        cx.sleep(Duration::from_millis(800)).await?;
    }
    fetch(
        cx,
        machine,
        "www.bing.com",
        &format!("/search?q={}", query.replace(' ', "+")),
        world.start,
    )
    .await?;
    fetch(
        cx,
        machine,
        "html.duckduckgo.com",
        &format!("/html/?q={}", query.replace(' ', "+")),
        world.start,
    )
    .await?;
    machine
        .lookup(cx, "10.0.0.1".parse()?, "wiki.corp", RecordType::A)
        .await?;
    let _ = cx
        .race(
            Some(cx.now() + Duration::from_secs(3)),
            machine.tcp.connect(cx, "1.1.1.1:443".parse()?),
        )
        .await;
    Ok(())
}
