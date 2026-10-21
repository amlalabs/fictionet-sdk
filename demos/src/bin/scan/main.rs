//! Two Ubuntu guests inventory an office through the shared kit. A scripted
//! agent runs three nmap steps in the workstation's terminal; the office
//! server is a second VM among four simulated machines. The page shows both
//! VMs and the Office, Ports and Services panels; the checks compare nmap's
//! reports, the world's port map and the page's own API.
mod checks;
mod client;
mod guests;
mod nmap;
mod page;
mod preview;
mod script;
mod story;
mod world;

use fictionet_demo::kit::{self, Kit, client::PageClient};
use fictionet_observe::page::Page;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let rest: Vec<String> = args.collect();
    let start = |runtime: tokio::runtime::Runtime| match first.as_deref() {
        Some("preview") => runtime.block_on(preview::run(rest.into_iter())),
        Some(downloads) if rest.is_empty() => runtime.block_on(run(Path::new(downloads))),
        _ => Err("usage: scan <downloads>, or scan preview [--bound] [--no-os-match ADDR]".into()),
    };
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| -> Error { e.into() })
        .and_then(start);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("scan: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(downloads: &Path) -> Result<(), Error> {
    let out = kit::checks::output(downloads, "scan")?;
    let closed = Arc::new(AtomicBool::new(false));
    let cutoff = closed.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    let topics = page::Topics::new();
    let progress = page::Progress::new(false);
    let published = (topics.clone(), progress.clone());
    let kit = Kit::new("scan")
        .guest(guests::workstation())
        .guest(guests::server())
        .page(move |dashboard, hosts| {
            topics.compose(
                Page::new(page::TITLE, dashboard)
                    .host(hosts.take(guests::WORKSTATION).pinned())
                    .host(hosts.take(guests::SERVER).pinned()),
            )
        })
        .world(move |cx, world| async move {
            let ports = world::start(&cx, world, cutoff)?;
            let (topics, progress) = published;
            page::publish(&cx, ports.clone(), topics, progress);
            let _ = send.send(ports);
            Ok(())
        });
    kit::checks::run(
        kit,
        downloads,
        &out,
        kit::checks::story(move |run, out| -> kit::checks::Story<'_, Error> {
            Box::pin(async move {
                let ports = receive.await?;
                closed.store(true, Ordering::SeqCst);
                println!("apt mirror closed: subsequent HTTP requests receive 403");
                story::run(run, &ports, out, &progress).await?;
                tokio::time::timeout(Duration::from_secs(45), page_checks(run.page_url()))
                    .await??;
                Ok::<_, Error>(())
            })
        }),
    )
    .await?;
    Ok(())
}

async fn page_checks(url: &str) -> Result<(), Error> {
    let client = PageClient::from_url(url)?;
    client.bootstrap().await?;
    let description = client.get_json("/api/page").await?;
    let hosts = description["hosts"].as_array().ok_or("page has no hosts")?;
    kit::checks::check(
        "the page pins both guests",
        hosts.len() == 2 && hosts.iter().all(|h| h["pinned"] == true),
    )?;
    // The world task publishes at most every 250 ms, so the last story step
    // can reach the page a moment after the story ends.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (topics, moment) = checks::read(&client).await?;
        match checks::check(&topics, &moment) {
            Ok(summary) => {
                println!("[pass] page topics: {summary}");
                return Ok(());
            }
            Err(error) if Instant::now() > deadline => {
                return Err(format!("page topics: {error}").into());
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}
