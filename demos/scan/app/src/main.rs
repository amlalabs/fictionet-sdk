//! Two Ubuntu guests inventory an office through the shared kit.
mod client;
mod guests;
mod nmap;
mod page;
mod preview;
mod script;
mod world;

use fictionet_demo::kit::Kit;
use fictionet_observe::page::Page;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, atomic::AtomicBool};

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
    let closed = Arc::new(AtomicBool::new(false));
    let cutoff = closed.clone();
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
            Ok(())
        });
    kit.run_app(downloads, guests::WORKSTATION).await?;
    Ok(())
}
