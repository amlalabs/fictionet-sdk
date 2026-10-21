//! An Ubuntu desktop with coding agents that sign in inside the VM.
mod guest;
mod world;

use fictionet_demo::kit::Kit;
use fictionet_observe::page::Page;
use std::path::PathBuf;

const HOSTNAME: &str = "workstation";
const USER: &str = "analyst";
const SITE: &str = "intranet.northwind.internal";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [downloads] = args.as_slice() else {
        return Err("usage: desktop <downloads>".into());
    };
    Kit::new("desktop")
        .guest(guest::workstation(HOSTNAME, USER, SITE))
        .page(|dashboard, hosts| {
            Page::new("Desktop", dashboard)
                .host(hosts.take(HOSTNAME))
                .standard_panels()
                .architecture(fictionet_demo::kit::architecture("adaptive"))
                .app()
        })
        .world(|cx, world| world::start(cx, world, SITE.into()))
        .run_app(downloads, HOSTNAME)
        .await?;
    Ok(())
}
