mod checks;
mod guest;
mod page;
mod world;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::time::Instant;

use fictionet_demo::kit::Kit;
use fictionet_observe::page::Page;

const HOST: &str = "workstation";
const WIKI: &str = "en.wikipedia.org";
const ARTICLE: &str = "/wiki/Stream_ripping";
const URL: &str = "https://en.wikipedia.org/wiki/Stream_ripping";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let downloads = args
        .next()
        .map(PathBuf::from)
        .ok_or("usage: fakewiki <downloads-directory>; run cargo xtask demo fakewiki")?;
    if args.next().is_some() {
        return Err("usage: fakewiki <downloads-directory>".into());
    }
    let total = Instant::now();
    let controls = page::Controls::new("Firefox (scripted)");
    let ui = controls.clone();
    let run = Kit::new("fakewiki")
        .guest(guest::workstation())
        .page(move |dashboard, hosts| {
            ui.page(Page::new("FakeWiki", dashboard).host(hosts.take(HOST)))
        })
        .world(move |cx, world| start(cx, world, controls))
        .boot(&downloads)
        .await?;
    println!("Scripted reader: Firefox on workstation");
    println!(
        "boot to SSH-ready: {} ms",
        run.guest(HOST).ssh_ready().as_millis()
    );
    let output = downloads
        .join("shots")
        .join(run.path().file_name().unwrap());
    let result = checks::run(&run, &output).await;
    if result.is_err() {
        eprint!("{}", run.guest(HOST).diagnostics().await);
    }
    run.shutdown().await?;
    result?;
    println!("whole run: {} ms", total.elapsed().as_millis());
    println!("every required check passed");
    Ok(())
}

async fn start(
    cx: fictionet::Cx,
    mut world: fictionet_demo::kit::World,
    controls: page::Controls,
) -> fictionet::Result {
    let tampering =
        fakewiki_world::tamper::Tampering::new(false, fakewiki_world::tamper::Scope::Wikipedia);
    let (root, leaves) = world::certificates(&cx)?;
    world.trust("internet", &root)?;
    let mirror = world.mirror(&cx)?;
    let net = world::network(&cx, leaves, tampering.clone(), || {
        fictionet::stdlib::web::Site::new(mirror.clone())
    })?;
    controls.start(&cx, tampering)?;
    net.start(&cx, world.into_attachments())
}
