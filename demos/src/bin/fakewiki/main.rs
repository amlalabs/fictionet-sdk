mod checks;
mod guest;
mod page;
mod preview;
mod world;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use fictionet_demo::kit::{self, Kit};
use fictionet_observe::page::Page;

const HOST: &str = "workstation";
const WIKI: &str = "en.wikipedia.org";
const ARTICLE: &str = "/wiki/Stream_ripping";
const URL: &str = "https://en.wikipedia.org/wiki/Stream_ripping";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const USAGE: &str = "usage: fakewiki <downloads>, or fakewiki preview";
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [first, rest @ ..] = args.as_slice() else {
        return Err(USAGE.into());
    };
    if !rest.is_empty() {
        return Err(USAGE.into());
    }
    if first.as_os_str() == "preview" {
        return preview::run().await;
    }
    let downloads = first;
    let output = kit::checks::output(downloads, "fakewiki")?;
    let controls = page::Controls::new("Firefox (scripted)");
    let ui = controls.clone();
    let kit = Kit::new("fakewiki")
        .guest(guest::workstation())
        .page(move |dashboard, hosts| {
            ui.page(Page::new("FakeWiki", dashboard).host(hosts.take(HOST)))
        })
        .world(move |cx, world| start(cx, world, controls));
    kit::checks::run(
        kit,
        downloads,
        &output,
        kit::checks::story(
            |run, out| -> kit::checks::Story<'_, Box<dyn std::error::Error + Send + Sync>> {
                Box::pin(async move { checks::run(run, out).await.map_err(Into::into) })
            },
        ),
    )
    .await?;
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
