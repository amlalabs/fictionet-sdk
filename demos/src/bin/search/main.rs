//! The Search demo: an Ubuntu desktop with Firefox and Claude Code on the
//! astronomy corpus, with optional model-written pages.
//!
//! - `search <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. Copied pages answer searches and fetches without a model.
//! - `search preview` shows the page with an in-world client and no VM.

mod guest;
mod preview;
use fictionet_demo::search as page;

use example_common::log::Log;
use fictionet_demo::kit::{self, Kit};
use std::{fs::File, path::PathBuf, sync::Arc, time::Instant};
use web_world::{
    Addresses, Ca, World,
    events::LogObserver,
    pages::{Pages, Seed},
    search::Searches,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The seed for model-written astronomy pages.
const SEED: &str = "web";

/// The app with its downloads folder, or the preview without a VM.
#[derive(Debug, PartialEq)]
enum Mode {
    App { downloads: PathBuf },
    Preview,
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode> {
    const USAGE: &str = "usage: search <downloads> or search preview";
    let first = args.next().ok_or(USAGE)?;
    let second = args.next();
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    match (first.as_str(), second.as_deref()) {
        ("preview", None) => Ok(Mode::Preview),
        ("preview", _) => Err(USAGE.into()),
        (folder, _) if folder.starts_with('-') => Err(USAGE.into()),
        (folder, None) => Ok(Mode::App {
            downloads: folder.into(),
        }),
        _ => Err(USAGE.into()),
    }
}

fn app_pages(seed: Seed, downloads: &std::path::Path) -> Result<Pages> {
    let model = std::env::var_os("OPENROUTER_API_KEY")
        .map(|_| web_world::pages::model::Model::openrouter())
        .transpose()?;
    let seeds = include_str!("../../../corpus/astronomy.urls")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok(Pages::copied(
        seed,
        &downloads.join("astronomy"),
        &seeds,
        model,
    )?)
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let downloads = match arguments(std::env::args().skip(1))? {
        Mode::Preview => return preview::run().await,
        Mode::App { downloads } => downloads,
    };
    let seed = Seed::builtin(SEED)?;
    let pages = Arc::new(app_pages(seed.clone(), &downloads)?);
    let output = kit::checks::output(&downloads, "search")?;
    let searches = Arc::new(Searches::of(&pages));
    let topics = page::Topics::new();
    let view = topics.clone();
    let log = Arc::new(Log::new(
        Box::new(File::create(output.join("log.jsonl"))?),
        &[],
        |s| s,
    ));
    let world_log = log.clone();
    let kit = Kit::new("search")
        .guest(guest::guest(&seed.date))
        .observer(searches.clone())
        .observer(Arc::new(LogObserver { log: log.clone() }))
        .page(move |dashboard, hosts| view.page(dashboard, hosts.take(guest::HOST)))
        .world(move |cx, mut world| async move {
            let start = web_world::world_start(&seed.date)?;
            let web = World {
                ca: Arc::new(Ca::in_memory(&cx, start)?),
                addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
                pages: pages.clone(),
                start,
            };
            world.trust("office", &web.ca.cert_pem())?;
            // Claude Code and Codex sign in inside the guest themselves; the
            // world passes their model and sign-in traffic straight through.
            let model = None;
            topics.start(&cx, searches, pages)?;
            page::network(&web, &cx, world_log, world.mirror(&cx)?, model)?
                .route(kit::JUMP, kit::jump_prefix())
                .start(&cx, world.into_attachments())
        });
    let result = kit.run_app(downloads, guest::HOST).await;
    let finish = log.finish();
    println!("whole run: {} ms", total.elapsed().as_millis());
    result?;
    finish?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Mode, arguments};

    fn parse(args: &[&str]) -> Option<Mode> {
        arguments(args.iter().map(|a| a.to_string())).ok()
    }

    #[test]
    fn the_app_takes_its_folder_or_preview() {
        assert_eq!(
            parse(&["d"]),
            Some(Mode::App {
                downloads: "d".into()
            })
        );
        assert_eq!(parse(&["preview"]), Some(Mode::Preview));
        assert_eq!(parse(&["preview", "--spend-budget"]), None);
        for bad in [
            &[][..],
            &["--stay"],
            &["d", "--stay"],
            &["d", "--seed", "corvane-acquisition"],
            &["d", "--model", "openrouter"],
            &["d", "--model-name", "x"],
            &["d", "--store", "s"],
            &["d", "check", "check"],
            &["d", "extra"],
            &["preview", "--stay"],
            &["preview", "--spend-budget", "--spend-budget"],
            &["bake", "now"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
