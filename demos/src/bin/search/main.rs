//! The Search demo: an Ubuntu desktop with Firefox and Claude Code on the
//! plain adaptive web: no scenario, nothing planted.
//!
//! - `search <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. Prepared pages answer searches and fetches without a model.
//! - `search <downloads> check` runs the scripted story and its checks.
//! - `search preview` shows the page with an in-world client and no VM.
//! - `search bake` makes a store with a model (see `bake.rs`).

mod bake;
mod checks;
mod guest;
mod preview;
use fictionet_demo::search as page;

use adaptive_web_world::{
    Addresses, Ca, World,
    events::LogObserver,
    pages::{Pages, Seed},
    search::Searches,
};
use example_common::log::Log;
use fictionet_demo::kit::{self, Kit};
use std::{collections::BTreeSet, fs::File, path::PathBuf, sync::Arc, time::Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The seed the app shows, and whose canned pages it serves.
const SEED: &str = "web";

/// What to run: the app or its checks with the downloads folder, the
/// preview without a VM, or the bake.
#[derive(Debug, PartialEq)]
enum Mode {
    App { downloads: PathBuf },
    Check { downloads: PathBuf },
    Preview,
    Bake,
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode> {
    const USAGE: &str = "usage: search <downloads> [check], search preview, or search bake";
    let first = args.next().ok_or(USAGE)?;
    let second = args.next();
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    match (first.as_str(), second.as_deref()) {
        ("preview", None) => Ok(Mode::Preview),
        ("bake", None) => Ok(Mode::Bake),
        ("preview" | "bake", _) => Err(USAGE.into()),
        (folder, _) if folder.starts_with('-') => Err(USAGE.into()),
        (folder, None) => Ok(Mode::App {
            downloads: folder.into(),
        }),
        (folder, Some("check")) => Ok(Mode::Check {
            downloads: folder.into(),
        }),
        _ => Err(USAGE.into()),
    }
}

fn app_pages(seed: Seed) -> Result<Pages> {
    Ok(Pages::canned(
        seed,
        &adaptive_web_world::pages::store::canned_root(SEED),
    )?)
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let (downloads, check) = match arguments(std::env::args().skip(1))? {
        Mode::Preview => return preview::run().await,
        Mode::Bake => return bake::run().await,
        Mode::App { downloads } => (downloads, false),
        Mode::Check { downloads } => (downloads, true),
    };
    let seed = Seed::builtin(SEED)?;
    let pages = Arc::new(app_pages(seed.clone())?);
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
    let scenario = seed.clone();
    let kit = Kit::new("search")
        .page_words(checks::PAGE_WORDS)
        .guest(guest::guest(&seed.date))
        .observer(searches.clone())
        .observer(Arc::new(LogObserver { log: log.clone() }))
        .page(move |dashboard, hosts| view.page(dashboard, hosts.take(guest::HOST)))
        .world(move |cx, mut world| async move {
            let start = adaptive_web_world::world_start(&seed.date)?;
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
    if !check {
        let result = kit.run_app(downloads, guest::HOST).await;
        let finish = log.finish();
        println!("whole run: {} ms", total.elapsed().as_millis());
        result?;
        finish?;
        return Ok(());
    }
    let story = checks::Story {
        seed: scenario,
        log,
        visited: BTreeSet::new(),
        output: output.clone(),
    };
    kit::checks::run(kit, &downloads, &output, story).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Mode, arguments};

    fn parse(args: &[&str]) -> Option<Mode> {
        arguments(args.iter().map(|a| a.to_string())).ok()
    }

    #[test]
    fn the_app_always_serves_prepared_pages_without_a_model() {
        use adaptive_web_world::pages::{GeneratorKind, NewPages, Seed};
        let pages = super::app_pages(Seed::builtin(super::SEED).unwrap()).unwrap();
        assert_eq!(pages.generator_kind(), GeneratorKind::Stub);
        assert_eq!(pages.prefetch(), 0);
        assert_eq!(pages.new_pages(), NewPages::Canned);
    }

    #[test]
    fn the_app_takes_only_its_folder_and_check_its_word() {
        assert_eq!(
            parse(&["d"]),
            Some(Mode::App {
                downloads: "d".into()
            })
        );
        assert_eq!(
            parse(&["d", "check"]),
            Some(Mode::Check {
                downloads: "d".into()
            })
        );
        assert_eq!(parse(&["preview"]), Some(Mode::Preview));
        assert_eq!(parse(&["preview", "--spend-budget"]), None);
        assert_eq!(parse(&["bake"]), Some(Mode::Bake));
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
