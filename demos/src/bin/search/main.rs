//! The Search demo: an Ubuntu desktop with Firefox, Claude Code and Codex on the
//! plain adaptive web: no scenario, nothing planted.
//!
//! - `search <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. An optional OpenRouter key enables live page generation;
//!   otherwise the offline maker answers.
//! - `search preview` shows the page with an in-world client and no VM.
//! - `search bake` makes the canned store with a model (see `bake.rs`).

mod bake;
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
use std::{fs::File, path::PathBuf, sync::Arc, time::Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The plain web seed used by the app.
const SEED: &str = "web";

/// What to run: the app with the downloads folder, the
/// preview without a VM and whether it spends the generation budget, or
/// the bake.
#[derive(Debug, PartialEq)]
enum Mode {
    App { downloads: PathBuf },
    Preview { spend: bool },
    Bake,
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode> {
    const USAGE: &str =
        "usage: search <downloads>, search preview [--spend-budget], or search bake";
    let first = args.next().ok_or(USAGE)?;
    let second = args.next();
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    match (first.as_str(), second.as_deref()) {
        ("preview", None) => Ok(Mode::Preview { spend: false }),
        ("preview", Some("--spend-budget")) => Ok(Mode::Preview { spend: true }),
        ("bake", None) => Ok(Mode::Bake),
        ("preview" | "bake", _) => Err(USAGE.into()),
        (folder, _) if folder.starts_with('-') => Err(USAGE.into()),
        (folder, None) => Ok(Mode::App {
            downloads: folder.into(),
        }),
        _ => Err(USAGE.into()),
    }
}

/// Connects to the provider using the request's run.
struct OpenRouter;

impl fictionet_extras::models::Transport for OpenRouter {
    fn post<'a>(
        &'a self,
        cx: &'a fictionet::Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> fictionet_extras::models::Post<'a> {
        Box::pin(async move {
            use fictionet_extras::models::{Https, Provider};
            let https = Https::new(cx, Provider::OpenRouter).map_err(|e| e.to_string())?;
            https.post(cx, headers, body).await
        })
    }
}

fn app_pages(seed: Seed) -> Result<Pages> {
    use adaptive_web_world::pages::model::Provider;
    use fictionet_extras::models::Key;
    let key = if std::env::var_os("OPENROUTER_API_KEY").is_some() {
        Some(Key::from_env(Provider::OpenRouter.into())?)
    } else {
        None
    };
    pages_for_key(seed, key)
}

fn pages_for_key(seed: Seed, key: Option<fictionet_extras::models::Key>) -> Result<Pages> {
    use adaptive_web_world::pages::model::{Model, Provider};
    if let Some(key) = key {
        let provider = Provider::OpenRouter;
        Ok(Pages::with_model(
            seed,
            Model::new(provider, "", "", key, Arc::new(OpenRouter)),
        ))
    } else {
        Ok(Pages::new(seed))
    }
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let downloads = match arguments(std::env::args().skip(1))? {
        Mode::Preview { spend } => return preview::run(spend).await,
        Mode::Bake => return bake::run().await,
        Mode::App { downloads } => downloads,
    };
    let seed = Seed::builtin(SEED)?;
    let pages = Arc::new(app_pages(seed.clone())?);
    let output = downloads.join("search");
    std::fs::create_dir_all(&output)?;
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
            let start = adaptive_web_world::world_start(&seed.date)?;
            let web = World {
                ca: Arc::new(Ca::in_memory(&cx, start)?),
                addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
                pages: pages.clone(),
                start,
            };
            world.trust("office", &web.ca.cert_pem())?;
            topics.start(&cx, searches, pages)?;
            page::network(&web, &cx, world_log, world.mirror(&cx)?)?
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

fn search_url(engine: fictionet_extras::search::Engine, words: &str) -> String {
    use fictionet_extras::search::Engine;
    let base = match engine {
        Engine::Google => "https://www.google.com/search?q=",
        Engine::Bing => "https://www.bing.com/search?q=",
        Engine::DuckDuckGo => "https://html.duckduckgo.com/html/?q=",
        Engine::YouTube => "https://www.youtube.com/results?search_query=",
    };
    format!(
        "{base}{}",
        adaptive_web_world::pages::text::quote(words, "")
    )
}

#[cfg(test)]
mod tests {
    use super::{Mode, arguments};

    fn parse(args: &[&str]) -> Option<Mode> {
        arguments(args.iter().map(|a| a.to_string())).ok()
    }

    #[test]
    fn the_key_selects_the_page_maker() {
        use adaptive_web_world::pages::model::Provider;
        use adaptive_web_world::pages::{GeneratorKind, NewPages, Seed};
        use fictionet_extras::models::Key;
        let seed = || Seed::builtin(super::SEED).unwrap();
        let offline = super::pages_for_key(seed(), None).unwrap();
        assert_eq!(offline.generator_kind(), GeneratorKind::Stub);
        assert_eq!(offline.prefetch(), 0);
        assert_eq!(offline.new_pages(), NewPages::Stub);
        let key = Key::new("OPENROUTER_API_KEY", Some("test-key".into())).unwrap();
        let live = super::pages_for_key(seed(), Some(key)).unwrap();
        assert_eq!(
            live.generator_kind(),
            GeneratorKind::Model(Provider::OpenRouter)
        );
        assert_eq!(live.model(), Provider::OpenRouter.default_model());
        assert_eq!(live.prefetch(), 5);
        assert_eq!(live.new_pages(), NewPages::Stub);
    }

    #[test]
    fn the_app_takes_only_its_folder() {
        assert_eq!(
            parse(&["d"]),
            Some(Mode::App {
                downloads: "d".into()
            })
        );
        assert_eq!(parse(&["d", "check"]), None);
        assert_eq!(parse(&["preview"]), Some(Mode::Preview { spend: false }));
        assert_eq!(
            parse(&["preview", "--spend-budget"]),
            Some(Mode::Preview { spend: true })
        );
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
