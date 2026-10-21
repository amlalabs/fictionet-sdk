//! The Search demo: an Ubuntu desktop with Firefox and Claude Code on the
//! adaptive web, with the canned pages for the halvard-cve seed.
//!
//! - `search <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. Prepared pages answer first. A model fills the gaps
//!   with an OpenRouter key; otherwise the offline maker does.
//! - `search <downloads> check` runs the scripted story and its checks.
//! - `search preview` shows the page with an in-world client and no VM.
//! - `search bake` makes the canned store with a model (see `bake.rs`).

mod bake;
mod checks;
mod guest;
mod preview;
use fictionet_demo::search as page;

use adaptive_web_world::{
    Addresses, Ca, World,
    events::LogObserver,
    pages::{Pages, Seed, store},
    search::Searches,
};
use example_common::log::Log;
use fictionet_demo::kit::{self, Kit};
use std::{
    collections::BTreeSet,
    fs::File,
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The seed the app shows, and whose canned pages it serves.
const SEED: &str = "halvard-cve";

/// What to run: the app or its checks with the downloads folder, the
/// preview without a VM and whether it spends the generation budget, or
/// the bake.
#[derive(Debug, PartialEq)]
enum Mode {
    App { downloads: PathBuf },
    Check { downloads: PathBuf },
    Preview { spend: bool },
    Bake,
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode> {
    const USAGE: &str =
        "usage: search <downloads> [check], search preview [--spend-budget], or search bake";
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
        (folder, Some("check")) => Ok(Mode::Check {
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

fn app_pages(seed: Seed, check: bool) -> Result<Pages> {
    use adaptive_web_world::pages::model::Provider;
    use fictionet_extras::models::Key;
    let key = if !check && std::env::var_os("OPENROUTER_API_KEY").is_some() {
        Some(Key::from_env(Provider::OpenRouter.into())?)
    } else {
        None
    };
    pages_for_key(seed, key)
}

fn pages_for_key(seed: Seed, key: Option<fictionet_extras::models::Key>) -> Result<Pages> {
    use adaptive_web_world::pages::model::{Model, Provider};
    let root = store::canned_root(&seed.name);
    if let Some(key) = key {
        let provider = Provider::OpenRouter;
        Ok(Pages::canned_with_model(
            seed,
            &root,
            Model::new(provider, "", "", key, Arc::new(OpenRouter)),
        )?)
    } else {
        Ok(Pages::canned(seed, &root)?)
    }
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let (downloads, check) = match arguments(std::env::args().skip(1))? {
        Mode::Preview { spend } => return preview::run(spend).await,
        Mode::Bake => return bake::run().await,
        Mode::App { downloads } => (downloads, false),
        Mode::Check { downloads } => (downloads, true),
    };
    let seed = Seed::builtin(SEED)?;
    let pages = Arc::new(app_pages(seed.clone(), check)?);
    let output = downloads.join("runs").join(format!(
        "search-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    ));
    std::fs::create_dir_all(output.parent().unwrap())?;
    std::fs::create_dir(&output)?;
    println!("output: {}", output.display());
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
            // The checks run with no key, so the guest has no model to call.
            let model = if check {
                None
            } else {
                kit::desktop::claude_model(&cx)?
            };
            let model = model.map(|model| model.search(pages.clone()));
            if let Some(model) = &model {
                kit::desktop::sign_in_claude(&mut world, model, guest::USER)?;
            }
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
    let run = kit.boot(downloads).await?;
    println!(
        "boot to SSH-ready: {} ms",
        run.guest(guest::HOST).ssh_ready().as_millis()
    );
    let mut visited = BTreeSet::new();
    let result = checks::run(&run, &scenario, &output, &mut visited).await;
    if result.is_ok() {
        println!(
            "story done: {} ms",
            run.boot_started().elapsed().as_millis()
        );
    }
    if result.is_err() {
        eprint!("{}", run.guest(guest::HOST).diagnostics().await);
    }
    let shutdown = run.shutdown().await;
    let finish = log.finish();
    println!("whole run: {} ms", total.elapsed().as_millis());
    finish?;
    let result = result.and(shutdown.map_err(Into::into));
    checks::finish(result, &output.join("log.jsonl"), &visited)?;
    println!("every required check passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Mode, arguments};

    fn parse(args: &[&str]) -> Option<Mode> {
        arguments(args.iter().map(|a| a.to_string())).ok()
    }

    #[test]
    fn the_key_selects_the_maker_and_checks_always_use_offline_pages() {
        use adaptive_web_world::pages::model::Provider;
        use adaptive_web_world::pages::{GeneratorKind, NewPages, Seed};
        use fictionet_extras::models::Key;
        let seed = || Seed::builtin(super::SEED).unwrap();
        let offline = super::pages_for_key(seed(), None).unwrap();
        assert_eq!(offline.generator_kind(), GeneratorKind::Stub);
        assert_eq!(offline.prefetch(), 0);
        assert_eq!(offline.new_pages(), NewPages::Canned);
        let check = super::app_pages(seed(), true).unwrap();
        assert_eq!(check.generator_kind(), GeneratorKind::Stub);
        assert_eq!(check.prefetch(), 0);
        let key = Key::new("OPENROUTER_API_KEY", Some("test-key".into())).unwrap();
        let live = super::pages_for_key(seed(), Some(key)).unwrap();
        assert_eq!(
            live.generator_kind(),
            GeneratorKind::Model(Provider::OpenRouter)
        );
        assert_eq!(live.model(), Provider::OpenRouter.default_model());
        assert_eq!(live.prefetch(), 3);
        assert_eq!(live.new_pages(), NewPages::Canned);
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
