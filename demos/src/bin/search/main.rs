//! The Search demo: an Ubuntu desktop with Firefox and Claude Code on the
//! adaptive web, with the canned pages for the halvard-cve seed.
//!
//! - `search <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. Pages come from the canned store, and the offline
//!   generator makes what it lacks; nothing calls a model for pages.
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
use fictionet_extras::models;
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
/// Claude Code's calls one run may make, as a ceiling on what a call costs.
const CLAUDE_CALLS: u64 = 60;

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

/// Claude Code's model site and the model it runs, from the host's key:
/// `ANTHROPIC_API_KEY`, else `OPENROUTER_API_KEY`. None without either.
fn claude_model(cx: &fictionet::Cx) -> fictionet::Result<Option<(models::Model, &'static str)>> {
    if std::env::var_os("ANTHROPIC_API_KEY").is_some() {
        Ok(Some((models::anthropic(cx)?, "claude-sonnet-5-5")))
    } else if std::env::var_os("OPENROUTER_API_KEY").is_some() {
        Ok(Some((
            models::anthropic_via_openrouter(cx)?,
            "anthropic/claude-sonnet-5.5",
        )))
    } else {
        Ok(None)
    }
}

/// Claude Code's settings and state for the guest user: the model, and the
/// first-run questions already answered for the key it is given.
fn claude_files(model: &str, key: &str) -> Vec<(&'static str, String)> {
    let mut settings = serde_json::json!({ "model": model });
    if let Some(small) = model.strip_suffix("claude-sonnet-5.5") {
        // Through OpenRouter, Claude Code's smaller model needs its name there too.
        settings["env"] = serde_json::json!({
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": format!("{small}claude-haiku-4.5"),
        });
    }
    let tail: String = key
        .chars()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let state = serde_json::json!({
        "hasCompletedOnboarding": true,
        "theme": "dark",
        "customApiKeyResponses": { "approved": [tail], "rejected": [] },
        "projects": { format!("/home/{}", guest::USER): { "hasTrustDialogAccepted": true } },
    });
    vec![
        (".claude/settings.json", settings.to_string()),
        (".claude.json", state.to_string()),
    ]
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
    let pages = Arc::new(Pages::canned(seed.clone(), &store::canned_root(SEED))?);
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
    let mut kit = Kit::new("search")
        .guest(guest::guest(&seed.date))
        .observer(searches.clone())
        .observer(Arc::new(LogObserver { log: log.clone() }))
        .page(move |dashboard, hosts| view.page(dashboard, hosts.take(guest::HOST)));
    if !check {
        kit = kit.open_page();
    }
    let kit = kit.world(move |cx, mut world| async move {
        let start = adaptive_web_world::world_start(&seed.date)?;
        let web = World {
            ca: Arc::new(Ca::in_memory(&cx, start)?),
            addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
            pages: pages.clone(),
            start,
        };
        world.trust("office", &web.ca.cert_pem())?;
        // The checks run with no key, so the guest has no model to call.
        let model = if check { None } else { claude_model(&cx)? };
        let model = model.map(|(model, name)| {
            let model = model
                .search(pages.clone())
                .budget(models::Budget::new().calls(CLAUDE_CALLS));
            (model, name)
        });
        if let Some((model, name)) = &model {
            let env = model.guest_env();
            let key = env
                .first()
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            world.seed_env(env)?;
            world.seed_home_files(claude_files(name, &key))?;
        }
        topics.start(&cx, searches, pages)?;
        page::network(
            &web,
            &cx,
            world_log,
            world.mirror(&cx)?,
            model.map(|(model, _)| model),
        )?
        .route(kit::JUMP, kit::jump_prefix())
        .start(&cx, world.into_attachments())
    });
    // The app stops cleanly on Ctrl-C at any point, booting included. The
    // checks keep the terminal's default.
    let mut interrupt = if check {
        None
    } else {
        Some(tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        )?)
    };
    let run = match &mut interrupt {
        None => kit.boot(downloads).await?,
        Some(interrupt) => tokio::select! {
            run = kit.boot(downloads) => run?,
            _ = interrupt.recv() => {
                println!("Stopped while booting.");
                return Ok(());
            }
        },
    };
    println!(
        "boot to SSH-ready: {} ms",
        run.guest(guest::HOST).ssh_ready().as_millis()
    );
    let mut visited = BTreeSet::new();
    let result = match &mut interrupt {
        None => {
            let result = checks::run(&run, &scenario, &output, &mut visited).await;
            if result.is_ok() {
                println!(
                    "story done: {} ms",
                    run.boot_started().elapsed().as_millis()
                );
            }
            result
        }
        Some(interrupt) => {
            let desktop = run.guest(guest::HOST);
            tokio::select! {
                ready = desktop.wait_desktop(std::time::Duration::from_secs(300)) => match ready {
                    Ok(_) => {
                        println!(
                            "desktop up: {} ms",
                            run.boot_started().elapsed().as_millis()
                        );
                        println!("The page stays open until Ctrl-C.");
                        interrupt.recv().await;
                        Ok(())
                    }
                    Err(error) => Err(error.into()),
                },
                _ = interrupt.recv() => Ok(()),
            }
        }
    };
    if result.is_err() {
        eprint!("{}", run.guest(guest::HOST).diagnostics().await);
    }
    let shutdown = run.shutdown().await;
    let finish = log.finish();
    println!("whole run: {} ms", total.elapsed().as_millis());
    finish?;
    let result = result.and(shutdown.map_err(Into::into));
    if check {
        checks::finish(result, &output.join("log.jsonl"), &visited)?;
        println!("every required check passed");
    } else {
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Mode, arguments, claude_files};

    fn parse(args: &[&str]) -> Option<Mode> {
        arguments(args.iter().map(|a| a.to_string())).ok()
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

    #[test]
    fn claude_code_starts_signed_in_with_the_placeholder_key() {
        let key = format!("sk-ant-api03-{}", "b".repeat(96));
        let files = claude_files("anthropic/claude-sonnet-5.5", &key);
        let settings: serde_json::Value = serde_json::from_str(&files[0].1).unwrap();
        assert_eq!(settings["model"], "anthropic/claude-sonnet-5.5");
        assert_eq!(
            settings["env"]["ANTHROPIC_DEFAULT_HAIKU_MODEL"],
            "anthropic/claude-haiku-4.5"
        );
        let state: serde_json::Value = serde_json::from_str(&files[1].1).unwrap();
        assert_eq!(
            state["customApiKeyResponses"]["approved"][0],
            "b".repeat(20)
        );
        assert_eq!(state["hasCompletedOnboarding"], true);
        let direct = claude_files("claude-sonnet-5-5", &key);
        let settings: serde_json::Value = serde_json::from_str(&direct[0].1).unwrap();
        assert!(settings.get("env").is_none());
    }
}
