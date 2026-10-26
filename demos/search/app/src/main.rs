//! An Ubuntu research workstation connected to the Search world.

mod guest;
use fictionet_search_demo::{network, page};

use fictionet_demo::kit;
use fictionet_extras::log::Log;
use std::{path::PathBuf, sync::Arc, time::Instant};
use web_world::{
    Addresses, Ca, World,
    pages::{Pages, Seed, Source},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The seed that chooses the copied web.
const SEED: &str = "security";

fn downloads() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    let folder = args.next().ok_or("usage: search <downloads>")?;
    if folder.starts_with('-') || args.next().is_some() {
        return Err("usage: search <downloads>".into());
    }
    Ok(folder.into())
}

fn app_pages(
    seed: Seed,
    downloads: &std::path::Path,
    claude_key: Option<fictionet_extras::models::Key>,
) -> Result<Pages> {
    use web_world::pages::model::Model;
    let model = if let Some(key) = claude_key {
        Some(Model::claude_token(key))
    } else if std::env::var("OPENROUTER_API_KEY").is_ok_and(|key| !key.is_empty()) {
        Some(Model::openrouter()?)
    } else if std::env::var("ANTHROPIC_API_KEY").is_ok_and(|key| !key.is_empty()) {
        Some(Model::anthropic()?)
    } else {
        None
    };
    let mut pages = Pages::from_corpus(
        seed,
        downloads.parent().ok_or("downloads folder has no parent")?,
    )?;
    if let Some(model) = model {
        pages = pages.with_editor(model);
    }
    if std::env::var("EXA_API_KEY").is_ok_and(|key| !key.is_empty()) {
        pages = pages.with_live_search(downloads)?;
    }
    Ok(pages)
}

/// How a session ended.
enum Ended {
    /// A mode was chosen: the next session runs in it.
    Chosen,
    /// The workstation never became ready.
    Failed(std::io::Error),
    /// The app is stopping.
    Stopping,
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let downloads = downloads()?;
    let baked = kit::image::Baked::new(&downloads, guest::IMAGE);
    let read_baked = |path: PathBuf| {
        std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "{}: {error}; build it with cargo xtask search-image <downloads>",
                path.display()
            )
        })
    };
    let roots = Arc::new(fictionet_extras::zscaler::Roots::from_pem(&read_baked(
        baked.trust_root(),
    )?)?);
    let (claude_token, claude_key) =
        if let Some(path) = std::env::var_os("CLAUDE_CODE_OAUTH_TOKEN_FILE") {
            let value = std::fs::read_to_string(path)
                .map_err(|_| "Cannot read the host Claude OAuth token file")?;
            let secret =
                fictionet_extras::models::Secret::new("Claude OAuth token", value.trim().into())?;
            let key = fictionet_extras::models::Key::claude_token(secret.clone())?;
            let token = fictionet_extras::models::Credential::claude_token(
                secret,
                read_baked(baked.placeholder())?,
            )?;
            (Some(token), Some(key))
        } else {
            (None, None)
        };
    let mut seed = Seed::builtin(SEED)?;
    let today = time::OffsetDateTime::now_utc().date();
    seed.date = today.to_string();
    let pages = Arc::new(app_pages(seed.clone(), &downloads, claude_key)?);
    let output = downloads.join("search");
    std::fs::create_dir_all(&output)?;
    let (page, (observations, commands)) = page::Page::new(pages.clone(), false);
    let server = page::serve(page.router(), kit::PAGE_PORT).await?;
    let _access = kit::PageAccess::new(&server.url)?;
    // Stopping frees the page's address first, so a restart comes back on it.
    let mut server = Some(server);
    let observe_page = page.clone();
    let mut observation_task =
        tokio::spawn(async move { observe_page.record(observations, &output).await });
    let (sessions, mut chosen) = tokio::sync::watch::channel(pages.source());
    page.serve_commands(pages.clone(), commands, sessions);
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Each session runs until another mode is chosen. A mode on the same
    // clock starts its session in the running world, on the same
    // workstation; a mode on another clock boots a fresh workstation, with
    // a world that starts empty.
    let result = loop {
        let mut source = *chosen.borrow_and_update();
        let copied_lag = pages.measure_lag();
        let lag = clock_lag(source, copied_lag);
        page.begin_session(&pages, source);
        println!("Starting a {source:?} session");
        let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
        let console_slot = Arc::new(std::sync::Mutex::new(None));
        let console = console_slot.clone();
        let cx_slot = Arc::new(std::sync::Mutex::new(None));
        let (world_page, world_pages, world_log, world_token, world_seed, world_roots, world_cx) = (
            page.clone(),
            pages.clone(),
            log.clone(),
            claude_token.clone(),
            seed.clone(),
            roots.clone(),
            cx_slot.clone(),
        );
        let boot = kit::boot(
            "search",
            vec![guest::guest()],
            downloads.clone(),
            move |consoles| {
                *console.lock().unwrap() = consoles.into_iter().next();
            },
            move |cx, run| async move {
                let start = std::time::SystemTime::now();
                // Copied mode sets the workstation's clock back to the day
                // its pages were copied; certificates hold from then too.
                let earliest = start - copied_lag.unwrap_or_default();
                world_pages
                    .start_session(&cx, source, copied_lag)
                    .map_err(|error| fictionet::Error::msg(format!("{error:?}")))?;
                world_page.attach_world(&cx, world_pages.clone());
                *world_cx.lock().unwrap() = Some(cx.clone());
                let web = World {
                    ca: Arc::new(Ca::new(&cx, &world_roots, earliest, start)?),
                    addresses: Arc::new(Addresses::new(world_seed.fixed_addresses(), None)?),
                    pages: world_pages,
                    start,
                };
                let net = network::build(&web, &cx, world_log, world_token)?
                    .route(kit::JUMP, kit::jump_prefix());
                net.start(&cx, run.into_attachments())
            },
        );
        let run = tokio::select! {
            run = boot => run,
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            result = &mut observation_task => break Err(recording_error(result)),
        };
        // A boot that fails has shut its own run down.
        let failure = match run {
            Err(error) => error,
            Ok(run) => {
                if let Some(console) = console_slot.lock().unwrap().take() {
                    page.attach_console(&pages, console);
                }
                let mut readiness = Box::pin(run.app_ready(guest::HOST));
                let mut ready = false;
                let ended = loop {
                    tokio::select! {
                        result = &mut readiness, if !ready => match result {
                            Ok(()) => { ready = true; page.end_boot(); println!("The Search page stays open until Ctrl-C."); },
                            Err(error) => break Ok(Ended::Failed(error)),
                        },
                        Ok(()) = chosen.changed() => {
                            let next = *chosen.borrow_and_update();
                            let next_lag = pages.measure_lag();
                            let cx = cx_slot.lock().unwrap().clone();
                            let Some(cx) = cx.filter(|_| clock_lag(next, next_lag) == lag) else {
                                break Ok(Ended::Chosen);
                            };
                            if let Err(error) = pages.start_session(&cx, next, next_lag) {
                                break Ok(Ended::Failed(std::io::Error::other(format!("{error:?}"))));
                            }
                            if let Err(error) = network::report_run(&pages, &cx) {
                                break Ok(Ended::Failed(std::io::Error::other(error.to_string())));
                            }
                            source = next;
                            page.switch_session(&pages, source);
                            println!("Switched to a {source:?} session on the running workstation");
                        }
                        result = &mut observation_task => break Err(recording_error(result)),
                        _ = interrupt.recv() => break Ok(Ended::Stopping),
                        _ = terminate.recv() => break Ok(Ended::Stopping),
                    }
                };
                drop(readiness);
                if matches!(ended, Ok(Ended::Stopping) | Err(_))
                    && let Some(server) = server.take()
                {
                    server.shutdown().await;
                }
                let shutdown = run.shutdown().await.and_then(|()| log.finish());
                match (ended, shutdown) {
                    (Ok(Ended::Chosen), Ok(())) => continue,
                    (Ok(Ended::Stopping), shutdown) => break shutdown,
                    (Err(error), _) => break Err(error),
                    (Ok(Ended::Failed(error)), shutdown) => {
                        if let Err(shutdown) = shutdown {
                            println!("The {source:?} session did not shut down: {shutdown}");
                        }
                        error
                    }
                    (Ok(Ended::Chosen), Err(error)) => error,
                }
            }
        };
        // A failed session leaves the page up: the next mode chosen
        // starts another.
        println!("The {source:?} session failed: {failure}");
        page.fail_session(&pages);
        tokio::select! {
            Ok(()) = chosen.changed() => {}
            result = &mut observation_task => break Err(recording_error(result)),
            _ = interrupt.recv() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
        }
    };
    if let Some(server) = server {
        server.shutdown().await;
    }
    observation_task.abort();
    println!("whole run: {} ms", total.elapsed().as_millis());
    result?;
    Ok(())
}

/// How far a session in `source` sets the workstation's clock back:
/// Copied's lag, and none for the live modes.
fn clock_lag(source: Source, copied_lag: Option<std::time::Duration>) -> std::time::Duration {
    if source == Source::Copied {
        copied_lag.unwrap_or_default()
    } else {
        std::time::Duration::ZERO
    }
}

fn recording_error(
    result: std::result::Result<std::io::Result<()>, tokio::task::JoinError>,
) -> std::io::Error {
    match result {
        Ok(Err(error)) => error,
        Ok(Ok(())) => std::io::Error::other("The observation stream ended"),
        Err(error) => std::io::Error::other(error),
    }
}
