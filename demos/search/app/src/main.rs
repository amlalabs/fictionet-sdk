//! An Ubuntu research workstation connected to the Search world.

mod guest;
use fictionet_search_demo::{network, page};

use fictionet_demo::kit;
use fictionet_extras::models::ClaudeLogin;
use std::{path::PathBuf, sync::Arc, time::Instant};
use web_world::{
    Ca, World,
    pages::{LiveWeb, Pages, Seed},
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

/// The pages, with the editor and live search the host's keys allow. A
/// hosted demo, which runs its workstation as a Nitro Sandbox on an EC2
/// parent, serves other people, who get only the pages their searches allow.
fn app_pages(seed: Seed, downloads: &std::path::Path, login: Option<ClaudeLogin>) -> Result<Pages> {
    use web_world::pages::model::Model;
    let model = if std::env::var("OPENROUTER_API_KEY").is_ok_and(|key| !key.is_empty()) {
        Some(Model::openrouter()?)
    } else if std::env::var("ANTHROPIC_API_KEY").is_ok_and(|key| !key.is_empty()) {
        Some(Model::anthropic()?)
    } else if login == Some(ClaudeLogin::Subscription) {
        Some(Model::claude_token(
            fictionet_extras::models::Key::claude_token(ClaudeLogin::Subscription.host_secret()?)?,
        ))
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
        let web = match kit::vm::Vmm::of_host() {
            kit::vm::Vmm::Nitro => LiveWeb::SearchedOnly,
            kit::vm::Vmm::CloudHypervisor => LiveWeb::Any,
        };
        pages = pages.with_live_search(downloads, web)?;
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
                "{}: {error}; build it with cargo xtask-host search-image <downloads>",
                path.display()
            )
        })
    };
    let roots = Arc::new(fictionet_extras::zscaler::Roots::from_pem(&read_baked(
        baked.trust_root(),
    )?)?);
    // The guest's Claude Code reaches Anthropic with this credential through
    // the gateway; the editor uses an API key of its own when it has one.
    let login = ClaudeLogin::of_host();
    let claude_token = match login {
        Some(login) => {
            let placeholder = read_baked(baked.placeholder())?;
            if ClaudeLogin::of(&placeholder) != Some(login) {
                return Err(format!(
                    "The workstation image was built for another Claude sign-in than the host's {login:?}; rebuild it with cargo xtask-host search-image <downloads> and the same credential set"
                )
                .into());
            }
            Some(fictionet_extras::models::Credential::claude(
                login,
                login.host_secret()?,
                placeholder,
            )?)
        }
        None => None,
    };
    let mut seed = Seed::builtin(SEED)?;
    let today = time::OffsetDateTime::now_utc().date();
    seed.date = today.to_string();
    let pages = Arc::new(app_pages(seed.clone(), &downloads, login)?);
    let output = downloads.join("search");
    std::fs::create_dir_all(&output)?;
    let (page, (observations, commands)) = page::Page::new(pages.clone());
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
    // Each mode starts with a fresh workstation and an empty world.
    let result = loop {
        let source = *chosen.borrow_and_update();
        let copied_lag = pages.measure_lag();
        page.begin_session(&pages, source);
        println!("Starting the {source:?} session");
        let console_slot = Arc::new(std::sync::Mutex::new(None));
        let console = console_slot.clone();
        let (world_page, world_pages, world_token, world_roots) = (
            page.clone(),
            pages.clone(),
            claude_token.clone(),
            roots.clone(),
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
                let web = World {
                    ca: Arc::new(Ca::new(&cx, &world_roots, earliest, start)?),
                    pages: world_pages,
                    start,
                };
                let net =
                    network::build(&web, &cx, world_token)?.route(kit::JUMP, kit::jump_prefix());
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
                        Ok(()) = chosen.changed() => break Ok(Ended::Chosen),
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
                let shutdown = run.shutdown().await;
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

fn recording_error(
    result: std::result::Result<std::io::Result<()>, tokio::task::JoinError>,
) -> std::io::Error {
    match result {
        Ok(Err(error)) => error,
        Ok(Ok(())) => std::io::Error::other("The observation stream ended"),
        Err(error) => std::io::Error::other(error),
    }
}
