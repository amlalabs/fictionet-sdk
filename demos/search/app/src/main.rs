//! An Ubuntu research workstation connected to the Search world.

mod guest;
use fictionet_search_demo::{network, page};

use fictionet_demo::kit;
use fictionet_extras::log::Log;
use std::{path::PathBuf, sync::Arc, time::Instant};
use web_world::{
    Addresses, Ca, World,
    pages::{Pages, Seed},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The world's brief chooses both the copied corpus and model-written topics.
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
    let pages = Pages::from_corpus(
        seed,
        downloads.parent().ok_or("downloads folder has no parent")?,
        model,
    )?;
    Ok(
        if std::env::var("EXA_API_KEY").is_ok_and(|key| !key.is_empty()) {
            pages.with_live_search(downloads)?
        } else {
            pages
        },
    )
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let downloads = downloads()?;
    let (claude_token, claude_key) =
        if let Some(path) = std::env::var_os("CLAUDE_CODE_OAUTH_TOKEN_FILE") {
            let value = std::fs::read_to_string(path)
                .map_err(|_| "Cannot read the host Claude OAuth token file")?;
            let secret =
                fictionet_extras::models::Secret::new("Claude OAuth token", value.trim().into())?;
            let key = fictionet_extras::models::Key::claude_token(secret.clone())?;
            let (send, receive) = tokio::sync::oneshot::channel();
            fictionet::run(fictionet::Seed::random(), |cx| async move {
                let token = fictionet_extras::models::Credential::claude_token(&cx, secret)?;
                let _ = send.send(token);
                Ok(())
            })
            .await?;
            (Some(receive.await?), Some(key))
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
    let observe_page = page.clone();
    let mut observation_task =
        tokio::spawn(async move { observe_page.record(observations, &output).await });
    let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
    let world_log = log.clone();
    let console_page = page.clone();
    let downloads_for_boot = downloads.clone();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let boot = kit::boot(
        "search",
        vec![guest::guest(
            claude_token.as_ref().map(|token| token.placeholder()),
        )],
        downloads_for_boot,
        move |consoles| {
            let console = consoles.into_iter().next().expect("one workstation");
            *console_page.console.lock().unwrap() = Some(Arc::new(console.clone()));
            let mut status = console.status.subscribe();
            let destination = console_page.host.clone();
            destination.send_replace(status.borrow().clone());
            tokio::spawn(async move {
                while status.changed().await.is_ok() {
                    destination.send_replace(status.borrow().clone());
                }
            });
        },
        move |cx, mut run| async move {
            let start = std::time::SystemTime::now();
            let web = World {
                ca: Arc::new(Ca::in_memory(&cx, start)?),
                addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
                pages: pages.clone(),
                start,
            };
            run.trust("office", &web.ca.cert_pem())?;
            page.run_commands(&cx, pages.clone(), commands);
            let net = network::build(&web, &cx, world_log, claude_token)?
                .route(kit::JUMP, kit::jump_prefix());
            net.start(&cx, run.into_attachments())
        },
    );
    let run = tokio::select! {
        run = boot => run?,
        _ = terminate.recv() => { server.shutdown().await; observation_task.abort(); return Ok(()); },
        _ = interrupt.recv() => { server.shutdown().await; observation_task.abort(); return Ok(()); },
        result = &mut observation_task => return Err(recording_error(result).into()),
    };
    let mut readiness = Box::pin(run.app_ready(guest::HOST));
    let mut ready = false;
    let mut recording_ended = false;
    let result = loop {
        tokio::select! {
            result = &mut readiness, if !ready => match result {
                Ok(()) => { ready = true; println!("The Search page stays open until Ctrl-C."); },
                Err(error) => break Err(error),
            },
            result = &mut observation_task => { recording_ended = true; break Err(recording_error(result)); },
            _ = interrupt.recv() => break Ok(()),
            _ = terminate.recv() => break Ok(()),
        }
    };
    drop(readiness);
    let shutdown = run.shutdown().await;
    server.shutdown().await;
    if !recording_ended {
        observation_task.await.map_err(std::io::Error::other)??;
    }
    let finish = log.finish();
    println!("whole run: {} ms", total.elapsed().as_millis());
    result?;
    shutdown?;
    finish?;
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
