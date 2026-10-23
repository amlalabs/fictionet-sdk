//! The Search demo: an Ubuntu desktop with Firefox and Claude Code on the
//! security corpus, with optional model-written pages.
//!
//! - `search <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. Copied pages answer searches and fetches without a model.
//! - `search preview` shows the page with an in-world client and no VM.

mod guest;
mod preview;
use fictionet_search_demo::{network, page};

use fictionet_demo::kit;
use fictionet_extras::log::Log;
use std::{fs::File, io::Write, path::PathBuf, sync::Arc, time::Instant};
use web_world::{
    Addresses, Ca, World,
    pages::{Pages, Seed},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The world's brief chooses both the copied corpus and model-written topics.
const SEED: &str = "security";

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
    let model = std::env::var("OPENROUTER_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
        .map(|_| web_world::pages::model::Model::openrouter())
        .transpose()?;
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
    let downloads = match arguments(std::env::args().skip(1))? {
        Mode::Preview => return preview::run().await,
        Mode::App { downloads } => downloads,
    };
    let mut seed = Seed::builtin(SEED)?;
    let today = time::OffsetDateTime::now_utc().date();
    seed.date = today.to_string();
    let pages = Arc::new(app_pages(seed.clone(), &downloads)?);
    let output = downloads.join("search");
    std::fs::create_dir_all(&output)?;
    let (page, (mut observations, commands)) = page::Page::new(&pages, false);
    let server = page::serve(page.router(), kit::PAGE_PORT).await?;
    let _access = kit::PageAccess::new(&server.url)?;
    let observe_page = page.clone();
    let mut recording = std::io::BufWriter::new(File::create(output.join("log.jsonl"))?);
    let mut observation_task = tokio::spawn(async move {
        while let Some(observation) = observations.recv().await {
            serde_json::to_writer(&mut recording, &observation)?;
            writeln!(&mut recording)?;
            recording.flush()?;
            observe_page.publish(observation);
        }
        Ok::<_, std::io::Error>(())
    });
    let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
    let world_log = log.clone();
    let console_page = page.clone();
    let downloads_for_boot = downloads.clone();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let boot = kit::boot(
        "search",
        vec![guest::guest()],
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
            let net = network::build(&web, &cx, world_log, run.mirror(&cx)?)?
                .route(kit::JUMP, kit::jump_prefix());
            net.start(&cx, run.into_attachments())
        },
    );
    let run = tokio::select! {
        run = boot => run?,
        _ = interrupt.recv() => { server.shutdown().await; observation_task.abort(); return Ok(()); },
        result = &mut observation_task => return Err(recording_error(result).into()),
    };
    let mut readiness = Box::pin(run.app_ready(guest::HOST));
    let mut ready = false;
    let result = loop {
        tokio::select! {
            result = &mut readiness, if !ready => match result {
                Ok(()) => { ready = true; println!("The Search page stays open until Ctrl-C."); },
                Err(error) => break Err(error),
            },
            result = &mut observation_task => break Err(recording_error(result)),
            _ = interrupt.recv() => break Ok(()),
        }
    };
    drop(readiness);
    let shutdown = run.shutdown().await;
    server.shutdown().await;
    observation_task.abort();
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
        for bad in [
            &[][..],
            &["--unknown"],
            &["d", "extra"],
            &["preview", "extra"],
            &["preview", "extra", "extra"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
