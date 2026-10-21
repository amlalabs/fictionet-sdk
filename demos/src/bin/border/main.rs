//! The Border demo: an Ubuntu workstation with Firefox and Claude Code, its
//! bank, and the route between them.
//!
//! - `border <downloads>` is the app: it boots, opens the page and stays up
//!   until Ctrl-C. Claude Code in the guest is signed in when the host has a
//!   key for it.
//! - `border <downloads> check` runs the scripted story and its checks.
//! - `border preview` shows the page with an in-world client and no VM.

mod checks;
mod client;
mod control;
mod guest;
mod preview;
mod story;
#[cfg(test)]
mod tests;
mod trace;
mod view;
mod world;

use border_world::log::Log;
use fictionet_demo::kit::{self, Kit};
use fictionet_observe::page::Page;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// What to run: the app or its checks with the downloads folder, or the
/// preview without a VM.
#[derive(Debug, PartialEq)]
enum Mode {
    App { downloads: PathBuf },
    Check { downloads: PathBuf },
    Preview,
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode, Error> {
    const USAGE: &str = "usage: border <downloads> [check], or border preview";
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
        (folder, Some("check")) => Ok(Mode::Check {
            downloads: folder.into(),
        }),
        _ => Err(USAGE.into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (downloads, check) = match arguments(std::env::args().skip(1))? {
        Mode::Preview => return preview::run().await,
        Mode::App { downloads } => (downloads, false),
        Mode::Check { downloads } => (downloads, true),
    };
    let started = Instant::now();
    let out = kit::checks::output(&downloads, "border")?;
    let scenario = control::scenario();
    let control = control::Control::new(&scenario)?;
    let log = Log::start(
        Box::new(std::io::BufWriter::new(std::fs::File::create(
            out.join("log.jsonl"),
        )?)),
        scenario.clone(),
    );
    let world_log = log.clone();
    let page_control = control.clone();
    let kit = Kit::new("Border")
        .guest(guest::guest(check))
        .observer(Arc::new(log.clone()))
        .observer(Arc::new(control.view.clone()))
        .page(move |dashboard, hosts| {
            page_control.page(
                Page::new("Border", dashboard)
                    .host(hosts.take(guest::HOSTNAME))
                    .standard_panels(),
            )
        })
        .world(move |cx, world| async move {
            // The checks run with no key, so the guest has no model to call.
            let model = if check {
                None
            } else {
                kit::desktop::claude_model(&cx)?
            };
            world::start(cx, world, scenario, control, world_log, model).await
        });
    if !check {
        let result = kit.run_app(&downloads, guest::HOSTNAME).await;
        let finished = log.finish();
        println!("whole run: {:.2} s", started.elapsed().as_secs_f64());
        result?;
        finished?;
        return Ok(());
    }
    kit::checks::run(
        kit,
        &downloads,
        &out,
        kit::checks::story(|run, out| -> kit::checks::Story<'_, Error> {
            Box::pin(async move { story::run(run, out).await.map_err(Into::into) })
        })
        .finish_with(move || Box::pin(async move { log.finish().map_err(Into::into) })),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod arguments {
    use super::{Mode, arguments};

    #[test]
    fn the_app_takes_only_its_folder_and_check_its_word() {
        let parse = |args: &[&str]| arguments(args.iter().map(|a| a.to_string())).ok();
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
        for bad in [
            &[][..],
            &["--checks"],
            &["d", "--checks"],
            &["d", "check", "check"],
            &["d", "extra"],
            &["preview", "check"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
