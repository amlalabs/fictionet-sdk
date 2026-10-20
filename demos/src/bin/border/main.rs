//! Border's scripted workstation on the shared page and microVM kit.

mod certificates;
mod checks;
mod client;
mod control;
mod guest;
mod preview;
mod results;
mod story;
#[cfg(test)]
mod tests;
mod tls;
mod trace;
mod view;
mod world;

use border_world::log::Log;
use fictionet_demo::kit::{self, Kit};
use fictionet_observe::page::Page;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    const USAGE: &str = "usage: border <downloads> [--checks], or border preview";
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or(USAGE)?;
    if first == "preview" {
        if args.next().is_some() {
            return Err(USAGE.into());
        }
        return preview::run().await;
    }
    let downloads = PathBuf::from(first);
    let option = args.next();
    if option.as_deref().is_some_and(|s| s != "--checks") || args.next().is_some() {
        return Err(USAGE.into());
    }
    let checks_only = option.is_some() || !std::io::stdin().is_terminal();
    let started = Instant::now();
    let out = downloads
        .join("shots")
        .join(format!("border-{}", kit::random_uuid()));
    std::fs::create_dir_all(&out)?;
    println!("Output: {}", out.display());
    let scenario = control::scenario();
    let control = control::Control::new(&scenario)?;
    let log = Log::start(
        Box::new(results::Writer::new(
            std::fs::File::create(out.join("log.jsonl"))?,
            control.results.clone(),
        )),
        scenario.clone(),
    );
    let world_log = log.clone();
    let page_control = control.clone();
    println!("Border: booting one Ubuntu workstation with a scripted agent.");
    println!(
        "Terminal: read-only tmux session main. Ctrl-b d opens your own login shell; run bank-check subcommands there."
    );
    println!("Taking browser input does not pause the scripted agent.");
    let boot = Kit::new("Border")
        .guest(guest::guest())
        .observer(Arc::new(log.clone()))
        .observer(Arc::new(control.view.clone()))
        .page(move |dashboard, hosts| {
            page_control.page(
                Page::new("Border", dashboard)
                    .host(hosts.take(guest::HOSTNAME))
                    .standard_panels(),
            )
        })
        .world(move |cx, world| world::start(cx, world, scenario, control, world_log))
        .boot(&downloads)
        .await;
    let run = match boot {
        Ok(run) => run,
        Err(error) => {
            let finished = log.finish();
            finished?;
            return Err(error.into());
        }
    };
    println!(
        "Boot to SSH-ready: {:.2} s",
        run.guest(guest::HOSTNAME).ssh_ready().as_secs_f64()
    );
    let result: Result<(), Error> = async {
        let ready = run
            .guest(guest::HOSTNAME)
            .wait_desktop(Duration::from_secs(300))
            .await?;
        println!("Boot to desktop-ready: {:.2} s", ready.as_secs_f64());
        story::run(&run, &out).await?;
        run.containment().await?;
        println!(
            "Story completed in {:.2} s",
            started.elapsed().as_secs_f64()
        );
        if !checks_only {
            println!("Use Routing to flip the route, or Ctrl-b d in the terminal for bank-check.");
            kit::checks::stay_open().await?;
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        eprint!("{}", run.guest(guest::HOSTNAME).diagnostics().await);
    }
    let shutdown = run.shutdown().await;
    let finished = log.finish();
    result?;
    shutdown?;
    finished?;
    println!("Output: {}", out.display());
    println!(
        "Shutdown complete; whole run: {:.2} s",
        started.elapsed().as_secs_f64()
    );
    println!("every required check passed");
    Ok(())
}
