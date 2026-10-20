mod checks;
mod guest;
mod preview;
use fictionet_demo::search as page;

use adaptive_web_world::{events::LogObserver, pages::Seed, search::Searches};
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

/// What to run: the VM demo with its downloads folder, the seed's name and
/// whether the page stays open after the checks, or the preview without a
/// VM and whether it spends the generation budget.
#[derive(Debug, PartialEq)]
enum Mode {
    Run {
        downloads: PathBuf,
        seed: String,
        stay: bool,
    },
    Preview {
        spend: bool,
    },
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode> {
    const USAGE: &str =
        "usage: search <downloads> [--seed <name>] [--stay], or search preview [--spend-budget]";
    let first = args.next().ok_or(USAGE)?;
    if first == "preview" {
        return match (args.next().as_deref(), args.next()) {
            (None, _) => Ok(Mode::Preview { spend: false }),
            (Some("--spend-budget"), None) => Ok(Mode::Preview { spend: true }),
            _ => Err(USAGE.into()),
        };
    }
    if first.starts_with('-') {
        return Err(USAGE.into());
    }
    let (mut seed, mut stay) = (None, false);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--seed" if seed.is_none() => seed = Some(args.next().ok_or(USAGE)?),
            "--stay" if !stay => stay = true,
            _ => return Err(USAGE.into()),
        }
    }
    Ok(Mode::Run {
        downloads: first.into(),
        seed: seed.unwrap_or_else(|| "halvard-cve".into()),
        stay,
    })
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let (downloads, seed, stay) = match arguments(std::env::args().skip(1))? {
        Mode::Preview { spend } => return preview::run(spend).await,
        Mode::Run {
            downloads,
            seed,
            stay,
        } => (downloads, seed, stay),
    };
    let seed = Seed::builtin(&seed)?;
    let output = downloads.join("runs").join(format!(
        "search-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    ));
    std::fs::create_dir_all(output.parent().unwrap())?;
    std::fs::create_dir(&output)?;
    println!("output: {}", output.display());
    let searches = Arc::new(Searches::from_seed(&seed));
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
        .guest(guest::guest())
        .observer(searches.clone())
        .observer(Arc::new(LogObserver { log: log.clone() }))
        .page(move |dashboard, hosts| view.page(dashboard, hosts.take(guest::HOST)))
        .world(move |cx, mut world| async move {
            let network = page::World::new(&cx, seed, world_log)?;
            world.trust("office", &network.ca.cert_pem())?;
            topics.start(&cx, searches, network.pages.clone(), "Firefox (scripted)")?;
            network
                .network(&cx, world.mirror(&cx)?)?
                .route(kit::JUMP, kit::jump_prefix())
                .start(&cx, world.into_attachments())
        });
    let run = kit.boot(downloads).await?;
    println!(
        "boot to SSH-ready: {} ms",
        run.guest(guest::HOST).ssh_ready().as_millis()
    );
    let mut visited = BTreeSet::new();
    let mut result = checks::run(&run, &scenario, &output, &mut visited).await;
    if result.is_ok() {
        println!(
            "story done: {} ms",
            run.boot_started().elapsed().as_millis()
        );
        if stay {
            result = kit::checks::stay_open().await.map_err(Into::into);
        }
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
    fn arguments_take_a_folder_a_seed_and_stay_in_any_order() {
        let run = |downloads: &str, seed: &str, stay| {
            Some(Mode::Run {
                downloads: downloads.into(),
                seed: seed.into(),
                stay,
            })
        };
        assert_eq!(parse(&["d"]), run("d", "halvard-cve", false));
        assert_eq!(
            parse(&["d", "--stay", "--seed", "corvane-acquisition"]),
            run("d", "corvane-acquisition", true)
        );
        assert_eq!(
            parse(&["d", "--seed", "fastjsonl-package", "--stay"]),
            run("d", "fastjsonl-package", true)
        );
        assert_eq!(parse(&["preview"]), Some(Mode::Preview { spend: false }));
        assert_eq!(
            parse(&["preview", "--spend-budget"]),
            Some(Mode::Preview { spend: true })
        );
        for bad in [
            &[][..],
            &["--stay"],
            &["d", "--stay", "--stay"],
            &["d", "--seed"],
            &["d", "--seed", "a", "--seed", "b"],
            &["d", "extra"],
            &["d", "--other"],
            &["preview", "--stay"],
            &["preview", "--spend-budget", "--spend-budget"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
