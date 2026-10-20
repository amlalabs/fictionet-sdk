mod checks;
mod guest;
use fictionet_demo::search as page;

use adaptive_web_world::{events::LogObserver, search::Searches, stub::Seed};
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

/// The downloads folder, the seed's name and whether the page stays open
/// after the checks.
fn arguments(args: impl Iterator<Item = String>) -> Result<(PathBuf, String, bool)> {
    const USAGE: &str = "usage: search [downloads] [--seed <name>] [--stay]";
    let mut args = args.peekable();
    let downloads = if args.peek().is_some_and(|s| !s.starts_with('-')) {
        PathBuf::from(args.next().unwrap())
    } else {
        PathBuf::from("demos/downloads/cloudimage")
    };
    let (mut seed, mut stay) = (None, false);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--seed" if seed.is_none() => seed = Some(args.next().ok_or(USAGE)?),
            "--stay" if !stay => stay = true,
            _ => return Err(USAGE.into()),
        }
    }
    Ok((
        downloads,
        seed.unwrap_or_else(|| "halvard-cve".into()),
        stay,
    ))
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let (downloads, seed, stay) = arguments(std::env::args().skip(1))?;
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
            topics.start(&cx, searches, network.stub.clone(), "Firefox (scripted)")?;
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
    use super::arguments;

    fn parse(args: &[&str]) -> Option<(String, String, bool)> {
        arguments(args.iter().map(|a| a.to_string()))
            .ok()
            .map(|(downloads, seed, stay)| (downloads.display().to_string(), seed, stay))
    }

    #[test]
    fn arguments_take_a_folder_a_seed_and_stay_in_any_order() {
        let default = Some((
            "demos/downloads/cloudimage".to_string(),
            "halvard-cve".to_string(),
            false,
        ));
        assert_eq!(parse(&[]), default);
        assert_eq!(
            parse(&["d", "--stay", "--seed", "corvane-acquisition"]),
            Some(("d".into(), "corvane-acquisition".into(), true))
        );
        assert_eq!(
            parse(&["--seed", "fastjsonl-package", "--stay"]),
            Some((
                "demos/downloads/cloudimage".into(),
                "fastjsonl-package".into(),
                true
            ))
        );
        for bad in [
            &["--stay", "--stay"][..],
            &["--seed"],
            &["--seed", "a", "--seed", "b"],
            &["d", "extra"],
            &["--other"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
