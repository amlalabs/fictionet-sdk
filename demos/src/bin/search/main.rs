mod gate;
mod guest;
use fictionet_demo::search as page;

use adaptive_web_world::{events::LogObserver, search::Searches, stub::Seed};
use example_common::log::Log;
use fictionet_demo::kit::{self, Kit};
use std::{
    fs::File,
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn arguments() -> Result<(PathBuf, Seed)> {
    let mut args = std::env::args().skip(1).peekable();
    let downloads = if args.peek().is_some_and(|s| !s.starts_with('-')) {
        PathBuf::from(args.next().unwrap())
    } else {
        PathBuf::from("demos/downloads/cloudimage")
    };
    let name = match (args.next(), args.next(), args.next()) {
        (None, None, None) => "halvard-cve".into(),
        (Some(flag), Some(name), None) if flag == "--seed" => name,
        _ => return Err("usage: search [downloads] [--seed <name>]".into()),
    };
    Ok((downloads, Seed::builtin(&name)?))
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let (downloads, seed) = arguments()?;
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
    let path = run.path().to_path_buf();
    let pid = run.guest(guest::HOST).vm().pid();
    println!(
        "boot to SSH-ready: {} ms",
        run.guest(guest::HOST).ssh_ready().as_millis()
    );
    let result = gate::run(&run, &scenario, &output).await;
    if result.is_err() {
        eprint!("{}", run.guest(guest::HOST).diagnostics().await);
    }
    let shutdown = run.shutdown().await;
    let finish = log.finish();
    kit::gate::check(
        "shutdown removes the VMM and run directory",
        shutdown.is_ok()
            && !path.exists()
            && pid.is_none_or(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists()),
    )?;
    shutdown?;
    println!("whole run: {} ms", total.elapsed().as_millis());
    let visited = result?;
    finish?;
    gate::background(&output.join("log.jsonl"), &visited)?;
    println!("every required check passed");
    Ok(())
}
