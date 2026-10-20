mod gate;
mod guest;
mod page;

#[cfg(test)]
mod tests;

use adaptive_web_world::{
    Addresses, Ca,
    events::LogObserver,
    search::Searches,
    stub::{Seed, Stub},
};
use example_common::log::Log;
use fictionet::stdlib::web;
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
        .page(move |dashboard, hosts| view.page(dashboard, hosts))
        .world(move |cx, mut world| async move {
            let start = adaptive_web_world::world_start(&seed.date)?;
            let addresses = Arc::new(Addresses::new(seed.fixed_addresses(), None)?);
            let ca = Arc::new(Ca::in_memory(&cx, start)?);
            world.trust("office", &ca.cert_pem())?;
            let tls = ca.config(&cx, kit::desktop::HOSTS[0])?.0;
            let mirror = world.mirror(&cx)?;
            let stub = Arc::new(Stub::new(seed));
            topics.start(&cx, searches, stub.clone())?;
            adaptive_web_world::net(&cx, addresses, ca, stub, world_log, start, move |host| {
                page::FORWARDED
                    .iter()
                    .any(|(name, _)| *name == host)
                    .then(|| {
                        let site = web::Site::new(mirror.clone());
                        if kit::desktop::HOSTS.contains(&host) {
                            site.tls(tls.clone())
                        } else {
                            site
                        }
                    })
            })
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
    let shutdown = run.shutdown().await;
    let finish = log.finish();
    gate::check(
        "shutdown removes the VMM and run directory",
        shutdown.is_ok()
            && !path.exists()
            && pid.is_none_or(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists()),
    )?;
    shutdown?;
    println!("whole run: {} ms", total.elapsed().as_millis());
    result?;
    finish?;
    println!("every required check passed");
    Ok(())
}
