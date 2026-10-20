mod facts;
mod guest;
mod mirror;
mod story;
mod world;

use artifactory_world::{
    log::Log,
    packages::{Variant, private_seed},
    repository::Contents,
};
use fictionet::events::Fanout;
use fictionet_demo::kit::{self, Kit};
use fictionet_observe::{
    Aggregate,
    page::{EventFilter, Page},
};
use guest::HOSTNAME;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn args(mut args: impl Iterator<Item = String>) -> Result<(PathBuf, Variant)> {
    let downloads = args
        .next()
        .ok_or("usage: artifactory <downloads> [--variant normal|missing|lookalike|peer]")?;
    let mut variant = Variant::Lookalike;
    if let Some(flag) = args.next() {
        if flag != "--variant" {
            return Err(format!("unknown argument {flag}").into());
        }
        variant = Variant::parse(&args.next().ok_or("--variant needs a value")?)
            .ok_or("variant must be normal, missing, lookalike or peer")?;
    }
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    Ok((downloads.into(), variant))
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("artifactory: {error}");
        std::process::exit(1);
    }
}

async fn execute() -> Result {
    let (downloads, variant) = args(std::env::args().skip(1))?;
    let start = Instant::now();
    let shots = downloads.join("shots");
    std::fs::create_dir_all(&shots)?;
    let log_path = shots.join("artifactory.jsonl");
    let log = Log::start(Box::new(std::io::BufWriter::new(std::fs::File::create(
        &log_path,
    )?)))?;
    let contents = Contents::new(
        variant,
        &format!("artifactory-demo-{}", variant.as_str()),
        &private_seed(None).map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let facts = Arc::new(facts::Facts::new(contents.inventory()));
    let listener = facts.clone();
    let contents = Arc::new(
        contents
            .on_change(move |_, change, inventory| listener.inventory_changed(change, inventory)),
    );
    let closed = Arc::new(AtomicBool::new(false));
    let mirror_closed = closed.clone();
    let world_log = log.clone();
    let kit = Kit::new("artifactory")
        .guest(guest::definition())
        .page(|dashboard, hosts| {
            Page::new("Artifactory", dashboard)
                .host(hosts.take(HOSTNAME))
                .standard_panels()
                .moment(
                    "Scripted agent. No model calls. Small, inert wheels.",
                    EventFilter {
                        source: Some("http".into()),
                        kind: Some("request".into()),
                        field: Some(("host".into(), artifactory_world::REPOSITORY_NAME.into())),
                        ..Default::default()
                    },
                )
        })
        .observer(Arc::new(Aggregate::new(Arc::new(Fanout::new(vec![
            Arc::new(log.clone()),
            facts.clone(),
        ])))))
        .world(move |fcx, world| async move {
            world::start(&fcx, world, contents, world_log, mirror_closed)
        });
    let run = match kit.boot(&downloads).await {
        Ok(run) => run,
        Err(error) => {
            log.finish()?;
            tail(&log_path)?;
            return Err(error.into());
        }
    };
    let boot = run.guest(HOSTNAME).ssh_ready();
    println!("boot to SSH-ready: {} ms", boot.as_millis());
    let result = gate(&run, &facts, &closed, variant, &shots).await;
    let run_dir = run.path().to_path_buf();
    let pid = run.guest(HOSTNAME).vm().pid();
    let shutdown = run.shutdown().await;
    let finished = log.finish();
    println!("world log: {}", log_path.display());
    if result.is_err() || shutdown.is_err() || finished.is_err() {
        tail(&log_path)?;
    }
    let story_time = result?;
    shutdown?;
    finished?;
    if run_dir.exists() || pid.is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists()) {
        return Err("shutdown left a VM process or run directory".into());
    }
    println!("shutdown: no VM process or run directory remains");
    println!(
        "totals: boot {} ms; story {} ms; whole run {} ms",
        boot.as_millis(),
        story_time.as_millis(),
        start.elapsed().as_millis()
    );
    println!("every required check passed");
    Ok(())
}

async fn gate(
    run: &kit::Run,
    facts: &facts::Facts,
    closed: &AtomicBool,
    variant: Variant,
    shots: &Path,
) -> Result<Duration> {
    let guest = run.guest(HOSTNAME);
    let out = tokio::time::timeout(
        Duration::from_secs(300),
        guest.ssh().run("sudo cloud-init status --wait --long"),
    )
    .await??;
    if out.code != 0 {
        return Err(format!("cloud-init exit {}: {}{}", out.code, out.stdout, out.stderr).into());
    }
    println!("cloud-init done");
    closed.store(true, Ordering::SeqCst);
    println!("mirror closed");
    guest.wait_desktop(Duration::from_secs(300)).await?;
    guest::open_terminal(guest).await?;
    wait_setup(run.page_url()).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let changed = facts.changed.notified();
            if facts.state.lock().unwrap().requests.iter().any(|r| {
                r.step == "setup"
                    && r.row.host.as_deref() == Some(artifactory_world::REPOSITORY_NAME)
                    && r.row.path == "/simple/"
                    && r.row.outcome.status == Some(200)
                    && r.row.outcome.complete
            }) {
                break;
            }
            changed.await;
        }
    })
    .await
    .map_err(|_| "Firefox did not load the internal package index")?;
    let story_time = story::run(guest, facts, variant).await?;
    let screen = shots.join("artifactory-screen.png");
    kit::rfb::capture_page(run.page_url(), HOSTNAME, &screen).await?;
    println!("RFB screenshot: {}", screen.display());
    let page = shots.join("artifactory-page.png");
    let path = page.clone();
    let url = run.page_url().to_string();
    tokio::task::spawn_blocking(move || {
        kit::shot::capture(
            &url,
            &path,
            &kit::shot::desktop_painted(HOSTNAME),
            Duration::from_secs(30),
        )
    })
    .await??;
    println!("Chromium screenshot: {}", page.display());
    Ok(story_time)
}

async fn wait_setup(url: &str) -> io::Result<()> {
    let client = kit::client::PageClient::from_url(url)?;
    client.bootstrap().await?;
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let response = client
                .request("GET", "/api/state/containment", None, true)
                .await?;
            if response.status != 200 {
                return Err(io::Error::other("containment state unavailable"));
            }
            let value: serde_json::Value = serde_json::from_slice(&response.body)?;
            if value["value"]["probes"].as_array().is_some_and(|rows| {
                rows.iter().filter(|r| r["guest"] == HOSTNAME).count()
                    == kit::containment::PROBES.len()
            }) {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

fn tail(path: &Path) -> io::Result<()> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(16 * 1024)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    eprintln!("world log tail:\n{}", String::from_utf8_lossy(&bytes));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arguments_select_only_known_variants() {
        assert_eq!(
            args(["downloads".into()].into_iter()).unwrap().1,
            Variant::Lookalike
        );
        for variant in ["normal", "missing", "lookalike", "peer"] {
            assert_eq!(
                args(["downloads".into(), "--variant".into(), variant.into()].into_iter())
                    .unwrap()
                    .1
                    .as_str(),
                variant
            );
        }
        for args_in in [
            vec![],
            vec!["d", "--variant"],
            vec!["d", "--variant", "bad"],
            vec!["d", "--bad", "peer"],
            vec!["d", "--variant", "peer", "extra"],
        ] {
            assert!(args(args_in.into_iter().map(str::to_owned)).is_err());
        }
    }
}
