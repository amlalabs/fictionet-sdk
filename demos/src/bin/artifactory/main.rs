//! Runs the Artifactory world and a scripted agent on an Ubuntu desktop, and
//! serves its page: Doors tried, Packages and Requests beside the standard
//! panels. Run `cargo xtask demo artifactory`. The default variant is
//! lookalike. Select normal, missing, lookalike or peer with `--variant`.
//! Add `--stay` to keep the page open after the gate until Ctrl-C.
//! Run `cargo run -p fictionet-demo --bin artifactory -- --fixture` to serve
//! the page without a VM. `--extra-reads N` adds N index reads after the
//! fixture's story, enough to fill the page's row bound.

mod facts;
mod fixture;
mod guest;
mod page;
mod story;
mod world;

use artifactory_world::{
    log::Log,
    packages::{Variant, private_seed},
    repository::Contents,
};
use fictionet::events::Fanout;
use fictionet_demo::kit::{self, Kit};
use fictionet_observe::Aggregate;
use guest::HOSTNAME;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Args {
    downloads: PathBuf,
    variant: Variant,
    stay: bool,
    fixture: bool,
    extra_reads: usize,
}

fn args(mut args: impl Iterator<Item = String>) -> Result<Args> {
    let first = args.next().ok_or(
        "usage: artifactory <downloads> [--variant normal|missing|lookalike|peer] [--stay], or artifactory --fixture [--variant V] [--extra-reads N]",
    )?;
    let mut parsed = Args {
        fixture: first == "--fixture",
        downloads: first.into(),
        variant: Variant::Lookalike,
        stay: false,
        extra_reads: 0,
    };
    if !parsed.fixture && parsed.downloads.to_string_lossy().starts_with("--") {
        return Err("expected the downloads directory before options".into());
    }
    let (mut selected, mut reads) = (false, false);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--fixture" if !parsed.fixture => parsed.fixture = true,
            "--stay" if !parsed.stay => parsed.stay = true,
            "--variant" if !selected => {
                selected = true;
                parsed.variant = Variant::parse(&args.next().ok_or("--variant needs a value")?)
                    .ok_or("variant must be normal, missing, lookalike or peer")?;
            }
            "--extra-reads" if !reads => {
                reads = true;
                parsed.extra_reads = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .ok_or("--extra-reads needs a count")?;
            }
            _ => return Err(format!("unknown argument {flag}").into()),
        }
    }
    if reads && !parsed.fixture {
        return Err("--extra-reads applies only to --fixture".into());
    }
    Ok(parsed)
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("artifactory: {error}");
        std::process::exit(1);
    }
}

async fn execute() -> Result {
    let Args {
        downloads,
        variant,
        stay,
        fixture,
        extra_reads,
    } = args(std::env::args().skip(1))?;
    if fixture {
        return fixture::serve(variant, extra_reads).await;
    }
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
    let facts = Arc::new(facts::Facts::new(
        contents.inventory(),
        page::scenario(variant, false),
    ));
    let publisher = facts::Publisher::start(facts.clone());
    let listener = facts.clone();
    let contents =
        Arc::new(contents.on_change(move |at, change, inventory| {
            listener.inventory_changed(at, change, inventory)
        }));
    let closed = Arc::new(AtomicBool::new(false));
    let mirror_closed = closed.clone();
    let world_log = log.clone();
    let topics = facts.topics.clone();
    let inventory = contents.inventory();
    let kit = Kit::new("artifactory")
        .guest(guest::definition())
        .page(move |dashboard, hosts| {
            page::compose(&inventory, dashboard, hosts.take(HOSTNAME), topics, false)
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
    let result = gate(&run, &facts, &publisher, &closed, variant, &shots).await;
    let result = match result {
        Ok(duration) if stay => {
            println!("gate passed");
            kit::gate::stay_open()
                .await
                .map(|()| duration)
                .map_err(Into::into)
        }
        result => result,
    };
    if result.is_err() {
        eprint!("{}", run.guest(HOSTNAME).diagnostics().await);
    }
    let run_dir = run.path().to_path_buf();
    let pid = run.guest(HOSTNAME).vm().pid();
    let shutdown = run.shutdown().await;
    let published = publisher
        .flush()
        .await
        .and_then(|()| facts.state.lock().unwrap().check_complete());
    let finished = log.finish();
    println!("world log: {}", log_path.display());
    if result.is_err() || shutdown.is_err() || published.is_err() || finished.is_err() {
        tail(&log_path)?;
    }
    let story_time = result?;
    shutdown?;
    published?;
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
    publisher: &facts::Publisher,
    closed: &AtomicBool,
    variant: Variant,
    shots: &Path,
) -> Result<Duration> {
    let guest = run.guest(HOSTNAME);
    guest.wait_cloud_init(Duration::from_secs(300)).await?;
    println!("cloud-init done");
    closed.store(true, Ordering::SeqCst);
    println!("mirror closed");
    guest.wait_desktop(Duration::from_secs(300)).await?;
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
    guest::open_terminal(guest).await?;
    let story_time = story::run(guest, facts, publisher, variant).await?;
    println!("{}", page::check(run.page_url(), variant).await?);
    run.screenshots(
        HOSTNAME,
        &shots.join("artifactory-screen.png"),
        &shots.join("artifactory-page.png"),
    )
    .await?;
    Ok(story_time)
}

async fn wait_setup(url: &str) -> io::Result<()> {
    let client = kit::client::PageClient::from_url(url)?;
    client.bootstrap().await?;
    client
        .wait_for(
            "/api/state/containment",
            Duration::from_secs(90),
            Duration::from_millis(250),
            |value| {
                Ok(value["value"]["probes"].as_array().is_some_and(|rows| {
                    rows.iter().filter(|r| r["guest"] == HOSTNAME).count()
                        == kit::containment::PROBES.len()
                }))
            },
        )
        .await?;
    Ok(())
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
        let parse = |input: &[&str]| args(input.iter().map(|s| (*s).to_owned()));
        assert_eq!(parse(&["downloads"]).unwrap().variant, Variant::Lookalike);
        for variant in ["normal", "missing", "lookalike", "peer"] {
            assert_eq!(
                parse(&["downloads", "--variant", variant])
                    .unwrap()
                    .variant
                    .as_str(),
                variant
            );
        }
        for input in [
            &["d", "--stay"][..],
            &["d", "--stay", "--variant", "peer"],
            &["d", "--variant", "normal", "--stay"],
        ] {
            assert!(parse(input).unwrap().stay);
        }
        for input in [
            &["--fixture"][..],
            &["d", "--fixture"],
            &["--fixture", "--variant", "peer"],
        ] {
            assert!(parse(input).unwrap().fixture);
        }
        let flooded = parse(&["--fixture", "--extra-reads", "600"]).unwrap();
        assert_eq!(flooded.extra_reads, 600);
        assert_eq!(parse(&["--fixture"]).unwrap().extra_reads, 0);
        for input in [
            &[][..],
            &["--stay"],
            &["--fixture", "--fixture"],
            &["d", "--stay", "--stay"],
            &["d", "--variant", "peer", "--variant", "normal"],
            &["d", "--variant"],
            &["d", "--variant", "bad"],
            &["d", "--bad", "peer"],
            &["d", "--variant", "peer", "extra"],
            &["d", "--extra-reads", "600"],
            &["--fixture", "--extra-reads"],
            &["--fixture", "--extra-reads", "many"],
            &["--fixture", "--extra-reads", "1", "--extra-reads", "2"],
        ] {
            assert!(parse(input).is_err(), "{input:?}");
        }
    }
}
