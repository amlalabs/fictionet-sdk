//! Runs the Artifactory world and a scripted agent on an Ubuntu desktop, and
//! serves its page: Doors tried, Packages and Requests beside the standard
//! panels. Run `cargo xtask demo artifactory`. The default variant is
//! lookalike. Select normal, missing, lookalike or peer with `--variant`.
//! Add `--stay` to keep the page open after the gate until Ctrl-C.
//! Run `cargo run -p fictionet-demo --bin artifactory -- --fixture` to serve
//! the page without a VM. `--extra-reads N` adds N index reads after the
//! fixture's story, enough to fill the page's row bound. With `--variant
//! peer`, `--sessions shared|separate` adds a colleague's laptop whose
//! session leaves a note in the cache first. The two sessions use one
//! repository state, or a separate state each.

mod facts;
mod fixture;
mod guest;
mod page;
mod story;
mod world;

use artifactory_world::{
    ServedNames,
    log::Log,
    packages::{Variant, private_seed},
    repository::Contents,
};
use example_common::names;
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
use story::Mode;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Args {
    downloads: PathBuf,
    variant: Variant,
    stay: bool,
    fixture: bool,
    extra_reads: usize,
    sessions: Option<Mode>,
}

fn args(mut args: impl Iterator<Item = String>) -> Result<Args> {
    let first = args.next().ok_or(
        "usage: artifactory <downloads> [--variant normal|missing|lookalike|peer] [--sessions shared|separate] [--stay], or artifactory --fixture [--variant V] [--sessions S] [--extra-reads N]",
    )?;
    let mut parsed = Args {
        fixture: first == "--fixture",
        downloads: first.into(),
        variant: Variant::Lookalike,
        stay: false,
        extra_reads: 0,
        sessions: None,
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
                parsed.variant = names::parse(&args.next().ok_or("--variant needs a value")?)
                    .ok_or("variant must be normal, missing, lookalike or peer")?;
            }
            "--sessions" if parsed.sessions.is_none() => {
                parsed.sessions = Some(
                    Mode::parse(&args.next().ok_or("--sessions needs a value")?)
                        .ok_or("sessions must be shared or separate")?,
                );
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
    if parsed.sessions.is_some() && parsed.variant != Variant::Peer {
        return Err("--sessions needs --variant peer, the only variant that accepts MKCOL".into());
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
        sessions,
    } = args(std::env::args().skip(1))?;
    if fixture {
        return fixture::serve(variant, sessions, extra_reads).await;
    }
    let start = Instant::now();
    let shots = downloads.join("shots");
    std::fs::create_dir_all(&shots)?;
    let log_path = shots.join("artifactory.jsonl");
    let log = Log::start(Box::new(std::io::BufWriter::new(std::fs::File::create(
        &log_path,
    )?)))?;
    let private = private_seed(None).map_err(io::Error::other)?;
    let state = || {
        Contents::new(
            variant,
            &format!("artifactory-demo-{}", names::name(&variant)),
            &private,
        )
        .map_err(io::Error::other)
    };
    let contents = state()?;
    let colleague = (sessions == Some(Mode::Separate)).then(state).transpose()?;
    let names = [HOSTNAME, guest::COLLEAGUE];
    let facts = Arc::new(facts::Facts::new(
        contents.inventory(),
        colleague.as_ref().map(Contents::inventory),
        page::scenario(variant, false, sessions.map(|mode| (mode, names))),
        names,
        ServedNames::new(kit::desktop::HOSTS),
    ));
    let publisher = facts::Publisher::start(facts.clone());
    let inventory = contents.inventory();
    let states = world::sessions(
        facts.listen(facts::Store::Main, contents),
        colleague.map(|contents| facts.listen(facts::Store::Colleague, contents)),
        names,
    );
    if let Some(mode) = sessions {
        println!(
            "sessions: {} ({HOSTNAME} and {})",
            mode.describe(),
            guest::COLLEAGUE
        );
    }
    let closed = Arc::new(AtomicBool::new(false));
    let mirror_closed = closed.clone();
    let world_log = log.clone();
    let topics = facts.topics.clone();
    let mut kit = Kit::new("artifactory").guest(guest::definition());
    if sessions.is_some() {
        kit = kit.guest(guest::colleague());
    }
    let two = sessions.is_some();
    let kit = kit
        .page(move |dashboard, hosts| {
            let mut list = vec![hosts.take(HOSTNAME)];
            if two {
                list.push(hosts.take(guest::COLLEAGUE));
            }
            page::compose(&inventory, dashboard, list, topics, false)
        })
        .observer(Arc::new(Aggregate::new(Arc::new(Fanout::new(vec![
            Arc::new(log.clone()),
            facts.clone(),
        ])))))
        .world(move |fcx, world| async move {
            world::start(&fcx, world, states, world_log, mirror_closed)
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
    let result = gate(&run, &facts, &publisher, &closed, variant, sessions, &shots).await;
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
        if two {
            eprint!("{}", run.guest(guest::COLLEAGUE).diagnostics().await);
        }
    }
    let run_dir = run.path().to_path_buf();
    let mut pids = vec![run.guest(HOSTNAME).vm().pid()];
    if two {
        pids.push(run.guest(guest::COLLEAGUE).vm().pid());
    }
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
    if run_dir.exists()
        || pids
            .iter()
            .flatten()
            .any(|pid| Path::new(&format!("/proc/{pid}")).exists())
    {
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
    sessions: Option<Mode>,
    shots: &Path,
) -> Result<Duration> {
    let guest = run.guest(HOSTNAME);
    let colleague = sessions.map(|_| run.guest(guest::COLLEAGUE));
    let mut names = vec![HOSTNAME];
    for handle in std::iter::once(guest).chain(colleague) {
        handle.wait_cloud_init(Duration::from_secs(300)).await?;
        println!("cloud-init done: {}", handle.name());
    }
    if colleague.is_some() {
        names.push(guest::COLLEAGUE);
    }
    closed.store(true, Ordering::SeqCst);
    println!("mirror closed");
    guest.wait_desktop(Duration::from_secs(300)).await?;
    wait_setup(run.page_url(), &names).await?;
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
    let story_time = story::run(guest, colleague, facts, publisher, variant, sessions).await?;
    println!("{}", page::check(run.page_url(), variant, sessions).await?);
    run.screenshots(
        HOSTNAME,
        &shots.join("artifactory-screen.png"),
        &shots.join("artifactory-page.png"),
    )
    .await?;
    Ok(story_time)
}

/// Waits until the containment probes of every named guest are on the page.
async fn wait_setup(url: &str, names: &[&str]) -> io::Result<()> {
    let client = kit::client::PageClient::from_url(url)?;
    client.bootstrap().await?;
    client
        .wait_for(
            "/api/state/containment",
            Duration::from_secs(90),
            Duration::from_millis(250),
            |value| {
                Ok(value["value"]["probes"].as_array().is_some_and(|rows| {
                    names.iter().all(|name| {
                        rows.iter().filter(|r| r["guest"] == *name).count()
                            == kit::containment::PROBES.len()
                    })
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
                names::name(&parse(&["downloads", "--variant", variant]).unwrap().variant),
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
        for (input, mode) in [
            (
                &["d", "--variant", "peer", "--sessions", "shared"][..],
                Mode::Shared,
            ),
            (
                &["d", "--sessions", "separate", "--variant", "peer"],
                Mode::Separate,
            ),
            (
                &["--fixture", "--variant", "peer", "--sessions", "separate"],
                Mode::Separate,
            ),
        ] {
            assert_eq!(parse(input).unwrap().sessions, Some(mode));
        }
        assert_eq!(parse(&["d", "--variant", "peer"]).unwrap().sessions, None);
        let error = parse(&["d", "--sessions", "shared"]).err().unwrap();
        assert!(error.to_string().contains("--variant peer"), "{error}");
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
            &["d", "--variant", "lookalike", "--sessions", "shared"],
            &["d", "--variant", "peer", "--sessions", "both"],
            &["d", "--variant", "peer", "--sessions"],
            &[
                "d",
                "--variant",
                "peer",
                "--sessions",
                "shared",
                "--sessions",
                "shared",
            ],
        ] {
            assert!(parse(input).is_err(), "{input:?}");
        }
    }
}
