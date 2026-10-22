//! Runs the Artifactory world and a scripted agent on an Ubuntu desktop, and
//! serves its page: Doors tried, Packages and Requests beside the standard
//! panels. Run `cargo xtask demo artifactory`. The default variant is
//! lookalike. Select normal, missing, lookalike or peer with `--variant`.
//! `artifactory preview` serves the page without a VM. Its `--extra-reads N`
//! adds N index reads after the replayed story, enough to fill the page's
//! row bound. With `--variant peer`, `--sessions shared|separate` adds a
//! colleague's laptop whose session leaves a note in the cache first. The
//! two sessions use one repository state, or a separate state each.

mod facts;
mod guest;
mod page;
mod preview;
mod story;
mod world;

use artifactory_world::{
    ServedNames,
    log::Log,
    packages::{Variant, private_seed},
    repository::Contents,
};
use fictionet::events::Fanout;
use fictionet_demo::kit::{self, Kit};
use fictionet_extras::names;
use fictionet_observe::Aggregate;
use guest::HOSTNAME;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicBool};
use story::Mode;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Args {
    /// None for the preview without a VM.
    downloads: Option<PathBuf>,
    variant: Variant,
    extra_reads: usize,
    sessions: Option<Mode>,
}

fn args(mut args: impl Iterator<Item = String>) -> Result<Args> {
    let first = args.next().ok_or(
        "usage: artifactory <downloads> [--variant normal|missing|lookalike|peer] [--sessions shared|separate], or artifactory preview [--variant V] [--sessions S] [--extra-reads N]",
    )?;
    if first.starts_with("--") {
        return Err("expected the downloads directory or preview before options".into());
    }
    let preview = first == "preview";
    let mut parsed = Args {
        downloads: (!preview).then(|| first.into()),
        variant: Variant::Lookalike,
        extra_reads: 0,
        sessions: None,
    };
    let (mut selected, mut reads) = (false, false);
    while let Some(flag) = args.next() {
        match flag.as_str() {
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
            "--extra-reads" if preview && !reads => {
                reads = true;
                parsed.extra_reads = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .ok_or("--extra-reads needs a count")?;
            }
            _ => return Err(format!("unknown argument {flag}").into()),
        }
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
        extra_reads,
        sessions,
    } = args(std::env::args().skip(1))?;
    let Some(downloads) = downloads else {
        return preview::serve(variant, sessions, extra_reads).await;
    };
    let shots = downloads.join("artifactory");
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
    let publisher = Arc::new(facts::Publisher::start(facts.clone()));
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
    let result = kit.run_app(&downloads, HOSTNAME).await;
    publisher.flush().await?;
    log.finish()?;
    result?;
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
        for input in [&["preview"][..], &["preview", "--variant", "peer"]] {
            assert!(parse(input).unwrap().downloads.is_none());
        }
        assert!(parse(&["d"]).unwrap().downloads.is_some());
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
                &["preview", "--variant", "peer", "--sessions", "separate"],
                Mode::Separate,
            ),
        ] {
            assert_eq!(parse(input).unwrap().sessions, Some(mode));
        }
        assert_eq!(parse(&["d", "--variant", "peer"]).unwrap().sessions, None);
        let error = parse(&["d", "--sessions", "shared"]).err().unwrap();
        assert!(error.to_string().contains("--variant peer"), "{error}");
        let flooded = parse(&["preview", "--extra-reads", "600"]).unwrap();
        assert_eq!(flooded.extra_reads, 600);
        assert_eq!(parse(&["preview"]).unwrap().extra_reads, 0);
        for input in [
            &[][..],
            &["--stay"],
            &["--variant", "peer"],
            &["preview", "--stay"],
            &["d", "preview"],
            &["d", "--stay", "--stay"],
            &["d", "--variant", "peer", "--variant", "normal"],
            &["d", "--variant"],
            &["d", "--variant", "bad"],
            &["d", "--bad", "peer"],
            &["d", "--variant", "peer", "extra"],
            &["d", "--extra-reads", "600"],
            &["preview", "--extra-reads"],
            &["preview", "--extra-reads", "many"],
            &["preview", "--extra-reads", "1", "--extra-reads", "2"],
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
