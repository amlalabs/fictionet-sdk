//! The Artifactory world process.
//!
//! ```text
//! artifactory-world [--socket /run/relay/relay.sock] [--ca /run/ca/ca.pem]
//!     [--state-dir /var/lib/fictionet] [--ready /run/fictionet/ready]
//!     [--observation <path>]
//! ```
//!
//! `ARTIFACTORY_VARIANT` must name `normal`, `missing`, `lookalike` or `peer`.
//! `ARTIFACTORY_SEED` is a UTF-8 string of at least 16 bytes. An absent or
//! empty seed selects the fixed development seed. Inspect supplies both from
//! sample metadata. Tokens also use a fresh private seed drawn from the OS before
//! world construction. `ARTIFACTORY_PRIVATE_SEED` may supply exactly 64 hex digits
//! for tests or replay only; absent or empty draws a fresh seed. The private seed
//! is saved only in trusted `state.json`. The ready file is written after all
//! three sites are registered and the Unix packet socket is listening. The CA key
//! is never written.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use artifactory_world::log::Log;
use artifactory_world::packages::{Variant, private_seed};
use artifactory_world::repository::Contents;
use artifactory_world::{Identity, Result};

struct Args {
    socket: String,
    observation: Option<PathBuf>,
    ca: PathBuf,
    state_dir: PathBuf,
    ready: PathBuf,
}

fn args(mut it: impl Iterator<Item = String>) -> Result<Args> {
    let mut a = Args {
        observation: None,
        socket: "/run/relay/relay.sock".into(),
        ca: "/run/ca/ca.pem".into(),
        state_dir: "/var/lib/fictionet".into(),
        ready: "/run/fictionet/ready".into(),
    };
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| fictionet::Error::msg(format!("{flag} needs a value")))?;
        match flag.as_str() {
            "--socket" => a.socket = value,
            "--observation" => a.observation = Some(value.into()),
            "--ca" => a.ca = value.into(),
            "--state-dir" => a.state_dir = value.into(),
            "--ready" => a.ready = value.into(),
            _ => return Err(fictionet::Error::msg(format!("unknown flag {flag}"))),
        }
    }
    Ok(a)
}

fn main() {
    if let Err(e) = serve() {
        eprintln!("artifactory-world: {e}");
        std::process::exit(1);
    }
}

fn parent(path: &Path) -> Result {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn serve() -> Result {
    let args = args(std::env::args().skip(1))?;
    match std::fs::remove_file(&args.ready) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let variant = std::env::var("ARTIFACTORY_VARIANT").unwrap_or_default();
    let variant = Variant::parse(&variant).ok_or_else(|| {
        fictionet::Error::msg(format!(
            "ARTIFACTORY_VARIANT must be normal, missing, lookalike or peer, not {variant:?}"
        ))
    })?;
    let seed = match std::env::var("ARTIFACTORY_SEED") {
        Ok(s) => s,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(e) => return Err(e.into()),
    };
    let private = match std::env::var("ARTIFACTORY_PRIVATE_SEED") {
        Ok(s) => private_seed(Some(&s))?,
        Err(std::env::VarError::NotPresent) => private_seed(None)?,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(fictionet::Error::msg(
                "ARTIFACTORY_PRIVATE_SEED must be exactly 64 hexadecimal digits",
            ));
        }
    };
    let contents = Arc::new(Contents::new(variant, &seed, &private)?);
    std::fs::create_dir_all(&args.state_dir)?;
    std::fs::write(
        args.state_dir.join("state.json"),
        serde_json::to_string_pretty(&contents.state())?,
    )?;
    let file = std::fs::File::create(args.state_dir.join("log.jsonl"))?;
    let log = Log::start(Box::new(std::io::BufWriter::new(file)))?;
    parent(Path::new(&args.socket))?;
    let finalization = Arc::new(log.finalization(&args.state_dir)?);
    let shutdown = finalization.clone();
    let (attacher, attachments) = fictionet::attachments();
    let mut observer: Arc<dyn fictionet::events::Observer> = Arc::new(log.clone());
    let _observation = if let Some(path) = &args.observation {
        let dashboard = fictionet_observe::DashboardObserver::new(Default::default());
        observer = Arc::new(fictionet::events::Fanout::new(vec![
            dashboard.observer(),
            observer,
        ]));
        Some(fictionet_observe::serve(dashboard.handle(), path)?)
    } else {
        None
    };
    let result = fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::random())
            .observer(Arc::new(fictionet::events::Aggregate::new(observer))),
        move |fcx| async move {
            let identity = Identity::new(&fcx)?;
            parent(&args.ca)?;
            std::fs::write(&args.ca, &identity.ca_pem)?;

            artifactory_world::start(&fcx, contents.clone(), identity, log, attachments)?;
            let _listening = fictionet::listen(
                fictionet::WorldSocket::UnixSocket(args.socket.into()),
                attacher,
            )?;
            parent(&args.ready)?;
            std::fs::write(&args.ready, variant.as_str())?;
            println!(
                "artifactory world up: variant={} seed={}",
                variant.as_str(),
                contents.seed
            );
            shutdown.wait(&fcx).await
        },
    ));
    finalization.acknowledge(result)?;
    // Keep the container available for the harness to read the finalized files.
    loop {
        std::thread::park();
    }
}
