//! The Artifactory world process.
//!
//! ```text
//! artifactory-world JSON [--socket /run/relay/relay.sock] [--ca-dir /run/ca]
//!     [--state-dir /var/lib/fictionet] [--ready /run/fictionet/ready]
//!     [--observation <path>]
//! ```
//!
//! The first argument is JSON with `variant`, optional `seed`, and optional
//! `private_seed` (64 hex digits for replay).

use std::path::Path;
use std::sync::Arc;

use artifactory_world::log::Log;
use artifactory_world::packages::{Variant, private_seed};
use artifactory_world::repository::Contents;
use artifactory_world::repository::Sessions;
use artifactory_world::{Identity, Result};
use example_common::args::{Args, configuration, unknown};
use example_common::names::{name, parse};

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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    variant: String,
    #[serde(default)]
    seed: String,
    private_seed: Option<String>,
}

fn serve() -> Result {
    let mut argv = std::env::args().skip(1);
    let config: Configuration = configuration(&mut argv).map_err(fictionet::Error::msg)?;
    let args = Args {
        socket: "/run/relay/relay.sock".into(),
        ca_dir: "/run/ca".into(),
        ..Args::default()
    }
    .read(argv, unknown)
    .map_err(fictionet::Error::msg)?;
    match std::fs::remove_file(&args.ready) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let variant = parse::<Variant>(&config.variant).ok_or_else(|| {
        fictionet::Error::msg("variant must be normal, missing, lookalike or peer")
    })?;
    let private = private_seed(config.private_seed.as_deref())?;
    let contents = Arc::new(Contents::new(variant, &config.seed, &private)?);
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
    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.observation.clone(),
        Some(Arc::new(log.clone())),
    )?;
    let result = fictionet::block_on(fictionet::run(options, move |fcx| async move {
        let identity = Identity::new(&fcx)?;
        std::fs::create_dir_all(&args.ca_dir)?;
        std::fs::write(args.ca_dir.join("ca.pem"), &identity.ca_pem)?;

        artifactory_world::start(
            &fcx,
            Sessions::Shared(contents.clone()),
            identity,
            log,
            attachments,
        )?;
        let _listening = fictionet::listen(
            fictionet::WorldSocket::UnixSocket(args.socket.into()),
            attacher,
        )?;
        parent(&args.ready)?;
        let variant = name(&variant);
        std::fs::write(&args.ready, &variant)?;
        println!(
            "artifactory world up: variant={variant} seed={}",
            contents.seed
        );
        shutdown.wait(&fcx).await
    }));
    finalization.acknowledge(result)?;
    // Keep the container available for the harness to read the finalized files.
    loop {
        std::thread::park();
    }
}
