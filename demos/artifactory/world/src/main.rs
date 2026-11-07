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
use fictionet_extras::args::{Args, configuration, unknown};

#[tokio::main]
async fn main() {
    if let Err(e) = serve().await {
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

async fn serve() -> Result {
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
    let variant = config
        .variant
        .parse::<Variant>()
        .map_err(|_| fictionet::Error::msg("variant must be normal, missing, lookalike or peer"))?;
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
    let (updates, snapshots) = tokio::sync::watch::channel(Snapshot::default());
    let log = if args.observation.is_some() {
        log.observe(move |fact| {
            updates.send_modify(|snapshot| snapshot.record(fact));
        })
    } else {
        log
    };
    let observation = if let Some(path) = &args.observation {
        parent(path)?;
        let listener = tokio::net::UnixListener::bind(path)?;
        let current = snapshots.clone();
        let routes = axum::Router::new()
            .route(
                "/",
                axum::routing::get(move || {
                    let current = current.clone();
                    async move { axum::Json(current.borrow().clone()) }
                }),
            )
            .merge(fictionet::stdlib::page::state(snapshots));
        Some(tokio::spawn(
            async move { axum::serve(listener, routes).await },
        ))
    } else {
        None
    };
    let result = fictionet::run(fictionet::Seed::random(), move |fcx| async move {
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
        let variant = variant.as_str();
        std::fs::write(&args.ready, variant)?;
        println!(
            "artifactory world up: variant={variant} seed={}",
            contents.seed
        );
        shutdown.wait(&fcx).await
    })
    .await;
    if let Some(task) = observation {
        task.abort();
    }
    finalization.acknowledge(result)?;
    // Keep the container available for the harness to read the finalized files.
    loop {
        std::thread::park();
    }
}

/// Recent typed facts. Counts expose truncation without retaining an unbounded log.
#[derive(Clone, Default, serde::Serialize)]
struct Snapshot {
    requests: std::collections::VecDeque<artifactory_world::facts::Request>,
    doors: std::collections::VecDeque<artifactory_world::facts::Door>,
    dropped: u64,
}

impl Snapshot {
    fn record(&mut self, fact: &artifactory_world::facts::Observation) {
        const LIMIT: usize = 256;
        if let Some(request) = &fact.request {
            self.requests.push_back(request.clone());
            if self.requests.len() > LIMIT {
                self.requests.pop_front();
                self.dropped += 1;
            }
        }
        if let Some(door) = &fact.door {
            self.doors.push_back(door.clone());
            if self.doors.len() > LIMIT {
                self.doors.pop_front();
                self.dropped += 1;
            }
        }
    }
}
