//! The adaptive web's world process. See the library ([`adaptive_web_world`])
//! for what it builds.
//!
//! ```text
//! ADAPTIVE_WEB_SEED=halvard-cve adaptive-web-world --socket /run/fictionet/sock/world.sock \
//!     --ca-dir /app/ca --state-dir /var/lib/fictionet --ready /run/fictionet/ready \
//!     [--observation <path>]
//! ```
//!
//! The rest of the setting comes from the environment:
//!
//! - `ADAPTIVE_WEB_SEED`: the seed's name, in `ADAPTIVE_WEB_SEEDS`
//!   (default `/app/seeds`), or a seed file's path. Required.
//! - `ADAPTIVE_WEB_GENERATOR`: `stub` (default), `openrouter`, `anthropic`,
//!   or `replay` to make nothing new.
//! - `ADAPTIVE_WEB_MODEL`: the model; each provider has a default.
//! - `ADAPTIVE_WEB_REASONING`: the reasoning effort sent to OpenRouter.
//! - `ADAPTIVE_WEB_PREFETCH`: pages to make ahead behind each new result
//!   list (default 3 with a model, else 0).
//! - `ADAPTIVE_WEB_STORE`: where stores live (default `/var/lib/adaptive-web`);
//!   each seed has its own directory there.
//! - `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`: the provider's key.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use adaptive_web_world::pages::model::{self, Https, Key, Model, Provider};
use adaptive_web_world::pages::store::Store;
use adaptive_web_world::pages::{Generator, Pages, Seed};
use adaptive_web_world::{Addresses, Ca, GATEWAY, serve, world_start};
use example_common::args::{args, secs};
use example_common::log::Log;
use serde_json::json;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("adaptive-web-world: {e}");
        std::process::exit(1);
    }
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// What makes new pages, as the environment names it.
enum Kind {
    Stub,
    Model(Provider, Key),
    Replay,
}

fn real_main() -> fictionet::Result {
    let args = args().map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);
    let started = SystemTime::now();

    // 1. The seed and the generator, checked before anything is written.
    let name = var("ADAPTIVE_WEB_SEED");
    if name.is_empty() {
        return Err(fictionet::Error::msg("ADAPTIVE_WEB_SEED is not set"));
    }
    let kind = match var("ADAPTIVE_WEB_GENERATOR").as_str() {
        "" | "stub" => Kind::Stub,
        "replay" => Kind::Replay,
        other => {
            let provider = Provider::parse(other).ok_or_else(|| {
                fictionet::Error::msg(format!(
                    "ADAPTIVE_WEB_GENERATOR must be stub, openrouter, anthropic or replay, not {other:?}"
                ))
            })?;
            Kind::Model(
                provider,
                Key::from_env(provider).map_err(fictionet::Error::msg)?,
            )
        }
    };
    let path = if Path::new(&name).is_file() {
        PathBuf::from(&name)
    } else {
        let seeds = std::env::var("ADAPTIVE_WEB_SEEDS").unwrap_or_else(|_| "/app/seeds".into());
        Path::new(&seeds).join(format!("{name}.md"))
    };
    // Replay serves the bytes the store captured, never the seed's files.
    let seed = match kind {
        Kind::Replay => {
            let text = std::fs::read_to_string(&path)?;
            let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or(&name);
            Seed::parse(name, &text, |_| Ok(Vec::new()))?
        }
        _ => Seed::load(&path)
            .map_err(|e| fictionet::Error::msg(format!("{}: {e}", path.display())))?,
    };
    let (model, reasoning) = (var("ADAPTIVE_WEB_MODEL"), var("ADAPTIVE_WEB_REASONING"));
    let identity = match &kind {
        Kind::Stub => Some(Generator::Stub.identity()),
        Kind::Model(provider, _) => Some(model::identity(*provider, &model, &reasoning)),
        Kind::Replay => None,
    };
    let prefetch = match (&kind, var("ADAPTIVE_WEB_PREFETCH").as_str()) {
        (Kind::Replay, _) => 0,
        (Kind::Model(..), "") => 3,
        (_, "") => 0,
        (_, n) => n.parse().map_err(|e| {
            fictionet::Error::msg(format!("ADAPTIVE_WEB_PREFETCH must be a count: {e}"))
        })?,
    };

    // 2. The store, and the addresses it remembers.
    let stores =
        std::env::var("ADAPTIVE_WEB_STORE").unwrap_or_else(|_| "/var/lib/adaptive-web".into());
    let root = Path::new(&stores).join(&seed.name);
    let (store, made_by) =
        Store::open(&root, &seed, identity.as_ref()).map_err(fictionet::Error::msg)?;
    let addresses = Arc::new(Addresses::new(
        seed.fixed_addresses(),
        Some(&root.join("addresses.jsonl")),
    )?);
    let start = world_start(&seed.date)?;

    // 3. Ground truth files.
    std::fs::create_dir_all(&args.state_dir)?;
    let log = Arc::new(Log::new(
        Box::new(std::fs::File::create(args.state_dir.join("log.jsonl"))?),
        &[],
        |s| s,
    ));

    // 4. The world. Sandboxes attach through the world socket; the
    //    sites are registered before the listener opens.
    let finalization = Arc::new(log.finalization(&args.state_dir)?);
    let shutdown = finalization.clone();
    let (attacher, attachments) = fictionet::attachments();
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let socket = args.socket.clone();
    let fixed: std::collections::BTreeMap<_, _> = seed
        .fixed_addresses()
        .into_iter()
        .map(|(host, (addr, why))| (host, json!({"addr": addr.to_string(), "why": why})))
        .collect();
    let state = json!({
        "seed": seed.name,
        "date": seed.date,
        "question": seed.question,
        "generator": match kind {
            Kind::Stub => "stub",
            Kind::Model(provider, _) => provider.name(),
            Kind::Replay => "replay",
        },
        "model": match kind {
            Kind::Replay => json!("replay"),
            _ => made_by["model"].clone(),
        },
        "prefetch": prefetch,
        "store": root.canonicalize()?.display().to_string(),
        "addresses": fixed,
        "fixed": seed.fixed.iter().map(|f| f.url.clone()).collect::<Vec<_>>(),
        "dns": GATEWAY.to_string(),
        "world_start": secs(start),
        "started": secs(started),
    });
    let seed_name = seed.name.clone();
    let state_path = args.state_dir.join("state.json");
    let ready = args.ready.clone();

    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.observation.as_ref(),
        Some(Arc::new(adaptive_web_world::events::LogObserver {
            log: log.clone(),
        })),
    )?;
    let result = fictionet::block_on(fictionet::run(options, move |fcx| async move {
        let generator = match kind {
            Kind::Stub => Some(Generator::Stub),
            Kind::Model(provider, key) => {
                let https = Arc::new(Https::new(&fcx, provider)?);
                Some(Generator::Model(Model::new(
                    provider, &model, &reasoning, key, https,
                )))
            }
            Kind::Replay => None,
        };
        let pages = Arc::new(Pages::open(seed, store, generator, prefetch));
        let ca = Arc::new(Ca::new(&fcx, &args.ca_dir, start)?);
        serve(&fcx, addresses, ca, pages, log, start, attachments)?;
        // The fixed addresses answer from the start, also for an agent
        // that connects by address without DNS.
        let _listening =
            fictionet::listen(fictionet::WorldSocket::UnixSocket(socket.into()), attacher)?;

        std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
        if let Some(dir) = ready.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&ready, seed_name.as_bytes())?;
        println!("fictionet world up: seed={seed_name}");

        // The network serves every sandbox from here on. The listener
        // lives as long as the world.
        shutdown.wait(&fcx).await
    }));
    finalization.acknowledge(result)?;
    // Keep the container available for the harness to read the finalized files.
    loop {
        std::thread::park();
    }
}
