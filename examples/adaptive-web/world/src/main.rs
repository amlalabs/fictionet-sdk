//! The adaptive web's world process. See the library ([`adaptive_web_world`])
//! for what it builds.
//!
//! The first argument is JSON with `seed` and optional `seeds`, `generator`,
//! `model`, `reasoning`, `prefetch`, and `store`.
//! Only provider API keys come from the environment.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use adaptive_web_world::pages::model::{self, Https, Key, Model};
use adaptive_web_world::pages::store::Store;
use adaptive_web_world::pages::{GeneratorKind, Maker, Pages, Seed};
use adaptive_web_world::{Addresses, Ca, GATEWAY, serve, world_start};
use example_common::args::{Args, configuration, secs, unknown};
use example_common::log::Log;
use example_common::names;
use serde_json::json;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("adaptive-web-world: {e}");
        std::process::exit(1);
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    seed: String,
    #[serde(default)]
    generator: String,
    seeds: Option<String>,
    store: Option<String>,
    #[serde(default)]
    model: String,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    prefetch: String,
}

fn real_main() -> fictionet::Result {
    let mut argv = std::env::args().skip(1);
    let Configuration {
        seed: name,
        generator,
        seeds,
        store,
        model,
        reasoning,
        prefetch,
    } = configuration(&mut argv).map_err(fictionet::Error::msg)?;
    let seeds = seeds.unwrap_or_else(|| "/app/seeds".into());
    let stores = store.unwrap_or_else(|| "/var/lib/adaptive-web".into());
    let args = Args::default()
        .read(argv, unknown)
        .map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);
    let started = SystemTime::now();

    // 1. The seed and the generator, checked before anything is written.
    if name.is_empty() {
        return Err(fictionet::Error::msg("seed is required"));
    }
    let kind = match generator.as_str() {
        "" => GeneratorKind::default(),
        text => names::parse(text).ok_or_else(|| {
            let kinds: Vec<_> = GeneratorKind::ALL.iter().map(names::name).collect();
            fictionet::Error::msg(format!(
                "generator must be one of {}, not {text:?}",
                kinds.join(", ")
            ))
        })?,
    };
    let key = match kind {
        GeneratorKind::Model(provider) => {
            Some(Key::from_env(provider).map_err(fictionet::Error::msg)?)
        }
        GeneratorKind::Stub | GeneratorKind::Replay => None,
    };
    let path = if Path::new(&name).is_file() {
        PathBuf::from(&name)
    } else {
        Path::new(&seeds).join(format!("{name}.md"))
    };
    // Replay serves the bytes the store captured, never the seed's files.
    let seed = match kind {
        GeneratorKind::Replay => {
            let text = std::fs::read_to_string(&path)?;
            let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or(&name);
            Seed::parse(name, &text, |_| Ok(Vec::new()))?
        }
        _ => Seed::load(&path)
            .map_err(|e| fictionet::Error::msg(format!("{}: {e}", path.display())))?,
    };
    let identity = match kind {
        GeneratorKind::Stub => Some(Maker::Stub.identity()),
        GeneratorKind::Model(provider) => Some(model::identity(provider, &model, &reasoning)),
        GeneratorKind::Replay => None,
    };
    let prefetch = match (kind, prefetch.as_str()) {
        (GeneratorKind::Replay, _) => 0,
        (GeneratorKind::Model(_), "") => 3,
        (_, "") => 0,
        (_, n) => n
            .parse()
            .map_err(|e| fictionet::Error::msg(format!("prefetch must be a count: {e}")))?,
    };

    // 2. The store, and the addresses it remembers.
    let root = Path::new(&stores).join(&seed.name);
    let (store, _) = Store::open(&root, &seed, identity.as_ref()).map_err(fictionet::Error::msg)?;
    let addresses = Arc::new(Addresses::new(seed.fixed_addresses(), Some(&root))?);
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
    let store_path = root.canonicalize()?.display().to_string();
    let state_path = args.state_dir.join("state.json");
    let ready = args.ready.clone();

    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.observation.clone(),
        Some(Arc::new(adaptive_web_world::events::LogObserver {
            log: log.clone(),
        })),
    )?;
    let result = fictionet::block_on(fictionet::run(options, move |fcx| async move {
        let maker = match (kind, key) {
            (GeneratorKind::Stub, _) => Some(Maker::Stub),
            (GeneratorKind::Model(provider), Some(key)) => {
                let https = Arc::new(Https::new(&fcx, provider)?);
                Some(Maker::Model(Model::new(
                    provider, &model, &reasoning, key, https,
                )))
            }
            (GeneratorKind::Model(_), None) => unreachable!("a model's key is read above"),
            (GeneratorKind::Replay, _) => None,
        };
        let pages = Arc::new(Pages::open(seed, store, maker, prefetch));
        let seed = pages.seed();
        let fixed: std::collections::BTreeMap<_, _> = seed
            .fixed_addresses()
            .into_iter()
            .map(|(host, (addr, why))| (host, json!({"addr": addr.to_string(), "why": why})))
            .collect();
        let state = json!({
            "seed": seed.name,
            "date": seed.date,
            "question": seed.question,
            "generator": pages.generator_kind(),
            "model": pages.model(),
            "prefetch": pages.prefetch(),
            "store": store_path,
            "addresses": fixed,
            "fixed": seed.fixed.iter().map(|f| f.url.clone()).collect::<Vec<_>>(),
            "dns": GATEWAY.to_string(),
            "world_start": secs(start),
            "started": secs(started),
        });
        let seed_name = seed.name.clone();
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
