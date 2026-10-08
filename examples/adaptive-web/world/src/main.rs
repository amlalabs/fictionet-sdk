//! The adaptive web's world process. See the library ([`adaptive_web_world`])
//! for what it builds.
//!
//! ```text
//! adaptive-web-world --socket /run/fictionet/sock/world.sock --ca-dir /app/ca \
//!     --backend /app/backend --backend-port 8080 \
//!     --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use adaptive_web_world::backend::Backend;
use adaptive_web_world::log::Log;
use adaptive_web_world::{
    Addresses, Ca, GATEWAY, args, fixed_addresses, look_up_all, secs, serve, start_backend,
    watch_backend, world_start,
};
use serde_json::json;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("adaptive-web-world: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> fictionet::Result {
    let args = args().map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);

    // 1. The Python backend. Its first line (`hello`) says it is listening,
    //    and carries the seed, the generator, the store and the fixed
    //    addresses.
    let started = SystemTime::now();
    let (hello, child) = start_backend(&args)?;
    watch_backend(child);
    let store = PathBuf::from(hello["store"].as_str().unwrap_or("/var/lib/adaptive-web"));

    // 2. Ground truth files.
    std::fs::create_dir_all(&args.state_dir)?;
    let log = Arc::new(Log::create(&args.state_dir.join("log.jsonl"))?);

    // 3. Addresses and certificates.
    let fixed = fixed_addresses(&hello)?;
    let pinned: Vec<String> = fixed.keys().cloned().collect();
    let addresses = Arc::new(Addresses::new(fixed, Some(&store.join("addresses.jsonl")))?);
    let start = world_start(hello["date"].as_str().unwrap_or_default())?;
    let ca = Arc::new(Ca::load(&args.ca_dir, start)?);

    // 4. The world. Sandboxes attach through the world socket; the world's
    //    own lookups use a clone of the same attacher.
    let (attacher, attachments) = fictionet::attachments();
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let socket = args.socket.clone();
    let backend = Backend::new(args.backend_port);
    let state = json!({
        "seed": hello["seed"],
        "date": hello["date"],
        "question": hello["question"],
        "generator": hello["generator"],
        "model": hello["model"],
        "prefetch": hello["prefetch"],
        "store": hello["store"],
        "addresses": hello["addresses"],
        "fixed": hello["fixed"],
        "dns": GATEWAY.to_string(),
        "world_start": secs(start),
        "started": secs(started),
    });
    let seed = hello["seed"].as_str().unwrap_or_default().to_owned();
    let state_path = args.state_dir.join("state.json");
    let ready = args.ready.clone();

    // The network itself needs no tokio; the backend's client does.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            serve(&fcx, addresses, ca, backend, log, start, attachments)?;
            // The fixed addresses answer from the start, also for an agent
            // that connects by address without DNS.
            look_up_all(&fcx, &attacher, &pinned).await?;
            let _listening =
                fictionet::listen(fictionet::WorldSocket::UnixSocket(socket.into()), attacher)?;

            std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
            if let Some(dir) = ready.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&ready, seed.as_bytes())?;
            println!("fictionet world up: seed={seed}");

            // The network serves every sandbox from here on. The listener
            // lives as long as the world.
            std::future::pending::<()>().await;
            Ok(())
        },
    ))
}
