//! The FakeWiki world process. See the library ([`fakewiki_world`]) for
//! what it builds.
//!
//! ```text
//! fakewiki-world --socket /run/fictionet/sock/world.sock --ca-dir /app/ca \
//!     --backend /app/backend --backend-port 8080 \
//!     --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use fakewiki_world::content::Content;
use fakewiki_world::log::Log;
use fakewiki_world::{GATEWAY, args, issue_leaves, secs, serve, start_backend, watch_backend};
use serde_json::json;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("fakewiki-world: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> fictionet::Result {
    let args = args().map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);

    // 1. The content server. Its first line says it is listening, and
    //    carries the variant, the hosts and the documents for state.json.
    let started = SystemTime::now();
    let (backend, child) = start_backend(&args)?;
    watch_backend(child);
    let variant = backend["variant"].as_str().unwrap_or_default().to_owned();
    let mut hosts = HashMap::new();
    for (name, ip) in backend["hosts"]
        .as_object()
        .ok_or_else(|| fictionet::Error::msg("backend sent no hosts"))?
    {
        let ip: Ipv4Addr = ip
            .as_str()
            .ok_or_else(|| fictionet::Error::msg("bad host address"))?
            .parse()?;
        hosts.insert(name.clone(), ip);
    }

    // 2. Ground truth files.
    std::fs::create_dir_all(&args.state_dir)?;
    let log = Arc::new(Log::create(&args.state_dir.join("log.jsonl"))?);

    // 3. Certificates are issued inside the run.

    // 4. The world. Sandboxes attach through the world socket; the
    //    sites are registered before the listener opens.
    let (attacher, attachments) = fictionet::attachments();
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let socket = args.socket.clone();

    let content = Content::new(args.backend_port);
    let state = json!({
        "variant": variant,
        "hosts": hosts.keys().collect::<BTreeSet<_>>(),
        "dns": GATEWAY.to_string(),
        "documents": backend["documents"],
        "started": secs(started),
    });
    let state_path = args.state_dir.join("state.json");
    let ready = args.ready.clone();

    // The network itself needs no tokio; the content client does.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let leaves = issue_leaves(&fcx, &args.ca_dir, hosts.keys())?;
            serve(&fcx, &hosts, leaves, content, log, attachments)?;

            // Every site answers before the first sandbox can attach.
            let _listening =
                fictionet::listen(fictionet::WorldSocket::UnixSocket(socket.into()), attacher)?;

            std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
            if let Some(dir) = ready.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&ready, variant.as_bytes())?;
            println!("fictionet world up: variant={variant}");

            // The network serves every sandbox from here on. The listener
            // lives as long as the world.
            std::future::pending::<()>().await;
            Ok(())
        },
    ))
}
