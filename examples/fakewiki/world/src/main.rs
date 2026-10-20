//! The FakeWiki world process. See the library ([`fakewiki_world`]) for
//! what it builds.
//!
//! ```text
//! fakewiki-world '{"variant":"altered_one"}' --socket /run/fictionet/sock/world.sock \
//!     --ca-dir /app/ca --state-dir /var/lib/fictionet --ready /run/fictionet/ready \
//!     [--observation <path>]
//! ```

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use example_common::args::{Args, secs, unknown};
use example_common::log::Log;
use fakewiki_world::content::Content;
use fakewiki_world::pages::{self, Variant};
use fakewiki_world::tamper::Tampering;
use fakewiki_world::{GATEWAY, issue_leaves, serve};
use serde_json::json;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("fakewiki-world: {e}");
        std::process::exit(1);
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    variant: String,
}

fn real_main() -> fictionet::Result {
    let mut argv = std::env::args().skip(1);
    let Configuration { variant } =
        example_common::args::configuration(&mut argv).map_err(fictionet::Error::msg)?;
    let args = Args::default()
        .read(argv, unknown)
        .map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);

    // 1. The variant, from the sample's metadata.
    let started = SystemTime::now();
    let variant: Variant = variant.parse().map_err(|_| {
        fictionet::Error::msg(format!(
            "variant must be control, altered_one or altered_all, not {variant:?}"
        ))
    })?;
    let hosts = pages::host_ips();
    let documents: Vec<_> = pages::documents(variant)
        .into_iter()
        .map(|d| json!({"url": d.url, "topic": d.topic, "source": d.source, "stance": d.stance}))
        .collect();

    // 2. Ground truth files.
    std::fs::create_dir_all(&args.state_dir)?;
    let log = Arc::new(Log::new(
        Box::new(std::fs::File::create(args.state_dir.join("log.jsonl"))?),
        &[],
        |s| s,
    ));

    // 3. Certificates are issued inside the run.

    // 4. The world. Sandboxes attach through the world socket; the
    //    sites are registered before the listener opens.
    let finalization = Arc::new(log.finalization(&args.state_dir)?);
    let shutdown = finalization.clone();
    let (attacher, attachments) = fictionet::attachments();
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let socket = args.socket.clone();

    let state = json!({
        "variant": variant.as_str(),
        "hosts": hosts.keys().collect::<BTreeSet<_>>(),
        "dns": GATEWAY.to_string(),
        "documents": documents,
        "started": secs(started),
    });
    let state_path = args.state_dir.join("state.json");
    let ready = args.ready.clone();

    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.observation.clone(),
        Some(Arc::new(fakewiki_world::events::LogObserver {
            log: log.clone(),
            hosts: hosts.clone(),
        })),
    )?;
    let result = fictionet::block_on(fictionet::run(options, move |fcx| async move {
        let content = Content::new(Tampering::from(variant));
        let (root, leaves) = issue_leaves(&fcx, hosts.keys())?;
        std::fs::create_dir_all(&args.ca_dir)?;
        std::fs::write(args.ca_dir.join("ca.pem"), root)?;
        log.attach(&fcx);
        serve(&fcx, &hosts, leaves, content, attachments)?;

        // Every site answers before the first sandbox can attach.
        let _listening =
            fictionet::listen(fictionet::WorldSocket::UnixSocket(socket.into()), attacher)?;

        std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
        if let Some(dir) = ready.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&ready, variant.as_str())?;
        println!("fictionet world up: variant={}", variant.as_str());

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
