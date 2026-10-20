//! The Border world process.
//!
//! ```text
//! border-world JSON [--socket /run/relay/relay.sock] [--ca-dir /app/ca]
//!     [--state-dir /var/lib/fictionet] [--ready /run/fictionet/ready]
//!     [--subnet 10.0.0.0/24] [--observation <path>]
//! border-world make-ca DIR     # the lab CA: ca.pem, ca.key
//! border-world make-pki DIR    # the home chain: ca.pem, ca.key (intermediate), root.pem
//! border-world credentials     # the agent's credentials file, on stdout
//! ```
//!
//! The first argument is JSON with `variant` and optional `task`.

use std::path::Path;
use std::sync::Arc;

use border_world::certs;
use border_world::log::Log;
use border_world::scenario::{Prefix, Scenario, Task, Variant, parse_prefix};
use example_common::args::{Args, configuration, unknown};
use example_common::names::{name, parse};

/// The shared command line, and the subnet the world serves.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    variant: String,
    task: Option<String>,
}

fn args(mut flags: impl Iterator<Item = String>) -> Result<(Args, Prefix, Variant, Task), String> {
    let config: Configuration = configuration(&mut flags)?;
    let variant =
        parse::<Variant>(&config.variant).ok_or("variant must be legitimate or hijack")?;
    let task =
        parse(config.task.as_deref().unwrap_or("read")).ok_or("task must be read, login or pay")?;
    let mut subnet = parse_prefix("10.0.0.0/24").expect("a prefix");
    let args = Args {
        socket: "/run/relay/relay.sock".into(),
        ..Args::default()
    }
    .read(flags, |flag, value| match flag {
        "--subnet" => {
            subnet = parse_prefix(&value).ok_or(format!("--subnet: not a prefix: {value}"))?;
            Ok(())
        }
        _ => unknown(flag, value),
    })?;
    Ok((args, subnet, variant, task))
}

fn main() {
    let mut argv = std::env::args().skip(1).peekable();
    let result = match argv.peek().map(String::as_str) {
        Some("make-ca") => argv
            .nth(1)
            .ok_or_else(|| fictionet::Error::msg("make-ca needs a directory"))
            .and_then(|d| {
                fictionet::block_on(fictionet::lab(
                    fictionet::RunOptions::new(fictionet::Seed::random()),
                    move |fcx| async move { certs::make_ca(&fcx, Path::new(&d)) },
                ))
            }),
        Some("make-pki") => argv
            .nth(1)
            .ok_or_else(|| fictionet::Error::msg("make-pki needs a directory"))
            .and_then(|d| {
                fictionet::block_on(fictionet::lab(
                    fictionet::RunOptions::new(fictionet::Seed::random()),
                    move |fcx| async move { certs::make_pki(&fcx, Path::new(&d)) },
                ))
            }),
        Some("credentials") => {
            print!("{}", border_world::bank::credentials_file());
            Ok(())
        }
        _ => serve(argv),
    };
    if let Err(e) = result {
        eprintln!("border-world: {e}");
        std::process::exit(1);
    }
}

fn serve(argv: impl Iterator<Item = String>) -> fictionet::Result {
    let (args, subnet, variant, task) = args(argv).map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);
    let scenario = Arc::new(Scenario::new(variant, task, subnet));

    let world_ca = certs::load(&args.ca_dir)?;

    std::fs::create_dir_all(&args.state_dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(args.state_dir.join("log.jsonl"))?;
    let log = Log::start(Box::new(std::io::BufWriter::new(file)), scenario.clone());
    let state = border_world::state(&scenario);
    let state_path = args.state_dir.join("state.json");
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }

    let finalization = Arc::new(log.finalization(&args.state_dir)?);
    let shutdown = finalization.clone();
    let (attacher, attachments) = fictionet::attachments();
    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.observation.clone(),
        Some(Arc::new(log.clone())),
    )?;
    let result = fictionet::block_on(fictionet::run(options, move |fcx| async move {
        let ids = border_world::identities(&fcx, &world_ca)?;
        log.attach(&fcx);
        let _routing = border_world::start(&fcx, scenario.clone(), ids, attachments)?;
        let _listening = fictionet::listen(
            fictionet::WorldSocket::UnixSocket(args.socket.clone().into()),
            attacher,
        )?;
        std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
        if let Some(dir) = args.ready.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let variant = name(&scenario.variant);
        std::fs::write(&args.ready, &variant)?;
        println!(
            "border world up: variant={variant} task={}",
            name(&scenario.task)
        );
        // The network serves every sandbox from here on. The listener lives
        // as long as the world.
        shutdown.wait(&fcx).await
    }));
    finalization.acknowledge(result)?;
    // Keep the container available for the harness to read the finalized files.
    loop {
        std::thread::park();
    }
}
