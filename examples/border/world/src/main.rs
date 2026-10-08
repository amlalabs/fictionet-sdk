//! The Border world process.
//!
//! ```text
//! border-world [--socket /run/relay/relay.sock] [--ca-dir /app/ca]
//!     [--state-dir /var/lib/fictionet] [--ready /run/fictionet/ready]
//!     [--subnet 10.0.0.0/24]
//! border-world make-ca DIR     # the lab CA: ca.pem, ca.key
//! border-world make-pki DIR    # the home chain: ca.pem, ca.key (intermediate), root.pem
//! border-world credentials     # the agent's credentials file, on stdout
//! ```
//!
//! The variant and the task come from the environment, as Compose
//! interpolates them from each sample's metadata: `BORDER_VARIANT`
//! (`legitimate` or `hijack`; the world refuses to start without one) and
//! `BORDER_TASK` (`read`, `login` or `pay`; `read` when empty).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use border_world::certs::{self, Ca};
use border_world::log::Log;
use border_world::scenario::{parse_prefix, Prefix, Scenario, Task, Variant};

struct Args {
    socket: String,
    ca_dir: PathBuf,
    state_dir: PathBuf,
    ready: PathBuf,
    subnet: Prefix,
}

fn args(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut a = Args {
        socket: "/run/relay/relay.sock".into(),
        ca_dir: "/app/ca".into(),
        state_dir: "/var/lib/fictionet".into(),
        ready: "/run/fictionet/ready".into(),
        subnet: parse_prefix("10.0.0.0/24").expect("a prefix"),
    };
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => a.socket = value,
            "--ca-dir" => a.ca_dir = value.into(),
            "--state-dir" => a.state_dir = value.into(),
            "--ready" => a.ready = value.into(),
            "--subnet" => a.subnet = parse_prefix(&value).ok_or(format!("--subnet: not a prefix: {value}"))?,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(a)
}

fn main() {
    let mut argv = std::env::args().skip(1).peekable();
    let result = match argv.peek().map(String::as_str) {
        Some("make-ca") => argv.nth(1).ok_or_else(|| fictionet::Error::msg("make-ca needs a directory")).and_then(|d| certs::make_ca(Path::new(&d))),
        Some("make-pki") => argv.nth(1).ok_or_else(|| fictionet::Error::msg("make-pki needs a directory")).and_then(|d| certs::make_pki(Path::new(&d))),
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
    let args = args(argv).map_err(fictionet::Error::msg)?;
    let _ = std::fs::remove_file(&args.ready);
    let variant = std::env::var("BORDER_VARIANT").unwrap_or_default();
    let variant = Variant::parse(&variant)
        .ok_or_else(|| fictionet::Error::msg(format!("BORDER_VARIANT must be legitimate or hijack, not {variant:?}")))?;
    let task = std::env::var("BORDER_TASK").unwrap_or_default();
    let task = if task.is_empty() { Task::Read } else { Task::parse(&task).ok_or_else(|| fictionet::Error::msg(format!("BORDER_TASK must be read, login or pay, not {task:?}")))? };
    let scenario = Arc::new(Scenario::new(variant, task, args.subnet));

    let world_ca = Ca::load(&args.ca_dir)?;
    let ids = border_world::identities(&scenario, &world_ca)?;

    std::fs::create_dir_all(&args.state_dir)?;
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(args.state_dir.join("log.jsonl"))?;
    let log = Log::start(Box::new(std::io::BufWriter::new(file)), scenario.clone());
    let state = border_world::state(&scenario);
    let state_path = args.state_dir.join("state.json");
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }

    let (attacher, attachments) = fictionet::attachments();
    fictionet::block_on(fictionet::run(move |fcx| async move {
        let lookups = border_world::start(&fcx, scenario.clone(), ids, log, attachments)?;
        border_world::look_up_all(&fcx, &lookups, &scenario).await?;
        let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(args.socket.clone().into()), attacher)?;
        std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
        if let Some(dir) = args.ready.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&args.ready, scenario.variant.as_str())?;
        println!("border world up: variant={} task={}", scenario.variant.as_str(), scenario.task.as_str());
        // The network serves every sandbox from here on. The listener lives
        // as long as the world.
        std::future::pending::<()>().await;
        Ok(())
    }))
}
