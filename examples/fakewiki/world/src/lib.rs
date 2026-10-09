//! The FakeWiki world on Fictionet.
//!
//! ```text
//! fakewiki-world --socket /run/fictionet/sock/world.sock --ca-dir /app/ca \
//!     --backend /app/backend --backend-port 8080 \
//!     --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```
//!
//! - **Content**: FakeWiki's Python `sites.py`, unchanged, runs as a small
//!   HTTP server on 127.0.0.1 (`backend.py`, started here). Every FakeWiki
//!   site's handler forwards to it ([`content`]).
//! - **Network**: `web::Sites`. Every FakeWiki host is pinned to its
//!   FakeWiki address with `Site::at`; every other name gets NXDOMAIN, and
//!   every other address "host unreachable".
//! - **TLS**: one leaf certificate per host, made here at start with
//!   the seeded CA helper. The world writes its public root at startup.
//! - **Ground truth**: `state.json` and `log.jsonl` in `--state-dir`, in
//!   main.py's formats, and the ready file. The log is written from the
//!   network's events ([`events`]).

pub mod content;
pub mod events;
#[path = "../../../common/log.rs"]
pub mod log;

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fictionet::Cx;
use fictionet::stdlib::web;

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
use serde_json::Value;

use crate::content::Content;
use crate::log::Log;

/// The world's command line.
pub struct Args {
    pub socket: String,
    pub ca_dir: PathBuf,
    pub backend: PathBuf,
    pub backend_port: u16,
    pub state_dir: PathBuf,
    pub ready: PathBuf,
}

/// Reads the command line.
pub fn args() -> Result<Args, String> {
    let mut a = Args {
        socket: "/run/fictionet/sock/world.sock".into(),
        ca_dir: "/app/ca".into(),
        backend: "/app/backend".into(),
        backend_port: 8080,
        state_dir: "/var/lib/fictionet".into(),
        ready: "/run/fictionet/ready".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => a.socket = value,
            "--ca-dir" => a.ca_dir = value.into(),
            "--backend" => a.backend = value.into(),
            "--backend-port" => {
                a.backend_port = value.parse().map_err(|e| format!("--backend-port: {e}"))?
            }
            "--state-dir" => a.state_dir = value.into(),
            "--ready" => a.ready = value.into(),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(a)
}

/// Builds the network: one site per FakeWiki host at its own address, with
/// its certificate, every request logged. `leaves` holds each host's
/// certificate chain and key. Returns at once; the network runs in `fcx`'s
/// region.
pub fn serve(
    fcx: &Cx,
    hosts: &HashMap<String, Ipv4Addr>,
    leaves: HashMap<String, fictionet::stdlib::ca::Leaf>,
    content: Content,
    log: Arc<Log>,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    let mut configs = HashMap::new();
    for (host, leaf) in leaves {
        configs.insert(host, leaf.server_config(fcx, SystemTime::now())?);
    }
    events::log_to(fcx, hosts.clone(), log);
    // The agent's sandbox has IPv6 off, and the sites keep their real IPv4 addresses only.
    let mut net = web::Sites::new(|_| None).into_net().ipv4_only();
    let mut names: Vec<_> = hosts.keys().collect();
    names.sort();
    for host in names {
        let addr = hosts[host];
        net = net.add_host(
            web::Site::new(content.clone())
                .at(addr)
                .tls(configs[host].clone())
                .into_host(host),
        )
    }
    net.start(fcx, attachments)?;
    Ok(())
}

/// Seconds since the epoch.
pub fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Starts backend.py and waits for its first line. Returns that line and
/// the running backend. [`watch_backend`] makes the world exit with it.
pub fn start_backend(args: &Args) -> fictionet::Result<(Value, std::process::Child)> {
    let mut child = Command::new("python3")
        .arg("backend.py")
        .arg(args.backend_port.to_string())
        .current_dir(&args.backend)
        .env("PYTHONUNBUFFERED", "1")
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| fictionet::Error::msg(format!("cannot start backend.py: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fictionet::Error::msg("no backend stdout"))?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    if line.trim().is_empty() {
        let status = child.wait()?;
        return Err(fictionet::Error::msg(format!(
            "backend.py exited before it was ready ({status})"
        )));
    }
    Ok((serde_json::from_str(&line)?, child))
}

/// If the backend exits, the world exits too, so the container stops
/// instead of serving errors.
pub fn watch_backend(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let status = child.wait();
        eprintln!("fakewiki-world: backend.py exited ({status:?}); stopping");
        std::process::exit(1);
    });
}

/// Issues one leaf per host and writes the public root for the agent.
pub fn issue_leaves<'a>(
    fcx: &Cx,
    ca_dir: &Path,
    hosts: impl Iterator<Item = &'a String>,
) -> fictionet::Result<HashMap<String, fictionet::stdlib::ca::Leaf>> {
    use fictionet::stdlib::{
        ca::Ca,
        x509::{Time, Validity},
    };
    let ca = Ca::new(fcx, "Internet Security Root CA")?;
    std::fs::create_dir_all(ca_dir)?;
    std::fs::write(ca_dir.join("ca.pem"), ca.cert_pem())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut hosts: Vec<_> = hosts.collect();
    hosts.sort();
    hosts
        .into_iter()
        .map(|host| {
            Ok((
                host.clone(),
                ca.issue(
                    fcx,
                    &[host],
                    Validity {
                        not_before: Time::from_unix(now - 86400)?,
                        not_after: Time::from_unix(now + 90 * 86400)?,
                    },
                )?,
            ))
        })
        .collect()
}
