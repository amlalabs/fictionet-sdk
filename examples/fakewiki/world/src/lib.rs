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
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fictionet::Cx;
use fictionet::stdlib::web;

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
use serde_json::Value;

use crate::content::Content;
use crate::log::Log;

#[path = "../../../common/backend_process.rs"]
mod backend_process;
pub use backend_process::{Args, args, secs, start_backend, watch_backend};

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
