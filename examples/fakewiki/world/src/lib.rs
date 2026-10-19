//! The FakeWiki world on Fictionet.
//!
//! ```text
//! fakewiki-world --socket /run/fictionet/sock/world.sock --ca-dir /app/ca \
//!     --backend /app/backend --backend-port 8080 \
//!     --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```
//!
//! - **Content**: [`content::Content`] renders embedded [`pages`] in a lab or
//!   forwards to Python's `backend.py`. Each request uses the world's variant.
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
pub mod pages;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use fictionet::Cx;
use fictionet::stdlib::web;

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

use crate::content::Content;

/// Builds the network: one site per FakeWiki host at its own address, with
/// its certificate. `leaves` holds each host's
/// certificate chain and key. Returns at once; the network runs in `fcx`'s
/// region.
pub fn serve(
    fcx: &Cx,
    hosts: &HashMap<String, Ipv4Addr>,
    leaves: HashMap<String, fictionet::stdlib::services::ca::Leaf>,
    content: Content,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    let now = SystemTime::now();
    let mut configs = HashMap::new();
    for (host, leaf) in leaves {
        configs.insert(host, leaf.server_config(fcx, now)?);
    }
    // The agent's sandbox has IPv6 off, and the sites keep their real IPv4 addresses only.
    let mut net = web::Sites::new(|_| None).into_net().ipv4_only();
    let mut names: Vec<_> = hosts.keys().collect();
    names.sort();
    for host in names {
        let addr = hosts[host];
        net = net.add_host(
            web::Site::handler(content.clone())
                .date(now)
                .at(addr)
                .tls(configs[host].clone())
                .into_host(host),
        )
    }
    net.start(fcx, attachments)?;
    Ok(())
}

/// Issues one leaf per host and returns the public root PEM with the leaves.
pub fn issue_leaves<'a>(
    fcx: &Cx,
    hosts: impl Iterator<Item = &'a String>,
) -> fictionet::Result<(
    String,
    HashMap<String, fictionet::stdlib::services::ca::Leaf>,
)> {
    use fictionet::stdlib::{
        protocols::x509::{Time, Validity},
        services::ca::Ca,
    };
    let ca = Ca::new(fcx, "Internet Security Root CA")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let mut hosts: Vec<_> = hosts.collect();
    hosts.sort();
    let leaves = hosts
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
        .collect::<fictionet::Result<_>>()?;
    Ok((ca.cert_pem(), leaves))
}
