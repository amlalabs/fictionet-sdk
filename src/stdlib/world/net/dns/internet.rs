//! The internet's DNS servers as hosts: the root servers at their real
//! addresses, and the root zone they serve.
//!
//! [`root_servers`] returns hosts at the addresses real clients know, so
//! a guest that asks `198.41.0.4` directly reaches one, and
//! [`server_host`] does the same for any other [`NameServer`]. What runs
//! on them, and how far away they are, is the world's
//! choice: any [`Authority`](fictionet::stdlib::services::dns::authority::Authority)
//! may run there, such as [`Zones`](fictionet::stdlib::services::dns::authority::Zones)
//! over the zone from [`root_zone`].
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::services::dns::authority::{ServerConfig, Zones};
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Authoritative;
//! # use fictionet::stdlib::world::net::dns::internet;
//! # async fn world(fcx: Cx, attachments: Attachments, root: &str) -> Result {
//! let root = Arc::new(internet::root_zone(root)?);
//! Net::new(fictionet::stdlib::world::net::Pools {
//!     v4: Some("192.0.2.0/24".parse()?),
//!     v6: Some("2001:db8:1::/64".parse()?),
//! })
//!     .hosts(internet::root_servers(|_, host| {
//!         let server = ServerConfig::generic();
//!         host.program(Authoritative::new(Zones::new(vec![root.clone()]), server))
//!     }))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```

use fictionet::stdlib::protocols::dns::rr::Name;
use fictionet::stdlib::services::dns::zone::{Zone, ZoneError};

pub use fictionet::stdlib::services::dns::resolver::{NameServer, ROOT_SERVERS, root_hints};

use super::super::Host;

/// A host at both of `server`'s addresses, named for it, with nothing on
/// it yet.
pub fn server_host(server: &NameServer) -> Host {
    Host::new(server.host.trim_end_matches('.'))
        .at(server.v4)
        .at(server.v6)
}

/// One host per root letter of [`ROOT_SERVERS`], at both of its
/// addresses, finished by `build`: the letter, and its [`server_host`].
/// `build` gives it its program, usually an
/// [`Authoritative`](super::Authoritative) with the
/// front the world gives that letter, and any [`Host::delay`].
pub fn root_servers(build: impl Fn(&NameServer, Host) -> Host) -> Vec<Host> {
    ROOT_SERVERS
        .iter()
        .map(|server| build(server, server_host(server)))
        .collect()
}

/// The root zone in master file `text`, such as IANA's
/// `https://www.internic.net/domain/root.zone`, checked as any zone is
/// (RFC 1035 §5). Text whose SOA is not at the root is another zone, and
/// gives [`ZoneError::OutOfZone`] for its apex.
// `ZoneError` is large; this returns it as `Zone::from_master` does.
#[allow(clippy::result_large_err)]
pub fn root_zone(text: &str) -> Result<Zone, ZoneError> {
    let zone = Zone::from_master(text, Some(Name::root()))?;
    if !zone.apex().is_root() {
        return Err(ZoneError::OutOfZone {
            owner: zone.apex().clone(),
        });
    }
    Ok(zone)
}
