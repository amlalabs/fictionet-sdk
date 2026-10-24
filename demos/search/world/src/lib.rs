//! The Search world's DNS, TLS, web pages and search engines.
//!
//! [`World`] joins public hostnames to certificates and an HTTP handler.
//! [`pages`] supplies copied WARC responses, model-written pages, or live
//! captures. Google, Bing and DuckDuckGo render results over the same index.
//! The world's clock comes from the brief's date; headers, pages and
//! certificates use it together. [`observation`] defines this world's typed
//! facts; the demo app projects them into its page.
//!
//! The demo app in `demos/search/app` adds the VM, guest credential model
//! gateway, provider sign-in relay and package mirror. The standalone
//! `web-world` binary accepts its configuration as JSON, followed by socket,
//! certificate, state and ready-file arguments.
//!

mod dns;
mod files;
pub mod handler;
pub mod observation;
pub mod pages;
pub mod route;
pub mod search;
mod tls;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use fictionet::Cx;
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web;
use serde::{Deserialize, Serialize};

use fictionet_extras::log::Log;
use files::{Appended, FileLock};
use pages::Pages;

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

pub use dns::{Addresses, admit};
pub use tls::Ca;

/// The world's date at the start of the run: the seed's day (`YYYY-MM-DD`,
/// UTC) at the host's time of day, so the clock reads like an ordinary day.
pub fn world_start(date: &str) -> fictionet::Result<SystemTime> {
    let bad = |why: String| {
        fictionet::Error::msg(format!(
            "the seed's date {date:?} is not a YYYY-MM-DD date: {why}"
        ))
    };
    let parts: Vec<&str> = date.split('-').collect();
    let [y, m, d] = parts[..] else {
        return Err(bad("it does not have three parts".into()));
    };
    let number = |p: &str| p.parse::<u16>().map_err(|e| bad(e.to_string()));
    let byte = |p: &str| u8::try_from(number(p)?).map_err(|e| bad(e.to_string()));
    let month = time::Month::try_from(byte(m)?).map_err(|e| bad(e.to_string()))?;
    let day = time::Date::from_calendar_date(number(y)? as i32, month, byte(d)?)
        .map_err(|e| bad(e.to_string()))?;
    let now = time::OffsetDateTime::now_utc();
    Ok(day.with_time(now.time()).assume_utc().into())
}

/// Builds the network: a site for every name [`admit`] lets in, at its
/// address from `addresses`, with a certificate from `ca` made at its first
/// handshake, every request answered by `pages` and logged, and every
/// response dated from `start`, the world's date at the start of the run.
/// Returns at once; the network runs in `fcx`'s region.
pub fn serve(
    fcx: &Cx,
    addresses: Arc<Addresses>,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    log: Arc<Log>,
    start: SystemTime,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    net(fcx, addresses, ca, pages, log, start, |_| None).start(fcx, attachments)
}

/// Builds an unstarted network, giving the caller first choice of each name.
/// Claimed names use assigned addresses and site events with their own TLS.
pub fn net(
    fcx: &Cx,
    addresses: Arc<Addresses>,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    log: Arc<Log>,
    start: SystemTime,
    forward: impl Fn(&str) -> Option<fictionet::stdlib::world::net::Host> + Send + Sync + 'static,
) -> fictionet::stdlib::world::net::Net {
    let handler = handler::Handler::new(fcx, pages.clone());
    log.attach(fcx);
    let world = fcx.clone();
    let refused_pages = pages.clone();
    let site_for = move |host: &str| {
        let name: crate::observation::HostName = host.parse().ok()?;
        let resolved = |address| {
            refused_pages.report(
                &world,
                crate::observation::SearchObs::Resolved {
                    name: name.clone(),
                    address,
                },
            );
        };
        if admit(host).is_err() {
            resolved(None);
            return None;
        }
        let forwarded = forward(host);
        if forwarded.is_none() && !refused_pages.serves_host(host) {
            resolved(None);
            return None;
        }
        // Live pages come from the internet, so its DNS decides: a name
        // with no address there has none here either. The host's resolver
        // answers from its cache or with one query, and the answer is kept
        // for the run.
        if forwarded.is_none() && refused_pages.live_only() && !on_the_internet(host) {
            resolved(None);
            return None;
        }
        let (addr, _) = match addresses.assign(host) {
            Ok(Some(assigned)) => assigned,
            Ok(None) => {
                resolved(None);
                return None;
            }
            Err(error) => {
                resolved(None);
                log.fail(format!("cannot record the address: {error}"));
                return None;
            }
        };
        resolved(Some(addr.into()));
        if let Some(site) = forwarded {
            return Some(site.at(addr));
        }
        let (ca, name) = (ca.clone(), host.to_owned());
        let config: Arc<OnceLock<Arc<ServerConfig>>> = Arc::new(OnceLock::new());
        Some(
            web::Site::new(handler.clone())
                .date(start)
                .at(addr)
                .tls_with(move |fcx| {
                    config
                        .get_or_init(|| {
                            let (config, _, _) = ca
                                .config(fcx, &name)
                                .expect("a certificate for an admitted name");
                            config
                        })
                        .clone()
                })
                .into_host(host),
        )
    };
    let report_cx = fcx.clone();
    let report_pages = pages.clone();
    fictionet::stdlib::world::net::Net::new()
        .ipv4_only()
        .drop_unrouted()
        .resolve(site_for)
        .on_unreachable(move |unreachable| {
            report_pages.report(
                &report_cx,
                crate::observation::SearchObs::NoRoute {
                    from: unreachable.from,
                    to: unreachable.to,
                },
            );
        })
}

/// Whether the internet's DNS gives `host` an address.
fn on_the_internet(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    (host, 443)
        .to_socket_addrs()
        .is_ok_and(|mut addresses| addresses.next().is_some())
}

/// A world kept in memory, made from one seed: a new CA, the seed's fixed
/// addresses and its fixed and stored pages, dated from `start`,
/// usually [`world_start`] of the seed's date. The executable keeps a store
/// and may use a model instead.
pub struct World {
    pub ca: Arc<Ca>,
    pub addresses: Arc<Addresses>,
    pub pages: Arc<Pages>,
    pub start: SystemTime,
}

impl World {
    pub fn new(fcx: &Cx, seed: pages::Seed, start: SystemTime) -> fictionet::Result<World> {
        Ok(World {
            ca: Arc::new(Ca::in_memory(fcx, start)?),
            addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
            pages: Arc::new(Pages::new(seed)),
            start,
        })
    }

    /// The world's unstarted network, as [`net`] builds it.
    pub fn net(
        &self,
        fcx: &Cx,
        log: Arc<Log>,
        forward: impl Fn(&str) -> Option<fictionet::stdlib::world::net::Host> + Send + Sync + 'static,
    ) -> fictionet::stdlib::world::net::Net {
        net(
            fcx,
            self.addresses.clone(),
            self.ca.clone(),
            self.pages.clone(),
            log,
            self.start,
            forward,
        )
    }

    /// Starts the world's network, as [`serve`] does.
    pub fn serve(
        &self,
        fcx: &Cx,
        log: Arc<Log>,
        attachments: fictionet::Attachments,
    ) -> fictionet::Result {
        self.net(fcx, log, |_| None).start(fcx, attachments)
    }
}
