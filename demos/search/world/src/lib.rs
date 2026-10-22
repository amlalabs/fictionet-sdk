//! The Search world's DNS, TLS, web pages and search engines.
//!
//! [`World`] joins public hostnames to certificates and an HTTP handler.
//! [`pages`] supplies copied WARC responses, model-written pages, or live
//! captures. Google, Bing and DuckDuckGo render results over the same index.
//! The world's clock comes from the brief's date; headers, pages and
//! certificates use it together. [`events`] writes the request log and
//! [`search`] projects those observations for the page.
//!
//! The demo app in `demos/search/app` adds the VM, guest credential model
//! gateway, provider sign-in relay and package mirror. The standalone
//! `web-world` binary accepts its configuration as JSON, followed by socket,
//! certificate, state and ready-file arguments.
//!
//! An in-process world can also serve an attached guest:
//!
//! ```no_run
//! use std::sync::Arc;
//! use web_world::{World, world_start};
//! use web_world::{events::LogObserver, search::Searches};
//! use web_world::pages::{Command, Seed};
//! use fictionet_extras::log::Log;
//! use fictionet::events::Fanout;
//!
//! # fn main() -> fictionet::Result {
//! let seed = Seed::builtin("web")?;
//! let start = world_start(&seed.date)?;
//! let searches = Arc::new(Searches::from_seed(&seed));
//! let log = Arc::new(Log::new(Box::new(std::io::stdout()), &[], |s| s));
//! let observer = Arc::new(Fanout::new(vec![
//!     searches.clone(),
//!     Arc::new(LogObserver { log: log.clone() }),
//! ]));
//! let options = fictionet::RunOptions::new(fictionet::Seed::from_u64(7))
//!     .observer(observer);
//! let output = log.clone();
//! fictionet::block_on(fictionet::run(options, |cx| async move {
//!     let world = World::new(&cx, seed, start)?;
//!     let root_pem = world.ca.cert_pem();
//!     let (attacher, attachments) = fictionet::attachments();
//!     world.serve(&cx, log.clone(), attachments)?;
//!     // Start a guest with root_pem and attacher here.
//!     let pages = &world.pages;
//!     let applied = pages.apply(&cx, Command::SetGeneration {
//!         generate: false,
//!         expected_revision: pages.generation().revision,
//!     }).unwrap();
//!     assert_eq!(applied.revision, 1);
//!     cx.cancelled().await;
//!     Ok(())
//! }))?;
//! output.finish()?;
//! # Ok(())
//! # }
//! ```

mod dns;
pub mod events;
mod files;
pub mod handler;
pub mod pages;
pub mod route;
pub mod search;

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

/// Top-level domains that never resolve on the internet: reserved by RFC
/// 2606 and 6761, used for mDNS, or used only inside private networks.
const NOT_ON_THE_INTERNET: [&str; 12] = [
    "test",
    "example",
    "invalid",
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "arpa",
];

/// Whether `name` gets a site. `Err` says why not, for the log.
///
/// A name gets a site when it could be a host on the internet: at least two
/// labels, each 1 to 63 letters, digits or hyphens, not starting or ending
/// with a hyphen, at most 253 characters in all, and a top-level domain of
/// two or more letters (or an `xn--` one) that is not reserved or private.
pub fn admit(name: &str) -> Result<(), &'static str> {
    if !name.contains('.') {
        return Err("single label");
    }
    if name.len() > 253 {
        return Err("too long");
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err("not a host name");
        }
    }
    let tld = labels[labels.len() - 1];
    if !(tld.starts_with("xn--")
        || (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())))
    {
        return Err("not a top-level domain");
    }
    if NOT_ON_THE_INTERNET.contains(&tld) {
        return Err("reserved or private top-level domain");
    }
    if pages::misspelled_host(&name.to_ascii_lowercase()) {
        return Err("unregistered host spelling");
    }
    Ok(())
}

pub use dns::Addresses;

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

/// The world's certificate authority, which signs a certificate for each
/// host at its first handshake.
pub struct Ca {
    issuer: fictionet::stdlib::services::ca::Ca,
    start: SystemTime,
}

impl Ca {
    /// Makes a seeded CA and writes its public certificate for the agent.
    pub fn new(fcx: &Cx, dir: &Path, start: SystemTime) -> fictionet::Result<Ca> {
        let ca = Self::in_memory(fcx, start)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), ca.cert_pem())?;
        Ok(ca)
    }

    /// Makes a seeded CA without writing files, for an in-process world.
    pub fn in_memory(fcx: &Cx, start: SystemTime) -> fictionet::Result<Ca> {
        Ok(Ca {
            issuer: fictionet::stdlib::services::ca::Ca::new(fcx, "Internet Security Root CA")?,
            start,
        })
    }

    /// Returns the public root certificate in PEM format for a guest to trust.
    pub fn cert_pem(&self) -> String {
        self.issuer.cert_pem()
    }

    /// A certificate for `host`: the host as CN and SAN, for server auth,
    /// issued 30 days before the world's date. The chain sent is the leaf,
    /// then the CA. Returns the TLS config and the validity, for the log.
    ///
    /// A client checks the certificate against its own clock, which is the
    /// host's, not the world's. So the validity covers both: it starts 30
    /// days before the earlier of the two, and lasts 90 days, or longer if
    /// that would end within 30 days of the later one.
    pub fn config(
        &self,
        fcx: &Cx,
        host: &str,
    ) -> fictionet::Result<(Arc<ServerConfig>, String, String)> {
        let world_now = time::OffsetDateTime::from(self.start + fcx.now().since_start());
        let host_now = time::OffsetDateTime::now_utc();
        let not_before = world_now.min(host_now) - time::Duration::days(30);
        let not_after = (not_before + time::Duration::days(90))
            .max(world_now.max(host_now) + time::Duration::days(30));
        let leaf = self.issuer.issue(
            fcx,
            &[host],
            fictionet::stdlib::protocols::x509::Validity {
                not_before: fictionet::stdlib::protocols::x509::Time::from_unix(
                    not_before.unix_timestamp(),
                )?,
                not_after: fictionet::stdlib::protocols::x509::Time::from_unix(
                    not_after.unix_timestamp(),
                )?,
            },
        )?;
        let config = leaf.server_config(fcx, self.start)?;
        let day = |t: time::OffsetDateTime| {
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        Ok((config, day(not_before), day(not_after)))
    }
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
    let names = addresses.fixed_names().to_vec();
    let world = fcx.clone();
    let site_for = move |host: &str| {
        if let Err(why) = admit(host) {
            world.emit("web", "refused", |event| {
                event
                    .summary(format_args!("{host}: {why}"))
                    .field("host", host)
                    .field("why", why)
            });
            return None;
        }
        let (addr, why) = match addresses.assign(host) {
            Ok(Some(assigned)) => assigned,
            Ok(None) => {
                world.emit("web", "refused", |event| {
                    event
                        .field("host", host)
                        .field("why", "address pool exhausted")
                });
                return None;
            }
            Err(e) => {
                let why = format!("cannot record the address: {e}");
                world.emit("web", "refused", |event| {
                    event.field("host", host).field("why", why.as_str())
                });
                log.fail(why);
                return None;
            }
        };
        world.emit("web", "site", |event| {
            event
                .summary(format_args!("{host} at {addr} ({why})"))
                .field("host", host)
                .field("site", pages.site_name(host))
                .field("addr", addr.to_string())
                .field("why", why)
        });
        if let Some(site) = forward(host) {
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
                            let (config, not_before, not_after) = ca
                                .config(fcx, &name)
                                .expect("a certificate for an admitted name");
                            fcx.emit("web", "cert", |event| {
                                event
                                    .summary(format_args!("a certificate for {name}"))
                                    .field("host", name.as_str())
                                    .field("not_before", not_before)
                                    .field("not_after", not_after)
                            });
                            config
                        })
                        .clone()
                })
                .into_host(host),
        )
    };
    let hosts: Vec<_> = names.iter().filter_map(|name| site_for(name)).collect();
    let mut net = fictionet::stdlib::world::net::Net::new()
        .ipv4_only()
        .resolve(site_for);
    for host in hosts {
        net = net.add_host(host);
    }
    net
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

#[cfg(test)]
mod spelling {
    #[test]
    fn misspelled_hosts_answer_nxdomain_over_dns() {
        use super::*;
        use fictionet::stdlib::{
            protocols::dns::{op::ResponseCode, rr::RecordType},
            world::sandbox::machine,
        };
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| async move {
                let seed = pages::Seed::builtin("web")?;
                let start = world_start(&seed.date)?;
                let world = World::new(&cx, seed, start)?;
                let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
                let (attacher, attachments) = fictionet::attachments();
                world.serve(&cx, log, attachments)?;
                let client = machine(&cx, attacher.attach("reader")?, Ipv4Addr::new(10, 0, 0, 2));
                for host in ["ww.bing.com", "gooogle.com", "WWW.GOOOGLE.COM"] {
                    let answer = client
                        .lookup(&cx, GATEWAY.into(), host, RecordType::A)
                        .await?;
                    assert_eq!(
                        answer.metadata.response_code,
                        ResponseCode::NXDomain,
                        "{host}"
                    );
                    assert!(answer.answers.is_empty());
                }
                let answer = client
                    .lookup(&cx, GATEWAY.into(), "www.bing.com", RecordType::A)
                    .await?;
                assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
                assert!(!answer.answers.is_empty());
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn close_spellings_of_known_hosts_do_not_resolve() {
        for host in ["ww.bing.com", "gooogle.com", "www.gooogle.com"] {
            assert!(super::admit(host).is_err(), "{host}");
        }
        assert!(super::admit("www.google.com").is_ok());
        assert!(super::admit("community.example.com").is_ok());
    }
}
