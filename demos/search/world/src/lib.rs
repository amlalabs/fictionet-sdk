#![deny(unsafe_code)]

//! The Search world's DNS, TLS, web pages and search engines.
//!
//! [`World`] joins public hostnames to certificates and an HTTP handler.
//! [`pages`] supplies copied WARC responses, live copies of the real web,
//! or live copies with a scenario's edits. Google, Bing and DuckDuckGo
//! render results in their own layouts. Headers and certificates use the
//! run clock. [`observation`] defines this world's typed facts; the demo
//! app projects them into its page.
//!
//! The world answers DNS itself ([`net`]): the gateway's resolver gives
//! each name the session serves a site the first time it is asked, and
//! every other name does not exist.
//!
//! The demo app in `demos/search/app` adds the VM, the guest credential
//! model gateway and the provider sign-in relay.

mod dns;
pub mod handler;
pub mod ntp;
pub mod observation;
pub mod pages;
pub mod route;
mod tls;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name};
use fictionet::stdlib::services::dns::Event;
use fictionet::stdlib::services::dns::resolver::{BlockedNames, Config, LocalZone};
use fictionet::stdlib::services::dns::zone::ZoneData;
use fictionet::stdlib::services::tls::CertifiedKey;
use fictionet::stdlib::web;
use fictionet::stdlib::world::net::dns::{Recursive, placing};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet_extras::dns::unbound;

use observation::SearchObs;
use pages::{Pages, Source};

pub use dns::admit;
pub use tls::Ca;

/// Builds the world's unstarted network.
///
/// The gateway runs a recursive resolver like Unbound whose only data is
/// a root zone of the world's own ([`placing`]): the first time a name
/// the session serves is asked, the world places its site, and the
/// resolver answers with the site's address. A name the session does not
/// serve does not exist. Live-Depth blocks the host names outside its
/// depth, and every mode the public resolvers' encrypted DNS names, with
/// NXDOMAIN and the Blocked extended error (RFC 8914). Every DNS reply
/// the resolver gives a client is reported as [`SearchObs::Resolved`].
///
/// The `forwarded` hosts answer to their names in place of a site, such
/// as the model gateway.
pub fn net(
    fcx: &Cx,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    start: SystemTime,
    forwarded: impl IntoIterator<Item = (Name, Host)>,
) -> Net {
    // The workstation sets its clock from Ubuntu's time server, which the
    // world plays in every mode.
    let ntp = Name::from_ascii(ntp::HOST).expect("a valid name");
    let forwarded: HashMap<String, Host> = forwarded
        .into_iter()
        .chain([(ntp, ntp::host(pages.clone()))])
        .map(|(mut name, host)| {
            name.set_fqdn(true);
            (dns::host(&LowerName::new(&name)), host)
        })
        .collect();
    let namespace = pages.namespace().clone();
    let clock = namespace.current().clock;
    let net = Net::new(fictionet_extras::network::cdn_pools())
        .ipv4_only()
        .drop_unrouted();
    let sites = Arc::new(Sites {
        handler: handler::Handler::new(fcx, pages.clone()),
        ca,
        pages: pages.clone(),
        start,
        upstream: Arc::new(tls::Upstream::default()),
        forwarded,
    });
    let zone: Arc<dyn ZoneData> = {
        let sites = sites.clone();
        Arc::new(placing(net.handle(), move |name| sites.host_for(name)))
    };
    let blocked_names: BlockedNames = {
        let sites = sites.clone();
        Arc::new(move |name| sites.blocks(name))
    };
    let observe = {
        let (fcx, pages) = (fcx.clone(), pages.clone());
        let blocked_names = blocked_names.clone();
        move |event: &Event| {
            if let Some(mut fact) = SearchObs::resolved(event) {
                if let SearchObs::Resolved {
                    name,
                    rcode,
                    blocked,
                    ..
                } = &mut fact
                {
                    let mut name = name.clone();
                    name.set_fqdn(true);
                    *blocked |=
                        *rcode == ResponseCode::NXDomain && blocked_names(&LowerName::new(&name));
                }
                pages.report(&fcx, fact);
            }
        }
    };
    let report_cx = fcx.clone();
    net.egress(fictionet_extras::network::corporate_egress)
        .gateway(move |host, _declared| {
            let config = Config {
                ede: true,
                hints: Vec::new(),
                blocked_names: Some(blocked_names.clone()),
                ..unbound::config()
            }
            .local(LocalZone::new(zone.clone()));
            host.program(
                Recursive::new(config, clock)
                    .namespace(&namespace)
                    .on_event(observe.clone()),
            )
        })
        .on_unreachable(move |unreachable| {
            pages.report(
                &report_cx,
                SearchObs::NoRoute {
                    from: unreachable.from,
                    to: unreachable.to,
                },
            );
        })
}

/// The sites the world places for the names the session serves.
struct Sites {
    handler: handler::Handler,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    start: SystemTime,
    /// Live hosts show the guest the real host's certificate failure: a
    /// site whose certificate expired presents an expired one here too.
    upstream: Arc<tls::Upstream>,
    /// The hosts the world places in place of a site, by name.
    forwarded: HashMap<String, Host>,
}

impl Sites {
    /// The host for `name`, lowercase without the trailing dot, the first
    /// time it is asked: a forwarded host, or a site if the session serves
    /// the name. `None` leaves the name nonexistent, until the session
    /// serves it.
    fn host_for(&self, name: &str) -> Option<Host> {
        if let Some(host) = self.forwarded.get(name) {
            return Some(host.clone());
        }
        if !self.pages.serves_host(name) {
            return None;
        }
        let name = Name::from_ascii(name).ok()?;
        Some(self.site(&LowerName::new(&name)))
    }

    /// Whether the gateway blocks `name`: a public resolver's encrypted
    /// DNS name in every mode, and in Live-Depth a host name outside the
    /// depth.
    fn blocks(&self, name: &LowerName) -> bool {
        let host = dns::host(name);
        dns::encrypted_resolver(&host)
            || (self.pages.source() == Source::LiveDepth
                && admit(&host).is_ok()
                && !self.forwarded.contains_key(&host)
                && !self.pages.serves_host(&host))
    }

    /// A site for `name`, answered by the world's handler, with a
    /// certificate from the world's CA, or in a live mode the one the real
    /// host's certificate failure calls for, and no handshake where the
    /// real host gives none.
    fn site(&self, name: &LowerName) -> Host {
        let host = dns::host(name);
        if self.pages.source().is_live() {
            self.upstream.start(&host);
        }
        let (ca, pages, upstream, site) = (
            self.ca.clone(),
            self.pages.clone(),
            self.upstream.clone(),
            host.clone(),
        );
        let config: Arc<OnceLock<Arc<CertifiedKey>>> = Arc::new(OnceLock::new());
        let refused: Arc<OnceLock<Arc<CertifiedKey>>> = Arc::new(OnceLock::new());
        web::Site::new(self.handler.clone())
            .date(self.start)
            .tls_when(move |fcx| {
                let (fcx, ca, name, pages, upstream) = (
                    fcx.clone(),
                    ca.clone(),
                    site.clone(),
                    pages.clone(),
                    upstream.clone(),
                );
                let (config, refused) = (config.clone(), refused.clone());
                async move {
                    let verdict = match pages.source().is_live() {
                        true => upstream.verdict(&name).await,
                        false => tls::Verdict::Verifies,
                    };
                    // A real host that gives no handshake, such as a name
                    // server with nothing on port 443, gets none here
                    // either: the handshake runs out its time.
                    if verdict == tls::Verdict::NoHandshake {
                        std::future::pending::<()>().await;
                    }
                    if let tls::Verdict::Refused(refusal) = verdict {
                        if let Ok(host) = name.parse() {
                            pages.report(
                                &fcx,
                                SearchObs::Certificate {
                                    host,
                                    problem: (&refusal).into(),
                                    source: if pages.source() == pages::Source::Edited {
                                        observation::PageSource::Edited
                                    } else {
                                        observation::PageSource::Live
                                    },
                                },
                            );
                        }
                        return refused
                            .get_or_init(|| {
                                ca.refused(&fcx, &name, &refusal)
                                    .expect("a certificate for an admitted name")
                            })
                            .clone();
                    }
                    config
                        .get_or_init(|| {
                            let (config, _, _) = ca
                                .config(&fcx, &name)
                                .expect("a certificate for an admitted name");
                            config
                        })
                        .clone()
                }
            })
            .into_host(&host)
    }
}

/// A world kept in memory: its CA, its pages, and the run's start on the
/// host clock.
pub struct World {
    pub ca: Arc<Ca>,
    pub pages: Arc<Pages>,
    pub start: SystemTime,
}

impl World {
    /// The world's unstarted network, as [`net`] builds it.
    pub fn net(&self, fcx: &Cx, forwarded: impl IntoIterator<Item = (Name, Host)>) -> Net {
        net(
            fcx,
            self.ca.clone(),
            self.pages.clone(),
            self.start,
            forwarded,
        )
    }
}
