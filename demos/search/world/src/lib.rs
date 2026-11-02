//! The Search world's DNS, TLS, web pages and search engines.
//!
//! [`World`] joins public hostnames to certificates and an HTTP handler.
//! [`pages`] supplies copied WARC responses, live copies of the real web,
//! or live copies with a scenario's edits. Google, Bing and DuckDuckGo
//! render results in their own layouts. Headers and certificates use the
//! run clock. [`observation`] defines this world's typed facts; the demo
//! app projects them into its page.
//!
//! The world's DNS is the real hierarchy, relayed ([`net`]): the guest's
//! resolver, the public resolvers, and the root servers answer as the real
//! ones do, with each site's real address and real signatures, and each
//! site's machine stands at those addresses.
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

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::Response;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData};
use fictionet::stdlib::services::dns::Event;
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web;
use fictionet::stdlib::world::net::dns::internet::{self, Egress, Location, Mirror};
use fictionet::stdlib::world::net::dns::{Only, Recursive};
use fictionet::stdlib::world::net::{Host, Net, NetHandle};
use fictionet::sync::Mutex;

use observation::SearchObs;
use pages::Pages;

use dns::{Outbound, SessionSource};

pub use dns::admit;
pub use tls::Ca;

/// Builds the world's unstarted network on the real DNS hierarchy, relayed.
///
/// The root and `gtld-servers.net` servers relay what the real ones
/// answer, from the internet or a Copied session's capture, and the mirror
/// places a relay at each name server address their replies name, so
/// every name the world serves resolves through the real hierarchy. Only
/// the questions the world's outbound policy allows reach a real server
/// (`dns::Outbound`). The
/// public resolvers run at their real addresses, and the gateway runs a
/// recursive resolver like Unbound with the root hints, holding no data of
/// its own. Every DNS reply either kind of resolver gives a client is
/// reported as [`SearchObs::Resolved`].
///
/// Each A record a relayed reply gives for a name the session lets out
/// gets a machine at that address, before the reply leaves: the
/// `forwarded` host given for that name, such as the model gateway, or a
/// site whose pages come from [`Pages`]. So the guest connects to the
/// address the real DNS gave, and the world changes the machine there,
/// never the DNS. `egress` is the host's public address, which the
/// public resolvers' whoami names answer with.
pub fn net(
    fcx: &Cx,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    start: SystemTime,
    egress: Egress,
    forwarded: impl IntoIterator<Item = (Name, Host)>,
) -> Net {
    let mut forwarded: HashMap<LowerName, Host> = forwarded
        .into_iter()
        .map(|(name, host)| (LowerName::new(&name), host))
        .collect();
    // The workstation sets its clock from Ubuntu's time server, which the
    // world plays in every mode.
    forwarded.insert(
        LowerName::new(&Name::from_ascii(ntp::HOST).expect("a valid name")),
        ntp::host(pages.clone()),
    );
    // The search engines are the world's own in every mode; a Copied
    // capture need not hold their DNS.
    let search_engines = route::SEARCH_HOSTS
        .iter()
        .map(|host| LowerName::new(&Name::from_ascii(host).expect("a valid name")));
    let namespace = pages.namespace().clone();
    let clock = namespace.current().clock;
    let location = Location::san_francisco_bay_area(egress);
    let net = Net::new(fictionet_extras::network::cdn_pools()).ipv4_only().drop_unrouted();
    let handle = net.handle();

    let outbound = Outbound::new(pages.clone(), forwarded.keys().cloned());
    let source = SessionSource::new(
        pages.clone(),
        forwarded.keys().cloned().chain(search_engines),
    );
    let sites = Arc::new(Sites {
        handle: handle.clone(),
        outbound: outbound.clone(),
        handler: handler::Handler::new(fcx, pages.clone()),
        ca,
        pages: pages.clone(),
        start,
        upstream: Arc::new(tls::Upstream::default()),
        forwarded,
        built: Mutex::default(),
        placed: Mutex::default(),
    });
    let mirror = Mirror::new(Only::new(outbound.policy(), source), handle, &location)
        .namespace(&namespace)
        .observe(outbound.observer())
        .observe(move |_request, _client, reply| sites.place(reply));

    let observe = {
        let (fcx, pages) = (fcx.clone(), pages.clone());
        move |event: &Event| {
            if let Some(fact) = SearchObs::resolved(event) {
                pages.report(&fcx, fact);
            }
        }
    };
    let gateway_observe = observe.clone();
    let gateway_namespace = namespace.clone();
    let (report_cx, report_pages) = (fcx.clone(), pages);
    net.hosts(internet::root_servers(
        |server| mirror.relay(server),
        &location,
    ))
    .hosts(internet::gtld_servers(
        |server| mirror.relay(server),
        &location,
    ))
    .hosts(internet::public_resolvers(
        |resolver, host| {
            host.program(
                resolver
                    .recursive(&location, clock)
                    .namespace(&namespace)
                    .on_event(observe.clone()),
            )
        },
        &location,
    ))
    .gateway(move |host, _declared| {
        // No declared data: every site the world places declares its
        // name, and every name it serves is real, so the real
        // hierarchy answers for all of them.
        host.program(
            Recursive::new(Config::unbound().hints(&internet::root_hints()), clock)
                .namespace(&gateway_namespace)
                .on_event(gateway_observe.clone()),
        )
    })
    .on_unreachable(move |unreachable| {
        report_pages.report(
            &report_cx,
            SearchObs::NoRoute {
                from: unreachable.from,
                to: unreachable.to,
            },
        );
    })
}

/// What puts each served name's machine at the real addresses the
/// hierarchy gives it.
struct Sites {
    handle: NetHandle,
    outbound: Outbound,
    handler: handler::Handler,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    start: SystemTime,
    /// Live hosts show the guest the real host's certificate failure: a
    /// site whose certificate expired presents an expired one here too.
    upstream: Arc<tls::Upstream>,
    /// The hosts the world puts at a name's addresses in place of a site.
    forwarded: HashMap<LowerName, Host>,
    /// Each site built so far, with no address yet, so all of a name's
    /// machines share its certificates.
    built: Mutex<HashMap<LowerName, Host>>,
    /// Each name and address given a machine, or found unable to take one.
    placed: Mutex<HashSet<(LowerName, Ipv4Addr)>>,
}

impl Sites {
    /// Places a machine at each IPv4 address `reply`, a relayed reply,
    /// gives in an A record, for the record's name and every name a
    /// relayed CNAME made an alias of it, as long as the session lets the
    /// name out. A name is placed at an address once: several names at one
    /// address share its machine, and TLS tells them apart by SNI, as at a
    /// CDN's address.
    ///
    /// The network has no IPv6, so AAAA records place nothing. An address
    /// the network refuses, such as one on the sandboxes' subnet, or one
    /// whose port 443 already serves the world's infrastructure, keeps no
    /// machine for the name.
    fn place(&self, reply: &Response) {
        for record in &reply.message.answers {
            let RData::A(a) = &record.data else {
                continue;
            };
            if !routable(a.0) {
                continue;
            }
            let owner = LowerName::new(&record.name);
            let aliases = self.outbound.aliases(&owner);
            for name in std::iter::once(owner).chain(aliases) {
                if self.outbound.admits(&name) && self.placed.lock().insert((name.clone(), a.0)) {
                    let _ = self.handle.add_host(self.host(&name).at(a.0));
                }
            }
        }
    }

    /// The host the world puts at `name`'s addresses.
    fn host(&self, name: &LowerName) -> Host {
        if let Some(host) = self.forwarded.get(name) {
            return host.clone();
        }
        self.built
            .lock()
            .entry(name.clone())
            .or_insert_with(|| self.site(name))
            .clone()
    }

    /// A site for `name`, answered by the world's handler, with a
    /// certificate from the world's CA, or in a live mode the one the real
    /// host's certificate failure calls for.
    fn site(&self, name: &LowerName) -> Host {
        let host = name.to_string().trim_end_matches('.').to_owned();
        if self.pages.source().is_live() {
            self.upstream.start(&host);
        }
        let (ca, pages, upstream, site) = (
            self.ca.clone(),
            self.pages.clone(),
            self.upstream.clone(),
            host.clone(),
        );
        let config: Arc<OnceLock<Arc<ServerConfig>>> = Arc::new(OnceLock::new());
        let refused: Arc<OnceLock<Arc<ServerConfig>>> = Arc::new(OnceLock::new());
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
                    if pages.source().is_live()
                        && let Some(refusal) = upstream.refusal(&name).await
                    {
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

/// Whether `addr` is an address a host on the internet can have, by the
/// IANA special-purpose registry (RFC 6890): not private, loopback,
/// link-local, shared (RFC 6598), documentation, multicast, broadcast, or
/// unspecified. A real name with such an address gets no machine there.
fn routable(addr: Ipv4Addr) -> bool {
    let shared = addr.octets()[0] == 100 && (addr.octets()[1] & 0xc0) == 64;
    !(addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_documentation()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_unspecified()
        || shared)
}

/// A world kept in memory: its CA, its pages, the run's start on the host
/// clock, and the host's public address.
pub struct World {
    pub ca: Arc<Ca>,
    pub pages: Arc<Pages>,
    pub start: SystemTime,
    pub egress: Egress,
}

impl World {
    /// The world's unstarted network, as [`net`] builds it.
    pub fn net(&self, fcx: &Cx, forwarded: impl IntoIterator<Item = (Name, Host)>) -> Net {
        net(
            fcx,
            self.ca.clone(),
            self.pages.clone(),
            self.start,
            self.egress,
            forwarded,
        )
    }
}
