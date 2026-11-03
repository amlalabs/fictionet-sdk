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
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use fictionet::Cx;
use fictionet::stdlib::network::ip::non_public_address;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData};
use fictionet::stdlib::services::dns::Event;
use fictionet::stdlib::services::dns::resolver::{Config, NegativeAnchors};
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web;
use fictionet::stdlib::world::net::dns::encrypted::Fronts;
use fictionet::stdlib::world::net::dns::internet::{self, Location, Mirror, PUBLIC_RESOLVERS};
use fictionet::stdlib::world::net::dns::{Only, PerSession, Recursive};
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
/// never the DNS. `location` is where the host is ([`Pages::location`]),
/// with its public address, when known, which the public resolvers'
/// whoami names answer with.
pub fn net(
    fcx: &Cx,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    start: SystemTime,
    location: Location,
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
    let namespace = pages.namespace().clone();
    let clock = namespace.current().clock;
    let net = Net::new().ipv4_only().drop_unrouted();
    let handle = net.handle();

    let outbound = Outbound::new(pages.clone(), forwarded.keys().cloned());
    let source = Arc::new(SessionSource::new(pages.clone(), forwarded.keys().cloned()));
    let negative_anchors: NegativeAnchors = Arc::new(source.negative_anchors());
    let resolver_ca = ca.clone();
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
        refusing: Mutex::default(),
        refused: Mutex::default(),
        addresses: PerSession::new(),
    });
    // A host refused once is served as soon as the session serves it.
    {
        let sites = Arc::downgrade(&sites);
        pages.on_hosts_served(move || {
            if let Some(sites) = sites.upgrade() {
                sites.place_refused();
            }
        });
    }
    let mut mirror = Mirror::new(Only::new(outbound.policy(), source), handle, &location)
        .namespace(&namespace)
        .observe(outbound.observer())
        .observe(move |_request, _client, reply| sites.place(&reply.message));
    // Each public resolver's DNS over HTTPS names, such as
    // `cloudflare-dns.com`, have addresses of their own, where the mirror
    // places a front that puts queries to the resolver's primary address.
    // The fronts are kept by the resolver's primary address.
    let doh: Arc<Mutex<HashMap<IpAddr, Fronts>>> = Arc::default();
    for resolver in &PUBLIC_RESOLVERS {
        let primary = IpAddr::V4(resolver.addresses[0].v4);
        for name in resolver.doh() {
            let doh = doh.clone();
            mirror = mirror.front(name, move |host| match doh.lock().get(&primary) {
                Some(fronts) => fronts.doh(host),
                None => host,
            });
        }
    }

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
            let config = Config {
                negative_anchors: Some(negative_anchors.clone()),
                ..resolver.config(&location)
            };
            let recursive = resolver
                .recursive(config, clock)
                .namespace(&namespace)
                .on_event(observe.clone());
            let (ca, served) = (resolver_ca.clone(), *resolver);
            let config = OnceLock::new();
            let tls = move |fcx: &Cx| {
                config
                    .get_or_init(|| {
                        ca.resolver_config(fcx, &served)
                            .expect("a certificate for a public resolver")
                    })
                    .clone()
            };
            let fronts = Fronts::new(recursive.handle(), tls)
                .names(resolver.doh())
                .operator(resolver.doh_operator)
                .date(start);
            // The primary address comes first, and its fronts serve the
            // resolver's DNS over HTTPS names elsewhere.
            let primary = IpAddr::V4(resolver.addresses[0].v4);
            doh.lock()
                .entry(primary)
                .or_insert_with(|| fronts.clone().resolver_at(primary));
            fronts.doh(fronts.dot(host.program(recursive)))
        },
        &location,
    ))
    .gateway(move |host, _declared| {
        // No declared data: every site the world places declares its
        // name, and every name it serves is real, so the real
        // hierarchy answers for all of them.
        let config = Config {
            negative_anchors: Some(negative_anchors.clone()),
            ..Config::unbound()
        };
        host.program(
            Recursive::new(config, clock)
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
    /// Addresses given a machine with no services, for names a session
    /// resolves but does not serve, so connections to them are refused.
    refusing: Mutex<HashSet<Ipv4Addr>>,
    /// The addresses of each name refused that way, where its site goes
    /// once a session serves it: a guest that resolved the name keeps
    /// the address for the record's TTL.
    refused: Mutex<HashMap<LowerName, HashSet<Ipv4Addr>>>,
    /// The session's relayed IPv4 addresses of each name, its own or those
    /// at the end of its CNAME chain.
    addresses: PerSession<HashMap<LowerName, HashSet<Ipv4Addr>>>,
}

impl Sites {
    /// Places a machine at each IPv4 address `reply`, a relayed reply,
    /// gives in an A record, for the record's name and every name a
    /// relayed CNAME made an alias of it, as long as the session lets the
    /// name out. A CNAME whose target's addresses an earlier reply gave
    /// places its owner there too, since a resolver that has the target's
    /// addresses cached does not ask for them again. A name is placed at
    /// an address once: several names at one address share its machine,
    /// and TLS tells them apart by SNI, as at a CDN's address.
    ///
    /// The network has no IPv6, so AAAA records place nothing. An address
    /// the network refuses, such as one on the sandboxes' subnet, or one
    /// whose port 443 already serves the world's infrastructure, keeps no
    /// machine for the name. A name the session resolves but does not
    /// serve, outside Live-Depth's depth, gets no site: a machine there
    /// with no services refuses connections at TCP.
    fn place(&self, reply: &Message) {
        let mut found: Vec<(LowerName, Ipv4Addr)> = reply
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) if !non_public_address(a.0.into()) => {
                    Some((LowerName::new(&record.name), a.0))
                }
                _ => None,
            })
            .collect();
        let generation = self.pages.namespace().current().generation;
        let placing = self.addresses.with(generation, |addresses| {
            for (name, addr) in &found {
                addresses.entry(name.clone()).or_default().insert(*addr);
            }
            for record in &reply.answers {
                if let RData::CNAME(cname) = &record.data
                    && let Some(known) = addresses.get(&LowerName::new(&cname.0))
                {
                    let owner = LowerName::new(&record.name);
                    found.extend(known.iter().map(|addr| (owner.clone(), *addr)));
                }
            }
            let mut placing = Vec::new();
            for (name, addr) in found {
                let aliases = self.outbound.aliases(&name);
                for name in std::iter::once(name).chain(aliases) {
                    addresses.entry(name.clone()).or_default().insert(addr);
                    if !self.outbound.admits(&name) {
                        continue;
                    }
                    if !self.serves(&name) {
                        // Live-Depth: the DNS is real, but the name is
                        // outside the depth. Its own machine refuses TCP,
                        // and a shared one has no site for its SNI.
                        self.refused
                            .lock()
                            .entry(name.clone())
                            .or_default()
                            .insert(addr);
                        if self.refusing.lock().insert(addr)
                            && !self.handle.has_machine(addr.into())
                        {
                            let refuser = Host::new(&name.to_string()).at(addr).ipv4_only();
                            let _ = self.handle.add_host(refuser);
                        }
                        continue;
                    }
                    if self.placed.lock().insert((name.clone(), addr)) {
                        placing.push((name, addr));
                    }
                }
            }
            placing
        });
        for (name, addr) in placing {
            let _ = self.handle.add_host(self.host(&name).at(addr));
        }
    }

    /// Places the site of each name refused before that the session now
    /// serves, at the addresses it was refused at, beside the machine with
    /// no services there.
    fn place_refused(&self) {
        let refused: Vec<(LowerName, HashSet<Ipv4Addr>)> = self
            .refused
            .lock()
            .iter()
            .map(|(name, addrs)| (name.clone(), addrs.clone()))
            .collect();
        for (name, addrs) in refused {
            if !self.outbound.admits(&name) || !self.serves(&name) {
                continue;
            }
            self.refused.lock().remove(&name);
            for addr in addrs {
                if self.placed.lock().insert((name.clone(), addr)) {
                    let _ = self.handle.add_host(self.host(&name).at(addr));
                }
            }
        }
    }

    /// Whether the session serves pages for `name`: a forwarded host's
    /// name always, and other names as [`Pages::serves_host`] says, which
    /// in Live-Depth keeps to the depth.
    fn serves(&self, name: &LowerName) -> bool {
        self.forwarded.contains_key(name)
            || self
                .pages
                .serves_host(name.to_string().trim_end_matches('.'))
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

/// A world kept in memory: its CA, its pages, the run's start on the host
/// clock, and where the host is on the internet.
pub struct World {
    pub ca: Arc<Ca>,
    pub pages: Arc<Pages>,
    pub start: SystemTime,
    pub location: Location,
}

impl World {
    /// The world's unstarted network, as [`net`] builds it.
    pub fn net(&self, fcx: &Cx, forwarded: impl IntoIterator<Item = (Name, Host)>) -> Net {
        net(
            fcx,
            self.ca.clone(),
            self.pages.clone(),
            self.start,
            self.location.clone(),
            forwarded,
        )
    }
}
