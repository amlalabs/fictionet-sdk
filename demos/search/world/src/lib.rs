//! The Search world's DNS, TLS, web pages and search engines.
//!
//! [`World`] joins public hostnames to certificates and an HTTP handler.
//! [`pages`] supplies copied WARC responses, live copies of the real web,
//! or live copies with a scenario's edits. Google, Bing and DuckDuckGo
//! render results in their own layouts. Headers and certificates use the
//! run clock. [`observation`] defines this world's typed facts; the demo
//! app projects them into its page.
//!
//! The world's DNS is the real hierarchy, copied ([`net`]): the guest's
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
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData};
use fictionet::stdlib::services::dns::Event;
use fictionet::stdlib::services::dns::resolver::{BlockedNames, Config, NegativeAnchors};
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web;
use fictionet::stdlib::world::net::dns::{Only, PerSession, Recursive};
use fictionet::stdlib::world::net::{Host, Net, NetHandle};
use fictionet::sync::Mutex;
use fictionet_extras::dns::learned::{Filing, Section};
use fictionet_extras::dns::mirror::Mirror;
use fictionet_extras::dns::place::Place;
use fictionet_extras::dns::public::PUBLIC_RESOLVERS;
use fictionet_extras::dns::{roots, unbound};

use observation::SearchObs;
use pages::Pages;

use dns::{Outbound, SessionUpstream};

pub use dns::admit;
pub use tls::Ca;

/// Builds the world's unstarted network on the real DNS hierarchy, copied.
///
/// The root and `gtld-servers.net` servers answer from records copied from
/// the real ones, from the internet or a Copied session's capture, and the
/// mirror places a server at each name server address the copied records
/// name, so every name the world serves resolves through the real
/// hierarchy. Only the lookups the world's outbound policy allows reach a
/// real server (`dns::Outbound`). The public resolvers run at their real
/// addresses, and the gateway runs a recursive resolver like Unbound with
/// the root hints, holding no data of its own. Every DNS reply either
/// kind of resolver gives a client is reported as
/// [`SearchObs::Resolved`].
///
/// Each A record a mirrored zone files for a name the session lets out
/// gets a machine at that address, before the reply that needed it
/// leaves: the `forwarded` host given for that name, such as the model
/// gateway, or a site whose pages come from [`Pages`]. So the guest connects to the
/// address the real DNS gave, and the world changes the machine there,
/// never the DNS. `place` is how far away the real servers are and which
/// instance of each answers, and `egress` the host's public address
/// ([`Pages::egress`]), when known, which the public resolvers' whoami
/// names answer with.
pub fn net(
    fcx: &Cx,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    start: SystemTime,
    place: Place,
    egress: Option<Ipv4Addr>,
    forwarded: impl IntoIterator<Item = (Name, Host)>,
) -> Net {
    // The workstation sets its clock from Ubuntu's time server, which the
    // world plays in every mode.
    let ntp = Name::from_ascii(ntp::HOST).expect("a valid name");
    // Names off the wire are fully qualified, and a relative name never
    // equals one, so each forwarded name is taken from the root.
    let forwarded: HashMap<LowerName, Host> = forwarded
        .into_iter()
        .chain([(ntp, ntp::host(pages.clone()))])
        .map(|(mut name, host)| {
            name.set_fqdn(true);
            (LowerName::new(&name), host)
        })
        .collect();
    let namespace = pages.namespace().clone();
    let clock = namespace.current().clock;
    let net = Net::new(fictionet_extras::network::cdn_pools())
        .ipv4_only()
        .drop_unrouted();
    let handle = net.handle();

    let outbound = Outbound::new(pages.clone(), forwarded.keys().cloned());
    let blocked_names: BlockedNames = {
        let outbound = outbound.clone();
        Arc::new(move |name| outbound.blocks_client(name))
    };
    let gateway_blocked_names = blocked_names.clone();
    let upstream = Arc::new(SessionUpstream::new(
        pages.clone(),
        forwarded.keys().cloned(),
    ));
    let negative_anchors: NegativeAnchors = Arc::new(upstream.negative_anchors());
    let mirror = Mirror::new(Only::new(outbound.policy(), upstream), handle.clone());
    let sites = Arc::new(Sites {
        handle,
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
        ech: PerSession::new(),
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
    let net = net.egress(fictionet_extras::network::corporate_egress);
    let mut mirror = roots::seed(
        mirror
            .delay(place.authority_rtt / 2)
            .namespace(&namespace)
            .observe(outbound.observer())
            .observe(move |filing| sites.place(filing)),
    );
    // The host asks every real server itself, so a real server that
    // echoes the asker's address would show the host's. A public
    // resolver's reply shows the resolver's own egress instead.
    if let Some(egress) = egress {
        let echo = place.echo(egress);
        mirror = mirror
            .egress(IpAddr::V4(egress))
            .wrap(move |authority| echo.over(authority));
    }
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
                    *blocked |= *rcode
                        == fictionet::stdlib::protocols::dns::op::ResponseCode::NXDomain
                        && blocked_names(&LowerName::new(&name));
                }
                pages.report(&fcx, fact);
            }
        }
    };
    let gateway_observe = observe.clone();
    let gateway_namespace = namespace.clone();
    let (report_cx, report_pages) = (fcx.clone(), pages);
    net.hosts(place.root_servers(|server| mirror.server(server)))
        .hosts(place.gtld_servers(|server| mirror.server(server)))
        .hosts(place.public_resolvers(|resolver, site, host| {
            let config = resolver.config(site.identity.clone());
            let config = match egress {
                Some(egress) => resolver.whoami(config, site, egress),
                None => config,
            };
            let config = Config {
                blocked_names: Some(blocked_names.clone()),
                negative_anchors: Some(negative_anchors.clone()),
                ..config
            };
            // One engine and cache per sandbox, so sandboxes can neither
            // warm nor probe each other's caches.
            let recursive = Recursive::new(config, clock)
                .per_sandbox()
                .namespace(&namespace)
                .on_event(observe.clone());
            host.program(recursive)
        }))
        .gateway(move |host, _declared| {
            // No declared data: every site the world places declares its
            // name, and every name it serves is real, so the real
            // hierarchy answers for all of them.
            let config = Config {
                ede: true,
                blocked_names: Some(gateway_blocked_names.clone()),
                negative_anchors: Some(negative_anchors.clone()),
                ..unbound::config()
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

/// Whether `addr` is one of [`PUBLIC_RESOLVERS`]' addresses, which the
/// world gives the resolver's machine.
fn resolver_address(addr: Ipv4Addr) -> bool {
    PUBLIC_RESOLVERS
        .iter()
        .flat_map(|resolver| resolver.addresses)
        .any(|address| address.v4 == addr)
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
    /// The IPv4 addresses the mirrored zones filed for each name this
    /// session, its own or those at the end of its CNAME chain.
    addresses: PerSession<HashMap<LowerName, HashSet<Ipv4Addr>>>,
    /// Public TLS names advertised by each site's HTTPS records.
    ech: PerSession<HashMap<LowerName, HashSet<LowerName>>>,
}

impl Sites {
    /// Places a machine at each IPv4 address `filing`, what a mirrored
    /// zone filed, gives in an A record of an answer section, for the
    /// record's name and every name a CNAME or DNAME made an alias of
    /// it, as long as the session lets the name out. Addresses from a
    /// referral's glue or a response's additional data are a name
    /// server's, which a guest reaches over DNS, so they place nothing.
    /// A filed CNAME whose target's addresses were filed before places
    /// its owner there too, and a filed DNAME the names it substitutes
    /// those names for, since a resolver that has the target's addresses
    /// cached does not ask for them again. A name is placed at an address
    /// once: several names at one address share its machine, and TLS
    /// tells them apart by SNI, as at a CDN's address.
    ///
    /// The network has no IPv6, so AAAA records place nothing. An address
    /// the network refuses, such as one on the sandboxes' subnet, or one
    /// whose port 443 already serves the world's infrastructure, keeps no
    /// machine for the name. So does a public resolver's address, which
    /// the guest cannot reach over DNS or HTTPS. A name at a name
    /// server's address gets its site there, as a small domain often runs
    /// its web site and its name server on one machine, and so does the
    /// name of a name server: a name is known to name one only once a
    /// delegation to it is filed, and the site a name gets must not depend
    /// on what was asked first. In a live mode the site shakes hands only
    /// as the real host does, so a name server with nothing on port 443
    /// gives no handshake ([`site`](Sites::site)). A name the
    /// session resolves but does not serve, outside Live-Depth's depth,
    /// gets no site: a machine there with no services refuses connections
    /// at TCP.
    fn place(&self, filing: &Filing) {
        let answers = || {
            filing
                .sets
                .iter()
                .filter(|(section, _)| *section == Section::Answer)
                .flat_map(|(_, set)| set.records_without_rrsigs())
        };
        let generation = self.pages.namespace().current().generation;
        self.ech.with(generation, |ech| {
            for record in answers() {
                let names = fictionet_extras::dns::ech_public_names(&record.data);
                if !names.is_empty() {
                    ech.entry(LowerName::new(&record.name))
                        .or_default()
                        .extend(names);
                }
            }
        });
        let mut found: Vec<(LowerName, Ipv4Addr)> = answers()
            .filter_map(|record| match &record.data {
                RData::A(a) if !non_public_address(a.0.into()) && !resolver_address(a.0) => {
                    Some((LowerName::new(&record.name), a.0))
                }
                _ => None,
            })
            .collect();
        let placing = self.addresses.with(generation, |addresses| {
            for (name, addr) in &found {
                addresses.entry(name.clone()).or_default().insert(*addr);
            }
            for record in answers() {
                if let RData::CNAME(cname) = &record.data
                    && let Some(known) = addresses.get(&LowerName::new(&cname.0))
                {
                    let owner = LowerName::new(&record.name);
                    found.extend(known.iter().map(|addr| (owner.clone(), *addr)));
                }
            }
            let filed: HashMap<LowerName, HashSet<LowerName>> =
                dns::dnames(filing).fold(HashMap::new(), |mut filed, (owner, target)| {
                    filed
                        .entry(LowerName::new(&target))
                        .or_default()
                        .insert(owner);
                    filed
                });
            for (name, known) in addresses.iter() {
                for original in dns::substituted_for(&filed, name) {
                    found.extend(known.iter().map(|addr| (original.clone(), *addr)));
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
                            let refuser = Host::new(&dns::host(&name)).at(addr).ipv4_only();
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
        let ech = self.ech.with(generation, |ech| ech.clone());
        let addresses = self
            .addresses
            .with(generation, |addresses| addresses.clone());
        for (owner, names) in ech {
            if !self.outbound.admits(&owner) || !self.serves(&owner) {
                continue;
            }
            for addr in addresses.get(&owner).into_iter().flatten() {
                for name in &names {
                    if !self.placed.lock().insert((name.clone(), *addr)) {
                        continue;
                    }
                    let ca = self.ca.clone();
                    let public_name = dns::host(name);
                    let certificate_name = public_name.clone();
                    let config = OnceLock::new();
                    let host = web::Site::new(tls::EchFallback)
                        .tls_with(move |fcx| {
                            config
                                .get_or_init(|| {
                                    ca.config(fcx, &certificate_name)
                                        .expect("a certificate for an ECH public name")
                                        .0
                                })
                                .clone()
                        })
                        .into_host(&public_name)
                        .at(*addr);
                    let _ = self.handle.add_host(host);
                }
            }
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
        self.forwarded.contains_key(name) || self.pages.serves_host(&dns::host(name))
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

/// A world kept in memory: its CA, its pages, the run's start on the host
/// clock, where the host is on the internet, and its public address when
/// known.
pub struct World {
    pub ca: Arc<Ca>,
    pub pages: Arc<Pages>,
    pub start: SystemTime,
    pub place: Place,
    pub egress: Option<Ipv4Addr>,
}

impl World {
    /// The world's unstarted network, as [`net`] builds it.
    pub fn net(&self, fcx: &Cx, forwarded: impl IntoIterator<Item = (Name, Host)>) -> Net {
        net(
            fcx,
            self.ca.clone(),
            self.pages.clone(),
            self.start,
            self.place.clone(),
            self.egress,
            forwarded,
        )
    }
}
