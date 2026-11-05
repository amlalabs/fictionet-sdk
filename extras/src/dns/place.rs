//! How the internet's DNS servers look from one place: the round trip to
//! each root letter, `gtld-servers.net` server, and public resolver, and
//! which anycast instance answers each address there, as an agent reads
//! it with `dig +nsid` or `id.server` CH TXT.
//!
//! [`Place::san_francisco_bay_area`] holds what those servers answered
//! there on 2026-11-01 and 2026-11-02. A world sets the round trips as
//! [`Host::delay`] and the identities in each server's front, with
//! [`Place::root_servers`] and [`Place::gtld_servers`], and with the
//! public resolvers of [`public`].

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::Name;
use fictionet::stdlib::services::dns::authority::{ChaosZone, Identity, ServerConfig};
use fictionet::stdlib::services::dns::resolver::ROOT_SERVERS;
use fictionet::stdlib::world::net::dns::internet;
use fictionet::stdlib::world::net::{Host, Program};

use super::public::{self, PUBLIC_RESOLVERS, PublicResolver};
use super::roots::{self, GTLD_SERVERS};
use super::{bind, chaos};

/// How one anycast server looks from a place: the round trip to the
/// instance that answers there, and what that instance says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The round trip from the network to the server.
    pub rtt: Duration,
    /// Its answers to CHAOS-class questions and its NSID (RFC 5001).
    pub identity: Identity,
}

/// How a public resolver looks from a place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverSite {
    /// The round trip from the network to the resolver.
    pub rtt: Duration,
    /// Its answers to CHAOS-class questions and its NSID.
    pub identity: Identity,
    /// The IPv4 address its own questions to authorities leave from,
    /// which Google's whoami answer and servers that echo the asker show.
    pub egress: Ipv4Addr,
}

/// Where a world's network is on the internet: the round trips to
/// servers, and which anycast instance answers each server address there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    /// Authoritative servers by IPv4 address.
    pub servers: BTreeMap<IpAddr, Site>,
    /// Public resolvers by their primary IPv4 address.
    pub resolvers: BTreeMap<IpAddr, ResolverSite>,
    /// The round trip to any other authoritative server.
    pub authority_rtt: Duration,
}

impl Place {
    /// The server at `addr` from here. A server not listed answers with no
    /// identity after [`authority_rtt`](Self::authority_rtt).
    pub fn site(&self, addr: IpAddr) -> Site {
        self.servers.get(&addr).cloned().unwrap_or_else(|| Site {
            rtt: self.authority_rtt,
            identity: Identity::none(),
        })
    }

    /// The resolver whose primary address is `addr` from here. One not
    /// listed answers with no identity after
    /// [`authority_rtt`](Self::authority_rtt), and asks from its own
    /// address.
    pub fn resolver(&self, addr: Ipv4Addr) -> ResolverSite {
        self.resolvers
            .get(&IpAddr::V4(addr))
            .cloned()
            .unwrap_or_else(|| ResolverSite {
                rtt: self.authority_rtt,
                identity: Identity::none(),
                egress: addr,
            })
    }

    /// The root letters as seen from here ([`internet::root_servers`]):
    /// each host behind [`Host::delay`] with half its round trip, so a
    /// guest's `dig @198.41.0.4` and a resolver's own question take the
    /// same time, running `program` with the letter's front: its identity
    /// here, its payload size, and its answer to ANY.
    pub fn root_servers<P: Program>(&self, program: impl Fn(ServerConfig) -> P) -> Vec<Host> {
        internet::root_servers(|server, host| {
            let site = self.site(IpAddr::V4(server.v4));
            let letter = roots::letter_at(server.v4).expect("a root letter");
            let server = letter.front(site.identity);
            host.delay(site.rtt / 2).program(program(server))
        })
    }

    /// The `gtld-servers.net` servers as seen from here
    /// ([`roots::gtld_servers`]): each host behind [`Host::delay`] with
    /// half its round trip, running `program` with the server's front and
    /// its identity here.
    pub fn gtld_servers<P: Program>(&self, program: impl Fn(ServerConfig) -> P) -> Vec<Host> {
        roots::gtld_servers(|server, host| {
            let site = self.site(IpAddr::V4(server.v4));
            host.delay(site.rtt / 2)
                .program(program(roots::gtld_front(site.identity)))
        })
    }

    /// The public resolvers as seen from here
    /// ([`public_resolvers`](super::public::public_resolvers)): each host
    /// behind [`Host::delay`] with half its round trip, finished by
    /// `build` with the resolver and its site here.
    pub fn public_resolvers(
        &self,
        build: impl Fn(&PublicResolver, &ResolverSite, Host) -> Host,
    ) -> Vec<Host> {
        public::public_resolvers(|resolver, host| {
            let site = self.resolver(resolver.addresses[0].v4);
            let host = host.delay(site.rtt / 2);
            build(resolver, &site, host)
        })
    }

    /// The San Francisco Bay Area, as every root letter, `gtld-servers.net`
    /// server, and public resolver answered there on 2026-11-01: the
    /// median of five round trips to each, the instance names it gave for
    /// `id.server`, `hostname.bind`, `version.bind`, and `version.server`
    /// and their TTL, its NSID, and the RCODE it gave for other CHAOS
    /// names. Instances are the ones anycast picked there that day, so
    /// some sit far away: k.root answered from London. Other authorities
    /// took 20 ms, the median over six of them. Quad9's and OpenDNS's
    /// egress are the addresses `whoami.akamai.net` A gave through each
    /// there on 2026-11-03.
    pub fn san_francisco_bay_area() -> Place {
        use ResponseCode::{NoError, NotImp, Refused, ServFail};
        fn txt(text: &str) -> Result<&str, ResponseCode> {
            Ok(text)
        }
        fn no(rcode: ResponseCode) -> Result<&'static str, ResponseCode> {
            Err(rcode)
        }
        // The names of `answers`, in order: id.server, hostname.bind,
        // version.bind, version.server. A name with text gets it in the
        // plain look with TTL `ttl`.
        fn identity(
            nsid: &str,
            unlisted: ResponseCode,
            ttl: u32,
            answers: [Result<&str, ResponseCode>; 4],
        ) -> Identity {
            let names = [
                chaos::id_server(),
                chaos::hostname_bind(),
                chaos::version_bind(),
                chaos::version_server(),
            ];
            let mut identity = Identity {
                unlisted,
                nsid: Some(nsid.as_bytes().to_vec()),
                ..Identity::none()
            };
            for (name, answer) in names.into_iter().zip(answers) {
                identity = match answer {
                    Ok(text) => identity.zone(chaos::txt(&name, ttl, text)),
                    Err(rcode) => identity.rcode(name, rcode),
                };
            }
            identity
        }
        let ms = Duration::from_millis;
        // BIND serves each of its names with text as a zone with an SOA
        // and an NS record, and G runs it too.
        let zones = |identity: Identity| Identity {
            zones: identity.zones.into_iter().map(bind::chaos_zone).collect(),
            ..identity
        };
        // C, I, and M also serve `authors.bind`, a zone with no TXT.
        let bind = |identity: Identity| {
            let authors = ChaosZone::new(Name::from(&chaos::authors_bind()));
            zones(identity).zone(bind::chaos_zone(authors))
        };
        let letters = [
            (
                32,
                identity(
                    "a.r.ussea-4c",
                    NoError,
                    0,
                    [
                        txt("nnn1-ussea-4c"),
                        txt("nnn1-ussea-4c"),
                        txt("ATLAS"),
                        txt("ATLAS"),
                    ],
                ),
            ),
            (
                72,
                identity(
                    "b1-iad",
                    Refused,
                    0,
                    [
                        txt("b1-iad"),
                        txt("b1-iad"),
                        txt("knot 3.x"),
                        txt("knot 3.x"),
                    ],
                ),
            ),
            (
                15,
                bind(identity(
                    "lax1a.c.root-servers.org",
                    Refused,
                    0,
                    [
                        txt("lax1b.c.root-servers.org"),
                        txt("lax1a.c.root-servers.org"),
                        txt("c-root"),
                        no(Refused),
                    ],
                )),
            ),
            (
                8,
                identity(
                    "paca6.droot.maxgigapop.net",
                    Refused,
                    0,
                    [
                        txt("paca7.droot.maxgigapop.net"),
                        txt("paca8.droot.maxgigapop.net"),
                        txt("NSD 4"),
                        txt("NSD 4"),
                    ],
                ),
            ),
            (
                24,
                identity(
                    "c01.SEA.eroot",
                    NotImp,
                    60,
                    [
                        txt("c01.SEA.eroot"),
                        txt("c01.SEA.eroot"),
                        txt("2026.10.4"),
                        no(NotImp),
                    ],
                ),
            ),
            (
                9,
                identity(
                    "SJC.cf.f.root-servers.org",
                    NotImp,
                    60,
                    [
                        txt("SJC.cf.f.root-servers.org"),
                        txt("SJC.cf.f.root-servers.org"),
                        txt("2026.10.4"),
                        no(NotImp),
                    ],
                ),
            ),
            (
                48,
                zones(identity(
                    "groot-con2-3",
                    Refused,
                    0,
                    [no(Refused), txt("groot-con2-2"), no(Refused), no(Refused)],
                )),
            ),
            (
                21,
                identity(
                    "001.nzy.h.root-servers.org",
                    Refused,
                    0,
                    [
                        txt("001.nzy.h.root-servers.org"),
                        txt("001.nzy.h.root-servers.org"),
                        txt("NSD 4.x"),
                        txt("NSD 4.x"),
                    ],
                ),
            ),
            (
                7,
                bind(identity(
                    "s1.pix",
                    Refused,
                    0,
                    [
                        txt("s1.pix"),
                        txt("s1.pix"),
                        txt("contact info@netnod.se"),
                        no(Refused),
                    ],
                )),
            ),
            (
                5,
                identity(
                    "k.r.ussjc-3",
                    Refused,
                    0,
                    [
                        txt("rootns-ussjc-3"),
                        txt("rootns-ussjc-3"),
                        txt("KnotDNS"),
                        txt("KnotDNS"),
                    ],
                ),
            ),
            (
                150,
                identity(
                    "ns2.gb-lon.k.ripe.net",
                    Refused,
                    0,
                    [
                        txt("ns3.gb-lon.k.ripe.net"),
                        txt("ns2.gb-lon.k.ripe.net"),
                        txt("BIND"),
                        no(Refused),
                    ],
                ),
            ),
            (
                15,
                identity(
                    "us-lax-aa",
                    Refused,
                    0,
                    [
                        txt("us-lax-aa"),
                        txt("us-lax-aa"),
                        txt("NSD 4"),
                        txt("NSD 4"),
                    ],
                ),
            ),
            (
                13,
                bind(identity(
                    "M-SJC-4",
                    Refused,
                    0,
                    [txt("M-SJC-4"), txt("M-SJC-4"), txt("9.16"), no(Refused)],
                )),
            ),
        ];
        // Every gtld-servers.net server answers "ATLAS" for its version.
        let atlas = |nsid: &str, id: &str, hostname: &str| {
            identity(
                nsid,
                Refused,
                0,
                [txt(id), txt(hostname), txt("ATLAS"), txt("ATLAS")],
            )
        };
        let gtld = [
            (6, atlas("nnn1-ussjc-3", "nnn1-ussjc-3", "nnn1-ussjc-3")),
            (156, atlas("nnn1-ein2", "nnn1-ein4", "nnn1-ein1")),
            (7, atlas("nnn1-ussjc-3", "nnn1-ussjc-3", "nnn1-ussjc-3")),
            (7, atlas("nnn1-ussjc-3", "nnn1-ussjc-3", "nnn1-ussjc-3")),
            (6, atlas("nnn1-ussjc-3", "nnn1-ussjc-3", "nnn1-ussjc-3")),
            (53, atlas("nnn1-uschi-2c", "nnn1-uschi-2c", "nnn1-uschi-2a")),
            (54, atlas("nnn1-uschi-2b", "nnn1-uschi-2c", "nnn1-uschi-2b")),
            (53, atlas("nnn1-uschi-2b", "nnn1-uschi-2a", "nnn1-uschi-2b")),
            (53, atlas("nnn1-uschi-2c", "nnn1-uschi-2b", "nnn1-uschi-2b")),
            (47, atlas("nnn1-usdal-3b", "nnn1-usdal-3b", "nnn1-usdal-3b")),
            (47, atlas("nnn1-usdal-3a", "nnn1-usdal-3a", "nnn1-usdal-3a")),
            (47, atlas("nnn1-usdal-3a", "nnn1-usdal-3c", "nnn1-usdal-3a")),
            (45, atlas("nnn1-usdal-3a", "nnn1-usdal-3c", "nnn1-usdal-3c")),
        ];
        let servers = ROOT_SERVERS
            .into_iter()
            .zip(letters)
            .chain(GTLD_SERVERS.into_iter().zip(gtld))
            .map(|(server, (rtt, identity))| {
                let site = Site {
                    rtt: ms(rtt),
                    identity,
                };
                (IpAddr::V4(server.v4), site)
            })
            .collect();
        let resolver = |rtt: u64, identity: Identity, egress: Ipv4Addr| ResolverSite {
            rtt: ms(rtt),
            identity,
            egress,
        };
        let nsid = |nsid: &str, identity: Identity| Identity {
            nsid: Some(nsid.as_bytes().to_vec()),
            ..identity
        };
        let resolvers = [
            resolver(
                7,
                nsid("gpdns-sfo", chaos::refusing(ServFail)),
                Ipv4Addr::new(172, 253, 1, 21),
            ),
            resolver(
                8,
                identity(
                    "sjc01",
                    Refused,
                    0,
                    [txt("sjc10"), no(Refused), no(Refused), txt("2026.10.11")],
                ),
                Ipv4Addr::new(172, 69, 133, 100),
            ),
            resolver(
                7,
                identity(
                    "res130.pao",
                    Refused,
                    0,
                    [
                        txt("res711.pao"),
                        no(ServFail),
                        txt("Q9-P-2026080500"),
                        no(ServFail),
                    ],
                )
                .rcode(chaos::authors_bind(), ServFail),
                Ipv4Addr::new(74, 63, 16, 229),
            ),
            resolver(
                17,
                nsid("r3003.lax", chaos::refusing(Refused)),
                Ipv4Addr::new(208, 67, 219, 130),
            ),
        ];
        let resolvers = PUBLIC_RESOLVERS
            .iter()
            .zip(resolvers)
            .map(|(resolver, site)| (IpAddr::V4(resolver.addresses[0].v4), site))
            .collect();
        Place {
            servers,
            resolvers,
            authority_rtt: ms(20),
        }
    }
}
