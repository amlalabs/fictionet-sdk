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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::{Ede, EdeCode};
use fictionet::stdlib::services::dns::authority::{
    ChaosAnswer, ChaosReply, Identity, ServerConfig, chaos,
};
use fictionet::stdlib::services::dns::resolver::ROOT_SERVERS;
use fictionet::stdlib::world::net::dns::internet::{self, Echo, GTLD_SERVERS};
use fictionet::stdlib::world::net::{Host, Program};

use super::bind;
use super::public::{self, PUBLIC_RESOLVERS, PublicResolver};
use super::roots;

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
    /// The address its own questions to authorities leave from, which
    /// Google's whoami answer and servers that echo the asker show.
    pub egress: IpAddr,
}

/// Where a world's network is on the internet: the round trips to
/// servers, and which anycast instance answers each server address there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    /// Authoritative servers by IPv4 address.
    pub servers: BTreeMap<IpAddr, Site>,
    /// Public resolvers by their primary IPv4 address.
    pub resolvers: BTreeMap<IpAddr, ResolverSite>,
    /// The round trip to any other authoritative server, such as one a
    /// [`Mirror`](internet::Mirror) places.
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
    pub fn resolver(&self, addr: IpAddr) -> ResolverSite {
        self.resolvers
            .get(&addr)
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
    /// ([`internet::gtld_servers`]): each host behind [`Host::delay`] with
    /// half its round trip, running `program` with the server's front and
    /// its identity here.
    pub fn gtld_servers<P: Program>(&self, program: impl Fn(ServerConfig) -> P) -> Vec<Host> {
        internet::gtld_servers(|server, host| {
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
            let site = self.resolver(IpAddr::V4(resolver.addresses[0].v4));
            let host = host.delay(site.rtt / 2);
            build(resolver, &site, host)
        })
    }

    /// The [`Echo`] for a mirror whose upstream asks from `upstream`: each
    /// address of each public resolver is shown its resolver's
    /// [`egress`](ResolverSite::egress) from here.
    pub fn echo(&self, upstream: Ipv4Addr) -> Echo {
        PUBLIC_RESOLVERS
            .iter()
            .flat_map(|resolver| {
                let egress = self.resolver(IpAddr::V4(resolver.addresses[0].v4)).egress;
                resolver.addresses.iter().flat_map(move |address| {
                    [
                        (IpAddr::V4(address.v4), egress),
                        (IpAddr::V6(address.v6), egress),
                    ]
                })
            })
            .fold(Echo::new(upstream), |echo, (client, egress)| {
                echo.client(client, egress)
            })
    }

    /// The San Francisco Bay Area, as every root letter, `gtld-servers.net`
    /// server, and public resolver answered there on 2026-11-01: the
    /// median of five round trips to each, the instance names it gave for
    /// `id.server`, `hostname.bind`, `version.bind`, and `version.server`
    /// and their TTL, its NSID, and the RCODE it gave for other CHAOS
    /// names. What each gives `id.server` CH A, whether its TXT answers
    /// set AA, and the payload of its CHAOS replies are as seen there on
    /// 2026-11-02. Instances are the ones anycast picked there that day,
    /// so some sit far away: k.root answered from London. Other
    /// authorities took 20 ms, the median over six of them.
    pub fn san_francisco_bay_area() -> Place {
        use ResponseCode::{NoError, NotImp, Refused, ServFail};
        let txt = |text: &str| ChaosAnswer::Txt(text.to_string());
        let no = |rcode| ChaosAnswer::Reply(ChaosReply::rcode(rcode));
        // The names below, in order: id.server, hostname.bind,
        // version.bind, version.server. Other types get REFUSED, and TXT
        // answers leave AA clear, as NSD and Knot do.
        let identity = |nsid: &str, unlisted: ResponseCode, answers: [ChaosAnswer; 4]| {
            let names = [
                chaos::id_server(),
                chaos::hostname_bind(),
                chaos::version_bind(),
                chaos::version_server(),
            ];
            let mut identity = Identity {
                unlisted: ChaosReply::rcode(unlisted),
                nsid: Some(nsid.as_bytes().to_vec()),
                ..Identity::none()
            };
            for (name, answer) in names.into_iter().zip(answers) {
                identity = identity.answer(name, answer);
            }
            identity
        };
        let ms = Duration::from_millis;
        // BIND serves each of its names with text as a zone, and G runs it
        // too.
        let zones = |identity: Identity| Identity {
            chaos: identity
                .chaos
                .into_iter()
                .map(|(name, answer)| match answer {
                    ChaosAnswer::Txt(text) => {
                        let zone = bind::chaos_zone(&name, Some(text));
                        (name, zone)
                    }
                    answer => (name, answer),
                })
                .collect(),
            ..identity
        };
        // C, I, and M also serve `authors.bind`, a zone with no TXT.
        let bind = |identity: Identity| {
            let authors = chaos::authors_bind();
            let zone = bind::chaos_zone(&authors, None);
            zones(identity).answer(authors, zone)
        };
        // Verisign's servers answer other types with NOTIMP and no OPT
        // record. Its root letter sets AA; its gTLD servers do not.
        let verisign = |identity: Identity| Identity {
            other_types: ChaosReply {
                edns: false,
                ..ChaosReply::rcode(NotImp)
            },
            ..identity
        };
        // E and F answer other types with NOTIMP and EDE 21, and advertise
        // 512 octets.
        let not_supported = |identity: Identity| Identity {
            aa: true,
            other_types: ChaosReply {
                ede: Some(Ede {
                    code: EdeCode::NOT_SUPPORTED,
                    text: Some("Unsupported DNS Type for Class CHAOS".to_string()),
                }),
                ..ChaosReply::rcode(NotImp)
            },
            payload: Some(512),
            ..identity
        };
        let letters = [
            (
                32,
                Identity {
                    aa: true,
                    ..verisign(identity(
                        "a.r.ussea-4c",
                        NoError,
                        [
                            txt("nnn1-ussea-4c"),
                            txt("nnn1-ussea-4c"),
                            txt("ATLAS"),
                            txt("ATLAS"),
                        ],
                    ))
                },
            ),
            (
                72,
                identity(
                    "b1-iad",
                    Refused,
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
                not_supported(identity(
                    "c01.SEA.eroot",
                    NotImp,
                    [
                        txt("c01.SEA.eroot"),
                        txt("c01.SEA.eroot"),
                        txt("2026.10.4"),
                        no(NotImp),
                    ],
                ))
                .ttl(60),
            ),
            (
                9,
                not_supported(identity(
                    "SJC.cf.f.root-servers.org",
                    NotImp,
                    [
                        txt("SJC.cf.f.root-servers.org"),
                        txt("SJC.cf.f.root-servers.org"),
                        txt("2026.10.4"),
                        no(NotImp),
                    ],
                ))
                .ttl(60),
            ),
            (
                48,
                zones(identity(
                    "groot-con2-3",
                    Refused,
                    [no(Refused), txt("groot-con2-2"), no(Refused), no(Refused)],
                )),
            ),
            (
                21,
                // H adds EDE 21 to its REFUSED.
                Identity {
                    other_types: ChaosReply {
                        ede: Some(Ede::new(EdeCode::NOT_SUPPORTED)),
                        ..ChaosReply::rcode(Refused)
                    },
                    ..identity(
                        "001.nzy.h.root-servers.org",
                        Refused,
                        [
                            txt("001.nzy.h.root-servers.org"),
                            txt("001.nzy.h.root-servers.org"),
                            txt("NSD 4.x"),
                            txt("NSD 4.x"),
                        ],
                    )
                },
            ),
            (
                7,
                bind(identity(
                    "s1.pix",
                    Refused,
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
                    [txt("M-SJC-4"), txt("M-SJC-4"), txt("9.16"), no(Refused)],
                )),
            ),
        ];
        // Every gtld-servers.net server answers "ATLAS" for its version.
        let atlas = |nsid: &str, id: &str, hostname: &str| {
            verisign(identity(
                nsid,
                Refused,
                [txt(id), txt(hostname), txt("ATLAS"), txt("ATLAS")],
            ))
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
        let resolver = |rtt: u64, identity: Identity, egress: IpAddr| ResolverSite {
            rtt: ms(rtt),
            identity,
            egress,
        };
        let resolvers = [
            resolver(
                7,
                // Every CHAOS question gets SERVFAIL.
                Identity {
                    other_types: ChaosReply::rcode(ServFail),
                    ..identity(
                        "gpdns-sfo",
                        ServFail,
                        [no(ServFail), no(ServFail), no(ServFail), no(ServFail)],
                    )
                },
                IpAddr::V4(Ipv4Addr::new(172, 253, 1, 21)),
            ),
            resolver(
                8,
                Identity {
                    other_types: ChaosReply::rcode(NotImp),
                    ..identity(
                        "sjc01",
                        Refused,
                        [txt("sjc10"), no(Refused), no(Refused), txt("2026.10.11")],
                    )
                },
                IpAddr::V4(Ipv4Addr::new(172, 69, 133, 100)),
            ),
            resolver(
                7,
                Identity {
                    other_types: ChaosReply::rcode(NoError),
                    ..identity(
                        "res130.pao",
                        Refused,
                        [
                            txt("res711.pao"),
                            no(ServFail),
                            txt("Q9-P-2026080500"),
                            no(ServFail),
                        ],
                    )
                    .answer(chaos::authors_bind(), no(ServFail))
                },
                IpAddr::V6(Ipv6Addr::new(0x2620, 0x171, 0xf0, 0xf0, 0, 0, 0, 0x227)),
            ),
            resolver(
                17,
                // Every CHAOS question gets REFUSED with no OPT record.
                {
                    let refused = ChaosReply {
                        edns: false,
                        ..ChaosReply::rcode(Refused)
                    };
                    let no = || ChaosAnswer::Reply(refused.clone());
                    Identity {
                        unlisted: refused.clone(),
                        other_types: refused.clone(),
                        ..identity("r3003.lax", Refused, [no(), no(), no(), no()])
                    }
                },
                IpAddr::V6(Ipv6Addr::new(0x2620, 0, 0xcc8, 0, 0, 0, 0, 0x36)),
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
