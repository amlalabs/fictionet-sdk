//! The large public resolvers as a world plays them: Google Public DNS,
//! Cloudflare's 1.1.1.1, Quad9, and OpenDNS, at their real addresses, with
//! the configuration and DNS over HTTPS answers each was seen with, and
//! their whoami names.
//!
//! [`public_resolvers`] returns one host per address pair, which a world
//! finishes with a [`Recursive`](fictionet::stdlib::world::net::dns::Recursive)
//! running [`PublicResolver::config`], and with
//! [`Fronts`] for DNS over TLS and HTTPS, given each operator's answers
//! past RFC 8484 by [`PublicResolver::doh_fronts`].
//! [`Place::public_resolvers`](super::place::Place::public_resolvers) puts
//! them as far away as a place sees them.
//!
//! ```
//! # use std::time::SystemTime;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::services::dns::WallClock;
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Recursive;
//! # use fictionet_extras::dns::place::Place;
//! # async fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let place = Place::san_francisco_bay_area();
//! let clock = WallClock { start: SystemTime::now() };
//! Net::new()
//!     .hosts(place.public_resolvers(|resolver, site, host| {
//!         let config = resolver.config(site.identity.clone());
//!         host.program(Recursive::new(config, clock).per_sandbox())
//!     }))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::dnssec::AlgorithmPolicy;
use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use fictionet::stdlib::protocols::dns::rr::rdata::{SVCB, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::services::dns::authority::{ChaosAnswer, Identity};
use fictionet::stdlib::services::dns::resolver::{Config, LocalZone};
use fictionet::stdlib::services::dns::zone::special::{
    self, alpn, dohpath, ipv4_hint, ipv6_hint, port,
};
use fictionet::stdlib::services::dns::zone::{Shown, ZoneData};
use fictionet::stdlib::services::dns::{Looked, Lookup};
use fictionet::stdlib::web::httpd::Handler;
use fictionet::stdlib::world::net::Host;
use fictionet::stdlib::world::net::dns::Upstream;
use fictionet::stdlib::world::net::dns::encrypted::Fronts;

use super::place::ResolverSite;
use super::{doh, unbound};

/// One address pair of a public resolver and the name its PTR records
/// give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolverAddress {
    /// Its IPv4 address.
    pub v4: Ipv4Addr,
    /// Its IPv6 address.
    pub v6: Ipv6Addr,
    /// The name the reverse names of both addresses point at, the first
    /// of them where they give several.
    pub ptr: &'static str,
}

/// A public recursive resolver: its addresses, the names of its DNS over
/// HTTPS service, the configuration it runs with, its whoami names, and
/// what its DNS over HTTPS service answers past RFC 8484.
#[derive(Clone, Copy, Debug)]
pub struct PublicResolver {
    /// The service's name.
    pub service: &'static str,
    /// Its primary and secondary addresses.
    pub addresses: [ResolverAddress; 2],
    /// The names of [`doh`](Self::doh), fully qualified.
    doh: &'static [&'static str],
    config: fn(Identity) -> Config,
    whoami: fn(Config, &ResolverSite, Ipv4Addr) -> Config,
    fallback: fn(Fronts) -> Arc<dyn Handler>,
}

impl PublicResolver {
    /// The names its DNS over HTTPS service answers under. The addresses
    /// the real hierarchy gives for them are where a world puts the
    /// resolver's DNS over HTTPS front
    /// ([`Mirror::front`](fictionet::stdlib::world::net::dns::internet::Mirror::front)).
    pub fn doh(&self) -> Vec<Name> {
        self.doh.iter().map(|text| name(text)).collect()
    }

    /// The subject alternative names of its DNS over TLS and HTTPS fronts'
    /// certificate: its DNS over HTTPS names, then each of its addresses as
    /// an IP SAN (RFC 5280 §4.2.1.6), so a client that connects to an
    /// address checks it as it would a name.
    pub fn sans(&self) -> Vec<String> {
        let names = self
            .doh()
            .into_iter()
            .map(|name| name.to_ascii().trim_end_matches('.').to_owned());
        let addresses = self
            .addresses
            .iter()
            .flat_map(|address| [address.v4.to_string(), address.v6.to_string()]);
        names.chain(addresses).collect()
    }

    /// The resolver's configuration, as seen on 2026-11-01, with the
    /// `identity` of the instance that answers the world.
    pub fn config(&self, identity: Identity) -> Config {
        (self.config)(identity)
    }

    /// `config` with the resolver's whoami names answered for a network
    /// that reaches the internet from `egress`, the instance at `site`
    /// asking from its own egress, as the real ones answer them. A
    /// resolver with no whoami names gets `config` as it is.
    pub fn whoami(&self, config: Config, site: &ResolverSite, egress: Ipv4Addr) -> Config {
        (self.whoami)(config, site, egress)
    }

    /// `fronts` answering DNS over HTTPS past RFC 8484 as the operator's
    /// own servers do ([`doh`]), putting JSON questions to the resolver
    /// `fronts` reach. Give it the fronts as they will serve, after
    /// [`Fronts::resolver_at`].
    pub fn doh_fronts(&self, fronts: Fronts) -> Fronts {
        let fallback = (self.fallback)(fronts.clone());
        fronts.fallback(fallback)
    }
}

/// One host per address pair of each of [`PUBLIC_RESOLVERS`], at both
/// addresses and called by its PTR name, finished by `build`. `build` is
/// called once per host and gives it its resolver, and any other ports,
/// such as DNS over TLS and HTTPS [`Fronts`] in front of that resolver's
/// handle. Each host's resolver keeps its own caches.
pub fn public_resolvers(build: impl Fn(&PublicResolver, Host) -> Host) -> Vec<Host> {
    PUBLIC_RESOLVERS
        .iter()
        .flat_map(|resolver| {
            let build = &build;
            resolver.addresses.iter().map(move |address| {
                let host = Host::new(address.ptr.trim_end_matches('.'))
                    .at(address.v4)
                    .at(address.v6);
                build(resolver, host)
            })
        })
        .collect()
}

/// Google Public DNS, Cloudflare's 1.1.1.1, Quad9, and OpenDNS, with the
/// addresses and PTR names each answered with on 2026-11-01.
pub const PUBLIC_RESOLVERS: [PublicResolver; 4] = [
    PublicResolver {
        service: "Google Public DNS",
        addresses: [
            ResolverAddress {
                v4: Ipv4Addr::new(8, 8, 8, 8),
                v6: Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                ptr: "dns.google.",
            },
            ResolverAddress {
                v4: Ipv4Addr::new(8, 8, 4, 4),
                v6: Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
                ptr: "dns.google.",
            },
        ],
        doh: &["dns.google."],
        fallback: doh::google,
        config: google,
        whoami: google_whoami,
    },
    PublicResolver {
        service: "Cloudflare 1.1.1.1",
        addresses: [
            ResolverAddress {
                v4: Ipv4Addr::new(1, 1, 1, 1),
                v6: Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
                ptr: "one.one.one.one.",
            },
            ResolverAddress {
                v4: Ipv4Addr::new(1, 0, 0, 1),
                v6: Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
                ptr: "one.one.one.one.",
            },
        ],
        doh: &["cloudflare-dns.com.", "one.one.one.one."],
        fallback: doh::cloudflare,
        config: cloudflare,
        whoami: cloudflare_whoami,
    },
    PublicResolver {
        service: "Quad9",
        addresses: [
            ResolverAddress {
                v4: Ipv4Addr::new(9, 9, 9, 9),
                v6: Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
                ptr: "dns9.quad9.net.",
            },
            ResolverAddress {
                v4: Ipv4Addr::new(149, 112, 112, 112),
                v6: Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
                ptr: "dns.quad9.net.",
            },
        ],
        doh: &["dns.quad9.net."],
        fallback: doh::quad9,
        config: quad9,
        whoami: no_whoami,
    },
    PublicResolver {
        service: "OpenDNS",
        addresses: [
            ResolverAddress {
                v4: Ipv4Addr::new(208, 67, 222, 222),
                v6: Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35),
                ptr: "resolver1.opendns.com.",
            },
            ResolverAddress {
                v4: Ipv4Addr::new(208, 67, 220, 220),
                v6: Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53),
                ptr: "resolver2.opendns.com.",
            },
        ],
        doh: &["doh.opendns.com.", "dns.opendns.com."],
        fallback: doh::opendns,
        config: opendns,
        whoami: no_whoami,
    },
];

// ---------------------------------------------------------------------------
// Configurations

/// Google Public DNS at 8.8.8.8, as observed on 2026-11-01, with the
/// site's `identity`. It serves no local zones but `resolver.arpa`,
/// which it answers with AA set and TTL 86400 from two SVCB records
/// for `dns.google`; advertises a 512-octet payload; answers RD clear
/// from its cache; sends Extended DNS Errors; and validates. Google
/// varies the case of its upstream questions. The site's identity
/// gives SERVFAIL for `id.server` and `version.bind` and carries its
/// NSID.
pub fn google(identity: Identity) -> Config {
    let google = name("dns.google.");
    Config {
        local: vec![ddr(
            vec![
                SVCB::new(1, google.clone(), vec![alpn(&["dot"])]),
                SVCB::new(2, google, vec![alpn(&["h2", "h3"]), dohpath()]),
            ],
            86400,
            true,
        )],
        payload: 512,
        case_randomise: true,
        policy: AlgorithmPolicy::iana(),
        rd0_from_cache: true,
        ede: true,
        identity,
        ..unbound::config()
    }
}

/// Cloudflare's 1.1.1.1, as observed on 2026-11-01, with the site's
/// `identity`: no local zones but `resolver.arpa`, two SVCB records
/// for `one.one.one.one` with address hints, AA clear, and TTL 300; a
/// 1232-octet payload; answers RD clear from its cache; Extended DNS
/// Errors; and validation. The site's identity answers `id.server`
/// with the site code and refuses `version.bind`.
pub fn cloudflare(identity: Identity) -> Config {
    let host = name("one.one.one.one.");
    let v4 = ipv4_hint(&[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]);
    let v6 = ipv6_hint(&[
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
    ]);
    Config {
        local: vec![ddr(
            vec![
                SVCB::new(
                    1,
                    host.clone(),
                    vec![
                        alpn(&["h2", "h3"]),
                        port(443),
                        v4.clone(),
                        v6.clone(),
                        dohpath(),
                    ],
                ),
                SVCB::new(2, host, vec![alpn(&["dot"]), port(853), v4, v6]),
            ],
            300,
            false,
        )],
        payload: 1232,
        policy: AlgorithmPolicy::iana(),
        rd0_from_cache: true,
        ede: true,
        identity,
        ..unbound::config()
    }
}

/// Quad9's 9.9.9.9, as observed on 2026-11-01, with the site's
/// `identity`: `localhost` answered locally with AA clear (A 127.0.0.1
/// and AAAA ::1); three SVCB records at `resolver.arpa` for
/// `dns.quad9.net` (DoH, DoT, and DoQ) with address hints, AA clear,
/// and TTL 60; a 512-octet payload; RD clear REFUSED; Extended DNS
/// Errors; and validation. The site's identity answers `id.server`
/// with the instance and `version.bind` with Quad9's build.
pub fn quad9(identity: Identity) -> Config {
    let host = name("dns.quad9.net.");
    let v4 = ipv4_hint(&[
        Ipv4Addr::new(9, 9, 9, 9),
        Ipv4Addr::new(149, 112, 112, 9),
        Ipv4Addr::new(149, 112, 112, 112),
    ]);
    let v6 = ipv6_hint(&[
        Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
        Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
        Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0xfe, 0x9),
    ]);
    Config {
        local: vec![
            plain(Arc::new(special::localhost(&unbound::apex()))),
            ddr(
                vec![
                    SVCB::new(
                        1,
                        host.clone(),
                        vec![alpn(&["h3", "h2"]), v4.clone(), v6.clone(), dohpath()],
                    ),
                    SVCB::new(
                        2,
                        host.clone(),
                        vec![alpn(&["dot"]), v4.clone(), v6.clone()],
                    ),
                    SVCB::new(3, host, vec![alpn(&["doq"]), v4, v6]),
                ],
                60,
                false,
            ),
        ],
        payload: 512,
        policy: AlgorithmPolicy::iana(),
        ede: true,
        identity,
        ..unbound::config()
    }
}

/// OpenDNS at 208.67.222.222, as observed on 2026-11-01, with the
/// site's `identity`: a 1410-octet payload; validation, with Extended
/// DNS Errors; RD clear answered from its cache; `localhost` and
/// `test` answered locally, with AA clear as on its `localhost`
/// answers; and six SVCB records at `_dns.resolver.arpa` with TTL 300.
/// What it does not show, such as QNAME minimisation, takes Unbound's
/// values.
pub fn opendns(identity: Identity) -> Config {
    let anycast = [
        ipv4_hint(&[
            Ipv4Addr::new(208, 67, 220, 220),
            Ipv4Addr::new(208, 67, 222, 222),
        ]),
        ipv6_hint(&[
            Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35),
            Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53),
        ]),
    ];
    let doh = [
        ipv4_hint(&[Ipv4Addr::new(146, 112, 41, 2)]),
        ipv6_hint(&[Ipv6Addr::new(0x2620, 0x119, 0xfc, 0, 0, 0, 0, 0x2)]),
    ];
    let dot = [alpn(&["dot"]), port(853)];
    let https =
        |hints: &[(SvcParamKey, SvcParamValue)]| [&[alpn(&["h2"])], hints, &[dohpath()]].concat();
    let endpoints = [
        (5, "dns.opendns.com.", [&dot[..], &anycast].concat()),
        (5, "dns.umbrella.com.", [&dot[..], &anycast].concat()),
        (10, "dns.opendns.com.", https(&anycast)),
        (10, "dns.umbrella.com.", https(&anycast)),
        (20, "doh.opendns.com.", https(&doh)),
        (20, "doh.umbrella.com.", https(&doh)),
    ];
    Config {
        local: vec![
            plain(Arc::new(special::localhost(&unbound::apex()))),
            plain(Arc::new(special::test(&unbound::apex()))),
            ddr(
                endpoints
                    .into_iter()
                    .map(|(priority, host, params)| SVCB::new(priority, name(host), params))
                    .collect(),
                300,
                false,
            ),
        ],
        payload: 1410,
        rd0_from_cache: true,
        ede: true,
        identity,
        ..unbound::config()
    }
}

/// `data` as a local zone whose answers have AA clear.
fn plain(data: Arc<dyn ZoneData>) -> LocalZone {
    LocalZone {
        data,
        keep_aa: false,
    }
}

/// `resolver.arpa` holding the resolver's encrypted `endpoints` with
/// `ttl`, for clients that discover them (RFC 9462 §4), with Unbound's
/// apex records, and AA on its answers as `keep_aa` says.
fn ddr(endpoints: Vec<SVCB>, ttl: u32, keep_aa: bool) -> LocalZone {
    let zone = special::resolver_arpa(&unbound::apex(), endpoints, ttl);
    LocalZone {
        data: Arc::new(zone),
        keep_aa,
    }
}

// ---------------------------------------------------------------------------
// Whoami names

/// Google Public DNS, with `o-o.myaddr.l.google.com` answered as the
/// real one is: Google's authority there sees Google's own egress address
/// and the client's subnet (RFC 7871), so a copy of its records could
/// never give it.
fn google_whoami(config: Config, site: &ResolverSite, egress: Ipv4Addr) -> Config {
    config.local(plain(Arc::new(myaddr(site.egress, egress))))
}

/// Cloudflare's 1.1.1.1, answering `whoami.cloudflare` CH TXT with the
/// network's egress address, the address the real one would see.
fn cloudflare_whoami(mut config: Config, _site: &ResolverSite, egress: Ipv4Addr) -> Config {
    let whoami = ChaosAnswer::Txt(egress.to_string());
    config.identity = config.identity.answer(whoami_cloudflare(), whoami);
    config
}

/// A resolver with no whoami names of its own.
fn no_whoami(config: Config, _site: &ResolverSite, _egress: Ipv4Addr) -> Config {
    config
}

/// `whoami.cloudflare.`, which 1.1.1.1 answers in the CHAOS class with the
/// address the question came from.
fn whoami_cloudflare() -> LowerName {
    LowerName::new(&name("whoami.cloudflare."))
}

/// `o-o.myaddr.l.google.com` TXT as Google's resolver answers it for a
/// client behind `egress`: TXT records with the client's /24 as Google
/// sends it in EDNS Client Subnet, and the address Google asked from, with
/// TTL 60. The zone knows nothing else there, so every other type and
/// every name below is asked of the real hierarchy, as the real resolver
/// does, and the TXT answer leaves without AA, as the real one does.
fn myaddr(google: IpAddr, egress: Ipv4Addr) -> Shown {
    const TTL: u32 = 60;
    let owner = name(MYADDR);
    let subnet = Ipv4Addr::from(u32::from(egress) & 0xffff_ff00);
    let records = [
        format!("edns0-client-subnet {subnet}/24"),
        google.to_string(),
    ]
    .map(|text| Record::from_rdata(owner.clone(), TTL, RData::TXT(TXT::new(vec![text]))));
    let mut txt = RecordSet::with_ttl(owner.clone(), RecordType::TXT, TTL);
    txt.set_records(records.to_vec());
    Shown::new(&owner, [txt]).expect("the TXT RRset is owned by o-o.myaddr.l.google.com")
}

/// Google's name for asking which address a question came from.
const MYADDR: &str = "o-o.myaddr.l.google.com.";

/// `ns1.google.com`, which answers a TXT question for [`MYADDR`] with the
/// address the question came from.
const MYADDR_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)), 53);

/// The public address `upstream` asks the internet from, as a real
/// authority sees it: the answer `ns1.google.com` gives for
/// `o-o.myaddr.l.google.com` TXT. `None` when the server cannot be
/// reached or its answer holds no address. A world that shows the real
/// internet passes it to [`PublicResolver::whoami`] and
/// [`Mirror::egress`](fictionet::stdlib::world::net::dns::internet::Mirror::egress).
pub async fn egress(fcx: &Cx, upstream: &dyn Upstream) -> Option<IpAddr> {
    myaddr_at(fcx, upstream, MYADDR_SERVER).await
}

/// The address `server` says a [`MYADDR`] question came from.
async fn myaddr_at(fcx: &Cx, upstream: &dyn Upstream, server: SocketAddr) -> Option<IpAddr> {
    let question = Query::query(name(MYADDR), RecordType::TXT);
    let zone = LowerName::new(&name("google.com."));
    let Looked::Response(response) = upstream
        .lookup(fcx, Lookup::new(server, zone, &question))
        .await
    else {
        return None;
    };
    response
        .answers
        .into_iter()
        .find_map(|record| match record.data {
            RData::TXT(txt) => txt
                .txt_data
                .iter()
                .find_map(|text| IpAddr::from_str(std::str::from_utf8(text).ok()?).ok()),
            _ => None,
        })
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a public resolver's name is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::protocols::dns::op::{Message, OpCode};
    use fictionet_host::dns::Internet;
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn egress_is_the_address_in_the_whoami_answer() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let server = udp.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0; 1232];
            let (length, client) = udp.recv_from(&mut buffer).unwrap();
            let question = Message::from_vec(&buffer[..length]).unwrap();
            assert_eq!(question.queries[0].name().to_ascii(), MYADDR);
            assert_eq!(question.queries[0].query_type(), RecordType::TXT);
            let mut reply = Message::response(question.metadata.id, OpCode::Query);
            reply.metadata.authoritative = true;
            reply.add_query(question.queries[0].clone());
            reply.add_answer(Record::from_rdata(
                name(MYADDR),
                60,
                RData::TXT(TXT::new(vec!["203.0.113.9".to_string()])),
            ));
            udp.send_to(&reply.to_vec().unwrap(), client).unwrap();
        });
        fictionet::block_on(fictionet::run(Seed::from_u64(1), |fcx| async move {
            let internet = Internet::new();
            let found = myaddr_at(&fcx, &internet, server).await;
            assert_eq!(found, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));
            Ok(())
        }))
        .unwrap();
        server_thread.join().unwrap();
    }
}
