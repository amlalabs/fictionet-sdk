//! The internet's DNS as presets: the root and `gtld-servers.net` servers,
//! the large public resolvers, and a [`Mirror`] that relays the real
//! hierarchy through machines at the real servers' addresses.
//!
//! Each preset returns hosts at the addresses real clients know, so a
//! guest that asks `198.41.0.4` or `8.8.8.8` directly reaches them. What
//! runs on them is the world's choice: a world with its own root serves
//! zones, and a world that shows the real internet relays it.
//!
//! ```
//! # use std::time::SystemTime;
//! # use std::net::Ipv4Addr;
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::services::dns::WallClock;
//! # use fictionet::stdlib::services::dns::authority::{Authority, Zones};
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Authoritative;
//! # use fictionet::stdlib::world::net::dns::internet::{self, Egress, Location};
//! # async fn world(fcx: Cx, attachments: Attachments, root: &str) -> Result {
//! let at = Location::san_francisco_bay_area(Egress(Ipv4Addr::new(198, 51, 100, 7)));
//! let clock = WallClock { start: SystemTime::now() };
//! let root = Arc::new(internet::root_zone(root)?);
//! Net::new()
//!     .hosts(internet::root_servers(|s| Authoritative::new(Zones::new(vec![root.clone()]), s), &at))
//!     .hosts(internet::public_resolvers(|r, h| h.program(r.recursive(&at, clock)), &at))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```
//!
//! The addresses, names, and server identities here were read on
//! 2026-11-01: the root servers from IANA's `named.root`, the rest from
//! the servers themselves, asked from the San Francisco Bay Area.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::protocols::dns::op::{Message, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{
    Alpn, IpHint, SvcParamKey, SvcParamValue, Unknown,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, AAAA, NS, SOA, SVCB, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Request, Response};
use fictionet::stdlib::services::dns::authority::{
    Authority, ChaosAnswer, Identity, Known, Relay, ServerConfig, Step, chaos,
};
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::stdlib::services::dns::zone::{AnyResponse, Zone, ZoneError, special};
use fictionet::stdlib::services::dns::{Client, Generation, WallClock};
use fictionet::sync::Mutex;

pub use fictionet::stdlib::services::dns::resolver::root_hints;

use super::super::{Host, NetHandle, Program};
use super::{Authoritative, Namespace, Recursive, Source};

// ---------------------------------------------------------------------------
// Servers and their addresses

/// A name server and its two addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameServer {
    /// Its name, fully qualified, as the zone that names it writes it.
    pub host: &'static str,
    /// Its IPv4 address.
    pub v4: Ipv4Addr,
    /// Its IPv6 address.
    pub v6: Ipv6Addr,
}

impl NameServer {
    /// Its name.
    pub fn name(&self) -> Name {
        name(self.host)
    }

    /// Both of its addresses, IPv4 first.
    pub fn addresses(&self) -> [IpAddr; 2] {
        [IpAddr::V4(self.v4), IpAddr::V6(self.v6)]
    }

    /// A host at both addresses running `program`, with a round trip from
    /// the network `rtt` longer.
    fn host(&self, program: impl Program, rtt: Duration) -> Host {
        Host::new(self.host.trim_end_matches('.'))
            .at(self.v4)
            .at(self.v6)
            .delay(rtt / 2)
            .program(program)
    }
}

/// One of the thirteen root server letters, with what its operator's
/// software does wherever it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Letter {
    /// `<letter>.root-servers.net.` and its addresses.
    pub server: NameServer,
    /// Who runs it, as root-servers.org lists it.
    pub operator: &'static str,
    /// The EDNS payload size its replies advertise (RFC 6891 §6.2.5).
    pub payload: u16,
    /// What it sends for QTYPE ANY at the root (RFC 8482 §4).
    pub any: AnyResponse,
}

const fn letter(
    host: &'static str,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    operator: &'static str,
    payload: u16,
    any: AnyResponse,
) -> Letter {
    Letter {
        server: NameServer { host, v4, v6 },
        operator,
        payload,
        any,
    }
}

/// The root servers, in letter order. Addresses from IANA's `named.root`,
/// "last update: October 28, 2026"; operators from root-servers.org. The
/// payload sizes and ANY answers were seen at each letter on 2026-11-01:
/// b, j, and k answer `. ANY` with the NS RRset alone, h and l with the
/// SOA alone, and the others with every RRset. [`root_hints`] gives the
/// same addresses as resolver hints.
pub const ROOT_LETTERS: [Letter; 13] = [
    letter(
        "a.root-servers.net.",
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30),
        "Verisign",
        4096,
        AnyResponse::All,
    ),
    letter(
        "b.root-servers.net.",
        Ipv4Addr::new(170, 247, 170, 2),
        Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb),
        "USC-ISI",
        1232,
        AnyResponse::OneRrset,
    ),
    letter(
        "c.root-servers.net.",
        Ipv4Addr::new(192, 33, 4, 12),
        Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),
        "Cogent",
        1232,
        AnyResponse::All,
    ),
    letter(
        "d.root-servers.net.",
        Ipv4Addr::new(199, 7, 91, 13),
        Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),
        "University of Maryland",
        1450,
        AnyResponse::All,
    ),
    letter(
        "e.root-servers.net.",
        Ipv4Addr::new(192, 203, 230, 10),
        Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),
        "NASA Ames",
        1472,
        AnyResponse::All,
    ),
    letter(
        "f.root-servers.net.",
        Ipv4Addr::new(192, 5, 5, 241),
        Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),
        "ISC",
        1472,
        AnyResponse::All,
    ),
    letter(
        "g.root-servers.net.",
        Ipv4Addr::new(192, 112, 36, 4),
        Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),
        "US DoD (DISA)",
        1232,
        AnyResponse::All,
    ),
    letter(
        "h.root-servers.net.",
        Ipv4Addr::new(198, 97, 190, 53),
        Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),
        "US Army (ARL)",
        1232,
        AnyResponse::OneRrset,
    ),
    letter(
        "i.root-servers.net.",
        Ipv4Addr::new(192, 36, 148, 17),
        Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),
        "Netnod",
        1232,
        AnyResponse::All,
    ),
    letter(
        "j.root-servers.net.",
        Ipv4Addr::new(192, 58, 128, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),
        "Verisign",
        1472,
        AnyResponse::OneRrset,
    ),
    letter(
        "k.root-servers.net.",
        Ipv4Addr::new(193, 0, 14, 129),
        Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1),
        "RIPE NCC",
        1232,
        AnyResponse::OneRrset,
    ),
    letter(
        "l.root-servers.net.",
        Ipv4Addr::new(199, 7, 83, 42),
        Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),
        "ICANN",
        4096,
        AnyResponse::OneRrset,
    ),
    letter(
        "m.root-servers.net.",
        Ipv4Addr::new(202, 12, 27, 33),
        Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),
        "WIDE",
        1232,
        AnyResponse::All,
    ),
];

/// `<letter>.ns.arpa.` on the root letter `index` of [`ROOT_LETTERS`].
const fn arpa(host: &'static str, index: usize) -> NameServer {
    NameServer {
        host,
        v4: ROOT_LETTERS[index].server.v4,
        v6: ROOT_LETTERS[index].server.v6,
    }
}

/// The servers of `arpa`: every root letter but j, each at the same
/// addresses as its letter, as IANA's root zone database lists them
/// (`https://www.iana.org/domains/root/db/arpa.html`). The root servers
/// answer for `arpa` themselves, so relays at the root addresses serve it.
pub const ARPA_SERVERS: [NameServer; 12] = [
    arpa("a.ns.arpa.", 0),
    arpa("b.ns.arpa.", 1),
    arpa("c.ns.arpa.", 2),
    arpa("d.ns.arpa.", 3),
    arpa("e.ns.arpa.", 4),
    arpa("f.ns.arpa.", 5),
    arpa("g.ns.arpa.", 6),
    arpa("h.ns.arpa.", 7),
    arpa("i.ns.arpa.", 8),
    arpa("k.ns.arpa.", 10),
    arpa("l.ns.arpa.", 11),
    arpa("m.ns.arpa.", 12),
];

const fn server(host: &'static str, v4: Ipv4Addr, v6: Ipv6Addr) -> NameServer {
    NameServer { host, v4, v6 }
}

/// The servers of `in-addr.arpa`, the reverse names of IPv4 addresses,
/// which IANA runs under `in-addr-servers.arpa` (RFC 5855). Addresses from
/// the glue of the `arpa` zone, asked of a.ns.arpa on 2026-11-01.
pub const IN_ADDR_SERVERS: [NameServer; 6] = [
    server(
        "a.in-addr-servers.arpa.",
        Ipv4Addr::new(199, 180, 182, 53),
        Ipv6Addr::new(0x2620, 0x37, 0xe000, 0, 0, 0, 0, 0x53),
    ),
    server(
        "b.in-addr-servers.arpa.",
        Ipv4Addr::new(199, 253, 183, 183),
        Ipv6Addr::new(0x2001, 0x500, 0x87, 0, 0, 0, 0, 0x87),
    ),
    server(
        "c.in-addr-servers.arpa.",
        Ipv4Addr::new(196, 216, 169, 10),
        Ipv6Addr::new(0x2001, 0x43f8, 0x110, 0, 0, 0, 0, 0x10),
    ),
    server(
        "d.in-addr-servers.arpa.",
        Ipv4Addr::new(200, 10, 60, 53),
        Ipv6Addr::new(0x2001, 0x13c7, 0x7010, 0, 0, 0, 0, 0x53),
    ),
    server(
        "e.in-addr-servers.arpa.",
        Ipv4Addr::new(203, 119, 86, 101),
        Ipv6Addr::new(0x2001, 0xdd8, 0x6, 0, 0, 0, 0, 0x101),
    ),
    server(
        "f.in-addr-servers.arpa.",
        Ipv4Addr::new(193, 0, 9, 1),
        Ipv6Addr::new(0x2a13, 0x27c0, 0x30, 0, 0, 0, 0, 0x1),
    ),
];

/// The servers of `ip6.arpa`, the reverse names of IPv6 addresses, under
/// `ip6-servers.arpa` (RFC 5855). Addresses from the glue of the `arpa`
/// zone, asked of a.ns.arpa on 2026-11-01.
pub const IP6_SERVERS: [NameServer; 6] = [
    server(
        "a.ip6-servers.arpa.",
        Ipv4Addr::new(199, 180, 182, 53),
        Ipv6Addr::new(0x2620, 0x37, 0xe000, 0, 0, 0, 0, 0x53),
    ),
    server(
        "b.ip6-servers.arpa.",
        Ipv4Addr::new(199, 253, 182, 182),
        Ipv6Addr::new(0x2001, 0x500, 0x86, 0, 0, 0, 0, 0x86),
    ),
    server(
        "c.ip6-servers.arpa.",
        Ipv4Addr::new(196, 216, 169, 11),
        Ipv6Addr::new(0x2001, 0x43f8, 0x110, 0, 0, 0, 0, 0x11),
    ),
    server(
        "d.ip6-servers.arpa.",
        Ipv4Addr::new(200, 7, 86, 53),
        Ipv6Addr::new(0x2001, 0x13c7, 0x7012, 0, 0, 0, 0, 0x53),
    ),
    server(
        "e.ip6-servers.arpa.",
        Ipv4Addr::new(203, 119, 86, 101),
        Ipv6Addr::new(0x2001, 0xdd8, 0x6, 0, 0, 0, 0, 0x101),
    ),
    server(
        "f.ip6-servers.arpa.",
        Ipv4Addr::new(193, 0, 9, 2),
        Ipv6Addr::new(0x2a13, 0x27c0, 0x30, 0, 0, 0, 0, 0x2),
    ),
];

/// The servers of `com` and `net`, which serve both zones, as the root
/// zone's glue gave them on 2026-11-01.
pub const GTLD_SERVERS: [NameServer; 13] = [
    server(
        "a.gtld-servers.net.",
        Ipv4Addr::new(192, 5, 6, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xa83e, 0, 0, 0, 0x2, 0x30),
    ),
    server(
        "b.gtld-servers.net.",
        Ipv4Addr::new(192, 33, 14, 30),
        Ipv6Addr::new(0x2001, 0x503, 0x231d, 0, 0, 0, 0x2, 0x30),
    ),
    server(
        "c.gtld-servers.net.",
        Ipv4Addr::new(192, 26, 92, 30),
        Ipv6Addr::new(0x2001, 0x503, 0x83eb, 0, 0, 0, 0, 0x30),
    ),
    server(
        "d.gtld-servers.net.",
        Ipv4Addr::new(192, 31, 80, 30),
        Ipv6Addr::new(0x2001, 0x500, 0x856e, 0, 0, 0, 0, 0x30),
    ),
    server(
        "e.gtld-servers.net.",
        Ipv4Addr::new(192, 12, 94, 30),
        Ipv6Addr::new(0x2001, 0x502, 0x1ca1, 0, 0, 0, 0, 0x30),
    ),
    server(
        "f.gtld-servers.net.",
        Ipv4Addr::new(192, 35, 51, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xd414, 0, 0, 0, 0, 0x30),
    ),
    server(
        "g.gtld-servers.net.",
        Ipv4Addr::new(192, 42, 93, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xeea3, 0, 0, 0, 0, 0x30),
    ),
    server(
        "h.gtld-servers.net.",
        Ipv4Addr::new(192, 54, 112, 30),
        Ipv6Addr::new(0x2001, 0x502, 0x8cc, 0, 0, 0, 0, 0x30),
    ),
    server(
        "i.gtld-servers.net.",
        Ipv4Addr::new(192, 43, 172, 30),
        Ipv6Addr::new(0x2001, 0x503, 0x39c1, 0, 0, 0, 0, 0x30),
    ),
    server(
        "j.gtld-servers.net.",
        Ipv4Addr::new(192, 48, 79, 30),
        Ipv6Addr::new(0x2001, 0x502, 0x7094, 0, 0, 0, 0, 0x30),
    ),
    server(
        "k.gtld-servers.net.",
        Ipv4Addr::new(192, 52, 178, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xd2d, 0, 0, 0, 0, 0x30),
    ),
    server(
        "l.gtld-servers.net.",
        Ipv4Addr::new(192, 41, 162, 30),
        Ipv6Addr::new(0x2001, 0x500, 0xd937, 0, 0, 0, 0, 0x30),
    ),
    server(
        "m.gtld-servers.net.",
        Ipv4Addr::new(192, 55, 83, 30),
        Ipv6Addr::new(0x2001, 0x501, 0xb1f9, 0, 0, 0, 0, 0x30),
    ),
];

// ---------------------------------------------------------------------------
// Public resolvers

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
/// HTTPS service, and the configuration it runs with.
#[derive(Clone, Copy, Debug)]
pub struct PublicResolver {
    /// The service's name.
    pub service: &'static str,
    /// Its primary and secondary addresses.
    pub addresses: [ResolverAddress; 2],
    /// The names its DNS over HTTPS service answers under. The addresses
    /// the real hierarchy gives for them are where a world puts the
    /// resolver's DoH front ([`Mirror::front`]).
    pub doh: &'static [&'static str],
    config: fn(&ResolverSite, &Egress) -> Config,
}

impl PublicResolver {
    /// The resolver's configuration as seen from `at`: its identity at
    /// the site that answers there, and its special names, the answers
    /// to its whoami names among them.
    pub fn config(&self, at: &Location) -> Config {
        let primary = IpAddr::V4(self.addresses[0].v4);
        (self.config)(&at.resolver(primary), &at.egress)
    }

    /// A resolver program with [`config`](Self::config), one engine and
    /// cache per sandbox ([`Recursive::per_sandbox`]), so sandboxes can
    /// neither warm nor probe each other's caches.
    pub fn recursive(&self, at: &Location, clock: WallClock) -> Recursive {
        Recursive::new(self.config(at), clock).per_sandbox()
    }
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
        config: google,
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
        config: cloudflare,
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
        config: quad9,
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
        config: opendns,
    },
];

/// `whoami.cloudflare.`, which 1.1.1.1 answers in the CHAOS class with the
/// address the question came from.
fn whoami_cloudflare() -> LowerName {
    LowerName::new(&name("whoami.cloudflare."))
}

/// Google Public DNS, with `o-o.myaddr.l.google.com` answered as the
/// real one is: Google's authority there sees Google's own egress address
/// and the client's subnet (RFC 7871), so a relay could never give it.
fn google(site: &ResolverSite, egress: &Egress) -> Config {
    Config::google(site.identity.clone()).local(Arc::new(myaddr(site.egress, egress)))
}

/// Cloudflare's 1.1.1.1, answering `whoami.cloudflare` CH TXT with the
/// world's egress address, the address the real one would see.
fn cloudflare(site: &ResolverSite, egress: &Egress) -> Config {
    let whoami = ChaosAnswer::Txt(egress.0.to_string());
    Config::cloudflare(site.identity.clone().answer(whoami_cloudflare(), whoami))
}

/// Quad9, as its preset is.
fn quad9(site: &ResolverSite, _egress: &Egress) -> Config {
    Config::quad9(site.identity.clone())
}

/// OpenDNS, as seen on 2026-11-01: a 1410-octet payload; validation, with
/// Extended DNS Errors; RD clear answered from its cache; `localhost` and
/// `test` answered locally, with AA clear as on its `localhost` answers;
/// and six SVCB records at `_dns.resolver.arpa` with TTL 300. It refuses
/// every CHAOS name. What it does not show, such as QNAME minimisation, takes
/// Unbound's values.
fn opendns(site: &ResolverSite, _egress: &Egress) -> Config {
    type Param = (SvcParamKey, SvcParamValue);
    let hints = |v4: &[Ipv4Addr], v6: &[Ipv6Addr]| -> [Param; 2] {
        [
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(v4.iter().map(|a| A(*a)).collect())),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(v6.iter().map(|a| AAAA(*a)).collect())),
            ),
        ]
    };
    let anycast = hints(
        &[
            Ipv4Addr::new(208, 67, 220, 220),
            Ipv4Addr::new(208, 67, 222, 222),
        ],
        &[
            Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35),
            Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53),
        ],
    );
    let doh = hints(
        &[Ipv4Addr::new(146, 112, 41, 2)],
        &[Ipv6Addr::new(0x2620, 0x119, 0xfc, 0, 0, 0, 0, 0x2)],
    );
    let alpn = |protocol: &str| -> Param {
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec![protocol.to_string()])),
        )
    };
    // The DoH URI template, SvcParamKey 7 (RFC 9461 §5).
    let dohpath: Param = (
        SvcParamKey::Unknown(7),
        SvcParamValue::Unknown(Unknown(b"/dns-query{?dns}".to_vec())),
    );
    let dot = [alpn("dot"), (SvcParamKey::Port, SvcParamValue::Port(853))];
    let https = |hints: &[Param]| [&[alpn("h2")], hints, std::slice::from_ref(&dohpath)].concat();
    let endpoints: [(u16, &str, Vec<Param>); 6] = [
        (5, "dns.opendns.com.", [&dot[..], &anycast].concat()),
        (5, "dns.umbrella.com.", [&dot[..], &anycast].concat()),
        (10, "dns.opendns.com.", https(&anycast)),
        (10, "dns.umbrella.com.", https(&anycast)),
        (20, "doh.opendns.com.", https(&doh)),
        (20, "doh.umbrella.com.", https(&doh)),
    ];
    let ddr = endpoints
        .into_iter()
        .map(|(priority, host, params)| SVCB::new(priority, name(host), params))
        .collect();
    Config {
        local: vec![Arc::new(special::localhost()), Arc::new(special::test())],
        local_aa: false,
        payload: 1410,
        rd0_from_cache: true,
        ede: true,
        identity: site.identity.clone(),
        ddr,
        ddr_ttl: 300,
        ..Config::unbound()
    }
}

/// `o-o.myaddr.l.google.com` as Google's resolver answers it for a client
/// behind `egress`: TXT records with the client's /24 as Google sends it
/// in EDNS Client Subnet, and the address Google asked from, with TTL 60.
fn myaddr(google: IpAddr, egress: &Egress) -> Zone {
    const TTL: u32 = 60;
    let apex = name("o-o.myaddr.l.google.com.");
    let subnet = Ipv4Addr::from(u32::from(egress.0) & 0xffff_ff00);
    let rrset = |rdata: Vec<RData>| {
        let mut set = RecordSet::with_ttl(apex.clone(), rdata[0].record_type(), TTL);
        let records = rdata
            .into_iter()
            .map(|data| Record::from_rdata(apex.clone(), TTL, data))
            .collect();
        set.set_records(records);
        set
    };
    let txt = |text: String| RData::TXT(TXT::new(vec![text]));
    let soa = SOA::new(
        apex.clone(),
        name("nobody.invalid."),
        1,
        3600,
        1200,
        604800,
        TTL,
    );
    Zone::builder(apex.clone(), soa, TTL)
        .rrset(rrset(vec![RData::NS(NS(apex.clone()))]))
        .rrset(rrset(vec![
            txt(format!("edns0-client-subnet {subnet}/24")),
            txt(google.to_string()),
        ]))
        .build()
        .expect("o-o.myaddr.l.google.com is a well-formed zone")
}

// ---------------------------------------------------------------------------
// Where the world is

/// The public IPv4 address the world's network reaches the internet from,
/// as servers that echo a client's address see it. The whoami names of
/// the public resolver presets answer with it. Under a live source it is
/// the host's own public address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Egress(pub Ipv4Addr);

/// How one anycast server looks from a location: the round trip to the
/// instance that answers there, and what that instance says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The round trip from the network to the server.
    pub rtt: Duration,
    /// Its answers to CHAOS-class questions and its NSID (RFC 5001).
    pub identity: Identity,
}

/// How a public resolver looks from a location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverSite {
    /// The round trip from the network to the resolver.
    pub rtt: Duration,
    /// Its answers to CHAOS-class questions and its NSID.
    pub identity: Identity,
    /// The address its own questions to authorities leave from, which
    /// Google's whoami answer shows.
    pub egress: IpAddr,
}

/// Where a world's network is on the internet: the round trips to
/// servers, and which anycast instance answers each server address there,
/// which an agent can read with `dig +nsid` or `id.server` CH TXT. These
/// must agree with the network's [`Egress`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// Authoritative servers by IPv4 address.
    pub servers: BTreeMap<IpAddr, Site>,
    /// Public resolvers by their primary IPv4 address.
    pub resolvers: BTreeMap<IpAddr, ResolverSite>,
    /// The round trip to any other authoritative server, such as one a
    /// [`Mirror`] places.
    pub authority_rtt: Duration,
    /// The address the network reaches the internet from.
    pub egress: Egress,
}

impl Location {
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
    /// [`authority_rtt`](Self::authority_rtt), and asks from its own address.
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

    /// The San Francisco Bay Area, reaching the internet from `egress`, as
    /// every root letter, `gtld-servers.net` server, and public resolver
    /// answered there on 2026-11-01: the median of five round trips to
    /// each, the instance names it gave for `id.server`, `hostname.bind`,
    /// `version.bind`, and `version.server` and their TTL, its NSID, and
    /// the RCODE it gave for other CHAOS names. Instances are the ones anycast picked
    /// there that day, so some sit far away: k.root answered from London.
    /// Other authorities took 20 ms, the median over six of them.
    pub fn san_francisco_bay_area(egress: Egress) -> Location {
        use ResponseCode::{NoError, NotImp, Refused, ServFail};
        let txt = |text: &str| ChaosAnswer::Txt(text.to_string());
        let no = ChaosAnswer::Rcode;
        // The names below, in order: id.server, hostname.bind,
        // version.bind, version.server.
        let identity = |nsid: &str, unlisted: ResponseCode, answers: [ChaosAnswer; 4]| {
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
                identity = identity.answer(name, answer);
            }
            identity
        };
        let ms = Duration::from_millis;
        // C, I, and M run BIND, whose `authors.bind` is a name with no TXT.
        let bind = |identity: Identity| identity.answer(chaos::authors_bind(), no(NoError));
        let letters = [
            (
                32,
                identity(
                    "a.r.ussea-4c",
                    NoError,
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
                identity(
                    "c01.SEA.eroot",
                    NotImp,
                    [
                        txt("c01.SEA.eroot"),
                        txt("c01.SEA.eroot"),
                        txt("2026.10.4"),
                        no(NotImp),
                    ],
                )
                .ttl(60),
            ),
            (
                9,
                identity(
                    "SJC.cf.f.root-servers.org",
                    NotImp,
                    [
                        txt("SJC.cf.f.root-servers.org"),
                        txt("SJC.cf.f.root-servers.org"),
                        txt("2026.10.4"),
                        no(NotImp),
                    ],
                )
                .ttl(60),
            ),
            (
                48,
                identity(
                    "groot-con2-3",
                    Refused,
                    [no(Refused), txt("groot-con2-2"), no(Refused), no(Refused)],
                ),
            ),
            (
                21,
                identity(
                    "001.nzy.h.root-servers.org",
                    Refused,
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
            identity(
                nsid,
                Refused,
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
        let servers = ROOT_LETTERS
            .iter()
            .map(|letter| letter.server)
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
                // Every CHAOS name gets SERVFAIL.
                identity(
                    "gpdns-sfo",
                    ServFail,
                    [no(ServFail), no(ServFail), no(ServFail), no(ServFail)],
                ),
                IpAddr::V4(Ipv4Addr::new(172, 253, 1, 21)),
            ),
            resolver(
                8,
                identity(
                    "sjc01",
                    Refused,
                    [txt("sjc10"), no(Refused), no(Refused), txt("2026.10.11")],
                ),
                IpAddr::V4(Ipv4Addr::new(172, 69, 133, 100)),
            ),
            resolver(
                7,
                identity(
                    "res130.pao",
                    Refused,
                    [
                        txt("res711.pao"),
                        no(ServFail),
                        txt("Q9-P-2026080500"),
                        no(ServFail),
                    ],
                )
                .answer(chaos::authors_bind(), no(ServFail)),
                IpAddr::V6(Ipv6Addr::new(0x2620, 0x171, 0xf0, 0xf0, 0, 0, 0, 0x227)),
            ),
            resolver(
                17,
                identity(
                    "r3003.lax",
                    Refused,
                    [no(Refused), no(Refused), no(Refused), no(Refused)],
                ),
                IpAddr::V6(Ipv6Addr::new(0x2620, 0, 0xcc8, 0, 0, 0, 0, 0x36)),
            ),
        ];
        let resolvers = PUBLIC_RESOLVERS
            .iter()
            .zip(resolvers)
            .map(|(resolver, site)| (IpAddr::V4(resolver.addresses[0].v4), site))
            .collect();
        Location {
            servers,
            resolvers,
            authority_rtt: ms(20),
            egress,
        }
    }
}

// ---------------------------------------------------------------------------
// Presets that return hosts

/// One host per root letter, at both of its addresses, each machine
/// running `program` with the letter's server front: its identity at
/// `at`, its payload size, and its answer to ANY. Each sits behind
/// [`Host::delay`] with half its round trip from `at`, so a guest's
/// `dig @198.41.0.4` and a resolver's own question take the same time.
pub fn root_servers<P: Program>(program: impl Fn(ServerConfig) -> P, at: &Location) -> Vec<Host> {
    ROOT_LETTERS
        .iter()
        .map(|letter| {
            let site = at.site(IpAddr::V4(letter.server.v4));
            let server = ServerConfig {
                payload: letter.payload,
                any: letter.any,
                ..ServerConfig::root(site.identity)
            };
            letter.server.host(program(server), site.rtt)
        })
        .collect()
}

/// One host per `gtld-servers.net` server, at both of its addresses, each
/// machine running `program` with the server's front at `at`, behind
/// [`Host::delay`] with half its round trip.
pub fn gtld_servers<P: Program>(program: impl Fn(ServerConfig) -> P, at: &Location) -> Vec<Host> {
    GTLD_SERVERS
        .iter()
        .map(|server| {
            let site = at.site(IpAddr::V4(server.v4));
            server.host(program(ServerConfig::gtld(site.identity)), site.rtt)
        })
        .collect()
}

/// One host per address pair of each of [`PUBLIC_RESOLVERS`], at both
/// addresses and behind [`Host::delay`] with half its round trip from
/// `at`, finished by `build`. `build` is called once per host and gives it
/// its resolver, usually [`PublicResolver::recursive`], and any other
/// ports, such as the [`encrypted`](super::encrypted) fronts in front of
/// that resolver's [`handle`](Recursive::handle). Each host's resolver
/// keeps its own caches.
pub fn public_resolvers(build: impl Fn(&PublicResolver, Host) -> Host, at: &Location) -> Vec<Host> {
    PUBLIC_RESOLVERS
        .iter()
        .flat_map(|resolver| {
            let site = at.resolver(IpAddr::V4(resolver.addresses[0].v4));
            let build = &build;
            resolver.addresses.iter().map(move |address| {
                let host = Host::new(address.ptr.trim_end_matches('.'))
                    .at(address.v4)
                    .at(address.v6)
                    .delay(site.rtt / 2);
                build(resolver, host)
            })
        })
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

// ---------------------------------------------------------------------------
// Mirror

/// A callback that sees each relayed reply.
type Observer = dyn Fn(&Request, &Client, &Response) + Send + Sync;

/// What a world puts around each relay's authority.
type Wrap = dyn Fn(Arc<dyn Authority>) -> Arc<dyn Authority> + Send + Sync;

/// What a world places at the addresses of one name.
type Front = dyn Fn(Host) -> Host + Send + Sync;

/// Relays for the real hierarchy: the root, `arpa`, `com`, `net`, and every
/// server below them that a relayed reply names.
///
/// [`relay`](Mirror::relay) is a program that passes on what the real
/// server at its own address answers, through the mirror's source, as
/// [`Relay`] does. A world runs it on the root and `gtld-servers.net`
/// presets. As replies pass, the mirror places more relays, so a resolver
/// in the world can follow the hierarchy as far down as the source
/// answers:
///
/// - at each address a reply gives as glue for a name server it names
///   (RFC 9471), and
/// - at each address answering an A or AAAA question for a name that a
///   relayed NS RRset named this session, for a delegation without glue,
///   such as a `.com` zone served from `awsdns-NN.org` or
///   `8.in-addr.arpa` served from `arin.net`.
///
/// Each relay is placed before the reply that names it leaves, behind
/// [`Host::delay`] with half the location's
/// [`authority_rtt`](Location::authority_rtt). Where a host's machine is
/// already, such as a site placed first, the relay joins it; where a
/// relay or a preset's server already answers, nothing more is placed.
/// A relay joining a machine takes its port 53, so a world puts no DNS
/// server of its own at an address the real hierarchy names. The names of
/// name servers are forgotten when the namespace advances.
///
/// Addresses on the sandboxes' subnet or a LAN, and addresses no
/// internet host can have (those the IANA special-purpose registries of
/// RFC 6890 mark not globally reachable), are never placed: the reply
/// still reaches the client as it was, and the address stays unreachable.
/// The public resolvers' addresses get no relay either: a world runs the
/// resolvers there.
#[derive(Clone)]
pub struct Mirror {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    source: Arc<dyn Source>,
    handle: NetHandle,
    delay: Duration,
    namespace: Option<Namespace>,
    observers: Vec<Arc<Observer>>,
    wrap: Option<Arc<Wrap>>,
    fronts: Vec<(LowerName, Arc<Front>)>,
    seen: Arc<Mutex<Seen>>,
}

/// What a mirror has seen of the hierarchy.
struct Seen {
    /// The session `targets` belong to.
    generation: Generation,
    /// The name server names relayed replies gave this session.
    targets: HashSet<LowerName>,
    /// Addresses given a relay, or found unable to take one.
    relays: HashSet<IpAddr>,
    /// Addresses given a front.
    fronts: HashSet<IpAddr>,
}

impl Mirror {
    /// A mirror asking `source` what the real servers answer, placing
    /// relays with `handle`, behind the round trip `at` gives other
    /// authorities.
    pub fn new(source: impl Source, handle: NetHandle, at: &Location) -> Mirror {
        Mirror {
            inner: Arc::new(Inner {
                source: Arc::new(source),
                handle,
                delay: at.authority_rtt / 2,
                namespace: None,
                observers: Vec::new(),
                wrap: None,
                fronts: Vec::new(),
                seen: Arc::new(Mutex::new(Seen {
                    generation: Generation(0),
                    targets: HashSet::new(),
                    relays: HashSet::new(),
                    fronts: HashSet::new(),
                })),
            }),
        }
    }

    /// The same mirror, changed by `change`. Relays made before keep what
    /// they had.
    fn with(self, change: impl FnOnce(&mut Inner)) -> Mirror {
        let mut inner = Arc::unwrap_or_clone(self.inner);
        change(&mut inner);
        Mirror {
            inner: Arc::new(inner),
        }
    }

    /// Relays for the sessions of `namespace`: when it advances, every
    /// relay abandons its questions, and the mirror forgets the name
    /// servers it has seen named.
    pub fn namespace(self, namespace: &Namespace) -> Mirror {
        self.with(|inner| inner.namespace = Some(namespace.clone()))
    }

    /// Calls `f` with each relayed reply, before it leaves and after the
    /// relays it names are placed. Observers run in the order given.
    pub fn observe(
        self,
        f: impl Fn(&Request, &Client, &Response) + Send + Sync + 'static,
    ) -> Mirror {
        self.with(|inner| inner.observers.push(Arc::new(f)))
    }

    /// Wraps the authority of every relay the mirror makes, such as with
    /// an [`Overlay`](fictionet::stdlib::services::dns::authority::Overlay)
    /// for an invented zone.
    pub fn wrap(
        self,
        f: impl Fn(Arc<dyn Authority>) -> Arc<dyn Authority> + Send + Sync + 'static,
    ) -> Mirror {
        self.with(|inner| inner.wrap = Some(Arc::new(f)))
    }

    /// Places `build(host)` at each address a relayed reply gives for
    /// `name` in an A or AAAA answer, the first time it gives it, joining
    /// a machine that is there. `host` is a host at that address only, and
    /// an address no internet host can have gets none, as with relays. A
    /// world uses it for a public resolver's DNS over HTTPS front at the
    /// addresses of [`PublicResolver::doh`] names, such as
    /// `cloudflare-dns.com`, which are not the resolver's own.
    pub fn front(self, name: Name, build: impl Fn(Host) -> Host + Send + Sync + 'static) -> Mirror {
        let name = LowerName::new(&name);
        self.with(|inner| inner.fronts.push((name, Arc::new(build))))
    }

    /// A program relaying to the real server at its own address, with
    /// `server` as its front, the mirror's source and namespace, and its
    /// observers.
    pub fn relay(&self, server: ServerConfig) -> Authoritative<Arc<dyn Authority>> {
        self.inner.relay(server)
    }
}

impl Inner {
    fn relay(self: &Arc<Self>, server: ServerConfig) -> Authoritative<Arc<dyn Authority>> {
        let mirrored: Arc<dyn Authority> = Arc::new(Mirrored(self.clone()));
        let authority = match &self.wrap {
            Some(wrap) => wrap(mirrored),
            None => mirrored,
        };
        let program = Authoritative::new(authority, server).source(self.source.clone());
        match &self.namespace {
            Some(namespace) => program.namespace(namespace),
            None => program,
        }
    }

    /// Places the relays and fronts `reply`, a relayed reply to `req`,
    /// names.
    fn place(self: &Arc<Self>, req: &Request, reply: &Message) {
        let qname = LowerName::new(req.question.name());
        let asks_address = matches!(req.question.query_type(), RecordType::A | RecordType::AAAA);
        let answered: Vec<IpAddr> = reply.answers.iter().filter_map(address).collect();
        let mut relays: Vec<(IpAddr, Name)> = Vec::new();
        let mut fronts: Vec<(IpAddr, &Arc<Front>)> = Vec::new();
        {
            let mut seen = self.seen.lock();
            if let Some(namespace) = &self.namespace {
                let generation = namespace.current().generation;
                if generation != seen.generation {
                    seen.generation = generation;
                    seen.targets.clear();
                }
            }
            let named: HashSet<LowerName> = reply
                .answers
                .iter()
                .chain(&reply.authorities)
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(LowerName::new(&ns.0)),
                    _ => None,
                })
                .collect();
            for record in &reply.additionals {
                if let Some(addr) = address(record)
                    && named.contains(&LowerName::new(&record.name))
                {
                    relays.push((addr, record.name.clone()));
                }
            }
            seen.targets.extend(named);
            if asks_address && seen.targets.contains(&qname) {
                let name = req.question.name().clone();
                relays.extend(answered.iter().map(|addr| (*addr, name.clone())));
            }
            if asks_address {
                for (name, front) in &self.fronts {
                    if *name == qname {
                        fronts.extend(answered.iter().map(|addr| (*addr, front)));
                    }
                }
            }
            relays.retain(|(addr, _)| self.may_relay(*addr) && seen.relays.insert(*addr));
            fronts.retain(|(addr, _)| globally_reachable(*addr) && seen.fronts.insert(*addr));
        }
        // The network refuses an address on the sandboxes' subnet or a
        // LAN; such an address stays without a relay.
        for (addr, name) in relays {
            let host = only_at(&name.to_string(), addr)
                .delay(self.delay)
                .program(self.relay(ServerConfig::generic()));
            let _ = self.handle.add_host(host);
        }
        for (addr, build) in fronts {
            let _ = self
                .handle
                .add_host(build(only_at(&qname.to_string(), addr)));
        }
    }

    /// Whether a relay may go at `addr`: an address an internet host can
    /// have, where no public resolver is and no preset's server already
    /// answers.
    fn may_relay(&self, addr: IpAddr) -> bool {
        let resolver = PUBLIC_RESOLVERS.iter().any(|resolver| {
            resolver
                .addresses
                .iter()
                .any(|a| addr == IpAddr::V4(a.v4) || addr == IpAddr::V6(a.v6))
        });
        let preset = ROOT_LETTERS
            .iter()
            .map(|letter| &letter.server)
            .chain(&GTLD_SERVERS)
            .any(|server| server.addresses().contains(&addr));
        globally_reachable(addr) && !resolver && !(preset && self.handle.has_machine(addr))
    }
}

/// A host at `addr` and at no other address, called `label`.
fn only_at(label: &str, addr: IpAddr) -> Host {
    let host = Host::new(label.trim_end_matches('.')).at(addr);
    match addr {
        IpAddr::V4(_) => host.ipv4_only(),
        IpAddr::V6(_) => host.ipv6_only(),
    }
}

/// The address an A or AAAA record holds.
fn address(record: &Record) -> Option<IpAddr> {
    match &record.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
        _ => None,
    }
}

/// A [`Relay`] whose replies place the relays they name, then go to the
/// mirror's observers.
struct Mirrored(Arc<Inner>);

impl Authority for Mirrored {
    fn respond(
        &self,
        req: &Request,
        local: std::net::SocketAddr,
        server: &ServerConfig,
        client: &Client,
        known: &dyn Known,
    ) -> Step {
        let step = Relay::new().respond(req, local, server, client, known);
        if let Step::Verbatim(bytes) = &step
            && let Ok(message) = Message::from_vec(bytes)
        {
            self.0.place(req, &message);
            if !self.0.observers.is_empty() {
                let response = Response {
                    message,
                    required_additional: 0,
                };
                for observer in &self.0.observers {
                    observer(req, client, &response);
                }
            }
        }
        step
    }
}

// ---------------------------------------------------------------------------
// Addresses an internet host can have

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix {
    Prefix {
        addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        len,
    }
}

const fn v6(segments: [u16; 8], len: u8) -> Prefix {
    let [a, b, c, d, e, f, g, h] = segments;
    Prefix {
        addr: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
        len,
    }
}

/// The IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890),
/// read on 2026-11-01: each block and whether its addresses are globally
/// reachable. The most specific block holding an address decides. Blocks
/// the registry gives no answer for (Teredo, 6to4, and the deprecated
/// 6to4 relay and ORCHID blocks) count as not reachable.
const SPECIAL_PURPOSE: [(Prefix, bool); 50] = [
    (v4(0, 0, 0, 0, 8), false),
    (v4(10, 0, 0, 0, 8), false),
    (v4(100, 64, 0, 0, 10), false),
    (v4(127, 0, 0, 0, 8), false),
    (v4(169, 254, 0, 0, 16), false),
    (v4(172, 16, 0, 0, 12), false),
    (v4(192, 0, 0, 0, 24), false),
    (v4(192, 0, 0, 9, 32), true),
    (v4(192, 0, 0, 10, 32), true),
    (v4(192, 0, 2, 0, 24), false),
    (v4(192, 31, 196, 0, 24), true),
    (v4(192, 52, 193, 0, 24), true),
    (v4(192, 88, 99, 0, 24), false),
    (v4(192, 168, 0, 0, 16), false),
    (v4(192, 175, 48, 0, 24), true),
    (v4(198, 18, 0, 0, 15), false),
    (v4(198, 51, 100, 0, 24), false),
    (v4(203, 0, 113, 0, 24), false),
    (v4(240, 0, 0, 0, 4), false),
    (v4(255, 255, 255, 255, 32), false),
    (v6([0, 0, 0, 0, 0, 0, 0, 1], 128), false),
    (v6([0, 0, 0, 0, 0, 0, 0, 0], 128), false),
    (v6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96), false),
    (v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96), true),
    (v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48), false),
    (v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64), false),
    (v6([0x100, 0, 0, 1, 0, 0, 0, 0], 64), false),
    (v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23), false),
    (v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 32), false),
    (v6([0x2001, 1, 0, 0, 0, 0, 0, 1], 128), true),
    (v6([0x2001, 1, 0, 0, 0, 0, 0, 2], 128), true),
    (v6([0x2001, 1, 0, 0, 0, 0, 0, 3], 128), true),
    (v6([0x2001, 2, 0, 0, 0, 0, 0, 0], 48), false),
    (v6([0x2001, 3, 0, 0, 0, 0, 0, 0], 32), true),
    (v6([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48), true),
    (v6([0x2001, 0x10, 0, 0, 0, 0, 0, 0], 28), false),
    (v6([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28), true),
    (v6([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28), true),
    (v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), false),
    (v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16), false),
    (v6([0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0], 48), true),
    (v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20), false),
    (v6([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16), false),
    (v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7), false),
    (v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), false),
    // Not in the registries, and no host's unicast address: multicast
    // (RFC 5771, RFC 4291 §2.7) and the rest of the IPv6 space outside
    // global unicast (RFC 4291 §2.4).
    (v4(224, 0, 0, 0, 4), false),
    (v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8), false),
    (v6([0, 0, 0, 0, 0, 0, 0, 0], 3), false),
    (v6([0x4000, 0, 0, 0, 0, 0, 0, 0], 2), false),
    (v6([0x8000, 0, 0, 0, 0, 0, 0, 0], 1), false),
];

/// Whether `addr` is one a host on the internet can have, by the IANA
/// special-purpose registries (RFC 6890). The mirror places no relay or
/// front at another address, and a world placing its own machines at
/// relayed addresses can skip the same ones.
pub fn globally_reachable(addr: IpAddr) -> bool {
    SPECIAL_PURPOSE
        .iter()
        .filter(|(block, _)| block.contains(addr))
        .max_by_key(|(block, _)| block.len)
        .is_none_or(|(_, reachable)| *reachable)
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a preset's name is valid")
}
