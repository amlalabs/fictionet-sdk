//! What a resolver does, as a value: every knob real resolver software
//! has, starting from the values the standards fix.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::dnssec::{AlgorithmPolicy, Anchors};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name};

use super::super::authority::Identity;
use super::super::zone::{AnyResponse, EmptyApex, ZoneData, special};

/// Whether a name is a negative trust anchor ([`Config::negative_anchors`]).
pub type NegativeAnchors = Arc<dyn Fn(&LowerName) -> bool + Send + Sync>;

/// How a recursive resolver behaves.
///
/// Every field is a knob real resolver software has. [`Config::new`]
/// holds the values the standards fix; a world that plays some resolver
/// writes that resolver's values over it.
#[derive(Clone)]
pub struct Config {
    /// The root servers to start from (RFC 8109). Empty: the resolver
    /// iterates nowhere, and a question its local zones and forward zones
    /// do not answer gets SERVFAIL with Extended DNS Error 22, as a
    /// resolver with no route to the roots gives.
    pub hints: Vec<(Name, IpAddr)>,
    /// Zones whose questions go to servers that resolve them, with RD
    /// set, instead of iterating: each zone's name and its servers. A
    /// question goes to the servers of the deepest zone that holds its
    /// name, and their answers are taken whole. `(".", servers)` forwards
    /// every question, as a home router does.
    pub forward: Vec<(Name, Vec<SocketAddr>)>,
    /// Zones answered without a query. The zones that hold QNAME answer
    /// deepest first, and at equal depth the zone added last; a fact a
    /// zone does not know passes the question on to the next, and after
    /// the last to the cache and iteration.
    pub local: Vec<LocalZone>,
    /// The EDNS payload size offered to servers and advertised to clients
    /// (RFC 6891 §6.2.5).
    pub payload: u16,
    /// QNAME minimisation (RFC 9156), or `None` to send every server the
    /// whole question.
    pub minimise: Option<Minimise>,
    /// Whether the letters of each upstream QNAME get a random case, and
    /// replies must repeat it exactly (the 0x20 technique of
    /// draft-vixie-dnsext-dns0x20).
    pub case_randomise: bool,
    /// The trust anchors answers are validated from. `None`: no answer is
    /// validated, every result is [`Validation::NotPerformed`], and AD is
    /// never set.
    ///
    /// [`Validation::NotPerformed`]: fictionet::stdlib::protocols::dns::dnssec::Validation::NotPerformed
    pub anchors: Option<Anchors>,
    /// Negative trust anchors (RFC 7646): `true` for a name at and below
    /// which no answer is validated, so each is Insecure as though no
    /// trust anchor covered it. A trust anchor in `anchors` at that name
    /// or below it starts validation again there (RFC 7646 §1.1). World
    /// code: the resolver asks it about an answer's owner and every name
    /// above, while it works, so it must return quickly, and its answers
    /// may change as the world runs. `None` for none.
    pub negative_anchors: Option<NegativeAnchors>,
    /// Which algorithms and digests may make an answer Secure (RFC 9904,
    /// RFC 9905).
    pub policy: AlgorithmPolicy,
    /// How much one client question may cost (RFC 1034 §5.3.3).
    pub work: Work,
    /// How long a failed resolution is answered from the cache
    /// (RFC 9520 §3.2: at least 1 second and at most 300).
    pub failure_ttl: Duration,
    /// The longest any data is cached (RFC 8767 §4: at most 604800
    /// seconds).
    pub max_ttl: Duration,
    /// The longest a negative answer is cached.
    pub max_negative_ttl: Duration,
    /// Serving expired data when resolution fails or is slow (RFC 8767),
    /// or `None` to never serve it.
    pub serve_stale: Option<Stale>,
    /// Whether a query with RD clear is answered from the cache. Otherwise
    /// it gets REFUSED unless a local zone answers it.
    pub rd0_from_cache: bool,
    /// Whether replies carry Extended DNS Errors (RFC 8914).
    pub ede: bool,
    /// Whether validated NSEC records answer for names they cover without
    /// asking again (RFC 8198).
    pub aggressive_nsec: bool,
    /// What the resolver says about itself to CHAOS-class questions and
    /// NSID requests.
    pub identity: Identity,
    /// What local zones send for QTYPE ANY (RFC 8482 §4). A question for
    /// ANY that leaves the resolver gets what the authority sends.
    pub any: AnyResponse,
    /// How long the resolver waits for a server it knows nothing of.
    /// After a server's first reply it waits what that server's round
    /// trips teach it (RFC 6298 §2), and each timeout doubles the wait.
    /// A query over TCP waits twice as long, for the connection's
    /// handshake. A query that times out is asked again, of the same
    /// server or another, and each server address gets the query at most
    /// three times per transport in one resolution (RFC 9520 §3.1).
    pub retransmit: Duration,
    /// How long the resolver remembers a server's round trips after it
    /// last asked it.
    pub server_ttl: Duration,
}

/// One of a resolver's local zones ([`Config::local`]).
#[derive(Clone)]
pub struct LocalZone {
    /// The zone's data.
    pub data: Arc<dyn ZoneData>,
    /// Whether its answers keep the AA bit the zone gives them. Otherwise
    /// every answer from it has AA clear.
    pub keep_aa: bool,
}

impl LocalZone {
    /// `data`, answered with the AA bit its zone gives, as a server
    /// answers from a zone it serves (RFC 6303 §3).
    pub fn new(data: Arc<dyn ZoneData>) -> LocalZone {
        LocalZone {
            data,
            keep_aa: true,
        }
    }
}

/// The bounds of QNAME minimisation (RFC 9156 §2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Minimise {
    /// The most minimised queries one resolution sends before it asks for
    /// the whole name: MAX_MINIMISE_COUNT.
    pub max_queries: u8,
    /// How many of those add one label each, before the rest add as many
    /// labels as reach the whole name within `max_queries`:
    /// MINIMISE_ONE_LAB.
    pub one_label: u8,
}

impl Minimise {
    /// The values RFC 9156 §2.3 recommends: 10 queries, the first 4 adding
    /// one label each.
    pub fn rfc9156() -> Minimise {
        Minimise {
            max_queries: 10,
            one_label: 4,
        }
    }
}

/// How a resolver serves expired data (RFC 8767).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stale {
    /// How long past its TTL data may still be served.
    pub max_stale: Duration,
    /// The TTL stale data is served with (RFC 8767 §4 recommends 30
    /// seconds).
    pub reply_ttl: Duration,
    /// How long a client waits for a fresh answer before stale data
    /// answers it, while the resolution goes on to refresh the cache.
    pub client_timeout: Duration,
}

/// How much one client question may cost, counted over everything it
/// needs: the question itself, the aliases it follows, the addresses of
/// name servers without glue, and the DS and DNSKEY sets validation
/// fetches (RFC 1034 §5.3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Work {
    /// The most queries sent to servers.
    pub queries: u16,
    /// The deepest dependency: how many aliases one answer follows, and,
    /// counted apart, how deeply the lookups one alias's name needs, for
    /// name server addresses and for the DS and DNSKEY sets a validation
    /// fetches, may nest.
    pub depth: u8,
}

impl Config {
    /// A resolver with the values the standards fix, and no more:
    ///
    /// - The IANA root hints ([`root_hints`], RFC 8109), and no forward
    ///   zones.
    /// - Every special-use zone of [`special::defaults`], with the apex
    ///   records of [`EmptyApex::rfc6303`], answered with AA (RFC 6303 §3).
    /// - A 1232-octet payload, the size the DNS Flag Day 2020 settled on.
    /// - QNAME minimisation with the bounds RFC 9156 §2.3 recommends, and
    ///   no random case.
    /// - Validation from the IANA root anchors, under the IANA algorithm
    ///   policy ([`AlgorithmPolicy::iana`]), with no negative trust
    ///   anchors, and with aggressive use of validated NSEC records
    ///   (RFC 8198).
    /// - A failure cached for 5 seconds, inside the bounds of RFC 9520
    ///   §3.2; data cached for at most 604800 seconds (RFC 8767 §4);
    ///   negative answers for at most 10800 seconds, the three hours
    ///   RFC 2308 §5 suggests; and no stale data served.
    /// - A query with RD clear answered from the cache (RFC 1034 §4.3.1).
    /// - Extended DNS Errors (RFC 8914).
    /// - Every RRset of a local zone's name for ANY, as RFC 1035 §3.2.3
    ///   defines the type.
    /// - An identity with no names and no NSID ([`Identity::none`]).
    /// - The initial retransmission timeout of RFC 6298 §2.1, 1 second.
    ///
    /// Two values are the SDK's own, since no standard fixes them: one
    /// client question may send 200 queries and follow 11 aliases, and a
    /// server's round trips are remembered for 600 seconds.
    pub fn new() -> Config {
        let apex = EmptyApex::rfc6303();
        Config {
            hints: root_hints(),
            forward: Vec::new(),
            local: special::defaults(&apex)
                .into_iter()
                .map(LocalZone::new)
                .collect(),
            payload: 1232,
            minimise: Some(Minimise::rfc9156()),
            case_randomise: false,
            anchors: Some(Anchors::iana_root()),
            negative_anchors: None,
            policy: AlgorithmPolicy::iana(),
            work: Work {
                queries: 200,
                depth: 11,
            },
            failure_ttl: Duration::from_secs(5),

            max_ttl: Duration::from_secs(604800),
            max_negative_ttl: Duration::from_secs(10800),
            serve_stale: None,
            rd0_from_cache: true,
            ede: true,
            aggressive_nsec: true,
            identity: Identity::none(),
            any: AnyResponse::All,
            retransmit: Duration::from_secs(1),
            server_ttl: Duration::from_secs(600),
        }
    }

    /// This configuration with root hints `hints`.
    pub fn hints(mut self, hints: &[(Name, IpAddr)]) -> Config {
        self.hints = hints.to_vec();
        self
    }

    /// This configuration with `zone` as one more local zone, which wins
    /// over the zones before it at equal depth.
    pub fn local(mut self, zone: LocalZone) -> Config {
        self.local.push(zone);
        self
    }

    /// This configuration validating from `anchors`.
    pub fn anchors(mut self, anchors: Anchors) -> Config {
        self.anchors = Some(anchors);
        self
    }
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

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
}

/// The root servers in IANA's `named.root`, "last update: October 28,
/// 2026", in letter order, with both addresses of each letter.
pub const ROOT_SERVERS: [NameServer; 13] = [
    NameServer {
        host: "a.root-servers.net.",
        v4: Ipv4Addr::new(198, 41, 0, 4),
        v6: Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30),
    },
    NameServer {
        host: "b.root-servers.net.",
        v4: Ipv4Addr::new(170, 247, 170, 2),
        v6: Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb),
    },
    NameServer {
        host: "c.root-servers.net.",
        v4: Ipv4Addr::new(192, 33, 4, 12),
        v6: Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),
    },
    NameServer {
        host: "d.root-servers.net.",
        v4: Ipv4Addr::new(199, 7, 91, 13),
        v6: Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),
    },
    NameServer {
        host: "e.root-servers.net.",
        v4: Ipv4Addr::new(192, 203, 230, 10),
        v6: Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),
    },
    NameServer {
        host: "f.root-servers.net.",
        v4: Ipv4Addr::new(192, 5, 5, 241),
        v6: Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),
    },
    NameServer {
        host: "g.root-servers.net.",
        v4: Ipv4Addr::new(192, 112, 36, 4),
        v6: Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),
    },
    NameServer {
        host: "h.root-servers.net.",
        v4: Ipv4Addr::new(198, 97, 190, 53),
        v6: Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),
    },
    NameServer {
        host: "i.root-servers.net.",
        v4: Ipv4Addr::new(192, 36, 148, 17),
        v6: Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),
    },
    NameServer {
        host: "j.root-servers.net.",
        v4: Ipv4Addr::new(192, 58, 128, 30),
        v6: Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),
    },
    NameServer {
        host: "k.root-servers.net.",
        v4: Ipv4Addr::new(193, 0, 14, 129),
        v6: Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1),
    },
    NameServer {
        host: "l.root-servers.net.",
        v4: Ipv4Addr::new(199, 7, 83, 42),
        v6: Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),
    },
    NameServer {
        host: "m.root-servers.net.",
        v4: Ipv4Addr::new(202, 12, 27, 33),
        v6: Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),
    },
];

/// [`ROOT_SERVERS`] as resolver hints, both addresses of each letter: the
/// hints resolvers build in (RFC 8109).
pub fn root_hints() -> Vec<(Name, IpAddr)> {
    ROOT_SERVERS
        .iter()
        .flat_map(|server| server.addresses().map(|address| (server.name(), address)))
        .collect()
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a root server's name is valid")
}
