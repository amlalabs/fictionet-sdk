//! What a resolver does, as a value: every knob real resolver software
//! has, and presets with the values of the resolvers a world copies.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::dnssec::{AlgorithmPolicy, Anchors};
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{
    Alpn, IpHint, SvcParamKey, SvcParamValue, Unknown,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, AAAA, NS, SOA, SVCB};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet, RecordType};

use super::super::authority::{ChaosAnswer, Identity, chaos};
use super::super::zone::{AnyResponse, Zone, ZoneData, special};

/// How a recursive resolver behaves.
///
/// Every field is a knob real resolver software has. The presets are
/// values; a world that wants other behavior writes another value.
#[derive(Clone)]
pub struct Config {
    /// The root servers to start from (RFC 8109). Empty: the resolver
    /// iterates nowhere, and a question its local zones do not answer
    /// gets SERVFAIL with Extended DNS Error 22, as a resolver with no
    /// route to the roots gives.
    pub hints: Vec<(Name, IpAddr)>,
    /// Servers to forward every question to, with RD set, instead of
    /// iterating, as dnsmasq does. Their answers are taken whole.
    pub forward: Vec<SocketAddr>,
    /// Zones answered without a query. The zones that hold QNAME answer
    /// deepest first, and at equal depth the zone added last; a fact a
    /// zone does not know passes the question on to the next, and after
    /// the last to the cache and iteration.
    pub local: Vec<Arc<dyn ZoneData>>,
    /// Whether answers from local zones keep the AA bit the zone gives
    /// them, as Unbound does for its local zones and Google's resolver
    /// does for `resolver.arpa`. Otherwise every answer has AA clear.
    pub local_aa: bool,
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
    /// The resolver's encrypted endpoints, as SVCB records at
    /// `_dns.resolver.arpa` (RFC 9462). When there are any, the resolver
    /// answers `resolver.arpa` from them with TTL [`ddr_ttl`](Config::ddr_ttl),
    /// ahead of its other local zones.
    pub ddr: Vec<SVCB>,
    /// The TTL of the [`ddr`](Config::ddr) records.
    pub ddr_ttl: u32,
    /// What local zones send for QTYPE ANY (RFC 8482 §4). A question for
    /// ANY that leaves the resolver gets what the authority sends.
    pub any: AnyResponse,
    /// How long the resolver waits for one server before it asks the
    /// next. Each server address is asked at most once per transport in
    /// one resolution (RFC 9520 §3.1), so the wait is not followed by a
    /// second try at the same server.
    pub retransmit: Duration,
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
    /// The deepest dependency: how many aliases one answer follows, and
    /// how deeply lookups for name server addresses may nest.
    pub depth: u8,
}

impl Config {
    /// Unbound 1.26 with its documented defaults, read from the
    /// `unbound.conf` manual on 2026-11-01:
    ///
    /// - The IANA root hints, which Unbound has built in.
    /// - Its default local zones: `localhost`, the reverse zones of
    ///   RFC 6303 and RFC 6598 (Unbound's default AS112, RFC 1918, and
    ///   Shared Address Space zones),
    ///   `home.arpa`, `resolver.arpa`, `service.arpa`, `onion`, `test`,
    ///   and `invalid`. With `ede: no` and no DDR endpoints,
    ///   `resolver.arpa` is an empty zone (RFC 9462 §6.4).
    /// - `edns-buffer-size: 1232`, `qname-minimisation: yes` with
    ///   `qname-minimisation-strict: no`, `use-caps-for-id: no`,
    ///   `aggressive-nsec: yes`, `serve-expired: no`, `ede: no`,
    ///   `deny-any: no`.
    /// - `cache-max-ttl: 86400` and `cache-max-negative-ttl: 3600`.
    /// - `val-nsec3-keysize-iterations: "1024 150 2048 150 4096 150"`:
    ///   NSEC3 records with more than 150 iterations make an answer
    ///   Insecure, whatever the key size.
    /// - `max-global-quota: 200` queries for one client question, and
    ///   `max-query-restarts: 11` aliases.
    /// - `unknown-server-time-limit: 376` milliseconds for a server it
    ///   has no round-trip time for.
    /// - `hide-identity: no` and `hide-version: no`: `id.server` and
    ///   `hostname.bind` give the host name, which this preset leaves as
    ///   `localhost` for a world to set; `version.server` and
    ///   `version.bind` give "unbound 1.26.2", the release of 2026-10-21.
    ///   Other CHAOS names get REFUSED.
    /// - The `allow` access control: a query with RD clear is answered
    ///   only from local zones and is otherwise REFUSED.
    /// - Answers from local zones carry AA, as `local_encode` in
    ///   Unbound's `services/localzone.c` sets it.
    /// - Validation with the IANA root anchors.
    ///
    /// A failure is cached for 5 seconds, inside the bounds of
    /// RFC 9520 §3.2.
    pub fn unbound() -> Config {
        let mut local: Vec<Arc<dyn ZoneData>> = vec![Arc::new(special::localhost())];
        for zone in special::rfc6303() {
            local.push(Arc::new(zone));
        }
        local.push(Arc::new(special::home_arpa()));
        local.push(Arc::new(special::resolver_arpa(Vec::new(), 3600)));
        local.push(Arc::new(service_arpa()));
        local.push(Arc::new(special::onion()));
        local.push(Arc::new(special::test()));
        local.push(Arc::new(special::invalid()));
        let host = ChaosAnswer::Txt("localhost".to_string());
        let version = ChaosAnswer::Txt("unbound 1.26.2".to_string());
        let identity = Identity::none()
            .answer(chaos::id_server(), host.clone())
            .answer(chaos::hostname_bind(), host)
            .answer(chaos::version_server(), version.clone())
            .answer(chaos::version_bind(), version);
        Config {
            hints: root_hints(),
            forward: Vec::new(),
            local,
            local_aa: true,
            payload: 1232,
            minimise: Some(Minimise::rfc9156()),
            case_randomise: false,
            anchors: Some(Anchors::iana_root()),
            policy: AlgorithmPolicy {
                max_nsec3_iterations: 150,
                ..AlgorithmPolicy::iana()
            },
            work: Work {
                queries: 200,
                depth: 11,
            },
            failure_ttl: Duration::from_secs(5),
            max_ttl: Duration::from_secs(86400),
            max_negative_ttl: Duration::from_secs(3600),
            serve_stale: None,
            rd0_from_cache: false,
            ede: false,
            aggressive_nsec: true,
            identity,
            ddr: Vec::new(),
            ddr_ttl: 3600,
            any: AnyResponse::All,
            retransmit: Duration::from_millis(376),
        }
    }

    /// [`Config::unbound`] with no root hints and `ede: yes`: a resolver
    /// with no route to the roots, as on a network with no internet. It
    /// answers from its local zones and gives SERVFAIL with Extended DNS
    /// Error 22, No Reachable Authority (RFC 8914 §4.23), for everything
    /// else, so a client can tell why.
    pub fn gateway() -> Config {
        Config {
            hints: Vec::new(),
            ede: true,
            ..Config::unbound()
        }
    }

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
            local: Vec::new(),
            local_aa: true,
            payload: 512,
            case_randomise: true,
            policy: AlgorithmPolicy::iana(),
            rd0_from_cache: true,
            ede: true,
            identity,
            ddr: vec![
                SVCB::new(1, google.clone(), vec![alpn(&["dot"])]),
                SVCB::new(2, google, vec![alpn(&["h2", "h3"]), dohpath()]),
            ],
            ddr_ttl: 86400,
            ..Config::unbound()
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
        let v4 = hints_v4(&[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)]);
        let v6 = hints_v6(&[
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
        ]);
        Config {
            local: Vec::new(),
            local_aa: false,
            payload: 1232,
            policy: AlgorithmPolicy::iana(),
            rd0_from_cache: true,
            ede: true,
            identity,
            ddr: vec![
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
            ddr_ttl: 300,
            ..Config::unbound()
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
        let v4 = hints_v4(&[
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(149, 112, 112, 9),
            Ipv4Addr::new(149, 112, 112, 112),
        ]);
        let v6 = hints_v6(&[
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0xfe, 0x9),
        ]);
        Config {
            local: vec![Arc::new(special::localhost())],
            local_aa: false,
            payload: 512,
            policy: AlgorithmPolicy::iana(),
            ede: true,
            identity,
            ddr: vec![
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
            ddr_ttl: 60,
            ..Config::unbound()
        }
    }

    /// dnsmasq forwarding to `forward`, as a home router runs it: no root
    /// hints, no local zones, no validation, and no QNAME minimisation; a
    /// 1232-octet payload; and TTLs capped only by RFC 8767 §4. It answers
    /// `version.bind` with its version and refuses other CHAOS names.
    pub fn dnsmasq(forward: Vec<SocketAddr>) -> Config {
        let version = ChaosAnswer::Txt("dnsmasq-2.91".to_string());
        Config {
            hints: Vec::new(),
            forward,
            local: Vec::new(),
            minimise: None,
            anchors: None,
            policy: AlgorithmPolicy::iana(),
            max_ttl: Duration::from_secs(604800),
            max_negative_ttl: Duration::from_secs(604800),
            aggressive_nsec: false,
            identity: Identity::none().answer(chaos::version_bind(), version),
            ..Config::unbound()
        }
    }

    /// This configuration with root hints `hints`.
    pub fn hints(mut self, hints: &[(Name, IpAddr)]) -> Config {
        self.hints = hints.to_vec();
        self
    }

    /// This configuration with `data` as one more local zone, which wins
    /// over the zones before it at equal depth.
    pub fn local(mut self, data: Arc<dyn ZoneData>) -> Config {
        self.local.push(data);
        self
    }

    /// This configuration validating from `anchors`.
    pub fn anchors(mut self, anchors: Anchors) -> Config {
        self.anchors = Some(anchors);
        self
    }
}

/// The root servers in IANA's `named.root`, "last update: October 28,
/// 2026", both addresses of each letter. These are the hints Unbound and
/// every other resolver build in (RFC 8109).
pub fn root_hints() -> Vec<(Name, IpAddr)> {
    const ROOTS: [(&str, Ipv4Addr, Ipv6Addr); 13] = [
        (
            "a",
            Ipv4Addr::new(198, 41, 0, 4),
            Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30),
        ),
        (
            "b",
            Ipv4Addr::new(170, 247, 170, 2),
            Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb),
        ),
        (
            "c",
            Ipv4Addr::new(192, 33, 4, 12),
            Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),
        ),
        (
            "d",
            Ipv4Addr::new(199, 7, 91, 13),
            Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),
        ),
        (
            "e",
            Ipv4Addr::new(192, 203, 230, 10),
            Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),
        ),
        (
            "f",
            Ipv4Addr::new(192, 5, 5, 241),
            Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),
        ),
        (
            "g",
            Ipv4Addr::new(192, 112, 36, 4),
            Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),
        ),
        (
            "h",
            Ipv4Addr::new(198, 97, 190, 53),
            Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),
        ),
        (
            "i",
            Ipv4Addr::new(192, 36, 148, 17),
            Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),
        ),
        (
            "j",
            Ipv4Addr::new(192, 58, 128, 30),
            Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),
        ),
        (
            "k",
            Ipv4Addr::new(193, 0, 14, 129),
            Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1),
        ),
        (
            "l",
            Ipv4Addr::new(199, 7, 83, 42),
            Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),
        ),
        (
            "m",
            Ipv4Addr::new(202, 12, 27, 33),
            Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),
        ),
    ];
    ROOTS
        .iter()
        .flat_map(|(letter, v4, v6)| {
            let server = name(&format!("{letter}.root-servers.net."));
            [(server.clone(), IpAddr::V4(*v4)), (server, IpAddr::V6(*v6))]
        })
        .collect()
}

/// `service.arpa`, for names of services inside a home network, which
/// Unbound serves as an empty static zone (RFC 9665), with the SOA and
/// NS of the other locally served zones (RFC 6303 §3).
fn service_arpa() -> Zone {
    let apex = name("service.arpa.");
    let soa = SOA::new(
        apex.clone(),
        name("nobody.invalid."),
        1,
        3600,
        1200,
        604800,
        10800,
    );
    let mut ns = RecordSet::with_ttl(apex.clone(), RecordType::NS, 10800);
    ns.set_records(vec![Record::from_rdata(
        apex.clone(),
        10800,
        RData::NS(NS(apex.clone())),
    )]);
    Zone::builder(apex, soa, 10800)
        .rrset(ns)
        .build()
        .expect("service.arpa is a well-formed zone")
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a preset's name is valid")
}

fn alpn(protocols: &[&str]) -> (SvcParamKey, SvcParamValue) {
    let protocols = protocols.iter().map(|p| p.to_string()).collect();
    (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(protocols)))
}

fn port(port: u16) -> (SvcParamKey, SvcParamValue) {
    (SvcParamKey::Port, SvcParamValue::Port(port))
}

fn hints_v4(addresses: &[Ipv4Addr]) -> (SvcParamKey, SvcParamValue) {
    let hints = addresses.iter().map(|a| A(*a)).collect();
    (
        SvcParamKey::Ipv4Hint,
        SvcParamValue::Ipv4Hint(IpHint(hints)),
    )
}

fn hints_v6(addresses: &[Ipv6Addr]) -> (SvcParamKey, SvcParamValue) {
    let hints = addresses.iter().map(|a| AAAA(*a)).collect();
    (
        SvcParamKey::Ipv6Hint,
        SvcParamValue::Ipv6Hint(IpHint(hints)),
    )
}

/// The DoH URI template, SvcParamKey 7 (RFC 9461 §5), which hickory
/// carries as an unknown key.
fn dohpath() -> (SvcParamKey, SvcParamValue) {
    (
        SvcParamKey::Unknown(7),
        SvcParamValue::Unknown(Unknown(b"/dns-query{?dns}".to_vec())),
    )
}
