//! A small internet's DNS for tests: a signed root at the real root
//! servers' addresses, `com` and `net` at the `gtld-servers.net`
//! addresses, `arpa` and the reverse names of the public resolvers, and a
//! few zones below them, signed with seeded keys.
//!
//! [`TestInternet`] serves the same zones two ways: as engines in a
//! [`MemoryNet`], with no runtime, and as hosts for a simulated network.
//! Its trust anchor goes in a resolver's
//! [`Config::anchors`](fictionet::stdlib::services::dns::resolver::Config::anchors).
//! Nothing is captured from the real internet, and nothing here reaches it.
//!
//! The hierarchy:
//!
//! | Zone | Signed | Served at |
//! | --- | --- | --- |
//! | `.` | RSA/SHA-256 KSK and ZSK, as the real root, NSEC | every root letter |
//! | `arpa` | ECDSA P-256, NSEC | every root letter |
//! | `ipv4only.arpa` | no, an insecure delegation | `a` and `b.iana-servers.net` |
//! | `in-addr.arpa` | no, an insecure delegation | `in-addr-servers.arpa` |
//! | `com` | ECDSA P-256, opt-out NSEC3, as the real `com` | `gtld-servers.net` |
//! | `net` | ECDSA P-256, opt-out NSEC3, as the real `net` | `gtld-servers.net` |
//! | `example.com` | RSA/SHA-256, NSEC | `ns1` and `ns2.example.com` |
//! | `dnssec-failed.com` | ECDSA P-256, with a DS in `com` for other keys | `ns1.dnssec-failed.com` |
//! | `example.net` | no, covered by `net`'s opt-out | `ns1.example.net` |
//! | `org` | no, proven unsigned by the root's NSEC | `ns1.nic.org` |
//! | `example.org` | no | `ns1.example.org` |
//! | `fict.com` | no: invented by an [`Overlay`] on the `com` servers | `ns1.fict.com` |
//!
//! The real `dnssec-failed.org` sits under a signed `org`; here `org` is
//! unsigned, so the broken zone sits under `com`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, AlgorithmPolicy, Anchors, DigestType, KeyFlags, KeySet, Sign, TrustAnchor, Window,
    ZoneKey,
};
use fictionet::stdlib::protocols::dns::rr::{Name, RecordSet};
use fictionet::stdlib::services::dns::WallClock;
use fictionet::stdlib::services::dns::authority::{
    Authority, AuthorityEngine, ChaosAnswer, Identity, Overlay, ServerConfig, Zones, chaos,
};
use fictionet::stdlib::services::dns::memory::MemoryNet;
use fictionet::stdlib::services::dns::resolver::{Config, NameServer, ROOT_SERVERS};
use fictionet::stdlib::services::dns::zone::{AnyResponse, Denial, Zone, ZoneData};
use fictionet::stdlib::world::net::Host;
use fictionet::stdlib::world::net::dns::Authoritative;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::place::Place;
use fictionet_extras::dns::public::PUBLIC_RESOLVERS;
use fictionet_extras::dns::roots::{self, GTLD_SERVERS};
use fictionet_extras::dns::unbound;

/// The date every test of this internet runs at: 2026-11-01 00:00:00 UTC.
pub const START: u64 = 1_793_491_200;

/// The root zone's serial on [`START`], as the real root's read that day.
pub const ROOT_SERIAL: u32 = 2_026_110_101;

/// The address the test network reaches the internet from.
pub const EGRESS: Ipv4Addr = Ipv4Addr::new(45, 70, 0, 9);

/// The servers of `example.com`, `ns1` and `ns2`.
pub const EXAMPLE_COM: [Ipv4Addr; 2] =
    [Ipv4Addr::new(45, 33, 20, 53), Ipv4Addr::new(45, 33, 21, 53)];
/// The server of `example.net`.
pub const EXAMPLE_NET: Ipv4Addr = Ipv4Addr::new(45, 33, 22, 53);
/// The server of `org`, `ns1.nic.org`.
pub const ORG: Ipv4Addr = Ipv4Addr::new(45, 33, 23, 53);
/// The server of `example.org`.
pub const EXAMPLE_ORG: Ipv4Addr = Ipv4Addr::new(45, 33, 24, 53);
/// The server of the invented `fict.com`.
pub const FICT_COM: Ipv4Addr = Ipv4Addr::new(45, 33, 25, 53);
/// The server of `dnssec-failed.com`.
pub const DNSSEC_FAILED: Ipv4Addr = Ipv4Addr::new(45, 33, 26, 53);

/// `<letter>.ns.arpa.` on the root letter `index` of [`ROOT_SERVERS`].
const fn arpa(host: &'static str, index: usize) -> NameServer {
    NameServer {
        host,
        v4: ROOT_SERVERS[index].v4,
        v6: ROOT_SERVERS[index].v6,
    }
}

/// The servers of `arpa`: every root letter but j, each at the same
/// addresses as its letter, as IANA's root zone database lists them
/// (`https://www.iana.org/domains/root/db/arpa.html`). The root servers
/// answer for `arpa` themselves, so a mirror serves its copy at the
/// root addresses once a root server answers from it.
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

/// The IANA servers `ipv4only.arpa` is delegated to, with the addresses
/// they had on 2026-11-01.
const IANA_SERVERS: [(&str, Ipv4Addr, Ipv6Addr); 2] = [
    (
        "a.iana-servers.net.",
        Ipv4Addr::new(199, 43, 135, 53),
        Ipv6Addr::new(0x2001, 0x500, 0x8f, 0, 0, 0, 0, 0x53),
    ),
    (
        "b.iana-servers.net.",
        Ipv4Addr::new(199, 43, 133, 53),
        Ipv6Addr::new(0x2001, 0x500, 0x8d, 0, 0, 0, 0, 0x53),
    ),
];

/// The IPv6 address of the test server at `v4`: `2600:3c00::<c>:53` for
/// `45.33.<c>.53`, so every server here has both families, as the real
/// servers of zones like these do.
pub fn v6(v4: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::new(0x2600, 0x3c00, 0, 0, 0, 0, u16::from(v4.octets()[2]), 0x53)
}

/// `www.example.com`'s address.
pub const WWW_EXAMPLE_COM: Ipv4Addr = Ipv4Addr::new(45, 33, 20, 80);

/// The DNS of a small internet, signed with seeded keys.
#[derive(Clone)]
pub struct TestInternet {
    /// What every root letter answers.
    root: Arc<dyn Authority>,
    /// What every `gtld-servers.net` server answers.
    gtld: Arc<dyn Authority>,
    /// Every other server.
    servers: Vec<Server>,
    anchor: TrustAnchor,
    place: Place,
}

/// A server of one zone at its own addresses.
#[derive(Clone)]
struct Server {
    /// Its name, which labels its host.
    name: &'static str,
    /// The zone it serves, which [`TestInternet::serving`] names.
    zone: Name,
    addresses: Vec<IpAddr>,
    front: ServerConfig,
    authority: Arc<dyn Authority>,
}

impl Server {
    fn new(
        name: &'static str,
        zone: &str,
        addresses: [IpAddr; 2],
        front: ServerConfig,
        authority: Arc<dyn Authority>,
    ) -> Server {
        Server {
            name,
            zone: self::name(zone),
            addresses: addresses.to_vec(),
            front,
            authority,
        }
    }
}

impl TestInternet {
    /// The internet with every zone in the module docs, as seen from the
    /// San Francisco Bay Area.
    pub fn new() -> TestInternet {
        let keys = keys();
        let window = TestInternet::window();
        let sign = |zone: Zone, keys: &KeySet, denial: Denial| -> Arc<dyn ZoneData> {
            Arc::new(
                zone.signed(keys, window, denial)
                    .expect("a test zone signs"),
            )
        };
        let opt_out = || Denial::Nsec3 {
            opt_out: true,
            salt: Vec::new(),
        };

        // A DS RRset at a cut is the cut's DS.
        let with_ds = |zone: Zone, sets: Vec<RecordSet>| {
            sets.into_iter().fold(zone, |zone, set| {
                zone.with(set).expect("a DS RRset at a cut")
            })
        };
        let root = with_ds(
            zone(&root_text()),
            vec![
                ds(&keys.com, "com."),
                ds(&keys.net, "net."),
                ds(&keys.arpa, "arpa."),
            ],
        );
        let arpa = zone(&arpa_text());
        let com = with_ds(
            zone(&com_text()),
            vec![
                ds(&keys.example_com, "example.com."),
                ds(&keys.not_dnssec_failed, "dnssec-failed.com."),
            ],
        );
        let root = sign(root, &keys.root, Denial::Nsec);
        let arpa = sign(arpa, &keys.arpa, Denial::Nsec);
        let com = sign(com, &keys.com, opt_out());
        let net = sign(zone(&net_text()), &keys.net, opt_out());
        let example_com = sign(TestInternet::example_com(), &keys.example_com, Denial::Nsec);
        let dnssec_failed = sign(
            zone(&dnssec_failed_text()),
            &keys.dnssec_failed,
            Denial::Nsec,
        );
        let ipv4only: Arc<dyn ZoneData> = Arc::new(zone(&ipv4only_text()));
        let in_addr: Arc<dyn ZoneData> = Arc::new(zone(&in_addr_text()));
        let org: Arc<dyn ZoneData> = Arc::new(zone(&org_text()));
        let example_org: Arc<dyn ZoneData> = Arc::new(zone(&example_org_text()));
        let example_net: Arc<dyn ZoneData> = Arc::new(zone(&example_net_text()));
        let fict: Arc<dyn ZoneData> = Arc::new(zone(&fict_text()));

        // example.com is served the way Cloudflare serves it, with one
        // HINFO record for ANY (RFC 8482 §4.2).
        let cloudflare = ServerConfig {
            any: AnyResponse::Hinfo,
            ..ServerConfig::generic()
        };
        let generic = ServerConfig::generic;
        let fict_servers: Arc<dyn Authority> = Arc::new(Zones::new(vec![fict.clone()]));
        let gtld =
            Overlay::new(Zones::new(vec![com, net]), name("com.")).below(name("fict.com."), fict_servers.clone());
        let zones = |zone: &Arc<dyn ZoneData>| -> Arc<dyn Authority> {
            Arc::new(Zones::new(vec![zone.clone()]))
        };
        let mut servers: Vec<Server> = IN_ADDR_SERVERS
            .iter()
            .map(|server| {
                Server::new(
                    server.host,
                    "in-addr.arpa.",
                    server.addresses(),
                    generic(),
                    zones(&in_addr),
                )
            })
            .collect();
        for (host, v4, v6) in IANA_SERVERS {
            let addresses = [IpAddr::V4(v4), IpAddr::V6(v6)];
            servers.push(Server::new(
                host,
                "ipv4only.arpa.",
                addresses,
                generic(),
                zones(&ipv4only),
            ));
        }
        let ours = [
            (
                "ns1.example.com.",
                "example.com.",
                EXAMPLE_COM[0],
                cloudflare.clone(),
                zones(&example_com),
            ),
            (
                "ns2.example.com.",
                "example.com.",
                EXAMPLE_COM[1],
                cloudflare,
                zones(&example_com),
            ),
            (
                "ns1.dnssec-failed.com.",
                "dnssec-failed.com.",
                DNSSEC_FAILED,
                generic(),
                zones(&dnssec_failed),
            ),
            (
                "ns1.example.net.",
                "example.net.",
                EXAMPLE_NET,
                generic(),
                zones(&example_net),
            ),
            ("ns1.nic.org.", "org.", ORG, generic(), zones(&org)),
            (
                "ns1.example.org.",
                "example.org.",
                EXAMPLE_ORG,
                generic(),
                zones(&example_org),
            ),
            (
                "ns1.fict.com.",
                "fict.com.",
                FICT_COM,
                generic(),
                fict_servers,
            ),
        ];
        for (host, apex, v4, front, authority) in ours {
            let addresses = [IpAddr::V4(v4), IpAddr::V6(v6(v4))];
            servers.push(Server::new(host, apex, addresses, front, authority));
        }
        TestInternet {
            root: Arc::new(Zones::new(vec![root, arpa])),
            gtld: Arc::new(gtld),
            servers,
            anchor: keys.root.anchor(&Name::root()),
            place: Place::san_francisco_bay_area(),
        }
    }

    /// This internet with the servers of `apex` answering as `authority`
    /// instead. `apex` is one of the zones served at their own addresses:
    /// `example.com`, `dnssec-failed.com`, `example.net`, `org`,
    /// `example.org`, `fict.com`, or `in-addr.arpa`.
    pub fn serving(mut self, apex: &str, authority: impl Authority) -> TestInternet {
        let apex = name(apex);
        let authority: Arc<dyn Authority> = Arc::new(authority);
        let mut found = false;
        for server in self.servers.iter_mut().filter(|server| server.zone == apex) {
            server.authority = authority.clone();
            found = true;
        }
        assert!(found, "no server of the test internet serves {apex}");
        self
    }

    /// `example.com` before signing.
    pub fn example_com() -> Zone {
        zone(&example_com_text())
    }

    /// The key `example.com` is signed with: one RSA/SHA-256 key with the
    /// Secure Entry Point flag, which signs every RRset.
    pub fn example_com_keys() -> KeySet {
        keys().example_com.clone()
    }

    /// The private key of [`example_com_keys`](Self::example_com_keys), as
    /// PKCS#8 DER.
    pub fn example_com_pkcs8() -> Vec<u8> {
        keys().example_com_pkcs8.clone()
    }

    /// The signature window of every signed zone here: 2026-10-31 to
    /// 2026-11-21, as the real root's signatures of 2026-11-01 ran.
    pub fn window() -> Window {
        Window {
            inception: date(START - 86_400),
            expiration: date(START + 20 * 86_400),
        }
    }

    /// The wall clock of a run at [`START`].
    pub fn clock() -> WallClock {
        WallClock { start: date(START) }
    }

    /// The anchor of the test root, for a resolver's
    /// [`Config::anchors`](Config::anchors).
    pub fn anchors(&self) -> Anchors {
        Anchors::of(vec![self.anchor.clone()])
    }

    /// Where this internet is seen from.
    pub fn place(&self) -> &Place {
        &self.place
    }

    /// An Unbound-like resolver for this internet: [`unbound::config`]
    /// sending Extended DNS Errors, with the real root hints, whose
    /// addresses the test root letters have, and the test root's anchor.
    pub fn config(&self) -> Config {
        Config {
            ede: true,
            ..unbound::config()
        }
        .anchors(self.anchors())
    }

    /// Every server as an engine in memory, at every address it has. Each
    /// has the front its host has in [`hosts`](Self::hosts).
    pub fn memory(&self) -> MemoryNet {
        let mut net = MemoryNet::new();
        let mut serve =
            |addresses: &[IpAddr], front: &ServerConfig, authority: &Arc<dyn Authority>| {
                for address in addresses {
                    let local = SocketAddr::new(*address, 53);
                    net.serve(
                        *address,
                        AuthorityEngine::new(authority.clone(), front.clone(), local),
                    );
                }
            };
        for server in &ROOT_SERVERS {
            serve(
                &server.addresses(),
                &self.letter_front(server.v4),
                &self.root,
            );
        }
        for server in &GTLD_SERVERS {
            let front = roots::gtld_front(self.place.site(IpAddr::V4(server.v4)).identity);
            serve(&server.addresses(), &front, &self.gtld);
        }
        for server in &self.servers {
            serve(&server.addresses, &server.front, &server.authority);
        }
        net
    }

    /// Every server as a host running [`Authoritative`]: the root letters
    /// and the `gtld-servers.net` servers as the place sees them
    /// ([`Place::root_servers`], [`Place::gtld_servers`]), and every
    /// other server behind half the place's round trip to an authority.
    pub fn hosts(&self) -> Vec<Host> {
        let at = &self.place;
        let mut hosts = at.root_servers(|s| Authoritative::new(self.root.clone(), s));
        hosts.extend(at.gtld_servers(|s| Authoritative::new(self.gtld.clone(), s)));
        for server in &self.servers {
            let host = server.addresses.iter().fold(
                Host::new(server.name.trim_end_matches('.')),
                |host, address| host.at(*address),
            );
            hosts.push(host.delay(at.site(server.addresses[0]).rtt / 2).program(
                Authoritative::new(server.authority.clone(), server.front.clone()),
            ));
        }
        hosts
    }

    /// The front [`Place::root_servers`] gives the letter at `v4`.
    pub fn letter_front(&self, v4: Ipv4Addr) -> ServerConfig {
        let letter = roots::letter_at(v4).expect("a root letter");
        letter.front(self.place.site(IpAddr::V4(v4)).identity)
    }
}

/// dnsmasq forwarding every question to `forward`, as a home router runs
/// it: no root hints, no local zones, no validation, and no QNAME
/// minimisation; a 1232-octet payload; and TTLs capped only by RFC 8767
/// §4. It answers `version.bind` with its version and refuses other CHAOS
/// names. What it does not show takes Unbound's values.
pub fn dnsmasq(forward: Vec<SocketAddr>) -> Config {
    let version = ChaosAnswer::Txt("dnsmasq-2.91".to_string());
    Config {
        hints: Vec::new(),
        forward: vec![(Name::root(), forward)],
        local: Vec::new(),
        minimise: None,
        anchors: None,
        policy: AlgorithmPolicy::iana(),
        max_ttl: Duration::from_secs(604800),
        max_negative_ttl: Duration::from_secs(604800),
        aggressive_nsec: false,
        identity: Identity::none().answer(chaos::version_bind(), version),
        ..unbound::config()
    }
}

impl Default for TestInternet {
    fn default() -> TestInternet {
        TestInternet::new()
    }
}

/// The keys of every signed zone, made once per test process: RSA keys
/// take a while to generate.
struct Keys {
    root: KeySet,
    arpa: KeySet,
    com: KeySet,
    net: KeySet,
    example_com: KeySet,
    example_com_pkcs8: Vec<u8>,
    dnssec_failed: KeySet,
    /// Keys `dnssec-failed.com` is not signed with, whose DS `com` holds.
    not_dnssec_failed: KeySet,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let key = |seed: u64, algorithm, flags| {
            ZoneKey::generate(&SeededEntropy::new(Seed::from_u64(seed)), algorithm, flags)
        };
        let set = |keys: Vec<ZoneKey>| KeySet {
            keys: keys
                .into_iter()
                .map(|key| Arc::new(key) as Arc<dyn Sign>)
                .collect(),
        };
        let p256 = |seed| set(vec![key(seed, Algorithm::EcdsaP256Sha256, KeyFlags::KSK)]);
        let example_com = key(6, Algorithm::RsaSha256, KeyFlags::KSK);
        let example_com_pkcs8 = example_com.to_pkcs8();
        Keys {
            root: set(vec![
                key(1, Algorithm::RsaSha256, KeyFlags::KSK),
                key(2, Algorithm::RsaSha256, KeyFlags::ZSK),
            ]),
            arpa: p256(3),
            com: p256(4),
            net: p256(5),
            example_com: set(vec![example_com]),
            example_com_pkcs8,
            dnssec_failed: p256(7),
            not_dnssec_failed: p256(8),
        }
    })
}

/// The DS RRset of the zone at `apex` signed with `keys`.
fn ds(keys: &KeySet, apex: &str) -> RecordSet {
    keys.ds(
        &name(apex),
        86_400,
        DigestType::Sha256,
        &AlgorithmPolicy::iana(),
    )
    .expect("a SHA-256 DS for a key the policy signs with")
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a test name")
}

fn date(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn zone(text: &str) -> Zone {
    Zone::from_master(text, None).unwrap_or_else(|error| panic!("a test zone: {error:?}\n{text}"))
}

/// `owner ttl NS host` and the host's addresses, for each of `servers`.
fn servers_of(owner: &str, ttl: u32, servers: &[(&str, Ipv4Addr, Option<Ipv6Addr>)]) -> String {
    let mut text = String::new();
    for (host, _, _) in servers {
        text += &format!("{owner} {ttl} IN NS {host}\n");
    }
    for (host, v4, v6) in servers {
        text += &format!("{host} {ttl} IN A {v4}\n");
        if let Some(v6) = v6 {
            text += &format!("{host} {ttl} IN AAAA {v6}\n");
        }
    }
    text
}

fn letters() -> Vec<(&'static str, Ipv4Addr, Option<Ipv6Addr>)> {
    ROOT_SERVERS
        .iter()
        .map(|server| (server.host, server.v4, Some(server.v6)))
        .collect()
}

fn gtld() -> Vec<(&'static str, Ipv4Addr, Option<Ipv6Addr>)> {
    GTLD_SERVERS
        .iter()
        .map(|server| (server.host, server.v4, Some(server.v6)))
        .collect()
}

/// The root zone: the root letters, `com` and `net` at the
/// `gtld-servers.net` servers, whose addresses sit below the `net` cut as
/// the real root holds them, `org`, and `arpa` at the root letters'
/// addresses.
fn root_text() -> String {
    let mut text = format!(
        ". 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. {ROOT_SERIAL} 1800 900 604800 86400\n"
    );
    text += &servers_of(".", 518_400, &letters());
    text += &servers_of("com.", 172_800, &gtld());
    for (host, _, _) in gtld() {
        text += &format!("net. 172800 IN NS {host}\n");
    }
    text += &servers_of("org.", 172_800, &[("ns1.nic.org.", ORG, Some(v6(ORG)))]);
    let arpa: Vec<_> = ARPA_SERVERS
        .iter()
        .map(|server| (server.host, server.v4, Some(server.v6)))
        .collect();
    text += &servers_of("arpa.", 172_800, &arpa);
    text
}

fn arpa_text() -> String {
    let mut text = String::from(
        "arpa. 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2026110100 1800 900 604800 86400\n",
    );
    for server in &ARPA_SERVERS {
        text += &format!("arpa. 518400 IN NS {}\n", server.host);
        text += &format!("{} 518400 IN A {}\n", server.host, server.v4);
        text += &format!("{} 518400 IN AAAA {}\n", server.host, server.v6);
    }
    let in_addr: Vec<_> = IN_ADDR_SERVERS
        .iter()
        .map(|server| (server.host, server.v4, Some(server.v6)))
        .collect();
    text += &servers_of("in-addr.arpa.", 172_800, &in_addr);
    for (host, _, _) in IANA_SERVERS {
        text += &format!("ipv4only.arpa. 172800 IN NS {host}\n");
    }
    text
}

/// `ipv4only.arpa`, with the two addresses RFC 7050 §2.2 gives it.
fn ipv4only_text() -> String {
    let mut text = String::from(
        "ipv4only.arpa. 3600 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2026110100 1800 900 604800 3600\n",
    );
    for (host, _, _) in IANA_SERVERS {
        text += &format!("ipv4only.arpa. 3600 IN NS {host}\n");
    }
    text += "ipv4only.arpa. 86400 IN A 192.0.0.170\nipv4only.arpa. 86400 IN A 192.0.0.171\n";
    text
}

/// `in-addr.arpa`, with the reverse names of the public resolvers'
/// addresses pointing at their names.
fn in_addr_text() -> String {
    let mut text = String::from(
        "in-addr.arpa. 3600 IN SOA b.in-addr-servers.arpa. nstld.iana.org. 2026110100 1800 900 604800 3600\n",
    );
    for server in &IN_ADDR_SERVERS {
        text += &format!("in-addr.arpa. 86400 IN NS {}\n", server.host);
    }
    for resolver in &PUBLIC_RESOLVERS {
        for address in &resolver.addresses {
            let [a, b, c, d] = address.v4.octets();
            text += &format!(
                "{d}.{c}.{b}.{a}.in-addr.arpa. 86400 IN PTR {}\n",
                address.ptr
            );
        }
    }
    text
}

/// `com`, whose serial is the Unix time as Verisign's is, with
/// `example.com` and `dnssec-failed.com` delegated. Their DS RRsets are
/// added once their keys are known.
fn com_text() -> String {
    let mut text = format!(
        "com. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. {START} 1800 900 604800 900\n"
    );
    for (host, _, _) in gtld() {
        text += &format!("com. 172800 IN NS {host}\n");
    }
    text += &servers_of(
        "example.com.",
        172_800,
        &[
            ("ns1.example.com.", EXAMPLE_COM[0], Some(v6(EXAMPLE_COM[0]))),
            ("ns2.example.com.", EXAMPLE_COM[1], Some(v6(EXAMPLE_COM[1]))),
        ],
    );
    text += &servers_of(
        "dnssec-failed.com.",
        172_800,
        &[(
            "ns1.dnssec-failed.com.",
            DNSSEC_FAILED,
            Some(v6(DNSSEC_FAILED)),
        )],
    );
    text
}

/// `net`, holding the addresses of the root, `gtld-servers.net`, and
/// `iana-servers.net` servers itself, and `example.net` delegated without a DS.
fn net_text() -> String {
    let mut text = format!(
        "net. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. {START} 1800 900 604800 900\n"
    );
    text += &servers_of("net.", 172_800, &gtld());
    for (host, v4, v6) in letters() {
        text += &format!("{host} 518400 IN A {v4}\n");
        if let Some(v6) = v6 {
            text += &format!("{host} 518400 IN AAAA {v6}\n");
        }
    }
    for (host, v4, v6) in IANA_SERVERS {
        text += &format!("{host} 172800 IN A {v4}\n{host} 172800 IN AAAA {v6}\n");
    }
    text += &servers_of(
        "example.net.",
        172_800,
        &[("ns1.example.net.", EXAMPLE_NET, Some(v6(EXAMPLE_NET)))],
    );
    text
}

fn org_text() -> String {
    let mut text = String::from(
        "org. 3600 IN SOA ns1.nic.org. hostmaster.nic.org. 2026110100 1800 900 604800 3600\n",
    );
    text += &servers_of("org.", 86_400, &[("ns1.nic.org.", ORG, Some(v6(ORG)))]);
    text += &servers_of(
        "example.org.",
        86_400,
        &[("ns1.example.org.", EXAMPLE_ORG, Some(v6(EXAMPLE_ORG)))],
    );
    text
}

/// `example.com`, with a record of most types an agent asks for, a CNAME,
/// and a TXT RRset too large for a 1232-octet UDP reply.
fn example_com_text() -> String {
    let big: String = (0..6)
        .map(|n| format!(" \"{n}{}\"", "x".repeat(250)))
        .collect();
    format!(
        "\
example.com. 3600 IN SOA ns1.example.com. dns.example.com. 2026110101 7200 3600 1209600 300
example.com. 86400 IN NS ns1.example.com.
example.com. 86400 IN NS ns2.example.com.
ns1.example.com. 86400 IN A {ns1}
ns1.example.com. 86400 IN AAAA {ns1_6}
ns2.example.com. 86400 IN A {ns2}
ns2.example.com. 86400 IN AAAA {ns2_6}
example.com. 300 IN A {www}
example.com. 300 IN AAAA 2600:3c00::80
www.example.com. 300 IN A {www}
www.example.com. 300 IN AAAA 2600:3c00::80
example.com. 300 IN MX 10 mail.example.com.
mail.example.com. 300 IN A 45.33.20.25
example.com. 300 IN TXT \"v=spf1 mx -all\"
_dmarc.example.com. 300 IN TXT \"v=DMARC1; p=reject\"
mail2026._domainkey.example.com. 300 IN TXT \"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\"
example.com. 300 IN CAA 0 issue \"letsencrypt.org\"
_xmpp-server._tcp.example.com. 300 IN SRV 5 0 5269 xmpp.example.com.
xmpp.example.com. 300 IN A 45.33.20.52
example.com. 300 IN HTTPS 1 . alpn=h2,h3 ipv4hint={www} ech={ech}
alias.example.com. 300 IN CNAME www.example.com.
big.example.com. 300 IN TXT{big}
",
        ns1 = EXAMPLE_COM[0],
        ns2 = EXAMPLE_COM[1],
        ns1_6 = v6(EXAMPLE_COM[0]),
        ns2_6 = v6(EXAMPLE_COM[1]),
        www = WWW_EXAMPLE_COM,
        ech = ECH,
    )
}

/// An ECHConfigList of the form Cloudflare publishes in its HTTPS
/// records, with the public name `cloudflare-ech.com`.
pub const ECH: &str = "AEX+DQBBpQAgACB/RU6G3j5GPZHUfMAH5Wi9XGBswuRJKhuyOUlmUa7wFwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

fn dnssec_failed_text() -> String {
    format!(
        "\
dnssec-failed.com. 3600 IN SOA ns1.dnssec-failed.com. dns.dnssec-failed.com. 1 7200 3600 1209600 300
dnssec-failed.com. 86400 IN NS ns1.dnssec-failed.com.
ns1.dnssec-failed.com. 86400 IN A {DNSSEC_FAILED}
ns1.dnssec-failed.com. 86400 IN AAAA {dnssec_failed_6}
www.dnssec-failed.com. 300 IN A 45.33.26.80
",
        dnssec_failed_6 = v6(DNSSEC_FAILED),
    )
}

fn example_net_text() -> String {
    format!(
        "\
example.net. 3600 IN SOA ns1.example.net. dns.example.net. 1 7200 3600 1209600 300
example.net. 86400 IN NS ns1.example.net.
ns1.example.net. 86400 IN A {EXAMPLE_NET}
ns1.example.net. 86400 IN AAAA {example_net_6}
www.example.net. 300 IN A 45.33.22.80
",
        example_net_6 = v6(EXAMPLE_NET),
    )
}

fn example_org_text() -> String {
    format!(
        "\
example.org. 3600 IN SOA ns1.example.org. dns.example.org. 1 7200 3600 1209600 300
example.org. 86400 IN NS ns1.example.org.
ns1.example.org. 86400 IN A {EXAMPLE_ORG}
ns1.example.org. 86400 IN AAAA {example_org_6}
www.example.org. 300 IN A 45.33.24.80
",
        example_org_6 = v6(EXAMPLE_ORG),
    )
}

fn fict_text() -> String {
    format!(
        "\
fict.com. 3600 IN SOA ns1.fict.com. dns.fict.com. 1 7200 3600 1209600 300
fict.com. 86400 IN NS ns1.fict.com.
ns1.fict.com. 86400 IN A {FICT_COM}
ns1.fict.com. 86400 IN AAAA {fict_com_6}
www.fict.com. 300 IN A 45.33.25.80
",
        fict_com_6 = v6(FICT_COM),
    )
}
