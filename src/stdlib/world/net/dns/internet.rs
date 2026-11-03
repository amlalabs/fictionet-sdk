//! The internet's DNS servers as hosts: the root and `gtld-servers.net`
//! servers at their real addresses, and a [`Mirror`] that copies the real
//! hierarchy onto machines at the real servers' addresses.
//!
//! [`root_servers`] and [`gtld_servers`] return hosts at the addresses
//! real clients know, so a guest that asks `198.41.0.4` directly reaches
//! one. What runs on them, and how far away they are, is the world's
//! choice: a world with its own root serves zones, and a world that shows
//! the real internet serves copies of its zones, answered by the world's
//! own servers.
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::services::dns::authority::{Identity, ServerConfig, Zones};
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Authoritative;
//! # use fictionet::stdlib::world::net::dns::internet;
//! # async fn world(fcx: Cx, attachments: Attachments, root: &str) -> Result {
//! let root = Arc::new(internet::root_zone(root)?);
//! Net::new()
//!     .hosts(internet::root_servers(|_, host| {
//!         let server = ServerConfig::root(Identity::none());
//!         host.program(Authoritative::new(Zones::new(vec![root.clone()]), server))
//!     }))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```
//!
//! The addresses and names here were read on 2026-11-01: the root servers
//! from IANA's `named.root`, the rest from the servers themselves.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::network::ip::non_public_address;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::rdata::TXT;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Request, dname_substitute};
use fictionet::stdlib::services::dns::authority::{Authority, Copies, ServerConfig, Step};
use fictionet::stdlib::services::dns::zone::{AnyResponse, Filing, Zone, ZoneError, dname_target};
use fictionet::stdlib::services::dns::{Client, Generation, Looked, Lookup};
use fictionet::sync::Mutex;

pub use fictionet::stdlib::services::dns::resolver::{NameServer, ROOT_SERVERS, root_hints};

use super::super::{Host, NetHandle};
use super::{Authoritative, Namespace, PerSession, Upstream};

// ---------------------------------------------------------------------------
// Servers and their addresses

/// A host at both of `server`'s addresses, named for it, with nothing on
/// it yet.
pub fn server_host(server: &NameServer) -> Host {
    Host::new(server.host.trim_end_matches('.'))
        .at(server.v4)
        .at(server.v6)
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

/// The root letter `index` of [`ROOT_SERVERS`], with what its operator's
/// software does.
const fn letter(index: usize, operator: &'static str, payload: u16, any: AnyResponse) -> Letter {
    Letter {
        server: ROOT_SERVERS[index],
        operator,
        payload,
        any,
    }
}

/// The root servers, in letter order, at the addresses of
/// [`ROOT_SERVERS`]; operators from root-servers.org. The payload sizes
/// and ANY answers were seen at each letter on 2026-11-01: b, j, and k
/// answer `. ANY` with the NS RRset alone, h and l with the SOA alone, and
/// the others with every RRset. [`root_hints`] gives the same addresses
/// as resolver hints.
pub const ROOT_LETTERS: [Letter; 13] = [
    letter(0, "Verisign", 4096, AnyResponse::All),
    letter(1, "USC-ISI", 1232, AnyResponse::OneRrset(RecordType::NS)),
    letter(2, "Cogent", 1232, AnyResponse::All),
    letter(3, "University of Maryland", 1450, AnyResponse::All),
    letter(4, "NASA Ames", 1472, AnyResponse::All),
    letter(5, "ISC", 1472, AnyResponse::All),
    letter(6, "US DoD (DISA)", 1232, AnyResponse::All),
    letter(
        7,
        "US Army (ARL)",
        1232,
        AnyResponse::OneRrset(RecordType::SOA),
    ),
    letter(8, "Netnod", 1232, AnyResponse::All),
    letter(9, "Verisign", 1472, AnyResponse::OneRrset(RecordType::NS)),
    letter(10, "RIPE NCC", 1232, AnyResponse::OneRrset(RecordType::NS)),
    letter(11, "ICANN", 4096, AnyResponse::OneRrset(RecordType::SOA)),
    letter(12, "WIDE", 1232, AnyResponse::All),
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
/// answer for `arpa` themselves, so a [`Mirror`] serves its copy at the
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
// Hosts

/// One host per root letter, at both of its addresses, finished by
/// `build`: the letter, and its [`server_host`]. `build` gives it its
/// program, usually an [`Authoritative`] with the letter's
/// [`payload`](Letter::payload) and [`any`](Letter::any) in its front, and
/// any [`Host::delay`].
pub fn root_servers(build: impl Fn(&Letter, Host) -> Host) -> Vec<Host> {
    ROOT_LETTERS
        .iter()
        .map(|letter| build(letter, server_host(&letter.server)))
        .collect()
}

/// One host per `gtld-servers.net` server, at both of its addresses,
/// finished by `build` as [`root_servers`] finishes a letter's.
pub fn gtld_servers(build: impl Fn(&NameServer, Host) -> Host) -> Vec<Host> {
    GTLD_SERVERS
        .iter()
        .map(|server| build(server, server_host(server)))
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

/// A callback that sees what each response gave a mirrored zone.
type Observer = dyn Fn(&Filing) + Send + Sync;

/// What a world puts around each mirrored server's authority.
type Wrap = dyn Fn(Arc<dyn Authority>) -> Arc<dyn Authority> + Send + Sync;

/// What a world places at the addresses of one name.
type Front = dyn Fn(Host) -> Host + Send + Sync;

/// Copies of the real hierarchy: the zones the world says its servers
/// serve, such as the root at the root letters' addresses, and every zone
/// below them that the copied records name, each served at its real
/// servers' addresses from records copied from those servers.
///
/// [`server`](Mirror::server) is a program that answers, at its own
/// address, for the zones the mirror knows that address serves: those
/// given with [`serves`](Mirror::serves), every zone whose copied records
/// name that address a server of it, and every zone below one of those
/// that the real server turns out to answer from, such as `arpa` at the
/// root letters' addresses. Each zone's data is
/// [`Learned`](fictionet::stdlib::services::dns::zone::Learned): one per
/// zone, shared by all of the zone's servers, filled from the real
/// servers through the mirror's upstream as the world's servers need
/// facts, and answered from by the world's own [`Copies`]. No real
/// server's message reaches a client. A world runs the program on hosts
/// of its own, such as [`root_servers`] and [`gtld_servers`]. As the
/// copies file what the real servers answered ([`Filing`]), the mirror
/// places more servers, so a resolver in the world can follow the
/// hierarchy as far down as the upstream answers:
///
/// - at each address a filed referral gives as glue for a name server it
///   names (RFC 9471), and
/// - at each address a filed A or AAAA RRset gives this session for a
///   name that a filed NS RRset named this session, whichever came first,
///   for a delegation without glue, such as a `.com` zone served from
///   `awsdns-NN.org` or `8.in-addr.arpa` served from `arin.net`.
///
/// Each server is placed when the records that name it are filed, before
/// the reply that needed them leaves, behind the mirror's
/// [`delay`](Mirror::delay). An address where a host's machine already
/// is gets no server: the world's own hosts there, such as its root
/// servers or a resolver, answer as the world made them, and where one
/// runs a mirrored server, that server answers for the new zone too. An
/// address a filed NS RRset
/// names whose real server turns out not to serve the zone, as at a lame
/// delegation, answers for the rest of the session from the zones it does
/// serve, as [`Copies`] says. The names of name servers and the addresses
/// filed for them are forgotten when the namespace advances, and so is
/// every zone's copied data.
///
/// Addresses on the sandboxes' subnet or a LAN, addresses no internet
/// host can have (those the IANA special-purpose registries of RFC 6890
/// mark not globally reachable), and the [`egress`](Mirror::egress)
/// addresses the upstream asks from are never placed: the reply still
/// reaches the client as it was, and the address stays unreachable.
#[derive(Clone)]
pub struct Mirror {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    upstream: Arc<dyn Upstream>,
    handle: NetHandle,
    delay: Duration,
    namespace: Option<Namespace>,
    observers: Vec<Arc<Observer>>,
    wraps: Vec<Arc<Wrap>>,
    fronts: Vec<(LowerName, Arc<Front>)>,
    named: Arc<PerSession<Named>>,
    placed: Arc<Mutex<Placed>>,
    /// Each zone's copied data, and the zones each address serves.
    copies: Arc<Copies>,
    /// The addresses the upstream asks the real servers from.
    egress: Vec<IpAddr>,
}

/// What the copies filed this session.
#[derive(Default)]
struct Named {
    /// The name servers filed NS RRsets named, with the zones they serve.
    targets: HashMap<LowerName, HashSet<LowerName>>,
    /// The addresses filed A and AAAA RRsets gave, by owner, so a name
    /// server whose address came before any NS RRset named it still gets
    /// its server.
    addresses: HashMap<LowerName, Vec<IpAddr>>,
    /// The target of each filed CNAME, by owner, so a front's name that
    /// is an alias finds its addresses.
    aliases: HashMap<LowerName, LowerName>,
    /// The target of each filed DNAME, by owner, so a front's name below
    /// one finds the addresses of the name it substitutes.
    dnames: HashMap<LowerName, Name>,
}

impl Named {
    /// The addresses filed for `name` or for the name at the end of its
    /// CNAME and DNAME chain. A DNAME above a name redirects it before
    /// any CNAME at it, since the DNAME's zone holds nothing below its
    /// owner (RFC 6672 §2.3).
    fn addresses_of(&self, name: &LowerName) -> Vec<IpAddr> {
        let mut name = name.clone();
        let mut seen = vec![name.clone()];
        while let Some(target) = self.alias_of(&name) {
            if seen.contains(&target) {
                return Vec::new();
            }
            seen.push(target.clone());
            name = target;
        }
        self.addresses.get(&name).cloned().unwrap_or_default()
    }

    /// The name a filed DNAME above `name` substitutes for it, or else
    /// the target of a filed CNAME at `name`.
    fn alias_of(&self, name: &LowerName) -> Option<LowerName> {
        let full = Name::from(name.clone());
        let mut owner = name.clone();
        while !owner.is_root() {
            owner = owner.base_name();
            if let Some(target) = self.dnames.get(&owner) {
                return dname_substitute(&full, &Name::from(owner), target)
                    .map(|substituted| LowerName::new(&substituted));
            }
        }
        self.aliases.get(name).cloned()
    }
}

/// Where a mirror placed something, in every session.
#[derive(Default)]
struct Placed {
    /// Addresses given a server, or found unable to take one.
    servers: HashSet<IpAddr>,
    /// Addresses given a front.
    fronts: HashSet<IpAddr>,
}

impl Mirror {
    /// A mirror copying what `upstream` says the real servers answer, and
    /// placing servers with `handle`. It knows no server yet: a world
    /// gives the zones its own hosts serve with [`serves`](Self::serves).
    pub fn new(upstream: impl Upstream, handle: NetHandle) -> Mirror {
        Mirror {
            inner: Arc::new(Inner {
                upstream: Arc::new(upstream),
                handle,
                delay: Duration::ZERO,
                namespace: None,
                observers: Vec::new(),
                wraps: Vec::new(),
                fronts: Vec::new(),
                named: Arc::default(),
                placed: Arc::default(),
                copies: Arc::new(Copies::new()),
                egress: Vec::new(),
            }),
        }
    }

    /// The same mirror, changed by `change`. Servers made before keep
    /// what they had.
    fn with(self, change: impl FnOnce(&mut Inner)) -> Mirror {
        let mut inner = Arc::unwrap_or_clone(self.inner);
        change(&mut inner);
        Mirror {
            inner: Arc::new(inner),
        }
    }

    /// Notes that the server at `addr` serves the zone at `zone`, such as
    /// the root at each root letter's addresses, so a
    /// [`server`](Self::server) there answers for it from the zone's copy.
    pub fn serves(self, addr: IpAddr, zone: &Name) -> Mirror {
        self.inner.copies.serves(addr, &LowerName::new(zone));
        self
    }

    /// Notes `addr` as an address the upstream asks the real servers from,
    /// where the mirror places no server: a server there would send its
    /// lookups from the host to the host's own network edge.
    pub fn egress(self, addr: IpAddr) -> Mirror {
        self.with(|inner| inner.egress.push(addr))
    }

    /// Places each server behind [`Host::delay`] `delay`, the time a
    /// packet takes each way between the network and the real server.
    /// Without it, servers answer at once.
    pub fn delay(self, delay: Duration) -> Mirror {
        self.with(|inner| inner.delay = delay)
    }

    /// Servers for the sessions of `namespace`: when it advances, every
    /// zone drops what it copied, every server abandons its lookups, and
    /// the mirror forgets the name servers it has seen named.
    pub fn namespace(self, namespace: &Namespace) -> Mirror {
        self.with(|inner| inner.namespace = Some(namespace.clone()))
    }

    /// Calls `f` with what each response gave a mirrored zone, when it
    /// gave any RRset: after the servers it names are placed, and before
    /// the reply that needed it leaves. So a world learns the names and
    /// addresses the copies hold, which are what the world's servers
    /// answer with. Observers run in the order given.
    pub fn observe(self, f: impl Fn(&Filing) + Send + Sync + 'static) -> Mirror {
        self.with(|inner| inner.observers.push(Arc::new(f)))
    }

    /// Wraps the authority of every server the mirror makes, such as with
    /// an [`Overlay`](fictionet::stdlib::services::dns::authority::Overlay)
    /// for an invented zone or an [`Echo`]. Each wrap goes around the
    /// ones given before it.
    pub fn wrap(
        self,
        f: impl Fn(Arc<dyn Authority>) -> Arc<dyn Authority> + Send + Sync + 'static,
    ) -> Mirror {
        self.with(|inner| inner.wraps.push(Arc::new(f)))
    }

    /// Places `build(host)` at each address filed for `name` in an A or
    /// AAAA RRset, or for the name at the end of its CNAME and DNAME
    /// chain, the first time it is filed, joining a machine that is
    /// there. `host` is a host at that address only, and an address no
    /// internet host can have gets none, as with servers. A world uses it
    /// for a resolver's DNS over HTTPS front at the addresses of a name of
    /// its own, which are not the resolver's.
    pub fn front(self, name: Name, build: impl Fn(Host) -> Host + Send + Sync + 'static) -> Mirror {
        let name = LowerName::new(&name);
        self.with(|inner| inner.fronts.push((name, Arc::new(build))))
    }

    /// A program answering, at its own address, for the zones the mirror
    /// knows that address serves, with `server` as its front, and the
    /// mirror's upstream and namespace.
    pub fn server(&self, server: ServerConfig) -> Authoritative<Arc<dyn Authority>> {
        self.inner.server(server)
    }
}

impl Inner {
    fn server(self: &Arc<Self>, server: ServerConfig) -> Authoritative<Arc<dyn Authority>> {
        let mirrored: Arc<dyn Authority> = Arc::new(Mirrored(self.clone()));
        let authority = self
            .wraps
            .iter()
            .fold(mirrored, |authority, wrap| wrap(authority));
        let program = Authoritative::new(authority, server).upstream(self.upstream.clone());
        match &self.namespace {
            Some(namespace) => program.namespace(namespace),
            None => program,
        }
    }

    /// Places the servers and fronts that `filing`, filed in session
    /// `generation`, names, notes the zones they serve, and shows the
    /// filing to the observers.
    fn place(self: &Arc<Self>, filing: &Filing, generation: Generation) {
        // Each name server a filed NS RRset names, with the zone it serves.
        let mut targets: HashMap<LowerName, HashSet<LowerName>> = HashMap::new();
        let mut addresses: Vec<(LowerName, IpAddr)> = Vec::new();
        let mut aliases: Vec<(LowerName, LowerName)> = Vec::new();
        let mut dnames: Vec<(LowerName, Name)> = Vec::new();
        for (_, set) in &filing.sets {
            let owner = LowerName::new(set.name());
            for record in set.records_without_rrsigs() {
                match &record.data {
                    RData::NS(ns) => {
                        targets
                            .entry(LowerName::new(&ns.0))
                            .or_default()
                            .insert(owner.clone());
                    }
                    RData::CNAME(cname) => aliases.push((owner.clone(), LowerName::new(&cname.0))),
                    data => match dname_target(data) {
                        Some(target) => dnames.push((owner.clone(), target)),
                        None => addresses.extend(data.ip_addr().map(|addr| (owner.clone(), addr))),
                    },
                }
            }
        }
        let mut servers: Vec<(IpAddr, LowerName, LowerName)> = Vec::new();
        let mut fronts: Vec<(IpAddr, &LowerName, &Arc<Front>)> = Vec::new();
        self.named.with(generation, |named| {
            for (owner, addr) in &addresses {
                let known = named.addresses.entry(owner.clone()).or_default();
                if !known.contains(addr) {
                    known.push(*addr);
                }
            }
            named.aliases.extend(aliases);
            named.dnames.extend(dnames);
            for (target, zones) in &targets {
                named
                    .targets
                    .entry(target.clone())
                    .or_default()
                    .extend(zones.iter().cloned());
            }
            // Each name server this filing named that has an address, and
            // each address it gave a name server, whichever of the NS
            // RRset and the address was filed first.
            for (target, zones) in &targets {
                for addr in named.addresses.get(target).into_iter().flatten() {
                    for zone in zones {
                        servers.push((*addr, target.clone(), zone.clone()));
                    }
                }
            }
            for (owner, addr) in &addresses {
                for zone in named.targets.get(owner).into_iter().flatten() {
                    servers.push((*addr, owner.clone(), zone.clone()));
                }
            }
            for (name, front) in &self.fronts {
                fronts.extend(
                    named
                        .addresses_of(name)
                        .into_iter()
                        .map(|addr| (addr, name, front)),
                );
            }
        });
        servers.retain(|(addr, _, _)| !non_public_address(*addr) && !self.egress.contains(addr));
        for (addr, _, zone) in &servers {
            self.copies.serves(*addr, zone);
        }
        {
            let mut placed = self.placed.lock();
            servers.retain(|(addr, _, _)| {
                !self.handle.has_machine(*addr) && placed.servers.insert(*addr)
            });
            fronts.retain(|(addr, _, _)| !non_public_address(*addr) && placed.fronts.insert(*addr));
        }
        // The network refuses an address on the sandboxes' subnet or a
        // LAN; such an address stays without a server.
        for (addr, name, _) in servers {
            let host = only_at(&name.to_ascii(), addr)
                .delay(self.delay)
                .program(self.server(ServerConfig::generic()));
            let _ = self.handle.add_host(host);
        }
        for (addr, name, build) in fronts {
            let _ = self.handle.add_host(build(only_at(&name.to_ascii(), addr)));
        }
        for observer in &self.observers {
            observer(filing);
        }
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

/// The zones a mirror knows an address serves, answered from their copied
/// data, with what is filed into them placing the servers it names.
struct Mirrored(Arc<Inner>);

impl Authority for Mirrored {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        self.0.copies.respond(req, local, server, client)
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        if let Some(filing) = self.0.copies.keep(lookup, looked, generation)
            && !filing.sets.is_empty()
        {
            self.0.place(&filing, generation);
        }
    }

    fn advance(&self, generation: Generation) {
        self.0.copies.advance(generation);
    }
}

// ---------------------------------------------------------------------------
// Echo

/// Replies that show each client the address its own questions to the
/// real servers would leave from, for servers that echo the address a
/// question came from, as the whoami names of Akamai do.
///
/// A [`Mirror`]'s upstream asks every real server from one address, the
/// [`upstream`](Echo::new) address, and the copied records hold what the
/// real server said to it. A resolver in the world whose real counterpart
/// asks from another address, its egress, would be shown that address
/// instead. So a reply to a client given with [`client`](Echo::client)
/// carries its egress in place of the upstream's: in an unsigned A record
/// when the egress is IPv4, and in a TXT string. The copied record stays
/// as the real server sent it; the address is put in as the reply leaves,
/// since it depends on who asked. A world adds it with [`Mirror::wrap`]
/// and [`Echo::over`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Echo {
    upstream: Ipv4Addr,
    egress: HashMap<IpAddr, IpAddr>,
}

impl Echo {
    /// Echoes for questions whose answers were asked from `upstream`. It
    /// changes no reply until a [`client`](Self::client) is given.
    pub fn new(upstream: Ipv4Addr) -> Echo {
        Echo {
            upstream,
            egress: HashMap::new(),
        }
    }

    /// Shows the client at `client` the address `egress` where a reply
    /// echoes the upstream's.
    pub fn client(mut self, client: IpAddr, egress: IpAddr) -> Echo {
        self.egress.insert(client, egress);
        self
    }

    /// `authority`, its replies echoing each client's egress.
    pub fn over(&self, authority: Arc<dyn Authority>) -> Arc<dyn Authority> {
        Arc::new(Echoed {
            echo: self.clone(),
            authority,
        })
    }
}

/// An authority whose replies [`Echo`] changes.
struct Echoed {
    echo: Echo,
    authority: Arc<dyn Authority>,
}

impl Authority for Echoed {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        match self.authority.respond(req, local, server, client) {
            Step::Reply(mut response) => {
                if let Some(&seen) = self.echo.egress.get(&client.peer.ip())
                    && seen != IpAddr::V4(self.echo.upstream)
                {
                    echo(&mut response.message, self.echo.upstream, seen);
                }
                Step::Reply(response)
            }
            step => step,
        }
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        self.authority.file(lookup, looked, generation);
    }

    fn advance(&self, generation: Generation) {
        self.authority.advance(generation);
    }
}

/// Puts `seen` in place of `egress` where `message`'s answer echoes the
/// address a question came from, as `whoami.akamai.net` A or
/// `whoami.ds.akahelp.net` TXT do: an A record holding `egress`, which
/// takes `seen` when it is IPv4, and a TXT string that is `egress`. An
/// RRset its RRSIGs cover is left as it is.
fn echo(message: &mut Message, egress: Ipv4Addr, seen: IpAddr) {
    let signed: Vec<(Name, RecordType)> = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                Some((record.name.clone(), rrsig.input().type_covered))
            }
            _ => None,
        })
        .collect();
    let text = egress.to_string();
    for record in &mut message.answers {
        if signed.contains(&(record.name.clone(), record.record_type())) {
            continue;
        }
        match (&mut record.data, seen) {
            (RData::A(a), IpAddr::V4(seen)) if a.0 == egress => a.0 = seen,
            (RData::TXT(txt), _) if txt.txt_data.iter().any(|s| **s == *text.as_bytes()) => {
                let strings = txt.txt_data.iter().map(|s| {
                    if **s == *text.as_bytes() {
                        seen.to_string()
                    } else {
                        String::from_utf8_lossy(s).into_owned()
                    }
                });
                *txt = TXT::new(strings.collect());
            }
            _ => {}
        }
    }
}
