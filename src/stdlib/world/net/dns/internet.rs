//! The internet's DNS servers as hosts: the root servers at their real
//! addresses, and a [`Mirror`] that copies the real hierarchy onto
//! machines at the real servers' addresses.
//!
//! [`root_servers`] returns hosts at the addresses real clients know, so
//! a guest that asks `198.41.0.4` directly reaches one, and
//! [`server_host`] does the same for any other [`NameServer`]. What runs
//! on them, and how far away they are, is the world's
//! choice: a world with its own root serves zones, and a world that shows
//! the real internet serves copies of its zones, answered by the world's
//! own servers.
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::services::dns::authority::{ServerConfig, Zones};
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Authoritative;
//! # use fictionet::stdlib::world::net::dns::internet;
//! # async fn world(fcx: Cx, attachments: Attachments, root: &str) -> Result {
//! let root = Arc::new(internet::root_zone(root)?);
//! Net::new()
//!     .hosts(internet::root_servers(|_, host| {
//!         let server = ServerConfig::generic();
//!         host.program(Authoritative::new(Zones::new(vec![root.clone()]), server))
//!     }))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::network::ip::non_public_address;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Request, dname_substitute};
use fictionet::stdlib::services::dns::authority::{Authority, Copies, ServerConfig, Step};
use fictionet::stdlib::services::dns::zone::{Filing, Zone, ZoneError, dname_target};
use fictionet::stdlib::services::dns::{Client, Generation, Looked, Lookup};
use fictionet::sync::Mutex;

pub use fictionet::stdlib::services::dns::resolver::{NameServer, ROOT_SERVERS, root_hints};

use super::super::{Host, NetHandle};
use super::{Authoritative, Namespace, PerSession, Upstream};

// ---------------------------------------------------------------------------
// Hosts

/// A host at both of `server`'s addresses, named for it, with nothing on
/// it yet.
pub fn server_host(server: &NameServer) -> Host {
    Host::new(server.host.trim_end_matches('.'))
        .at(server.v4)
        .at(server.v6)
}

/// One host per root letter of [`ROOT_SERVERS`], at both of its
/// addresses, finished by `build`: the letter, and its [`server_host`].
/// `build` gives it its program, usually an [`Authoritative`] with the
/// front the world gives that letter, and any [`Host::delay`].
pub fn root_servers(build: impl Fn(&NameServer, Host) -> Host) -> Vec<Host> {
    ROOT_SERVERS
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

/// The port DNS servers answer on (RFC 1035 §4.2).
const DNS_PORT: u16 = 53;

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
/// of its own, such as [`root_servers`]. As the
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
/// [`delay`](Mirror::delay). An address where a machine already answers
/// on UDP port 53 gets no server: the world's own hosts there, such as
/// its root servers or a resolver, answer as the world made them, and
/// where one runs a mirrored server, that server answers for the new zone
/// too. A machine there that answers no DNS, such as a web site a world
/// placed at the address before any NS RRset named it, gets the server
/// beside its own services, behind the machine's own link. An
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

    /// The names of the mirror's name servers, as it learns them: the
    /// targets of the NS RRsets its copies file. A filing's targets are
    /// known before the observers see it.
    pub fn servers(&self) -> Servers {
        Servers(self.inner.named.clone())
    }
}

/// The names of a [`Mirror`]'s name servers ([`Mirror::servers`]).
#[derive(Clone)]
pub struct Servers(Arc<PerSession<Named>>);

impl Servers {
    /// Whether `name` names a name server in session `generation`: the
    /// target of an NS RRset the mirror's copies filed in it.
    pub fn named(&self, generation: Generation, name: &LowerName) -> bool {
        self.0
            .with(generation, |named| named.targets.contains_key(name))
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
                !self.handle.udp_bound(*addr, DNS_PORT) && placed.servers.insert(*addr)
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
/// A [`Mirror`]'s upstream asks every real server from one IPv4 address,
/// the [`upstream`](Echo::new) address, and the copied records hold what
/// the real server said to it. A resolver in the world whose real
/// counterpart asks that server from another IPv4 address, its egress,
/// would be shown that address instead. So a reply to a client given with
/// [`client`](Echo::client) carries its egress in place of the
/// upstream's: in an unsigned TXT string that is the upstream's address,
/// at any name, since a zone's own text names no single asker's address,
/// and in an unsigned A record at the names given with
/// [`name`](Echo::name), whose servers echo the asker. An A record at any
/// other name that holds the upstream's address is real data, such as a
/// site on the host's own address, and is left alone. The copied record
/// stays as the real server sent it; the
/// address is put in as the reply leaves, since it depends on who asked.
/// A world adds it with [`Mirror::wrap`] and [`Echo::over`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Echo {
    upstream: Ipv4Addr,
    egress: HashMap<IpAddr, Ipv4Addr>,
    names: HashSet<LowerName>,
}

impl Echo {
    /// Echoes for questions whose answers were asked from `upstream`. It
    /// changes no reply until a [`client`](Self::client) is given. Then it
    /// changes the TXT strings that are the upstream's address, at any
    /// name, and the A records that hold it only at the names given with
    /// [`name`](Self::name).
    pub fn new(upstream: Ipv4Addr) -> Echo {
        Echo {
            upstream,
            egress: HashMap::new(),
            names: HashSet::new(),
        }
    }

    /// Shows the client at `client` the IPv4 address `egress` where a
    /// reply echoes the upstream's.
    pub fn client(mut self, client: IpAddr, egress: Ipv4Addr) -> Echo {
        self.egress.insert(client, egress);
        self
    }

    /// Echoes the asker's address in the A records at `name`, whose real
    /// servers answer with the address a question came from.
    pub fn name(mut self, name: &Name) -> Echo {
        self.names.insert(LowerName::new(name));
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
                    && seen != self.echo.upstream
                {
                    echo(
                        &mut response.message,
                        &self.echo.names,
                        self.echo.upstream,
                        seen,
                    );
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
/// address a question came from: a TXT string that is `egress`, and an A
/// record holding `egress` at one of `names`. An RRset its RRSIGs cover
/// is left as it is.
fn echo(message: &mut Message, names: &HashSet<LowerName>, egress: Ipv4Addr, seen: Ipv4Addr) {
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
        let named = names.contains(&LowerName::new(&record.name));
        match &mut record.data {
            RData::A(a) if a.0 == egress && named => a.0 = seen,
            // Every other string keeps its octets (RFC 1035 §3.3.14).
            RData::TXT(txt) => {
                for string in txt.txt_data.iter_mut() {
                    if **string == *text.as_bytes() {
                        *string = seen.to_string().into_bytes().into_boxed_slice();
                    }
                }
            }
            _ => {}
        }
    }
}
