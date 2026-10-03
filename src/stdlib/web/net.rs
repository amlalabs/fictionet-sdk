//! The network around the sites: the router, the sandboxes' filters with
//! address binding and DHCP, the gateway, the machines, and ICMP "host
//! unreachable" (ICMPv6 "address unreachable") for every other address.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;

use super::{Blocked, BlockedWhy, Event, Family, Handler, OnEvent, Sandbox, Site, SiteFor, SiteTls, http_serve, names};
use crate::stdlib::dhcp::{self, opt};
use crate::stdlib::route::{self, Prefix, Router};
use crate::stdlib::udp::{UDP, ip_packet, parse_ip, transport_checksum, udp_checksum_ok};
use crate::stdlib::wire::{self, V4, V6};
use crate::stdlib::ip::{Intake, Reassembly};
use crate::stdlib::{Event as PortEvent, Ports, icmp, ip, tcp, udp};
use crate::{Attachment, Attachments, Cx, End, Error, Interface, InterfaceExt, Packet};

/// How long a DHCP lease lasts. The binding itself lasts until the sandbox
/// detaches; the lease time only tells the client when to renew.
const LEASE: u32 = 3600;

/// Where sites without [`Site::at`](super::Site::at) get their addresses:
/// `198.18.0.0/15`.
const AUTO_BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const AUTO_SIZE: u32 = 1 << 17;

/// Where sites without an IPv6 [`Site::at`](super::Site::at) get theirs:
/// `2001:2::/48`, the IPv6 range set aside for benchmarking (RFC 5180), as
/// `198.18.0.0/15` is for IPv4.
const AUTO6_BASE: u128 = 0x2001_0002_0000_0000_0000_0000_0000_0000;
const AUTO6_LEN: u8 = 48;
const AUTO6_SIZE: u128 = 1 << (128 - AUTO6_LEN);

/// Each link inside the network (sandbox to router, router to machine)
/// holds at most this many bytes of packets each way; past that, packets
/// are dropped. Several sandboxes, each sending as fast as it can, can
/// send faster than the router forwards, and the queues in between would
/// otherwise grow without end.
const LINK_QUEUE: usize = 4 << 20;

/// A link inside the network: a cable whose queues are capped at
/// [`LINK_QUEUE`].
fn link() -> (End, End) {
    crate::cable::pair_with_limit(LINK_QUEUE)
}

/// Locks a mutex, ignoring poison: a panic elsewhere (such as in the
/// world's callback) must not take the whole network down with it.
pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Everything the tasks of one `serve` share.
pub(super) struct Shared {
    /// A context in the region `serve` was given. Machines that appear
    /// later start their tasks here.
    pub(super) cx: Cx,
    site_for: Arc<SiteFor>,
    pub(super) subnet: Subnet,
    /// The sandboxes' IPv6 subnet. `None` when IPv6 is off.
    pub(super) subnet6: Option<Subnet6>,
    router: Router,
    world: Mutex<World>,
    leases: Mutex<Leases>,
    /// The gateway's TCP, for DNS: one endpoint for each of its addresses.
    gateway_tcp: Mutex<Vec<tcp::Endpoint>>,
    pub(super) hooks: Arc<Hooks>,
}

/// The world's event callback, and what events need to name sandboxes.
/// Machines hold it too.
pub(super) struct Hooks {
    on_event: Option<Arc<OnEvent>>,
    /// The sandbox that last bound each address, IPv4 and IPv6. An entry
    /// stays after its sandbox detaches, until another binds the address,
    /// so packets and connections still on their way name the sandbox that
    /// sent them. Filled only when there is a callback.
    by_addr: Mutex<HashMap<IpAddr, Sandbox>>,
    /// The last connection number given out.
    conns: AtomicU64,
    /// The ids of the sandboxes attached now. Filled only when there is a
    /// callback.
    attached: Mutex<std::collections::HashSet<u64>>,
}

impl Hooks {
    /// Whether the world set a callback. Without one, events are never
    /// made.
    pub(super) fn on(&self) -> bool {
        self.on_event.is_some()
    }

    /// Gives `event` to the world's callback, if there is one.
    pub(super) fn emit(&self, cx: &Cx, event: Event) {
        if let Some(f) = &self.on_event {
            f(cx, &event);
        }
    }

    /// The sandbox that sent from `addr`.
    pub(super) fn sandbox_at(&self, addr: IpAddr) -> Sandbox {
        if let Some(s) = lock(&self.by_addr).get(&addr) {
            return s.clone();
        }
        // Only addresses some sandbox bound reach the sites, so this is
        // not expected. The address alone still says something.
        let (v4, v6) = match addr {
            IpAddr::V4(a) => (Some(a), None),
            IpAddr::V6(a) => (None, Some(a)),
        };
        Sandbox { id: 0, name: Arc::from(""), addr: v4, addr_v6: v6 }
    }

    /// Whether the sandbox with this id is still attached.
    pub(super) fn is_attached(&self, id: u64) -> bool {
        lock(&self.attached).contains(&id)
    }

    /// A number for a new connection on port 80 or 443.
    pub(super) fn next_conn(&self) -> u64 {
        self.conns.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// The sandboxes' subnet.
#[derive(Clone, Copy, Debug)]
pub(super) struct Subnet {
    net: u32,
    mask: u32,
    pub(super) gateway: Ipv4Addr,
}

impl Subnet {
    fn new(p: Prefix) -> Result<Subnet, Error> {
        let IpAddr::V4(a) = p.addr else {
            return Err(format!("the sandboxes' subnet {}/{} must be IPv4", p.addr, p.len).into());
        };
        if !(8..=30).contains(&p.len) {
            return Err(format!("the sandboxes' subnet {a}/{} must have a length from 8 to 30", p.len).into());
        }
        let mask = u32::MAX << (32 - p.len as u32);
        let net = u32::from(a) & mask;
        Ok(Subnet { net, mask, gateway: Ipv4Addr::from(net + 1) })
    }

    pub(super) fn contains(&self, a: Ipv4Addr) -> bool {
        u32::from(a) & self.mask == self.net
    }

    fn broadcast(&self) -> u32 {
        self.net | !self.mask
    }

    /// Whether a sandbox may have `a`: inside the subnet, and not the
    /// network address, the broadcast address or the gateway.
    fn is_sandbox(&self, a: Ipv4Addr) -> bool {
        let n = u32::from(a);
        self.contains(a) && n != self.net && n != self.broadcast() && a != self.gateway
    }

    /// Every address a sandbox may have, lowest first.
    fn sandboxes(&self) -> impl Iterator<Item = Ipv4Addr> {
        (self.net + 2..self.broadcast()).map(Ipv4Addr::from)
    }

    fn mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.mask)
    }
}

/// The sandboxes' IPv6 subnet.
#[derive(Clone, Copy, Debug)]
pub(super) struct Subnet6 {
    net: u128,
    mask: u128,
    pub(super) gateway: Ipv6Addr,
}

impl Subnet6 {
    fn new(p: Prefix) -> Result<Subnet6, Error> {
        let IpAddr::V6(a) = p.addr else {
            return Err(format!("the sandboxes' IPv6 subnet {}/{} must be IPv6", p.addr, p.len).into());
        };
        if !(8..=126).contains(&p.len) {
            return Err(format!("the sandboxes' IPv6 subnet {a}/{} must have a length from 8 to 126", p.len).into());
        }
        let mask = u128::MAX << (128 - p.len as u32);
        let net = u128::from(a) & mask;
        // Global unicast (2000::/3) or unique local (fc00::/7).
        let global = net >> 125 == 0b001;
        let ula = net >> 121 == 0b111_1110;
        if !(global || ula) {
            return Err(format!("the sandboxes' IPv6 subnet {a}/{} must lie inside 2000::/3 or fc00::/7", p.len).into());
        }
        Ok(Subnet6 { net, mask, gateway: Ipv6Addr::from(net + 1) })
    }

    pub(super) fn contains(&self, a: Ipv6Addr) -> bool {
        u128::from(a) & self.mask == self.net
    }

    /// Whether a sandbox may have `a`: inside the subnet, and not the
    /// subnet's first address (the subnet-router anycast address) or the
    /// gateway.
    fn is_sandbox(&self, a: Ipv6Addr) -> bool {
        self.contains(a) && u128::from(a) != self.net && a != self.gateway
    }
}

/// A site's addresses. A name with a site has at least one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Placed {
    pub(super) v4: Option<Ipv4Addr>,
    pub(super) v6: Option<Ipv6Addr>,
}

/// Whether a site may be served at `a`: an address one host can have, and
/// not a sandbox's.
fn may_serve_v4(a: Ipv4Addr, subnet: &Subnet) -> bool {
    !(subnet.contains(a) || a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.is_loopback())
}

/// As [`may_serve_v4`], for IPv6.
fn may_serve_v6(a: Ipv6Addr, subnet: &Subnet6) -> bool {
    !(subnet.contains(a)
        || a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || a.is_unicast_link_local()
        || a.to_ipv4_mapped().is_some())
}

/// At most this many names the callback turned down are remembered. Past
/// that, such names are not kept, and asking again runs the callback
/// again. The agent picks the names, so without a limit a flood of lookups
/// for made-up names would grow the world's memory without end. A name
/// costs its length plus about 50 bytes of table. Only names of at most
/// 253 bytes are kept (see [`World::remember`]), so about 35 MB at most.
const MAX_UNKNOWN_NAMES: usize = 100_000;

/// How many names may have a site, unless the world sets another limit with
/// [`Sites::max_sites`](super::Sites::max_sites). Each site has at most
/// two machines, one per family, and a machine costs about 11 KiB, so the
/// default holds the machines to about 430 MiB.
pub(super) const MAX_SITES: usize = 20_000;

/// What a lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lookup {
    /// The name has a site, at these addresses.
    Site(Placed),
    /// The name has no site: NXDOMAIN.
    NoSite,
    /// The callback gave the name a site, but the world already has as many
    /// sites as it may. The site was dropped and the name is not kept.
    Full,
}

/// Names and machines.
struct World {
    /// Every name looked up so far, with its addresses, or `None` for
    /// NXDOMAIN.
    names: HashMap<String, Option<Placed>>,
    /// How many of `names` are NXDOMAIN.
    unknown: usize,
    /// [`MAX_UNKNOWN_NAMES`], or less in tests.
    max_unknown: usize,
    /// How many of `names` have a site.
    sites: usize,
    /// [`MAX_SITES`], or what the world set.
    max_sites: usize,
    /// One machine per address, IPv4 and IPv6.
    machines: HashMap<IpAddr, Arc<Machine>>,
    /// Where the search for a free automatic address starts.
    next_auto: u32,
    /// The same, for IPv6: an offset into `2001:2::/48`.
    next_auto6: u128,
    /// No automatic address is left. Machines are never removed, so this
    /// stays true, and later searches are skipped: each would scan all
    /// 131,072 addresses, for every new name the agent asks for.
    auto_full: bool,
}

impl World {
    fn new(max_sites: usize) -> World {
        World {
            names: HashMap::new(),
            unknown: 0,
            max_unknown: MAX_UNKNOWN_NAMES,
            sites: 0,
            max_sites,
            machines: HashMap::new(),
            next_auto: 1,
            next_auto6: 1,
            auto_full: false,
        }
    }

    /// Keeps the answer for `name`, unless it is NXDOMAIN and too many
    /// of those are kept already, or it is longer than a host name can be.
    /// A name arrives in its text form, where a byte that is not printable
    /// takes four characters (`\255`), so the 255 bytes of a name on the
    /// wire can be about 1,000 here. A site is always kept:
    /// [`Shared::lookup`] counts it against [`World::max_sites`] before it
    /// starts machines.
    fn remember(&mut self, name: &str, addr: Option<Placed>) {
        match addr {
            None if self.unknown >= self.max_unknown || name.len() > 253 => return,
            None => self.unknown += 1,
            Some(_) => self.sites += 1,
        }
        self.names.insert(name.to_owned(), addr);
    }
    /// A free address in `198.18.0.0/15`, not the first or last, and not
    /// inside the sandboxes' subnet (which holds the gateway).
    fn free_auto(&mut self, subnet: &Subnet) -> Option<Ipv4Addr> {
        if self.auto_full {
            return None;
        }
        for _ in 0..AUTO_SIZE {
            let n = self.next_auto;
            self.next_auto = (self.next_auto + 1) % AUTO_SIZE;
            if n == 0 || n == AUTO_SIZE - 1 {
                continue;
            }
            let a = Ipv4Addr::from(AUTO_BASE + n);
            if !subnet.contains(a) && !self.machines.contains_key(&a.into()) {
                return Some(a);
            }
        }
        self.auto_full = true;
        None
    }

    /// A free address in `2001:2::/48`, not its first address, and not
    /// inside the sandboxes' subnet. `None` only when that subnet covers
    /// the whole range.
    fn free_auto6(&mut self, subnet: &Subnet6) -> Option<Ipv6Addr> {
        // Prefixes either nest or do not meet. A subnet that holds the
        // whole range leaves nothing.
        let pool_mask = u128::MAX << (128 - AUTO6_LEN as u32);
        if subnet.mask <= pool_mask && subnet.contains(Ipv6Addr::from(AUTO6_BASE)) {
            return None;
        }
        // Each machine can be passed over once, and the subnet skipped
        // once per round, so this always ends.
        for _ in 0..self.machines.len() + 4 {
            let n = self.next_auto6;
            self.next_auto6 = (self.next_auto6 + 1) % AUTO6_SIZE;
            if n == 0 {
                continue;
            }
            let a = Ipv6Addr::from(AUTO6_BASE + n);
            if subnet.contains(a) {
                // Jump past the subnet, which lies inside the range.
                self.next_auto6 = ((subnet.net | !subnet.mask) - AUTO6_BASE + 1) % AUTO6_SIZE;
                continue;
            }
            if !self.machines.contains_key(&a.into()) {
                return Some(a);
            }
        }
        None
    }
}

/// Builds the network: the router, ICMP "host unreachable" as its default
/// route, the gateway with DNS, and a filter for each sandbox.
pub(super) fn serve(
    cx: &Cx,
    site_for: Arc<SiteFor>,
    subnet: Prefix,
    subnet6: Option<Prefix>,
    max_sites: usize,
    on_event: Option<Arc<OnEvent>>,
    mut attachments: Attachments,
) -> Result<(), Error> {
    let subnet = Subnet::new(subnet)?;
    let subnet6 = subnet6.map(Subnet6::new).transpose()?;
    // Everything below is one group for observers, except each sandbox's
    // filter, which stays in the caller's group with its sandbox: a
    // sandbox sits in the group of the task that reads it.
    let caller = cx.clone();
    let cx = &cx.group("web::Sites");
    let router = route::router(cx, Vec::new());

    // Everything without a better route: answered with "host unreachable".
    let (router_side, unreachable_side) = link();
    router.add(Prefix { addr: Ipv4Addr::UNSPECIFIED.into(), len: 0 }, Box::new(router_side));
    let gateway = subnet.gateway;
    cx.spawn(move |cx| unreachable(cx, unreachable_side, gateway.into()));
    if let Some(subnet6) = subnet6 {
        let (router_side, unreachable_side) = link();
        router.add(Prefix { addr: Ipv6Addr::UNSPECIFIED.into(), len: 0 }, Box::new(router_side));
        let gateway = subnet6.gateway;
        cx.spawn(move |cx| unreachable(cx, unreachable_side, gateway.into()));
    }
    let hooks = Arc::new(Hooks { on_event, by_addr: Mutex::default(), conns: AtomicU64::new(0), attached: Mutex::default() });

    let shared = Arc::new(Shared {
        cx: cx.clone(),
        site_for,
        subnet,
        subnet6,
        router,
        world: Mutex::new(World::new(max_sites)),
        leases: Mutex::new(Leases::default()),
        gateway_tcp: Mutex::new(Vec::new()),
        hooks,
    });
    start_gateway(&shared)?;

    caller.spawn(move |cx| async move {
        while let Some(sandbox) = attachments.next(&cx).await {
            let shared = shared.clone();
            cx.spawn(move |cx| filter(cx, sandbox, shared));
        }
        Ok(())
    });
    Ok(())
}

impl Shared {
    /// What `name` is. The first lookup of a name runs the world's callback
    /// and, for a site, starts its machines, unless the world already has
    /// [`World::max_sites`] sites. `name` is already lowercase with no
    /// trailing dot.
    pub(super) fn lookup(self: &Arc<Self>, name: &str) -> Lookup {
        let mut world = lock(&self.world);
        if let Some(addr) = world.names.get(name) {
            return addr.map_or(Lookup::NoSite, Lookup::Site);
        }
        let addr = match (self.site_for)(name) {
            // Checked before the site gets addresses or machines, and not
            // kept: asking again runs the callback again.
            Some(_) if world.sites >= world.max_sites => return Lookup::Full,
            Some(site) => self.place(&mut world, name, site),
            None => None,
        };
        world.remember(name, addr);
        addr.map_or(Lookup::NoSite, Lookup::Site)
    }

    /// Gives `site` its addresses and machines: one address for each family
    /// it has, from [`Site::at`](super::Site::at) or the family's pool.
    /// `None` if an address given with `at` cannot be served, or the site
    /// ends up with no address at all.
    fn place(self: &Arc<Self>, world: &mut World, name: &str, site: Site) -> Option<Placed> {
        let wants_v4 = site.family != Family::V6;
        let subnet6 = self.subnet6.filter(|_| site.family != Family::V4);
        let mut placed = Placed::default();
        if wants_v4 {
            placed.v4 = match site.at {
                Some(a) if may_serve_v4(a, &self.subnet) => Some(a),
                Some(_) => return None,
                None => world.free_auto(&self.subnet),
            };
        }
        if let Some(subnet6) = subnet6 {
            placed.v6 = match site.at_v6 {
                Some(a) if may_serve_v6(a, &subnet6) => Some(a),
                Some(_) => return None,
                None => world.free_auto6(&subnet6),
            };
        }
        if placed == Placed::default() {
            return None;
        }
        let default_host = site.default_host;
        let entry = Arc::new(SiteEntry { handler: site.handler, tls: site.tls, plain_http: site.plain_http });
        let addrs = placed.v4.map(IpAddr::V4).into_iter().chain(placed.v6.map(IpAddr::V6));
        for addr in addrs {
            let machine = match world.machines.get(&addr) {
                Some(m) => m.clone(),
                None => {
                    let m = Machine::start(self, addr, name);
                    world.machines.insert(addr, m.clone());
                    m
                }
            };
            machine.add(name, entry.clone(), default_host);
        }
        Some(placed)
    }
}

// ---------------------------------------------------------------------------
// Machines

/// How many connections one peer address may have open at one machine (or
/// at the gateway's DNS) at once, counted until each has finished
/// closing. More are reset as soon as they are accepted. Every open
/// connection costs the machine's TCP a little on every packet, so one
/// sandbox must not hold thousands of them on a machine the others share.
pub(super) const CONNECTIONS_PER_PEER: usize = 256;

/// Open connections by peer address, for [`CONNECTIONS_PER_PEER`].
#[derive(Default)]
pub(super) struct Peers(Mutex<HashMap<IpAddr, usize>>);

impl Peers {
    /// Counts one more connection from `peer`, or `None` if it already has
    /// as many as it may. The count goes down when the guard is dropped.
    pub(super) fn enter(self: &Arc<Self>, peer: IpAddr) -> Option<PeerGuard> {
        let mut map = lock(&self.0);
        let n = map.entry(peer).or_default();
        if *n >= CONNECTIONS_PER_PEER {
            return None;
        }
        *n += 1;
        Some(PeerGuard { peers: self.clone(), peer })
    }
}

/// One open connection, counted in [`Peers`].
pub(super) struct PeerGuard {
    peers: Arc<Peers>,
    peer: IpAddr,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut map = lock(&self.peers.0);
        if let Some(n) = map.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.peer);
            }
        }
    }
}

/// One address with its sites, its TCP, and its open ports.
pub(super) struct Machine {
    /// In the machine's own group, for observers.
    cx: Cx,
    tcp: tcp::Endpoint,
    sites: Mutex<HashMap<String, Arc<SiteEntry>>>,
    /// The site that answers hosts no site here is called by
    /// ([`Site::default_host`]).
    default: Mutex<Option<Arc<SiteEntry>>>,
    /// Port 443 is open.
    https: AtomicBool,
    /// Open connections, on both ports.
    pub(super) peers: Arc<Peers>,
    pub(super) hooks: Arc<Hooks>,
}

/// A site, as a machine keeps it.
pub(super) struct SiteEntry {
    pub(super) handler: Handler,
    pub(super) tls: Option<Arc<SiteTls>>,
    /// A TLS site's handler also answers on port 80, without a redirect.
    pub(super) plain_http: bool,
}

impl Machine {
    /// Starts a machine at `addr`: a route, TCP with port 80 open, UDP with
    /// no ports open (so UDP gets "port unreachable"), and ping replies.
    /// The machine's tasks are a group named after `name`, the first site
    /// placed at `addr`, and the address.
    fn start(shared: &Arc<Shared>, addr: IpAddr, name: &str) -> Arc<Machine> {
        let cx = &shared.cx.group(format!("{name} ({addr})"));
        let (router_side, side) = link();
        shared.router.add(host_prefix(addr), Box::new(router_side));
        let (tcp, udp, icmp, _other) = ip::split_protocols(cx, side);
        let tcp = tcp::endpoint(cx, tcp, addr);
        let _udp = udp::endpoint(cx, udp, addr);
        cx.spawn(move |cx| pings(cx, icmp, addr));
        let machine = Arc::new(Machine {
            cx: cx.clone(),
            tcp,
            sites: Mutex::new(HashMap::new()),
            default: Mutex::new(None),
            https: AtomicBool::new(false),
            peers: Arc::default(),
            hooks: shared.hooks.clone(),
        });
        if let Ok(listener) = machine.tcp.listen(80) {
            let m = machine.clone();
            cx.spawn(move |cx| http_serve::accept(cx, listener, m, false));
        }
        machine
    }

    /// Adds a site, and opens port 443 for the first site with TLS.
    fn add(self: &Arc<Self>, name: &str, entry: Arc<SiteEntry>, default_host: bool) {
        let tls = entry.tls.is_some();
        if default_host {
            lock(&self.default).get_or_insert_with(|| entry.clone());
        }
        lock(&self.sites).insert(name.to_owned(), entry);
        if tls && !self.https.swap(true, Ordering::SeqCst) && let Ok(listener) = self.tcp.listen(443) {
            let m = self.clone();
            self.cx.spawn(move |cx| http_serve::accept(cx, listener, m, true));
        }
    }

    /// The site called `name` at this machine.
    pub(super) fn site(&self, name: &str) -> Option<Arc<SiteEntry>> {
        lock(&self.sites).get(name).cloned()
    }

    /// The site for a request to `host` here: the site of that name, else
    /// the machine's default site, if it has one.
    pub(super) fn site_or_default(&self, host: &str) -> Option<Arc<SiteEntry>> {
        self.site(host).or_else(|| lock(&self.default).clone())
    }

    /// Whether TCP `port` is open here.
    fn serves(&self, port: u16) -> bool {
        port == 80 || (port == 443 && self.https.load(Ordering::SeqCst))
    }
}

/// The route to one address: `/32` or `/128`.
fn host_prefix(addr: IpAddr) -> Prefix {
    Prefix { addr, len: if addr.is_ipv4() { 32 } else { 128 } }
}

/// Answers pings to `addr`.
async fn pings(cx: Cx, mut icmp: End, addr: IpAddr) -> crate::Result {
    let mut run = 0;
    while let Ok(packet) = icmp.recv(&cx).await {
        if let Some(reply) = icmp::echo_reply(&packet, addr) {
            icmp.send(reply);
        }
        // Counts to 64 and starts again: a count that only grew would
        // overflow, and panic with overflow checks, after 2^31 packets.
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

/// The gateway, at its IPv4 address and, with IPv6, at its IPv6 address:
/// DNS over UDP and TCP on port 53, and ping replies. DHCP is answered in
/// each sandbox's filter, which knows which sandbox asked.
fn start_gateway(shared: &Arc<Shared>) -> Result<(), Error> {
    let gateways = std::iter::once(IpAddr::V4(shared.subnet.gateway)).chain(shared.subnet6.map(|s| IpAddr::V6(s.gateway)));
    let cx = &shared.cx.group("gateway");
    for gateway in gateways {
        let (router_side, side) = link();
        shared.router.add(host_prefix(gateway), Box::new(router_side));
        let (tcp, udp, icmp, _other) = ip::split_protocols(cx, side);
        let tcp = tcp::endpoint(cx, tcp, gateway);
        let udp = udp::endpoint(cx, udp, gateway);
        let socket = udp.bind(53)?;
        let listener = tcp.listen(53)?;
        lock(&shared.gateway_tcp).push(tcp);
        let s = shared.clone();
        cx.spawn(move |cx| names::serve_udp(cx, socket, s));
        let s = shared.clone();
        cx.spawn(move |cx| names::serve_tcp(cx, listener, s));
        cx.spawn(move |cx| pings(cx, icmp, gateway));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ICMP "host unreachable"

/// Answers every packet with ICMP "host unreachable", or ICMPv6 "address
/// unreachable", from the gateway's address of the same family.
async fn unreachable(cx: Cx, mut end: End, gateway: IpAddr) -> crate::Result {
    let mut run = 0;
    while let Ok(packet) = end.recv(&cx).await {
        let reply = match gateway {
            IpAddr::V4(g) => host_unreachable(&packet.0, g),
            IpAddr::V6(g) => address_unreachable(&packet.0, g),
        };
        if let Some(reply) = reply {
            end.send(reply);
        }
        // Counts to 64 and starts again: a count that only grew would
        // overflow, and panic with overflow checks, after 2^31 packets.
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

/// The ICMP "host unreachable" (type 3, code 1) answer to `p`, sent from
/// `from`. `None` where RFC 1122 forbids one: for ICMP errors, fragments
/// after the first, and packets from or to addresses that are not one host.
fn host_unreachable(p: &[u8], from: Ipv4Addr) -> Option<Packet> {
    let v4 = V4::parse(p, false)?;
    if v4.frag_offset() != 0 {
        return None;
    }
    let (src, dst) = (v4.src(), v4.dst());
    if src.is_unspecified() || src.is_broadcast() || src.is_multicast() || src.is_loopback() {
        return None;
    }
    if dst.is_broadcast() || dst.is_multicast() {
        return None;
    }
    if v4.proto() == wire::PROTO_ICMP {
        // Only queries (echo, timestamp, information, mask) get an answer.
        let kind = *v4.payload().first()?;
        if !matches!(kind, 0 | 8 | 13..=18) {
            return None;
        }
    }
    // The header and as much of the packet as fits in 576 bytes (RFC 1812).
    let quote = &p[..v4.total.min(576 - 28)];
    let mut icmp = vec![3, 1, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quote);
    let sum = wire::checksum(0, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(ip_packet(from.into(), src.into(), wire::PROTO_ICMP, 0, &icmp))
}

/// The ICMPv6 "destination unreachable, address unreachable" (type 1, code
/// 3) answer to `p`, sent from `from`. Linux reports it to the program as
/// "No route to host", as it does ICMP "host unreachable". `None` where
/// RFC 4443 forbids one: for ICMPv6 errors and redirects, fragments after
/// the first, and packets from or to addresses that are not one host. Also
/// `None` for neighbor discovery messages.
fn address_unreachable(p: &[u8], from: Ipv6Addr) -> Option<Packet> {
    let v6 = V6::parse(p, false)?;
    if let Some((at, _)) = v6.frag
        && u16::from_be_bytes([p[at + 2], p[at + 3]]) & 0xfff8 != 0
    {
        return None;
    }
    let (src, dst) = (v6.src(), v6.dst());
    if src.is_unspecified() || src.is_multicast() || src.is_loopback() || dst.is_multicast() {
        return None;
    }
    // Error messages (types below 128) and redirects (137) never get an
    // error. Neither do the other neighbor discovery messages (133 to 136),
    // which belong to one link and are never routed.
    if v6.proto == wire::PROTO_ICMPV6 && v6.payload().first().is_none_or(|t| *t < 128 || (133..=137).contains(t)) {
        return None;
    }
    // As much of the packet as fits in the minimum MTU, 1280 bytes.
    let quote = &p[..v6.end.min(1280 - 48)];
    let mut icmp = vec![1, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quote);
    let sum = transport_checksum(from.into(), src.into(), wire::PROTO_ICMPV6, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(ip_packet(from.into(), src.into(), wire::PROTO_ICMPV6, 0, &icmp))
}

// ---------------------------------------------------------------------------
// Address binding and DHCP

/// Which attachment holds which address.
#[derive(Default)]
struct Leases {
    /// Address to (owner, bound). An address that is not bound is held: it
    /// was offered by DHCP and not yet acknowledged.
    by_addr: HashMap<Ipv4Addr, (u64, bool)>,
    by_owner: HashMap<u64, Ipv4Addr>,
    /// IPv6 addresses, by address and by owner. These are always static,
    /// so they are bound from the start.
    by_addr6: HashMap<Ipv6Addr, u64>,
    by_owner6: HashMap<u64, Ipv6Addr>,
    next_owner: u64,
}

impl Leases {
    fn new_owner(&mut self) -> u64 {
        self.next_owner += 1;
        self.next_owner
    }

    /// The address `owner` holds or has bound.
    fn of(&self, owner: u64) -> Option<(Ipv4Addr, bool)> {
        let a = *self.by_owner.get(&owner)?;
        Some((a, self.by_addr[&a].1))
    }

    /// Whether `owner` may take `a`: no one else holds or has bound it.
    fn free_for(&self, owner: u64, a: Ipv4Addr) -> bool {
        self.by_addr.get(&a).is_none_or(|(o, _)| *o == owner)
    }

    fn set(&mut self, owner: u64, a: Ipv4Addr, bound: bool) {
        self.release(owner);
        self.by_addr.insert(a, (owner, bound));
        self.by_owner.insert(owner, a);
    }

    fn release(&mut self, owner: u64) {
        if let Some(a) = self.by_owner.remove(&owner) {
            self.by_addr.remove(&a);
        }
    }

    /// Frees both of `owner`'s addresses, for good.
    fn release_all(&mut self, owner: u64) {
        self.release(owner);
        if let Some(a) = self.by_owner6.remove(&owner) {
            self.by_addr6.remove(&a);
        }
    }
}

/// What came of trying to bind an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bind {
    /// Bound now. The caller adds the route.
    New,
    /// This attachment had already bound this address.
    Already,
    /// Another attachment holds it, it is not a sandbox address, or this
    /// attachment has bound another.
    Refused,
}

impl Shared {
    /// The address to offer `owner`: the one it has bound, else the one it
    /// asked for if that is free, else the one it holds, else the lowest
    /// free one, which it then holds.
    fn offer(&self, owner: u64, requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let mut leases = lock(&self.leases);
        let mine = leases.of(owner);
        if let Some((a, true)) = mine {
            return Some(a);
        }
        if let Some(r) = requested && self.subnet.is_sandbox(r) && leases.free_for(owner, r) {
            leases.set(owner, r, false);
            return Some(r);
        }
        if let Some((a, false)) = mine {
            return Some(a);
        }
        let a = self.subnet.sandboxes().find(|a| !leases.by_addr.contains_key(a))?;
        leases.set(owner, a, false);
        Some(a)
    }

    /// Whether `owner` could bind `a` now: it has bound nothing, and `a` is
    /// a sandbox address no one else holds.
    fn may_bind(&self, owner: u64, a: Ipv4Addr) -> bool {
        let leases = lock(&self.leases);
        !matches!(leases.of(owner), Some((_, true))) && self.subnet.is_sandbox(a) && leases.free_for(owner, a)
    }

    /// Binds `a` to `owner`, if it may have it.
    fn bind(&self, owner: u64, a: Ipv4Addr) -> Bind {
        let mut leases = lock(&self.leases);
        if let Some((b, true)) = leases.of(owner) {
            return if a == b { Bind::Already } else { Bind::Refused };
        }
        if self.subnet.is_sandbox(a) && leases.free_for(owner, a) {
            leases.set(owner, a, true);
            Bind::New
        } else {
            Bind::Refused
        }
    }

    /// Binds the IPv6 address `a` to `owner`, if it may have it: it has
    /// bound no other, and `a` is a sandbox address no one else has.
    fn bind6(&self, owner: u64, a: Ipv6Addr) -> Bind {
        let Some(subnet) = &self.subnet6 else { return Bind::Refused };
        let mut leases = lock(&self.leases);
        if let Some(b) = leases.by_owner6.get(&owner) {
            return if a == *b { Bind::Already } else { Bind::Refused };
        }
        if subnet.is_sandbox(a) && !leases.by_addr6.contains_key(&a) {
            leases.by_addr6.insert(a, owner);
            leases.by_owner6.insert(owner, a);
            Bind::New
        } else {
            Bind::Refused
        }
    }

    /// Answers one DHCP message from `owner`, sent from `src`. Returns the
    /// reply, and the address if this bound one.
    fn dhcp(&self, owner: u64, src: Ipv4Addr, m: &dhcp::Message) -> (Option<Packet>, Option<Ipv4Addr>) {
        if m.op != dhcp::BOOTREQUEST {
            return (None, None);
        }
        match m.message_type() {
            Some(dhcp::DISCOVER) => match self.offer(owner, m.option_addr(opt::REQUESTED_IP)) {
                Some(a) => (Some(self.dhcp_reply(m, dhcp::OFFER, a)), None),
                None => (None, None),
            },
            Some(dhcp::REQUEST) => {
                // A client that chose another server's offer.
                if m.option_addr(opt::SERVER_ID).is_some_and(|s| s != self.subnet.gateway) {
                    return (None, None);
                }
                let wanted = m.option_addr(opt::REQUESTED_IP).or((!m.ciaddr.is_unspecified()).then_some(m.ciaddr));
                let Some(wanted) = wanted else { return (None, None) };
                match self.bind(owner, wanted) {
                    Bind::New => (Some(self.dhcp_reply(m, dhcp::ACK, wanted)), Some(wanted)),
                    Bind::Already => (Some(self.dhcp_reply(m, dhcp::ACK, wanted)), None),
                    Bind::Refused => (Some(self.dhcp_reply(m, dhcp::NAK, Ipv4Addr::UNSPECIFIED)), None),
                }
            }
            // A client with a static address asking for the other settings.
            Some(dhcp::INFORM) if !m.ciaddr.is_unspecified() && m.ciaddr == src => {
                (Some(self.dhcp_reply(m, dhcp::INFORM, Ipv4Addr::UNSPECIFIED)), None)
            }
            // RELEASE and DECLINE change nothing: the address stays bound to
            // the attachment until it detaches.
            _ => (None, None),
        }
    }

    /// A reply to `request`. `kind` INFORM means the ACK to an INFORM,
    /// which carries no lease.
    fn dhcp_reply(&self, request: &dhcp::Message, kind: u8, yiaddr: Ipv4Addr) -> Packet {
        let gateway = self.subnet.gateway;
        let mut m = dhcp::Message::new(dhcp::BOOTREPLY, request.xid);
        m.htype = request.htype;
        m.hlen = request.hlen;
        m.flags = request.flags;
        m.giaddr = request.giaddr;
        m.chaddr = request.chaddr;
        m.yiaddr = yiaddr;
        if kind == dhcp::INFORM {
            m.ciaddr = request.ciaddr;
        }
        m.push(opt::MESSAGE_TYPE, [if kind == dhcp::INFORM { dhcp::ACK } else { kind }]);
        m.push(opt::SERVER_ID, gateway.octets());
        if kind != dhcp::NAK {
            if kind != dhcp::INFORM {
                m.push(opt::LEASE_TIME, LEASE.to_be_bytes());
                m.push(opt::RENEWAL_TIME, (LEASE / 2).to_be_bytes());
                m.push(opt::REBINDING_TIME, (LEASE / 8 * 7).to_be_bytes());
            }
            m.push(opt::SUBNET_MASK, self.subnet.mask().octets());
            m.push(opt::ROUTER, gateway.octets());
            m.push(opt::DNS, gateway.octets());
        }
        // A client that has an address hears back there. Every other reply
        // is broadcast, since the client has no address yet.
        let to = if kind != dhcp::NAK && !request.ciaddr.is_unspecified() { request.ciaddr } else { Ipv4Addr::BROADCAST };
        udp_packet(gateway, dhcp::SERVER_PORT, to, dhcp::CLIENT_PORT, &m.to_bytes())
    }
}

/// A UDP packet with correct checksums.
fn udp_packet(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::with_capacity(8 + data.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let mut sum = transport_checksum(src.into(), dst.into(), UDP, &u);
    if sum == 0 {
        sum = 0xffff;
    }
    u[6..8].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src.into(), dst.into(), UDP, 0, &u)
}

/// If `v4` is a packet to the DHCP server (UDP port 67 at the broadcast
/// address or the gateway), its message, or `Some(None)` if it does not
/// parse. `None` for every other packet.
fn to_dhcp_server(v4: &V4<'_>, gateway: Ipv4Addr) -> Option<Option<dhcp::Message>> {
    if v4.proto() != UDP || v4.is_fragment() {
        return None;
    }
    let dst = v4.dst();
    if dst != Ipv4Addr::BROADCAST && dst != gateway {
        return None;
    }
    let u = v4.payload();
    if u.len() < 8 || u16::from_be_bytes([u[2], u[3]]) != dhcp::SERVER_PORT {
        return None;
    }
    let len = (u16::from_be_bytes([u[4], u[5]]) as usize).clamp(8, u.len());
    Some(dhcp::Message::parse(&u[8..len]))
}

/// Frees an attachment's address when its filter ends.
struct Release {
    shared: Arc<Shared>,
    owner: u64,
    cx: Cx,
    name: Arc<str>,
}

impl Drop for Release {
    fn drop(&mut self) {
        let shared = &self.shared;
        // Events for connections reset below say Sites ended them.
        if shared.hooks.on() {
            lock(&shared.hooks.attached).remove(&self.owner);
        }
        // First end every connection the sandbox had, so nothing meant for
        // it reaches the next sandbox to take its address.
        let (bound, bound6) = {
            let leases = lock(&shared.leases);
            let v4 = leases.of(self.owner).and_then(|(a, bound)| bound.then_some(a));
            (v4, leases.by_owner6.get(&self.owner).copied())
        };
        let addrs: Vec<IpAddr> = bound.map(IpAddr::V4).into_iter().chain(bound6.map(IpAddr::V6)).collect();
        if !addrs.is_empty() {
            let machines: Vec<Arc<Machine>> = lock(&shared.world).machines.values().cloned().collect();
            for m in machines {
                for a in &addrs {
                    m.tcp.abort_peer(*a);
                }
            }
            for tcp in lock(&shared.gateway_tcp).iter() {
                for a in &addrs {
                    tcp.abort_peer(*a);
                }
            }
        }
        lock(&shared.leases).release_all(self.owner);
        if shared.hooks.on() {
            let sandbox = Sandbox { id: self.owner, name: self.name.clone(), addr: bound, addr_v6: bound6 };
            shared.hooks.emit(&self.cx, Event::Detached { sandbox });
        }
    }
}

/// One sandbox's filter, between its attachment and the router.
///
/// From the sandbox: DHCP is answered here. Other packets bind the
/// sandbox's address of their family on the first one, must come from that
/// address after, and must not go to the sandboxes' subnets other than the
/// gateway. Everything else is dropped. Toward the sandbox: everything the
/// router sends for its addresses.
async fn filter(cx: Cx, sandbox: Attachment, shared: Arc<Shared>) -> crate::Result {
    let name: Arc<str> = Arc::from(sandbox.name());
    // The owner of a lease is also the sandbox's id in events.
    let owner = lock(&shared.leases).new_owner();
    let mut f = Filter {
        on: shared.hooks.on(),
        shared: shared.clone(),
        owner,
        name: name.clone(),
        // Port 0 is the sandbox. Each address, once bound, gets its route
        // as a port of its own.
        ports: Ports::new(vec![Box::new(sandbox) as Box<dyn Interface>]),
        bound: None,
        bound6: None,
        route4: None,
        route6: None,
        reassembly: Reassembly::default(),
    };
    if f.on {
        lock(&shared.hooks.attached).insert(owner);
        shared.hooks.emit(&cx, Event::Attached { sandbox: f.me() });
    }
    let _release = Release { shared, owner, cx: cx.clone(), name };
    loop {
        let deadline = f.reassembly.next_expiry();
        match f.ports.next(&cx, deadline, |_| Poll::Pending).await {
            PortEvent::Packet(0, packet) => match wire::version(&packet.0) {
                Some(6) => f.sent_v6(&cx, packet),
                _ => f.sent_v4(&cx, packet),
            },
            PortEvent::Packet(_, packet) => f.ports.send(0, packet),
            // The sandbox detached, or the router stopped.
            PortEvent::Closed(_) | PortEvent::Cancelled => return Ok(()),
            PortEvent::Timer => f.reassembly.expire(cx.now()),
            PortEvent::Extra => {}
        }
    }
}

/// The state of one sandbox's filter.
struct Filter {
    shared: Arc<Shared>,
    /// Whether the world wants events.
    on: bool,
    owner: u64,
    name: Arc<str>,
    ports: Ports,
    bound: Option<Ipv4Addr>,
    bound6: Option<Ipv6Addr>,
    /// The ports of the routes to `bound` and `bound6`.
    route4: Option<usize>,
    route6: Option<usize>,
    /// The sandbox's fragments, put back together here, after the checks
    /// on each fragment's source and destination. The state lives and dies
    /// with this filter, so a fragment from one sandbox can never complete
    /// a packet with another's, even one that later takes the same address.
    reassembly: Reassembly,
}

impl Filter {
    /// The sandbox, as events name it now.
    fn me(&self) -> Sandbox {
        Sandbox { id: self.owner, name: self.name.clone(), addr: self.bound, addr_v6: self.bound6 }
    }

    /// Tells the world about a packet this filter drops, or that the
    /// network will refuse.
    fn block(&self, cx: &Cx, why: BlockedWhy, packet: &[u8]) {
        if self.on {
            self.shared.hooks.emit(cx, Event::Blocked(blocked(self.me(), why, packet)));
        }
    }

    /// Notes a newly bound address: its route, and its event.
    fn bound_now(&mut self, cx: &Cx, addr: IpAddr, by_dhcp: bool) {
        let port = add_route(&self.shared, &mut self.ports, addr);
        match addr {
            IpAddr::V4(a) => (self.bound, self.route4) = (Some(a), Some(port)),
            IpAddr::V6(a) => (self.bound6, self.route6) = (Some(a), Some(port)),
        }
        if self.on {
            let sandbox = self.me();
            let mut by_addr = lock(&self.shared.hooks.by_addr);
            for a in self.bound.map(IpAddr::V4).into_iter().chain(self.bound6.map(IpAddr::V6)) {
                by_addr.insert(a, sandbox.clone());
            }
            drop(by_addr);
            self.shared.hooks.emit(cx, Event::Bound { sandbox, by_dhcp });
        }
    }

    fn sent_v4(&mut self, cx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let gateway = shared.subnet.gateway;
        let Some(v4) = V4::parse(&packet.0, false) else {
            self.block(cx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (src, dst) = (v4.src(), v4.dst());
        if let Some(message) = to_dhcp_server(&v4, gateway) {
            // DHCP that cannot be read is dropped unreported.
            let Some(message) = message else { return };
            // A static client may send INFORM before anything else, from
            // the address it is about to use. That is answered (to that
            // address, on this attachment) but binds nothing.
            let inform_first = self.bound.is_none()
                && message.message_type() == Some(dhcp::INFORM)
                && shared.may_bind(self.owner, src);
            if !(src.is_unspecified() || Some(src) == self.bound || inform_first) {
                self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            let (reply, new) = shared.dhcp(self.owner, src, &message);
            if let Some(a) = new {
                self.bound_now(cx, a.into(), true);
            }
            if let Some(reply) = reply {
                self.ports.send(0, reply);
            }
            return;
        }
        match self.bound {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind(self.owner, src) != Bind::New {
                    self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(cx, src.into(), false);
            }
        }
        if dst.is_broadcast() || dst.is_multicast() || dst.is_unspecified() {
            self.block(cx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        if shared.subnet.contains(dst) && dst != gateway {
            self.block(cx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(cx, self.route4, packet);
    }

    /// An IPv6 packet from the sandbox. IPv6 addresses are always static:
    /// there is no DHCPv6, and no router advertisements.
    fn sent_v6(&mut self, cx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let Some(subnet) = shared.subnet6 else {
            self.block(cx, BlockedWhy::Ipv6, &packet.0);
            return;
        };
        let Some(v6) = V6::parse(&packet.0, false) else {
            self.block(cx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (src, dst) = (v6.src(), v6.dst());
        // Multicast first: a Linux sandbox sends router solicitations and
        // listener reports from its link-local address before anything
        // else, and they must not stand in the way of binding.
        if dst.is_multicast() || dst.is_unspecified() {
            self.block(cx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        match self.bound6 {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind6(self.owner, src) != Bind::New {
                    self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(cx, src.into(), false);
            }
        }
        if subnet.contains(dst) && dst != subnet.gateway {
            self.block(cx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(cx, self.route6, packet);
    }

    /// Sends a packet that passed the checks on to the router, on the
    /// route of its family. A fragment waits until its packet is whole.
    ///
    /// A packet whose IPv6 extension headers are refused is answered as its
    /// destination would answer it. Only the gateway and the machines are
    /// there to answer, so for any other address the packet goes on to the
    /// router, which answers "address unreachable" as for any packet to
    /// that address.
    fn forward(&mut self, cx: &Cx, route: Option<usize>, packet: Packet) {
        let packet = match self.reassembly.intake(packet, cx.now()) {
            Intake::Whole(p) => p,
            Intake::Waiting => return,
            Intake::Refused { packet, answer } => {
                if !self.shared.is_host(&packet.0) {
                    packet
                } else {
                    if let Some(answer) = answer {
                        self.ports.send(0, answer);
                    }
                    return;
                }
            }
        };
        if self.on && let Some(why) = self.shared.refused(&packet.0) {
            self.block(cx, why, &packet.0);
        }
        if let Some(port) = route {
            self.ports.send(port, packet);
        }
    }
}

impl Shared {
    /// Whether `p` is for the gateway or a machine: an address that a host
    /// here has.
    fn is_host(&self, p: &[u8]) -> bool {
        let Some(dst) = wire::destination(p) else { return false };
        let gateway = match dst {
            IpAddr::V4(a) => a == self.subnet.gateway,
            IpAddr::V6(a) => self.subnet6.is_some_and(|s| a == s.gateway),
        };
        gateway || lock(&self.world).machines.contains_key(&dst)
    }

    /// Why the network will refuse `p`, an IPv4 or IPv6 packet from a
    /// sandbox that passed its filter: no machine has its address, or its
    /// port is not served there. `None` if it will be delivered.
    fn refused(&self, p: &[u8]) -> Option<BlockedWhy> {
        let dst = wire::destination(p)?;
        // Only whole packets with a good checksum get to a port at all: the
        // layers below drop the rest unreported. A RST to a closed port is
        // dropped without an answer, and is not refused either.
        let port = transport(p);
        let closed = |open: &dyn Fn(u16) -> bool| match port {
            Some((wire::PROTO_TCP, port, rst)) => !open(port) && !rst,
            Some((_, port, _)) => !open(port),
            None => false,
        };
        let gateway = match dst {
            IpAddr::V4(a) => a == self.subnet.gateway,
            IpAddr::V6(a) => self.subnet6.is_some_and(|s| a == s.gateway),
        };
        if gateway {
            return closed(&|p| p == 53).then_some(BlockedWhy::ClosedPort);
        }
        let machine = lock(&self.world).machines.get(&dst).cloned();
        match machine {
            None => Some(BlockedWhy::NoRoute),
            Some(m) => {
                let tcp = matches!(port, Some((wire::PROTO_TCP, _, _)));
                closed(&|p| tcp && m.serves(p)).then_some(BlockedWhy::ClosedPort)
            }
        }
    }
}

/// The protocol, destination port, and whether it is a TCP RST, of a whole
/// (not fragmented) TCP or UDP packet with a good checksum. `None` for
/// everything else.
fn transport(p: &[u8]) -> Option<(u8, u16, bool)> {
    let ip = parse_ip(p)?;
    if !matches!(ip.proto, wire::PROTO_TCP | UDP) {
        return None;
    }
    let t = &p[ip.payload..ip.end];
    if t.len() < 8 {
        return None;
    }
    let good = match ip.proto {
        UDP => udp_checksum_ok(ip.src, ip.dst, t),
        _ => transport_checksum(ip.src, ip.dst, ip.proto, t) == 0,
    };
    if !good {
        return None;
    }
    let rst = ip.proto == wire::PROTO_TCP && t.get(13).is_some_and(|flags| flags & 0x04 != 0);
    Some((ip.proto, u16::from_be_bytes([t[2], t[3]]), rst))
}

/// The TCP or UDP destination port of `v4`, if it has one: the packet is
/// TCP or UDP, and not a fragment past the first.
fn transport_port(v4: &V4<'_>) -> Option<u16> {
    if v4.frag_offset() != 0 || !matches!(v4.proto(), wire::PROTO_TCP | UDP) {
        return None;
    }
    let t = v4.payload();
    (t.len() >= 4).then(|| u16::from_be_bytes([t[2], t[3]]))
}

/// As [`transport_port`], for IPv6.
fn transport_port6(v6: &V6<'_>) -> Option<u16> {
    if let Some((at, _)) = v6.frag
        && u16::from_be_bytes([v6.bytes[at + 2], v6.bytes[at + 3]]) & 0xfff8 != 0
    {
        return None;
    }
    if !matches!(v6.proto, wire::PROTO_TCP | UDP) {
        return None;
    }
    let t = v6.payload();
    (t.len() >= 4).then(|| u16::from_be_bytes([t[2], t[3]]))
}

/// The event for a blocked packet.
fn blocked(sandbox: Sandbox, why: BlockedWhy, p: &[u8]) -> Blocked {
    if let Some(v4) = V4::parse(p, true) {
        return Blocked {
            sandbox,
            why,
            protocol: Some(v4.proto()),
            src: Some(v4.src().into()),
            dst: Some(v4.dst().into()),
            dst_port: transport_port(&v4),
        };
    }
    if let Some(v6) = V6::parse(p, true) {
        return Blocked {
            sandbox,
            why,
            protocol: Some(v6.proto),
            src: Some(v6.src().into()),
            dst: Some(v6.dst().into()),
            dst_port: transport_port6(&v6),
        };
    }
    Blocked { sandbox, why, protocol: None, src: None, dst: None, dst_port: None }
}

/// Gives a newly bound address its route, as a new port of the filter.
/// Returns the port.
fn add_route(shared: &Shared, ports: &mut Ports, addr: IpAddr) -> usize {
    let (router_side, mine) = link();
    shared.router.add(host_prefix(addr), Box::new(router_side));
    ports.add(Box::new(mine))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Once no automatic address is left, a new name does not scan them
    /// all again. With a wildcard site, each new name the agent asked for
    /// used to cost a scan of 131,072 addresses.
    #[test]
    fn a_full_automatic_range_is_not_scanned_again() {
        let mut w = World::new(MAX_SITES);
        // A subnet that holds all of 198.18.0.0/15.
        let subnet = Subnet::new(Prefix { addr: Ipv4Addr::new(198, 0, 0, 0).into(), len: 8 }).unwrap();
        assert_eq!(w.free_auto(&subnet), None);
        assert!(w.auto_full, "the range is known to be full");
        // The next search returns at once: 10,000 of them take far less
        // than the 10,000 scans of 131,072 addresses they replace.
        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            assert_eq!(w.free_auto(&subnet), None);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "{:?}", started.elapsed());
    }

    #[test]
    fn names_turned_down_are_remembered_up_to_a_limit() {
        let mut w = World::new(MAX_SITES);
        assert_eq!(w.max_unknown, 100_000);
        w.max_unknown = 3;
        for i in 0..10 {
            w.remember(&format!("n{i}.test"), None);
        }
        assert_eq!((w.names.len(), w.unknown), (3, 3));
        // Sites are always kept.
        for i in 0..10 {
            w.remember(&format!("s{i}.test"), Some(Placed { v4: Some(Ipv4Addr::new(198, 18, 0, i + 1)), v6: None }));
        }
        assert_eq!((w.names.len(), w.sites), (13, 10));
        assert_eq!(w.names.get("n9.test"), None);
        assert_eq!(w.names.get("n0.test"), Some(&None));
        // A name longer than a host name can be is not kept. Escaped bytes
        // can make such names about 1,000 bytes.
        let mut w = World::new(MAX_SITES);
        let long = "\\255".repeat(64);
        w.remember(&long, None);
        assert!(w.names.is_empty());
    }

    fn subnet6(s: &str) -> Result<Subnet6, Error> {
        Subnet6::new(s.parse().unwrap())
    }

    #[test]
    fn ipv6_subnets_must_be_global_or_unique_local() {
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(s.gateway, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert!(s.is_sandbox("2001:db8::2".parse().unwrap()));
        assert!(s.is_sandbox("2001:db8::ffff:ffff:ffff:ffff".parse().unwrap()));
        for not in ["2001:db8::", "2001:db8::1", "2001:db8:0:1::2"] {
            assert!(!s.is_sandbox(not.parse().unwrap()), "{not}");
        }
        assert_eq!(subnet6("fd00:1:2:3::/64").unwrap().gateway, "fd00:1:2:3::1".parse::<Ipv6Addr>().unwrap());
        for bad in ["fe80::/64", "ff02::/16", "::/8", "::ffff:0:0/96", "2001:db8::/127", "2000::/4", "10.0.0.0/24"] {
            assert!(subnet6(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn automatic_ipv6_addresses_count_up_and_skip_the_subnet() {
        let mut w = World::new(MAX_SITES);
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(w.free_auto6(&s), Some("2001:2::1".parse().unwrap()));
        assert_eq!(w.free_auto6(&s), Some("2001:2::2".parse().unwrap()));
        // Inside the range: skipped whole.
        let mut w = World::new(MAX_SITES);
        let inside = subnet6("2001:2::/120").unwrap();
        assert_eq!(w.free_auto6(&inside), Some("2001:2::100".parse().unwrap()));
        // Over the whole range: nothing.
        assert_eq!(World::new(MAX_SITES).free_auto6(&subnet6("2001::/16").unwrap()), None);
        assert_eq!(World::new(MAX_SITES).free_auto6(&subnet6("2001:2::/48").unwrap()), None);
    }

    #[test]
    fn sites_cannot_have_addresses_a_host_cannot_have() {
        let s = subnet6("2001:db8::/64").unwrap();
        assert!(may_serve_v6("2a02:ec80:300:ed1a::1".parse().unwrap(), &s));
        assert!(may_serve_v6("2001:db8:1::1".parse().unwrap(), &s));
        for bad in ["::", "::1", "ff02::1", "fe80::1", "::ffff:1.2.3.4", "2001:db8::5"] {
            assert!(!may_serve_v6(bad.parse().unwrap(), &s), "{bad}");
        }
    }

    /// An IPv6 packet with an ICMPv6 message of type `kind`, or UDP when
    /// `kind` is `None`.
    fn v6_packet(src: &str, dst: &str, kind: Option<u8>, len: usize) -> Vec<u8> {
        let (next, mut payload) = match kind {
            Some(k) => (wire::PROTO_ICMPV6, vec![k, 0, 0, 0]),
            None => (UDP, vec![0, 1, 0, 2, 0, 0, 0, 0]),
        };
        payload.resize(len, 0);
        let (src, dst): (Ipv6Addr, Ipv6Addr) = (src.parse().unwrap(), dst.parse().unwrap());
        ip_packet(src.into(), dst.into(), next, 0, &payload).0
    }

    #[test]
    fn address_unreachable_follows_rfc_4443() {
        let gw: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let p = v6_packet("2001:db8::2", "2001:db8:99::1", Some(128), 16);
        let reply = address_unreachable(&p, gw).expect("an echo request gets an error");
        let v6 = V6::parse(&reply.0, false).unwrap();
        assert_eq!((v6.src(), v6.dst().to_string().as_str(), v6.proto), (gw, "2001:db8::2", wire::PROTO_ICMPV6));
        let icmp = v6.payload();
        assert_eq!((icmp[0], icmp[1]), (1, 3));
        assert_eq!(&icmp[8..], &p[..]);
        assert_eq!(transport_checksum(v6.src().into(), v6.dst().into(), wire::PROTO_ICMPV6, icmp), 0);
        // A big packet is quoted up to the minimum MTU.
        let big = v6_packet("2001:db8::2", "2001:db8:99::1", None, 4000);
        assert_eq!(address_unreachable(&big, gw).unwrap().0.len(), 1280);
        // No error for an error, or from or to an address that is not one host.
        assert!(address_unreachable(&v6_packet("2001:db8::2", "2001:db8:99::1", Some(1), 16), gw).is_none());
        for nd in 133..=137 {
            assert!(address_unreachable(&v6_packet("2001:db8::2", "2001:db8:99::1", Some(nd), 16), gw).is_none(), "{nd}");
        }
        assert!(address_unreachable(&v6_packet("::", "2001:db8:99::1", None, 16), gw).is_none());
        assert!(address_unreachable(&v6_packet("2001:db8::2", "ff02::1", None, 16), gw).is_none());
    }
}
