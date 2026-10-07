//! Forwarding packets between interfaces by destination address.
//!
//! Use a [`router`] when a world has more than one machine, or more than
//! one sandbox. You give it a list of routes, each an address [`Prefix`]
//! and the [`Interface`] that leads there. It forwards every packet that
//! arrives on any of those interfaces out of the one whose prefix best
//! matches the packet's destination. The [`router`] docs show a sandbox and
//! two machines wired together.
//!
//! Use a [`lan`] when real or simulated machines share one IP subnet. It
//! forwards unicast by exact address and floods IP broadcast and multicast
//! packets to the other members, including the NBNS and LLMNR traffic common
//! on Windows networks.
//!
//! To build a whole network of websites, routes and all, use
//! [`web::Sites`](crate::stdlib::web::Sites) instead.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};

use crate::events::{self, Level};
use crate::stdlib::{Event, Ports, wire};
use crate::{Cx, Error, Interface, Packet};

/// An address prefix, such as `104.18.32.7/32` or `::/0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    /// The network address.
    pub addr: IpAddr,
    /// How many leading bits must match.
    pub len: u8,
}

impl FromStr for Prefix {
    type Err = Error;

    /// Parses `"10.0.0.0/8"` or `"::/0"`.
    ///
    /// The length may be left out for a single address: `"1.1.1.1"` is
    /// `1.1.1.1/32`. Bits of the address past the length are cleared, so
    /// `"10.1.2.3/8"` is `10.0.0.0/8`. A length longer than the address
    /// (33 or more for IPv4, 129 or more for IPv6) is an error.
    fn from_str(s: &str) -> Result<Prefix, Error> {
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| format!("{s:?} is not an address prefix"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(l) => match l.parse::<u8>() {
                Ok(n) if n <= max && !l.starts_with('+') => n,
                _ => return Err(format!("{s:?}: the length must be 0 to {max}").into()),
            },
        };
        Ok(Prefix { addr: mask(addr, len), len })
    }
}

impl Prefix {
    /// The same prefix with the bits past its length cleared. A length
    /// longer than the address, in a `Prefix` built by hand, counts as the
    /// whole address.
    pub fn canonical(self) -> Prefix {
        let len = self.len.min(if self.addr.is_ipv4() { 32 } else { 128 });
        Prefix { addr: mask(self.addr, len), len }
    }

    /// Whether `addr` is in this prefix. An address of the other family
    /// never is.
    pub fn contains(self, addr: IpAddr) -> bool {
        self.addr.is_ipv4() == addr.is_ipv4() && mask(addr, self.len) == self.canonical().addr
    }
}

/// Locks `m`. A poisoned lock is used anyway: it holds lists and flags
/// that a panic elsewhere leaves whole.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `addr` with every bit after the first `len` cleared.
fn mask(addr: IpAddr, len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32) as u32) };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len.min(128) as u32) };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

/// Forwards packets between `routes`, by destination address.
///
/// Starts a background task and returns immediately with a [`Router`]
/// handle, which can add more routes while the router runs.
///
/// A packet that arrives on any interface goes out on the interface whose
/// prefix best matches its destination address (the longest prefix wins).
/// A packet with no matching prefix is dropped.
///
/// When one route's interface closes, the router drops that route and keeps
/// running. Packets for its prefix then match the next-best route, or are
/// dropped. This is what a real router does when a link goes down. The
/// router's task stops when the caller's [region](crate::Cx#regions) is
/// cancelled, or when the interfaces of all its routes have closed and
/// every [`Router`] handle has been dropped.
///
/// Each route needs an interface whose other end is held by whatever lies
/// in that direction. Make the two ends with [`pair`](crate::pair), give
/// one to the router, and build a machine on the other. Here the sandbox
/// gets the default route, and two machines each get one address:
///
/// ```
/// # use fictionet::{Cx, End, Interface, Result, pair};
/// # use fictionet::stdlib::{ip, route, tcp};
/// # fn wire(cx: Cx, toward_sandbox: End) -> Result {
/// let (router_side, stripe_side) = pair();
/// let (router_side_dns, dns_side) = pair();
/// route::router(&cx, vec![
///     ("0.0.0.0/0".parse()?, Box::new(toward_sandbox) as Box<dyn Interface>),
///     ("104.18.32.7/32".parse()?, Box::new(router_side)),
///     ("1.1.1.1/32".parse()?, Box::new(router_side_dns)),
/// ]);
/// let (tcp, _udp, _icmp, _other) = ip::split_protocols(&cx, stripe_side);
/// let stripe = tcp::endpoint(&cx, tcp, "104.18.32.7".parse()?);
/// # drop((dns_side, stripe));
/// # Ok(())
/// # }
/// ```
///
/// Interfaces of different types share the list as `Box<dyn Interface>`.
///
/// A route's prefix is compared with its address bits past the length
/// cleared. A packet that is neither IPv4 nor IPv6, or too short to hold a
/// destination address, is dropped. The router does not change packets: it
/// does not lower the TTL or hop limit. A packet whose best route is the
/// interface it came in on goes back out on that interface, as on a real
/// router.
#[track_caller]
pub fn router(cx: &Cx, routes: Vec<(Prefix, Box<dyn Interface>)>) -> Router {
    let shared = Arc::new(Mutex::new(Shared { adds: routes, waker: None, handles_gone: false, stopped: false }));
    let router = Router { handle: Arc::new(Handle { shared: shared.clone() }) };
    cx.spawn_as(|| "router".into(), move |cx| async move {
        // However the task ends, later routes are dropped immediately.
        let _stopped = Stopped(shared.clone());
        let mut ports = Ports::new(Vec::new());
        // Which port each prefix goes out on.
        let mut table = Table::default();
        let mut handles_gone = false;
        loop {
            // Take routes added since the last turn.
            let (adds, gone) = {
                let mut s = lock(&shared);
                (std::mem::take(&mut s.adds), s.handles_gone)
            };
            handles_gone = handles_gone || gone;
            for (prefix, interface) in adds {
                let prefix = prefix.canonical();
                if let Some(link) = interface.observe_link() {
                    cx.graph().label(&link.0, format!("{}/{}", prefix.addr, prefix.len));
                }
                match table.routes.get(&prefix) {
                    Some(&i) => ports.replace(i, interface),
                    None => {
                        let i = ports.add(interface);
                        table.insert(prefix, i);
                    }
                }
            }
            if table.is_empty() && handles_gone {
                return Ok(());
            }
            let event = ports
                .next(&cx, None, |task| {
                    let mut s = lock(&shared);
                    if !s.adds.is_empty() || (s.handles_gone && !handles_gone) {
                        return Poll::Ready(());
                    }
                    match &s.waker {
                        Some(w) if w.will_wake(task.waker()) => {}
                        _ => s.waker = Some(task.waker().clone()),
                    }
                    Poll::Pending
                })
                .await;
            match event {
                Event::Packet(_, packet) => {
                    let Some(dst) = wire::destination(&packet.0) else { continue };
                    if let Some(i) = table.best(dst) {
                        ports.send(i, packet);
                    }
                }
                Event::Closed(i) => {
                    if let Some(prefix) = table.by_port.get(&i) {
                        let prefix = format!("{}/{}", prefix.addr, prefix.len);
                        let event = events::Event::new("router", "route_removed").level(Level::Notice).summary(format!("{prefix}: its interface closed")).field("prefix", prefix);
                        cx.record(event);
                    }
                    table.remove_port(i)
                }
                Event::Extra | Event::Timer => {}
                Event::Cancelled => return Ok(()),
            }
        }
    });
    router
}

/// A router's routes. Finding the best route costs one hash lookup per
/// prefix length in use, however many routes there are.
#[derive(Default)]
struct Table {
    /// Prefix to port.
    routes: HashMap<Prefix, usize>,
    /// Port to prefix.
    by_port: HashMap<usize, Prefix>,
    /// How many routes have each (IPv4?, length), longest last.
    lengths: BTreeMap<(bool, u8), usize>,
}

impl Table {
    fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Adds a route for a prefix that has none.
    fn insert(&mut self, prefix: Prefix, port: usize) {
        self.routes.insert(prefix, port);
        self.by_port.insert(port, prefix);
        *self.lengths.entry((prefix.addr.is_ipv4(), prefix.len)).or_default() += 1;
    }

    /// Drops the route that goes out on `port`.
    fn remove_port(&mut self, port: usize) {
        let Some(prefix) = self.by_port.remove(&port) else { return };
        self.routes.remove(&prefix);
        let key = (prefix.addr.is_ipv4(), prefix.len);
        if let Some(n) = self.lengths.get_mut(&key) {
            *n -= 1;
            if *n == 0 {
                self.lengths.remove(&key);
            }
        }
    }

    /// The port of the longest prefix that holds `dst`.
    fn best(&self, dst: IpAddr) -> Option<usize> {
        let v4 = dst.is_ipv4();
        self.lengths
            .range((v4, 0)..=(v4, u8::MAX))
            .rev()
            .find_map(|(&(_, len), _)| self.routes.get(&Prefix { addr: mask(dst, len), len }).copied())
    }
}

/// What a [`Router`] handle and its task share.
struct Shared {
    /// Routes added and not yet taken by the task.
    adds: Vec<(Prefix, Box<dyn Interface>)>,
    /// The task, waiting for routes.
    waker: Option<Waker>,
    /// Every handle has been dropped.
    handles_gone: bool,
    /// The task has ended.
    stopped: bool,
}

/// Marks the router stopped when its task ends, and drops routes added
/// that it never took.
struct Stopped(Arc<Mutex<Shared>>);

impl Drop for Stopped {
    fn drop(&mut self) {
        let adds = {
            let mut s = lock(&self.0);
            s.stopped = true;
            std::mem::take(&mut s.adds)
        };
        drop(adds);
    }
}

/// Dropped when the last clone of a [`Router`] is dropped.
struct Handle {
    shared: Arc<Mutex<Shared>>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let waker = {
            let mut s = lock(&self.shared);
            s.handles_gone = true;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl Handle {
    fn add(&self, prefix: Prefix, interface: Box<dyn Interface>) {
        let waker = {
            let mut s = lock(&self.shared);
            if s.stopped {
                drop(s);
                drop(interface);
                return;
            }
            s.adds.push((prefix, interface));
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// A handle to a running [`router`], for adding routes later.
///
/// Clones share the same router. Dropping a handle does not stop the
/// router. Once every handle is dropped, no more routes can be added, and
/// the router stops when its last route's interface closes.
#[derive(Clone)]
pub struct Router {
    handle: Arc<Handle>,
}

impl Router {
    /// Adds a route. Packets for `prefix` now go out on `interface`, and
    /// packets that arrive on `interface` are forwarded like any others.
    ///
    /// If a route for exactly `prefix` already exists, the new one replaces
    /// it, and the old interface is dropped, which closes it.
    ///
    /// If the router has stopped, `interface` is dropped.
    pub fn add(&self, prefix: Prefix, interface: Box<dyn Interface>) {
        self.handle.add(prefix, interface);
    }
}

/// Starts an IP LAN that joins real or simulated machines on one subnet.
///
/// Unlike [`router`], a LAN floods broadcast and multicast packets to every
/// other member. A unicast packet goes to the one member registered for its
/// destination address. A unicast packet for an address outside the subnet
/// goes to the [gateway](Lan::gateway), when there is one. The packets
/// themselves are unchanged: the LAN does not lower their TTL or hop limit.
///
/// A LAN carries one address family, its subnet's. On an IPv4 LAN, the
/// subnet's broadcast address, `255.255.255.255` and every multicast
/// address (`224.0.0.0/4`) are flooded. On an IPv6 LAN, every multicast
/// address (`ff00::/8`) is. Flooded packets stay among the members: they
/// do not reach the gateway. The network address of a `/30` or shorter
/// subnet is an ordinary address, and a `/31` or `/32` has no broadcast
/// address (RFC 3021). Packets of the other family are dropped, so a
/// Windows VM's IPv6 link-local traffic does not cross an IPv4 LAN. A
/// link-local address (`169.254.0.0/16`, `fe80::/10`) is on the LAN
/// whatever its subnet: a packet for one goes to the member with exactly
/// that address, or is dropped. It never goes to the gateway.
///
/// Every packet the LAN drops is recorded as a `lan.drop`
/// [event](crate::events) with the reason: no member at the destination,
/// no gateway for an address outside the subnet, a packet from the gateway
/// for such an address, a member's own address, the other address family,
/// or not an IP packet. A member that is replaced or whose interface closes
/// is recorded too (`lan.member_replaced`, `lan.member_removed`). `on_drop`,
/// when given, hears every drop with its reason as well, as
/// [`net::Net`](crate::stdlib::net::Net) uses to name the sandbox that
/// sent it.
///
/// This is how virtual machines attached with `fictionet attach --type tap`
/// share a subnet. Attach answers each VM's ARP itself and hands the LAN
/// its IP packets, so machines configured for the same subnet reach each
/// other although every VM has a point-to-point attachment. IP broadcasts
/// such as NetBIOS Name Service, and multicast such as LLMNR over IPv4,
/// reach the other members. Ethernet-only traffic, including ARP, never
/// reaches a world and is outside this LAN.
///
/// Add members with [`Lan::add`] and the way out with [`Lan::gateway`].
/// Here two machines share a subnet, and a [`router`] carries everything
/// else:
///
/// ```
/// # use fictionet::{Cx, End, Interface, Result, pair};
/// # use fictionet::stdlib::route;
/// # fn wire(cx: Cx, toward_sandbox: End, dc_side: End, pc_side: End) -> Result {
/// let lan = route::lan(&cx, "192.168.56.0/24".parse()?, None);
/// lan.add("192.168.56.10".parse()?, Box::new(dc_side))?;
/// lan.add("192.168.56.100".parse()?, Box::new(pc_side))?;
/// let (lan_side, router_side) = pair();
/// lan.gateway(Box::new(lan_side))?;
/// route::router(&cx, vec![
///     ("192.168.56.0/24".parse()?, Box::new(router_side) as Box<dyn Interface>),
///     ("0.0.0.0/0".parse()?, Box::new(toward_sandbox)),
/// ]);
/// # Ok(())
/// # }
/// ```
///
/// An address has one member: adding it again replaces and closes the old
/// interface. The task stops when the caller's [region](crate::Cx#regions)
/// is cancelled, or when every member and the gateway have closed and the
/// last [`Lan`] handle has been dropped.
#[track_caller]
pub fn lan(cx: &Cx, subnet: Prefix, on_drop: Option<OnDrop>) -> Lan {
    let subnet = subnet.canonical();
    let shared = Arc::new(Mutex::new(LanShared { joins: Vec::new(), waker: None, handles_gone: false, stopped: false }));
    let lan = Lan { handle: Arc::new(LanHandle { subnet, shared: shared.clone() }) };
    cx.spawn_as(|| "lan".into(), move |cx| async move {
        // However the task ends, later members are dropped immediately.
        let _stopped = LanStopped(shared.clone());
        let mut ports = Ports::new(Vec::new());
        let mut members = Members { on_drop, ..Members::default() };
        let mut handles_gone = false;
        loop {
            // Take members added since the last turn.
            let (joins, gone) = {
                let mut s = lock(&shared);
                (std::mem::take(&mut s.joins), s.handles_gone)
            };
            handles_gone = handles_gone || gone;
            for join in joins {
                members.join(&cx, &mut ports, join);
            }
            if members.is_empty() && handles_gone {
                return Ok(());
            }
            let event = ports
                .next(&cx, None, |task| {
                    let mut s = lock(&shared);
                    if !s.joins.is_empty() || (s.handles_gone && !handles_gone) {
                        return Poll::Ready(());
                    }
                    match &s.waker {
                        Some(w) if w.will_wake(task.waker()) => {}
                        _ => s.waker = Some(task.waker().clone()),
                    }
                    Poll::Pending
                })
                .await;
            match event {
                Event::Packet(from, packet) => members.forward(&cx, &mut ports, subnet, from, packet),
                Event::Closed(i) => members.remove_port(&cx, i),
                Event::Extra | Event::Timer => {}
                Event::Cancelled => return Ok(()),
            }
        }
    });
    lan
}

/// Whether a packet for `dst` is flooded to every member of `subnet`: the
/// subnet's broadcast address, the limited broadcast or a multicast address
/// of the subnet's family.
fn floods(subnet: Prefix, dst: IpAddr) -> bool {
    match (subnet.addr, dst) {
        (IpAddr::V4(network), IpAddr::V4(dst)) => {
            dst.is_multicast() || dst == Ipv4Addr::BROADCAST || Some(dst) == broadcast4(network, subnet.len)
        }
        (IpAddr::V6(_), IpAddr::V6(dst)) => dst.is_multicast(),
        _ => false,
    }
}

/// The broadcast address of `network/len`: the host bits all set. A `/31`
/// or `/32` has none (RFC 3021).
fn broadcast4(network: Ipv4Addr, len: u8) -> Option<Ipv4Addr> {
    if len >= 31 {
        return None;
    }
    Some(Ipv4Addr::from(u32::from(network) | (u32::MAX >> len)))
}

/// Whether `addr` is link-local (`169.254.0.0/16` or `fe80::/10`). Such
/// an address is on the LAN whatever its subnet, and never for the gateway.
fn link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.is_unicast_link_local(),
    }
}

/// Hears every packet a [`lan`] drops, with the reason.
pub type OnDrop = Arc<dyn Fn(&Cx, &Packet, &'static str) + Send + Sync>;

/// Records that the LAN dropped `packet`, and why, and tells the
/// `on_drop` sink. Every drop goes through here, so the reporting is one
/// piece.
fn dropped(cx: &Cx, on_drop: &Option<OnDrop>, packet: &Packet, why: &'static str) {
    if let Some(f) = on_drop {
        f(cx, packet, why);
    }
    crate::observe::record_drop(cx, "lan", packet, why);
}

/// Records a change to a LAN's members.
fn member_event(cx: &Cx, kind: &'static str, member: String, what: &str) {
    cx.record(events::Event::new("lan", kind).level(Level::Notice).summary(format!("{member}: {what}")).field("member", member));
}

/// A LAN's members: which port each address goes out on, and the gateway.
#[derive(Default)]
struct Members {
    /// Address to port.
    by_addr: HashMap<IpAddr, usize>,
    /// Port to address.
    by_port: HashMap<usize, IpAddr>,
    /// The gateway's port.
    gateway: Option<usize>,
    /// Hears every drop.
    on_drop: Option<OnDrop>,
}

/// What a [`Lan`] handle adds.
enum Join {
    Member(IpAddr, Box<dyn Interface>),
    Gateway(Box<dyn Interface>),
}

impl Members {
    fn is_empty(&self) -> bool {
        self.by_addr.is_empty() && self.gateway.is_none()
    }

    /// Adds a member or the gateway. One already there is replaced, which
    /// closes its interface.
    fn join(&mut self, cx: &Cx, ports: &mut Ports, join: Join) {
        match join {
            Join::Member(addr, interface) => {
                if let Some(link) = interface.observe_link() {
                    cx.graph().label(&link.0, addr.to_string());
                }
                match self.by_addr.get(&addr).copied() {
                    Some(i) => {
                        ports.replace(i, interface);
                        member_event(cx, "member_replaced", addr.to_string(), "a new interface took over, and the old one is closed");
                    }
                    None => {
                        let i = ports.add(interface);
                        self.by_addr.insert(addr, i);
                        self.by_port.insert(i, addr);
                    }
                }
            }
            Join::Gateway(interface) => {
                if let Some(link) = interface.observe_link() {
                    cx.graph().label(&link.0, "gateway".into());
                }
                match self.gateway {
                    Some(i) => {
                        ports.replace(i, interface);
                        member_event(cx, "member_replaced", "the gateway".into(), "a new interface took over, and the old one is closed");
                    }
                    None => self.gateway = Some(ports.add(interface)),
                }
            }
        }
    }

    /// Forgets the member or gateway whose port closed.
    fn remove_port(&mut self, cx: &Cx, port: usize) {
        if let Some(addr) = self.by_port.remove(&port) {
            self.by_addr.remove(&addr);
            member_event(cx, "member_removed", addr.to_string(), "its interface closed");
        } else if self.gateway == Some(port) {
            self.gateway = None;
            member_event(cx, "member_removed", "the gateway".into(), "its interface closed");
        }
    }

    /// Sends `packet`, which arrived on port `from`, where it belongs, or
    /// drops it with an event.
    fn forward(&self, cx: &Cx, ports: &mut Ports, subnet: Prefix, from: usize, packet: Packet) {
        let Some(dst) = wire::destination(&packet.0) else {
            return dropped(cx, &self.on_drop, &packet, "not an IP packet");
        };
        if dst.is_ipv4() != subnet.addr.is_ipv4() {
            let why = if dst.is_ipv4() { "IPv4 on an IPv6 LAN" } else { "IPv6 on an IPv4 LAN" };
            return dropped(cx, &self.on_drop, &packet, why);
        }
        if floods(subnet, dst) {
            // Every member but the sender. The gateway gets none of it.
            let mut sent = 0;
            for &i in self.by_addr.values() {
                if i != from {
                    ports.send(i, packet.clone());
                    sent += 1;
                }
            }
            ports.spend(sent);
        } else if subnet.contains(dst) || link_local(dst) {
            match self.by_addr.get(&dst) {
                Some(&to) if to == from => dropped(cx, &self.on_drop, &packet, "sent to its own address"),
                Some(&to) => ports.send(to, packet),
                None => dropped(cx, &self.on_drop, &packet, "no member at that address"),
            }
        } else {
            match self.gateway {
                Some(to) if to != from => ports.send(to, packet),
                Some(_) => dropped(cx, &self.on_drop, &packet, "from the gateway, for an address outside the subnet"),
                None => dropped(cx, &self.on_drop, &packet, "outside the subnet, and the LAN has no gateway"),
            }
        }
    }
}

/// What a [`Lan`] handle and its task share.
struct LanShared {
    /// Members added and not yet taken by the task.
    joins: Vec<Join>,
    /// The task, waiting for members.
    waker: Option<Waker>,
    /// Every handle has been dropped.
    handles_gone: bool,
    /// The task has ended.
    stopped: bool,
}

/// Marks the LAN stopped when its task ends, and drops members added that
/// it never took.
struct LanStopped(Arc<Mutex<LanShared>>);

impl Drop for LanStopped {
    fn drop(&mut self) {
        let joins = {
            let mut s = lock(&self.0);
            s.stopped = true;
            std::mem::take(&mut s.joins)
        };
        drop(joins);
    }
}

/// Dropped when the last clone of a [`Lan`] is dropped.
struct LanHandle {
    subnet: Prefix,
    shared: Arc<Mutex<LanShared>>,
}

impl Drop for LanHandle {
    fn drop(&mut self) {
        let waker = {
            let mut s = lock(&self.shared);
            s.handles_gone = true;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl LanHandle {
    fn join(&self, join: Join) -> Result<(), Error> {
        let waker = {
            let mut s = lock(&self.shared);
            if s.stopped {
                drop(s);
                drop(join);
                return Err("the LAN has stopped".into());
            }
            s.joins.push(join);
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }
}

/// A handle to a running IP [`lan`], for adding members later.
///
/// Clones share the same LAN. Dropping a handle does not disconnect
/// members. Once every handle has gone, no more members can be added, and
/// the LAN stops when its last member and the gateway have closed.
#[derive(Clone)]
pub struct Lan {
    handle: Arc<LanHandle>,
}

impl Lan {
    /// Adds the member at `addr`. Packets for `addr` now go out on
    /// `interface`, and packets that arrive on it are forwarded like any
    /// others.
    ///
    /// `addr` must be a unicast address in the LAN's subnet: not its
    /// broadcast address, `255.255.255.255`, a multicast address or the
    /// unspecified address. If `addr` already has a member, the new one
    /// replaces it, and the old interface is dropped, which closes it.
    ///
    /// Fails, and drops `interface`, if `addr` is not such an address or
    /// the LAN has stopped.
    pub fn add(&self, addr: IpAddr, interface: Box<dyn Interface>) -> Result<(), Error> {
        let subnet = self.handle.subnet;
        if !subnet.contains(addr) {
            return Err(format!("{addr} is outside the LAN's subnet {}/{}", subnet.addr, subnet.len).into());
        }
        if addr.is_unspecified() || floods(subnet, addr) {
            return Err(format!("{addr} is not a unicast address, so no member can have it").into());
        }
        self.handle.join(Join::Member(addr, interface))
    }

    /// Makes `interface` the gateway: the way out of the subnet.
    ///
    /// A unicast packet from a member for an address outside the subnet
    /// goes out on `interface`, where a [`router`] can take it. Packets
    /// that arrive on it are delivered like a member's: unicast to the
    /// member at the destination, broadcast and multicast to every member.
    /// Broadcast, multicast and link-local traffic from members do not
    /// reach the gateway, and an arriving packet for an address outside
    /// the subnet is dropped.
    ///
    /// A LAN has one gateway. Calling this again replaces it, and the old
    /// interface is dropped, which closes it. Fails, and drops `interface`,
    /// if the LAN has stopped.
    pub fn gateway(&self, interface: Box<dyn Interface>) -> Result<(), Error> {
        self.handle.join(Join::Gateway(interface))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InterfaceExt;
    use std::time::Duration;

    /// A bare IPv4 header, protocol 253 (for experiments), no payload.
    fn v4(src: [u8; 4], dst: [u8; 4]) -> Packet {
        let mut p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 253, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        Packet(p)
    }

    /// A bare IPv6 header, next header 59 (none), no payload.
    fn v6(src: Ipv6Addr, dst: Ipv6Addr) -> Packet {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        Packet(p)
    }

    #[test]
    fn broadcast_and_multicast_addresses_flood() {
        let p = |s: &str| s.parse::<Prefix>().unwrap().canonical();
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        let lan24 = p("192.168.56.0/24");
        assert!(floods(lan24, a("192.168.56.255")));
        assert!(floods(lan24, a("255.255.255.255")));
        assert!(floods(lan24, a("224.0.0.252")));
        assert!(floods(lan24, a("239.255.255.250")));
        assert!(!floods(lan24, a("192.168.56.0")), "the network address is an ordinary address");
        assert!(!floods(lan24, a("192.168.56.10")));
        assert!(!floods(lan24, a("192.168.57.255")), "another subnet's broadcast is unicast here");
        assert!(!floods(lan24, a("ff02::1:3")), "the other family never floods");
        // A /31 or /32 has no broadcast address.
        assert!(!floods(p("10.0.0.0/31"), a("10.0.0.1")));
        assert!(!floods(p("10.0.0.1/32"), a("10.0.0.1")));
        assert!(floods(p("10.0.0.0/31"), a("255.255.255.255")));
        assert_eq!(broadcast4(Ipv4Addr::UNSPECIFIED, 0), Some(Ipv4Addr::BROADCAST));
        // A length past the address is the whole address, so no shift
        // reaches 32.
        assert_eq!(Prefix { addr: a("10.0.0.1"), len: 40 }.canonical(), p("10.0.0.1/32"));
        assert!(!floods(Prefix { addr: a("10.0.0.1"), len: 40 }.canonical(), a("10.0.0.1")));
        let lan6 = p("fd00::/64");
        assert!(floods(lan6, a("ff02::1:3")));
        assert!(!floods(lan6, a("fd00::1")));
        assert!(!floods(lan6, a("224.0.0.252")));
    }

    #[test]
    fn member_addresses_are_unicast_in_the_subnet() {
        crate::block_on(crate::run(|cx| async move {
            let lan = lan(&cx, "192.168.56.0/24".parse()?, None);
            for bad in ["192.168.57.1", "192.168.56.255", "255.255.255.255", "224.0.0.252", "0.0.0.0", "fd00::1"] {
                let (end, mut far) = crate::pair();
                let err = lan.add(bad.parse()?, Box::new(end)).unwrap_err().to_string();
                assert!(err.contains(bad), "{bad}: {err}");
                assert_eq!(far.recv(&cx).await, Err(crate::RecvError::Closed), "{bad}: the interface is dropped");
            }
            let (end, _far) = crate::pair();
            lan.add("192.168.56.0".parse()?, Box::new(end))?;
            Ok(())
        }))
        .unwrap();
    }

    /// Each kind of drop, a replaced member and a closed one are recorded,
    /// each with its reason, with no observer.
    #[test]
    fn drops_and_member_changes_are_recorded() {
        crate::block_on(crate::run(|cx| async move {
            let lan = lan(&cx, "192.168.56.0/24".parse()?, None);
            let (a_lan, mut a) = crate::pair();
            let (b_lan, _b) = crate::pair();
            lan.add("192.168.56.10".parse()?, Box::new(a_lan))?;
            lan.add("192.168.56.11".parse()?, Box::new(b_lan))?;
            assert!(!cx.observed());
            a.send(v4([192, 168, 56, 10], [192, 168, 56, 12]));
            a.send(v4([192, 168, 56, 10], [10, 0, 0, 1]));
            a.send(v4([192, 168, 56, 10], [192, 168, 56, 10]));
            a.send(v6("fe80::1".parse()?, "ff02::1:3".parse()?));
            a.send(Packet(vec![1, 2, 3]));
            let (b2_lan, b2) = crate::pair();
            lan.add("192.168.56.11".parse()?, Box::new(b2_lan))?;
            cx.sleep(Duration::from_millis(20)).await?;
            drop(b2);
            cx.sleep(Duration::from_millis(20)).await?;

            let events: Vec<(&str, String)> = cx.events().all().into_iter().filter(|e| e.source == "lan").map(|e| (e.kind, e.summary)).collect();
            let drops: Vec<&str> = events.iter().filter(|(k, _)| *k == "drop").map(|(_, t)| t.as_str()).collect();
            let reasons = [
                "no member at that address",
                "outside the subnet, and the LAN has no gateway",
                "sent to its own address",
                "IPv6 on an IPv4 LAN",
                "not an IP packet",
            ];
            assert_eq!(drops.len(), reasons.len(), "{drops:?}");
            for (text, why) in drops.iter().zip(reasons) {
                assert!(text.ends_with(why), "{text:?} should end with {why:?}");
            }
            assert!(drops[0].starts_with("192.168.56.10 → 192.168.56.12"), "{:?}", drops[0]);
            let changes: Vec<_> = events.iter().filter(|(k, _)| *k != "drop").collect();
            assert_eq!(changes.len(), 2, "{changes:?}");
            assert_eq!(changes[0].0, "member_replaced");
            assert!(changes[0].1.starts_with("192.168.56.11"));
            assert_eq!(changes[1].0, "member_removed");
            assert!(changes[1].1.starts_with("192.168.56.11"));
            Ok(())
        }))
        .unwrap();
    }

    /// Once the LAN's task has ended, adding fails and the interface is
    /// dropped.
    #[test]
    fn joining_a_stopped_lan_fails() {
        crate::block_on(crate::run(|cx| async move {
            let kept: Arc<Mutex<Option<Lan>>> = Arc::default();
            let k = kept.clone();
            let r = cx
                .region(|cx| async move {
                    *lock(&k) = Some(lan(&cx, "10.0.0.0/24".parse()?, None));
                    Err("stop".into())
                })
                .await;
            assert_eq!(r.unwrap_err().to_string(), "stop");
            let lan = lock(&kept).take().unwrap();
            let (end, mut far) = crate::pair();
            assert_eq!(lan.add("10.0.0.2".parse()?, Box::new(end)).unwrap_err().to_string(), "the LAN has stopped");
            assert_eq!(far.recv(&cx).await, Err(crate::RecvError::Closed));
            let (end, mut far) = crate::pair();
            assert_eq!(lan.gateway(Box::new(end)).unwrap_err().to_string(), "the LAN has stopped");
            assert_eq!(far.recv(&cx).await, Err(crate::RecvError::Closed));
            Ok(())
        }))
        .unwrap();
    }
}
