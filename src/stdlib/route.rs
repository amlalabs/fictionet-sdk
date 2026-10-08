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
//! [`web::Sites`](fictionet::stdlib::web::Sites) instead.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};

use fictionet::events::{self, Level};
use fictionet::stdlib::{
    ip,
    ports::{self, Ports},
};
use fictionet::{Cx, Error, Interface, Packet};

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
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| fictionet::Error::msg(format!("{s:?} is not an address prefix")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(l) => match l.parse::<u8>() {
                Ok(n) if n <= max && !l.starts_with('+') => n,
                _ => {
                    return Err(fictionet::Error::msg(format!(
                        "{s:?}: the length must be 0 to {max}"
                    )));
                }
            },
        };
        Ok(Prefix {
            addr: mask(addr, len),
            len,
        })
    }
}

impl Prefix {
    /// The same prefix with the bits past its length cleared. A length
    /// longer than the address, in a `Prefix` built by hand, counts as the
    /// whole address.
    pub fn canonical(self) -> Prefix {
        let len = self.len.min(if self.addr.is_ipv4() { 32 } else { 128 });
        Prefix {
            addr: mask(self.addr, len),
            len,
        }
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
            let m = if len == 0 {
                0
            } else {
                u32::MAX << (32 - len.min(32) as u32)
            };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len.min(128) as u32)
            };
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
/// router's task stops when the caller's [region](fictionet::Cx#regions) is
/// cancelled, or when the interfaces of all its routes have closed and
/// every [`Router`] handle has been dropped.
///
/// Each route needs an interface whose other end is held by whatever lies
/// in that direction. Make the two ends with [`pair`](fictionet::pair), give
/// one to the router, and build a machine on the other. Here the sandbox
/// gets the default route, and two machines each get one address:
///
/// ```
/// # use fictionet::{Cx, End, Interface, Result, pair};
/// # use fictionet::stdlib::{ip, route, tcp};
/// # fn wire(fcx: Cx, toward_sandbox: End) -> Result {
/// let (router_side, stripe_side) = pair();
/// let (router_side_dns, dns_side) = pair();
/// route::router(&fcx, vec![
///     ("0.0.0.0/0".parse()?, Box::new(toward_sandbox) as Box<dyn Interface>),
///     ("104.18.32.7/32".parse()?, Box::new(router_side)),
///     ("1.1.1.1/32".parse()?, Box::new(router_side_dns)),
/// ]);
/// let (tcp, _udp, _icmp, _other) = ip::split_protocols(&fcx, stripe_side);
/// let stripe = tcp::endpoint(&fcx, tcp, "104.18.32.7".parse()?);
/// # drop((dns_side, stripe));
/// # Ok(())
/// # }
/// ```
///
/// Interfaces of different types share the list as `I`.
///
/// A route's prefix is compared with its address bits past the length
/// cleared. A packet that is neither IPv4 nor IPv6, or too short to hold a
/// destination address, is dropped. A packet whose best route is the
/// interface it came in on goes back out on that interface, as on a real
/// router.
///
/// Like a real router, it lowers each packet's TTL or hop limit by one,
/// and changes nothing else (the IPv4 header checksum follows the TTL). A
/// packet that arrives with a TTL or hop limit of 0 or 1 is dropped, so a
/// loop of routes, such as two routers whose default routes point at each
/// other, cannot carry a packet forever. The drop is recorded as a
/// `router.drop` [event](fictionet::events), a [repeat](fictionet::events#repeats). Once the router has an [address](Router::address) of the
/// packet's family, it also answers the sender with an ICMP "time
/// exceeded" ([`icmp::time_exceeded`](fictionet::stdlib::icmp::time_exceeded)),
/// which is what `traceroute` reads. Packets to or from the router's own
/// addresses are its own, not forwarded, and keep their TTL. A router
/// told to [`keep_ttl`](Router::keep_ttl) changes no packet.
#[track_caller]
pub fn router<I: Interface>(fcx: &Cx, routes: Vec<(Prefix, I)>) -> Router<I> {
    let (sender, changes) =
        Changes::channel(routes.into_iter().map(|(p, i)| Edit::Route(p, i)).collect());
    let router = Router {
        handle: Arc::new(sender),
    };
    fcx.spawn_as(
        || "router".into(),
        move |fcx| async move {
            let mut ports = Ports::new(Vec::new());
            // Which port each prefix goes out on.
            let mut table = Table::default();
            let mut handles_gone = false;
            let mut addrs = (None, None);
            let mut keep_ttl = false;
            loop {
                let (edits, gone) = changes.drain();
                handles_gone = handles_gone || gone;
                for edit in edits {
                    let (prefix, interface) = match edit {
                        Edit::Route(prefix, interface) => (prefix, interface),
                        Edit::Address(addr) => {
                            match addr {
                                IpAddr::V4(a) => addrs.0 = Some(a),
                                IpAddr::V6(a) => addrs.1 = Some(a),
                            }
                            continue;
                        }
                        Edit::KeepTtl => {
                            keep_ttl = true;
                            continue;
                        }
                    };
                    let prefix = prefix.canonical();
                    if let Some(link) = interface.observe_link() {
                        link.label(&fcx, format!("{}/{}", prefix.addr, prefix.len));
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
                    .next(&fcx, None, |cx| changes.poll(cx, handles_gone))
                    .await?;
                match event {
                    ports::Event::Packet(_, mut packet) => {
                        let Some(dst) = ip::destination(&packet.0) else {
                            continue;
                        };
                        if !keep_ttl
                            && !is_own(addrs, dst)
                            && !ip::source(&packet.0).is_some_and(|src| is_own(addrs, src))
                            && ip::hop(&mut packet.0) == ip::Hop::Expired
                        {
                            expired(&fcx, addrs, &table, &mut ports, packet);
                            continue;
                        }
                        if let Some(i) = table.best(dst) {
                            ports.send(i, packet);
                        }
                    }
                    ports::Event::Closed(i) => {
                        if let Some(prefix) = table.by_port.get(&i) {
                            let prefix = format!("{}/{}", prefix.addr, prefix.len);
                            let event = events::Event::new("router", "route_removed")
                                .level(Level::Notice)
                                .summary(format!("{prefix}: its interface closed"))
                                .field("prefix", prefix);
                            fcx.record(event);
                        }
                        table.remove_port(i)
                    }
                    ports::Event::Extra | ports::Event::Timer => {}
                }
            }
        },
    );
    router
}

/// Drops a packet whose TTL or hop limit ran out, records the drop, and
/// sends the "time exceeded" answer back toward its source, when the router
/// has an address of its family.
fn expired<I: Interface>(
    fcx: &Cx,
    addrs: Addrs,
    table: &Table,
    ports: &mut Ports<I>,
    packet: Packet,
) {
    let v4 = ip::version(&packet.0) == Some(4);
    let why = if v4 {
        "its TTL ran out"
    } else {
        "its hop limit ran out"
    };
    fictionet::events::record_drop(
        fcx,
        "router",
        &packet,
        why,
        events::Fields::new(),
        |event| event,
    );
    let (a4, a6) = addrs;
    let from = if v4 {
        a4.map(IpAddr::V4)
    } else {
        a6.map(IpAddr::V6)
    };
    let answer = from.and_then(|from| fictionet::stdlib::icmp::time_exceeded(&packet.0, from));
    if let Some(answer) = answer
        && let Some(src) = ip::source(&packet.0)
        && let Some(i) = table.best(src)
    {
        ports.send(i, answer);
    }
}

/// A router's own IPv4 and IPv6 addresses.
type Addrs = (Option<Ipv4Addr>, Option<Ipv6Addr>);

/// Whether `addr` is one of the router's own.
fn is_own(addrs: Addrs, addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => addrs.0 == Some(a),
        IpAddr::V6(a) => addrs.1 == Some(a),
    }
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
        *self
            .lengths
            .entry((prefix.addr.is_ipv4(), prefix.len))
            .or_default() += 1;
    }

    /// Drops the route that goes out on `port`.
    fn remove_port(&mut self, port: usize) {
        let Some(prefix) = self.by_port.remove(&port) else {
            return;
        };
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
            .find_map(|(&(_, len), _)| {
                self.routes
                    .get(&Prefix {
                        addr: mask(dst, len),
                        len,
                    })
                    .copied()
            })
    }
}

/// Pending changes and the task waiting for them.
struct Changes<C> {
    queue: Vec<C>,
    waker: Option<Waker>,
    closed: bool,
    stopped: bool,
}

struct Sender<C>(Arc<Mutex<Changes<C>>>);
struct Receiver<C>(Arc<Mutex<Changes<C>>>);

impl<C> Changes<C> {
    fn channel(queue: Vec<C>) -> (Sender<C>, Receiver<C>) {
        let shared = Arc::new(Mutex::new(Self {
            queue,
            waker: None,
            closed: false,
            stopped: false,
        }));
        (Sender(shared.clone()), Receiver(shared))
    }
}

impl<C> Sender<C> {
    fn send(&self, change: C) -> Result<(), C> {
        let waker = {
            let mut s = lock(&self.0);
            if s.stopped {
                return Err(change);
            }
            s.queue.push(change);
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }
}

impl<C> Drop for Sender<C> {
    fn drop(&mut self) {
        let waker = {
            let mut s = lock(&self.0);
            s.closed = true;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl<C> Receiver<C> {
    fn drain(&self) -> (Vec<C>, bool) {
        let mut s = lock(&self.0);
        (std::mem::take(&mut s.queue), s.closed)
    }

    fn poll(&self, cx: &mut std::task::Context<'_>, closed: bool) -> Poll<()> {
        let mut s = lock(&self.0);
        if !s.queue.is_empty() || (s.closed && !closed) {
            return Poll::Ready(());
        }
        match &s.waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => s.waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl<C> Drop for Receiver<C> {
    fn drop(&mut self) {
        let queued = {
            let mut s = lock(&self.0);
            s.stopped = true;
            std::mem::take(&mut s.queue)
        };
        drop(queued);
    }
}

enum Edit<I> {
    Route(Prefix, I),
    Address(IpAddr),
    KeepTtl,
}

/// A handle to a running [`router`], for adding routes later.
///
/// Clones share the same router. Dropping a handle does not stop the
/// router. Once every handle is dropped, no more routes can be added, and
/// the router stops when its last route's interface closes.
pub struct Router<I: Interface> {
    handle: Arc<Sender<Edit<I>>>,
}

impl<I: Interface> Clone for Router<I> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
        }
    }
}

impl<I: Interface> Router<I> {
    /// Adds a route. Packets for `prefix` now go out on `interface`, and
    /// packets that arrive on `interface` are forwarded like any others.
    ///
    /// If a route for exactly `prefix` already exists, the new one replaces
    /// it, and the old interface is dropped, which closes it.
    ///
    /// If the router has stopped, `interface` is dropped.
    pub fn add(&self, prefix: Prefix, interface: I) {
        drop(self.handle.send(Edit::Route(prefix, interface)));
    }

    /// Gives the router an address of `addr`'s family, replacing the one it
    /// had. Its ICMP "time exceeded" answers come from it. A router has no
    /// address at first, and then drops expired packets without an answer.
    pub fn address(&self, addr: IpAddr) {
        drop(self.handle.send(Edit::Address(addr)));
    }

    /// Makes the router a private one, invisible to the packets it
    /// forwards: from now on it leaves their TTL and hop limit as they are,
    /// and never drops a packet for running out. A network that should look
    /// like one hop, such as [`Net`](fictionet::stdlib::net::Net), uses this.
    /// Such a router can carry a packet around a loop of routes forever, so
    /// use it only where every way back to it passes something that lowers
    /// the TTL itself, such as a sandbox's kernel.
    pub fn keep_ttl(&self) {
        drop(self.handle.send(Edit::KeepTtl));
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
/// [repeat](fictionet::events#repeats) with the reason: no member at the destination,
/// no gateway for an address outside the subnet, a packet from the gateway
/// for such an address, a member's own address, the other address family,
/// or not an IP packet. A member that is replaced or whose interface closes
/// is recorded too (`lan.member_replaced`, `lan.member_removed`). `enrich`
/// adds context to each drop before recording it, as
/// [`net::Net`](fictionet::stdlib::net::Net) uses to name the LAN.
/// Attachment identity comes from the ingress registration.
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
/// # fn wire(fcx: Cx, toward_sandbox: End, dc_side: End, pc_side: End) -> Result {
/// let lan = route::lan::<Box<dyn Interface>, _>(&fcx, "192.168.56.0/24".parse()?, |event| event);
/// lan.add("192.168.56.10".parse()?, Box::new(dc_side), None)?;
/// lan.add("192.168.56.100".parse()?, Box::new(pc_side), None)?;
/// let (lan_side, router_side) = pair();
/// lan.gateway(Box::new(lan_side))?;
/// route::router(&fcx, vec![
///     ("192.168.56.0/24".parse()?, Box::new(router_side) as Box<dyn Interface>),
///     ("0.0.0.0/0".parse()?, Box::new(toward_sandbox)),
/// ]);
/// # Ok(())
/// # }
/// ```
///
/// An address has one member: adding it again replaces and closes the old
/// interface. The task stops when the caller's [region](fictionet::Cx#regions)
/// is cancelled, or when every member and the gateway have closed and the
/// last [`Lan`] handle has been dropped.
#[track_caller]
pub fn lan<I, F>(fcx: &Cx, subnet: Prefix, enrich: F) -> Lan<I>
where
    I: Interface,
    F: Fn(events::Event) -> events::Event + Send + 'static,
{
    let subnet = subnet.canonical();
    let (sender, changes) = Changes::channel(Vec::new());
    let lan = Lan {
        handle: Arc::new(LanHandle { subnet, sender }),
    };
    fcx.spawn_as(
        || "lan".into(),
        move |fcx| async move {
            let mut ports = Ports::new(Vec::new());
            let mut members = Members::new(enrich);
            let mut handles_gone = false;
            loop {
                let (joins, gone) = changes.drain();
                handles_gone = handles_gone || gone;
                for join in joins {
                    members.join(&fcx, &mut ports, join);
                }
                if members.is_empty() && handles_gone {
                    return Ok(());
                }
                let event = ports
                    .next(&fcx, None, |cx| changes.poll(cx, handles_gone))
                    .await?;
                match event {
                    ports::Event::Packet(from, packet) => {
                        members.forward(&fcx, &mut ports, subnet, from, packet)
                    }
                    ports::Event::Closed(i) => members.remove_port(&fcx, i),
                    ports::Event::Extra | ports::Event::Timer => {}
                }
            }
        },
    );
    lan
}

/// Whether a packet for `dst` is flooded to every member of `subnet`: the
/// subnet's broadcast address, the limited broadcast or a multicast address
/// of the subnet's family.
fn floods(subnet: Prefix, dst: IpAddr) -> bool {
    match (subnet.addr, dst) {
        (IpAddr::V4(network), IpAddr::V4(dst)) => {
            dst.is_multicast()
                || dst == Ipv4Addr::BROADCAST
                || Some(dst) == broadcast4(network, subnet.len)
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

/// Records one LAN drop with its ingress attachment and caller context.
fn dropped<F>(
    fcx: &Cx,
    packet: &Packet,
    why: &'static str,
    sandbox: Option<&events::Sandbox>,
    enrich: &F,
) where
    F: Fn(events::Event) -> events::Event,
{
    events::record_drop(
        fcx,
        "lan",
        packet,
        why,
        events::Fields::new(),
        |mut event| {
            event.conn.sandbox = sandbox.cloned();
            enrich(event)
        },
    );
}

/// Records a change to a LAN's members.
fn member_event(fcx: &Cx, kind: &'static str, member: String, what: &str) {
    fcx.record(
        events::Event::new("lan", kind)
            .level(Level::Notice)
            .summary(format!("{member}: {what}"))
            .field("member", member),
    );
}

/// A LAN's members: which port each address goes out on, and the gateway.
struct Members<F> {
    /// Address to port.
    by_addr: BTreeMap<IpAddr, usize>,
    /// Port to address.
    by_port: HashMap<usize, IpAddr>,
    /// The gateway's port.
    gateway: Option<usize>,
    /// Attachment identity registered for each ingress port.
    attachments: HashMap<usize, events::Sandbox>,
    enrich: F,
}

/// What a [`Lan`] handle adds.
enum Join<I: Interface> {
    Member(IpAddr, I, Option<events::Sandbox>),
    Gateway(I),
}

impl<F: Fn(events::Event) -> events::Event> Members<F> {
    fn new(enrich: F) -> Self {
        Self {
            by_addr: BTreeMap::new(),
            by_port: HashMap::new(),
            gateway: None,
            attachments: HashMap::new(),
            enrich,
        }
    }

    fn is_empty(&self) -> bool {
        self.by_addr.is_empty() && self.gateway.is_none()
    }

    /// Adds a member or the gateway. One already there is replaced, which
    /// closes its interface.
    fn join<I: Interface>(&mut self, fcx: &Cx, ports: &mut Ports<I>, join: Join<I>) {
        match join {
            Join::Member(addr, interface, attachment) => {
                if let Some(link) = interface.observe_link() {
                    link.label(fcx, addr.to_string());
                }
                let i = match self.by_addr.get(&addr).copied() {
                    Some(i) => {
                        ports.replace(i, interface);
                        member_event(
                            fcx,
                            "member_replaced",
                            addr.to_string(),
                            "a new interface took over, and the old one is closed",
                        );
                        i
                    }
                    None => {
                        let i = ports.add(interface);
                        self.by_addr.insert(addr, i);
                        self.by_port.insert(i, addr);
                        i
                    }
                };
                match attachment {
                    Some(attachment) => {
                        self.attachments.insert(i, attachment);
                    }
                    None => {
                        self.attachments.remove(&i);
                    }
                }
            }
            Join::Gateway(interface) => {
                if let Some(link) = interface.observe_link() {
                    link.label(fcx, "gateway".into());
                }
                match self.gateway {
                    Some(i) => {
                        ports.replace(i, interface);
                        member_event(
                            fcx,
                            "member_replaced",
                            "the gateway".into(),
                            "a new interface took over, and the old one is closed",
                        );
                    }
                    None => self.gateway = Some(ports.add(interface)),
                }
            }
        }
    }

    /// Forgets the member or gateway whose port closed.
    fn remove_port(&mut self, fcx: &Cx, port: usize) {
        self.attachments.remove(&port);
        if let Some(addr) = self.by_port.remove(&port) {
            self.by_addr.remove(&addr);
            member_event(
                fcx,
                "member_removed",
                addr.to_string(),
                "its interface closed",
            );
        } else if self.gateway == Some(port) {
            self.gateway = None;
            member_event(
                fcx,
                "member_removed",
                "the gateway".into(),
                "its interface closed",
            );
        }
    }

    /// Sends `packet`, which arrived on port `from`, where it belongs, or
    /// drops it with an event.
    fn forward<I: Interface>(
        &self,
        fcx: &Cx,
        ports: &mut Ports<I>,
        subnet: Prefix,
        from: usize,
        packet: Packet,
    ) {
        let Some(dst) = ip::destination(&packet.0) else {
            return dropped(
                fcx,
                &packet,
                "not an IP packet",
                self.attachments.get(&from),
                &self.enrich,
            );
        };
        if dst.is_ipv4() != subnet.addr.is_ipv4() {
            let why = if dst.is_ipv4() {
                "IPv4 on an IPv6 LAN"
            } else {
                "IPv6 on an IPv4 LAN"
            };
            return dropped(fcx, &packet, why, self.attachments.get(&from), &self.enrich);
        }
        if floods(subnet, dst) {
            // Every member but the sender, in address order. The gateway gets none of it.
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
                Some(&to) if to == from => dropped(
                    fcx,
                    &packet,
                    "sent to its own address",
                    self.attachments.get(&from),
                    &self.enrich,
                ),
                Some(&to) => ports.send(to, packet),
                None => dropped(
                    fcx,
                    &packet,
                    "no member at that address",
                    self.attachments.get(&from),
                    &self.enrich,
                ),
            }
        } else {
            match self.gateway {
                Some(to) if to != from => ports.send(to, packet),
                Some(_) => dropped(
                    fcx,
                    &packet,
                    "from the gateway, for an address outside the subnet",
                    self.attachments.get(&from),
                    &self.enrich,
                ),
                None => dropped(
                    fcx,
                    &packet,
                    "outside the subnet, and the LAN has no gateway",
                    self.attachments.get(&from),
                    &self.enrich,
                ),
            }
        }
    }
}

struct LanHandle<I: Interface> {
    subnet: Prefix,
    sender: Sender<Join<I>>,
}

impl<I: Interface> LanHandle<I> {
    fn join(&self, join: Join<I>) -> Result<(), Error> {
        self.sender.send(join).map_err(|join| {
            drop(join);
            fictionet::Error::msg("the LAN has stopped")
        })
    }
}

/// A handle to a running IP [`lan`], for adding members later.
///
/// Clones share the same LAN. Dropping a handle does not disconnect
/// members. Once every handle has gone, no more members can be added, and
/// the LAN stops when its last member and the gateway have closed.
pub struct Lan<I: Interface> {
    handle: Arc<LanHandle<I>>,
}

impl<I: Interface> Clone for Lan<I> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
        }
    }
}

impl<I: Interface> Lan<I> {
    /// Adds the member at `addr`, with optional ingress attachment identity.
    /// Packets for `addr` now go out on
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
    pub fn add(
        &self,
        addr: IpAddr,
        interface: I,
        attachment: Option<events::Sandbox>,
    ) -> Result<(), Error> {
        let subnet = self.handle.subnet;
        if !subnet.contains(addr) {
            return Err(fictionet::Error::msg(format!(
                "{addr} is outside the LAN's subnet {}/{}",
                subnet.addr, subnet.len
            )));
        }
        if addr.is_unspecified() || floods(subnet, addr) {
            return Err(fictionet::Error::msg(format!(
                "{addr} is not a unicast address, so no member can have it"
            )));
        }
        self.handle.join(Join::Member(addr, interface, attachment))
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
    pub fn gateway(&self, interface: I) -> Result<(), Error> {
        self.handle.join(Join::Gateway(interface))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::InterfaceExt;
    use std::time::Duration;

    #[test]
    fn stopped_changes_drop_values_outside_the_lock() {
        struct Pending(std::sync::Weak<Mutex<Changes<Pending>>>);
        impl Drop for Pending {
            fn drop(&mut self) {
                if let Some(shared) = self.0.upgrade() {
                    assert!(shared.try_lock().is_ok());
                }
            }
        }
        let (sender, receiver) = Changes::channel(Vec::new());
        let pending = || Pending(Arc::downgrade(&sender.0));
        assert!(sender.send(pending()).is_ok());
        drop(receiver);
        assert!(sender.send(pending()).is_err());
        assert!(lock(&sender.0).queue.is_empty());
    }

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

    /// The packet waiting on `iface`, if any, without waiting.
    fn ready(fcx: &Cx, iface: &mut fictionet::End) -> Option<Packet> {
        let mut cx = std::task::Context::from_waker(Waker::noop());
        match iface.poll_recv(fcx, &mut cx) {
            Poll::Ready(Ok(p)) => Some(p),
            _ => None,
        }
    }

    fn ip(src: &str, dst: &str, ttl: u8) -> Packet {
        let mut p =
            fictionet::stdlib::ip::packet(src.parse().unwrap(), dst.parse().unwrap(), 17, &[0; 8]);
        if p.0[0] >> 4 == 4 {
            p.0[8] = ttl;
            ip::set_header_checksum(&mut p.0[..20]);
        } else {
            p.0[7] = ttl;
        }
        p
    }

    /// Two routers whose default routes point at each other: the packet
    /// dies when its TTL or hop limit runs out, the router that drops it
    /// says so, and the sender hears "time exceeded".
    #[test]
    fn a_routing_loop_ends_when_the_ttl_runs_out() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let (r1_s4, mut s4) = fictionet::pair();
                let (r1_s6, mut s6) = fictionet::pair();
                let (r1_r2, r2_r1) = fictionet::pair();
                let (r1_r2_6, r2_r1_6) = fictionet::pair();
                let r1 = router(
                    &fcx,
                    vec![
                        (
                            "10.0.0.2/32".parse()?,
                            Box::new(r1_s4) as Box<dyn Interface>,
                        ),
                        ("fd00::2/128".parse()?, Box::new(r1_s6)),
                        ("0.0.0.0/0".parse()?, Box::new(r1_r2)),
                        ("::/0".parse()?, Box::new(r1_r2_6)),
                    ],
                );
                r1.address("10.0.0.1".parse()?);
                let r2 = router(
                    &fcx,
                    vec![
                        ("0.0.0.0/0".parse()?, Box::new(r2_r1) as Box<dyn Interface>),
                        ("::/0".parse()?, Box::new(r2_r1_6)),
                    ],
                );
                r2.address("fd00:1::1".parse()?);

                // TTL 5: r1 sends it on with 4, r2 with 3, r1 with 2, r2 with
                // 1, and r1 drops it.
                s4.send(ip("10.0.0.2", "192.0.2.1", 5));
                // Hop limit 4: r1, r2, r1, and r2 drops it.
                s6.send(ip("fd00::2", "2001:db8::1", 4));
                fcx.sleep(Duration::from_millis(100)).await?;

                let answer = ready(&fcx, &mut s4).expect("a time exceeded answer");
                assert_eq!(ip::source(&answer.0), Some("10.0.0.1".parse()?));
                assert_eq!(
                    (answer.0[9], answer.0[20], answer.0[21]),
                    (ip::protocol::ICMP, 11, 0)
                );
                assert!(ready(&fcx, &mut s4).is_none());
                let answer = ready(&fcx, &mut s6).expect("a time exceeded answer");
                assert_eq!(ip::source(&answer.0), Some("fd00:1::1".parse()?));
                assert_eq!(
                    (answer.0[6], answer.0[40], answer.0[41]),
                    (ip::protocol::ICMPV6, 3, 0)
                );
                // r1 forwarded r2's answer: one hop.
                assert_eq!(answer.0[7], 63);

                let drops: Vec<String> = fcx
                    .events()
                    .of("router", "drop")
                    .into_iter()
                    .map(|e| e.summary)
                    .collect();
                assert_eq!(drops.len(), 2, "{drops:?}");
                assert!(
                    drops
                        .iter()
                        .any(|d| d == "10.0.0.2 → 192.0.2.1: its TTL ran out"),
                    "{drops:?}"
                );
                assert!(
                    drops.iter().any(|d| d.ends_with("its hop limit ran out")),
                    "{drops:?}"
                );
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A forwarded packet loses one from its TTL, with a checksum that still
    /// holds. The router's own packets keep theirs.
    #[test]
    fn forwarding_lowers_the_ttl() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let (ra, mut a) = fictionet::pair();
                let (rb, mut b) = fictionet::pair();
                let (rg, mut g) = fictionet::pair();
                let r = router(
                    &fcx,
                    vec![
                        ("10.0.0.2/32".parse()?, Box::new(ra) as Box<dyn Interface>),
                        ("10.0.0.3/32".parse()?, Box::new(rb)),
                        ("10.0.0.1/32".parse()?, Box::new(rg)),
                    ],
                );
                r.address("10.0.0.1".parse()?);
                a.send(ip("10.0.0.2", "10.0.0.3", 64));
                let p = b.recv(&fcx).await?;
                assert_eq!(p.0[8], 63);
                assert_eq!(ip::checksum(&p.0[..20]), 0, "the header checksum holds");
                // An expired packet for the router itself is still delivered.
                a.send(ip("10.0.0.2", "10.0.0.1", 1));
                assert_eq!(g.recv(&fcx).await?.0[8], 1);
                g.send(ip("10.0.0.1", "10.0.0.2", 64));
                assert_eq!(a.recv(&fcx).await?.0[8], 64);
                // A private router changes nothing, and forwards even TTL 1.
                r.keep_ttl();
                fcx.sleep(Duration::from_millis(1)).await?;
                a.send(ip("10.0.0.2", "10.0.0.3", 1));
                assert_eq!(b.recv(&fcx).await?.0[8], 1);
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn lan_floods_in_address_order() {
        struct Receiver(u8, Arc<Mutex<Vec<u8>>>);
        impl Interface for Receiver {
            fn poll_recv(
                &mut self,
                _: &Cx,
                _: &mut std::task::Context<'_>,
            ) -> Poll<Result<Packet, fictionet::RecvError>> {
                Poll::Pending
            }

            fn send(&mut self, _: Packet) {
                lock(&self.1).push(self.0);
            }
        }

        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                for _ in 0..128 {
                    let sent = Arc::new(Mutex::new(Vec::new()));
                    let mut members = Members::new(|event| event);
                    let mut ports = Ports::new(Vec::new());
                    for n in [40, 10, 30, 20, 50] {
                        members.join(
                            &fcx,
                            &mut ports,
                            Join::Member(
                                Ipv4Addr::new(10, 0, 0, n).into(),
                                Receiver(n, sent.clone()),
                                None,
                            ),
                        );
                    }
                    members.join(&fcx, &mut ports, Join::Gateway(Receiver(99, sent.clone())));
                    for dst in [[255; 4], [10, 0, 0, 255], [224, 0, 0, 1]] {
                        members.forward(
                            &fcx,
                            &mut ports,
                            "10.0.0.0/24".parse()?,
                            2,
                            v4([10, 0, 0, 30], dst),
                        );
                        assert_eq!(*lock(&sent), [10, 20, 40, 50]);
                        lock(&sent).clear();
                    }
                }
                Ok(())
            },
        ))
        .unwrap();
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
        assert!(
            !floods(lan24, a("192.168.56.0")),
            "the network address is an ordinary address"
        );
        assert!(!floods(lan24, a("192.168.56.10")));
        assert!(
            !floods(lan24, a("192.168.57.255")),
            "another subnet's broadcast is unicast here"
        );
        assert!(
            !floods(lan24, a("ff02::1:3")),
            "the other family never floods"
        );
        // A /31 or /32 has no broadcast address.
        assert!(!floods(p("10.0.0.0/31"), a("10.0.0.1")));
        assert!(!floods(p("10.0.0.1/32"), a("10.0.0.1")));
        assert!(floods(p("10.0.0.0/31"), a("255.255.255.255")));
        assert_eq!(
            broadcast4(Ipv4Addr::UNSPECIFIED, 0),
            Some(Ipv4Addr::BROADCAST)
        );
        // A length past the address is the whole address, so no shift
        // reaches 32.
        assert_eq!(
            Prefix {
                addr: a("10.0.0.1"),
                len: 40
            }
            .canonical(),
            p("10.0.0.1/32")
        );
        assert!(!floods(
            Prefix {
                addr: a("10.0.0.1"),
                len: 40
            }
            .canonical(),
            a("10.0.0.1")
        ));
        let lan6 = p("fd00::/64");
        assert!(floods(lan6, a("ff02::1:3")));
        assert!(!floods(lan6, a("fd00::1")));
        assert!(!floods(lan6, a("224.0.0.252")));
    }

    #[test]
    fn member_addresses_are_unicast_in_the_subnet() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let lan =
                    lan::<Box<dyn Interface>, _>(&fcx, "192.168.56.0/24".parse()?, |event| event);
                for bad in [
                    "192.168.57.1",
                    "192.168.56.255",
                    "255.255.255.255",
                    "224.0.0.252",
                    "0.0.0.0",
                    "fd00::1",
                ] {
                    let (end, mut far) = fictionet::pair();
                    let err = lan
                        .add(bad.parse()?, Box::new(end), None)
                        .unwrap_err()
                        .to_string();
                    assert!(err.contains(bad), "{bad}: {err}");
                    assert_eq!(
                        far.recv(&fcx).await,
                        Err(fictionet::RecvError::Closed),
                        "{bad}: the interface is dropped"
                    );
                }
                let (end, _far) = fictionet::pair();
                lan.add("192.168.56.0".parse()?, Box::new(end), None)?;
                Ok(())
            },
        ))
        .unwrap();
    }

    /// Each kind of drop, a replaced member and a closed one are recorded,
    /// each with its reason, with no observer.
    #[test]
    fn drops_and_member_changes_are_recorded() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let lan =
                    lan::<Box<dyn Interface>, _>(&fcx, "192.168.56.0/24".parse()?, |event| event);
                let (a_lan, mut a) = fictionet::pair();
                let (b_lan, _b) = fictionet::pair();
                lan.add("192.168.56.10".parse()?, Box::new(a_lan), None)?;
                lan.add("192.168.56.11".parse()?, Box::new(b_lan), None)?;
                assert!(!fcx.observed());
                a.send(v4([192, 168, 56, 10], [192, 168, 56, 12]));
                a.send(v4([192, 168, 56, 10], [10, 0, 0, 1]));
                a.send(v4([192, 168, 56, 10], [192, 168, 56, 10]));
                a.send(v6("fe80::1".parse()?, "ff02::1:3".parse()?));
                a.send(Packet(vec![1, 2, 3]));
                let (b2_lan, b2) = fictionet::pair();
                lan.add("192.168.56.11".parse()?, Box::new(b2_lan), None)?;
                fcx.sleep(Duration::from_millis(20)).await?;
                drop(b2);
                fcx.sleep(Duration::from_millis(20)).await?;

                let events: Vec<(&str, String)> = fcx
                    .events()
                    .all()
                    .into_iter()
                    .filter(|e| e.source == "lan")
                    .map(|e| (e.kind, e.summary))
                    .collect();
                let drops: Vec<&str> = events
                    .iter()
                    .filter(|(k, _)| *k == "drop")
                    .map(|(_, t)| t.as_str())
                    .collect();
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
                assert!(
                    drops[0].starts_with("192.168.56.10 → 192.168.56.12"),
                    "{:?}",
                    drops[0]
                );
                let changes: Vec<_> = events.iter().filter(|(k, _)| *k != "drop").collect();
                assert_eq!(changes.len(), 2, "{changes:?}");
                assert_eq!(changes[0].0, "member_replaced");
                assert!(changes[0].1.starts_with("192.168.56.11"));
                assert_eq!(changes[1].0, "member_removed");
                assert!(changes[1].1.starts_with("192.168.56.11"));
                Ok(())
            },
        ))
        .unwrap();
    }

    /// Once the LAN's task has ended, adding fails and the interface is
    /// dropped.
    #[test]
    fn joining_a_stopped_lan_fails() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let kept = Arc::new(Mutex::new(None::<Lan<Box<dyn Interface>>>));
                let k = kept.clone();
                let r = fcx
                    .region(|fcx| async move {
                        *lock(&k) = Some(lan(&fcx, "10.0.0.0/24".parse()?, |event| event));
                        Err(fictionet::Error::msg("stop"))
                    })
                    .await;
                assert_eq!(r.unwrap_err().to_string(), "stop");
                let lan = lock(&kept).take().unwrap();
                let (end, mut far) = fictionet::pair();
                assert_eq!(
                    lan.add("10.0.0.2".parse()?, Box::new(end), None)
                        .unwrap_err()
                        .to_string(),
                    "the LAN has stopped"
                );
                assert_eq!(far.recv(&fcx).await, Err(fictionet::RecvError::Closed));
                let (end, mut far) = fictionet::pair();
                assert_eq!(
                    lan.gateway(Box::new(end)).unwrap_err().to_string(),
                    "the LAN has stopped"
                );
                assert_eq!(far.recv(&fcx).await, Err(fictionet::RecvError::Closed));
                Ok(())
            },
        ))
        .unwrap();
    }
}
