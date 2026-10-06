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
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use crate::stdlib::{Event, Ports, wire};
use crate::{Cx, Error, Interface};

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
    /// The same prefix with the bits past its length cleared.
    fn canonical(self) -> Prefix {
        Prefix { addr: mask(self.addr, self.len), len: self.len }
    }

    fn contains(self, addr: IpAddr) -> bool {
        self.addr.is_ipv4() == addr.is_ipv4() && mask(addr, self.len) == self.canonical().addr
    }
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
                let mut s = shared.lock().unwrap();
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
                    let mut s = shared.lock().unwrap();
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
                    if let Some(prefix) = table.by_port.get(&i)
                        && cx.observed()
                    {
                        cx.graph().note("route_removed", format!("{}/{}: its interface closed", prefix.addr, prefix.len), None);
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
            let mut s = self.0.lock().unwrap();
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
            let mut s = self.shared.lock().unwrap();
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
            let mut s = self.shared.lock().unwrap();
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
/// Unlike [`router`], a LAN floods IPv4 broadcast and multicast packets to
/// every other member. Unicast packets go only to the member registered for
/// their destination address. The packets themselves are unchanged: the LAN
/// does not lower their TTL or hop limit.
///
/// This is useful for virtual machines attached through
/// `fictionet attach --type tap`. Attach answers each VM's ARP locally and
/// hands the LAN its IP packets, so machines configured for the same subnet
/// can communicate even though every VM has a point-to-point attachment. IP
/// broadcasts such as NetBIOS Name Service and LLMNR still reach the other
/// members. Ethernet-only traffic, including ARP, does not reach a world and
/// is outside this LAN.
///
/// Add members with [`Lan::add`]. An address may have one member; adding it
/// again replaces and closes the old interface. The task stops when every
/// member has disconnected and the last handle has been dropped.
#[track_caller]
pub fn lan(cx: &Cx, subnet: Prefix) -> Lan {
    let subnet = subnet.canonical();
    let shared = Arc::new(Mutex::new(LanShared {
        adds: Vec::new(),
        handles_gone: false,
        stopped: false,
        waker: None,
    }));
    let lan = Lan { handle: Arc::new(LanHandle { subnet, shared: shared.clone() }) };
    cx.spawn_as(|| "lan".into(), move |cx| async move {
        let _stopped = LanStopped(shared.clone());
        let mut ports = Ports::new(Vec::new());
        let mut by_addr = HashMap::<IpAddr, usize>::new();
        let mut by_port = HashMap::<usize, IpAddr>::new();
        let mut handles_gone = false;
        loop {
            let (adds, gone) = {
                let mut s = shared.lock().unwrap();
                (std::mem::take(&mut s.adds), s.handles_gone)
            };
            handles_gone = handles_gone || gone;
            for (addr, interface) in adds {
                if let Some(link) = interface.observe_link() {
                    cx.graph().label(&link.0, addr.to_string());
                }
                match by_addr.get(&addr).copied() {
                    Some(i) => ports.replace(i, interface),
                    None => {
                        let i = ports.add(interface);
                        by_addr.insert(addr, i);
                        by_port.insert(i, addr);
                    }
                }
            }
            if by_addr.is_empty() && handles_gone {
                return Ok(());
            }
            match ports
                .next(&cx, None, |task| {
                    let mut s = shared.lock().unwrap();
                    if !s.adds.is_empty() || (s.handles_gone && !handles_gone) {
                        return Poll::Ready(());
                    }
                    match &s.waker {
                        Some(w) if w.will_wake(task.waker()) => {}
                        _ => s.waker = Some(task.waker().clone()),
                    }
                    Poll::Pending
                })
                .await
            {
                Event::Packet(from, packet) => {
                    let Some(dst) = wire::destination(&packet.0) else { continue };
                    if lan_group_destination(subnet, dst) {
                        let mut recipients = 0;
                        for i in by_addr.values().copied().filter(|&i| i != from) {
                            ports.send(i, packet.clone());
                            recipients += 1;
                        }
                        ports.spend(recipients);
                    } else if let Some(&to) = by_addr.get(&dst) {
                        ports.send(to, packet);
                    }
                }
                Event::Closed(i) => {
                    if let Some(addr) = by_port.remove(&i) {
                        by_addr.remove(&addr);
                        if cx.observed() {
                            cx.graph().note("lan_member_removed", format!("{addr}: its interface closed"), None);
                        }
                    }
                }
                Event::Extra | Event::Timer => {}
                Event::Cancelled => return Ok(()),
            }
        }
    });
    lan
}

/// Whether `dst` is delivered to every other member of `subnet`.
fn lan_group_destination(subnet: Prefix, dst: IpAddr) -> bool {
    match (subnet.addr, dst) {
        (IpAddr::V4(network), IpAddr::V4(dst)) => {
            if dst.is_multicast() || dst == Ipv4Addr::BROADCAST {
                return true;
            }
            if subnet.len >= 31 {
                return false;
            }
            let host = u32::MAX >> subnet.len;
            dst == Ipv4Addr::from(u32::from(network) | host)
        }
        (IpAddr::V6(_), IpAddr::V6(dst)) => dst.is_multicast(),
        _ => false,
    }
}

struct LanShared {
    adds: Vec<(IpAddr, Box<dyn Interface>)>,
    handles_gone: bool,
    stopped: bool,
    waker: Option<Waker>,
}

struct LanStopped(Arc<Mutex<LanShared>>);

impl Drop for LanStopped {
    fn drop(&mut self) {
        let adds = {
            let mut s = self.0.lock().unwrap();
            s.stopped = true;
            std::mem::take(&mut s.adds)
        };
        drop(adds);
    }
}

struct LanHandle {
    subnet: Prefix,
    shared: Arc<Mutex<LanShared>>,
}

impl Drop for LanHandle {
    fn drop(&mut self) {
        let waker = {
            let mut s = self.shared.lock().unwrap();
            s.handles_gone = true;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// A handle to a running IP [`lan`].
///
/// Clones share the same LAN. Dropping a handle does not disconnect members.
/// Once every handle has gone, the LAN stops after its last member closes.
#[derive(Clone)]
pub struct Lan {
    handle: Arc<LanHandle>,
}

impl Lan {
    /// Adds one member at `addr`.
    ///
    /// `addr` must belong to the LAN's subnet and use the same address
    /// family. Adding an address already present replaces and closes its old
    /// interface. If the LAN has stopped, `interface` is dropped.
    pub fn add(&self, addr: IpAddr, interface: Box<dyn Interface>) -> Result<(), Error> {
        if !self.handle.subnet.contains(addr) {
            return Err(format!(
                "{addr} is outside LAN subnet {}/{}",
                self.handle.subnet.addr, self.handle.subnet.len
            )
            .into());
        }
        let waker = {
            let mut s = self.handle.shared.lock().unwrap();
            if s.stopped {
                drop(s);
                drop(interface);
                return Ok(());
            }
            s.adds.push((addr, interface));
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }
}
