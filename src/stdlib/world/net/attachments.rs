use super::addresses::{Bind, Bindings};
use super::hosts::Machines;
use super::{PROTO_UDP, host_prefix, link};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ip::{Header, Intake, Reassembly};
use fictionet::stdlib::network::ports::{self, Ports};
use fictionet::stdlib::network::route::{Lan, Prefix, Router};
use fictionet::stdlib::network::{ip, udp};
use fictionet::stdlib::protocols::dhcp;
use fictionet::stdlib::services::serve::{Budget, Sandbox};
use fictionet::sync::Mutex;
use fictionet::{Attachment, Cx, Interface, Packet};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

/// Sandbox addresses, connection numbering and admission budgets.
pub(super) struct Hooks {
    /// The sandbox that last bound each address. An entry stays after its
    /// sandbox detaches, until another binds the address, so packets and
    /// connections still on their way name the sandbox that sent them.
    pub(super) by_addr: Mutex<HashMap<IpAddr, Sandbox>>,
    /// Each route's prefix ([`Net::route`](super::Net::route)),
    /// with the sandbox that attached there last, which every address in
    /// the prefix that no sandbox binds comes from. One entry per prefix,
    /// kept after its sandbox detaches as `by_addr` keeps its own. A route
    /// keeps nothing per source address, so sources it forwards, spoofed
    /// ones included, leave nothing behind.
    pub(super) routes: Mutex<Vec<(Prefix, Sandbox)>>,
    /// The last connection number given out.
    pub(super) conns: AtomicU64,
    /// The sandboxes attached now, by id, each with its budget.
    pub(super) attached: Mutex<HashMap<u64, Option<Budget>>>,
}

impl Hooks {
    /// The sandbox that `addr` belongs to: the one that bound it, or else
    /// the route with the longest prefix that holds it. One with id 0 and
    /// no name if neither does.
    pub(super) fn sandbox_at(&self, addr: IpAddr) -> Sandbox {
        if let Some(s) = self.by_addr.lock().get(&addr) {
            return s.clone();
        }
        let (v4, v6) = match addr {
            IpAddr::V4(a) => (Some(a), None),
            IpAddr::V6(a) => (None, Some(a)),
        };
        let (id, name) = longest_route(&self.routes.lock(), addr)
            .map_or((0, Arc::from("")), |(_, s)| (s.id, s.name.clone()));
        Sandbox {
            id,
            name,
            addr: v4,
            addr_v6: v6,
        }
    }

    /// The budget of the sandbox with id `id`, while it is attached.
    pub(super) fn budget(&self, id: u64) -> Option<Budget> {
        self.attached.lock().get(&id).cloned().flatten()
    }

    pub(super) fn next_conn(&self) -> u64 {
        self.conns.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Attachment ownership, identity and routing, with transport cleanup supplied
/// by the network. It cannot resolve names or install host services.
pub(super) struct Context {
    pub(super) bindings: Bindings,
    pub(super) hooks: Arc<Hooks>,
    pub(super) sandbox_budget: usize,
    pub(super) router: Router<Box<dyn Interface>>,
    pub(super) destinations: Destinations,
    pub(super) abort_peers: Arc<PeerAbort>,
}

/// Resets every connection whose peer address the argument accepts.
pub(super) type PeerAbort = dyn Fn(&dyn Fn(IpAddr) -> bool) + Send + Sync;

/// Network destinations used for source validation and reassembly replies.
pub(super) struct Destinations {
    pub(super) gateways: Vec<IpAddr>,
    pub(super) trusted: Vec<Prefix>,
    pub(super) machines: Machines,
}

impl Context {
    /// Attributes traffic from a route at `prefixes`, and passes on only
    /// packets from sources the network routes back to it: see [`Routed`].
    pub(super) fn routed(self: &Arc<Self>, sandbox: Attachment, prefixes: Vec<Prefix>) -> Routed {
        let owner = self.bindings.new_owner();
        self.hooks.attached.lock().insert(owner, None);
        let me = Sandbox {
            id: owner,
            name: Arc::from(sandbox.name()),
            addr: None,
            addr_v6: None,
        };
        let mut routes = self.hooks.routes.lock();
        for &prefix in &prefixes {
            match routes.iter_mut().find(|(p, _)| *p == prefix) {
                Some((_, last)) => *last = me.clone(),
                None => routes.push((prefix, me.clone())),
            }
        }
        drop(routes);
        Routed {
            sandbox,
            context: self.clone(),
            owner,
            prefixes,
        }
    }

    /// A member sandbox attached: it joins its LAN at its address, with no
    /// filter. It detaches as any
    /// sandbox does when the LAN lets its interface go: when it closes,
    /// when another takes its address, or when it could not join.
    pub(super) fn join_lan(
        self: &Arc<Self>,
        fcx: &Cx,
        name: &str,
        _lan: &str,
        segment: &Lan<Box<dyn Interface>>,
        addr: IpAddr,
        sandbox: Attachment,
    ) {
        let attached = Arc::new(Attached::new(self, fcx, Arc::from(name), Some(addr)));
        let hooks = &self.hooks;
        let me = Sandbox {
            id: attached.owner,
            name: Arc::from(name),
            addr: if let IpAddr::V4(a) = addr {
                Some(a)
            } else {
                None
            },
            addr_v6: if let IpAddr::V6(a) = addr {
                Some(a)
            } else {
                None
            },
        };
        hooks.by_addr.lock().insert(addr, me.clone());
        let member = Member {
            sandbox,
            _attached: attached.clone(),
        };
        let _joined = segment.add(addr, Box::new(member));
    }
}

/// The route in `routes` with the longest prefix that holds `addr`, as the
/// router picks one.
fn longest_route(routes: &[(Prefix, Sandbox)], addr: IpAddr) -> Option<&(Prefix, Sandbox)> {
    routes
        .iter()
        .filter(|(p, _)| p.contains(addr))
        .max_by_key(|(p, _)| p.len)
}

/// Whether no router forwards from or to `addr`: an IPv4 address in
/// 0.0.0.0/8, 127.0.0.0/8 or 240.0.0.0/4 (which holds the limited
/// broadcast), or an IPv6 unspecified or loopback address, none of them
/// forwardable (RFC 6890), or a multicast address, which is never a
/// source (RFC 1122 section 3.2.1.3, RFC 4291 section 2.7).
fn martian(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let first = a.octets()[0];
            first == 0 || first == 127 || first >= 224
        }
        IpAddr::V6(a) => a.is_unspecified() || a.is_loopback() || a.is_multicast(),
    }
}

impl Context {
    /// Whether the network routes `addr` to the route at `prefix`: it is in
    /// `prefix`, it is no martian, and no subnet, gateway, machine or route
    /// with a longer prefix has it.
    fn routes_to(&self, prefix: Prefix, addr: IpAddr) -> bool {
        let bindings = &self.bindings;
        let destinations = &self.destinations;
        prefix.contains(addr)
            && !martian(addr)
            && !bindings.subnet.prefix.contains(addr)
            && !bindings.subnet6.is_some_and(|s| s.prefix.contains(addr))
            && !destinations.is_gateway(addr)
            && !destinations
                .trusted
                .iter()
                .any(|p| p.len > prefix.len && p.contains(addr))
            && !destinations.machines.contains(addr)
    }
}

/// A sandbox wired to the router at its prefixes
/// ([`Net::route`](super::Net::route)). It passes packets as they are and
/// keeps no state per source.
///
/// It passes on only packets from addresses the network routes back to
/// it, as a router with strict reverse-path forwarding does (RFC 3704
/// section 2.2). A route open to the internet carries packets with any
/// source but a martian one, such as a loopback, multicast or broadcast
/// address, which no router forwards. One that claims an address the
/// network has elsewhere, such as a sandbox's or a host's, is dropped too:
/// answers to it would go there.
pub(super) struct Routed {
    sandbox: Attachment,
    context: Arc<Context>,
    owner: u64,
    prefixes: Vec<Prefix>,
}

impl Interface for Routed {
    fn poll_recv(
        &mut self,
        fcx: &Cx,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Packet, fictionet::RecvError>> {
        loop {
            let packet = std::task::ready!(self.sandbox.poll_recv(fcx, cx))?;
            if ip::source(&packet.0).is_some_and(|src| {
                self.prefixes
                    .iter()
                    .any(|p| self.context.routes_to(*p, src))
            }) {
                return Poll::Ready(Ok(packet));
            }
        }
    }

    fn send(&mut self, packet: Packet) {
        self.sandbox.send(packet);
    }
}

impl Drop for Routed {
    /// Resets the connections of every peer the route's prefixes give this
    /// sandbox: addresses that no sandbox binds and no route with a longer
    /// prefix holds.
    fn drop(&mut self) {
        let hooks = &self.context.hooks;
        hooks.attached.lock().remove(&self.owner);
        // Copied first: the aborts ask about each peer with the endpoints
        // locked.
        let bound: HashSet<IpAddr> = hooks.by_addr.lock().keys().copied().collect();
        let routes = hooks.routes.lock().clone();
        let prefixes = &self.prefixes;
        (self.context.abort_peers)(&|peer| {
            !bound.contains(&peer)
                && longest_route(&routes, peer).is_some_and(|(p, _)| prefixes.contains(p))
        });
    }
}
/// A UDP packet with correct checksums.
pub(super) fn udp_packet(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    data: &[u8],
) -> Packet {
    let len = udp::encoded_len(src.into(), dst.into(), data.len())
        .expect("a DHCP reply fits one IPv4 packet");
    let mut u = vec![0; len];
    udp::encode(
        SocketAddr::new(src.into(), sport),
        SocketAddr::new(dst.into(), dport),
        data,
        &mut u,
    )
    .expect("a checked UDP length fits");
    ip::packet(src.into(), dst.into(), PROTO_UDP, &u)
}

/// If `packet` (with header `h`) is for the DHCP server (UDP port 67 at the
/// broadcast address or the gateway), its message, or `Some(None)` if
/// its UDP envelope or message is invalid. `None` for every other packet.
fn to_dhcp_server(packet: &[u8], h: &Header, gateway: Ipv4Addr) -> Option<Option<dhcp::Message>> {
    if h.protocol != PROTO_UDP || h.fragment.is_some() {
        return None;
    }
    let dst = h.dst;
    if dst != IpAddr::V4(Ipv4Addr::BROADCAST) && dst != IpAddr::V4(gateway) {
        return None;
    }
    let u = h.payload(packet);
    if u.len() < 4 || u16::from_be_bytes([u[2], u[3]]) != dhcp::SERVER_PORT {
        return None;
    }
    let Some(u) = udp::Datagram::parse(u) else {
        return Some(None);
    };
    if !u.checksum_ok(h.src, h.dst) {
        return Some(None);
    }
    Some(dhcp::Message::parse(u.payload()).ok())
}

/// One attachment's time on the network, the same for a sandbox behind a
/// filter and a LAN member. Made when it attaches, which gives it an id
/// and its budget. Dropped when it detaches, which resets its connections,
/// frees its addresses and its budget, and records `net.detached`.
struct Attached {
    context: Arc<Context>,
    owner: u64,
    name: Arc<str>,
    /// A LAN member's address. A filtered sandbox's are its leases.
    fixed: Option<IpAddr>,
}

impl Attached {
    fn new(context: &Arc<Context>, _fcx: &Cx, name: Arc<str>, fixed: Option<IpAddr>) -> Attached {
        let owner = context.bindings.new_owner();
        context
            .hooks
            .attached
            .lock()
            .insert(owner, Some(Budget::new(context.sandbox_budget)));
        Attached {
            context: context.clone(),
            owner,
            name,
            fixed,
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        let context = &self.context;
        context.hooks.attached.lock().remove(&self.owner);
        let (bound, bound6) = match self.fixed {
            Some(IpAddr::V4(a)) => (Some(a), None),
            Some(IpAddr::V6(a)) => (None, Some(a)),
            None => {
                let bound = context.bindings.bound(self.owner);
                (bound.v4, bound.v6)
            }
        };
        let addrs: Vec<IpAddr> = bound
            .map(IpAddr::V4)
            .into_iter()
            .chain(bound6.map(IpAddr::V6))
            .collect();
        if !addrs.is_empty() {
            (context.abort_peers)(&|peer| addrs.contains(&peer));
        }
        context.bindings.release(self.owner);
        let _sandbox = Sandbox {
            id: self.owner,
            name: self.name.clone(),
            addr: bound,
            addr_v6: bound6,
        };
    }
}

/// A LAN member's attachment, which holds its [`Attached`]: the member
/// detaches when the LAN drops this.
struct Member {
    sandbox: Attachment,
    _attached: Arc<Attached>,
}

impl Interface for Member {
    fn poll_recv(
        &mut self,
        fcx: &Cx,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Packet, fictionet::RecvError>> {
        self.sandbox.poll_recv(fcx, cx)
    }

    fn send(&mut self, packet: Packet) {
        self.sandbox.send(packet);
    }
}

/// One sandbox's filter, between its attachment and the router.
pub(super) async fn filter(
    fcx: Cx,
    sandbox: Attachment,
    context: Arc<Context>,
) -> fictionet::Result {
    let name: Arc<str> = Arc::from(sandbox.name());
    let attached = Attached::new(&context, &fcx, name.clone(), None);
    let mut f = Filter {
        context: context.clone(),
        owner: attached.owner,
        name,
        ports: Ports::new(vec![Box::new(sandbox) as Box<dyn Interface>]),
        bound: None,
        bound6: None,
        route4: None,
        route6: None,
        reassembly: Reassembly::default(),
    };

    // Detaches before the filter's links close.
    let _attached = attached;
    loop {
        let deadline = f.reassembly.next_expiry();
        match f.ports.next(&fcx, deadline, |_| Poll::Pending).await? {
            ports::Event::Packet(0, packet) => match ip::version(&packet.0) {
                Some(6) => f.sent_v6(&fcx, packet),
                _ => f.sent_v4(&fcx, packet),
            },
            ports::Event::Packet(_, packet) => f.ports.send(0, packet),
            ports::Event::Closed(_) => return Ok(()),
            ports::Event::Timer => f.reassembly.expire(fcx.now()),
            ports::Event::Extra => {}
        }
    }
}

struct Filter {
    context: Arc<Context>,
    owner: u64,
    name: Arc<str>,
    ports: Ports<Box<dyn Interface>>,
    bound: Option<Ipv4Addr>,
    bound6: Option<Ipv6Addr>,
    route4: Option<usize>,
    route6: Option<usize>,
    reassembly: Reassembly,
}

impl Filter {
    fn me(&self) -> Sandbox {
        Sandbox {
            id: self.owner,
            name: self.name.clone(),
            addr: self.bound,
            addr_v6: self.bound6,
        }
    }

    fn bound_now(&mut self, _fcx: &Cx, addr: IpAddr, _by_dhcp: bool) {
        let (router_side, mine) = link();
        self.context
            .router
            .add(host_prefix(addr), Box::new(router_side));
        let port = self.ports.add(Box::new(mine));
        match addr {
            IpAddr::V4(a) => (self.bound, self.route4) = (Some(a), Some(port)),
            IpAddr::V6(a) => (self.bound6, self.route6) = (Some(a), Some(port)),
        }
        let sandbox = self.me();
        let mut by_addr = self.context.hooks.by_addr.lock();
        for a in self
            .bound
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.bound6.map(IpAddr::V6))
        {
            by_addr.insert(a, sandbox.clone());
        }
        drop(by_addr);
    }

    fn sent_v4(&mut self, fcx: &Cx, packet: Packet) {
        let context = self.context.clone();
        let gateway = context.bindings.subnet.gateway;
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv4()) else {
            return;
        };
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else {
            return;
        };
        if let Some(message) = to_dhcp_server(&packet.0, &h, gateway) {
            let Some(message) = message else { return };
            let inform_first = self.bound.is_none()
                && message.message_type() == Some(dhcp::INFORM)
                && context.bindings.may_bind(self.owner, src);
            if !(src.is_unspecified() || Some(src) == self.bound || inform_first) {
                return;
            }
            let (reply, new) = context.bindings.dhcp(self.owner, src, &message);
            if let Some(a) = new {
                self.bound_now(fcx, a.into(), true);
            }
            if let Some(reply) = reply {
                self.ports.send(0, reply);
            }
            return;
        }
        match self.bound {
            Some(a) if a == src => {}
            Some(_) => {
                return;
            }
            None => {
                if context.bindings.bind(self.owner, src) != Bind::New {
                    return;
                }
                self.bound_now(fcx, src.into(), false);
            }
        }
        if dst.is_broadcast() || dst.is_multicast() || dst.is_unspecified() {
            return;
        }
        if context.bindings.subnet.contains(dst) && dst != gateway {
            return;
        }
        self.forward(fcx, self.route4, packet);
    }

    fn sent_v6(&mut self, fcx: &Cx, packet: Packet) {
        let context = self.context.clone();
        let Some(subnet) = context.bindings.subnet6 else {
            return;
        };
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv6()) else {
            return;
        };
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (h.src, h.dst) else {
            return;
        };
        if dst.is_multicast() || dst.is_unspecified() {
            return;
        }
        match self.bound6 {
            Some(a) if a == src => {}
            Some(_) => {
                return;
            }
            None => {
                if context.bindings.bind6(self.owner, src) != Bind::New {
                    return;
                }
                self.bound_now(fcx, src.into(), false);
            }
        }
        if subnet.contains(dst) && dst != subnet.gateway {
            return;
        }
        self.forward(fcx, self.route6, packet);
    }

    fn forward(&mut self, fcx: &Cx, route: Option<usize>, packet: Packet) {
        let packet = match self.reassembly.push(packet, fcx.now()) {
            Intake::Whole(p) => p,
            Intake::Waiting => return,
            Intake::Refused { packet, answer } => {
                if !self.context.destinations.is_host(&packet.0) {
                    packet
                } else {
                    if let Some(answer) = answer {
                        self.ports.send(0, answer);
                    }
                    return;
                }
            }
        };
        if let Some(port) = route {
            self.ports.send(port, packet);
        }
    }
}

impl Destinations {
    /// Whether `dst` is the gateway, or a LAN's DNS address.
    fn is_gateway(&self, dst: IpAddr) -> bool {
        self.gateways.contains(&dst)
    }

    /// Whether `p` is for the gateway or a machine.
    fn is_host(&self, p: &[u8]) -> bool {
        let Some(dst) = ip::destination(p) else {
            return false;
        };
        self.is_gateway(dst) || self.machines.contains(dst)
    }
}
