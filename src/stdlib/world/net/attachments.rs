use super::addresses::{Bind, Bindings};
use super::hosts::Machines;
use super::{PROTO_UDP, host_prefix, link};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::network::ip::{Header, Intake, Reassembly};
use fictionet::stdlib::network::ports::{self, Ports};
use fictionet::stdlib::network::route::{Lan, Prefix, Router};
use fictionet::stdlib::network::{ip, udp};
use fictionet::stdlib::protocols::dhcp;
use fictionet::sync::Mutex;
use fictionet::{Attachment, Cx, Interface, Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

/// A sandbox attached to a network.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sandbox {
    /// The attachment, numbered from 1 in the order sandboxes attached. A
    /// name and an address can be used again after a sandbox detaches; the
    /// id never is.
    pub id: u64,
    /// Its attachment's name.
    pub name: Arc<str>,
    /// Its IPv4 address, once bound.
    pub addr: Option<Ipv4Addr>,
    /// Its IPv6 address, once bound.
    pub addr_v6: Option<Ipv6Addr>,
}

/// Sandbox addresses, connection numbering and admission budgets.
pub(super) struct Hooks {
    pub(super) refused_observe: Option<super::OnRefused>,
    pub(super) tls_observe: Option<super::OnTls>,
    pub(super) attachment_observe: Option<super::OnAttachment>,
    pub(super) dns_observe: Option<super::OnDns>,

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
    /// Where the network has addresses other than at its routes, which
    /// decides what a route carries and so whose a source is.
    pub(super) destinations: Destinations,
}

impl Hooks {
    pub(super) fn refused(&self, fcx: &Cx, packet: &[u8], reason: super::Refusal) {
        let Some(observe) = &self.refused_observe else {
            return;
        };
        let Some(header) = Header::parse(packet) else {
            return;
        };
        let payload = header.payload(packet);
        let ports = matches!(header.protocol, 6 | 17)
            .then(|| payload.get(..4))
            .flatten();
        let conn = fictionet::stdlib::network::ConnInfo {
            sandbox: self.sandbox_of(header.src),
            peer: ports.map(|p| SocketAddr::new(header.src, u16::from_be_bytes([p[0], p[1]]))),
            local: ports.map(|p| SocketAddr::new(header.dst, u16::from_be_bytes([p[2], p[3]]))),
            transport: if header.protocol == 17 {
                fictionet::stdlib::network::Transport::Udp
            } else {
                fictionet::stdlib::network::Transport::Tcp
            },
            ..Default::default()
        };
        observe(&super::RefusedPacket {
            at: fcx.now(),
            conn,
            from: header.src,
            to: header.dst,
            protocol: header.protocol,
            reason,
        });
    }

    fn attachment(&self, fcx: &Cx, sandbox: Sandbox, change: super::AttachmentChange) {
        if let Some(observe) = &self.attachment_observe {
            observe(&super::AttachmentObservation {
                at: fcx.now(),
                sandbox,
                change,
            });
        }
    }

    /// The sandbox that bound the address, or the one at the route with
    /// the longest prefix that holds it, when the network routes the
    /// address there ([`Destinations::routes_to`]). `None` for an address
    /// the network has elsewhere: a machine's, a gateway's, or one of the
    /// sandboxes' subnet that no sandbox bound.
    pub(super) fn sandbox_of(&self, addr: IpAddr) -> Option<Sandbox> {
        if let Some(sandbox) = self.by_addr.lock().get(&addr).cloned() {
            return Some(sandbox);
        }
        let (prefix, mut sandbox) = {
            let routes = self.routes.lock();
            let (prefix, sandbox) = longest_route(&routes, addr)?;
            (*prefix, sandbox.clone())
        };
        if !self.destinations.routes_to(prefix, addr) {
            return None;
        }
        sandbox.addr = match addr {
            IpAddr::V4(a) => Some(a),
            _ => None,
        };
        sandbox.addr_v6 = match addr {
            IpAddr::V6(a) => Some(a),
            _ => None,
        };
        Some(sandbox)
    }

    /// The sandbox at the address, or an unnamed sandbox with id zero.
    pub(super) fn sandbox_at(&self, addr: IpAddr) -> Sandbox {
        self.sandbox_of(addr).unwrap_or_else(|| Sandbox {
            id: 0,
            name: Arc::from(""),
            addr: match addr {
                IpAddr::V4(a) => Some(a),
                _ => None,
            },
            addr_v6: match addr {
                IpAddr::V6(a) => Some(a),
                _ => None,
            },
        })
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
    pub(super) egress: Option<Arc<super::Egress>>,
    pub(super) router: Router<Box<dyn Interface>>,
    pub(super) abort_peers: Arc<PeerAbort>,
}

/// Resets every connection whose peer address the argument accepts.
pub(super) type PeerAbort = dyn Fn(&dyn Fn(IpAddr) -> bool) + Send + Sync;

/// Where the network has addresses other than at its routes: the
/// sandboxes' subnets, the gateways, the prefixes of the LANs and the
/// routes, and the machines. A route carries only sources the network has
/// nowhere else ([`routes_to`](Destinations::routes_to)), and a
/// reassembly's answers go to hosts.
pub(super) struct Destinations {
    pub(super) subnets: Vec<Prefix>,
    pub(super) gateways: Vec<IpAddr>,
    pub(super) trusted: Vec<Prefix>,
    pub(super) machines: Machines,
}

impl Context {
    /// Attributes traffic from a route at `prefixes`, and passes on only
    /// packets from sources the network routes back to it: see [`Routed`].
    pub(super) fn routed(
        self: &Arc<Self>,
        fcx: &Cx,
        sandbox: Attachment,
        prefixes: Vec<Prefix>,
    ) -> Routed {
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
        self.hooks
            .attachment(fcx, me, super::AttachmentChange::Attached);
        Routed {
            fcx: fcx.clone(),
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
    fcx: Cx,
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
            let destinations = &self.context.hooks.destinations;
            if ip::source(&packet).is_some_and(|src| {
                self.prefixes
                    .iter()
                    .any(|p| destinations.routes_to(*p, src))
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
    /// Resets the connections of every peer the route carried: the
    /// sources the network routes to it
    /// ([`Destinations::routes_to`]), as they are now.
    fn drop(&mut self) {
        let hooks = &self.context.hooks;
        hooks.attached.lock().remove(&self.owner);
        let sources = hooks
            .destinations
            .sources(std::mem::take(&mut self.prefixes));
        (self.context.abort_peers)(&sources);
        hooks.attachment(
            &self.fcx,
            Sandbox {
                id: self.owner,
                name: Arc::from(self.sandbox.name()),
                addr: None,
                addr_v6: None,
            },
            super::AttachmentChange::Detached,
        );
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
    fcx: Cx,
    context: Arc<Context>,
    owner: u64,
    name: Arc<str>,
    /// A LAN member's address. A filtered sandbox's are its leases.
    fixed: Option<IpAddr>,
}

impl Attached {
    fn new(context: &Arc<Context>, fcx: &Cx, name: Arc<str>, fixed: Option<IpAddr>) -> Attached {
        let owner = context.bindings.new_owner();
        context
            .hooks
            .attached
            .lock()
            .insert(owner, Some(Budget::new(context.sandbox_budget)));
        context.hooks.attachment(
            fcx,
            Sandbox {
                id: owner,
                name: name.clone(),
                addr: fixed.and_then(|addr| {
                    if let IpAddr::V4(addr) = addr {
                        Some(addr)
                    } else {
                        None
                    }
                }),
                addr_v6: fixed.and_then(|addr| {
                    if let IpAddr::V6(addr) = addr {
                        Some(addr)
                    } else {
                        None
                    }
                }),
            },
            super::AttachmentChange::Attached,
        );
        Attached {
            fcx: fcx.clone(),
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
        let sandbox = Sandbox {
            id: self.owner,
            name: self.name.clone(),
            addr: bound,
            addr_v6: bound6,
        };
        context
            .hooks
            .attachment(&self.fcx, sandbox, super::AttachmentChange::Detached);
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
            ports::Event::Packet(0, packet) => match ip::version(&packet) {
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

    fn bound_now(&mut self, fcx: &Cx, addr: IpAddr, by_dhcp: bool) {
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
        self.context
            .hooks
            .attachment(fcx, sandbox, super::AttachmentChange::Bound { by_dhcp });
    }

    fn sent_v4(&mut self, fcx: &Cx, packet: Packet) {
        let context = self.context.clone();
        let gateway = context.bindings.subnet.gateway;
        let Some(h) = Header::parse(&packet).filter(|h| h.src.is_ipv4()) else {
            return;
        };
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else {
            return;
        };
        if let Some(message) = to_dhcp_server(&packet, &h, gateway) {
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
        let Some(h) = Header::parse(&packet).filter(|h| h.src.is_ipv6()) else {
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
        let packet = match self.reassembly.push(packet.into_chunk(), fcx.now()) {
            Intake::Whole(p) => Packet::from_chunk(p),
            Intake::Waiting | Intake::Discarded => return,
            Intake::Refused { packet, answer } => {
                if !self.context.hooks.destinations.is_host(&packet) {
                    Packet::from_chunk(packet)
                } else {
                    if let Some(answer) = answer {
                        self.ports.send(0, Packet::from_chunk(answer));
                    }
                    return;
                }
            }
        };
        if let Some(allow) = &self.context.egress {
            let Some(header) = Header::parse_whole(&packet) else {
                return;
            };
            let gateway = header.dst == IpAddr::V4(self.context.bindings.subnet.gateway)
                || self
                    .context
                    .bindings
                    .subnet6
                    .is_some_and(|subnet| header.dst == IpAddr::V6(subnet.gateway));
            if !gateway
                && let Some(port) = header.dst_port(&packet)
                && !allow(SocketAddr::new(header.dst, port))
            {
                self.context
                    .hooks
                    .refused(fcx, &packet, super::Refusal::Policy);
                return;
            }
        }
        if let Some(port) = route {
            self.ports.send(port, packet);
        }
    }
}

impl Destinations {
    /// Whether the network routes `addr` to the route at `prefix`: it is in
    /// `prefix`, it is no martian, and no subnet, gateway, machine or route
    /// with a longer prefix has it.
    pub(super) fn routes_to(&self, prefix: Prefix, addr: IpAddr) -> bool {
        self.routes_to_among(prefix, addr, &|a| self.machines.contains(a))
    }

    /// [`routes_to`](Self::routes_to), with `machine` saying which
    /// addresses machines have: the machines now, or a copy of them.
    fn routes_to_among(
        &self,
        prefix: Prefix,
        addr: IpAddr,
        machine: &dyn Fn(IpAddr) -> bool,
    ) -> bool {
        prefix.contains(addr)
            && !martian(addr)
            && !self.subnets.iter().any(|s| s.contains(addr))
            && !self.is_gateway(addr)
            && !self
                .trusted
                .iter()
                .any(|p| p.len > prefix.len && p.contains(addr))
            && !machine(addr)
    }

    /// The sources a route at `prefixes` carries, decided against a copy
    /// of the machines' addresses taken now, for a caller that asks about
    /// many peers with the endpoints locked.
    pub(super) fn sources(&self, prefixes: Vec<Prefix>) -> impl Fn(IpAddr) -> bool + '_ {
        let machines = self.machines.addresses();
        move |addr| {
            prefixes
                .iter()
                .any(|p| self.routes_to_among(*p, addr, &|a| machines.contains(&a)))
        }
    }

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
