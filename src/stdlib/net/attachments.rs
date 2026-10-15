use super::addresses::Bind;
use super::{Machine, PROTO_TCP, PROTO_UDP, Shared, host_prefix, link};
use fictionet::events::{ConnInfo, Event, Fields, Level, Sandbox, opt as jopt};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::dhcp;
use fictionet::stdlib::ip::{Header, Intake, Reassembly};
use fictionet::stdlib::ports::{self, Ports};
use fictionet::stdlib::serve::{Budget, Counted};
use fictionet::stdlib::{ip, udp};
use fictionet::sync::Mutex;
use fictionet::{Attachment, Cx, Interface, Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;

/// What events need to name sandboxes.
pub(super) struct Hooks {
    /// The sandbox that last bound each address. An entry stays after its
    /// sandbox detaches, until another binds the address, so packets and
    /// connections still on their way name the sandbox that sent them.
    pub(super) by_addr: Mutex<HashMap<IpAddr, Sandbox>>,
    /// The last connection number given out.
    pub(super) conns: AtomicU64,
    /// The sandboxes attached now, by id, each with its budget.
    pub(super) attached: Mutex<HashMap<u64, Budget>>,
}

impl Hooks {
    pub(super) fn record(&self, fcx: &Cx, conn: &ConnInfo, event: Event) {
        fcx.record(event.conn(conn));
    }

    /// Records a `net.blocked` event, with its detail, as a repeat: a
    /// flood of them is counted, not kept one by one.
    pub(super) fn blocked(&self, fcx: &Cx, conn: &ConnInfo, (event, detail): (Event, Fields)) {
        fcx.record_repeat(event.conn(conn), detail);
    }

    pub(super) fn sandbox_at(&self, addr: IpAddr) -> Sandbox {
        if let Some(s) = self.by_addr.lock().get(&addr) {
            return s.clone();
        }
        let (v4, v6) = match addr {
            IpAddr::V4(a) => (Some(a), None),
            IpAddr::V6(a) => (None, Some(a)),
        };
        Sandbox {
            id: 0,
            name: Arc::from(""),
            addr: v4,
            addr_v6: v6,
        }
    }

    pub(super) fn is_attached(&self, id: u64) -> bool {
        self.attached.lock().contains_key(&id)
    }

    /// The budget of the sandbox with id `id`, while it is attached.
    pub(super) fn budget(&self, id: u64) -> Option<Budget> {
        self.attached.lock().get(&id).cloned()
    }

    pub(super) fn next_conn(&self) -> u64 {
        self.conns.fetch_add(1, Ordering::Relaxed) + 1
    }
}

pub(super) fn sandbox_only(sandbox: Sandbox) -> ConnInfo {
    ConnInfo {
        sandbox: Some(sandbox),
        ..ConnInfo::default()
    }
}

impl Shared {
    /// A member sandbox attached: it joins its LAN at its address, with no
    /// filter, and events know it by that address. It detaches as any
    /// sandbox does when the LAN lets its interface go: when it closes,
    /// when another takes its address, or when it could not join.
    pub(super) fn join_lan(
        self: &Arc<Self>,
        fcx: &Cx,
        name: &str,
        lan: &str,
        addr: IpAddr,
        sandbox: Attachment,
    ) {
        let Some(seg) = self.lans.get(lan) else {
            return;
        };
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
        let joined = seg.lan.add(addr, Box::new(member), Some(me.clone()));
        let event = match joined {
            Ok(()) => Event::new("net", "attached")
                .summary(format!("sandbox {name} joined LAN {lan} at {addr}")),
            Err(e) => Event::new("net", "error")
                .level(Level::Notice)
                .summary(format!("sandbox {name} could not join LAN {lan}: {e}"))
                .field("error", e.to_string()),
        };
        hooks.record(
            fcx,
            &sandbox_only(me),
            event.field("lan", lan).field("addr", addr.to_string()),
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
    shared: Arc<Shared>,
    owner: u64,
    fcx: Cx,
    name: Arc<str>,
    /// A LAN member's address. A filtered sandbox's are its leases.
    fixed: Option<IpAddr>,
}

impl Attached {
    fn new(shared: &Arc<Shared>, fcx: &Cx, name: Arc<str>, fixed: Option<IpAddr>) -> Attached {
        let owner = shared.leases.lock().new_owner();
        shared
            .hooks
            .attached
            .lock()
            .insert(owner, Budget::new(shared.limits.sandbox_budget));
        Attached {
            shared: shared.clone(),
            owner,
            fcx: fcx.clone(),
            name,
            fixed,
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        let shared = &self.shared;
        shared.hooks.attached.lock().remove(&self.owner);
        let (bound, bound6) = match self.fixed {
            Some(IpAddr::V4(a)) => (Some(a), None),
            Some(IpAddr::V6(a)) => (None, Some(a)),
            None => {
                let leases = shared.leases.lock();
                let v4 = leases
                    .of(self.owner)
                    .and_then(|(a, bound)| bound.then_some(a));
                (v4, leases.by_owner6.get(&self.owner).copied())
            }
        };
        let addrs: Vec<IpAddr> = bound
            .map(IpAddr::V4)
            .into_iter()
            .chain(bound6.map(IpAddr::V6))
            .collect();
        if !addrs.is_empty() {
            let machines: Vec<Arc<Machine>> =
                shared.world.lock().machines.values().cloned().collect();
            for m in machines {
                for a in &addrs {
                    m.tcp.abort_peer(*a);
                }
            }
            for tcp in shared.gateway_tcp.lock().iter() {
                for a in &addrs {
                    tcp.abort_peer(*a);
                }
            }
        }
        shared.leases.lock().release_all(self.owner);
        let sandbox = Sandbox {
            id: self.owner,
            name: self.name.clone(),
            addr: bound,
            addr_v6: bound6,
        };
        let event =
            Event::new("net", "detached").summary(format!("sandbox {} detached", self.name));
        shared
            .hooks
            .record(&self.fcx, &sandbox_only(sandbox), event);
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

    fn observe_link(&self) -> Option<fictionet::observe::LinkHandle> {
        self.sandbox.observe_link()
    }
}

/// One sandbox's filter, between its attachment and the router.
pub(super) async fn filter(fcx: Cx, sandbox: Attachment, shared: Arc<Shared>) -> fictionet::Result {
    let name: Arc<str> = Arc::from(sandbox.name());
    let attached = Attached::new(&shared, &fcx, name.clone(), None);
    let mut f = Filter {
        shared: shared.clone(),
        owner: attached.owner,
        name,
        ports: Ports::new(vec![Box::new(sandbox) as Box<dyn Interface>]),
        bound: None,
        bound6: None,
        route4: None,
        route6: None,
        reassembly: Reassembly::default(),
    };
    let event = Event::new("net", "attached").summary(format!("sandbox {} attached", f.name));
    shared.hooks.record(&fcx, &sandbox_only(f.me()), event);
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

/// Why the network dropped or refused a packet from a sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockedWhy {
    /// Its source was not the sandbox's address, or the static address it
    /// tried to bind was not free. Dropped.
    NotItsAddress,
    /// It was for another sandbox's address. Dropped.
    OtherSandbox,
    /// It was for a broadcast, multicast or unspecified address, and was
    /// not DHCP. Dropped.
    Broadcast,
    /// It was IPv6, on a network with IPv6 off. Dropped.
    Ipv6,
    /// It was not an IP packet, or its header was broken. Dropped.
    Malformed,
    /// No machine has its destination: answered "host unreachable".
    NoRoute,
    /// Its destination port is closed: TCP gets a RST, UDP "port
    /// unreachable".
    ClosedPort,
    /// A new TCP connection past the network's limit per peer address, or past
    /// a service's cap. Reset.
    TooManyConnections,
}

impl BlockedWhy {
    /// The name in the `why` field of a `net.blocked` event: the variant's
    /// name, as `NotItsAddress`.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockedWhy::NotItsAddress => "NotItsAddress",
            BlockedWhy::OtherSandbox => "OtherSandbox",
            BlockedWhy::Broadcast => "Broadcast",
            BlockedWhy::Ipv6 => "Ipv6",
            BlockedWhy::Malformed => "Malformed",
            BlockedWhy::NoRoute => "NoRoute",
            BlockedWhy::ClosedPort => "ClosedPort",
            BlockedWhy::TooManyConnections => "TooManyConnections",
        }
    }
}

/// Counts an accepted connection or records why the connection limit refused it.
pub fn connection_limit(
    fcx: &Cx,
    info: &ConnInfo,
    open: &Arc<AtomicUsize>,
    max: usize,
) -> Option<Counted> {
    let guard = Counted::enter(open, max);
    if guard.is_none() {
        let (src, dst) = (info.peer, info.local);
        let event = blocked_event(
            BlockedWhy::TooManyConnections,
            Some(PROTO_TCP),
            src.map(|a| a.ip()),
            dst.map(|a| a.ip()),
        );
        let conn = ConnInfo {
            sandbox: info.sandbox.clone(),
            ..ConnInfo::default()
        };
        fcx.record_repeat(event.conn(&conn), port_detail(dst.map(|a| a.port())));
    }
    guard
}

/// A `net.blocked` event. The destination port goes in its detail
/// ([`port_detail`]), since a scan changes it with every packet.
pub(super) fn blocked_event(
    why: BlockedWhy,
    protocol: Option<u8>,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
) -> Event {
    Event::new("net", "blocked")
        .level(Level::Notice)
        .summary(format!(
            "blocked {}: {} -> {}",
            why.as_str(),
            src.map_or("-".into(), |a| a.to_string()),
            dst.map_or("-".into(), |a| a.to_string())
        ))
        .field("why", why.as_str())
        .field("protocol", jopt(protocol.map(u32::from)))
        .field("src", jopt(src.map(|a| a.to_string())))
        .field("dst", jopt(dst.map(|a| a.to_string())))
}

/// The detail of a `net.blocked` event: its destination port.
pub(super) fn port_detail(port: Option<u16>) -> Fields {
    Fields::new().with("dst_port", jopt(port.map(u32::from)))
}

/// The event for a blocked packet, and its detail.
fn blocked(why: BlockedWhy, p: &[u8]) -> (Event, Fields) {
    match Header::parse_truncated(p) {
        Some(h) => (
            blocked_event(why, Some(h.protocol), Some(h.src), Some(h.dst)),
            port_detail(h.dst_port(p)),
        ),
        None => (blocked_event(why, None, None, None), port_detail(None)),
    }
}

struct Filter {
    shared: Arc<Shared>,
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

    fn block(&self, fcx: &Cx, why: BlockedWhy, packet: &[u8]) {
        self.shared
            .hooks
            .blocked(fcx, &sandbox_only(self.me()), blocked(why, packet));
    }

    fn bound_now(&mut self, fcx: &Cx, addr: IpAddr, by_dhcp: bool) {
        let (router_side, mine) = link();
        self.shared
            .router
            .add(host_prefix(addr), Box::new(router_side));
        let port = self.ports.add(Box::new(mine));
        match addr {
            IpAddr::V4(a) => (self.bound, self.route4) = (Some(a), Some(port)),
            IpAddr::V6(a) => (self.bound6, self.route6) = (Some(a), Some(port)),
        }
        let sandbox = self.me();
        let mut by_addr = self.shared.hooks.by_addr.lock();
        for a in self
            .bound
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.bound6.map(IpAddr::V6))
        {
            by_addr.insert(a, sandbox.clone());
        }
        drop(by_addr);
        let event = Event::new("net", "bound")
            .summary(format!("sandbox {} bound {addr}", self.name))
            .field("by_dhcp", by_dhcp)
            .field("addr", addr.to_string());
        self.shared.hooks.record(fcx, &sandbox_only(sandbox), event);
    }

    fn sent_v4(&mut self, fcx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let gateway = shared.subnet.gateway;
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv4()) else {
            self.block(fcx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else {
            return;
        };
        if let Some(message) = to_dhcp_server(&packet.0, &h, gateway) {
            let Some(message) = message else { return };
            let inform_first = self.bound.is_none()
                && message.message_type() == Some(dhcp::INFORM)
                && shared.may_bind(self.owner, src);
            if !(src.is_unspecified() || Some(src) == self.bound || inform_first) {
                self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            let (reply, new) = shared.dhcp(self.owner, src, &message);
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
                self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind(self.owner, src) != Bind::New {
                    self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(fcx, src.into(), false);
            }
        }
        if dst.is_broadcast() || dst.is_multicast() || dst.is_unspecified() {
            self.block(fcx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        if shared.subnet.contains(dst) && dst != gateway {
            self.block(fcx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(fcx, self.route4, packet);
    }

    fn sent_v6(&mut self, fcx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let Some(subnet) = shared.subnet6 else {
            self.block(fcx, BlockedWhy::Ipv6, &packet.0);
            return;
        };
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv6()) else {
            self.block(fcx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (h.src, h.dst) else {
            return;
        };
        if dst.is_multicast() || dst.is_unspecified() {
            self.block(fcx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        match self.bound6 {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind6(self.owner, src) != Bind::New {
                    self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(fcx, src.into(), false);
            }
        }
        if subnet.contains(dst) && dst != subnet.gateway {
            self.block(fcx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(fcx, self.route6, packet);
    }

    fn forward(&mut self, fcx: &Cx, route: Option<usize>, packet: Packet) {
        let packet = match self.reassembly.push(packet, fcx.now()) {
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
        if let Some(why) = self.shared.refused(&packet.0) {
            self.block(fcx, why, &packet.0);
        }
        if let Some(port) = route {
            self.ports.send(port, packet);
        }
    }
}

impl Shared {
    /// Whether `dst` is the gateway, or a LAN's DNS address.
    fn is_gateway(&self, dst: IpAddr) -> bool {
        let gateway = match dst {
            IpAddr::V4(a) => a == self.subnet.gateway,
            IpAddr::V6(a) => self.subnet6.is_some_and(|s| a == s.gateway),
        };
        gateway || self.lans.values().any(|l| l.dns == dst)
    }

    /// Whether `p` is for the gateway or a machine.
    fn is_host(&self, p: &[u8]) -> bool {
        let Some(dst) = ip::destination(p) else {
            return false;
        };
        self.is_gateway(dst) || self.world.lock().machines.contains_key(&dst)
    }

    /// Why the network will refuse `p`: no machine has its address, or its
    /// port is not served there. `None` if it will be delivered.
    fn refused(&self, p: &[u8]) -> Option<BlockedWhy> {
        let dst = ip::destination(p)?;
        let closed = |open: &dyn Fn(u8, u16) -> bool| answered_closed(p, open);
        if self.is_gateway(dst) {
            return closed(&|_, p| p == 53).then_some(BlockedWhy::ClosedPort);
        }
        let machine = self.world.lock().machines.get(&dst).cloned();
        match machine {
            Some(m) => closed(&|proto, p| {
                if proto == PROTO_TCP {
                    m.serves_tcp(p)
                } else {
                    m.serves_udp(p)
                }
            })
            .then_some(BlockedWhy::ClosedPort),
            // A trusted sandbox's prefix, or a LAN, which reports its own
            // drops.
            None if self
                .fixed
                .iter()
                .chain(self.lans.values().map(|l| &l.prefix))
                .any(|p| p.contains(dst)) =>
            {
                None
            }
            None => Some(BlockedWhy::NoRoute),
        }
    }
}

/// Whether `p`, a whole TCP or UDP packet, is for a port that `open` says
/// is closed, and will be answered as such: it is not a TCP RST, and its
/// checksum is good. The port is looked up first, so only a packet for a
/// closed port has its checksum checked.
pub(super) fn answered_closed(p: &[u8], open: impl Fn(u8, u16) -> bool) -> bool {
    let Some(h) = Header::parse_whole(p) else {
        return false;
    };
    if !matches!(h.protocol, PROTO_TCP | PROTO_UDP) {
        return false;
    }
    let t = h.payload(p);
    if t.len() < 8 || open(h.protocol, u16::from_be_bytes([t[2], t[3]])) {
        return false;
    }
    if h.protocol == PROTO_TCP && t.get(13).is_some_and(|flags| flags & 0x04 != 0) {
        return false;
    }
    match h.protocol {
        PROTO_UDP => udp::Datagram::parse(t).is_some_and(|u| u.checksum_ok(h.src, h.dst)),
        _ => ip::transport_checksum(h.src, h.dst, h.protocol, t) == 0,
    }
}
