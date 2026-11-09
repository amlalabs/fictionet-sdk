//! The UDP layer: a machine's sockets over whole IP packets.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use fictionet::Entropy;
use fictionet::stdlib::layer::{
    Admit, ChildId, Chunk, CommandOf, Datagram, DatagramCommand, DatagramEvent, Datagrams, Env,
    EventOf, Layer, MessageCommand, MessageEvent, Messages, MuxEvent, MuxOp, PacketCommand,
    PacketEvent, Packets, Slots,
};
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::network::icmp;
use fictionet::stdlib::network::ip::{self, Fields, protocol};
use fictionet::stdlib::network::packet::{IpPacket, Scope, Sort};
use fictionet::stdlib::network::transport::{Request, Udp, UdpBound, UdpControl, UdpNotice};

use super::wire;
use super::{PortZero, Settings};

/// How many bytes of datagrams a socket holds before it drops new ones,
/// like a full socket buffer, counting [`DATAGRAM_COST`] more for each.
pub(super) const QUEUE: usize = 1 << 20;
/// What a queued datagram costs beyond its bytes: its sender's address and
/// its place in the queue. So a flood of tiny datagrams is bounded too: a
/// socket holds at most `QUEUE / DATAGRAM_COST` of them.
pub(super) const DATAGRAM_COST: usize = 64;
/// How many datagrams each socket may have handed to the layer and not yet
/// seen go down: the command credit a socket starts with.
const SEND_WINDOW: u64 = 64;
/// How many packets the layer holds for the IP layer below, and how many
/// control events for the port above, before it refuses input.
const HELD: usize = 64;
/// The first ephemeral port, as IANA suggests (RFC 6335).
const EPHEMERAL: u16 = 49152;
/// The most sockets at once: one per port.
const SOCKETS: usize = 1 << 16;

/// A machine's UDP as a [layer](fictionet::stdlib::layer): whole IP packets
/// below, and above, one child per bound socket ([`Udp`]).
///
/// The layer above binds with [`UdpControl::Bind`]. Each socket it binds
/// opens a child with a [`UdpBound`] that says which address and port it
/// has, and carries [`Datagrams`] with the peer's address: every datagram
/// whole, empty ones included. A child's datagram goes out in one IP
/// packet from the socket's port; one that does not fit a single packet,
/// or names an address of the other IP version, is lost, as UDP datagrams
/// are. Datagrams are never split into fragments. A child's
/// [`DatagramCommand::End`] or its handle's close frees the port.
///
/// The packets it takes in are the ones the IP layer sorts to UDP, and
/// only [checked](IpPacket::is_checked) ones of its own network, the
/// [`Scope`] it was made with: observed copies and packets of other
/// networks are dropped. Of the packets it takes in, it keeps UDP datagrams
/// sent to its address, and to the multicast
/// groups joined with [`UdpControl::Join`], and drops the rest, ICMP errors
/// about datagrams it sent included. A datagram with a bad checksum is
/// dropped. So is one over IPv6 whose checksum field is zero: that means
/// "no checksum" only over IPv4, and RFC 8200 forbids it over IPv6. A UDP
/// length below eight bytes or beyond the IP payload is dropped. Bytes
/// after the declared UDP length are ignored, including for checksums.
///
/// A datagram for its address and a port with no socket gets an ICMP "port
/// unreachable" answer (RFC 1122 section 4.1.3.1, RFC 4443), built with the
/// layer's [`icmp::Options`], and the port above hears
/// [`UdpNotice::Refused`]. [`Settings::port_zero`] can make port 0 silent;
/// the notice still goes up. A datagram for a group goes unanswered.
///
/// Each socket holds at most 1 MiB of datagrams the port above has not
/// taken, counting 64 bytes more for each. A datagram past that is dropped,
/// as with a full socket buffer, and reported ([`UdpReport::Dropped`]).
/// Each one it keeps is charged, its bytes and those 64 more, to the
/// layer's [budget](Env::budget) before it is
/// copied, and the charge goes up with it; one the budget has no room for
/// is dropped and reported the same way. When the packets below end, each
/// socket's [`DatagramEvent::Ended`] follows the datagrams it still holds.
///
/// A socket's datagrams go up within the credit the port above grants, one
/// unit each. A socket starts with 64 units of credit for what it sends,
/// and gets each back once the packet it made has gone down. The layer
/// holds at most 64 packets for the layer below and 64 control events for
/// the port above, and refuses input, changing nothing, until those are
/// taken. Those packets are outside the budget, as the IP layer's are: a
/// budgeted carrier below reserves them.
pub struct UdpLayer {
    scope: Scope,
    addr: IpAddr,
    settings: Settings,
    icmp: icmp::Options,
    ip_id: u16,
    next_port: u16,
    groups: Vec<IpAddr>,
    sockets: Slots<Socket>,
    ports: BTreeMap<u16, ChildId>,
    /// Sockets with something for the port above, in turn.
    ready: VecDeque<ChildId>,
    /// Opened children and control notices, in order.
    up: VecDeque<MuxEvent<Datagrams<SocketAddr>, Messages<UdpNotice, UdpControl>, UdpBound>>,
    /// Children closed by their own end, to say so. Each socket ends once,
    /// so this holds at most one per socket.
    closed: VecDeque<ChildId>,
    /// Packets for the layer below, with the socket each one's credit goes
    /// back to.
    down: VecDeque<(Chunk, Option<ChildId>)>,
    input_ended: bool,
}

/// One bound socket.
struct Socket {
    port: u16,
    queue: VecDeque<Datagram<SocketAddr>>,
    /// What `queue` holds, counted as for [`QUEUE`].
    bytes: usize,
    /// Credit the port above granted for this socket's datagrams.
    granted: u64,
    /// Credit the port above has for this socket's commands.
    credit: u64,
    /// Command credit to give back.
    owed: u64,
    /// The packets below ended, so the socket ends after its queue.
    ending: bool,
    /// Whether [`DatagramEvent::Ended`] has gone up.
    ended: bool,
    /// Whether the socket is in [`UdpLayer::ready`].
    queued: bool,
}

impl Socket {
    /// Whether the socket has an event the port above may take now.
    fn has_event(&self) -> bool {
        self.owed > 0
            || (self.granted > 0 && !self.queue.is_empty())
            || (self.ending && !self.ended && self.queue.is_empty())
    }
}

/// What [`UdpLayer`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpReport {
    /// A datagram for a bound socket was dropped.
    Dropped {
        /// The socket.
        local: SocketAddr,
        /// Who sent it.
        peer: SocketAddr,
        /// Why.
        cause: Dropped,
    },
}

/// Why [`UdpLayer`] dropped a datagram for a bound socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// The socket's queue was full.
    QueueFull,
    /// The budget had no room for it.
    Budget,
}

/// The port above sent a socket a command beyond the credit the layer
/// granted it: a broken port above, so the whole layer stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overrun(pub ChildId);

impl core::fmt::Display for Overrun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a UDP socket sent more than its credit")
    }
}

impl core::error::Error for Overrun {}

impl UdpLayer {
    /// The UDP of a machine with address `addr` on network `scope`, with
    /// the standards' [`Settings`] and default [`icmp::Options`]. Draws the
    /// first IP identification from `entropy`.
    pub fn new(scope: Scope, addr: IpAddr, entropy: &dyn Entropy) -> UdpLayer {
        UdpLayer {
            scope,
            addr,
            settings: Settings::default(),
            icmp: icmp::Options::default(),
            ip_id: entropy.random_u64() as u16,
            next_port: EPHEMERAL,
            groups: Vec::new(),
            sockets: Slots::new(SOCKETS),
            ports: BTreeMap::new(),
            ready: VecDeque::new(),
            up: VecDeque::new(),
            closed: VecDeque::new(),
            down: VecDeque::new(),
            input_ended: false,
        }
    }

    /// The machine's address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Sets the choices a world makes for this machine's UDP.
    pub fn set_settings(&mut self, settings: Settings) {
        self.settings = settings;
    }

    /// Sets the header choices for its ICMP errors.
    pub fn set_icmp_options(&mut self, options: icmp::Options) {
        self.icmp = options;
    }

    /// Whether a socket is bound on `port`.
    pub fn is_bound(&self, port: u16) -> bool {
        self.ports.contains_key(&port)
    }

    /// Puts socket `id` in turn if it has something for the port above.
    fn wake(&mut self, id: ChildId) {
        if let Some(socket) = self.sockets.get_mut(id)
            && !socket.queued
            && socket.has_event()
        {
            socket.queued = true;
            self.ready.push_back(id);
        }
    }

    /// A free ephemeral port, from 49152 through 65535, taken in turn.
    fn ephemeral(&mut self) -> Option<u16> {
        for _ in EPHEMERAL..=u16::MAX {
            let candidate = self.next_port;
            self.next_port = if candidate == u16::MAX {
                EPHEMERAL
            } else {
                candidate + 1
            };
            if !self.ports.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn bind(&mut self, request: Request, port: u16) {
        let bound = if port == 0 {
            self.ephemeral()
        } else {
            Some(port).filter(|port| !self.ports.contains_key(port))
        };
        let socket = bound.map(|port| Socket {
            port,
            queue: VecDeque::new(),
            bytes: 0,
            granted: 0,
            credit: 0,
            owed: SEND_WINDOW,
            ending: self.input_ended,
            ended: false,
            queued: false,
        });
        let Some(child) = socket.and_then(|socket| self.sockets.insert(socket).ok()) else {
            self.notice(UdpNotice::BindFailed { request, port });
            return;
        };
        let id = child.id();
        let local = SocketAddr::new(self.addr, self.sockets.get(id).expect("just bound").port);
        self.ports.insert(local.port(), id);
        self.up.push_back(MuxEvent::Opened(
            child,
            UdpBound {
                scope: self.scope,
                local,
                request,
            },
            1,
        ));
        self.wake(id);
    }

    fn notice(&mut self, notice: UdpNotice) {
        self.up
            .push_back(MuxEvent::Control(MessageEvent::Message(notice)));
    }

    /// Frees socket `id`'s port, dropping what it holds.
    fn close(&mut self, id: ChildId) -> bool {
        let Some(socket) = self.sockets.remove(id) else {
            return false;
        };
        self.ports.remove(&socket.port);
        true
    }

    /// Builds the packet for one datagram a socket sends, or `None` if it
    /// cannot go in one IP packet to that address.
    fn packet(&mut self, port: u16, payload: &[u8], to: SocketAddr) -> Option<Chunk> {
        let from = SocketAddr::new(self.addr, port);
        let len = wire::encoded_len(self.addr, to.ip(), payload.len()).ok()?;
        let mut udp = vec![0; len];
        wire::encode(from, to, payload, &mut udp).expect("a checked UDP length fits");
        self.ip_id = self.ip_id.wrapping_add(1);
        let packet = ip::packet_with(
            self.addr,
            to.ip(),
            protocol::UDP,
            Fields {
                id: self.ip_id,
                ..Fields::default()
            },
            &udp,
        );
        Some(Chunk::new(packet.0))
    }

    /// Takes in one packet the IP layer sorted to UDP.
    fn take_in(&mut self, env: &mut Env<'_, UdpReport>, packet: IpPacket) {
        if !packet.is_checked()
            || packet.ingress().scope != self.scope
            || packet.sort() != Sort::Transport(Transport::Udp)
        {
            return;
        }
        let Some(header) = packet.header() else {
            return;
        };
        if header.protocol != protocol::UDP {
            return;
        }
        let (src, dst) = (header.src, header.dst);
        let group = dst != self.addr;
        if group && !self.groups.contains(&dst) {
            return;
        }
        let Some(udp) = wire::Datagram::parse(packet.payload()) else {
            return;
        };
        if !udp.checksum_ok(src, dst) {
            return;
        }
        let peer = SocketAddr::new(src, udp.source_port());
        let local = SocketAddr::new(dst, udp.destination_port());
        let Some(&id) = self.ports.get(&udp.destination_port()) else {
            // No one answers a group's datagram, with an error or a notice.
            if group {
                return;
            }
            let silent = local.port() == 0 && self.settings.port_zero == PortZero::Silent;
            if !silent && let Some(answer) = port_unreachable(packet.bytes(), dst, &self.icmp) {
                self.down.push_back((Chunk::new(answer.0), None));
            }
            self.notice(UdpNotice::Refused { peer, local });
            return;
        };
        let socket = self.sockets.get_mut(id).expect("a bound port has a socket");
        let payload = udp.payload();
        let cost = payload.len() + DATAGRAM_COST;
        let cause = if socket.bytes + cost > QUEUE {
            Dropped::QueueFull
        } else if let Some(charge) = env.budget().charge(cost) {
            let mut bytes = Vec::with_capacity(payload.len());
            bytes.extend_from_slice(payload);
            socket.bytes += cost;
            socket
                .queue
                .push_back(Datagram::new(Chunk::with_charge(bytes, charge), peer));
            self.wake(id);
            return;
        } else {
            Dropped::Budget
        };
        env.report(UdpReport::Dropped { local, peer, cause });
    }

    /// The next event of a socket in turn, if any has one.
    fn socket_event(&mut self) -> Option<EventOf<Udp>> {
        for _ in 0..self.ready.len() {
            let id = self.ready.pop_front()?;
            let Some(socket) = self.sockets.get_mut(id) else {
                continue;
            };
            socket.queued = false;
            let event = if socket.owed > 0 {
                let owed = std::mem::take(&mut socket.owed);
                socket.credit += owed;
                MuxEvent::Credit(id, owed)
            } else if socket.granted > 0
                && let Some(datagram) = socket.queue.pop_front()
            {
                socket.granted -= 1;
                socket.bytes -= datagram.payload().len() + DATAGRAM_COST;
                MuxEvent::Child(id, DatagramEvent::Datagram(datagram))
            } else if socket.ending && !socket.ended && socket.queue.is_empty() {
                socket.ended = true;
                MuxEvent::Child(id, DatagramEvent::Ended)
            } else {
                continue;
            };
            self.wake(id);
            return Some(event);
        }
        None
    }
}

impl Layer for UdpLayer {
    type Lower = Packets<IpPacket, Chunk>;
    type Upper = Udp;
    type Report = UdpReport;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Overrun;

    fn report_bytes(_: &UdpReport) -> Option<usize> {
        Some(0)
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, UdpReport>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Overrun> {
        if self.input_ended {
            return Ok(Admit::Closed(event));
        }
        if self.up.len() >= HELD || self.down.len() >= HELD {
            return Ok(Admit::Blocked(event));
        }
        match event {
            PacketEvent::Packet(packet) => self.take_in(env, packet),
            PacketEvent::Ended => {
                self.input_ended = true;
                let ids: Vec<ChildId> = self.sockets.ids().collect();
                for id in ids {
                    if let Some(socket) = self.sockets.get_mut(id) {
                        socket.ending = true;
                    }
                    self.wake(id);
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, UdpReport>,
        command: CommandOf<Self::Upper>,
    ) -> Result<Admit<CommandOf<Self::Upper>>, Overrun> {
        let blocked = match command.op() {
            MuxOp::Control(MessageCommand::Send(_)) => self.up.len() >= HELD,
            MuxOp::Child(id, DatagramCommand::Send(_)) => match self.sockets.get(*id) {
                Some(socket) if socket.credit == 0 => return Err(Overrun(*id)),
                Some(_) => self.down.len() >= HELD,
                None => false,
            },
            _ => false,
        };
        if blocked {
            return Ok(Admit::Blocked(command));
        }
        match command.into_op() {
            MuxOp::Control(MessageCommand::Send(control)) => match control {
                UdpControl::Bind { request, port } => self.bind(request, port),
                UdpControl::Join(group) => {
                    if !group.is_multicast() || group.is_ipv4() != self.addr.is_ipv4() {
                        self.notice(UdpNotice::JoinFailed(group));
                    } else if !self.groups.contains(&group) {
                        self.groups.push(group);
                    }
                }
                UdpControl::Leave(group) => self.groups.retain(|g| *g != group),
            },
            MuxOp::Control(MessageCommand::End) => {}
            MuxOp::Credit(id, units) => {
                if let Some(socket) = self.sockets.get_mut(id) {
                    socket.granted = socket.granted.saturating_add(units);
                    self.wake(id);
                }
            }
            MuxOp::Close(id) => {
                self.close(id);
            }
            MuxOp::Child(id, DatagramCommand::End) => {
                if self.close(id) {
                    self.closed.push_back(id);
                }
            }
            MuxOp::Child(id, DatagramCommand::Send(datagram)) => {
                let Some(socket) = self.sockets.get_mut(id) else {
                    // A socket already closed sends nothing.
                    return Ok(Admit::Taken);
                };
                socket.credit -= 1;
                let port = socket.port;
                let (payload, to) = datagram.into_parts();
                match self.packet(port, &payload, to) {
                    Some(packet) => self.down.push_back((packet, Some(id))),
                    None => {
                        let socket = self.sockets.get_mut(id).expect("checked above");
                        socket.owed += 1;
                        self.wake(id);
                    }
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<CommandOf<Self::Lower>> {
        let (packet, sender) = self.down.pop_front()?;
        if let Some(id) = sender
            && let Some(socket) = self.sockets.get_mut(id)
        {
            socket.owed += 1;
            self.wake(id);
        }
        Some(PacketCommand::Send(packet))
    }

    fn take_event(&mut self) -> Option<EventOf<Self::Upper>> {
        if let Some(event) = self.up.pop_front() {
            return Some(event);
        }
        if let Some(id) = self.closed.pop_front() {
            return Some(MuxEvent::Closed(id));
        }
        self.socket_event()
    }
}

/// The ICMP "port unreachable" answer to `packet`, a whole UDP packet to
/// `addr`, this machine (RFC 1122, RFC 4443).
fn port_unreachable(
    packet: &[u8],
    addr: IpAddr,
    options: &icmp::Options,
) -> Option<fictionet::Packet> {
    match addr {
        IpAddr::V4(_) => options.error(packet, addr, 3, 3, 0),
        IpAddr::V6(_) => options.error(packet, addr, 1, 4, 0),
    }
}

#[cfg(test)]
mod tests;
