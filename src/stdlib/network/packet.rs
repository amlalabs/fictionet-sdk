//! The IP layer: raw packets taken in as a host takes them, checked, and
//! sorted for the transports above; and captured copies read as a passive
//! observer reads them.
//!
//! [`IpLayer`] is a [layer](fictionet::stdlib::layer) with whole packets on
//! both sides. Below, it takes raw packets, each a [`Chunk`] of bytes from
//! the input path its endpoint owns. Above, it hands each whole packet a
//! host would take in to the transports as a [`CheckedIpPacket`]: the
//! bytes together with the header read from them and where the packet goes
//! ([`Sort`]). It does what
//! [`ip::split_protocols`](fictionet::stdlib::network::ip::split_protocols)
//! promises, and that split now runs on it:
//!
//! - an IPv6 packet's extension headers are checked as RFC 8200 asks of the
//!   packet's destination ([`Header::check`]) and taken out, and a packet
//!   that fails is dropped, with the ICMPv6 Parameter Problem answer sent
//!   back down where the RFC asks for one;
//! - fragments are put back together ([`Reassembly`]), with its limits on
//!   overlap, size and waiting time, and the layer's
//!   [deadline](fictionet::stdlib::layer::Layer::deadline) is when the
//!   oldest unfinished packet expires;
//! - a packet it cannot read, whose IPv4 header checksum is wrong, or whose
//!   fragments can never make a packet is dropped and reported
//!   ([`IpReport::Malformed`]), so it never reaches a transport;
//! - each packet is sorted by protocol, and an ICMP error goes to the
//!   transport of the packet it quotes ([`Sort::of`]).
//!
//! A transport layer sits above it with `Packets<CheckedIpPacket, Chunk>` as
//! its lower port. It receives the packets whose [`CheckedIpPacket::sort`]
//! is its [`Transport`], ICMP errors quoting its packets included, and sends
//! whole IP packets it built down. The IP layer sends them on unchanged.
//! Everything after the IP header (the transport header, its checksum and
//! its ports) is the transport's to check.
//!
//! An endpoint serves one network. It owns its interface, its IP layer
//! and its transports, and a tunnel carrying another network feeds an
//! endpoint of its own (a [`Framed`] stream below a second `IpLayer`).
//! Where packets of several networks arrive together, [`NetworkInput`]
//! picks out one network's packets before they reach an IP layer, since
//! two networks' fragments may share addresses and identification.
//!
//! A passive observer of a capture does not take packets in as a host
//! does: a capture may hold copies cut short, and nothing answers it.
//! [`ObservedIpPacket::observed`] reads such a copy with the same parsing
//! helpers but no host policy, and keeps where the capture saw it
//! ([`Ingress`]). The two types never mix: a transport cannot be handed an
//! observed copy.
//!
//! ```compile_fail
//! use fictionet::stdlib::layer::Chunk;
//! use fictionet::stdlib::network::packet::{CheckedIpPacket, Ingress, ObservedIpPacket};
//!
//! fn transport_input(_: CheckedIpPacket) {}
//! let captured = ObservedIpPacket::observed(Chunk::new(vec![]), Ingress::default());
//! transport_input(captured);
//! ```
//!
//! A host takes raw packets in:
//!
//! ```
//! use std::sync::Arc;
//! use fictionet::stdlib::layer::{Admit, Budget, Chunk, Driver, PacketEvent};
//! use fictionet::stdlib::network::ip::{self, protocol};
//! use fictionet::stdlib::network::Transport;
//! use fictionet::stdlib::network::packet::{IpLayer, Sort};
//! use fictionet::time::Instant;
//! use fictionet::{Seed, SeededEntropy};
//!
//! let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(1)));
//! let mut ip = Driver::new(IpLayer::host(), entropy, Budget::unlimited(), Instant::ZERO);
//! let udp = [0, 1, 0, 53, 0, 8, 0, 0];
//! let packet = ip::packet("10.0.0.2".parse()?, "10.0.0.1".parse()?, protocol::UDP, &udp);
//! assert!(matches!(ip.deliver(PacketEvent::Packet(Chunk::new(packet.0))), Ok(Admit::Taken)));
//! ip.send_above(|event| {
//!     let PacketEvent::Packet(packet) = event else { unreachable!() };
//!     assert_eq!(packet.sort(), Sort::Transport(Transport::Udp));
//!     assert_eq!(packet.payload(), &udp);
//!     Admit::Taken
//! });
//! # Ok::<(), std::net::AddrParseError>(())
//! ```

use core::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fictionet::Packet;
use fictionet::stdlib::layer::{
    Admit, Budget, Chunk, CommandOf, Datagram, Env, EventOf, Layer, PacketCommand, PacketEvent,
    Packets, Whole,
};
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::network::ip::{Header, Intake, Reassembly, protocol};
use fictionet::time::Instant;

mod factory;
mod framed;
pub use factory::{Factory, Opening, Stack};
pub use framed::{FrameError, Framed};

/// Which network a packet belongs to: the world's own, or the network
/// inside one tunnel.
///
/// The same addresses and ports may be in use in two networks at once. An
/// endpoint is never told its network: it owns its input path. Where
/// several networks' traffic comes together, as in a capture, anything
/// keyed by addresses (a connection, a conversation) includes the scope,
/// and [`NetworkInput`] picks out one network's packets before an IP layer
/// sees them. A scope is made by whatever owns the network, never read
/// from a peer, and a tunnel that replaces another may keep its scope when
/// it carries on the same network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(u64);

impl Scope {
    /// The world's own network.
    pub const ROOT: Scope = Scope(0);
}

/// Numbers the networks inside one world's tunnels, from 1 in the order
/// they are made.
///
/// A world keeps one and every tunnel in it takes its network's scope from
/// it, nested tunnels included, so no two of the world's networks share a
/// scope. The numbers come in the order tunnels are made, and mean nothing
/// outside their world. Tunnels made concurrently may be numbered in a
/// different order on another run, so a replay that needs the same numbers
/// records which network each one names. A capture reader keeps its own
/// for the tunnels it reads. Clones share the numbering.
#[derive(Clone, Debug, Default)]
pub struct Scopes {
    last: Arc<AtomicU64>,
}

impl Scopes {
    /// The scope of the network inside a new tunnel.
    pub fn tunnel(&self) -> Scope {
        let previous = self
            .last
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("network scopes exhausted");
        Scope(previous + 1)
    }
}

/// Where a packet was seen, given by whoever combines several networks'
/// packets: its network, the interface or tunnel it was seen on, and, for
/// a captured copy, what the capture recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ingress {
    /// The network it belongs to.
    pub scope: Scope,
    /// The interface or tunnel it was seen on, as numbered by whoever owns
    /// them. Several may see one network, so this does not name the
    /// network.
    pub link: u32,
    /// What a capture recorded, for a captured copy.
    pub capture: Option<Capture>,
}

/// What a capture recorded about one packet, supplied by the capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capture {
    /// The capture's number for the packet, which observed bytes name as
    /// their [`Source`](fictionet::stdlib::layer::Source).
    pub number: u64,
    /// When the capture saw it.
    pub at: Instant,
    /// Its length on the wire. The capture may hold fewer bytes.
    pub original_len: usize,
}

/// Where the IP layer sorts a packet: to a [`Transport`], to ICMP, or to
/// neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sort {
    /// A TCP segment or UDP datagram, or an ICMP error quoting one.
    Transport(Transport),
    /// Any other ICMP or ICMPv6 message: pings, and errors that quote
    /// neither TCP nor UDP.
    Icmp,
    /// Anything else, with the protocol it names: another protocol, or a
    /// fragment after the first. [`protocol::NONE`] when the packet could
    /// not be read.
    Other(u8),
}

impl Sort {
    /// Where a whole packet a host would take in goes. A packet that is not
    /// one ([`Header::parse_whole`] refuses it) is `Other(protocol::NONE)`.
    /// ICMP errors (destination unreachable, source quench, time exceeded
    /// and parameter problem for IPv4, and every type below 128 for IPv6)
    /// go to the transport of the packet they quote, when it is TCP or UDP.
    pub fn of(packet: &[u8]) -> Sort {
        Sort::read(Header::parse_whole(packet).as_ref(), packet)
    }

    /// Where the packet that `header` was read from goes, or
    /// `Other(protocol::NONE)` when no header could be read.
    fn read(header: Option<&Header>, packet: &[u8]) -> Sort {
        let Some(header) = header else {
            return Sort::Other(protocol::NONE);
        };
        if header.fragment.is_some_and(|f| f.offset != 0) {
            return Sort::Other(header.protocol);
        }
        let message = header.payload(packet);
        let quoted = match header.protocol {
            protocol::TCP => return Sort::Transport(Transport::Tcp),
            protocol::UDP => return Sort::Transport(Transport::Udp),
            protocol::ICMP if header.src.is_ipv4() => {
                message.len() >= 8 && matches!(message[0], 3 | 4 | 11 | 12)
            }
            protocol::ICMPV6 if header.src.is_ipv6() => message.len() >= 8 && message[0] < 128,
            protocol::ICMP | protocol::ICMPV6 => false,
            other => return Sort::Other(other),
        };
        if quoted
            && let Some(quoted) = Header::parse_truncated(&message[8..])
            && quoted.fragment.is_none_or(|f| f.offset == 0)
        {
            match quoted.protocol {
                protocol::TCP => return Sort::Transport(Transport::Tcp),
                protocol::UDP => return Sort::Transport(Transport::Udp),
                _ => {}
            }
        }
        Sort::Icmp
    }
}

/// How a [`CheckedIpPacket`]'s bytes relate to what arrived.
#[derive(Debug)]
pub enum Origin {
    /// They are exactly what arrived.
    Arrived,
    /// An IPv6 packet whose extension headers were checked and taken out,
    /// so the upper-layer header follows the IPv6 header. `original` is
    /// what arrived.
    Normalized {
        /// The packet as it arrived.
        original: Chunk,
    },
    /// Put together from fragments, or from one atomic fragment: no single
    /// packet arrived with these bytes.
    Reassembled,
}

/// One whole IP packet a host takes in, with the header read from its own
/// bytes and where it goes ([`Sort`]).
///
/// It passed [`Header::check`], is not a fragment, and has no IPv6
/// extension headers left. [`IpLayer`] and [`CheckedIpPacket::checked`]
/// make one, so the header and sort always describe these bytes, and a
/// transport given one need not check the IP header again. What follows
/// the IP header is the transport's to check.
#[derive(Debug)]
pub struct CheckedIpPacket {
    bytes: Chunk,
    header: Header,
    sort: Sort,
    origin: Origin,
}

impl CheckedIpPacket {
    /// Reads a whole packet as a host takes it in, for an IP layer of your
    /// own to hand its transports, as [`IpLayer`] does. `bytes` must be one
    /// whole IP packet that passes [`Header::check`] and is not a fragment,
    /// and an IPv6 packet must have no extension headers left
    /// ([`strip_extension_headers`] takes them out). `origin` says how the
    /// bytes relate to what arrived. Hands `bytes` back when any of that
    /// fails.
    ///
    /// [`strip_extension_headers`]: fictionet::stdlib::network::ip::strip_extension_headers
    pub fn checked(bytes: Chunk, origin: Origin) -> Result<Self, Chunk> {
        let Some(header) = Header::parse_whole(&bytes)
            .filter(|header| header.src.is_ipv4() || header.payload.start == 40)
        else {
            return Err(bytes);
        };
        let sort = Sort::read(Some(&header), &bytes);
        Ok(Self {
            bytes,
            header,
            sort,
            origin,
        })
    }

    /// The packet's bytes, IP header first. For a reassembled or normalized
    /// packet these are not the bytes that arrived ([`origin`](Self::origin)).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Its header, read from [`bytes`](Self::bytes).
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The bytes after the IP header: the transport's header and payload,
    /// or an ICMP message.
    pub fn payload(&self) -> &[u8] {
        self.header.payload(&self.bytes)
    }

    /// Where the IP layer sorts it.
    pub fn sort(&self) -> Sort {
        self.sort
    }

    /// How its bytes relate to what arrived.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Its bytes, giving up the rest.
    pub fn into_bytes(self) -> Chunk {
        self.bytes
    }
}

/// A captured copy of an IP packet, read as a passive observer reads it,
/// with where the capture saw it.
///
/// A capture may hold fewer bytes than the packet had, and its packets are
/// not taken in by anyone, so nothing is reassembled, stripped, answered
/// or checked against host policy. Transports take [`CheckedIpPacket`]s
/// only; an observed copy cannot be handed to one.
#[derive(Debug)]
pub struct ObservedIpPacket {
    bytes: Chunk,
    header: Option<Header>,
    sort: Sort,
    ingress: Ingress,
    complete: bool,
}

impl ObservedIpPacket {
    /// Reads a captured copy: the header with [`Header::parse_truncated`],
    /// since a capture may hold fewer bytes than the packet had, and no
    /// host policy. An IPv4 header checksum is not checked. A fragment
    /// after the first goes to [`Sort::Other`].
    pub fn observed(bytes: Chunk, ingress: Ingress) -> Self {
        let header = Header::parse_truncated(&bytes);
        let sort = Sort::read(header.as_ref(), &bytes);
        let complete = Header::parse(&bytes).is_some()
            && ingress
                .capture
                .is_none_or(|capture| capture.original_len <= bytes.len());
        Self {
            bytes,
            header,
            sort,
            ingress,
            complete,
        }
    }
    /// The bytes the capture holds, IP header first.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Its header, when the capture holds enough of it to read.
    pub fn header(&self) -> Option<&Header> {
        self.header.as_ref()
    }

    /// The bytes after the IP header and any extension headers that the
    /// capture holds. Empty when the header could not be read.
    pub fn payload(&self) -> &[u8] {
        self.header
            .as_ref()
            .map_or(&[][..], |header| header.payload(&self.bytes))
    }

    /// Where a host would sort it.
    pub fn sort(&self) -> Sort {
        self.sort
    }

    /// Where the capture saw it.
    pub fn ingress(&self) -> &Ingress {
        &self.ingress
    }

    /// Whether every byte of the packet is here: false when the capture
    /// holds fewer bytes than the packet had or than its header says.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Its bytes, giving up the rest.
    pub fn into_bytes(self) -> Chunk {
        self.bytes
    }
}

impl Whole for ObservedIpPacket {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn reserve(&mut self, budget: &Budget) -> bool {
        self.bytes.reserve(budget)
    }
}

/// Picks one network's packets out of input that carries several, before
/// they reach that network's IP layer.
///
/// An endpoint owns its input path and needs none. A component that takes
/// in packets of several networks together, each labelled with its
/// [`Ingress`], keeps one per network it feeds: two networks' fragments may
/// share addresses and identification, so they must be parted before
/// reassembly.
pub struct NetworkInput {
    network: Scope,
}

impl NetworkInput {
    /// Takes the packets of network `network`.
    pub fn new(network: Scope) -> Self {
        Self { network }
    }

    /// The raw bytes of `packet` if it is of this network; otherwise
    /// `packet` back, unchanged, for another network's input.
    pub fn accept(&self, packet: Datagram<Ingress>) -> Result<Chunk, Datagram<Ingress>> {
        if packet.meta().scope != self.network {
            return Err(packet);
        }
        Ok(packet.into_parts().0)
    }
}

impl Whole for CheckedIpPacket {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Charges the packet and, for a normalized one, the original it keeps,
    /// together or not at all.
    fn reserve(&mut self, budget: &Budget) -> bool {
        let original = match &self.origin {
            Origin::Normalized { original } if original.charged() == 0 => Some(original.len()),
            _ => None,
        };
        let packet = (self.bytes.charged() == 0).then(|| self.bytes.len());
        let total = original.unwrap_or(0) + packet.unwrap_or(0);
        let Some(mut charge) = budget.charge(total) else {
            return false;
        };
        if let (Some(len), Origin::Normalized { original }) = (original, &mut self.origin) {
            let part = charge.split(len).expect("the charge covers both");
            *original = Chunk::with_charge(original.to_vec(), part);
        }
        if packet.is_some() {
            self.bytes = Chunk::with_charge(self.bytes.to_vec(), charge);
        }
        true
    }
}

/// What [`IpLayer`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpReport {
    /// A packet was dropped for its IPv6 extension headers. `answered` says
    /// whether an ICMPv6 Parameter Problem went back for it.
    Refused {
        /// Whether an answer went back.
        answered: bool,
    },
    /// A packet was dropped because a host cannot take it in: it could not
    /// be read, its IPv4 header checksum is wrong, or it is a fragment that
    /// can never make a packet.
    Malformed,
}

/// A host's IP layer: raw packets below, whole checked packets for the
/// transports above. See the [module docs](self).
///
/// It holds at most one packet each way that the other side has not taken,
/// plus one answer, and refuses input (changing nothing) until those are
/// taken. A packet it takes in is either handed up whole, kept as a
/// fragment, or dropped with a report; it never hands back part of one.
///
/// It serves one network: the one its endpoint's input path carries. It
/// sends packets down with no label, so it could not tell two networks'
/// answers apart, and two networks' fragments may share addresses and
/// identification. A tunnel's network gets an IP layer of its own, and
/// input carrying several networks is parted first ([`NetworkInput`]).
///
/// Fragments wait in [`Reassembly`], which holds at most 4 MiB, counting its
/// bookkeeping, as fixed engine state outside the connection's budget. The
/// layer keeps no charge of a packet it takes in: what it hands up is
/// uncharged until a budgeted carrier above reserves it, as
/// [`Packets`]' credit does.
#[derive(Default)]
pub struct IpLayer {
    reassembly: Reassembly,
    up: Option<PacketEvent<CheckedIpPacket>>,
    answer: Option<Chunk>,
    down: Option<PacketCommand<Chunk>>,
    input_closed: bool,
    output_closed: bool,
}

impl IpLayer {
    /// A host's IP layer, taking packets in as their destination.
    pub fn host() -> IpLayer {
        IpLayer::default()
    }

    /// Takes in one raw packet the layer has room for.
    fn take_in(&mut self, env: &mut Env<'_, IpReport>, bytes: Chunk) {
        let before = Header::parse(&bytes);
        let fragment = before.as_ref().is_some_and(|h| h.fragment.is_some());
        let extended = before
            .as_ref()
            .is_some_and(|h| h.src.is_ipv6() && h.payload.start != 40);
        // A whole IPv4 packet goes up as it came, in the buffer it came
        // in: reassembly would hand it back unchanged. Only its expiry of
        // waiting fragments is kept up. An IPv6 packet has its chain
        // checked there first.
        if before.as_ref().is_some_and(|h| h.src.is_ipv4()) && !fragment {
            self.reassembly.expire(env.now());
            self.checked(env, bytes, Origin::Arrived);
            return;
        }
        let bytes = bytes.into_vec();
        let original = (!fragment && extended).then(|| Chunk::new(bytes.clone()));
        match self.reassembly.push(Packet(bytes), env.now()) {
            Intake::Whole(Packet(whole)) => {
                let origin = match original {
                    _ if fragment => Origin::Reassembled,
                    Some(original) if original.len() != whole.len() => {
                        Origin::Normalized { original }
                    }
                    _ => Origin::Arrived,
                };
                self.checked(env, Chunk::new(whole), origin);
            }
            Intake::Waiting => {}
            Intake::Discarded => env.report(IpReport::Malformed),
            Intake::Refused { answer, .. } => {
                let answer = answer.filter(|_| !self.output_closed);
                env.report(IpReport::Refused {
                    answered: answer.is_some(),
                });
                self.answer = answer.map(|Packet(bytes)| Chunk::new(bytes));
            }
        }
    }

    /// Hands `bytes` up if a host takes them in, and reports them otherwise.
    fn checked(&mut self, env: &mut Env<'_, IpReport>, bytes: Chunk, origin: Origin) {
        match CheckedIpPacket::checked(bytes, origin) {
            Ok(packet) => self.up = Some(PacketEvent::Packet(packet)),
            Err(_) => env.report(IpReport::Malformed),
        }
    }
}

impl Layer for IpLayer {
    type Lower = Packets<Chunk, Chunk>;
    type Upper = Packets<CheckedIpPacket, Chunk>;
    type Report = IpReport;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn report_bytes(_: &IpReport) -> Option<usize> {
        Some(0)
    }

    fn is_terminal(&self) -> bool {
        self.input_closed && self.output_closed
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, IpReport>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Infallible> {
        if self.input_closed {
            return Ok(Admit::Closed(event));
        }
        if self.up.is_some() || self.answer.is_some() {
            return Ok(Admit::Blocked(event));
        }
        match event {
            PacketEvent::Packet(raw) => self.take_in(env, raw),
            PacketEvent::Ended => {
                self.input_closed = true;
                self.up = Some(PacketEvent::Ended);
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, IpReport>,
        command: CommandOf<Self::Upper>,
    ) -> Result<Admit<CommandOf<Self::Upper>>, Infallible> {
        if self.output_closed {
            return Ok(Admit::Closed(command));
        }
        if self.down.is_some() {
            return Ok(Admit::Blocked(command));
        }
        self.output_closed = matches!(command, PacketCommand::End);
        self.down = Some(command);
        Ok(Admit::Taken)
    }

    fn on_timer(&mut self, env: &mut Env<'_, IpReport>, (): ()) -> Result<bool, Infallible> {
        self.reassembly.expire(env.now());
        Ok(true)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<CommandOf<Self::Lower>> {
        self.answer
            .take()
            .map(PacketCommand::Send)
            .or_else(|| self.down.take())
    }

    fn take_event(&mut self) -> Option<EventOf<Self::Upper>> {
        self.up.take()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.reassembly.next_expiry().map(|at| (at, ()))
    }
}

#[cfg(kani)]
#[path = "../../../verification/packet-udp/kani/packet.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::layer::Driver;
    use fictionet::stdlib::network::ip;
    use fictionet::{Seed, SeededEntropy};
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

    fn driver() -> Driver<IpLayer> {
        Driver::new(
            IpLayer::host(),
            Arc::new(SeededEntropy::new(Seed::from_u64(3))),
            Budget::unlimited(),
            Instant::ZERO,
        )
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn raw(bytes: Vec<u8>) -> PacketEvent<Chunk> {
        PacketEvent::Packet(Chunk::new(bytes))
    }

    fn up(d: &mut Driver<IpLayer>) -> Vec<CheckedIpPacket> {
        let mut out = Vec::new();
        d.send_above(|event| {
            if let PacketEvent::Packet(p) = event {
                out.push(p);
            }
            Admit::Taken
        });
        out
    }

    fn down(d: &mut Driver<IpLayer>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        d.send_below(|command| {
            if let PacketCommand::Send(p) = command {
                out.push(p.to_vec());
            }
            Admit::Taken
        });
        out
    }

    /// `packet` cut into IPv4 fragments of at most `size` data bytes each, a
    /// multiple of eight.
    fn fragments(packet: &[u8], size: usize) -> Vec<Vec<u8>> {
        let ihl = (packet[0] & 0x0f) as usize * 4;
        let data = &packet[ihl..];
        let mut out = Vec::new();
        for (i, piece) in data.chunks(size).enumerate() {
            let offset = i * size;
            let more = offset + piece.len() < data.len();
            let mut f = packet[..ihl].to_vec();
            f.extend_from_slice(piece);
            let len = f.len() as u16;
            f[2..4].copy_from_slice(&len.to_be_bytes());
            // Keep "don't fragment" as the whole packet has it, as reassembly does.
            let df = u16::from_be_bytes([packet[6], packet[7]]) & 0x4000;
            let flags = df | (u16::from(more) << 13) | (offset / 8) as u16;
            f[6..8].copy_from_slice(&flags.to_be_bytes());
            ip::set_header_checksum(&mut f[..ihl]);
            out.push(f);
        }
        out
    }

    fn udp(len: usize) -> Vec<u8> {
        let mut u = vec![0, 9, 0, 53];
        u.extend_from_slice(&((8 + len) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend((0..len).map(|i| i as u8));
        u
    }

    #[test]
    fn malformed_host_input_is_reported_without_reaching_transports() {
        let mut d = driver();
        let mut checksum = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(4)).0;
        checksum[10] ^= 1;
        for bytes in [vec![0x45], checksum] {
            assert!(d.deliver(raw(bytes)).unwrap().moved());
            assert!(up(&mut d).is_empty());
            assert_eq!(
                d.observations().drain().collect::<Vec<_>>(),
                [IpReport::Malformed]
            );
            assert!(down(&mut d).is_empty());
        }
    }

    #[test]
    fn transports_get_their_packets_and_the_errors_about_them() {
        let (a, b) = (addr("10.0.0.2"), addr("10.0.0.1"));
        let tcp = ip::packet(a, b, protocol::TCP, &[0; 20]).0;
        let datagram = ip::packet(a, b, protocol::UDP, &udp(4)).0;
        let mut unreachable = vec![3, 3, 0, 0, 0, 0, 0, 0];
        unreachable.extend_from_slice(&tcp);
        let error = ip::packet(b, a, protocol::ICMP, &unreachable).0;
        let ping = ip::packet(a, b, protocol::ICMP, &[8, 0, 0, 0, 0, 1, 0, 1]).0;
        let gre = ip::packet(a, b, 47, &[0; 4]).0;
        let mut d = driver();
        let mut seen = Vec::new();
        for p in [tcp, datagram, error, ping, gre] {
            assert!(matches!(d.deliver(raw(p.clone())), Ok(Admit::Taken)));
            let got = up(&mut d);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].bytes(), &p[..]);
            seen.push(got[0].sort());
        }
        assert_eq!(
            seen,
            [
                Sort::Transport(Transport::Tcp),
                Sort::Transport(Transport::Udp),
                Sort::Transport(Transport::Tcp),
                Sort::Icmp,
                Sort::Other(47),
            ]
        );
    }

    #[test]
    fn malformed_fragments_are_reported_without_reaching_transports() {
        let whole = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(100)).0;
        let pieces = fragments(&whole, 32);
        for payload_len in [0, 9] {
            let mut malformed = pieces[0][..20 + payload_len].to_vec();
            let len = malformed.len() as u16;
            malformed[2..4].copy_from_slice(&len.to_be_bytes());
            ip::set_header_checksum(&mut malformed[..20]);
            let mut d = driver();
            assert!(d.deliver(raw(malformed)).unwrap().moved());
            assert!(up(&mut d).is_empty());
            assert_eq!(d.deadline(), None);
            assert!(matches!(
                d.observations().drain().collect::<Vec<_>>().as_slice(),
                [IpReport::Malformed]
            ));
            assert!(d.deliver(raw(pieces[0].clone())).unwrap().moved());
            assert!(up(&mut d).is_empty());
            assert!(d.deadline().is_some());
            assert_eq!(d.observations().drain().count(), 0);
        }
    }

    #[test]
    fn fragments_in_any_order_come_up_as_one_packet() {
        let whole = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(100)).0;
        let mut pieces = fragments(&whole, 32);
        assert!(pieces.len() > 2);
        pieces.reverse();
        let mut d = driver();
        let last = pieces.pop().unwrap();
        for p in pieces {
            assert!(matches!(d.deliver(raw(p)), Ok(Admit::Taken)));
            assert!(up(&mut d).is_empty());
        }
        assert!(d.deadline().is_some());
        assert!(matches!(d.deliver(raw(last)), Ok(Admit::Taken)));
        let got = up(&mut d);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].bytes(), &whole[..]);
        assert!(matches!(got[0].origin(), Origin::Reassembled));
        assert_eq!(got[0].sort(), Sort::Transport(Transport::Udp));
        assert_eq!(d.deadline(), None);
    }

    #[test]
    fn unfinished_packets_expire_at_the_deadline() {
        let whole = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(100)).0;
        let pieces = fragments(&whole, 32);
        let mut d = driver();
        assert!(matches!(
            d.deliver(raw(pieces[0].clone())),
            Ok(Admit::Taken)
        ));
        let due = d.deadline().unwrap();
        d.set_now(due);
        d.run().unwrap();
        assert_eq!(d.deadline(), None);
        // The rest no longer complete the packet that expired.
        for p in &pieces[1..] {
            assert!(matches!(d.deliver(raw(p.clone())), Ok(Admit::Taken)));
        }
        assert!(up(&mut d).is_empty());
        assert!(due >= Instant::ZERO + Duration::from_secs(1));
    }

    /// The driver hands packets in without firing due timers first, so the
    /// rest of a packet can arrive after its deadline and before the timer
    /// runs. They still do not complete it.
    #[test]
    fn fragments_after_the_deadline_complete_nothing_before_the_timer_runs() {
        let whole = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(100)).0;
        let pieces = fragments(&whole, 32);
        let mut d = driver();
        assert!(matches!(
            d.deliver(raw(pieces[0].clone())),
            Ok(Admit::Taken)
        ));
        let due = d.deadline().unwrap();
        d.set_now(due);
        for p in &pieces[1..] {
            assert!(matches!(d.deliver(raw(p.clone())), Ok(Admit::Taken)));
        }
        assert!(up(&mut d).is_empty());
    }

    #[test]
    fn extension_headers_are_taken_out_and_the_original_kept() {
        let (a, b) = (addr("2001:db8::2"), addr("2001:db8::1"));
        let plain = ip::packet(a, b, protocol::UDP, &udp(3)).0;
        // Destination options with one PadN option, in front of UDP.
        let mut with = plain[..40].to_vec();
        with[6] = protocol::DEST_OPTIONS;
        with.extend_from_slice(&[protocol::UDP, 0, 1, 4, 0, 0, 0, 0]);
        with.extend_from_slice(&plain[40..]);
        let len = (with.len() - 40) as u16;
        with[4..6].copy_from_slice(&len.to_be_bytes());
        let mut d = driver();
        assert!(matches!(d.deliver(raw(with.clone())), Ok(Admit::Taken)));
        let got = up(&mut d);
        assert_eq!(got[0].bytes(), &plain[..]);
        let Origin::Normalized { original } = got[0].origin() else {
            panic!("not normalized: {:?}", got[0].origin());
        };
        assert_eq!(&original[..], &with[..]);
        assert_eq!(got[0].payload(), &plain[40..]);
    }

    #[test]
    fn a_refused_packet_is_answered_below_and_never_handed_up() {
        let (a, b) = (addr("2001:db8::2"), addr("2001:db8::1"));
        let plain = ip::packet(a, b, protocol::UDP, &udp(3)).0;
        // A Routing header with segments left: a host here forwards none.
        let mut routed = plain[..40].to_vec();
        routed[6] = protocol::ROUTING;
        routed.extend_from_slice(&[protocol::UDP, 0, 0, 1, 0, 0, 0, 0]);
        routed.extend_from_slice(&plain[40..]);
        let len = (routed.len() - 40) as u16;
        routed[4..6].copy_from_slice(&len.to_be_bytes());
        let mut d = driver();
        assert!(matches!(d.deliver(raw(routed.clone())), Ok(Admit::Taken)));
        assert!(up(&mut d).is_empty());
        let answers = down(&mut d);
        assert_eq!(answers.len(), 1);
        let answer = Header::parse_whole(&answers[0]).unwrap();
        assert_eq!((answer.src, answer.dst), (b, a));
        assert_eq!(answer.protocol, protocol::ICMPV6);
        assert_eq!(
            d.observations().drain().collect::<Vec<_>>(),
            [IpReport::Refused { answered: true }]
        );
    }

    #[test]
    fn a_full_layer_refuses_without_changing_anything() {
        let (a, b) = (addr("10.0.0.2"), addr("10.0.0.1"));
        let first = ip::packet(a, b, protocol::UDP, &udp(1)).0;
        let second = ip::packet(a, b, protocol::UDP, &udp(2)).0;
        let mut d = driver();
        assert!(matches!(d.deliver(raw(first.clone())), Ok(Admit::Taken)));
        let Ok(Admit::Blocked(PacketEvent::Packet(back))) = d.deliver(raw(second.clone())) else {
            panic!("a full layer took a packet");
        };
        assert_eq!(&back[..], &second[..]);
        let got = up(&mut d);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].bytes(), &first[..]);
        assert!(matches!(d.deliver(raw(second)), Ok(Admit::Taken)));

        // The same holds going down.
        assert!(matches!(
            d.command(PacketCommand::Send(Chunk::new(first.clone()))),
            Ok(Admit::Taken)
        ));
        assert!(matches!(
            d.command(PacketCommand::Send(Chunk::new(vec![1]))),
            Ok(Admit::Blocked(_))
        ));
        assert_eq!(down(&mut d), [first]);
    }

    #[test]
    fn ends_pass_once_each_way() {
        let mut d = driver();
        assert!(matches!(d.deliver(PacketEvent::Ended), Ok(Admit::Taken)));
        let mut ended = 0;
        d.send_above(|event| {
            ended += usize::from(matches!(event, PacketEvent::Ended));
            Admit::Taken
        });
        assert_eq!(ended, 1);
        assert!(matches!(d.deliver(raw(vec![0x45])), Ok(Admit::Closed(_))));
        assert!(matches!(d.command(PacketCommand::End), Ok(Admit::Taken)));
        assert!(matches!(
            d.command(PacketCommand::Send(Chunk::new(vec![1]))),
            Ok(Admit::Closed(_))
        ));
        let mut ends = 0;
        d.send_below(|command| {
            ends += usize::from(matches!(command, PacketCommand::End));
            Admit::Taken
        });
        assert_eq!(ends, 1);
        assert!(d.layer().is_terminal());
    }

    #[test]
    fn an_observed_copy_cut_short_is_read_but_not_complete() {
        let (a, b) = (addr("10.0.0.2"), addr("10.0.0.1"));
        let whole = ip::packet(a, b, protocol::TCP, &[0; 40]).0;
        let capture = |original_len| Ingress {
            capture: Some(Capture {
                number: 7,
                at: Instant::ZERO,
                original_len,
            }),
            ..Ingress::default()
        };
        let full = ObservedIpPacket::observed(Chunk::new(whole.clone()), capture(whole.len()));
        assert!(full.is_complete());
        assert_eq!(full.sort(), Sort::Transport(Transport::Tcp));
        let cut =
            ObservedIpPacket::observed(Chunk::new(whole[..30].to_vec()), capture(whole.len()));
        assert!(!cut.is_complete());
        assert_eq!(cut.sort(), Sort::Transport(Transport::Tcp));
        assert_eq!(cut.payload(), &whole[20..30]);
        assert_eq!(cut.ingress().capture.unwrap().number, 7);
        let garbage = ObservedIpPacket::observed(Chunk::new(vec![0x60, 1]), Ingress::default());
        assert_eq!(garbage.sort(), Sort::Other(protocol::NONE));
        assert!(garbage.header().is_none());
        assert!(!garbage.is_complete());
    }

    #[test]
    fn a_later_fragment_is_not_a_transport_packet_to_an_observer() {
        let whole = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(100)).0;
        let pieces = fragments(&whole, 32);
        let first = ObservedIpPacket::observed(Chunk::new(pieces[0].clone()), Ingress::default());
        let later = ObservedIpPacket::observed(Chunk::new(pieces[1].clone()), Ingress::default());
        assert_eq!(first.sort(), Sort::Transport(Transport::Udp));
        assert_eq!(later.sort(), Sort::Other(protocol::UDP));
    }

    #[test]
    fn a_packet_and_its_original_are_charged_together() {
        let (a, b) = (addr("2001:db8::2"), addr("2001:db8::1"));
        let plain = ip::packet(a, b, protocol::UDP, &udp(3)).0;
        let mut packet = CheckedIpPacket {
            bytes: Chunk::new(plain.clone()),
            header: Header::parse_whole(&plain).unwrap(),
            sort: Sort::Transport(Transport::Udp),
            origin: Origin::Normalized {
                original: Chunk::new(vec![0; 64]),
            },
        };
        let tight = Budget::new(plain.len() + 10);
        assert!(!packet.reserve(&tight));
        assert_eq!(tight.used(), 0);
        let budget = Budget::new(1000);
        assert!(packet.reserve(&budget));
        assert!(budget.used() >= plain.len() + 64);
        drop(packet);
        assert_eq!(budget.used(), 0);
    }

    /// A tunnel's packets and the world's may share addresses, protocol and
    /// identification. Their fragments, interleaved so that each could fill
    /// the other's gaps, never meet: each IP layer puts together only its
    /// own network's packet.
    #[test]
    fn inner_and_outer_fragments_with_one_key_stay_apart() {
        let (a, b) = (addr("10.0.0.2"), addr("10.0.0.1"));
        let fields = ip::Fields {
            id: 7,
            dont_fragment: false,
            ..ip::Fields::default()
        };
        let outer = ip::packet_with(a, b, protocol::UDP, fields, &udp(100)).0;
        let mut inner_udp = udp(100);
        inner_udp[8..].reverse();
        let inner = ip::packet_with(a, b, protocol::UDP, fields, &inner_udp).0;
        let tunnel = Scopes::default().tunnel();
        let (outer_pieces, inner_pieces) = (fragments(&outer, 32), fragments(&inner, 32));
        assert_eq!(outer_pieces.len(), 4);
        // Alternate the two networks, each filling the other's gaps, then
        // send the rest the same way.
        let mut arrivals = Vec::new();
        for round in [[0, 2], [1, 3]] {
            for i in 0..4 {
                let (scope, pieces) = if round.contains(&i) {
                    (Scope::ROOT, &outer_pieces)
                } else {
                    (tunnel, &inner_pieces)
                };
                arrivals.push((scope, pieces[i].clone()));
            }
        }
        for (scope, whole) in [(Scope::ROOT, &outer), (tunnel, &inner)] {
            let input = NetworkInput::new(scope);
            let mut d = driver();
            let mut got = Vec::new();
            let mut rejected = 0;
            for (from, bytes) in &arrivals {
                let ingress = Ingress {
                    scope: *from,
                    ..Ingress::default()
                };
                let packet = Datagram::new(Chunk::new(bytes.clone()), ingress);
                match input.accept(packet) {
                    Ok(bytes) => {
                        assert!(d.deliver(PacketEvent::Packet(bytes)).unwrap().moved());
                        got.extend(up(&mut d));
                    }
                    Err(packet) => {
                        assert_ne!(packet.meta().scope, scope);
                        assert_eq!(packet.meta().scope, *from);
                        rejected += 1;
                    }
                }
            }
            assert_eq!(rejected, 4);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].bytes(), &whole[..]);
            assert_eq!(d.observations().drain().count(), 0);
        }
    }

    #[test]
    fn a_checked_packet_is_what_the_ip_layer_hands_up() {
        let (a, b) = (addr("10.0.0.2"), addr("10.0.0.1"));
        let good = ip::packet(a, b, protocol::UDP, &udp(4)).0;
        let mut d = driver();
        assert!(matches!(d.deliver(raw(good.clone())), Ok(Admit::Taken)));
        let layer = up(&mut d).pop().unwrap();
        let checked = CheckedIpPacket::checked(Chunk::new(good.clone()), Origin::Arrived).unwrap();
        assert_eq!(checked.header(), layer.header());
        assert_eq!(checked.sort(), layer.sort());
        // The same bytes observed are read, but not checked.
        let observed = ObservedIpPacket::observed(Chunk::new(good.clone()), Ingress::default());
        assert_eq!(observed.sort(), Sort::Transport(Transport::Udp));
        // What a host would not take in is handed back unchanged.
        let mut bad_sum = good.clone();
        bad_sum[10] ^= 1;
        let fragment = fragments(&ip::packet(a, b, protocol::UDP, &udp(100)).0, 32).remove(0);
        let (a6, b6) = (addr("2001:db8::2"), addr("2001:db8::1"));
        let plain6 = ip::packet(a6, b6, protocol::UDP, &udp(3)).0;
        let mut options6 = plain6[..40].to_vec();
        options6[6] = protocol::DEST_OPTIONS;
        options6.extend_from_slice(&[protocol::UDP, 0, 1, 4, 0, 0, 0, 0]);
        options6.extend_from_slice(&plain6[40..]);
        let len = (options6.len() - 40) as u16;
        options6[4..6].copy_from_slice(&len.to_be_bytes());
        for refused in [bad_sum, fragment, options6, vec![0x45]] {
            let back =
                CheckedIpPacket::checked(Chunk::new(refused.clone()), Origin::Arrived).unwrap_err();
            assert_eq!(&back[..], &refused[..]);
        }
        assert!(CheckedIpPacket::checked(Chunk::new(plain6), Origin::Arrived).is_ok());
    }

    /// A world's tunnels never share a scope, whichever clone of its
    /// numbering makes them, and none is the world's own. Another world
    /// making its tunnels in the same order gets the same scopes: they come
    /// from the world, not from what else ran in the process.
    #[test]
    fn a_worlds_scopes_are_never_shared_and_repeat_with_the_world() {
        let made = |scopes: Scopes| {
            let clone = scopes.clone();
            [scopes.tunnel(), clone.tunnel(), scopes.tunnel()]
        };
        let first = made(Scopes::default());
        assert!(!first.contains(&Scope::ROOT));
        assert!(first[0] != first[1] && first[1] != first[2] && first[0] != first[2]);
        assert_eq!(made(Scopes::default()), first);
        assert_eq!(Ingress::default().scope, Scope::ROOT);
    }
}
