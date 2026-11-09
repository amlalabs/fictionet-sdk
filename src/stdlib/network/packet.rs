//! The IP layer: whole IP packets with what is known about them, taken in
//! as a host takes them and sorted for the transports above.
//!
//! [`IpLayer`] is a [layer](fictionet::stdlib::layer) with whole packets on
//! both sides. Below, it takes raw packets from an interface, each a
//! [`Datagram`] of bytes with its [`Ingress`]. Above, it hands each whole
//! packet a host would take in to the transports as an [`IpPacket`]: an
//! envelope that keeps the bytes together with the header read from those
//! bytes, the [`Transport`] the packet goes to, and where it came from. It
//! does what
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
//! - each packet is sorted by protocol, and an ICMP error goes to the
//!   transport of the packet it quotes ([`Transport::of`]).
//!
//! A transport layer sits above it with `Packets<IpPacket, Chunk>` as its
//! lower port. It receives the packets whose [`IpPacket::transport`] is its
//! own, ICMP errors quoting its packets included, and sends whole IP
//! packets it built down. The IP layer sends them on unchanged. What the
//! IP layer checks is listed above; everything after the IP header (the
//! transport header, its checksum and its ports) is the transport's to
//! check, and an IPv4 header checksum is checked by [`Header::check`] for
//! every packet a transport is given.
//!
//! A passive observer of a capture does not take packets in as a host
//! does: a capture may hold copies cut short, and nothing answers it.
//! [`IpPacket::observed`] reads such a copy with the same parsing helpers
//! but no host policy.
//!
//! ```
//! use std::sync::Arc;
//! use fictionet::stdlib::layer::{Admit, Budget, Chunk, Datagram, Driver, PacketEvent};
//! use fictionet::stdlib::network::ip::{self, protocol};
//! use fictionet::stdlib::network::packet::{Ingress, IpLayer, Transport};
//! use fictionet::time::Instant;
//! use fictionet::{Seed, SeededEntropy};
//!
//! let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(1)));
//! let mut ip = Driver::new(IpLayer::host(), entropy, Budget::unlimited(), Instant::ZERO);
//! let udp = [0, 1, 0, 53, 0, 8, 0, 0];
//! let packet = ip::packet("10.0.0.2".parse()?, "10.0.0.1".parse()?, protocol::UDP, &udp);
//! let raw = Datagram::new(Chunk::new(packet.0), Ingress::default());
//! assert!(matches!(ip.deliver(PacketEvent::Packet(raw)), Ok(Admit::Taken)));
//! ip.send_above(|event| {
//!     let PacketEvent::Packet(packet) = event else { unreachable!() };
//!     assert_eq!(packet.transport(), Transport::Udp);
//!     assert_eq!(packet.payload(), &udp);
//!     Admit::Taken
//! });
//! # Ok::<(), std::net::AddrParseError>(())
//! ```

use core::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};

use fictionet::Packet;
use fictionet::stdlib::layer::{
    Admit, Budget, Chunk, CommandOf, Datagram, Env, EventOf, Layer, PacketCommand, PacketEvent,
    Packets, Whole,
};
use fictionet::stdlib::network::ip::{Header, Intake, Reassembly, protocol};
use fictionet::time::Instant;

mod factory;
pub use factory::{Factory, Opening, Stack};

/// Which network a packet belongs to: the world's own, or the network
/// inside one tunnel.
///
/// The same addresses and ports may be in use in two scopes at once, so
/// anything keyed by addresses (a connection, a capture's conversation)
/// includes the scope. A scope is made by whatever owns the network, never
/// read from a peer: a tunnel layer makes a new one for the network it
/// carries ([`Scope::tunnel`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(u64);

/// The last scope [`Scope::tunnel`] made.
static SCOPES: AtomicU64 = AtomicU64::new(0);

impl Scope {
    /// The world's own network.
    pub const ROOT: Scope = Scope(0);

    /// A new scope, different from every other one made in this process,
    /// for the network inside one tunnel.
    pub fn tunnel() -> Scope {
        let previous = SCOPES
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("network scopes exhausted");
        Scope(previous + 1)
    }
}

/// Where a packet arrived: its network, its interface, and, for a captured
/// copy, what the capture recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ingress {
    /// The network it belongs to.
    pub scope: Scope,
    /// The interface it arrived on, as numbered by whoever owns the
    /// interfaces. Zero for a stack with one.
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

/// Which transport a packet goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// A TCP segment, or an ICMP error quoting one.
    Tcp,
    /// A UDP datagram, or an ICMP error quoting one.
    Udp,
    /// Any other ICMP or ICMPv6 message: pings, and errors that quote
    /// neither TCP nor UDP.
    Icmp,
    /// Anything else, with the protocol it names: another protocol, or a
    /// fragment after the first. [`protocol::NONE`] when the packet could
    /// not be read.
    Other(u8),
}

impl Transport {
    /// Which transport a whole packet a host would take in goes to. A packet
    /// that is not one ([`Header::parse_whole`] refuses it) is
    /// `Other(protocol::NONE)`. ICMP errors (destination unreachable, source
    /// quench, time exceeded and parameter problem for IPv4, and every type
    /// below 128 for IPv6) go to the transport of the packet they quote,
    /// when it is TCP or UDP.
    pub fn of(packet: &[u8]) -> Transport {
        Transport::read(Header::parse_whole(packet).as_ref(), packet)
    }

    /// Which transport the packet that `header` was read from goes to, or
    /// `Other(protocol::NONE)` when no header could be read.
    fn read(header: Option<&Header>, packet: &[u8]) -> Transport {
        let Some(header) = header else {
            return Transport::Other(protocol::NONE);
        };
        if header.fragment.is_some_and(|f| f.offset != 0) {
            return Transport::Other(header.protocol);
        }
        let message = header.payload(packet);
        let quoted = match header.protocol {
            protocol::TCP => return Transport::Tcp,
            protocol::UDP => return Transport::Udp,
            protocol::ICMP if header.src.is_ipv4() => {
                message.len() >= 8 && matches!(message[0], 3 | 4 | 11 | 12)
            }
            protocol::ICMPV6 if header.src.is_ipv6() => message.len() >= 8 && message[0] < 128,
            protocol::ICMP | protocol::ICMPV6 => false,
            other => return Transport::Other(other),
        };
        if quoted
            && let Some(quoted) = Header::parse_truncated(&message[8..])
            && quoted.fragment.is_none_or(|f| f.offset == 0)
        {
            match quoted.protocol {
                protocol::TCP => return Transport::Tcp,
                protocol::UDP => return Transport::Udp,
                _ => {}
            }
        }
        Transport::Icmp
    }
}

/// How an [`IpPacket`]'s bytes relate to what arrived.
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
    /// A captured copy, read without host policy ([`IpPacket::observed`]).
    Observed,
}

/// One whole IP packet, with the header read from its own bytes and the
/// transport it goes to.
///
/// Only [`IpLayer`] and [`IpPacket::observed`] make one, so the header and
/// transport always describe these bytes. A packet from the IP layer passed
/// [`Header::check`], is not a fragment, and has no IPv6 extension headers
/// left; its header is there unless its transport is
/// [`Transport::Other`] and it could not be read.
#[derive(Debug)]
pub struct IpPacket {
    bytes: Chunk,
    header: Option<Header>,
    transport: Transport,
    ingress: Ingress,
    origin: Origin,
    complete: bool,
}

impl IpPacket {
    /// Reads a captured copy as a passive observer does: the header with
    /// [`Header::parse_truncated`], since a capture may hold fewer bytes
    /// than the packet had, and no host policy. Nothing is reassembled,
    /// stripped or answered, and an IPv4 header checksum is not checked. A
    /// fragment after the first goes to [`Transport::Other`].
    pub fn observed(bytes: Chunk, ingress: Ingress) -> IpPacket {
        let header = Header::parse_truncated(&bytes);
        let transport = Transport::read(header.as_ref(), &bytes);
        let complete = Header::parse(&bytes).is_some()
            && ingress
                .capture
                .is_none_or(|capture| capture.original_len <= bytes.len());
        IpPacket {
            bytes,
            header,
            transport,
            ingress,
            origin: Origin::Observed,
            complete,
        }
    }

    /// A packet the host takes in, sorted by its whole header.
    fn host(bytes: Chunk, ingress: Ingress, origin: Origin) -> IpPacket {
        let header = Header::parse_whole(&bytes);
        let transport = Transport::read(header.as_ref(), &bytes);
        IpPacket {
            bytes,
            header,
            transport,
            ingress,
            origin,
            complete: true,
        }
    }

    /// The packet's bytes, IP header first.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Its header, read from [`bytes`](Self::bytes).
    pub fn header(&self) -> Option<&Header> {
        self.header.as_ref()
    }

    /// The bytes after the IP header and any extension headers: the
    /// transport's header and payload, or an ICMP message. Empty when the
    /// header could not be read.
    pub fn payload(&self) -> &[u8] {
        self.header
            .as_ref()
            .map_or(&[][..], |h| h.payload(&self.bytes))
    }

    /// The transport it goes to.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Where it arrived.
    pub fn ingress(&self) -> &Ingress {
        &self.ingress
    }

    /// How its bytes relate to what arrived.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Whether every byte of the packet is here. Always true for a packet
    /// from the IP layer. For a captured copy, false when the capture holds
    /// fewer bytes than the packet had or than its header says.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Its bytes, giving up the rest.
    pub fn into_bytes(self) -> Chunk {
        self.bytes
    }
}

impl Whole for IpPacket {
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
}

/// A host's IP layer: raw packets below, whole checked packets for the
/// transports above. See the [module docs](self).
///
/// It holds at most one packet each way that the other side has not taken,
/// plus one answer, and refuses input (changing nothing) until those are
/// taken. A packet it takes in is either handed up whole, kept as a
/// fragment, or dropped with a report; it never hands back part of one.
///
/// Fragments wait in [`Reassembly`], which holds at most 4 MiB, counting its
/// bookkeeping, as fixed engine state outside the connection's budget. The
/// layer keeps no charge of a packet it takes in: what it hands up is
/// uncharged until a budgeted carrier above reserves it, as
/// [`Packets`]' credit does.
#[derive(Default)]
pub struct IpLayer {
    reassembly: Reassembly,
    up: Option<PacketEvent<IpPacket>>,
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
    fn take_in(&mut self, env: &mut Env<'_, IpReport>, raw: Datagram<Ingress>) {
        let (bytes, ingress) = raw.into_parts();
        let bytes = bytes.into_vec();
        let before = Header::parse(&bytes);
        let fragment = before.as_ref().is_some_and(|h| h.fragment.is_some());
        let original = (!fragment
            && before
                .as_ref()
                .is_some_and(|h| h.src.is_ipv6() && h.payload.start != 40))
        .then(|| Chunk::new(bytes.clone()));
        match self.reassembly.push(Packet(bytes), env.now()) {
            Intake::Whole(Packet(whole)) => {
                let origin = match original {
                    _ if fragment => Origin::Reassembled,
                    Some(original) if original.len() != whole.len() => {
                        Origin::Normalized { original }
                    }
                    _ => Origin::Arrived,
                };
                let packet = IpPacket::host(Chunk::new(whole), ingress, origin);
                self.up = Some(PacketEvent::Packet(packet));
            }
            Intake::Waiting => {}
            Intake::Refused { answer, .. } => {
                let answer = answer.filter(|_| !self.output_closed);
                env.report(IpReport::Refused {
                    answered: answer.is_some(),
                });
                self.answer = answer.map(|Packet(bytes)| Chunk::new(bytes));
            }
        }
    }
}

impl Layer for IpLayer {
    type Lower = Packets<Datagram<Ingress>, Chunk>;
    type Upper = Packets<IpPacket, Chunk>;
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

    fn on_timer(&mut self, env: &mut Env<'_, IpReport>, (): ()) -> Result<(), Infallible> {
        self.reassembly.expire(env.now());
        Ok(())
    }

    fn take_command(&mut self) -> Option<CommandOf<Self::Lower>> {
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

    fn raw(bytes: Vec<u8>) -> PacketEvent<Datagram<Ingress>> {
        PacketEvent::Packet(Datagram::new(Chunk::new(bytes), Ingress::default()))
    }

    fn up(d: &mut Driver<IpLayer>) -> Vec<IpPacket> {
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
        for p in [tcp, datagram, error, ping, gre, vec![0x45]] {
            assert!(matches!(d.deliver(raw(p.clone())), Ok(Admit::Taken)));
            let got = up(&mut d);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].bytes(), &p[..]);
            seen.push(got[0].transport());
        }
        assert_eq!(
            seen,
            [
                Transport::Tcp,
                Transport::Udp,
                Transport::Tcp,
                Transport::Icmp,
                Transport::Other(47),
                Transport::Other(protocol::NONE),
            ]
        );
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
        assert_eq!(got[0].transport(), Transport::Udp);
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
        assert_eq!(back.payload(), &second[..]);
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
        let full = IpPacket::observed(Chunk::new(whole.clone()), capture(whole.len()));
        assert!(full.is_complete());
        assert_eq!(full.transport(), Transport::Tcp);
        let cut = IpPacket::observed(Chunk::new(whole[..30].to_vec()), capture(whole.len()));
        assert!(!cut.is_complete());
        assert_eq!(cut.transport(), Transport::Tcp);
        assert_eq!(cut.payload(), &whole[20..30]);
        assert!(matches!(cut.origin(), Origin::Observed));
        assert_eq!(cut.ingress().capture.unwrap().number, 7);
        let garbage = IpPacket::observed(Chunk::new(vec![0x60, 1]), Ingress::default());
        assert_eq!(garbage.transport(), Transport::Other(protocol::NONE));
        assert!(garbage.header().is_none());
        assert!(!garbage.is_complete());
    }

    #[test]
    fn a_later_fragment_is_not_a_transport_packet_to_an_observer() {
        let whole = ip::packet(addr("10.0.0.2"), addr("10.0.0.1"), protocol::UDP, &udp(100)).0;
        let pieces = fragments(&whole, 32);
        let first = IpPacket::observed(Chunk::new(pieces[0].clone()), Ingress::default());
        let later = IpPacket::observed(Chunk::new(pieces[1].clone()), Ingress::default());
        assert_eq!(first.transport(), Transport::Udp);
        assert_eq!(later.transport(), Transport::Other(protocol::UDP));
    }

    #[test]
    fn a_packet_and_its_original_are_charged_together() {
        let (a, b) = (addr("2001:db8::2"), addr("2001:db8::1"));
        let plain = ip::packet(a, b, protocol::UDP, &udp(3)).0;
        let mut packet = IpPacket {
            bytes: Chunk::new(plain.clone()),
            header: Header::parse_whole(&plain),
            transport: Transport::Udp,
            ingress: Ingress::default(),
            origin: Origin::Normalized {
                original: Chunk::new(vec![0; 64]),
            },
            complete: true,
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

    #[test]
    fn scopes_are_never_shared() {
        let (a, b) = (Scope::tunnel(), Scope::tunnel());
        assert_ne!(a, b);
        assert_ne!(a, Scope::ROOT);
        assert_eq!(Ingress::default().scope, Scope::ROOT);
    }
}
