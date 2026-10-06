//! IP: sorting packets by IP version and by the protocol they carry.
//!
//! Use this module to build a [machine](crate::stdlib#what-you-build-with-it),
//! one IP address on the simulated network. A machine's packets arrive on one
//! [`Interface`], all mixed together. [`split_protocols`] sorts them into
//! four new interfaces: TCP, UDP, ICMP and everything else. You then hand
//! each one to the code for that protocol. No protocol layer
//! knows about the others, and each sees only its own packets.
//!
//! Here a DNS server's machine at `1.1.1.1` gets TCP and UDP on port 53:
//!
//! ```
//! # use fictionet::{Cx, End, Result};
//! # use fictionet::stdlib::{ip, tcp, udp};
//! # fn dns(cx: Cx, dns_side: End) -> Result {
//! let (tcp, udp, icmp, _other) = ip::split_protocols(&cx, dns_side);
//!
//! let tcp = tcp::endpoint(&cx, tcp, "1.1.1.1".parse()?);
//! let mut tcp_listener = tcp.listen(53)?;
//!
//! let udp = udp::endpoint(&cx, udp, "1.1.1.1".parse()?);
//! let mut socket = udp.bind(53)?;
//!
//! // `icmp` is an interface of ICMP packets: answer pings on it with
//! // icmp::echo_reply, or drop it and the machine stays silent to ping.
//! # drop((tcp_listener, socket, icmp));
//! # Ok(())
//! # }
//! ```
//!
//! Each step in that wiring is an ordinary interface carrying IP packets,
//! so you can put your own code between any two of them.
//!
//! Both splits start a background task and return immediately. A packet
//! sent into any of the returned interfaces goes out unchanged on the
//! interface that was split. The task stops when the caller's
//! [region](crate::Cx#regions) is cancelled, when the interface it splits
//! closes, or when all of the interfaces it returned have closed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::task::Poll;

use crate::stdlib::wire::{self, V4, V6};
use crate::stdlib::{Event, Ports};
use crate::time::{Duration, Instant};
use crate::{Cx, End, Interface, Packet};

/// Each interface a split returns holds at most this many bytes of packets
/// each way, counting 64 bytes more for each packet; past that, packets
/// are dropped. A world that keeps an interface it never reads, such as
/// the "everything else" one, would otherwise keep every such packet the
/// agent sends.
const QUEUE: usize = 4 << 20;

fn capped() -> (End, End) {
    crate::cable::pair_with_limit(QUEUE)
}

/// Splits an interface's packets by IP version.
///
/// Starts a background task and returns immediately with three new
/// interfaces:
///
/// 1. IPv4 packets (version field 4),
/// 2. IPv6 packets (version field 6),
/// 3. everything else: any packet the first two did not take, such as an
///    empty packet or one with another version number.
///
/// A packet sent into any of the three goes out on `inner`. The task stops
/// as the [module docs](self) say. Each of the three holds at most 4 MiB of
/// packets each way that its other end has not read yet, counting 64
/// bytes more for each packet. Past that, packets are dropped, as on a
/// congested link.
#[track_caller]
pub fn split_versions(cx: &Cx, inner: impl Interface) -> (End, End, End) {
    let (v4, v4_mine) = capped();
    let (v6, v6_mine) = capped();
    let (other, other_mine) = capped();
    cx.spawn_as(|| "split_versions".into(), move |cx| async move {
        let ports = Ports::new(vec![Box::new(inner), Box::new(v4_mine), Box::new(v6_mine), Box::new(other_mine)]);
        split(cx, ports, None, |packet| match wire::version(&packet.0) {
            Some(4) => 1,
            Some(6) => 2,
            _ => 3,
        })
        .await
    });
    (v4, v6, other)
}

/// The loop behind both splits. Port 0 is the interface being split. Each
/// packet from it goes to the port `sort` names. Packets from every other
/// port go out on port 0. With `reassembly`, packets from port 0 go through
/// [`Reassembly::intake`] before they are sorted.
///
/// It ends when the region is cancelled, when port 0 closes, or when every
/// other port has closed.
async fn split(
    cx: Cx,
    mut ports: Ports,
    mut reassembly: Option<Reassembly>,
    sort: impl Fn(&Packet) -> usize,
) -> crate::Result {
    loop {
        let deadline = reassembly.as_ref().and_then(|r| r.next_expiry());
        match ports.next(&cx, deadline, |_| Poll::Pending).await {
            Event::Packet(0, packet) => {
                let packet = match reassembly.as_mut() {
                    Some(r) => match r.intake(packet, cx.now()) {
                        Intake::Whole(p) => p,
                        Intake::Waiting => continue,
                        Intake::Refused { answer, .. } => {
                            if let Some(answer) = answer {
                                ports.send(0, answer);
                            }
                            continue;
                        }
                    },
                    None => packet,
                };
                let to = sort(&packet);
                ports.send(to, packet);
            }
            Event::Packet(_, packet) => ports.send(0, packet),
            Event::Timer => {
                if let Some(r) = reassembly.as_mut() {
                    r.expire(cx.now());
                }
            }
            Event::Closed(0) | Event::Cancelled | Event::Extra => return Ok(()),
            Event::Closed(_) => {
                if ports.open() <= 1 {
                    return Ok(());
                }
            }
        }
    }
}

/// Splits an interface's packets by the protocol they carry.
///
/// Starts a background task and returns immediately with four new
/// interfaces:
///
/// 1. TCP packets (protocol 6),
/// 2. UDP packets (protocol 17),
/// 3. ICMP packets (protocol 1 in IPv4, 58 in IPv6),
/// 4. everything else.
///
/// Works on IPv4 and IPv6 packets.
///
/// **IPv6 extension headers are checked and taken out.** Each packet's
/// Hop-by-Hop Options, Routing and Destination Options headers are checked
/// as RFC 8200 asks of the packet's destination. A packet that passes
/// leaves with them taken out, so the upper-layer header follows the IPv6
/// header and the protocol layers never see them. A packet that fails is
/// dropped. Where RFC 8200 asks for it, it is also answered with ICMPv6
/// "parameter problem", sent back out on `inner`: for a Routing header with
/// segments left (a machine here forwards no source-routed packets), for
/// Hop-by-Hop Options anywhere but first, and for an unknown option whose
/// type says to answer. An unknown option whose type says to discard the
/// packet drops it with no answer. Pad1, PadN and unknown options whose
/// type says to skip them are ignored. An Authentication header is taken
/// out unchecked, since nothing here runs IPsec. The headers in front of
/// every fragment are checked as it arrives, and a first fragment must hold
/// the whole chain and the upper-layer header (RFC 7112), or it is answered
/// with "parameter problem" code 3.
///
/// **ICMP errors go with the packet they are about.** An ICMP error, such as
/// "packet too big" or "port unreachable", carries the start of the packet
/// that caused it. An error about a TCP packet goes to the TCP end, and one
/// about a UDP packet to the UDP end, so code that reads the TCP end sees
/// the errors about its own connections without reading the ICMP
/// interface. The stdlib's own [`tcp::endpoint`](crate::stdlib::tcp::endpoint)
/// and [`udp::endpoint`](crate::stdlib::udp::endpoint) drop them. Pings and
/// other ICMP messages go to the ICMP end.
///
/// **Fragments are put back together first.** A fragmented packet only
/// names its protocol in the first fragment, so fragments are reassembled
/// before they are sorted. Fragments that never complete are dropped after
/// a timeout, as a kernel does.
///
/// A packet sent into any of the four goes out on `inner`. The task stops
/// as the [module docs](self) say. Each of the four holds at most 4 MiB of
/// packets each way that its other end has not read yet, counting 64
/// bytes more for each packet. Past that, packets are dropped, as on a
/// congested link.
///
/// Reassembly follows RFC 791 and RFC 8200. Fragments of one packet are
/// matched by source, destination, identification and, for IPv4, protocol.
/// A packet whose fragments overlap is dropped whole (RFC 5722), and so is
/// one whose fragments disagree on its length. An exact copy of a fragment
/// that is already waiting is ignored, but a fragment at the same place
/// with other bytes is an overlap. A copy whose "more fragments" flag
/// differs is not a copy. Once a packet is dropped this way, its later
/// fragments are dropped too, so they cannot start it again: until the
/// time it would have waited is up, or until the 4 MiB cap below pushes it
/// out as the oldest. Unfinished
/// packets are dropped 30 seconds (IPv4) or 60 seconds (IPv6) after their
/// first fragment arrived. At most 4 MiB of fragments wait at any one time,
/// counting a little bookkeeping for each fragment, so many tiny fragments
/// count for more than their bytes. Past that, the oldest unfinished packet
/// is dropped. Each fragment costs the same small amount of work, however
/// many are waiting.
#[track_caller]
pub fn split_protocols(cx: &Cx, inner: impl Interface) -> (End, End, End, End) {
    let (tcp, tcp_mine) = capped();
    let (udp, udp_mine) = capped();
    let (icmp, icmp_mine) = capped();
    let (other, other_mine) = capped();
    cx.spawn_as(|| "split_protocols".into(), move |cx| async move {
        let ports = Ports::new(vec![
            Box::new(inner),
            Box::new(tcp_mine),
            Box::new(udp_mine),
            Box::new(icmp_mine),
            Box::new(other_mine),
        ]);
        split(cx, ports, Some(Reassembly::default()), |packet| match protocol(&packet.0) {
            wire::PROTO_TCP => 1,
            wire::PROTO_UDP => 2,
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => 3,
            _ => 4,
        })
        .await
    });
    (tcp, udp, icmp, other)
}

/// Which end of [`split_protocols`] a whole (not fragmented) packet belongs
/// to, as a protocol number: TCP, UDP, ICMP (1 for both versions' ICMP), or
/// anything else for the last end. ICMP errors are sorted by the protocol
/// of the packet they quote.
pub(crate) fn protocol(packet: &[u8]) -> u8 {
    const OTHER: u8 = wire::PROTO_NONE;
    match wire::version(packet) {
        Some(4) => {
            let Some(ip) = V4::parse(packet, false) else { return OTHER };
            if ip.is_fragment() {
                return OTHER;
            }
            match ip.proto() {
                wire::PROTO_ICMP => {
                    let icmp = ip.payload();
                    // Destination unreachable (including "fragmentation
                    // needed"), source quench, time exceeded, parameter
                    // problem.
                    if icmp.len() >= 8 && matches!(icmp[0], 3 | 4 | 11 | 12)
                        && let Some(proto) = quoted_protocol(&icmp[8..])
                    {
                        return proto;
                    }
                    wire::PROTO_ICMP
                }
                p => p,
            }
        }
        Some(6) => {
            let Ok(chain) = wire::ext6_chain(packet) else { return OTHER };
            if chain.frag.is_some() {
                return OTHER;
            }
            match chain.proto {
                wire::PROTO_ICMPV6 => {
                    let icmp = &packet[chain.upper..chain.end];
                    // Types below 128 are errors: destination unreachable,
                    // packet too big, time exceeded, parameter problem.
                    if icmp.len() >= 8 && icmp[0] < 128 && let Some(proto) = quoted_protocol(&icmp[8..]) {
                        return proto;
                    }
                    wire::PROTO_ICMP
                }
                p => p,
            }
        }
        _ => OTHER,
    }
}

/// The protocol of the packet quoted in an ICMP error, if it is TCP or UDP.
fn quoted_protocol(quoted: &[u8]) -> Option<u8> {
    let proto = match wire::version(quoted)? {
        4 => {
            let ip = V4::parse(quoted, true)?;
            if ip.frag_offset() != 0 {
                return None;
            }
            ip.proto()
        }
        6 => {
            let ip = V6::parse(quoted, true)?;
            if let Some((at, _)) = ip.frag && u16::from_be_bytes([quoted[at + 2], quoted[at + 3]]) & 0xfff8 != 0 {
                return None;
            }
            ip.proto
        }
        _ => return None,
    };
    matches!(proto, wire::PROTO_TCP | wire::PROTO_UDP).then_some(proto)
}

/// How long an unfinished IPv4 packet waits for its fragments, as Linux's
/// `ipfrag_time`.
const V4_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an unfinished IPv6 packet waits (RFC 8200, section 4.5).
const V6_TIMEOUT: Duration = Duration::from_secs(60);
/// At most this many bytes of fragments wait at any one time, counting
/// [`PIECE_COST`] and [`PARTIAL_COST`] for the bookkeeping.
const MAX_WAITING: usize = 4 << 20;
/// What one waiting fragment costs beyond its data: its map entry and
/// vector. Counted so that a flood of tiny fragments hits the cap as soon
/// as large ones would.
const PIECE_COST: usize = 64;
/// What one unfinished packet costs beyond its fragments.
const PARTIAL_COST: usize = 192;

/// Which packet a fragment belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Key {
    V4 { src: Ipv4Addr, dst: Ipv4Addr, id: u16, proto: u8 },
    V6 { src: Ipv6Addr, dst: Ipv6Addr, id: u32 },
}

/// One packet being put back together, or dropped.
struct Partial {
    /// The packet was dropped for a bad fragment ([`Reassembly::kill`]).
    /// It stays, with no fragments, until it expires, so that its later
    /// fragments are dropped too.
    dead: bool,
    /// From the first fragment: the headers that go in front of the data.
    /// For IPv6, the "next header" byte that named the fragment header
    /// already names what the fragment header named.
    header: Option<Vec<u8>>,
    /// Data by offset. Never overlapping.
    pieces: BTreeMap<usize, Vec<u8>>,
    /// The length of the data, once the last fragment has arrived.
    total: Option<usize>,
    /// Data bytes in `pieces`. Pieces never overlap and never pass
    /// `total`, so the packet is whole when this reaches `total`.
    have: usize,
    /// Bytes counted against [`MAX_WAITING`] for this packet.
    size: usize,
    expires: Instant,
}

/// Fragment reassembly, for [`split_protocols`] and for each sandbox's
/// filter in [`net::Net`](crate::stdlib::net::Net).
///
/// Every step costs at most a logarithm of the number of unfinished
/// packets, since the agent decides how many there are. At most 4 MiB of
/// fragments wait at once; past that, the packets that expire soonest are
/// dropped. IPv4 packets wait at most 30 seconds, IPv6 packets 60.
#[derive(Default)]
pub struct Reassembly {
    partial: HashMap<Key, Partial>,
    /// Every unfinished packet by when it expires, soonest first.
    by_expiry: BTreeSet<(Instant, Key)>,
    size: usize,
}

/// What [`Reassembly::intake`] made of a packet.
#[derive(Debug)]
pub enum Intake {
    /// A whole packet. An IPv6 packet's extension headers are checked and
    /// taken out.
    Whole(Packet),
    /// A fragment, waiting for the rest of its packet.
    Waiting,
    /// A packet dropped for its IPv6 extension headers: the packet, and the
    /// ICMPv6 "parameter problem" its destination sends back to its source,
    /// if RFC 8200 asks for one.
    Refused {
        /// The packet that was refused.
        packet: Packet,
        /// The ICMPv6 "parameter problem" to send back, if any.
        answer: Option<Packet>,
    },
}

/// One fragment, read from a packet.
struct Fragment<'a> {
    key: Key,
    offset: usize,
    more: bool,
    data: &'a [u8],
    /// The headers in front of the data, ready to use, if this is the first
    /// fragment.
    header: Option<Vec<u8>>,
    timeout: Duration,
}

impl Reassembly {
    /// Takes a packet from the agent's side, as a host takes it in.
    ///
    /// An IPv6 packet's extension headers are checked with
    /// `wire::ext6_chain` as it arrives, fragment or not. So the headers
    /// in front of every fragment are checked, not only the first
    /// fragment's (RFC 8200, section 4.5), and a first fragment must hold
    /// the whole chain (RFC 7112). Fragments are then put back together
    /// (`push`). A whole IPv6 packet is checked again
    /// and its extension headers taken out (`wire::strip_ext6`); that
    /// also drops a packet whose fragments held another fragment.
    pub fn intake(&mut self, packet: Packet, now: Instant) -> Intake {
        let refused = |packet: Packet, reject| {
            let answer = wire::parameter_problem(&packet.0, reject).map(Packet);
            Intake::Refused { packet, answer }
        };
        if wire::version(&packet.0) == Some(6)
            && let Err(reject) = wire::ext6_chain(&packet.0)
        {
            return refused(packet, reject);
        }
        let Some(whole) = self.push(packet, now) else { return Intake::Waiting };
        if wire::version(&whole.0) != Some(6) {
            return Intake::Whole(whole);
        }
        match wire::strip_ext6(&whole.0) {
            Ok(None) => Intake::Whole(whole),
            Ok(Some(stripped)) => Intake::Whole(Packet(stripped)),
            Err(reject) => refused(whole, reject),
        }
    }

    /// Takes a packet. Returns it if it is not a fragment, the whole packet
    /// if this fragment completed one, and `None` otherwise.
    pub(crate) fn push(&mut self, packet: Packet, now: Instant) -> Option<Packet> {
        let whole = self.push_fragment(packet, now);
        // Every path that may have added bookkeeping ends here, so the cap
        // holds after each packet.
        while self.size > MAX_WAITING {
            match self.by_expiry.first() {
                Some(&(_, k)) => self.remove(&k),
                None => break,
            }
        }
        whole
    }

    /// [`push`](Reassembly::push), without the cap.
    fn push_fragment(&mut self, packet: Packet, now: Instant) -> Option<Packet> {
        let Some(frag) = fragment(&packet.0) else { return Some(packet) };
        // A packet in one fragment needs no waiting (RFC 6946).
        if frag.offset == 0 && !frag.more {
            let header = frag.header?;
            return finish(header, &[(0, frag.data)], frag.data.len()).map(Packet);
        }
        // Every fragment but the last carries a multiple of 8 bytes, and
        // every fragment carries some.
        if (frag.more && frag.data.len() % 8 != 0) || frag.data.is_empty() {
            return None;
        }
        let end = frag.offset + frag.data.len();
        let key = frag.key;
        if end > 65_535 {
            self.kill(&key);
            return None;
        }
        let by_expiry = &mut self.by_expiry;
        let size = &mut self.size;
        let partial = self.partial.entry(key).or_insert_with(|| {
            let expires = crate::stdlib::later(now, frag.timeout);
            by_expiry.insert((expires, key));
            *size += PARTIAL_COST;
            Partial {
                dead: false,
                header: None,
                pieces: BTreeMap::new(),
                total: None,
                have: 0,
                size: PARTIAL_COST,
                expires,
            }
        });
        if partial.dead {
            return None;
        }
        // An exact copy of a fragment that is already here, with the same
        // bytes and the same "more fragments" flag, is ignored. Fragments
        // never overlap and carry data, so the one that ends at the length
        // is the last fragment.
        if let Some((o, d)) = partial.pieces.range(..=frag.offset).next_back()
            && *o == frag.offset
            && d.as_slice() == frag.data
        {
            let was_last = partial.total == Some(end);
            if was_last != frag.more {
                return None;
            }
            self.kill(&key);
            return None;
        }
        let mut ok = true;
        // The last fragment sets the length. It must agree with the data.
        if !frag.more {
            match partial.total {
                Some(t) if t != end => ok = false,
                _ => {}
            }
            if partial.pieces.iter().next_back().is_some_and(|(o, d)| o + d.len() > end) {
                ok = false;
            }
            partial.total = Some(end);
        } else if partial.total.is_some_and(|t| end >= t) {
            ok = false;
        }
        // Any other overlap drops the whole packet, including the same
        // place with other bytes (RFC 5722).
        if ok {
            if let Some((o, d)) = partial.pieces.range(..=frag.offset).next_back()
                && o + d.len() > frag.offset
            {
                ok = false;
            }
            if let Some((o, _)) = partial.pieces.range(frag.offset + 1..).next() && *o < end {
                ok = false;
            }
        }
        if !ok {
            self.kill(&key);
            return None;
        }
        let mut added = frag.data.len() + PIECE_COST;
        if let Some(h) = frag.header && partial.header.is_none() {
            added += h.len();
            partial.header = Some(h);
        }
        partial.pieces.insert(frag.offset, frag.data.to_vec());
        partial.have += frag.data.len();
        partial.size += added;
        self.size += added;
        // Complete when the pieces cover the data. They never overlap and
        // never pass the end, so counting their bytes is enough.
        if partial.header.is_some() && partial.total == Some(partial.have) {
            let partial = self.take(&key).unwrap();
            let pieces: Vec<(usize, &[u8])> = partial.pieces.iter().map(|(o, d)| (*o, d.as_slice())).collect();
            return finish(partial.header.unwrap(), &pieces, partial.have).map(Packet);
        }
        None
    }

    /// Takes an unfinished packet out, with its bookkeeping.
    fn take(&mut self, key: &Key) -> Option<Partial> {
        let p = self.partial.remove(key)?;
        self.size -= p.size;
        self.by_expiry.remove(&(p.expires, *key));
        Some(p)
    }

    fn remove(&mut self, key: &Key) {
        self.take(key);
    }

    /// Drops a packet for a bad fragment: frees its fragments, and keeps it
    /// as dead until it expires, so its later fragments are dropped too
    /// (RFC 5722).
    fn kill(&mut self, key: &Key) {
        let Some(p) = self.partial.get_mut(key) else { return };
        self.size -= p.size - PARTIAL_COST;
        p.size = PARTIAL_COST;
        p.dead = true;
        p.header = None;
        p.pieces = BTreeMap::new();
        p.have = 0;
    }

    /// When the next unfinished packet times out.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.by_expiry.first().map(|(t, _)| *t)
    }

    /// Panics if the bookkeeping is wrong: the sizes do not add up, the
    /// cap is passed, the expiry index and the map disagree, or pieces
    /// overlap. For tests and fuzzing.
    #[cfg(any(test, fuzzing))]
    pub(crate) fn check(&self) {
        assert!(self.size <= MAX_WAITING, "{} bytes wait", self.size);
        assert_eq!(self.partial.len(), self.by_expiry.len());
        let mut size = 0;
        for (key, p) in &self.partial {
            assert!(self.by_expiry.contains(&(p.expires, *key)));
            let mut end = 0;
            let mut have = 0;
            for (o, d) in &p.pieces {
                assert!(*o >= end, "pieces overlap");
                end = o + d.len();
                have += d.len();
            }
            assert_eq!(have, p.have);
            assert!(p.total.is_none_or(|t| end <= t));
            size += p.size;
        }
        assert_eq!(size, self.size);
    }

    /// Drops every unfinished packet whose time is up.
    pub fn expire(&mut self, now: Instant) {
        while let Some(&(t, k)) = self.by_expiry.first() {
            if t > now {
                break;
            }
            self.remove(&k);
        }
    }
}

/// Reads a fragment. `None` if the packet is not a fragment, or cannot be
/// read.
fn fragment(packet: &[u8]) -> Option<Fragment<'_>> {
    match wire::version(packet)? {
        4 => {
            let ip = V4::parse(packet, false)?;
            if !ip.is_fragment() {
                return None;
            }
            let header = (ip.frag_offset() == 0).then(|| packet[..ip.ihl].to_vec());
            Some(Fragment {
                key: Key::V4 { src: ip.src(), dst: ip.dst(), id: ip.id(), proto: ip.proto() },
                offset: ip.frag_offset(),
                more: ip.more_fragments(),
                data: ip.payload(),
                header,
                timeout: V4_TIMEOUT,
            })
        }
        6 => {
            let ip = V6::parse(packet, false)?;
            let (at, next_at) = wire::ext6_chain(packet).ok()?.frag?;
            let f = &packet[at..at + 8];
            let off_m = u16::from_be_bytes([f[2], f[3]]);
            let offset = (off_m & 0xfff8) as usize;
            let header = (offset == 0).then(|| {
                let mut h = packet[..at].to_vec();
                h[next_at] = f[0];
                h
            });
            Some(Fragment {
                key: Key::V6 { src: ip.src(), dst: ip.dst(), id: u32::from_be_bytes([f[4], f[5], f[6], f[7]]) },
                offset,
                more: off_m & 1 != 0,
                data: &packet[at + 8..ip.end],
                header,
                timeout: V6_TIMEOUT,
            })
        }
        _ => None,
    }
}

/// Builds the whole packet from the first fragment's headers and the data.
/// `None` if it would be longer than its header's length field can say:
/// 65,535 bytes for IPv4, and 65,535 bytes after the fixed header for
/// IPv6. The data alone stays within 65,535 bytes, but headers come on top.
fn finish(mut header: Vec<u8>, pieces: &[(usize, &[u8])], total: usize) -> Option<Vec<u8>> {
    let head = header.len();
    let len = if header[0] >> 4 == 4 { head + total } else { head - 40 + total };
    let len = u16::try_from(len).ok()?;
    header.reserve(total);
    for (_, d) in pieces {
        header.extend_from_slice(d);
    }
    if header[0] >> 4 == 4 {
        header[2..4].copy_from_slice(&len.to_be_bytes());
        // No more fragments, offset 0. Keep "don't fragment".
        header[6] &= 0x40;
        header[7] = 0;
        wire::set_v4_checksum(&mut header[..head]);
    } else {
        header[4..6].copy_from_slice(&len.to_be_bytes());
    }
    Some(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 fragment of a packet with identification `id`: `len` data bytes
    /// at `offset`.
    fn frag4(id: u16, offset: usize, len: usize, more: bool) -> Packet {
        frag4_of(id, offset, &vec![0xab; len], more)
    }

    /// The same, with `data` as the data.
    fn frag4_of(id: u16, offset: usize, data: &[u8], more: bool) -> Packet {
        let mut h = wire::v4_header(wire::PROTO_UDP, Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(1, 1, 1, 1), 64, id, 0, &[], data.len());
        let flags: u16 = if more { 0x2000 } else { 0 };
        h[6..8].copy_from_slice(&((offset / 8) as u16 | flags).to_be_bytes());
        wire::set_v4_checksum(&mut h[..20]);
        h.extend_from_slice(data);
        Packet(h)
    }

    /// How many packets are being put back together, not counting the
    /// dropped ones that wait to expire.
    fn live(r: &Reassembly) -> usize {
        r.partial.values().filter(|p| !p.dead).count()
    }

    fn at(secs: u64) -> Instant {
        Instant::from_since_start(Duration::from_secs(secs))
    }

    #[test]
    fn unfinished_packets_time_out() {
        let mut r = Reassembly::default();
        assert!(r.push(frag4(1, 0, 16, true), at(0)).is_none());
        assert_eq!(r.next_expiry(), Some(at(30)));
        r.expire(at(29));
        assert_eq!(r.partial.len(), 1);
        r.expire(at(30));
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
        // The rest alone does not make a packet: the first fragment is gone.
        assert!(r.push(frag4(1, 16, 8, false), at(31)).is_none());
        // Within the time, both halves make one.
        assert!(r.push(frag4(2, 0, 16, true), at(40)).is_none());
        let whole = r.push(frag4(2, 16, 8, false), at(69)).expect("a whole packet");
        assert_eq!(whole.0.len(), 20 + 24);
        assert_eq!(wire::checksum(0, &whole.0[..20]), 0);
    }

    #[test]
    fn waiting_fragments_are_capped() {
        let mut r = Reassembly::default();
        // 600 unfinished packets of 8,000 bytes is more than 4 MiB.
        for id in 0..600u16 {
            let t = Instant::from_since_start(Duration::from_millis(id as u64));
            assert!(r.push(frag4(id, 0, 8000, true), t).is_none());
            r.check();
        }
        assert!(r.partial.len() < 600);
        // The oldest went first.
        assert!(!r.partial.contains_key(&Key::V4 {
            src: Ipv4Addr::new(10, 0, 0, 2),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            id: 0,
            proto: wire::PROTO_UDP
        }));
    }

    #[test]
    fn tiny_fragments_count_their_bookkeeping() {
        let mut r = Reassembly::default();
        // 8-byte fragments of 200,000 different packets: far more memory
        // than their bytes, so the cap holds them to a few thousand.
        for i in 0..200_000u32 {
            let t = Instant::from_since_start(Duration::from_micros(i as u64));
            let mut f = frag4((i % 65_536) as u16, 0, 8, true);
            f.0[15] = (i / 65_536) as u8; // another source for each round of ids
            wire::set_v4_checksum(&mut f.0[..20]);
            assert!(r.push(f, t).is_none());
            assert!(r.size <= MAX_WAITING);
        }
        assert!(r.partial.len() < MAX_WAITING / PARTIAL_COST);
        assert_eq!(r.partial.len(), r.by_expiry.len());
        // The ones left are the newest, and they expire in order.
        let first = r.next_expiry().unwrap();
        r.expire(first);
        assert_eq!(r.partial.len(), r.by_expiry.len());
        r.expire(at(1_000));
        assert!(r.partial.is_empty() && r.by_expiry.is_empty());
        assert_eq!(r.size, 0);
    }

    #[test]
    fn fragments_in_any_order_make_one_packet() {
        let mut r = Reassembly::default();
        // The last first, then the middle ones backward, then the first.
        assert!(r.push(frag4(9, 64, 5, false), at(0)).is_none());
        for k in (1..8).rev() {
            assert!(r.push(frag4(9, k * 8, 8, true), at(0)).is_none());
        }
        r.check();
        let whole = r.push(frag4(9, 0, 8, true), at(0)).expect("a whole packet");
        assert_eq!(whole.0.len(), 20 + 69);
        assert!(r.partial.is_empty() && r.by_expiry.is_empty());
        assert_eq!(r.size, 0);
    }

    /// Fragments whose data ends at the last offset an IPv4 header can
    /// name, behind a first fragment with 40 bytes of options: 65,595
    /// bytes in all, more than an IP packet can hold. Found while writing
    /// the `ip_reassembly` fuzz target: the length field wrapped around.
    #[test]
    fn a_whole_packet_longer_than_ip_allows_is_dropped() {
        let mut r = Reassembly::default();
        let mut offset = 0;
        while offset < 65_535 {
            let len = 1480.min(65_535 - offset);
            let more = offset + len < 65_535;
            let options: &[u8] = if offset == 0 { &[1; 40] } else { &[] };
            let src = Ipv4Addr::new(10, 0, 0, 2);
            let mut h = wire::v4_header(wire::PROTO_UDP, src, Ipv4Addr::new(1, 1, 1, 1), 64, 7, 0, options, len);
            let flags: u16 = if more { 0x2000 } else { 0 };
            h[6..8].copy_from_slice(&((offset / 8) as u16 | flags).to_be_bytes());
            let ihl = h.len();
            wire::set_v4_checksum(&mut h[..ihl]);
            h.extend(std::iter::repeat_n(0xab, len));
            assert_eq!(r.push(Packet(h), at(0)), None, "a packet of {} bytes came out", 40 + 20 + offset + len);
            offset += len;
        }
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
    }

    /// The same for IPv6: extension headers before the fragment header
    /// count toward the 65,535 bytes of payload too.
    #[test]
    fn a_whole_ipv6_packet_longer_than_ip_allows_is_dropped() {
        let mut r = Reassembly::default();
        let mut offset = 0;
        while offset < 65_535 {
            let len = 1448.min(65_535 - offset);
            let more = offset + len < 65_535;
            // A destination options header (16 bytes), then the fragment
            // header, then the data.
            let mut p = vec![0x60, 0, 0, 0];
            p.extend_from_slice(&((16 + 8 + len) as u16).to_be_bytes());
            p.extend_from_slice(&[60, 64]);
            p.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            p.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            p.extend_from_slice(&[wire::PROTO_IPV6_FRAG, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            p.push(wire::PROTO_UDP);
            p.push(0);
            p.extend_from_slice(&(offset as u16 | more as u16).to_be_bytes());
            p.extend_from_slice(&9u32.to_be_bytes());
            p.extend(std::iter::repeat_n(0xab, len));
            assert_eq!(r.push(Packet(p), at(0)), None, "a packet came out at offset {offset}");
            offset += len;
        }
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
    }

    /// A world that keeps an interface it never reads does not keep every
    /// packet the agent sends there.
    #[test]
    fn an_interface_never_read_holds_at_most_its_queue() {
        let result = crate::block_on(crate::run(|cx| async move {
            let (mut raw, side) = crate::pair();
            let (_tcp, _udp, _icmp, other) = split_protocols(&cx, side);
            // 20 MiB of protocol 99, which goes to `other`.
            for _ in 0..20 * 1024 {
                let h = wire::v4_header(99, Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 64, 0, 0, &[], 1000);
                let mut p = h;
                p.extend_from_slice(&[0; 1000]);
                raw.send(Packet(p));
                cx.yield_now().await?;
            }
            assert!(other.queued() <= QUEUE, "{} bytes wait", other.queued());
            assert!(other.queued() > QUEUE / 2, "{} bytes wait", other.queued());
            Err::<(), crate::Error>("done".into())
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    #[test]
    fn bad_fragments_are_dropped() {
        let mut r = Reassembly::default();
        // Not a multiple of 8 with more to come.
        assert!(r.push(frag4(3, 0, 13, true), at(0)).is_none());
        assert!(r.partial.is_empty());
        // Past 65,535 bytes: nothing is kept for a packet not yet started.
        assert!(r.push(frag4(4, 65_528, 16, false), at(0)).is_none());
        assert!(r.partial.is_empty());
        // Two different lengths for one packet.
        assert!(r.push(frag4(5, 16, 8, false), at(0)).is_none());
        assert!(r.push(frag4(5, 32, 8, false), at(0)).is_none());
        assert_eq!(live(&r), 0);
        // What is left of it is its bookkeeping, until it expires.
        assert_eq!(r.size, PARTIAL_COST);
        r.check();
        r.expire(at(30));
        assert!(r.partial.is_empty() && r.by_expiry.is_empty());
        assert_eq!(r.size, 0);
        // Truncated packets are not fragments and pass through as they are.
        let mut cut = frag4(6, 0, 16, true);
        cut.0.truncate(30);
        assert_eq!(r.push(cut.clone(), at(0)), Some(cut));
    }

    #[test]
    fn conflicting_copies_drop_the_packet_until_it_expires() {
        let mut r = Reassembly::default();
        let first = [1u8; 16];
        let mut other = first;
        other[8] = 2;
        // The same place, other bytes: an overlap (RFC 5722).
        assert!(r.push(frag4_of(1, 0, &first, true), at(0)).is_none());
        assert!(r.push(frag4_of(1, 0, &other, true), at(0)).is_none());
        assert_eq!(live(&r), 0);
        // Its later fragments cannot start it again.
        assert!(r.push(frag4_of(1, 0, &first, true), at(10)).is_none());
        assert!(r.push(frag4(1, 16, 8, false), at(10)).is_none());
        assert_eq!(live(&r), 0);
        // Once its time is up, the identification can be used again.
        r.expire(at(30));
        assert!(r.partial.is_empty());
        assert!(r.push(frag4_of(1, 0, &first, true), at(31)).is_none());
        let whole = r.push(frag4(1, 16, 8, false), at(31)).expect("a whole packet");
        assert_eq!(&whole.0[20..36], &first);
        // An exact copy is ignored.
        assert!(r.push(frag4_of(2, 0, &first, true), at(40)).is_none());
        assert!(r.push(frag4_of(2, 0, &first, true), at(40)).is_none());
        assert!(r.push(frag4(2, 16, 8, false), at(40)).is_some());
    }

    /// Fragments that run past 65,535 bytes keep nothing, however many
    /// packets they name.
    #[test]
    fn fragments_too_long_for_ip_keep_nothing() {
        let mut r = Reassembly::default();
        for id in 0..20_000u16 {
            assert!(r.push(frag4(id, 65_528, 16, false), at(0)).is_none());
        }
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
        // Dead entries count against the cap like any other.
        for id in 0..40_000u32 {
            let mut first = frag4_of((id % 65_536) as u16, 0, &[1; 16], true);
            first.0[15] = (id / 65_536) as u8 + 1;
            wire::set_v4_checksum(&mut first.0[..20]);
            let mut other = first.clone();
            other.0[28] ^= 1;
            r.push(first, at(0));
            r.push(other, at(0));
            if id % 4_000 == 0 {
                r.check();
            }
        }
        r.check();
    }

    /// A copy of a fragment with the same bytes but another "more
    /// fragments" flag is not a copy: it says the packet ends somewhere
    /// else.
    #[test]
    fn a_copy_with_another_more_flag_drops_the_packet() {
        for last_first in [false, true] {
            let mut r = Reassembly::default();
            let (a, b) = if last_first { (false, true) } else { (true, false) };
            assert!(r.push(frag4_of(1, 8, &[2; 8], a), at(0)).is_none());
            assert!(r.push(frag4_of(1, 8, &[2; 8], b), at(0)).is_none());
            assert!(r.push(frag4_of(1, 0, &[1; 8], true), at(0)).is_none(), "last first: {last_first}");
            assert!(r.push(frag4_of(1, 16, &[3; 8], false), at(0)).is_none(), "last first: {last_first}");
            assert_eq!(live(&r), 0);
            r.check();
        }
        // A true copy of the last fragment is still ignored.
        let mut r = Reassembly::default();
        assert!(r.push(frag4_of(1, 8, &[2; 8], false), at(0)).is_none());
        assert!(r.push(frag4_of(1, 8, &[2; 8], false), at(0)).is_none());
        assert!(r.push(frag4_of(1, 0, &[1; 8], true), at(0)).is_some());
    }
}

// ---------------------------------------------------------------------------
// Reading and building IP headers, for code that sees whole packets

/// The IP version of a packet, from the top four bits of its first byte:
/// 4 or 6 for an IP packet. `None` for an empty packet.
pub fn version(packet: &[u8]) -> Option<u8> {
    wire::version(packet)
}

/// The destination address of an IPv4 or IPv6 packet, if its fixed header
/// is there.
pub fn destination(packet: &[u8]) -> Option<std::net::IpAddr> {
    wire::destination(packet)
}

/// A checked view of an IPv4 or IPv6 header: what a filter or a router
/// needs to decide where a packet goes.
///
/// Every reader checks lengths, since the agent can send any bytes it
/// likes. For IPv6, the extension headers are walked to find the
/// upper-layer protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// The source address.
    pub src: std::net::IpAddr,
    /// The destination address.
    pub dst: std::net::IpAddr,
    /// The upper-layer protocol: 6 for TCP, 17 for UDP, 1 for ICMP, 58 for
    /// ICMPv6. For IPv6, the protocol after the extension headers, or 59
    /// ("no next header") when they could not be read.
    pub protocol: u8,
    /// Where the upper-layer header starts and the packet ends, as byte
    /// offsets into the packet. The end is cut to the bytes present.
    pub payload: std::ops::Range<usize>,
    /// Whether the packet is a fragment of a larger one.
    pub fragment: bool,
    /// The fragment's offset in its packet, in bytes. Zero for the first
    /// fragment and for a whole packet. Only the first fragment carries
    /// the upper-layer header.
    pub fragment_offset: usize,
}

impl Header {
    /// Reads the header of a whole packet, whose length fields fit the
    /// bytes present. `None` if it is not IPv4 or IPv6, or is cut short.
    pub fn parse(packet: &[u8]) -> Option<Header> {
        Header::read(packet, false)
    }

    /// Reads a header that may be followed by fewer bytes than its length
    /// field says, as the copy of a packet inside an ICMP error is, or a
    /// packet a world logs without trusting.
    pub fn parse_truncated(packet: &[u8]) -> Option<Header> {
        Header::read(packet, true)
    }

    fn read(packet: &[u8], truncated: bool) -> Option<Header> {
        if let Some(v4) = V4::parse(packet, truncated) {
            return Some(Header {
                src: v4.src().into(),
                dst: v4.dst().into(),
                protocol: v4.proto(),
                payload: v4.ihl..v4.total,
                fragment: v4.is_fragment(),
                fragment_offset: v4.frag_offset(),
            });
        }
        let v6 = V6::parse(packet, truncated)?;
        let offset = v6.frag.map_or(0, |(at, _)| usize::from(u16::from_be_bytes([packet[at + 2], packet[at + 3]]) & 0xfff8));
        Some(Header {
            src: v6.src().into(),
            dst: v6.dst().into(),
            protocol: v6.proto,
            payload: v6.upper..v6.end,
            fragment: v6.frag.is_some(),
            fragment_offset: offset,
        })
    }

    /// Reads the header of a whole packet that a host would take in: not a
    /// fragment, and for IPv6, with extension headers a host accepts.
    /// This is what the TCP and UDP endpoints read.
    pub fn parse_whole(packet: &[u8]) -> Option<Header> {
        let ip = crate::stdlib::udp::parse_ip(packet)?;
        Some(Header { src: ip.src, dst: ip.dst, protocol: ip.proto, payload: ip.payload..ip.end, fragment: false, fragment_offset: 0 })
    }

    /// The upper-layer bytes of `packet`, which this header was read from.
    pub fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        packet.get(self.payload.clone()).unwrap_or_default()
    }
}

/// Builds an IP packet from `src` to `dst` around `payload`, with a TTL or
/// hop limit of 64. The IPv4 header checksum is filled in. The payload's
/// own checksum must already be done: see [`transport_checksum`]. `src`
/// and `dst` must be of the same family.
pub fn packet(src: std::net::IpAddr, dst: std::net::IpAddr, protocol: u8, payload: &[u8]) -> Packet {
    crate::stdlib::udp::ip_packet(src, dst, protocol, 0, payload)
}

/// The TCP, UDP or ICMPv6 checksum of `data` over the pseudo-header for
/// `src`, `dst` and `protocol`. Over data whose checksum field is filled
/// in, a correct checksum gives 0.
pub fn transport_checksum(src: std::net::IpAddr, dst: std::net::IpAddr, protocol: u8, data: &[u8]) -> u16 {
    crate::stdlib::udp::transport_checksum(src, dst, protocol, data)
}

/// Whether a UDP datagram has a good checksum. A zero checksum field means
/// "no checksum" over IPv4, and is never valid over IPv6.
pub fn udp_checksum_ok(src: std::net::IpAddr, dst: std::net::IpAddr, udp: &[u8]) -> bool {
    crate::stdlib::udp::udp_checksum_ok(src, dst, udp)
}
