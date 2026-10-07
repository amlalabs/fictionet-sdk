//! IP: sorting packets by IP version and by the protocol they carry, and
//! reading, checking and building IP headers.
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
//! # fn dns(fcx: Cx, dns_side: End) -> Result {
//! let (tcp, udp, icmp, _other) = ip::split_protocols(&fcx, dns_side);
//!
//! let tcp = tcp::endpoint(&fcx, tcp, "1.1.1.1".parse()?);
//! let mut tcp_listener = tcp.listen(53)?;
//!
//! let udp = udp::endpoint(&fcx, udp, "1.1.1.1".parse()?);
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
//!
//! # Reading and building packets
//!
//! This module is also the stdlib's one IP layer: the TCP, UDP and ICMP
//! modules, the router and `Net` all read and build packets with it, so
//! code of your own between two interfaces can too.
//!
//! - [`Header`] reads an IPv4 or IPv6 header with every length checked.
//!   [`Header::check`] also checks IPv6 extension headers as a host must
//!   (RFC 8200), and [`parameter_problem`] builds the answer to a packet it
//!   refuses. One walker reads the extension headers for every reader, so
//!   they all agree on the upper-layer protocol.
//! - [`checksum`] is the Internet checksum, [`transport_checksum`] adds the
//!   TCP, UDP or ICMPv6 pseudo-header, and [`set_header_checksum`] redoes an
//!   IPv4 header's.
//! - [`packet`] and [`packet_with`] put an IP header in front of a payload.
//!   [`hop`] lowers the TTL as a router does.
//!
//! ```
//! use fictionet::stdlib::ip::{self, Header, protocol};
//!
//! let (src, dst) = ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
//! let mut udp = vec![0, 1, 0, 53, 0, 8, 0, 0];
//! let sum = ip::transport_checksum(src, dst, protocol::UDP, &udp);
//! udp[6..8].copy_from_slice(&sum.to_be_bytes());
//! let packet = ip::packet(src, dst, protocol::UDP, &udp);
//!
//! let header = Header::parse(&packet.0).unwrap();
//! assert_eq!((header.src, header.protocol), (src, protocol::UDP));
//! assert!(ip::udp_checksum_ok(src, dst, header.payload(&packet.0)));
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::task::Poll;

use fictionet::stdlib::{PortEvent as Event, Ports, icmp};
use fictionet::time::{Duration, Instant};
use fictionet::{Cx, End, Interface, Packet};

/// Each interface a split returns holds at most this many bytes of packets
/// each way, counting 64 bytes more for each packet; past that, packets
/// are dropped. A world that keeps an interface it never reads, such as
/// the "everything else" one, would otherwise keep every such packet the
/// agent sends.
const QUEUE: usize = 4 << 20;

fn capped() -> (End, End) {
    fictionet::pair_with_limit(QUEUE)
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
pub fn split_versions(fcx: &Cx, inner: impl Interface) -> (End, End, End) {
    let (v4, v4_mine) = capped();
    let (v6, v6_mine) = capped();
    let (other, other_mine) = capped();
    fcx.spawn_as(|| "split_versions".into(), move |fcx| async move {
        let ports = Ports::new(vec![Box::new(inner), Box::new(v4_mine), Box::new(v6_mine), Box::new(other_mine)]);
        split(fcx, ports, None, |packet| match version(&packet.0) {
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
/// [`Reassembly::push`] before they are sorted.
///
/// It ends when the region is cancelled, when port 0 closes, or when every
/// other port has closed.
async fn split(
    fcx: Cx,
    mut ports: Ports,
    mut reassembly: Option<Reassembly>,
    sort: impl Fn(&Packet) -> usize,
) -> fictionet::Result {
    loop {
        let deadline = reassembly.as_ref().and_then(|r| r.next_expiry());
        match ports.next(&fcx, deadline, |_| Poll::Pending).await? {
            Event::Packet(0, packet) => {
                let packet = match reassembly.as_mut() {
                    Some(r) => match r.push(packet, fcx.now()) {
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
                    r.expire(fcx.now());
                }
            }
            Event::Closed(0) | Event::Extra => return Ok(()),
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
pub fn split_protocols(fcx: &Cx, inner: impl Interface) -> (End, End, End, End) {
    let (tcp, tcp_mine) = capped();
    let (udp, udp_mine) = capped();
    let (icmp, icmp_mine) = capped();
    let (other, other_mine) = capped();
    fcx.spawn_as(|| "split_protocols".into(), move |fcx| async move {
        let ports = Ports::new(vec![
            Box::new(inner),
            Box::new(tcp_mine),
            Box::new(udp_mine),
            Box::new(icmp_mine),
            Box::new(other_mine),
        ]);
        split(fcx, ports, Some(Reassembly::default()), |packet| match protocol_end(&packet.0) {
            protocol::TCP => 1,
            protocol::UDP => 2,
            protocol::ICMP | protocol::ICMPV6 => 3,
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
pub(crate) fn protocol_end(packet: &[u8]) -> u8 {
    let Some(h) = Header::parse_whole(packet) else { return protocol::NONE };
    let icmp = h.payload(packet);
    match h.protocol {
        // Destination unreachable (including "fragmentation needed"),
        // source quench, time exceeded, parameter problem.
        protocol::ICMP if h.src.is_ipv4() => {
            if icmp.len() >= 8 && matches!(icmp[0], 3 | 4 | 11 | 12) && let Some(p) = quoted_protocol(&icmp[8..]) {
                return p;
            }
            protocol::ICMP
        }
        // Types below 128 are errors: destination unreachable, packet too
        // big, time exceeded, parameter problem.
        protocol::ICMPV6 if h.src.is_ipv6() => {
            if icmp.len() >= 8 && icmp[0] < 128 && let Some(p) = quoted_protocol(&icmp[8..]) {
                return p;
            }
            protocol::ICMP
        }
        p => p,
    }
}

/// The protocol of the packet quoted in an ICMP error, if it is TCP or UDP.
fn quoted_protocol(quoted: &[u8]) -> Option<u8> {
    let h = Header::parse_truncated(quoted)?;
    if h.fragment.is_some_and(|f| f.offset != 0) {
        return None;
    }
    matches!(h.protocol, protocol::TCP | protocol::UDP).then_some(h.protocol)
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

/// What [`Reassembly::push`] made of a packet.
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
struct Arrived<'a> {
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
    /// An IPv6 packet's extension headers are checked as
    /// [`Header::check`] says as it arrives, fragment or not. So the headers
    /// in front of every fragment are checked, not only the first
    /// fragment's (RFC 8200, section 4.5), and a first fragment must hold
    /// the whole chain (RFC 7112). Fragments are then put back together.
    /// A whole IPv6 packet is checked again and its extension headers taken out
    /// ([`strip_extension_headers`]); that also drops a packet whose
    /// fragments held another fragment.
    pub fn push(&mut self, packet: Packet, now: Instant) -> Intake {
        let refused = |packet: Packet, reject| {
            let answer = parameter_problem(&packet.0, reject);
            Intake::Refused { packet, answer }
        };
        if version(&packet.0) == Some(6)
            && let Err(reject) = chain6(&packet.0, Walk::Check)
        {
            return refused(packet, reject);
        }
        let Some(whole) = self.reassemble(packet, now) else { return Intake::Waiting };
        if version(&whole.0) != Some(6) {
            return Intake::Whole(whole);
        }
        match strip_extension_headers(&whole.0) {
            Ok(None) => Intake::Whole(whole),
            Ok(Some(stripped)) => Intake::Whole(Packet(stripped)),
            Err(reject) => refused(whole, reject),
        }
    }

    /// Takes a packet. Returns it if it is not a fragment, the whole packet
    /// if this fragment completed one, and `None` otherwise.
    pub(crate) fn reassemble(&mut self, packet: Packet, now: Instant) -> Option<Packet> {
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

    /// [`reassemble`](Reassembly::reassemble), without the cap.
    fn push_fragment(&mut self, packet: Packet, now: Instant) -> Option<Packet> {
        let Some(frag) = arrived(&packet.0) else { return Some(packet) };
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
            let expires = now + frag.timeout;
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
fn arrived(packet: &[u8]) -> Option<Arrived<'_>> {
    match version(packet)? {
        4 => {
            let h = v4(packet, false)?;
            let f = h.fragment?;
            let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else { return None };
            Some(Arrived {
                key: Key::V4 { src, dst, id: f.id as u16, proto: h.protocol },
                offset: f.offset,
                more: f.more,
                data: h.payload(packet),
                header: (f.offset == 0).then(|| packet[..h.payload.start].to_vec()),
                timeout: V4_TIMEOUT,
            })
        }
        6 => {
            let chain = chain6(packet, Walk::Check).ok()?;
            let (at, next_at) = chain.frag?;
            let h = v6(packet, &chain);
            let f = h.fragment?;
            let (IpAddr::V6(src), IpAddr::V6(dst)) = (h.src, h.dst) else { return None };
            // The headers in front of the fragment header, with the "next
            // header" byte that named it naming what it named.
            let header = (f.offset == 0).then(|| {
                let mut header = packet[..at].to_vec();
                header[next_at] = packet[at];
                header
            });
            Some(Arrived {
                key: Key::V6 { src, dst, id: f.id },
                offset: f.offset,
                more: f.more,
                data: &packet[at + 8..chain.end],
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
        set_header_checksum(&mut header[..head]);
    } else {
        header[4..6].copy_from_slice(&len.to_be_bytes());
    }
    Some(header)
}

// ---------------------------------------------------------------------------
// Reading and building IP headers

/// IP protocol numbers, and the IPv6 extension headers this module walks.
pub mod protocol {
    /// IPv6 Hop-by-Hop Options.
    pub const HOP_BY_HOP: u8 = 0;
    /// ICMP, over IPv4.
    pub const ICMP: u8 = 1;
    /// TCP.
    pub const TCP: u8 = 6;
    /// UDP.
    pub const UDP: u8 = 17;
    /// IPv6 Routing header.
    pub const ROUTING: u8 = 43;
    /// IPv6 Fragment header.
    pub const FRAGMENT: u8 = 44;
    /// The Authentication header (IPsec AH).
    pub const AUTH: u8 = 51;
    /// ICMPv6.
    pub const ICMPV6: u8 = 58;
    /// IPv6 "no next header".
    pub const NONE: u8 = 59;
    /// IPv6 Destination Options.
    pub const DEST_OPTIONS: u8 = 60;
}

/// The IP version of a packet, from the top four bits of its first byte:
/// 4 or 6 for an IP packet. `None` for an empty packet.
#[inline]
pub fn version(packet: &[u8]) -> Option<u8> {
    packet.first().map(|b| b >> 4)
}

/// The source address of an IPv4 or IPv6 packet, if its fixed header is
/// there.
#[inline]
pub fn source(packet: &[u8]) -> Option<IpAddr> {
    address(packet, 12, 8)
}

/// The destination address of an IPv4 or IPv6 packet, if its fixed header
/// is there.
#[inline]
pub fn destination(packet: &[u8]) -> Option<IpAddr> {
    address(packet, 16, 24)
}

/// The address at byte `v4` of an IPv4 header or `v6` of an IPv6 one.
#[inline]
fn address(packet: &[u8], v4: usize, v6: usize) -> Option<IpAddr> {
    match version(packet)? {
        4 => Some(IpAddr::V4(<[u8; 4]>::try_from(packet.get(v4..v4 + 4)?).ok()?.into())),
        6 if packet.len() >= 40 => Some(IpAddr::V6(<[u8; 16]>::try_from(&packet[v6..v6 + 16]).ok()?.into())),
        _ => None,
    }
}

/// A checked view of an IPv4 or IPv6 header: what a filter, a router or a
/// transport needs to decide where a packet goes.
///
/// Every reader checks lengths, since the agent can send any bytes it
/// likes. For IPv6, one walk over the extension headers finds the
/// upper-layer protocol, for every reader here: Hop-by-Hop Options,
/// Routing, Destination Options, Authentication and Fragment are extension
/// headers, and anything else, such as the mobility header, is the
/// upper-layer protocol, as it is to the world's stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The source address.
    pub src: IpAddr,
    /// The destination address.
    pub dst: IpAddr,
    /// The upper-layer protocol: [`protocol::TCP`], [`protocol::UDP`],
    /// [`protocol::ICMP`] or [`protocol::ICMPV6`], for example. For IPv6,
    /// the protocol after the extension headers, or [`protocol::NONE`] when
    /// [`Header::parse_truncated`] found them cut short. In a fragment after
    /// the first, what its fragment header names.
    pub protocol: u8,
    /// Where the upper-layer header starts and the packet ends, as byte
    /// offsets into the packet. The end is cut to the bytes present.
    pub payload: Range<usize>,
    /// The fragment this packet is, if it is one.
    pub fragment: Option<Fragment>,
}

/// One fragment of a larger packet: the fragment fields of an IPv4 header,
/// or an IPv6 Fragment header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// The identification shared by the fragments of one packet: 16 bits
    /// for IPv4, 32 for IPv6.
    pub id: u32,
    /// The fragment's offset in its packet, in bytes. Only the first
    /// fragment, at offset 0, carries the upper-layer header.
    pub offset: usize,
    /// Whether more fragments follow.
    pub more: bool,
}

impl Fragment {
    /// Whether this fragment is the whole packet: offset 0 and no more to
    /// come (an atomic fragment, RFC 6946).
    #[inline]
    pub fn is_atomic(&self) -> bool {
        self.offset == 0 && !self.more
    }
}

/// Why a host must not take in an IPv6 packet, from [`Header::check`], and
/// what RFC 8200 says to do about it. An IPv4 packet or an IPv6 packet that
/// cannot be read at all is [`Reject::Discard`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Drop the packet without an answer: it is not a whole IP packet, a
    /// header runs past it, an option's length runs past its header, or an
    /// option's action bits say to discard it silently.
    Discard,
    /// Drop the packet and answer with ICMPv6 Parameter Problem (type 4)
    /// with this code; [`parameter_problem`] builds the answer. `pointer`
    /// is the offset, from the start of the IPv6 header, of the byte at
    /// fault.
    Problem {
        /// The Parameter Problem code: 0 for an erroneous header field, 1
        /// for an unrecognized next header, 2 for an unrecognized option, 3
        /// for a first fragment that does not hold the whole chain.
        code: u8,
        /// The offset of the byte at fault.
        pointer: u32,
    },
}

impl Header {
    /// Reads the header of a whole packet, whose length fields fit the
    /// bytes present. `None` if it is not IPv4 or IPv6, or is cut short.
    /// IPv6 extension headers are walked, not checked: see
    /// [`Header::check`] for that.
    #[inline]
    pub fn parse(packet: &[u8]) -> Option<Header> {
        Header::read(packet, false)
    }

    /// Reads a header that may be followed by fewer bytes than its length
    /// field says, as the copy of a packet inside an ICMP error is, or a
    /// packet a world logs without trusting.
    #[inline]
    pub fn parse_truncated(packet: &[u8]) -> Option<Header> {
        Header::read(packet, true)
    }

    /// Reads the header of a whole packet as a host that is its
    /// destination takes it in, fragment or not. IPv6 extension headers
    /// are checked as RFC 8200 asks (sections 4.1 to 4.6):
    ///
    /// - Hop-by-Hop Options may only come first. Anywhere else, it is
    ///   answered with Parameter Problem code 1, pointing at the "next
    ///   header" byte that names it.
    /// - In Hop-by-Hop and Destination Options, Pad1 and PadN are skipped.
    ///   Any other option is unknown, and its two high bits decide: 00 skip
    ///   it, 01 discard the packet, 10 and 11 discard it and answer with
    ///   Parameter Problem code 2, pointing at the option. (RFC 8200
    ///   answers 10, but not 11, even to a multicast address.
    ///   [`parameter_problem`] answers neither, as it has no address of its
    ///   own to answer from.)
    /// - A Routing header with Segments Left 0 is skipped. Any other is
    ///   answered with Parameter Problem code 0, pointing at its Routing
    ///   Type: a host here forwards no source-routed packets.
    /// - A Fragment header is noted. In a fragment after the first, the
    ///   walk stops there. A second Fragment header discards the packet: no
    ///   stack puts a fragment inside a fragment.
    /// - The Authentication header is read past and asks nothing more: the
    ///   world runs no IPsec, so it checks none.
    /// - Anything else, including ESP and "no next header", is the
    ///   upper-layer protocol.
    ///
    /// A first fragment (offset 0, more to come) must hold the whole chain
    /// and the upper-layer header: 20 bytes of TCP, 8 of UDP, 4 of ICMPv6
    /// (RFC 7112). One that does not is answered with Parameter Problem
    /// code 3, pointer 0. Any other header that runs past the packet
    /// discards it, and so does a packet that is not a whole IP packet.
    pub fn check(packet: &[u8]) -> Result<Header, Reject> {
        match version(packet) {
            Some(4) => v4(packet, false).ok_or(Reject::Discard),
            Some(6) => Ok(v6(packet, &chain6(packet, Walk::Check)?)),
            _ => Err(Reject::Discard),
        }
    }

    /// Reads the header of a whole packet that a host would take in, as
    /// [`Header::check`] does, and that is not a fragment. This is what the
    /// TCP and UDP endpoints read.
    #[inline]
    pub fn parse_whole(packet: &[u8]) -> Option<Header> {
        Header::check(packet).ok().filter(|h| h.fragment.is_none())
    }

    /// The upper-layer bytes of `packet`, which this header was read from.
    #[inline]
    pub fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        packet.get(self.payload.clone()).unwrap_or_default()
    }

    /// The destination port of a TCP or UDP packet, which this header was
    /// read from. `None` for other protocols, for a fragment after the
    /// first, and when the port's bytes are not there.
    pub fn dst_port(&self, packet: &[u8]) -> Option<u16> {
        if self.fragment.is_some_and(|f| f.offset != 0) || !matches!(self.protocol, protocol::TCP | protocol::UDP) {
            return None;
        }
        let t = self.payload(packet);
        (t.len() >= 4).then(|| u16::from_be_bytes([t[2], t[3]]))
    }

    #[inline]
    fn read(packet: &[u8], truncated: bool) -> Option<Header> {
        match version(packet)? {
            4 => v4(packet, truncated),
            6 => Some(v6(packet, &chain6(packet, Walk::Read { truncated }).ok()?)),
            _ => None,
        }
    }
}

/// Reads an IPv4 header. With `truncated`, the packet may be cut short (as
/// the copy inside an ICMP error is), and only the header must be whole.
#[inline]
fn v4(bytes: &[u8], truncated: bool) -> Option<Header> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let ihl = (bytes[0] & 0x0f) as usize * 4;
    let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if ihl < 20 || bytes.len() < ihl || total < ihl || (!truncated && total > bytes.len()) {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
    let fragment = (flags & 0x3fff != 0).then(|| Fragment {
        id: u16::from_be_bytes([bytes[4], bytes[5]]).into(),
        offset: (flags & 0x1fff) as usize * 8,
        more: flags & 0x2000 != 0,
    });
    Some(Header {
        src: IpAddr::V4(<[u8; 4]>::try_from(&bytes[12..16]).ok()?.into()),
        dst: IpAddr::V4(<[u8; 4]>::try_from(&bytes[16..20]).ok()?.into()),
        protocol: bytes[9],
        payload: ihl..total.min(bytes.len()),
        fragment,
    })
}

/// The header of an IPv6 packet whose chain [`chain6`] walked.
#[inline]
fn v6(bytes: &[u8], chain: &Chain) -> Header {
    let fragment = chain.frag.map(|(at, _)| {
        let f = &bytes[at..at + 8];
        let off_m = u16::from_be_bytes([f[2], f[3]]);
        Fragment { id: u32::from_be_bytes([f[4], f[5], f[6], f[7]]), offset: (off_m & 0xfff8) as usize, more: off_m & 1 != 0 }
    });
    let addr = |at: usize| IpAddr::V6(<[u8; 16]>::try_from(&bytes[at..at + 16]).expect("a whole IPv6 header").into());
    Header { src: addr(8), dst: addr(24), protocol: chain.proto, payload: chain.upper..chain.end, fragment }
}

// The IPv6 extension-header chain (RFC 8200, section 4)

/// How [`chain6`] walks a chain.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Find the upper-layer protocol and check nothing else. With
    /// `truncated`, the packet may be shorter than its length field says,
    /// and a chain that runs past the bytes present gives
    /// [`protocol::NONE`].
    Read { truncated: bool },
    /// As a host takes the packet in: see [`Header::check`].
    Check,
}

/// An IPv6 packet's extension-header chain, walked by [`chain6`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Chain {
    /// The upper-layer protocol. For a fragment after the first, this is
    /// what its fragment header names, since the headers after it are in
    /// the first fragment.
    proto: u8,
    /// Where the upper-layer header starts.
    upper: usize,
    /// Where the "next header" byte that names `proto` is: 6 when there
    /// are no extension headers.
    proto_at: usize,
    /// The first fragment header, if any: where it starts, and where the
    /// "next header" byte that names it is.
    frag: Option<(usize, usize)>,
    /// The packet's length, from its payload length field, cut to the
    /// bytes present.
    end: usize,
}

/// Walks the extension-header chain of an IPv6 packet: the one walker
/// behind every reader in this module. [`Walk::Check`] checks it as
/// [`Header::check`] says. [`Walk::Read`] walks the same headers and checks
/// only that they fit.
fn chain6(bytes: &[u8], walk: Walk) -> Result<Chain, Reject> {
    use Reject::{Discard, Problem};
    use protocol::{AUTH, DEST_OPTIONS, FRAGMENT, HOP_BY_HOP, ROUTING};
    if bytes.len() < 40 || bytes[0] >> 4 != 6 {
        return Err(Discard);
    }
    let check = walk == Walk::Check;
    let mut end = 40 + u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if end > bytes.len() {
        if walk != (Walk::Read { truncated: true }) {
            return Err(Discard);
        }
        end = bytes.len();
    }
    // A first fragment: offset 0, more to come.
    let first = |frag: Option<(usize, usize)>| {
        frag.is_some_and(|(at, _): (usize, usize)| u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) & 0xfff9 == 1)
    };
    let mut next = bytes[6];
    let mut next_at = 6;
    let mut at = 40;
    let mut frag = None;
    loop {
        if check && next == HOP_BY_HOP && next_at != 6 {
            return Err(Problem { code: 1, pointer: next_at as u32 });
        }
        // The header's length, for the headers that say it.
        let len = match next {
            HOP_BY_HOP | DEST_OPTIONS | ROUTING => bytes.get(at + 1).map(|l| (*l as usize + 1) * 8),
            // Its length is in 4-byte units, not counting the first two.
            AUTH => bytes.get(at + 1).map(|l| (*l as usize + 2) * 4),
            FRAGMENT => Some(8),
            _ => break,
        };
        let Some(len) = len.filter(|len| at + len <= end) else {
            // The header runs past the packet.
            if check {
                return Err(if first(frag) && next != FRAGMENT { Problem { code: 3, pointer: 0 } } else { Discard });
            }
            return Ok(Chain { proto: protocol::NONE, upper: at.min(end), proto_at: next_at, frag, end });
        };
        match next {
            HOP_BY_HOP | DEST_OPTIONS if check => check_options(&bytes[at..at + len], at)?,
            ROUTING if check && bytes[at + 3] != 0 => return Err(Problem { code: 0, pointer: (at + 2) as u32 }),
            FRAGMENT => {
                if frag.is_some() {
                    if check {
                        return Err(Discard);
                    }
                } else {
                    frag = Some((at, next_at));
                }
            }
            _ => {}
        }
        // Only the first fragment carries the headers after a fragment
        // header.
        let later = next == FRAGMENT && u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) & 0xfff8 != 0;
        (next, next_at, at) = (bytes[at], at, at + len);
        if later {
            break;
        }
    }
    let need = match next {
        protocol::TCP => 20,
        protocol::UDP => 8,
        protocol::ICMPV6 => 4,
        _ => 0,
    };
    if check && first(frag) && end - at < need {
        return Err(Problem { code: 3, pointer: 0 });
    }
    Ok(Chain { proto: next, upper: at, proto_at: next_at, frag, end })
}

/// Checks the options of one Hop-by-Hop or Destination Options header,
/// `header`, which starts `base` bytes into the packet.
fn check_options(header: &[u8], base: usize) -> Result<(), Reject> {
    let mut i = 2;
    while i < header.len() {
        let kind = header[i];
        // Pad1: one byte, no length.
        if kind == 0 {
            i += 1;
            continue;
        }
        if i + 2 > header.len() || i + 2 + header[i + 1] as usize > header.len() {
            return Err(Reject::Discard);
        }
        // PadN is the only other option a host here knows.
        if kind != 1 {
            let pointer = (base + i) as u32;
            match kind >> 6 {
                0 => {}
                1 => return Err(Reject::Discard),
                _ => return Err(Reject::Problem { code: 2, pointer }),
            }
        }
        i += 2 + header[i + 1] as usize;
    }
    Ok(())
}

/// A whole IPv6 packet with its extension headers checked by
/// [`Header::check`] and taken out, so the upper-layer header follows the
/// IPv6 header. `Ok(None)` if it has none to take out. A packet with a
/// Fragment header is not whole, and is discarded.
///
/// What a header asks of a host is done once the check passes: skipped
/// options and a Routing header with no segments left ask for nothing more.
/// Taking them out lets layers that read only the upper-layer header, such
/// as smoltcp's TCP, accept the packet.
pub fn strip_extension_headers(packet: &[u8]) -> Result<Option<Vec<u8>>, Reject> {
    let chain = chain6(packet, Walk::Check)?;
    if chain.frag.is_some() {
        return Err(Reject::Discard);
    }
    if chain.upper == 40 {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(40 + chain.end - chain.upper);
    out.extend_from_slice(&packet[..40]);
    out.extend_from_slice(&packet[chain.upper..chain.end]);
    out[6] = chain.proto;
    out[4..6].copy_from_slice(&((chain.end - chain.upper) as u16).to_be_bytes());
    Ok(Some(out))
}

/// The ICMPv6 Parameter Problem answer to `packet`, for `reject`, built by
/// [`icmp::error`]. It comes from the packet's destination. `None` for
/// [`Reject::Discard`], and where `icmp::error` sends no answer.
pub fn parameter_problem(packet: &[u8], reject: Reject) -> Option<Packet> {
    let Reject::Problem { code, pointer } = reject else { return None };
    let from = destination(packet)?;
    icmp::error(packet, from, 4, code, pointer)
}

// Checksums (RFC 1071)

/// Adds `data` to a one's-complement sum, as 16-bit big-endian words. Four
/// bytes at a time: since 2^16 is 1 modulo 2^16 - 1, a 32-bit word adds
/// the same as its two halves once the sum is folded.
#[inline]
fn sum(mut acc: u64, data: &[u8]) -> u64 {
    let (words, rest) = data.as_chunks::<4>();
    for w in words {
        acc += u32::from_be_bytes(*w) as u64;
    }
    let (pairs, odd) = rest.as_chunks::<2>();
    for p in pairs {
        acc += u16::from_be_bytes(*p) as u64;
    }
    if let [last] = odd {
        acc += (*last as u64) << 8;
    }
    acc
}

/// Folds a one's-complement sum to 16 bits and complements it.
#[inline]
fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The Internet checksum of `data` (RFC 1071), as the IPv4 header, ICMP and
/// IGMP use it. Over data whose checksum field is filled in, a correct
/// checksum gives 0.
#[inline]
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum(0, data))
}

/// The TCP, UDP or ICMPv6 checksum of `data` over the pseudo-header for
/// `src`, `dst` and `protocol` (RFC 9293, RFC 768, RFC 8200 section 8.1).
/// Over data whose checksum field is filled in, a correct checksum gives 0.
/// Addresses of two families have no pseudo-header, and give 1, which is
/// never correct.
#[inline]
pub fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, data: &[u8]) -> u16 {
    let len = data.len() as u64;
    let acc = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => sum(sum(0, &s.octets()), &d.octets()),
        (IpAddr::V6(s), IpAddr::V6(d)) => sum(sum(0, &s.octets()), &d.octets()),
        _ => return 1,
    };
    fold(sum(acc + protocol as u64 + len, data))
}

/// Whether a UDP datagram from `src` to `dst` has a good checksum. A zero
/// checksum field means "no checksum" over IPv4. Over IPv6 it is never
/// valid (RFC 8200, section 8.1): a sender whose sum comes out as zero
/// sends `0xffff` instead.
#[inline]
pub fn udp_checksum_ok(src: IpAddr, dst: IpAddr, udp: &[u8]) -> bool {
    if udp.len() < 8 {
        return false;
    }
    if udp[6..8] == [0, 0] {
        return src.is_ipv4();
    }
    transport_checksum(src, dst, protocol::UDP, udp) == 0
}

/// Recomputes the checksum of an IPv4 header, options included, in place.
///
/// # Panics
///
/// If `header` is shorter than 20 bytes.
#[inline]
pub fn set_header_checksum(header: &mut [u8]) {
    header[10..12].copy_from_slice(&[0, 0]);
    let c = checksum(header);
    header[10..12].copy_from_slice(&c.to_be_bytes());
}

// Building packets

/// The fields of an IP header that [`packet_with`] sets beyond the
/// addresses, the protocol and the length. The default is what
/// [`packet`] uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    /// The TTL (IPv4) or hop limit (IPv6). 64 by default.
    pub ttl: u8,
    /// The IPv4 type of service or the IPv6 traffic class. 0 by default.
    pub tos: u8,
    /// The IPv4 identification. Unused for IPv6. 0 by default.
    pub id: u16,
    /// The IPv4 "don't fragment" flag. Unused for IPv6. Set by default.
    pub dont_fragment: bool,
}

impl Default for Fields {
    fn default() -> Fields {
        Fields { ttl: 64, tos: 0, id: 0, dont_fragment: true }
    }
}

/// Builds an IP packet from `src` to `dst` around `payload`, with a TTL or
/// hop limit of 64. The IPv4 header checksum is filled in. The payload's
/// own checksum must already be done: see [`transport_checksum`].
///
/// # Panics
///
/// If `src` and `dst` are of two families, or `payload` is too long for one
/// packet.
#[inline]
pub fn packet(src: IpAddr, dst: IpAddr, protocol: u8, payload: &[u8]) -> Packet {
    packet_with(src, dst, protocol, Fields::default(), payload)
}

/// [`packet`], with the header's other `fields`.
///
/// # Panics
///
/// As [`packet`].
pub fn packet_with(src: IpAddr, dst: IpAddr, protocol: u8, fields: Fields, payload: &[u8]) -> Packet {
    let mut p;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(20 + payload.len()).expect("a payload that fits one IPv4 packet");
            p = Vec::with_capacity(20 + payload.len());
            p.extend_from_slice(&[0x45, fields.tos]);
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&fields.id.to_be_bytes());
            p.extend_from_slice(&[if fields.dont_fragment { 0x40 } else { 0 }, 0, fields.ttl, protocol, 0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            set_header_checksum(&mut p);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = u16::try_from(payload.len()).expect("a payload that fits one IPv6 packet");
            p = Vec::with_capacity(40 + payload.len());
            p.extend_from_slice(&[0x60 | fields.tos >> 4, fields.tos << 4, 0, 0]);
            p.extend_from_slice(&len.to_be_bytes());
            p.extend_from_slice(&[protocol, fields.ttl]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
        }
        _ => panic!("an IP packet from {src} to {dst}: the addresses are of two families"),
    }
    p.extend_from_slice(payload);
    Packet(p)
}

/// What a router hop did to a packet's TTL or hop limit, from [`hop`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hop {
    /// Lowered by one: forward the packet.
    Forward,
    /// It was 0 or 1, so the packet must not be forwarded (RFC 1812
    /// 5.3.1, RFC 8200 section 3).
    Expired,
    /// Neither IPv4 nor IPv6, or too short to hold the field.
    NotIp,
}

/// Lowers the TTL (IPv4, updating the header checksum as RFC 1624 does) or
/// the hop limit (IPv6) of `packet` by one, as a router does for each hop.
/// An expired packet is left as it was.
pub fn hop(packet: &mut [u8]) -> Hop {
    match version(packet) {
        Some(4) if packet.len() >= 20 => {
            let ttl = packet[8];
            if ttl <= 1 {
                return Hop::Expired;
            }
            let old = u16::from_be_bytes([ttl, packet[9]]);
            let new = u16::from_be_bytes([ttl - 1, packet[9]]);
            packet[8] = ttl - 1;
            // HC' = ~(~HC + ~m + m')
            let hc = u16::from_be_bytes([packet[10], packet[11]]);
            let c = fold(u64::from(!hc) + u64::from(!old) + u64::from(new));
            packet[10..12].copy_from_slice(&c.to_be_bytes());
            Hop::Forward
        }
        Some(6) if packet.len() >= 40 => {
            if packet[7] <= 1 {
                return Hop::Expired;
            }
            packet[7] -= 1;
            Hop::Forward
        }
        _ => Hop::NotIp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 header with a correct checksum, from `src` to `dst`, for
    /// `payload_len` bytes of `proto` after `options` (a multiple of 4
    /// bytes).
    fn v4_header(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, id: u16, options: &[u8], payload_len: usize) -> Vec<u8> {
        let fields = Fields { id, dont_fragment: false, ..Fields::default() };
        let mut h = packet_with(src.into(), dst.into(), proto, fields, &[]).0;
        h.extend_from_slice(options);
        h[0] = 0x40 | (h.len() / 4) as u8;
        let total = (h.len() + payload_len) as u16;
        h[2..4].copy_from_slice(&total.to_be_bytes());
        set_header_checksum(&mut h);
        h
    }

    /// IPv4 fragment of a packet with identification `id`: `len` data bytes
    /// at `offset`.
    fn frag4(id: u16, offset: usize, len: usize, more: bool) -> Packet {
        frag4_of(id, offset, &vec![0xab; len], more)
    }

    /// The same, with `data` as the data.
    fn frag4_of(id: u16, offset: usize, data: &[u8], more: bool) -> Packet {
        let mut h = v4_header(protocol::UDP, Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(1, 1, 1, 1), id, &[], data.len());
        let flags: u16 = if more { 0x2000 } else { 0 };
        h[6..8].copy_from_slice(&((offset / 8) as u16 | flags).to_be_bytes());
        set_header_checksum(&mut h[..20]);
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
        assert!(r.reassemble(frag4(1, 0, 16, true), at(0)).is_none());
        assert_eq!(r.next_expiry(), Some(at(30)));
        r.expire(at(29));
        assert_eq!(r.partial.len(), 1);
        r.expire(at(30));
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
        // The rest alone does not make a packet: the first fragment is gone.
        assert!(r.reassemble(frag4(1, 16, 8, false), at(31)).is_none());
        // Within the time, both halves make one.
        assert!(r.reassemble(frag4(2, 0, 16, true), at(40)).is_none());
        let whole = r.reassemble(frag4(2, 16, 8, false), at(69)).expect("a whole packet");
        assert_eq!(whole.0.len(), 20 + 24);
        assert_eq!(checksum(&whole.0[..20]), 0);
    }

    #[test]
    fn waiting_fragments_are_capped() {
        let mut r = Reassembly::default();
        // 600 unfinished packets of 8,000 bytes is more than 4 MiB.
        for id in 0..600u16 {
            let t = Instant::from_since_start(Duration::from_millis(id as u64));
            assert!(r.reassemble(frag4(id, 0, 8000, true), t).is_none());
            r.check();
        }
        assert!(r.partial.len() < 600);
        // The oldest went first.
        assert!(!r.partial.contains_key(&Key::V4 {
            src: Ipv4Addr::new(10, 0, 0, 2),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            id: 0,
            proto: protocol::UDP
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
            set_header_checksum(&mut f.0[..20]);
            assert!(r.reassemble(f, t).is_none());
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
        assert!(r.reassemble(frag4(9, 64, 5, false), at(0)).is_none());
        for k in (1..8).rev() {
            assert!(r.reassemble(frag4(9, k * 8, 8, true), at(0)).is_none());
        }
        r.check();
        let whole = r.reassemble(frag4(9, 0, 8, true), at(0)).expect("a whole packet");
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
            let mut h = v4_header(protocol::UDP, src, Ipv4Addr::new(1, 1, 1, 1), 7, options, len);
            let flags: u16 = if more { 0x2000 } else { 0 };
            h[6..8].copy_from_slice(&((offset / 8) as u16 | flags).to_be_bytes());
            let ihl = h.len();
            set_header_checksum(&mut h[..ihl]);
            h.extend(std::iter::repeat_n(0xab, len));
            assert_eq!(r.reassemble(Packet(h), at(0)), None, "a packet of {} bytes came out", 40 + 20 + offset + len);
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
            p.extend_from_slice(&[protocol::FRAGMENT, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            p.push(protocol::UDP);
            p.push(0);
            p.extend_from_slice(&(offset as u16 | more as u16).to_be_bytes());
            p.extend_from_slice(&9u32.to_be_bytes());
            p.extend(std::iter::repeat_n(0xab, len));
            assert_eq!(r.reassemble(Packet(p), at(0)), None, "a packet came out at offset {offset}");
            offset += len;
        }
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
    }

    /// A world that keeps an interface it never reads does not keep every
    /// packet the agent sends there.
    #[test]
    fn an_interface_never_read_holds_at_most_its_queue() {
        let result = crate::block_on(crate::run(|fcx| async move {
            let (mut raw, side) = crate::pair();
            let (_tcp, _udp, _icmp, other) = split_protocols(&fcx, side);
            // 20 MiB of protocol 99, which goes to `other`.
            for _ in 0..20 * 1024 {
                let h = v4_header(99, Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 0, &[], 1000);
                let mut p = h;
                p.extend_from_slice(&[0; 1000]);
                raw.send(Packet(p));
                fcx.yield_now().await?;
            }
            assert!(other.queued() <= QUEUE, "{} bytes wait", other.queued());
            assert!(other.queued() > QUEUE / 2, "{} bytes wait", other.queued());
            Err::<(), crate::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    #[test]
    fn bad_fragments_are_dropped() {
        let mut r = Reassembly::default();
        // Not a multiple of 8 with more to come.
        assert!(r.reassemble(frag4(3, 0, 13, true), at(0)).is_none());
        assert!(r.partial.is_empty());
        // Past 65,535 bytes: nothing is kept for a packet not yet started.
        assert!(r.reassemble(frag4(4, 65_528, 16, false), at(0)).is_none());
        assert!(r.partial.is_empty());
        // Two different lengths for one packet.
        assert!(r.reassemble(frag4(5, 16, 8, false), at(0)).is_none());
        assert!(r.reassemble(frag4(5, 32, 8, false), at(0)).is_none());
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
        assert_eq!(r.reassemble(cut.clone(), at(0)), Some(cut));
    }

    #[test]
    fn conflicting_copies_drop_the_packet_until_it_expires() {
        let mut r = Reassembly::default();
        let first = [1u8; 16];
        let mut other = first;
        other[8] = 2;
        // The same place, other bytes: an overlap (RFC 5722).
        assert!(r.reassemble(frag4_of(1, 0, &first, true), at(0)).is_none());
        assert!(r.reassemble(frag4_of(1, 0, &other, true), at(0)).is_none());
        assert_eq!(live(&r), 0);
        // Its later fragments cannot start it again.
        assert!(r.reassemble(frag4_of(1, 0, &first, true), at(10)).is_none());
        assert!(r.reassemble(frag4(1, 16, 8, false), at(10)).is_none());
        assert_eq!(live(&r), 0);
        // Once its time is up, the identification can be used again.
        r.expire(at(30));
        assert!(r.partial.is_empty());
        assert!(r.reassemble(frag4_of(1, 0, &first, true), at(31)).is_none());
        let whole = r.reassemble(frag4(1, 16, 8, false), at(31)).expect("a whole packet");
        assert_eq!(&whole.0[20..36], &first);
        // An exact copy is ignored.
        assert!(r.reassemble(frag4_of(2, 0, &first, true), at(40)).is_none());
        assert!(r.reassemble(frag4_of(2, 0, &first, true), at(40)).is_none());
        assert!(r.reassemble(frag4(2, 16, 8, false), at(40)).is_some());
    }

    /// Fragments that run past 65,535 bytes keep nothing, however many
    /// packets they name.
    #[test]
    fn fragments_too_long_for_ip_keep_nothing() {
        let mut r = Reassembly::default();
        for id in 0..20_000u16 {
            assert!(r.reassemble(frag4(id, 65_528, 16, false), at(0)).is_none());
        }
        assert!(r.partial.is_empty());
        assert_eq!(r.size, 0);
        // Dead entries count against the cap like any other.
        for id in 0..40_000u32 {
            let mut first = frag4_of((id % 65_536) as u16, 0, &[1; 16], true);
            first.0[15] = (id / 65_536) as u8 + 1;
            set_header_checksum(&mut first.0[..20]);
            let mut other = first.clone();
            other.0[28] ^= 1;
            r.reassemble(first, at(0));
            r.reassemble(other, at(0));
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
            assert!(r.reassemble(frag4_of(1, 8, &[2; 8], a), at(0)).is_none());
            assert!(r.reassemble(frag4_of(1, 8, &[2; 8], b), at(0)).is_none());
            assert!(r.reassemble(frag4_of(1, 0, &[1; 8], true), at(0)).is_none(), "last first: {last_first}");
            assert!(r.reassemble(frag4_of(1, 16, &[3; 8], false), at(0)).is_none(), "last first: {last_first}");
            assert_eq!(live(&r), 0);
            r.check();
        }
        // A true copy of the last fragment is still ignored.
        let mut r = Reassembly::default();
        assert!(r.reassemble(frag4_of(1, 8, &[2; 8], false), at(0)).is_none());
        assert!(r.reassemble(frag4_of(1, 8, &[2; 8], false), at(0)).is_none());
        assert!(r.reassemble(frag4_of(1, 0, &[1; 8], true), at(0)).is_some());
    }

    // The IPv6 extension-header chain

    const SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    const DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    /// An IPv6 packet from `SRC` to `DST` whose first header is `next`.
    fn v6(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[next, 64]);
        p.extend_from_slice(&SRC.octets());
        p.extend_from_slice(&DST.octets());
        p.extend_from_slice(payload);
        p
    }

    /// `headers` in front of 8 bytes of UDP.
    fn chained(next: u8, headers: &[&[u8]]) -> Vec<u8> {
        let mut payload: Vec<u8> = headers.concat();
        payload.extend_from_slice(&[0, 1, 0, 2, 0, 8, 0, 0]);
        v6(next, &payload)
    }

    fn checked(p: &[u8]) -> Result<Chain, Reject> {
        chain6(p, Walk::Check)
    }

    fn problem(code: u8, pointer: u32) -> Result<Chain, Reject> {
        Err(Reject::Problem { code, pointer })
    }

    #[test]
    fn headers_that_ask_nothing_are_walked() {
        let plain = v6(protocol::UDP, &[0; 8]);
        assert_eq!(checked(&plain), Ok(Chain { proto: protocol::UDP, upper: 40, proto_at: 6, frag: None, end: 48 }));
        // An Authentication header is read past.
        let ah = chained(protocol::AUTH, &[&[17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
        assert_eq!(checked(&ah).map(|c| (c.proto, c.upper)), Ok((protocol::UDP, 52)));
        // Hop-by-Hop with PadN, a Routing header with no segments left, and
        // Destination Options with an unknown option to skip and Pad1.
        let p = chained(0, &[&[43, 0, 1, 4, 0, 0, 0, 0], &[60, 0, 250, 0, 0, 0, 0, 0], &[17, 0, 0x1e, 3, 9, 9, 9, 0]]);
        assert_eq!(checked(&p), Ok(Chain { proto: protocol::UDP, upper: 64, proto_at: 56, frag: None, end: 72 }));
        let stripped = strip_extension_headers(&p).unwrap().unwrap();
        assert_eq!(stripped, v6(protocol::UDP, &[0, 1, 0, 2, 0, 8, 0, 0]));
        assert_eq!(strip_extension_headers(&plain), Ok(None));
    }

    #[test]
    fn headers_a_host_must_refuse_are_refused() {
        // Unknown options, by their two high bits.
        assert_eq!(checked(&chained(60, &[&[17, 0, 0x40, 0, 0, 0, 0, 0]])), Err(Reject::Discard));
        assert_eq!(checked(&chained(60, &[&[17, 0, 0x80, 0, 0, 0, 0, 0]])), problem(2, 42));
        assert_eq!(checked(&chained(0, &[&[17, 0, 1, 0, 0xc2, 0, 0, 0]])), problem(2, 44));
        // A Routing header with segments left, of any type.
        for kind in [0, 2, 3, 4, 250] {
            assert_eq!(checked(&chained(43, &[&[17, 0, kind, 1, 0, 0, 0, 0]])), problem(0, 42));
        }
        // Hop-by-Hop anywhere but first, even cut short.
        assert_eq!(checked(&chained(60, &[&[0, 0, 0, 0, 0, 0, 0, 0], &[17, 0, 0, 0, 0, 0, 0, 0]])), problem(1, 40));
        assert_eq!(checked(&v6(60, &[0, 0, 0, 0, 0, 0, 0, 0, 17])), problem(1, 40));
        // An option that runs past its header, and headers that run past
        // the packet.
        assert_eq!(checked(&chained(60, &[&[17, 0, 1, 5, 0, 0, 0, 0]])), Err(Reject::Discard));
        assert_eq!(checked(&v6(60, &[17, 1, 0, 0, 0, 0, 0, 0])), Err(Reject::Discard));
        assert_eq!(checked(&v6(43, &[17, 0, 0, 0])), Err(Reject::Discard));
        assert_eq!(checked(&v6(protocol::FRAGMENT, &[17, 0, 0, 0])), Err(Reject::Discard));
        // A length field longer than the bytes present.
        let mut cut = v6(protocol::UDP, &[0; 8]);
        cut.truncate(44);
        assert_eq!(checked(&cut), Err(Reject::Discard));
    }

    #[test]
    fn fragments_are_noted_and_not_stripped() {
        // A first fragment: the walk goes on past it.
        let first = chained(protocol::FRAGMENT, &[&[60, 0, 0, 1, 0, 0, 0, 7], &[17, 0, 0, 0, 0, 0, 0, 0]]);
        let chain = checked(&first).unwrap();
        assert_eq!((chain.proto, chain.upper, chain.frag), (protocol::UDP, 56, Some((40, 6))));
        assert_eq!(Header::check(&first).unwrap().fragment, Some(Fragment { id: 7, offset: 0, more: true }));
        // A later fragment: the walk stops at it.
        let later = chained(protocol::FRAGMENT, &[&[60, 0, 0, 16, 0, 0, 0, 7]]);
        let chain = checked(&later).unwrap();
        assert_eq!((chain.proto, chain.upper), (protocol::DEST_OPTIONS, 48));
        assert_eq!(Header::check(&later).unwrap().fragment, Some(Fragment { id: 7, offset: 16, more: false }));
        assert_eq!(strip_extension_headers(&first), Err(Reject::Discard));
        assert_eq!(Header::parse_whole(&first), None);
        // A second fragment header: refused by a host, read past otherwise.
        let twice = chained(protocol::FRAGMENT, &[&[44, 0, 0, 1, 0, 0, 0, 7], &[17, 0, 0, 0, 0, 0, 0, 7]]);
        assert_eq!(checked(&twice), Err(Reject::Discard));
        assert_eq!(Header::parse(&twice).map(|h| (h.protocol, h.payload.start)), Some((protocol::UDP, 56)));
    }

    /// Before there was one walker, `Header::parse` and
    /// `Header::parse_truncated` read mobility (135), HIP (139), shim6 (140)
    /// and the experimental numbers (253, 254) as extension headers and
    /// walked past them, while `Header::parse_whole`, the protocol split and
    /// the attach binary read them as the upper-layer protocol. So the
    /// sandbox filter took a mobility header in front of UDP for UDP, and
    /// the world's stack for protocol 135. Every reader now agrees.
    #[test]
    fn every_reader_walks_the_same_chain() {
        for next in [135, 139, 140, 253, 254] {
            let p = v6(next, &[protocol::UDP, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 0]);
            let read = |h: Option<Header>| h.map(|h| (h.protocol, h.payload.start));
            assert_eq!(read(Header::parse(&p)), Some((next, 40)), "parse, next header {next}");
            assert_eq!(read(Header::parse_truncated(&p)), Some((next, 40)), "parse_truncated, next header {next}");
            assert_eq!(read(Header::parse_truncated(&p[..44])), Some((next, 40)), "cut short, next header {next}");
            assert_eq!(read(Header::check(&p).ok()), Some((next, 40)), "check, next header {next}");
            assert_eq!(read(Header::parse_whole(&p)), Some((next, 40)), "parse_whole, next header {next}");
            assert_eq!(protocol_end(&p), next, "the split, next header {next}");
        }
        // A chain cut short reads as "no next header" only to the reader
        // that allows it.
        let cut = chained(60, &[&[17, 1, 0, 0, 0, 0, 0, 0]]);
        assert_eq!(Header::parse_truncated(&cut[..44]).map(|h| h.protocol), Some(protocol::NONE));
        assert_eq!(Header::parse(&cut[..44]), None);
    }

    #[test]
    fn parameter_problems_follow_rfc_4443() {
        let bad = chained(43, &[&[17, 0, 250, 1, 0, 0, 0, 0]]);
        let reject = checked(&bad).unwrap_err();
        let answer = parameter_problem(&bad, reject).expect("an answer").0;
        let ip = Header::parse(&answer).unwrap();
        assert_eq!((ip.src, ip.dst, ip.protocol), (DST.into(), SRC.into(), protocol::ICMPV6));
        let icmp = ip.payload(&answer);
        assert_eq!(&icmp[..2], &[4, 0]);
        assert_eq!(&icmp[4..8], &42u32.to_be_bytes());
        assert_eq!(&icmp[8..], &bad[..]);
        assert_eq!(transport_checksum(DST.into(), SRC.into(), protocol::ICMPV6, icmp), 0);
        // Nothing for a silent discard, to a multicast address, from an
        // unspecified one, or for an ICMPv6 error.
        assert_eq!(parameter_problem(&bad, Reject::Discard), None);
        let mut multicast = bad.clone();
        multicast[24] = 0xff;
        assert_eq!(parameter_problem(&multicast, reject), None);
        let mut unspecified = bad.clone();
        unspecified[8..24].fill(0);
        assert_eq!(parameter_problem(&unspecified, reject), None);
        let error = v6(43, &[protocol::ICMPV6, 0, 250, 1, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parameter_problem(&error, checked(&error).unwrap_err()), None);
        // Nor for the first fragment of an ICMPv6 error, cut short (RFC
        // 7112): its type is there to read.
        let first = v6(protocol::FRAGMENT, &[protocol::ICMPV6, 0, 0, 1, 0, 0, 0, 9, 1, 4]);
        let reject = checked(&first).unwrap_err();
        assert_eq!(reject, Reject::Problem { code: 3, pointer: 0 });
        assert_eq!(parameter_problem(&first, reject), None);
        // An echo request cut short the same way is answered.
        let ping = v6(protocol::FRAGMENT, &[protocol::ICMPV6, 0, 0, 1, 0, 0, 0, 9, 128, 0]);
        assert!(parameter_problem(&ping, checked(&ping).unwrap_err()).is_some());
        // A big packet is quoted up to the minimum MTU.
        let mut big = chained(43, &[&[17, 0, 250, 1, 0, 0, 0, 0]]);
        big.resize(4000, 0);
        let len = (big.len() - 40) as u16;
        big[4..6].copy_from_slice(&len.to_be_bytes());
        assert_eq!(parameter_problem(&big, reject).unwrap().0.len(), 1280);
    }

    // Checksums and building

    /// RFC 1071 one 16-bit word at a time, as the copies of it did.
    fn reference_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u64;
        for c in data.chunks(2) {
            sum += u64::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn checksums_match_rfc_1071_at_every_length() {
        let data: Vec<u8> = (0..2000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for len in 0..data.len() {
            assert_eq!(checksum(&data[..len]), reference_checksum(&data[..len]), "{len} bytes");
        }
        assert_eq!(checksum(&[0xff; 65_536]), reference_checksum(&[0xff; 65_536]));
        // A pseudo-header is the addresses, the protocol and the length.
        let (s, d): (Ipv4Addr, Ipv4Addr) = ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        let udp = [0, 1, 0, 2, 0, 9, 0, 0, 0xab];
        let pseudo = [&s.octets()[..], &d.octets(), &[0, 17, 0, 9], &udp].concat();
        assert_eq!(transport_checksum(s.into(), d.into(), protocol::UDP, &udp), reference_checksum(&pseudo));
        assert_eq!(transport_checksum(s.into(), DST.into(), protocol::UDP, &udp), 1);
    }

    #[test]
    fn built_packets_read_back() {
        let (s, d): (IpAddr, IpAddr) = ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        let p = packet_with(s, d, protocol::UDP, Fields { ttl: 9, tos: 0x10, id: 7, dont_fragment: false }, &[1; 8]).0;
        assert_eq!(&p[..12], &[0x45, 0x10, 0, 28, 0, 7, 0, 0, 9, 17, p[10], p[11]]);
        assert_eq!(checksum(&p[..20]), 0);
        assert_eq!(Header::parse(&p), Some(Header { src: s, dst: d, protocol: protocol::UDP, payload: 20..28, fragment: None }));
        let p = packet_with(SRC.into(), DST.into(), protocol::UDP, Fields { tos: 0xab, ..Fields::default() }, &[1; 8]).0;
        assert_eq!(&p[..8], &[0x6a, 0xb0, 0, 0, 0, 8, 17, 64]);
        assert_eq!((source(&p), destination(&p)), (Some(SRC.into()), Some(DST.into())));
        // A router hop lowers the TTL and keeps the header checksum right.
        let mut p = packet(s, d, protocol::UDP, &[]).0;
        assert_eq!(hop(&mut p), Hop::Forward);
        assert_eq!((p[8], checksum(&p)), (63, 0));
        p[8] = 1;
        assert_eq!(hop(&mut p), Hop::Expired);
        assert_eq!(hop(&mut [0x45; 10]), Hop::NotIp);
    }

    #[test]
    fn a_zero_checksum_means_none_only_over_ipv4() {
        let (v4a, v4b): (IpAddr, IpAddr) = ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        let (v6a, v6b): (IpAddr, IpAddr) = ("2001:db8::2".parse().unwrap(), "2001:db8::1".parse().unwrap());
        let mut u = vec![0, 1, 0, 2, 0, 10, 0, 0, 0xab, 0xcd];
        assert!(udp_checksum_ok(v4a, v4b, &u));
        assert!(!udp_checksum_ok(v6a, v6b, &u));
        // Data whose sum, with the field zero, comes out as zero: over
        // IPv6, the field must say 0xffff.
        let w = (0..=u16::MAX)
            .find(|w| {
                u[8..10].copy_from_slice(&w.to_be_bytes());
                transport_checksum(v6a, v6b, protocol::UDP, &u) == 0
            })
            .expect("some data sums to zero");
        u[8..10].copy_from_slice(&w.to_be_bytes());
        assert!(!udp_checksum_ok(v6a, v6b, &u));
        u[6..8].copy_from_slice(&[0xff, 0xff]);
        assert!(udp_checksum_ok(v6a, v6b, &u));
        // A wrong checksum fails over both.
        u[6..8].copy_from_slice(&[0x12, 0x34]);
        assert!(!udp_checksum_ok(v6a, v6b, &u));
        assert!(!udp_checksum_ok(v4a, v4b, &u));
    }
}
