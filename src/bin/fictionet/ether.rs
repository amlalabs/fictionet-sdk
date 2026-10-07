//! Ethernet for `--type tap`: reading and writing the frames of a VM's
//! network card, QEMU's stream framing, and the link-local answers attach
//! gives itself (ARP and IPv6 neighbor advertisements).
//!
//! Everything here is pure: it takes bytes and returns bytes. The VM is
//! run by the agent, so every frame is read as hostile input: no length
//! is trusted before it is checked.

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::transport::{Transport, transport};

/// A MAC address.
pub(crate) type Mac = [u8; 6];

/// The broadcast MAC.
pub(crate) const BROADCAST: Mac = [0xff; 6];

/// Attach's own MAC on the VM's link: the gateway's, as the VM sees it.
/// It is locally administered (`02:...`), and the same every run, so a VM
/// that keeps running while attach restarts keeps a valid ARP entry.
pub(crate) const GATEWAY_MAC: Mac = [0x02, 0x66, 0x6e, 0x00, 0x00, 0x01];

pub(crate) const IPV4: u16 = 0x0800;
pub(crate) const ARP: u16 = 0x0806;
pub(crate) const IPV6: u16 = 0x86dd;

/// The length of an Ethernet header.
pub(crate) const HEADER: usize = 14;

pub(crate) const UDP: u8 = 17;
pub(crate) const ICMPV6: u8 = 58;

/// An Ethernet frame, read.
pub(crate) struct Frame<'a> {
    pub(crate) dst: Mac,
    pub(crate) src: Mac,
    pub(crate) ethertype: u16,
    pub(crate) payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Reads a frame. `None` if it is shorter than a header.
    pub(crate) fn parse(b: &'a [u8]) -> Option<Frame<'a>> {
        if b.len() < HEADER {
            return None;
        }
        Some(Frame {
            dst: b[0..6].try_into().unwrap(),
            src: b[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes([b[12], b[13]]),
            payload: &b[HEADER..],
        })
    }
}

/// Whether a MAC is a group (broadcast or multicast) address.
pub(crate) fn is_group(mac: &Mac) -> bool {
    mac[0] & 1 == 1
}

/// An Ethernet header.
pub(crate) fn header(dst: Mac, src: Mac, ethertype: u16) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[0..6].copy_from_slice(&dst);
    h[6..12].copy_from_slice(&src);
    h[12..14].copy_from_slice(&ethertype.to_be_bytes());
    h
}

/// A whole frame: a header, then `payload`, padded to Ethernet's minimum
/// of 60 bytes.
pub(crate) fn frame(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((HEADER + payload.len()).max(60));
    f.extend_from_slice(&header(dst, src, ethertype));
    f.extend_from_slice(payload);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

/// The Ethernet destination and type for an IP packet on its way to the
/// VM: broadcast for 255.255.255.255, the multicast MAC for a multicast
/// address, and otherwise `vm` (broadcast while the VM's MAC is not known
/// yet). `None` if the packet is neither IPv4 nor IPv6.
pub(crate) fn destination(packet: &[u8], vm: Option<Mac>) -> Option<(Mac, u16)> {
    let unicast = vm.unwrap_or(BROADCAST);
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let d: [u8; 4] = packet[16..20].try_into().unwrap();
            let mac = if d == [255; 4] {
                BROADCAST
            } else if Ipv4Addr::from(d).is_multicast() {
                [0x01, 0x00, 0x5e, d[1] & 0x7f, d[2], d[3]]
            } else {
                unicast
            };
            Some((mac, IPV4))
        }
        6 if packet.len() >= 40 => {
            let d = &packet[24..40];
            let mac = if d[0] == 0xff { [0x33, 0x33, d[12], d[13], d[14], d[15]] } else { unicast };
            Some((mac, IPV6))
        }
        _ => None,
    }
}

/// The IP packet in an IPv4 or IPv6 frame's payload, without the padding
/// Ethernet may add after it. `None` if the header is broken or says the
/// packet is longer than the payload.
pub(crate) fn ip_packet(ethertype: u16, payload: &[u8]) -> Option<&[u8]> {
    match ethertype {
        IPV4 => {
            let b = payload;
            if b.len() < 20 || b[0] >> 4 != 4 {
                return None;
            }
            let ihl = (b[0] & 0x0f) as usize * 4;
            let total = u16::from_be_bytes([b[2], b[3]]) as usize;
            if ihl < 20 || total < ihl || total > b.len() {
                return None;
            }
            Some(&b[..total])
        }
        IPV6 => {
            let b = payload;
            if b.len() < 40 || b[0] >> 4 != 6 {
                return None;
            }
            let total = 40 + u16::from_be_bytes([b[4], b[5]]) as usize;
            if total > b.len() {
                return None;
            }
            Some(&b[..total])
        }
        _ => None,
    }
}

// Checksums and packet building

/// The ones' complement sum of `data` as 16-bit words, added to `sum`.
fn add(mut sum: u32, data: &[u8]) -> u32 {
    let (chunks, rest) = data.as_chunks::<2>();
    for c in chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        // Fold early, so a long packet cannot overflow.
        if sum > 0xffff_0000 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    if let [last] = rest {
        sum += (*last as u32) << 8;
    }
    sum
}

/// Folds a sum and complements it: the Internet checksum.
fn finish(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 packet around `payload`, with TTL 64 and a correct header
/// checksum.
pub(crate) fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, proto, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let sum = finish(add(0, &p));
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// A UDP datagram in an IPv4 packet, with a correct checksum.
pub(crate) fn udp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    let u = udp(sport, dport, data, |u| {
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src.octets());
        pseudo[4..8].copy_from_slice(&dst.octets());
        pseudo[9] = UDP;
        pseudo[10..12].copy_from_slice(&(u.len() as u16).to_be_bytes());
        add(add(0, &pseudo), u)
    });
    ipv4(src, dst, UDP, &u)
}

/// A UDP datagram, its checksum computed by `sum` over the datagram with
/// the checksum field zero.
fn udp(sport: u16, dport: u16, data: &[u8], sum: impl Fn(&[u8]) -> u32) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + data.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let mut c = finish(sum(&u));
    if c == 0 {
        c = 0xffff;
    }
    u[6..8].copy_from_slice(&c.to_be_bytes());
    u
}

/// The IPv6 pseudo-header sum for an upper-layer packet of `len` bytes.
fn pseudo_v6(src: &Ipv6Addr, dst: &Ipv6Addr, next: u8, len: usize) -> u32 {
    let mut s = add(0, &src.octets());
    s = add(s, &dst.octets());
    s = add(s, &(len as u32).to_be_bytes());
    add(s, &[0, 0, 0, next])
}

/// An IPv6 packet around `payload`.
pub(crate) fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.push(next);
    p.push(hop_limit);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// A UDP datagram in an IPv6 packet, with a correct checksum.
pub(crate) fn udp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    let u = udp(sport, dport, data, |u| add(pseudo_v6(&src, &dst, UDP, u.len()), u));
    ipv6(src, dst, UDP, 64, &u)
}

/// An ICMPv6 message in an IPv6 packet with hop limit 255, as neighbor
/// discovery requires. `body` is the whole message with its checksum
/// field (bytes 2 and 3) zero; this fills it in.
pub(crate) fn icmp6(src: Ipv6Addr, dst: Ipv6Addr, mut body: Vec<u8>) -> Vec<u8> {
    let sum = finish(add(pseudo_v6(&src, &dst, ICMPV6, body.len()), &body));
    body[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv6(src, dst, ICMPV6, 255, &body)
}

/// The link-local address made from a MAC (modified EUI-64).
pub(crate) fn link_local(mac: Mac) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    Ipv6Addr::from(a)
}

// ARP and neighbor discovery

/// The answer to an ARP request from the VM: a reply frame that gives
/// [`GATEWAY_MAC`] for the asked address. Attach answers for every
/// address, as a proxy ARP router does, so every packet the VM sends
/// reaches attach, and the world decides what is there. It does not
/// answer:
///
/// - probes (sender address 0.0.0.0) and gratuitous ARP (sender address
///   equal to the target): an answer would tell the VM its own address is
///   taken;
/// - questions about `own`, the address attach handed the VM, for the same
///   reason;
/// - anything that is not an Ethernet/IPv4 request.
pub(crate) fn arp_reply(arp: &[u8], vm: Mac, own: Option<Ipv4Addr>) -> Option<Vec<u8>> {
    if arp.len() < 28 || arp[0..8] != [0, 1, 0x08, 0x00, 6, 4, 0, 1] {
        return None;
    }
    let sha = &arp[8..14];
    let spa = &arp[14..18];
    let tpa = &arp[24..28];
    if spa == [0; 4] || spa == tpa || own.is_some_and(|a| a.octets() == tpa) {
        return None;
    }
    let mut reply = Vec::with_capacity(28);
    reply.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
    reply.extend_from_slice(&GATEWAY_MAC);
    reply.extend_from_slice(tpa);
    reply.extend_from_slice(sha);
    reply.extend_from_slice(spa);
    Some(frame(vm, GATEWAY_MAC, ARP, &reply))
}

/// ICMPv6 types of neighbor discovery.
pub(crate) const ROUTER_SOLICITATION: u8 = 133;
pub(crate) const ROUTER_ADVERTISEMENT: u8 = 134;
pub(crate) const NEIGHBOR_SOLICITATION: u8 = 135;
pub(crate) const NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub(crate) const REDIRECT: u8 = 137;

/// What attach needs to know about the transport of one IP packet from
/// the VM. [`transport`](fictionet::stdlib::transport::transport) reads
/// the extension headers and fragments, with the parser the world's own
/// stack uses; this adds the UDP port and the ICMPv6 type.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Upper<'a> {
    /// A whole UDP datagram: its destination port and payload.
    Udp { port: u16, payload: &'a [u8] },
    /// The first fragment of a UDP datagram: its destination port. The rest
    /// of the datagram is in later fragments, which attach does not keep.
    UdpFragment { port: u16 },
    /// An ICMPv6 message: its type, and the message from its first byte.
    /// With `fragment`, this is the first fragment of a longer message.
    Icmp6 { kind: u8, msg: &'a [u8], fragment: bool },
    /// Any other transport, or a fragment other than the first, which
    /// holds no transport header.
    Other,
}

/// A packet whose transport attach cannot read: an IPv6 extension header
/// that runs past its end, a UDP or ICMPv6 header cut short (in a first
/// fragment, too), or a UDP length that does not fit the packet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unreadable;

/// Reads the transport of an IP packet, which [`ip_packet`] has checked.
pub(crate) fn upper(packet: &[u8]) -> Result<Upper<'_>, Unreadable> {
    let (proto, bytes, fragment) = match transport(packet).ok_or(Unreadable)? {
        Transport::Whole { proto, bytes } => (proto, bytes, false),
        // An atomic fragment is a whole packet, but neighbor discovery may
        // not carry a fragment header at all (RFC 6980), so it counts as a
        // fragment here.
        Transport::First { proto, bytes } | Transport::Atomic { proto, bytes } => (proto, bytes, true),
        Transport::Later => return Ok(Upper::Other),
    };
    match proto {
        UDP => {
            if bytes.len() < 8 {
                return Err(Unreadable);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            if fragment {
                return Ok(Upper::UdpFragment { port });
            }
            let len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
            if len < 8 || len > bytes.len() {
                return Err(Unreadable);
            }
            Ok(Upper::Udp { port, payload: &bytes[8..len] })
        }
        ICMPV6 if packet[0] >> 4 == 6 => {
            if bytes.len() < 4 {
                return Err(Unreadable);
            }
            Ok(Upper::Icmp6 { kind: bytes[0], msg: bytes, fragment })
        }
        _ => Ok(Upper::Other),
    }
}

/// The ICMPv6 types of neighbor discovery and redirects, which only make
/// sense on one link.
pub(crate) fn is_neighbor_discovery(kind: u8) -> bool {
    (ROUTER_SOLICITATION..=REDIRECT).contains(&kind)
}

/// The answer to a neighbor solicitation from the VM: a neighbor
/// advertisement that gives [`GATEWAY_MAC`] for the target, for the same
/// reason [`arp_reply`] answers every address. It does not answer
/// duplicate address detection (source `::`), a target that is `own` or
/// multicast, or a solicitation that is not valid (hop limit other than
/// 255, code other than 0).
pub(crate) fn neighbor_advert(packet: &[u8], vm: Mac, own: Option<Ipv6Addr>) -> Option<Vec<u8>> {
    let Ok(Upper::Icmp6 { kind: NEIGHBOR_SOLICITATION, msg, fragment: false }) = upper(packet) else { return None };
    if msg[1] != 0 || packet[7] != 255 || msg.len() < 24 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&msg[8..24]).unwrap());
    if src.is_unspecified() || target.is_multicast() || Some(target) == own {
        return None;
    }
    let mut body = Vec::with_capacity(32);
    // Router, solicited and override: the VM may use attach as a router
    // for any address, so the router flag is always set.
    body.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT, 0, 0, 0, 0xe0, 0, 0, 0]);
    body.extend_from_slice(&target.octets());
    // Target link-layer address option.
    body.extend_from_slice(&[2, 1]);
    body.extend_from_slice(&GATEWAY_MAC);
    let ip = icmp6(target, src, body);
    Some(frame(vm, GATEWAY_MAC, IPV6, &ip))
}

/// The UDP destination port and payload of an IPv4 or IPv6 packet that
/// holds a whole UDP datagram. `None` otherwise.
#[cfg(test)]
pub(crate) fn udp_to(packet: &[u8]) -> Option<(u16, &[u8])> {
    match upper(packet) {
        Ok(Upper::Udp { port, payload }) => Some((port, payload)),
        _ => None,
    }
}

/// The source address of an IPv4 or IPv6 packet. The packet must be at
/// least a header long, as [`ip_packet`] checks.
pub(crate) fn source_v4(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])
}

pub(crate) fn source_v6(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap())
}

// QEMU's stream framing

/// The longest frame QEMU's stream backend sends: its 68 KiB buffer. A
/// longer length means the stream is broken.
pub(crate) const MAX_STREAM_FRAME: usize = 69_632;

/// Splits QEMU's stream into frames. On a `-netdev stream` socket, each
/// frame is a 32-bit big-endian length, then that many bytes.
pub(crate) struct Decoder {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

/// A length prefix longer than [`MAX_STREAM_FRAME`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TooLong(pub(crate) usize);

impl Decoder {
    pub(crate) fn new() -> Decoder {
        Decoder { buf: vec![0; 4 * (4 + MAX_STREAM_FRAME)], start: 0, end: 0 }
    }

    /// Where the next read should go. Never empty.
    pub(crate) fn spare(&mut self) -> &mut [u8] {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.buf.len() - self.end < 4 + MAX_STREAM_FRAME {
            // Move the partial frame to the front, so a whole frame fits.
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        &mut self.buf[self.end..]
    }

    /// Records that `n` bytes were read into [`spare`](Decoder::spare).
    pub(crate) fn filled(&mut self, n: usize) {
        self.end += n;
    }

    /// The next whole frame, if one has arrived.
    pub(crate) fn next_frame(&mut self) -> Result<Option<&[u8]>, TooLong> {
        let have = &self.buf[self.start..self.end];
        if have.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([have[0], have[1], have[2], have[3]]) as usize;
        if len > MAX_STREAM_FRAME {
            return Err(TooLong(len));
        }
        if have.len() < 4 + len {
            return Ok(None);
        }
        let at = self.start + 4;
        self.start = at + len;
        Ok(Some(&self.buf[at..at + len]))
    }
}

/// Frames waiting to be written to QEMU's stream, each with its length
/// prefix. It holds at most `cap` bytes; a frame that does not fit is
/// dropped, as a full network card queue drops it.
pub(crate) struct Outbox {
    buf: Vec<u8>,
    start: usize,
    cap: usize,
}

impl Outbox {
    pub(crate) fn new(cap: usize) -> Outbox {
        Outbox { buf: Vec::new(), start: 0, cap }
    }

    /// Queues one frame made of `parts`. `false` if it was dropped.
    pub(crate) fn push(&mut self, parts: &[&[u8]]) -> bool {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if self.len() + 4 + len > self.cap {
            return false;
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(&(len as u32).to_be_bytes());
        for p in parts {
            self.buf.extend_from_slice(p);
        }
        true
    }

    /// The bytes waiting.
    pub(crate) fn len(&self) -> usize {
        self.buf.len() - self.start
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes to write next.
    pub(crate) fn pending(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// Records that `n` bytes of [`pending`](Outbox::pending) were written.
    pub(crate) fn written(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const VM: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    /// Checks the Internet checksum over `data` (it sums to zero).
    pub(crate) fn sums_to_zero(sum: u32, data: &[u8]) -> bool {
        finish(add(sum, data)) == 0
    }

    pub(crate) fn v6_checksum_ok(packet: &[u8]) -> bool {
        let src = source_v6(packet);
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        sums_to_zero(pseudo_v6(&src, &dst, packet[6], packet.len() - 40), &packet[40..])
    }

    fn arp_request(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut a = vec![0, 1, 0x08, 0x00, 6, 4, 0, 1];
        a.extend_from_slice(&VM);
        a.extend_from_slice(&spa);
        a.extend_from_slice(&[0; 6]);
        a.extend_from_slice(&tpa);
        a
    }

    #[test]
    fn frames_parse_and_build() {
        let f = frame(VM, GATEWAY_MAC, IPV4, &[1, 2, 3]);
        assert_eq!(f.len(), 60, "padded to the minimum");
        let p = Frame::parse(&f).unwrap();
        assert_eq!((p.dst, p.src, p.ethertype), (VM, GATEWAY_MAC, IPV4));
        assert_eq!(&p.payload[..3], &[1, 2, 3]);
        assert!(Frame::parse(&f[..13]).is_none());
        assert!(is_group(&BROADCAST) && is_group(&[0x33, 0x33, 0, 0, 0, 1]) && !is_group(&VM));
    }

    #[test]
    fn padding_is_trimmed_and_lying_lengths_are_refused() {
        let p = udp4(Ipv4Addr::new(10, 0, 0, 2), 1, Ipv4Addr::new(10, 0, 0, 1), 2, b"hi");
        let mut padded = p.clone();
        padded.resize(46, 0);
        assert_eq!(ip_packet(IPV4, &padded), Some(&p[..]));
        assert_eq!(ip_packet(IPV4, &p[..p.len() - 1]), None, "total length past the end");
        let mut bad = p.clone();
        bad[0] = 0x44;
        assert_eq!(ip_packet(IPV4, &bad), None, "header length under 20");
        let p6 = udp6(link_local(VM), 1, link_local(GATEWAY_MAC), 2, b"hi");
        let mut padded = p6.clone();
        padded.extend_from_slice(&[0; 4]);
        assert_eq!(ip_packet(IPV6, &padded), Some(&p6[..]));
        assert_eq!(ip_packet(IPV6, &p6[..p6.len() - 1]), None);
        assert_eq!(ip_packet(IPV6, &p), None, "an IPv4 packet in an IPv6 frame");
        assert_eq!(ip_packet(ARP, &p), None);
    }

    #[test]
    fn built_packets_have_correct_checksums() {
        let p = udp4(Ipv4Addr::new(10, 0, 0, 1), 67, Ipv4Addr::BROADCAST, 68, b"odd");
        assert!(sums_to_zero(0, &p[..20]), "IPv4 header");
        let mut pseudo = vec![10, 0, 0, 1, 255, 255, 255, 255, 0, UDP];
        pseudo.extend_from_slice(&((p.len() - 20) as u16).to_be_bytes());
        assert!(sums_to_zero(add(0, &pseudo), &p[20..]), "UDP over IPv4");
        let p = udp6(link_local(GATEWAY_MAC), 547, link_local(VM), 546, b"odd");
        assert!(v6_checksum_ok(&p));
        assert_eq!(udp_to(&p), Some((546, &b"odd"[..])));
    }

    #[test]
    fn destinations() {
        let to = |dst: Ipv4Addr| destination(&ipv4(Ipv4Addr::new(10, 0, 0, 1), dst, UDP, &[]), Some(VM));
        assert_eq!(to(Ipv4Addr::new(10, 0, 0, 2)), Some((VM, IPV4)));
        assert_eq!(to(Ipv4Addr::BROADCAST), Some((BROADCAST, IPV4)));
        assert_eq!(to(Ipv4Addr::new(239, 129, 2, 3)), Some(([1, 0, 0x5e, 1, 2, 3], IPV4)));
        let p = ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), UDP, &[]);
        assert_eq!(destination(&p, None), Some((BROADCAST, IPV4)), "the VM's MAC is not known yet");
        let p = ipv6(link_local(GATEWAY_MAC), "ff02::1:ff12:3456".parse().unwrap(), UDP, 1, &[]);
        assert_eq!(destination(&p, Some(VM)), Some(([0x33, 0x33, 0xff, 0x12, 0x34, 0x56], IPV6)));
        let p = ipv6(link_local(GATEWAY_MAC), "fd00::2".parse().unwrap(), UDP, 1, &[]);
        assert_eq!(destination(&p, Some(VM)), Some((VM, IPV6)));
        assert_eq!(destination(&[0x50; 40], Some(VM)), None);
        assert_eq!(destination(&[0x45; 19], Some(VM)), None);
        assert_eq!(destination(&[], Some(VM)), None);
    }

    #[test]
    fn arp_answers_every_address_but_probes_gratuitous_and_its_own() {
        let reply = arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 1]), VM, None).unwrap();
        let f = Frame::parse(&reply).unwrap();
        assert_eq!((f.dst, f.src, f.ethertype), (VM, GATEWAY_MAC, ARP));
        let a = f.payload;
        assert_eq!(&a[6..8], &[0, 2], "a reply");
        assert_eq!(&a[8..14], &GATEWAY_MAC, "the gateway's MAC");
        assert_eq!(&a[14..18], &[10, 0, 0, 1], "for the asked address");
        assert_eq!(&a[18..24], &VM);
        assert_eq!(&a[24..28], &[10, 0, 0, 2]);
        // Any address: the world decides what is there.
        assert!(arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 77]), VM, None).is_some());
        // A probe, a gratuitous ARP, and a question about the VM's own address.
        assert!(arp_reply(&arp_request([0; 4], [10, 0, 0, 2]), VM, None).is_none());
        assert!(arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 2]), VM, None).is_none());
        let own = Some(Ipv4Addr::new(10, 0, 0, 2));
        assert!(arp_reply(&arp_request([10, 0, 0, 9], [10, 0, 0, 2]), VM, own).is_none());
        // A reply, a short request, another hardware type.
        let mut r = arp_request([10, 0, 0, 2], [10, 0, 0, 1]);
        r[7] = 2;
        assert!(arp_reply(&r, VM, None).is_none());
        assert!(arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 1])[..27], VM, None).is_none());
        let mut r = arp_request([10, 0, 0, 2], [10, 0, 0, 1]);
        r[1] = 6;
        assert!(arp_reply(&r, VM, None).is_none());
    }

    pub(crate) fn solicitation(src: Ipv6Addr, target: Ipv6Addr, hop: u8) -> Vec<u8> {
        let mut body = vec![NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        body.extend_from_slice(&[1, 1]);
        body.extend_from_slice(&VM);
        let mut p = icmp6(src, "ff02::1:ff00:1".parse().unwrap(), body);
        p[7] = hop;
        p
    }

    #[test]
    fn neighbor_solicitations_are_answered_except_dad() {
        let vm_ll = link_local(VM);
        let target: Ipv6Addr = "fd00::1".parse().unwrap();
        let reply = neighbor_advert(&solicitation(vm_ll, target, 255), VM, None).unwrap();
        let f = Frame::parse(&reply).unwrap();
        assert_eq!((f.dst, f.src, f.ethertype), (VM, GATEWAY_MAC, IPV6));
        let p = f.payload;
        assert!(v6_checksum_ok(p));
        assert_eq!(p[7], 255, "hop limit");
        assert_eq!(source_v6(p), target);
        assert_eq!(&p[24..40], &vm_ll.octets());
        assert_eq!(p[40], NEIGHBOR_ADVERTISEMENT);
        assert_eq!(p[44], 0xe0, "router, solicited, override");
        assert_eq!(&p[48..64], &target.octets());
        assert_eq!(&p[64..72], &[2, 1, 0x02, 0x66, 0x6e, 0, 0, 1]);

        let dad = solicitation(Ipv6Addr::UNSPECIFIED, "fd00::2".parse().unwrap(), 255);
        assert!(neighbor_advert(&dad, VM, None).is_none(), "duplicate address detection");
        assert!(neighbor_advert(&solicitation(vm_ll, target, 64), VM, None).is_none(), "hop limit not 255");
        assert!(neighbor_advert(&solicitation(vm_ll, "ff02::1".parse().unwrap(), 255), VM, None).is_none());
        assert!(neighbor_advert(&solicitation(vm_ll, target, 255), VM, Some(target)).is_none(), "its own address");
        let short = solicitation(vm_ll, target, 255);
        assert!(neighbor_advert(&short[..60], VM, None).is_none());
    }

    /// `n` destination options headers, then `inner` (an upper-layer
    /// header of protocol `proto`), in a packet from the VM's link-local
    /// address.
    fn behind_options(n: usize, proto: u8, inner: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        for i in 0..n {
            ext.extend_from_slice(&[if i + 1 == n { proto } else { 60 }, 0, 1, 4, 0, 0, 0, 0]);
        }
        ext.extend_from_slice(inner);
        ipv6(link_local(VM), "ff02::1".parse().unwrap(), if n == 0 { proto } else { 60 }, 255, &ext)
    }

    fn icmp6_kind(p: &[u8]) -> Option<u8> {
        match upper(p) {
            Ok(Upper::Icmp6 { kind, .. }) => Some(kind),
            _ => None,
        }
    }

    #[test]
    fn extension_headers_are_skipped() {
        let src = link_local(VM);
        let ra = icmp6(src, "ff02::1".parse().unwrap(), vec![ROUTER_ADVERTISEMENT, 0, 0, 0, 64, 0, 0, 0]);
        // The same message behind a hop-by-hop header.
        let mut ext = vec![ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&ra[40..]);
        let p = ipv6(src, "ff02::1".parse().unwrap(), 0, 255, &ext);
        assert_eq!(icmp6_kind(&p), Some(ROUTER_ADVERTISEMENT));
        // Behind eight destination options headers, and behind sixteen: no
        // chain is too long to read.
        assert_eq!(icmp6_kind(&behind_options(8, ICMPV6, &ra[40..])), Some(ROUTER_ADVERTISEMENT));
        assert_eq!(icmp6_kind(&behind_options(16, ICMPV6, &ra[40..])), Some(ROUTER_ADVERTISEMENT));
        // Behind an authentication header.
        let mut ah = vec![ICMPV6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ah.extend_from_slice(&ra[40..]);
        assert_eq!(icmp6_kind(&ipv6(src, "ff02::1".parse().unwrap(), 51, 255, &ah)), Some(ROUTER_ADVERTISEMENT));
        // A first fragment holds the type, and says it is a fragment; a later
        // one does not hold it.
        let mut frag = vec![ICMPV6, 0, 0, 1, 0, 0, 0, 7];
        frag.extend_from_slice(&ra[40..]);
        let p = ipv6(src, "ff02::1".parse().unwrap(), 44, 255, &frag);
        assert!(matches!(upper(&p), Ok(Upper::Icmp6 { kind: ROUTER_ADVERTISEMENT, fragment: true, .. })));
        let mut later = frag.clone();
        later[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(upper(&ipv6(src, "ff02::1".parse().unwrap(), 44, 255, &later)), Ok(Upper::Other));
        // A header that runs past the end cannot be read, unlike a packet
        // that is simply not ICMPv6 or UDP.
        assert_eq!(upper(&ipv6(src, src, 0, 1, &[UDP, 9])), Err(Unreadable));
        assert_eq!(upper(&ipv6(src, src, 6, 1, &[0; 20])), Ok(Upper::Other));
        // UDP behind a destination options header.
        let mut dst = vec![UDP, 0, 1, 4, 0, 0, 0, 0];
        dst.extend_from_slice(&udp6(src, 546, src, 547, b"x")[40..]);
        assert_eq!(udp_to(&ipv6(src, src, 60, 1, &dst)), Some((547, &b"x"[..])));
    }

    #[test]
    fn udp_lengths_and_fragments() {
        let p = udp4(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67, b"discover");
        assert_eq!(upper(&p), Ok(Upper::Udp { port: 67, payload: b"discover" }));
        // A UDP length past the packet's end, or under the header's.
        let mut long = p.clone();
        long[24..26].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(upper(&long), Err(Unreadable));
        let mut short = p.clone();
        short[24..26].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(upper(&short), Err(Unreadable));
        // The first fragment gives the port, and only the port.
        let mut first = p.clone();
        first[6] = 0x20;
        assert_eq!(upper(&first), Ok(Upper::UdpFragment { port: 67 }));
        let mut later = p.clone();
        later[7] = 1;
        assert_eq!(upper(&later), Ok(Upper::Other));
        // A first fragment that stops inside the UDP header.
        let cut = ipv4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::BROADCAST, UDP, &p[20..24]);
        let mut cut_first = cut.clone();
        cut_first[6] = 0x20;
        assert_eq!(upper(&cut_first), Err(Unreadable));
        // IPv6: a first fragment of a DHCPv6 request.
        let u = udp6(link_local(VM), 546, "ff02::1:2".parse().unwrap(), 547, &[1; 40]);
        let mut frag = vec![UDP, 0, 0, 1, 0, 0, 0, 9];
        frag.extend_from_slice(&u[40..88]);
        let p6 = ipv6(link_local(VM), "ff02::1:2".parse().unwrap(), 44, 64, &frag);
        assert_eq!(upper(&p6), Ok(Upper::UdpFragment { port: 547 }));
    }

    #[test]
    fn link_local_from_mac() {
        assert_eq!(link_local(VM), "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap());
        assert_eq!(link_local(GATEWAY_MAC), "fe80::66:6eff:fe00:1".parse::<Ipv6Addr>().unwrap());
    }

    fn stream(frames: &[&[u8]]) -> Vec<u8> {
        let mut s = Vec::new();
        for f in frames {
            s.extend_from_slice(&(f.len() as u32).to_be_bytes());
            s.extend_from_slice(f);
        }
        s
    }

    fn feed(d: &mut Decoder, bytes: &[u8]) {
        let spare = d.spare();
        spare[..bytes.len()].copy_from_slice(bytes);
        d.filled(bytes.len());
    }

    #[test]
    fn decoder_splits_frames_across_reads() {
        let big = vec![7u8; 9014];
        let s = stream(&[b"first", &big, b"", b"last"]);
        let mut d = Decoder::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        // One byte at a time, then in odd pieces.
        for b in &s {
            feed(&mut d, std::slice::from_ref(b));
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f.to_vec());
            }
        }
        assert_eq!(got, vec![b"first".to_vec(), big.clone(), vec![], b"last".to_vec()]);
        got.clear();
        for piece in s.chunks(1000) {
            feed(&mut d, piece);
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f.to_vec());
            }
        }
        assert_eq!(got.len(), 4);
        assert_eq!(got[1], big);
    }

    #[test]
    fn decoder_keeps_room_for_a_whole_frame() {
        // Many full-size frames, read in pieces that leave a partial frame
        // at the end of the buffer each time.
        let f = vec![1u8; MAX_STREAM_FRAME];
        let s = stream(&[&f, &f, &f, &f, &f, &f, &f]);
        let mut d = Decoder::new();
        let mut n = 0;
        let mut at = 0;
        while at < s.len() {
            let spare = d.spare();
            assert!(spare.len() >= 4 + MAX_STREAM_FRAME);
            let k = spare.len().min(s.len() - at).min(100_000);
            spare[..k].copy_from_slice(&s[at..at + k]);
            d.filled(k);
            at += k;
            while let Some(frame) = d.next_frame().unwrap() {
                assert_eq!(frame.len(), MAX_STREAM_FRAME);
                n += 1;
            }
        }
        assert_eq!(n, 7);
    }

    #[test]
    fn decoder_refuses_a_length_past_qemus_buffer() {
        let mut d = Decoder::new();
        feed(&mut d, &((MAX_STREAM_FRAME + 1) as u32).to_be_bytes());
        assert_eq!(d.next_frame(), Err(TooLong(MAX_STREAM_FRAME + 1)));
        let mut d = Decoder::new();
        feed(&mut d, &u32::MAX.to_be_bytes());
        assert!(d.next_frame().is_err());
    }

    #[test]
    fn outbox_frames_and_drops_when_full() {
        let mut o = Outbox::new(20);
        assert!(o.push(&[b"abc", b"de"]));
        assert_eq!(o.pending(), &[0, 0, 0, 5, b'a', b'b', b'c', b'd', b'e']);
        assert!(!o.push(&[&[0u8; 8]]), "9 + 12 > 20");
        assert!(o.push(&[&[9u8; 7]]));
        assert_eq!(o.len(), 20);
        o.written(9);
        assert_eq!(o.pending(), &[0, 0, 0, 7, 9, 9, 9, 9, 9, 9, 9]);
        assert!(o.push(&[b"x"]), "room again after a write");
        o.written(o.len());
        assert!(o.is_empty());
    }
}
