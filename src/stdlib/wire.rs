//! Reading and writing IP headers, for the packet stdlib.
//!
//! Small and private. Every reader checks lengths, because the agent can
//! send any bytes it likes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP protocol numbers.
pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_IPV6_FRAG: u8 = 44;
pub(crate) const PROTO_ICMPV6: u8 = 58;
pub(crate) const PROTO_NONE: u8 = 59;

/// The IP version of a packet: the top four bits of its first byte.
pub(crate) fn version(packet: &[u8]) -> Option<u8> {
    packet.first().map(|b| b >> 4)
}

/// The Internet checksum (RFC 1071) of `data`, starting from `sum`.
pub(crate) fn checksum(sum: u32, data: &[u8]) -> u16 {
    let mut sum = sum as u64;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u64) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The partial sum of an IPv6 pseudo-header (RFC 8200, section 8.1).
pub(crate) fn pseudo_v6(src: &Ipv6Addr, dst: &Ipv6Addr, next: u8, len: u32) -> u32 {
    let mut sum = 0u32;
    for a in [src.octets(), dst.octets()] {
        for c in a.chunks_exact(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
    }
    sum += len >> 16;
    sum += len & 0xffff;
    sum += next as u32;
    sum
}

/// A checked view of an IPv4 header.
pub(crate) struct V4<'a> {
    pub(crate) bytes: &'a [u8],
    /// Header length in bytes.
    pub(crate) ihl: usize,
    /// Total length, as the header says, cut to the bytes present.
    pub(crate) total: usize,
}

impl<'a> V4<'a> {
    /// Parses an IPv4 header. With `quoted`, the packet may be cut short (as
    /// the copy inside an ICMP error is), and only the header must be whole.
    pub(crate) fn parse(bytes: &'a [u8], quoted: bool) -> Option<V4<'a>> {
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return None;
        }
        let ihl = (bytes[0] & 0x0f) as usize * 4;
        if ihl < 20 || bytes.len() < ihl {
            return None;
        }
        let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if total < ihl {
            return None;
        }
        if !quoted && total > bytes.len() {
            return None;
        }
        Some(V4 { bytes, ihl, total: total.min(bytes.len()) })
    }

    pub(crate) fn proto(&self) -> u8 {
        self.bytes[9]
    }
    pub(crate) fn id(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }
    pub(crate) fn more_fragments(&self) -> bool {
        self.bytes[6] & 0x20 != 0
    }
    /// Fragment offset in bytes.
    pub(crate) fn frag_offset(&self) -> usize {
        (u16::from_be_bytes([self.bytes[6], self.bytes[7]]) & 0x1fff) as usize * 8
    }
    pub(crate) fn is_fragment(&self) -> bool {
        self.more_fragments() || self.frag_offset() != 0
    }
    pub(crate) fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15])
    }
    pub(crate) fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.bytes[16], self.bytes[17], self.bytes[18], self.bytes[19])
    }
    pub(crate) fn payload(&self) -> &'a [u8] {
        &self.bytes[self.ihl..self.total]
    }
}

/// Builds an IPv4 header with a correct checksum. `options` must be a
/// multiple of 4 bytes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn v4_header(
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ttl: u8,
    id: u16,
    tos: u8,
    options: &[u8],
    payload_len: usize,
) -> Vec<u8> {
    let ihl = 20 + options.len();
    let total = (ihl + payload_len) as u16;
    let mut h = Vec::with_capacity(ihl + payload_len);
    h.push(0x40 | (ihl / 4) as u8);
    h.push(tos);
    h.extend_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.push(ttl);
    h.push(proto);
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h.extend_from_slice(options);
    set_v4_checksum(&mut h[..ihl]);
    h
}

/// Recomputes the header checksum of an IPv4 header in place.
pub(crate) fn set_v4_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let c = checksum(0, header);
    header[10..12].copy_from_slice(&c.to_be_bytes());
}

/// A checked view of an IPv6 packet, with its extension headers walked.
pub(crate) struct V6<'a> {
    pub(crate) bytes: &'a [u8],
    /// Where the upper-layer header starts (after every extension header).
    pub(crate) upper: usize,
    /// The upper-layer protocol, or `PROTO_NONE` if the chain had none or
    /// could not be read.
    pub(crate) proto: u8,
    /// The fragment header, if any: where it starts, and where the "next
    /// header" byte that names it is.
    pub(crate) frag: Option<(usize, usize)>,
    /// The packet's length, cut to the bytes present.
    pub(crate) end: usize,
}

impl<'a> V6<'a> {
    /// Parses an IPv6 header and walks its extension headers. With `quoted`,
    /// the packet may be cut short. A chain that runs past the bytes present
    /// gives `proto` `PROTO_NONE`.
    pub(crate) fn parse(bytes: &'a [u8], quoted: bool) -> Option<V6<'a>> {
        if bytes.len() < 40 || bytes[0] >> 4 != 6 {
            return None;
        }
        let plen = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if !quoted && 40 + plen > bytes.len() {
            return None;
        }
        let end = (40 + plen).min(bytes.len());
        let mut next = bytes[6];
        let mut next_at = 6;
        let mut at = 40;
        let mut frag = None;
        loop {
            match next {
                // Hop-by-hop, routing, destination options, mobility, HIP,
                // shim6, experimental.
                0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                    if at + 2 > end {
                        next = PROTO_NONE;
                        break;
                    }
                    let len = (bytes[at + 1] as usize + 1) * 8;
                    next_at = at;
                    next = bytes[at];
                    at += len;
                }
                PROTO_IPV6_FRAG => {
                    if at + 8 > end {
                        next = PROTO_NONE;
                        break;
                    }
                    if frag.is_none() {
                        frag = Some((at, next_at));
                    }
                    // Only the first fragment carries the headers after
                    // this one.
                    let offset = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) & 0xfff8;
                    next_at = at;
                    next = bytes[at];
                    at += 8;
                    if offset != 0 {
                        break;
                    }
                }
                // Authentication header: length in 4-byte units.
                51 => {
                    if at + 2 > end {
                        next = PROTO_NONE;
                        break;
                    }
                    let len = (bytes[at + 1] as usize + 2) * 4;
                    next_at = at;
                    next = bytes[at];
                    at += len;
                }
                _ => break,
            }
            if at > end {
                next = PROTO_NONE;
                break;
            }
        }
        let _ = next_at;
        Some(V6 { bytes, upper: at.min(end), proto: next, frag, end })
    }

    pub(crate) fn src(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.bytes[8..24]);
        Ipv6Addr::from(a)
    }
    pub(crate) fn dst(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.bytes[24..40]);
        Ipv6Addr::from(a)
    }
    pub(crate) fn payload(&self) -> &'a [u8] {
        &self.bytes[self.upper..self.end]
    }
}

/// What a router hop did to a packet's TTL or hop limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hop {
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
pub(crate) fn hop(packet: &mut [u8]) -> Hop {
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
            let mut sum = u32::from(!hc) + u32::from(!old) + u32::from(new);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
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

/// The source address of an IPv4 or IPv6 packet.
pub(crate) fn source(packet: &[u8]) -> Option<IpAddr> {
    match version(packet)? {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]))),
        6 if packet.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// The destination address of an IPv4 or IPv6 packet.
pub(crate) fn destination(packet: &[u8]) -> Option<IpAddr> {
    match version(packet)? {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))),
        6 if packet.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The IPv6 extension-header chain, checked (RFC 8200, section 4)

/// IPv6 extension headers this module checks.
pub(crate) const PROTO_HOP_BY_HOP: u8 = 0;
pub(crate) const PROTO_ROUTING: u8 = 43;
pub(crate) const PROTO_DEST_OPTIONS: u8 = 60;
pub(crate) const PROTO_AUTH: u8 = 51;

/// Why an IPv6 packet's extension headers make it one a host must not
/// accept, and what RFC 8200 says to do about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtReject {
    /// Drop the packet without an answer: a header runs past the packet,
    /// an option's length runs past its header, or an option's action bits
    /// say to discard it silently.
    Discard,
    /// Drop the packet and answer with ICMPv6 Parameter Problem (type 4)
    /// with this code. `pointer` is the offset, from the start of the IPv6
    /// header, of the byte at fault.
    Problem { code: u8, pointer: u32 },
}

/// An IPv6 packet's extension-header chain, walked and checked by
/// [`ext6_chain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ext6 {
    /// The upper-layer protocol. For a fragment after the first, this is
    /// what its fragment header names, since the headers after it are in
    /// the first fragment.
    pub(crate) proto: u8,
    /// Where the upper-layer header starts.
    pub(crate) upper: usize,
    /// Where the "next header" byte that names `proto` is: 6 when there
    /// are no extension headers.
    pub(crate) proto_at: usize,
    /// The first fragment header, if any: where it starts, and where the
    /// "next header" byte that names it is.
    pub(crate) frag: Option<(usize, usize)>,
    /// The packet's length, from its payload length field.
    pub(crate) end: usize,
}

/// Walks and checks the extension-header chain of a whole IPv6 packet, as
/// a host that is the packet's destination must (RFC 8200, sections 4.1 to
/// 4.6):
///
/// - Hop-by-Hop Options may only come first. Anywhere else, it is answered
///   with Parameter Problem code 1, pointing at the "next header" byte that
///   names it.
/// - In Hop-by-Hop and Destination Options, Pad1 and PadN are skipped. Any
///   other option is unknown, and its two high bits decide: 00 skip it, 01
///   discard the packet, 10 and 11 discard it and answer with Parameter
///   Problem code 2, pointing at the option. (RFC 8200 answers 10, but not
///   11, even to a multicast address. [`parameter_problem`] answers
///   neither, as it has no address of its own to answer from.)
/// - A Routing header with Segments Left 0 is skipped. Any other is
///   answered with Parameter Problem code 0, pointing at its Routing Type:
///   a host here forwards no source-routed packets.
/// - A Fragment header is noted. In a fragment after the first, the walk
///   stops there. A second Fragment header discards the packet: no stack
///   puts a fragment inside a fragment.
/// - The Authentication header is read past and asks nothing more: the
///   world runs no IPsec, so it checks none.
/// - Anything else, including ESP and "no next header", is the upper-layer
///   protocol.
///
/// A first fragment (offset 0, more to come) must hold the whole chain and
/// the upper-layer header: 20 bytes of TCP, 8 of UDP, 4 of ICMPv6 (RFC
/// 7112). One that does not is answered with Parameter Problem code 3,
/// pointer 0. Any other header that runs past the packet discards it, and
/// so does a packet that is not a whole IPv6 packet.
pub(crate) fn ext6_chain(bytes: &[u8]) -> Result<Ext6, ExtReject> {
    use ExtReject::{Discard, Problem};
    if bytes.len() < 40 || bytes[0] >> 4 != 6 {
        return Err(Discard);
    }
    let end = 40 + u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if end > bytes.len() {
        return Err(Discard);
    }
    // A first fragment: offset 0, more to come.
    let first = |frag: Option<(usize, usize)>| {
        frag.is_some_and(|(at, _): (usize, usize)| u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) & 0xfff9 == 1)
    };
    // What a header that runs past the packet gets.
    let cut = |frag| if first(frag) { Problem { code: 3, pointer: 0 } } else { Discard };
    let mut next = bytes[6];
    let mut next_at = 6;
    let mut at = 40;
    let mut frag = None;
    loop {
        match next {
            PROTO_HOP_BY_HOP | PROTO_DEST_OPTIONS => {
                if next == PROTO_HOP_BY_HOP && next_at != 6 {
                    return Err(Problem { code: 1, pointer: next_at as u32 });
                }
                if at + 2 > end || at + (bytes[at + 1] as usize + 1) * 8 > end {
                    return Err(cut(frag));
                }
                let len = (bytes[at + 1] as usize + 1) * 8;
                check_options(&bytes[at..at + len], at)?;
                (next, next_at, at) = (bytes[at], at, at + len);
            }
            PROTO_ROUTING => {
                if at + 8 > end || at + (bytes[at + 1] as usize + 1) * 8 > end {
                    return Err(cut(frag));
                }
                let len = (bytes[at + 1] as usize + 1) * 8;
                if bytes[at + 3] != 0 {
                    return Err(Problem { code: 0, pointer: (at + 2) as u32 });
                }
                (next, next_at, at) = (bytes[at], at, at + len);
            }
            // Its length is in 4-byte units, not counting the first two.
            PROTO_AUTH => {
                if at + 2 > end || at + (bytes[at + 1] as usize + 2) * 4 > end {
                    return Err(cut(frag));
                }
                let len = (bytes[at + 1] as usize + 2) * 4;
                (next, next_at, at) = (bytes[at], at, at + len);
            }
            PROTO_IPV6_FRAG => {
                if frag.is_some() || at + 8 > end {
                    return Err(Discard);
                }
                frag = Some((at, next_at));
                let offset = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) & 0xfff8;
                (next, next_at, at) = (bytes[at], at, at + 8);
                if offset != 0 {
                    break;
                }
            }
            _ => break,
        }
    }
    let need = match next {
        PROTO_TCP => 20,
        PROTO_UDP => 8,
        PROTO_ICMPV6 => 4,
        _ => 0,
    };
    if first(frag) && end - at < need {
        return Err(Problem { code: 3, pointer: 0 });
    }
    Ok(Ext6 { proto: next, upper: at, proto_at: next_at, frag, end })
}

/// Checks the options of one Hop-by-Hop or Destination Options header,
/// `header`, which starts `base` bytes into the packet.
fn check_options(header: &[u8], base: usize) -> Result<(), ExtReject> {
    let mut i = 2;
    while i < header.len() {
        let kind = header[i];
        // Pad1: one byte, no length.
        if kind == 0 {
            i += 1;
            continue;
        }
        if i + 2 > header.len() || i + 2 + header[i + 1] as usize > header.len() {
            return Err(ExtReject::Discard);
        }
        // PadN is the only other option a host here knows.
        if kind != 1 {
            let pointer = (base + i) as u32;
            match kind >> 6 {
                0 => {}
                1 => return Err(ExtReject::Discard),
                _ => return Err(ExtReject::Problem { code: 2, pointer }),
            }
        }
        i += 2 + header[i + 1] as usize;
    }
    Ok(())
}

/// A whole IPv6 packet with its extension headers checked by
/// [`ext6_chain`] and taken out, so the upper-layer header follows the
/// IPv6 header. `Ok(None)` if it has none to take out. A packet with a
/// Fragment header is not whole, and is discarded.
///
/// What a header asks of a host is done once the check passes: skipped
/// options and a Routing header with no segments left ask for nothing more.
/// Taking them out lets layers that read only the upper-layer header, such
/// as smoltcp's TCP, accept the packet.
pub(crate) fn strip_ext6(bytes: &[u8]) -> Result<Option<Vec<u8>>, ExtReject> {
    let chain = ext6_chain(bytes)?;
    if chain.frag.is_some() {
        return Err(ExtReject::Discard);
    }
    if chain.upper == 40 {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(40 + chain.end - chain.upper);
    out.extend_from_slice(&bytes[..40]);
    out.extend_from_slice(&bytes[chain.upper..chain.end]);
    out[6] = chain.proto;
    out[4..6].copy_from_slice(&((chain.end - chain.upper) as u16).to_be_bytes());
    Ok(Some(out))
}

/// The ICMPv6 Parameter Problem answer to `bytes`, for `reject`. It comes
/// from the packet's destination and quotes as much of the packet as fits
/// in 1,280 bytes. `None` where RFC 4443 (section 2.4) forbids an answer:
/// for [`ExtReject::Discard`], to an ICMPv6 error or redirect, and from an
/// address that is not one host. Neighbor discovery messages, which belong
/// to one link, get none either. A packet to a multicast address gets no answer
/// either, since its destination is no address to answer from.
pub(crate) fn parameter_problem(bytes: &[u8], reject: ExtReject) -> Option<Vec<u8>> {
    let ExtReject::Problem { code, pointer } = reject else { return None };
    let ip = V6::parse(bytes, false)?;
    let (src, dst) = (ip.src(), ip.dst());
    if src.is_unspecified() || src.is_multicast() || src.is_loopback() || dst.is_multicast() {
        return None;
    }
    // Errors (types below 128) and redirects (137) never get an error.
    // Neither do the other neighbor discovery messages (133 to 136), which
    // belong to one link.
    // In a first fragment the message type is there to read. A later
    // fragment holds no type, so it is answered.
    let later = ip.frag.is_some_and(|(at, _)| u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) & 0xfff8 != 0);
    if ip.proto == PROTO_ICMPV6 && !later && ip.payload().first().is_some_and(|t| *t < 128 || (133..=137).contains(t)) {
        return None;
    }
    let quote = &bytes[..ip.end.min(1280 - 48)];
    let mut icmp = Vec::with_capacity(8 + quote.len());
    icmp.extend_from_slice(&[4, code, 0, 0]);
    icmp.extend_from_slice(&pointer.to_be_bytes());
    icmp.extend_from_slice(quote);
    let sum = checksum(pseudo_v6(&dst, &src, PROTO_ICMPV6, icmp.len() as u32), &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut p = Vec::with_capacity(40 + icmp.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    p.extend_from_slice(&[PROTO_ICMPV6, 64]);
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&icmp);
    Some(p)
}

#[cfg(test)]
mod ext6_tests {
    use super::*;

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

    fn problem(code: u8, pointer: u32) -> Result<Ext6, ExtReject> {
        Err(ExtReject::Problem { code, pointer })
    }

    #[test]
    fn headers_that_ask_nothing_are_walked() {
        let plain = v6(PROTO_UDP, &[0; 8]);
        assert_eq!(ext6_chain(&plain), Ok(Ext6 { proto: PROTO_UDP, upper: 40, proto_at: 6, frag: None, end: 48 }));
        // An Authentication header is read past.
        let ah = chained(51, &[&[17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
        assert_eq!(ext6_chain(&ah).map(|c| (c.proto, c.upper)), Ok((PROTO_UDP, 52)));
        // Hop-by-Hop with PadN, a Routing header with no segments left, and
        // Destination Options with an unknown option to skip and Pad1.
        let p = chained(0, &[&[43, 0, 1, 4, 0, 0, 0, 0], &[60, 0, 250, 0, 0, 0, 0, 0], &[17, 0, 0x1e, 3, 9, 9, 9, 0]]);
        assert_eq!(ext6_chain(&p), Ok(Ext6 { proto: PROTO_UDP, upper: 64, proto_at: 56, frag: None, end: 72 }));
        let stripped = strip_ext6(&p).unwrap().unwrap();
        assert_eq!(stripped, v6(PROTO_UDP, &[0, 1, 0, 2, 0, 8, 0, 0]));
        assert_eq!(strip_ext6(&plain), Ok(None));
    }

    #[test]
    fn headers_a_host_must_refuse_are_refused() {
        // Unknown options, by their two high bits.
        assert_eq!(ext6_chain(&chained(60, &[&[17, 0, 0x40, 0, 0, 0, 0, 0]])), Err(ExtReject::Discard));
        assert_eq!(ext6_chain(&chained(60, &[&[17, 0, 0x80, 0, 0, 0, 0, 0]])), problem(2, 42));
        assert_eq!(ext6_chain(&chained(0, &[&[17, 0, 1, 0, 0xc2, 0, 0, 0]])), problem(2, 44));
        // A Routing header with segments left, of any type.
        for kind in [0, 2, 3, 4, 250] {
            assert_eq!(ext6_chain(&chained(43, &[&[17, 0, kind, 1, 0, 0, 0, 0]])), problem(0, 42));
        }
        // Hop-by-Hop anywhere but first.
        assert_eq!(ext6_chain(&chained(60, &[&[0, 0, 0, 0, 0, 0, 0, 0], &[17, 0, 0, 0, 0, 0, 0, 0]])), problem(1, 40));
        // An option that runs past its header, and headers that run past
        // the packet.
        assert_eq!(ext6_chain(&chained(60, &[&[17, 0, 1, 5, 0, 0, 0, 0]])), Err(ExtReject::Discard));
        assert_eq!(ext6_chain(&v6(60, &[17, 1, 0, 0, 0, 0, 0, 0])), Err(ExtReject::Discard));
        assert_eq!(ext6_chain(&v6(43, &[17, 0, 0, 0])), Err(ExtReject::Discard));
        assert_eq!(ext6_chain(&v6(PROTO_IPV6_FRAG, &[17, 0, 0, 0])), Err(ExtReject::Discard));
        // A length field longer than the bytes present.
        let mut cut = v6(PROTO_UDP, &[0; 8]);
        cut.truncate(44);
        assert_eq!(ext6_chain(&cut), Err(ExtReject::Discard));
    }

    #[test]
    fn fragments_are_noted_and_not_stripped() {
        // A first fragment: the walk goes on past it.
        let first = chained(PROTO_IPV6_FRAG, &[&[60, 0, 0, 1, 0, 0, 0, 7], &[17, 0, 0, 0, 0, 0, 0, 0]]);
        let chain = ext6_chain(&first).unwrap();
        assert_eq!((chain.proto, chain.upper, chain.frag), (PROTO_UDP, 56, Some((40, 6))));
        // A later fragment: the walk stops at it.
        let later = chained(PROTO_IPV6_FRAG, &[&[60, 0, 0, 16, 0, 0, 0, 7]]);
        let chain = ext6_chain(&later).unwrap();
        assert_eq!((chain.proto, chain.upper), (PROTO_DEST_OPTIONS, 48));
        assert_eq!(strip_ext6(&first), Err(ExtReject::Discard));
    }

    #[test]
    fn parameter_problems_follow_rfc_4443() {
        let bad = chained(43, &[&[17, 0, 250, 1, 0, 0, 0, 0]]);
        let reject = ext6_chain(&bad).unwrap_err();
        let answer = parameter_problem(&bad, reject).expect("an answer");
        let ip = V6::parse(&answer, false).unwrap();
        assert_eq!((ip.src(), ip.dst(), ip.proto), (DST, SRC, PROTO_ICMPV6));
        let icmp = ip.payload();
        assert_eq!(&icmp[..2], &[4, 0]);
        assert_eq!(&icmp[4..8], &42u32.to_be_bytes());
        assert_eq!(&icmp[8..], &bad[..]);
        assert_eq!(checksum(pseudo_v6(&DST, &SRC, PROTO_ICMPV6, icmp.len() as u32), icmp), 0);
        // Nothing for a silent discard, to a multicast address, from an
        // unspecified one, or for an ICMPv6 error.
        assert_eq!(parameter_problem(&bad, ExtReject::Discard), None);
        let mut multicast = bad.clone();
        multicast[24] = 0xff;
        assert_eq!(parameter_problem(&multicast, reject), None);
        let mut unspecified = bad.clone();
        unspecified[8..24].fill(0);
        assert_eq!(parameter_problem(&unspecified, reject), None);
        let error = v6(43, &[PROTO_ICMPV6, 0, 250, 1, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parameter_problem(&error, ext6_chain(&error).unwrap_err()), None);
        // Nor for the first fragment of an ICMPv6 error, cut short (RFC
        // 7112): its type is there to read.
        let first = v6(PROTO_IPV6_FRAG, &[PROTO_ICMPV6, 0, 0, 1, 0, 0, 0, 9, 1, 4]);
        let reject = ext6_chain(&first).unwrap_err();
        assert_eq!(reject, ExtReject::Problem { code: 3, pointer: 0 });
        assert_eq!(parameter_problem(&first, reject), None);
        // An echo request cut short the same way is answered.
        let ping = v6(PROTO_IPV6_FRAG, &[PROTO_ICMPV6, 0, 0, 1, 0, 0, 0, 9, 128, 0]);
        assert!(parameter_problem(&ping, ext6_chain(&ping).unwrap_err()).is_some());
        // A big packet is quoted up to the minimum MTU.
        let mut big = chained(43, &[&[17, 0, 250, 1, 0, 0, 0, 0]]);
        big.resize(4000, 0);
        let len = (big.len() - 40) as u16;
        big[4..6].copy_from_slice(&len.to_be_bytes());
        assert_eq!(parameter_problem(&big, reject).unwrap().len(), 1280);
    }
}
