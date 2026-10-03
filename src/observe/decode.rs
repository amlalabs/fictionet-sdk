//! Decoding packets the way Wireshark shows them: a list line (source,
//! destination, protocol, info) and a tree of layers whose fields point at
//! their bytes.
//!
//! Packets on a link are raw IPv4 or IPv6, with no Ethernet header. A
//! [`Dissector`] sees every copied packet of one link in order, so it can
//! follow TCP streams across packets.

use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::json;
use crate::watch::KeyLine;

/// A field of a layer, and where its bytes are.
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) value: String,
    /// Byte range in the layer's buffer.
    pub(crate) range: Option<(usize, usize)>,
}

/// One protocol layer of a packet.
pub(crate) struct Layer {
    pub(crate) name: String,
    pub(crate) summary: String,
    /// Which buffer the ranges index: 0 is the packet itself.
    pub(crate) buf: usize,
    pub(crate) range: (usize, usize),
    pub(crate) fields: Vec<Field>,
}

impl Layer {
    pub(crate) fn new(name: &str, buf: usize, range: (usize, usize)) -> Layer {
        Layer { name: name.to_owned(), summary: String::new(), buf, range, fields: Vec::new() }
    }

    pub(crate) fn field(&mut self, name: &str, value: impl Into<String>, range: (usize, usize)) {
        self.fields.push(Field { name: name.to_owned(), value: value.into(), range: Some(range) });
    }

    pub(crate) fn note(&mut self, name: &str, value: impl Into<String>) {
        self.fields.push(Field { name: name.to_owned(), value: value.into(), range: None });
    }

    /// Roughly how many bytes the layer adds to the packet's detail.
    fn size(&self) -> usize {
        let fields: usize = self.fields.iter().map(|f| f.name.len() + f.value.len() + 32).sum();
        self.name.len() + self.summary.len() + fields + 64
    }
}

/// The most bytes of layers and buffers one packet's detail holds. One
/// packet can complete many messages at once, such as when it fills a gap
/// that held segments were waiting on, and HTTP/2 headers can name the
/// same long table entry many times over. Past this, the decoders still
/// follow the stream, but what they find is not kept.
pub(crate) const MAX_DETAIL: usize = 1 << 20;
/// The longest list line kept.
const MAX_INFO: usize = 1024;

/// A decoded packet.
#[derive(Default)]
pub(crate) struct Decoded {
    pub(crate) src: String,
    pub(crate) dst: String,
    pub(crate) proto: String,
    pub(crate) info: String,
    pub(crate) tags: Vec<&'static str>,
    /// How high the protocol in `proto` is: 0 for IP and transport, 1 for
    /// TLS, 2 for what TLS carries and other applications.
    pub(crate) level: u8,
    pub(crate) layers: Vec<Layer>,
    /// Bytes other than the packet that layers point into, such as
    /// decrypted TLS, with a name for each.
    pub(crate) extra: Vec<(String, Vec<u8>)>,
    /// Bytes of layers and buffers kept so far, toward [`MAX_DETAIL`].
    used: usize,
    /// Layers and buffers not kept, past [`MAX_DETAIL`].
    pub(crate) cut: usize,
}

impl Decoded {
    /// The layers as a JSON array.
    #[cfg(test)]
    pub(crate) fn layers_json(&self) -> String {
        let mut out = String::new();
        self.write_layers(&mut out);
        out
    }

    /// Appends the layers as a JSON array: objects with `name`, `summary`,
    /// `buf`, `range` and `fields`, each field with `name`, `value` and,
    /// if it points at bytes, `range`. Written straight into `out`, since
    /// this runs for every packet kept on a watched link.
    pub(crate) fn write_layers(&self, out: &mut String) {
        out.push('[');
        for (i, l) in self.layers.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            json::string(out, &l.name);
            out.push_str(",\"summary\":");
            json::string(out, &l.summary);
            let _ = write!(out, ",\"buf\":{},\"range\":[{},{}],\"fields\":[", l.buf, l.range.0, l.range.1);
            for (j, f) in l.fields.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                out.push_str("{\"name\":");
                json::string(out, &f.name);
                out.push_str(",\"value\":");
                json::string(out, &f.value);
                if let Some((a, b)) = f.range {
                    let _ = write!(out, ",\"range\":[{a},{b}]");
                }
                out.push('}');
            }
            out.push_str("]}");
        }
        out.push(']');
    }

    /// Appends the buffers as a JSON array: the packet, then each extra
    /// buffer, as objects with `name` and `hex`.
    pub(crate) fn write_buffers(&self, out: &mut String, packet: &[u8]) {
        out.reserve(2 * packet.len() + self.extra.iter().map(|(n, b)| n.len() + 2 * b.len() + 24).sum::<usize>() + 32);
        out.push('[');
        let all = std::iter::once(("Packet", packet)).chain(self.extra.iter().map(|(n, b)| (n.as_str(), b.as_slice())));
        for (i, (name, bytes)) in all.enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            json::string(out, name);
            out.push_str(",\"hex\":\"");
            super::packets::push_hex(out, bytes);
            out.push_str("\"}");
        }
        out.push(']');
    }

    /// Adds a buffer and returns its index. Past [`MAX_DETAIL`], the buffer
    /// is not kept, and neither is any layer after it, so the index it
    /// returns is never shown.
    pub(crate) fn buffer(&mut self, name: &str, bytes: Vec<u8>) -> usize {
        // Shown as hex: two characters a byte.
        if !self.take(name.len() + bytes.len() * 2) {
            return self.extra.len() + 1;
        }
        self.extra.push((name.to_owned(), bytes));
        self.extra.len()
    }

    /// Adds a layer, unless the detail is full.
    pub(crate) fn push(&mut self, layer: Layer) {
        if self.take(layer.size()) {
            self.layers.push(layer);
        }
    }

    /// Counts `n` more bytes toward [`MAX_DETAIL`], if they fit and nothing
    /// was cut before.
    fn take(&mut self, n: usize) -> bool {
        if self.cut > 0 || n > self.room() {
            self.cut += 1;
            return false;
        }
        self.used += n;
        true
    }

    /// Bytes the detail still has room for.
    pub(crate) fn room(&self) -> usize {
        if self.cut > 0 { 0 } else { MAX_DETAIL - self.used }
    }

    /// Adds a tag, once.
    pub(crate) fn tag(&mut self, tag: &'static str) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Cuts the list line to [`MAX_INFO`] bytes.
    pub(crate) fn cap_info(&mut self) {
        if self.info.len() > MAX_INFO {
            let mut end = MAX_INFO;
            while !self.info.is_char_boundary(end) {
                end -= 1;
            }
            self.info.truncate(end);
            self.info.push('…');
        }
    }
}

/// Decodes the packets of one link, in order.
#[derive(Default)]
pub(crate) struct Dissector {
    tcp: super::stream::Streams,
    /// Stop at the transport layer.
    headers_only: bool,
}

/// The two big-endian bytes at `i`.
pub(crate) fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

pub(crate) fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "IP",
    }
}

impl Dissector {
    /// A dissector that decodes IP, TCP, UDP and ICMP, and nothing past.
    pub(crate) fn headers_only() -> Dissector {
        Dissector { headers_only: true, ..Dissector::default() }
    }

    pub(crate) fn decode(&mut self, p: &[u8], keys: &[KeyLine]) -> Decoded {
        let mut d = Decoded::default();
        match p.first().map(|b| b >> 4) {
            Some(4) => self.ipv4(p, &mut d, keys),
            Some(6) => self.ipv6(p, &mut d, keys),
            _ => {
                d.proto = "?".into();
                d.info = format!("Not an IP packet ({} bytes)", p.len());
                d.tag("malformed");
            }
        }
        if d.cut > 0 {
            let mut l = Layer::new("Not shown", 0, (0, 0));
            l.summary = format!("{} more layers and buffers: one packet's detail holds at most 1 MiB", d.cut);
            d.layers.push(l);
        }
        d.cap_info();
        d
    }

    fn ipv4(&mut self, p: &[u8], d: &mut Decoded, keys: &[KeyLine]) {
        if p.len() < 20 {
            return truncated(d, "IPv4", p.len());
        }
        let ihl = usize::from(p[0] & 0x0f) * 4;
        let total = usize::from(be16(p, 2));
        if ihl < 20 || p.len() < ihl {
            return truncated(d, "IPv4", p.len());
        }
        let end = total.clamp(ihl, p.len());
        let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
        let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
        let proto = p[9];
        let flags = p[6] >> 5;
        let offset = (usize::from(be16(p, 6)) & 0x1fff) * 8;
        let mut l = Layer::new("Internet Protocol Version 4", 0, (0, ihl));
        l.summary = format!("Src: {src}, Dst: {dst}");
        l.field("Version", "4", (0, 1));
        l.field("Header length", format!("{ihl} bytes"), (0, 1));
        l.field("Differentiated services", format!("0x{:02x}", p[1]), (1, 2));
        l.field("Total length", total.to_string(), (2, 4));
        l.field("Identification", format!("0x{:04x} ({})", be16(p, 4), be16(p, 4)), (4, 6));
        let mut fl = Vec::new();
        if flags & 2 != 0 {
            fl.push("Don't fragment");
        }
        if flags & 1 != 0 {
            fl.push("More fragments");
        }
        l.field("Flags", if fl.is_empty() { "none".to_owned() } else { fl.join(", ") }, (6, 7));
        l.field("Fragment offset", offset.to_string(), (6, 8));
        l.field("Time to live", p[8].to_string(), (8, 9));
        l.field("Protocol", format!("{} ({proto})", ip_proto_name(proto)), (9, 10));
        l.field("Header checksum", format!("0x{:04x}", be16(p, 10)), (10, 12));
        l.field("Source address", src.to_string(), (12, 16));
        l.field("Destination address", dst.to_string(), (16, 20));
        d.push(l);
        d.src = src.to_string();
        d.dst = dst.to_string();
        if offset != 0 || flags & 1 != 0 {
            d.proto = "IPv4".into();
            d.info = format!("Fragment of a {} packet (offset {offset}, {} bytes)", ip_proto_name(proto), end - ihl);
            d.tag("fragment");
            if offset != 0 {
                return;
            }
        }
        self.transport(p, ihl, end, proto, src.into(), dst.into(), d, keys);
    }

    fn ipv6(&mut self, p: &[u8], d: &mut Decoded, keys: &[KeyLine]) {
        if p.len() < 40 {
            return truncated(d, "IPv6", p.len());
        }
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
        let payload = usize::from(be16(p, 4));
        let end = (40 + payload).min(p.len());
        let mut l = Layer::new("Internet Protocol Version 6", 0, (0, 40));
        l.summary = format!("Src: {src}, Dst: {dst}");
        l.field("Version", "6", (0, 1));
        l.field("Traffic class", format!("0x{:02x}", (be16(p, 0) >> 4) as u8), (0, 2));
        l.field("Flow label", format!("0x{:05x}", be32(p, 0) & 0xfffff), (1, 4));
        l.field("Payload length", payload.to_string(), (4, 6));
        l.field("Next header", format!("{} ({})", ip_proto_name(p[6]), p[6]), (6, 7));
        l.field("Hop limit", p[7].to_string(), (7, 8));
        l.field("Source address", src.to_string(), (8, 24));
        l.field("Destination address", dst.to_string(), (24, 40));
        d.src = src.to_string();
        d.dst = dst.to_string();
        // Skip extension headers: hop-by-hop, routing, destination options,
        // and fragment.
        let (mut next, mut at) = (p[6], 40);
        while matches!(next, 0 | 43 | 44 | 60) && at + 8 <= end {
            if next == 44 {
                let offset = usize::from(be16(p, at + 2) & 0xfff8);
                l.field("Fragment header", format!("offset {offset}, more: {}", p[at + 3] & 1 == 1), (at, at + 8));
                if offset != 0 || p[at + 3] & 1 == 1 {
                    d.proto = "IPv6".into();
                    d.info = format!("Fragment (offset {offset})");
                    d.tag("fragment");
                    l.range.1 = at + 8;
                    d.push(l);
                    return;
                }
                next = p[at];
                at += 8;
            } else {
                let len = (usize::from(p[at + 1]) + 1) * 8;
                l.field("Extension header", format!("type {next}, {len} bytes"), (at, (at + len).min(end)));
                next = p[at];
                at += len;
            }
        }
        l.range.1 = at.min(end);
        d.push(l);
        if at > end {
            return;
        }
        self.transport(p, at, end, next, src.into(), dst.into(), d, keys);
    }

    #[allow(clippy::too_many_arguments)]
    fn transport(&mut self, p: &[u8], at: usize, end: usize, proto: u8, src: IpAddr, dst: IpAddr, d: &mut Decoded, keys: &[KeyLine]) {
        let body = &p[at..end];
        match proto {
            6 => self.tcp(p, at, end, src, dst, d, keys),
            17 => udp(p, at, end, d, !self.headers_only),
            1 => icmp(p, at, end, d, false),
            58 => icmp(p, at, end, d, true),
            other => {
                d.proto = ip_proto_name(other).into();
                d.info = format!("IP protocol {other}, {} bytes", body.len());
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp(&mut self, p: &[u8], at: usize, end: usize, src: IpAddr, dst: IpAddr, d: &mut Decoded, keys: &[KeyLine]) {
        let t = &p[at..end];
        if t.len() < 20 {
            return truncated(d, "TCP", t.len());
        }
        let off = usize::from(t[12] >> 4) * 4;
        if off < 20 || off > t.len() {
            return truncated(d, "TCP", t.len());
        }
        let (sport, dport) = (be16(t, 0), be16(t, 2));
        let (seq, ack, flags, win) = (be32(t, 4), be32(t, 8), t[13], be16(t, 14));
        let payload = (at + off, end);
        let flow = self.tcp.segment(src, sport, dst, dport, seq, ack, flags, end - at - off);
        let names = flag_names(flags);
        let mut l = Layer::new("Transmission Control Protocol", 0, (at, at + off));
        let r = |a: usize, b: usize| (at + a, at + b);
        l.summary = format!(
            "Src Port: {sport}, Dst Port: {dport}, Seq: {}, Ack: {}, Len: {}",
            flow.rel_seq,
            flow.rel_ack,
            payload.1 - payload.0
        );
        l.field("Source port", sport.to_string(), r(0, 2));
        l.field("Destination port", dport.to_string(), r(2, 4));
        l.field("Sequence number", format!("{} (raw {seq})", flow.rel_seq), r(4, 8));
        l.field("Acknowledgment number", format!("{} (raw {ack})", flow.rel_ack), r(8, 12));
        l.field("Header length", format!("{off} bytes"), r(12, 13));
        l.field("Flags", format!("0x{flags:03x} ({})", names.join(", ")), r(12, 14));
        l.field("Window", win.to_string(), r(14, 16));
        l.field("Checksum", format!("0x{:04x}", be16(t, 16)), r(16, 18));
        l.field("Urgent pointer", be16(t, 18).to_string(), r(18, 20));
        let opts = tcp_options(&t[20..off]);
        if !opts.is_empty() {
            l.field("Options", opts.join(", "), r(20, off));
        }
        l.note("Payload", format!("{} bytes", payload.1 - payload.0));
        d.push(l);
        d.src = sock(&d.src, sport);
        d.dst = sock(&d.dst, dport);
        d.proto = "TCP".into();
        let mut info = format!("{sport} → {dport} [{}] Seq={} ", names.join(", "), flow.rel_seq);
        if flags & 0x10 != 0 {
            let _ = write!(info, "Ack={} ", flow.rel_ack);
        }
        let _ = write!(info, "Win={win} Len={}", payload.1 - payload.0);
        if !opts.is_empty() && flags & 0x02 != 0 {
            let _ = write!(info, " {}", opts.join(" "));
        }
        if flow.retransmission {
            d.tag("retransmission");
            info.push_str(" [retransmission]");
        }
        if flags & 0x04 != 0 {
            d.tag("reset");
        }
        d.info = info;
        // Data on a SYN (TCP Fast Open) starts after the SYN's own number.
        if self.headers_only {
            return;
        }
        let data_seq = if flags & 0x02 != 0 { seq.wrapping_add(1) } else { seq };
        self.tcp.payload(flow.key, data_seq, flags & 0x01 != 0, p, payload, d, keys);
    }
}

fn sock(ip: &str, port: u16) -> String {
    if ip.contains(':') { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") }
}

fn truncated(d: &mut Decoded, what: &str, len: usize) {
    d.proto = what.into();
    d.info = format!("Truncated {what} header ({len} bytes)");
    d.tag("malformed");
}

pub(crate) fn flag_names(flags: u8) -> Vec<&'static str> {
    let names = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")];
    names.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, n)| *n).collect()
}

fn tcp_options(o: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < o.len() {
        match o[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = o.get(i + 1) else { break };
                let len = usize::from(len);
                if len < 2 || i + len > o.len() {
                    break;
                }
                let v = &o[i + 2..i + len];
                out.push(match (kind, v.len()) {
                    (2, 2) => format!("MSS={}", be16(v, 0)),
                    (3, 1) => format!("WS={}", 1u32 << v[0].min(14)),
                    (4, 0) => "SACK_PERM".to_owned(),
                    (5, _) => format!("SACK({} blocks)", v.len() / 8),
                    (8, 8) => format!("TSval={} TSecr={}", be32(v, 0), be32(v, 4)),
                    _ => format!("option {kind}"),
                });
                i += len;
            }
        }
    }
    out
}

fn udp(p: &[u8], at: usize, end: usize, d: &mut Decoded, apps: bool) {
    let u = &p[at..end];
    if u.len() < 8 {
        return truncated(d, "UDP", u.len());
    }
    let (sport, dport, len) = (be16(u, 0), be16(u, 2), be16(u, 4));
    // The datagram is as long as its header says, if the packet holds that
    // much: bytes after it are not part of it.
    let ulen = usize::from(len);
    let short = ulen < 8 || ulen > u.len();
    let end = if short { end } else { at + ulen };
    let u = &p[at..end];
    let mut l = Layer::new("User Datagram Protocol", 0, (at, at + 8));
    l.summary = format!("Src Port: {sport}, Dst Port: {dport}");
    l.field("Source port", sport.to_string(), (at, at + 2));
    l.field("Destination port", dport.to_string(), (at + 2, at + 4));
    l.field("Length", len.to_string(), (at + 4, at + 6));
    l.field("Checksum", format!("0x{:04x}", be16(u, 6)), (at + 6, at + 8));
    d.push(l);
    d.src = sock(&d.src, sport);
    d.dst = sock(&d.dst, dport);
    d.proto = "UDP".into();
    d.info = format!("{sport} → {dport} Len={}", u.len() - 8);
    if short {
        d.info.push_str(" [bad length]");
        d.tag("malformed");
        return;
    }
    let body = (at + 8, end);
    if !apps || body.0 >= body.1 {
        return;
    }
    if sport == 53 || dport == 53 {
        let place = super::app::Place { stream_start: 0, buf: 0, offset: Some(body.0), len: body.1 - body.0 };
        super::app::dns(&p[body.0..body.1], place, 0, d);
    } else if matches!((sport, dport), (67, 68) | (68, 67)) {
        super::app::dhcp(p, body, d);
    }
}

fn icmp(p: &[u8], at: usize, end: usize, d: &mut Decoded, v6: bool) {
    let c = &p[at..end];
    let name = if v6 { "ICMPv6" } else { "ICMP" };
    if c.len() < 4 {
        return truncated(d, name, c.len());
    }
    let (kind, code) = (c[0], c[1]);
    let what = icmp_name(kind, code, v6);
    let mut l = Layer::new(if v6 { "Internet Control Message Protocol v6" } else { "Internet Control Message Protocol" }, 0, (at, end));
    l.summary = what.clone();
    l.field("Type", format!("{kind} ({what})"), (at, at + 1));
    l.field("Code", code.to_string(), (at + 1, at + 2));
    l.field("Checksum", format!("0x{:04x}", be16(c, 2)), (at + 2, at + 4));
    let mut info = what;
    let echo = if v6 { matches!(kind, 128 | 129) } else { matches!(kind, 0 | 8) };
    if echo && c.len() >= 8 {
        let (id, seq) = (be16(c, 4), be16(c, 6));
        l.field("Identifier", format!("0x{id:04x}"), (at + 4, at + 6));
        l.field("Sequence number", seq.to_string(), (at + 6, at + 8));
        l.note("Data", format!("{} bytes", c.len() - 8));
        let _ = write!(info, " id=0x{id:04x}, seq={seq}");
    }
    let quotes = if v6 { matches!(kind, 1..=4) } else { matches!(kind, 3 | 4 | 5 | 11 | 12) };
    if quotes && c.len() >= 8 + 20 {
        let inner = &c[8..];
        let summary = quoted_summary(inner);
        l.field("Original packet", summary.clone(), (at + 8, end));
        let _ = write!(info, " ({summary})");
    }
    d.push(l);
    d.proto = name.into();
    d.info = info;
}

/// "10.0.0.2:5000 → 203.0.113.9:80 TCP" for a packet quoted in an ICMP
/// error.
fn quoted_summary(q: &[u8]) -> String {
    let (src, dst, proto, at) = match q[0] >> 4 {
        4 if q.len() >= 20 => {
            let ihl = usize::from(q[0] & 0xf) * 4;
            (IpAddr::from([q[12], q[13], q[14], q[15]]), IpAddr::from([q[16], q[17], q[18], q[19]]), q[9], ihl)
        }
        6 if q.len() >= 40 => (
            IpAddr::from(<[u8; 16]>::try_from(&q[8..24]).unwrap()),
            IpAddr::from(<[u8; 16]>::try_from(&q[24..40]).unwrap()),
            q[6],
            40,
        ),
        _ => return "a packet".into(),
    };
    if matches!(proto, 6 | 17) && q.len() >= at + 4 {
        format!("{} → {} {}", sock(&src.to_string(), be16(q, at)), sock(&dst.to_string(), be16(q, at + 2)), ip_proto_name(proto))
    } else {
        format!("{src} → {dst} {}", ip_proto_name(proto))
    }
}

fn icmp_name(kind: u8, code: u8, v6: bool) -> String {
    let s = if v6 {
        match (kind, code) {
            (1, 0) => "Destination unreachable (no route)",
            (1, 1) => "Destination unreachable (administratively prohibited)",
            (1, 3) => "Destination unreachable (address unreachable)",
            (1, 4) => "Destination unreachable (port unreachable)",
            (1, _) => "Destination unreachable",
            (2, _) => "Packet too big",
            (3, _) => "Time exceeded",
            (4, _) => "Parameter problem",
            (128, _) => "Echo (ping) request",
            (129, _) => "Echo (ping) reply",
            (133, _) => "Router solicitation",
            (134, _) => "Router advertisement",
            (135, _) => "Neighbor solicitation",
            (136, _) => "Neighbor advertisement",
            (143, _) => "Multicast listener report v2",
            _ => return format!("Type {kind}"),
        }
    } else {
        match (kind, code) {
            (0, _) => "Echo (ping) reply",
            (3, 0) => "Destination unreachable (network unreachable)",
            (3, 1) => "Destination unreachable (host unreachable)",
            (3, 3) => "Destination unreachable (port unreachable)",
            (3, 4) => "Destination unreachable (fragmentation needed)",
            (3, 13) => "Destination unreachable (administratively prohibited)",
            (3, _) => "Destination unreachable",
            (5, _) => "Redirect",
            (8, _) => "Echo (ping) request",
            (11, 0) => "Time to live exceeded in transit",
            (11, _) => "Time exceeded",
            _ => return format!("Type {kind}"),
        }
    };
    s.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(body);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    #[test]
    fn a_ping_is_decoded() {
        let mut echo = vec![8, 0, 0, 0, 0x12, 0x34, 0, 7];
        echo.extend_from_slice(&[0; 16]);
        let d = Dissector::default().decode(&ipv4(1, [10, 0, 0, 2], [10, 0, 0, 1], &echo), &[]);
        assert_eq!((d.src.as_str(), d.dst.as_str(), d.proto.as_str()), ("10.0.0.2", "10.0.0.1", "ICMP"));
        assert_eq!(d.info, "Echo (ping) request id=0x1234, seq=7");
        assert_eq!(d.layers.len(), 2);
        assert_eq!(d.layers[1].fields[3].range, Some((24, 26)));
    }

    #[test]
    fn a_syn_shows_its_flags_and_options() {
        let mut syn = vec![0xc3, 0x50, 0, 80, 0, 0, 0, 100, 0, 0, 0, 0, 0x60, 0x02, 0xfa, 0xf0, 0, 0, 0, 0];
        syn.extend_from_slice(&[2, 4, 0x05, 0xb4]);
        let d = Dissector::default().decode(&ipv4(6, [10, 0, 0, 2], [203, 0, 113, 10], &syn), &[]);
        assert_eq!(d.src, "10.0.0.2:50000");
        assert_eq!(d.dst, "203.0.113.10:80");
        assert_eq!(d.info, "50000 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460");
    }

    fn tcp(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t.extend_from_slice(payload);
        ipv4(6, [10, 0, 0, 2], [10, 0, 0, 1], &t)
    }

    #[test]
    fn a_dns_query_is_decoded() {
        // A query for example.test, type A.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x04test\x00\x00\x01\x00\x01");
        let mut udp = vec![0xc0, 0x00, 0, 53, 0, (8 + q.len()) as u8, 0, 0];
        udp.extend_from_slice(&q);
        let d = Dissector::default().decode(&ipv4(17, [10, 0, 0, 2], [10, 0, 0, 1], &udp), &[]);
        assert_eq!(d.proto, "DNS");
        assert_eq!(d.info, "Standard query 0x1234 A example.test");
        // The message is in the packet, so its fields point there.
        let dns = d.layers.last().unwrap();
        assert_eq!((dns.buf, dns.fields[0].range), (0, Some((28, 30))));
    }

    /// A request cut over two segments, and the second arriving first, is
    /// shown whole on the packet that completes it.
    #[test]
    fn http_is_reassembled_across_segments() {
        let mut dis = Dissector::default();
        let request = b"GET /count HTTP/1.1\r\nHost: example.test\r\n\r\n";
        dis.decode(&tcp(40000, 80, 100, 0x02, b""), &[]);
        let second = dis.decode(&tcp(40000, 80, 111, 0x18, &request[10..]), &[]);
        assert_eq!(second.proto, "TCP");
        let first = dis.decode(&tcp(40000, 80, 101, 0x18, &request[..10]), &[]);
        assert_eq!((first.proto.as_str(), first.info.as_str()), ("HTTP", "GET /count HTTP/1.1"));
        let http = first.layers.last().unwrap();
        assert_eq!(http.buf, 1, "the request spans packets, so it has a buffer of its own");
        assert_eq!(first.extra[0].1, request);
        assert!(http.fields.iter().any(|f| f.name == "Host" && f.value == "example.test"));
        // The same bytes again are a retransmission, and decode to nothing new.
        let again = dis.decode(&tcp(40000, 80, 101, 0x18, &request[..10]), &[]);
        assert!(again.tags.contains(&"retransmission"));
        assert_eq!(again.proto, "TCP");
    }

    fn tcp_back(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = tcp(80, 40000, seq, flags, payload);
        // Swap the addresses: from 10.0.0.1 to 10.0.0.2.
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p
    }

    /// A response to HEAD has no body, whatever its content-length says,
    /// so the next response is still found.
    #[test]
    fn a_head_response_has_no_body() {
        let mut dis = Dissector::default();
        dis.decode(&tcp(40000, 80, 100, 0x02, b""), &[]);
        dis.decode(&tcp_back(500, 0x12, b""), &[]);
        dis.decode(&tcp(40000, 80, 101, 0x18, b"HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n"), &[]);
        let first = dis.decode(&tcp_back(501, 0x18, b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n"), &[]);
        assert_eq!(first.info, "HTTP/1.1 200 OK");
        let second = dis.decode(&tcp_back(541, 0x18, b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"), &[]);
        assert_eq!(second.info, "HTTP/1.1 404 Not Found");
    }

    /// Segments held across the point where sequence numbers wrap are
    /// delivered in order, and an early FIN does not eat a byte.
    #[test]
    fn reassembly_across_the_wrap_and_an_early_fin() {
        let mut dis = Dissector::default();
        let request = b"GET /wrap HTTP/1.1\r\nHost: x\r\n\r\n";
        let isn = u32::MAX - 10;
        dis.decode(&tcp(40000, 80, isn, 0x02, b""), &[]);
        let (a, b) = request.split_at(10);
        // The second half, past the wrap, comes first, with a FIN.
        dis.decode(&tcp(40000, 80, isn.wrapping_add(11), 0x19, b), &[]);
        let done = dis.decode(&tcp(40000, 80, isn.wrapping_add(1), 0x18, a), &[]);
        assert_eq!(done.info, "GET /wrap HTTP/1.1");
    }

    /// When the endpoint that sorts second opens a new connection on the
    /// same ports, the old connection's decoders are dropped: a request
    /// that waited for its body does not eat the new one.
    #[test]
    fn a_new_connection_on_the_same_ports_starts_over() {
        let mut dis = Dissector::default();
        dis.decode(&tcp(40000, 80, 100, 0x02, b""), &[]);
        dis.decode(&tcp(40000, 80, 101, 0x18, b"POST / HTTP/1.1\r\ncontent-length: 100\r\n\r\n"), &[]);
        dis.decode(&tcp(40000, 80, 5000, 0x02, b""), &[]);
        let d = dis.decode(&tcp(40000, 80, 5001, 0x18, b"GET /new HTTP/1.1\r\n\r\n"), &[]);
        assert_eq!(d.info, "GET /new HTTP/1.1");
        // A SYN-ACK that answers the SYN keeps what the SYN carried, whether
        // it acknowledges the SYN's data (TCP Fast Open) or only the SYN.
        for ack in [9001u32, 9010] {
            let mut dis = Dissector::default();
            dis.decode(&tcp(40000, 80, 9000, 0x02, b"GET /fast"), &[]);
            let mut syn_ack = tcp_back(700, 0x12, b"");
            syn_ack[28..32].copy_from_slice(&ack.to_be_bytes());
            dis.decode(&syn_ack, &[]);
            let rest = tcp(40000, 80, 9010, 0x18, b" HTTP/1.1\r\n\r\n");
            assert_eq!(dis.decode(&rest, &[]).info, "GET /fast HTTP/1.1", "ack {ack}");
        }
    }

    /// One packet that fills a gap can release many held segments at once.
    /// What it decodes to is bounded, and the HPACK table still follows
    /// every header block.
    #[test]
    fn one_packet_decodes_to_a_bounded_detail() {
        let mut dis = Dissector::default();
        dis.decode(&tcp(40000, 80, 100, 0x02, b""), &[]);
        // The preface, and a block that adds x: 4,000 bytes to the table.
        let mut block = vec![0x40, 0x01, b'x', 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'v', 4000));
        let mut first = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        first.extend(h2_frame(1, 0x4, 1, &block));
        dis.decode(&tcp(40000, 80, 101, 0x18, &first), &[]);
        let base = 101 + first.len() as u32;
        // Each segment holds four blocks that name that entry 16 times:
        // 256 KB of headers a segment, from 100 bytes.
        let mut segment = Vec::new();
        for stream in [3, 5, 7, 9] {
            segment.extend(h2_frame(1, 0x4, stream, &[0xbe; 16]));
        }
        for k in (1..256).rev() {
            dis.decode(&tcp(40000, 80, base + k * 100, 0x18, &segment), &[]);
        }
        let d = dis.decode(&tcp(40000, 80, base, 0x18, &segment), &[]);
        let kept: usize = d.layers.iter().flat_map(|l| &l.fields).map(|f| f.value.len()).sum();
        assert!(kept <= MAX_DETAIL, "{kept} bytes of fields");
        assert!(d.layers_json().len() < 2 * MAX_DETAIL);
        assert!(d.info.len() < 2048);
        assert_eq!(d.layers.last().unwrap().name, "Not shown");
        // The table is still known.
        let d = dis.decode(&tcp(40000, 80, base + 256 * 100, 0x18, &h2_frame(1, 0x4, 11, &[0xbe])), &[]);
        let x = d.layers.last().unwrap().fields.iter().find(|f| f.name == "x").unwrap();
        assert_eq!(x.value.len(), 4000);
    }

    fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Bytes after a UDP datagram's length are not part of it.
    #[test]
    fn udp_bytes_past_the_length_are_ignored() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x04test\x00\x00\x01\x00\x01");
        let mut udp = vec![0xc0, 0x00, 0, 53, 0, 8, 0, 0];
        udp.extend_from_slice(&q);
        let d = Dissector::default().decode(&ipv4(17, [10, 0, 0, 2], [10, 0, 0, 1], &udp), &[]);
        assert_eq!(d.proto, "UDP");
        assert_eq!(d.info, "49152 → 53 Len=0");
    }

    /// Streams that look like TLS, HTTP/2, HTTP/1.1 and DNS, then turn to
    /// noise, cut at random, out of order, over many connections: the
    /// decoder never panics, whatever the agent sends.
    #[test]
    fn hostile_streams_are_not_a_panic() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut rand = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let starts: [&[u8]; 6] = [
            &[0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x03, 0x03],
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            &[0x00, 0x00, 0x05, 0x01, 0x2d, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x05, 0xff, 0xff],
            b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
            b"HTTP/1.1 200 OK\r\ncontent-length: 99999999999\r\n\r\n",
            &[0x17, 0x03, 0x03, 0x40, 0x00],
        ];
        let mut dis = Dissector::default();
        for round in 0..4000 {
            let port = 1000 + (rand() % 700) as u16;
            let dport = [443, 80, 53, 8080][(rand() % 4) as usize];
            let mut payload = starts[(rand() % 6) as usize].to_vec();
            for _ in 0..(rand() % 200) {
                payload.push(rand() as u8);
            }
            let flags = [0x02, 0x10, 0x18, 0x11, 0x04][(rand() % 5) as usize];
            let seq = if round % 3 == 0 { rand() as u32 } else { 1000 + (rand() % 3000) as u32 };
            let packet = tcp(port, dport, seq, flags, &payload);
            let mut packet = packet;
            if round % 7 == 0 {
                let cut = (rand() as usize) % packet.len();
                packet.truncate(cut.max(1));
            }
            let _ = dis.decode(&packet, &[]);
        }
    }

    /// The detail JSON, written the plain way: one object at a time, as
    /// strings joined together.
    fn detail_by_objects(d: &Decoded, packet: &[u8]) -> (String, String) {
        use super::super::json::Object;
        let layers = json::array(d.layers.iter().map(|l| {
            let fields = json::array(l.fields.iter().map(|f| {
                let o = Object::new().str("name", &f.name).str("value", &f.value);
                match f.range {
                    Some((a, b)) => o.raw("range", &format!("[{a},{b}]")),
                    None => o,
                }
                .done()
            }));
            Object::new()
                .str("name", &l.name)
                .str("summary", &l.summary)
                .num("buf", l.buf)
                .raw("range", &format!("[{},{}]", l.range.0, l.range.1))
                .raw("fields", &fields)
                .done()
        }));
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let first = Object::new().str("name", "Packet").str("hex", &hex(packet)).done();
        let rest = d.extra.iter().map(|(name, b)| Object::new().str("name", name).str("hex", &hex(b)).done());
        (layers, json::array(std::iter::once(first).chain(rest)))
    }

    /// The direct writers give exactly what the plain way gives, for
    /// HTTP, DNS, odd names and values, and streams of noise.
    #[test]
    fn detail_writers_match_the_plain_json() {
        let mut packets = vec![
            tcp(40000, 80, 100, 0x02, b""),
            tcp(40000, 80, 101, 0x18, b"GET /a\"b\\c\x01</script> HTTP/1.1\r\nhost: x\r\n\r\n"),
            tcp_back(700, 0x18, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"),
            tcp(40001, 9000, 5, 0x18, &[0xff; 1460]),
        ];
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x04test\x00\x00\x01\x00\x01");
        let mut udp = vec![0xc0, 0x00, 0, 53, 0, (8 + q.len()) as u8, 0, 0];
        udp.extend_from_slice(&q);
        packets.push(ipv4(17, [10, 0, 0, 2], [10, 0, 0, 1], &udp));
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..300 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let payload: Vec<u8> = (0..(state % 300)).map(|i| (state >> (i % 56)) as u8).collect();
            packets.push(tcp(1000 + (state % 50) as u16, [443, 80, 53][(state % 3) as usize], state as u32, 0x18, &payload));
        }
        let mut dis = Dissector::default();
        for p in &packets {
            let d = dis.decode(p, &[]);
            let (layers, buffers) = detail_by_objects(&d, p);
            assert_eq!(d.layers_json(), layers);
            let mut out = String::new();
            d.write_buffers(&mut out, p);
            assert_eq!(out, buffers);
        }
    }

    #[test]
    fn garbage_is_not_a_panic() {
        let mut dis = Dissector::default();
        for len in 0..80 {
            for fill in [0u8, 0x45, 0x60, 0xff] {
                let mut p = vec![fill; len];
                if let Some(b) = p.first_mut() {
                    *b = if len % 2 == 0 { 0x45 } else { 0x60 };
                }
                let _ = dis.decode(&p, &[]);
            }
        }
    }
}
