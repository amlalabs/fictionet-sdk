//! TCP, UDP and ICMP as the dissector sees them: each header is read whole
//! from the captured bytes first, and only then shown as a layer and a
//! list line.

use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};

use fictionet::stdlib::codec::{be16, be32};
use fictionet::stdlib::network::ip::Header;

use super::{Layer, ip_proto_name};

/// TCP's SYN flag.
const SYN: u8 = 0x02;
/// TCP's RST flag.
pub(super) const RST: u8 = 0x04;
/// TCP's ACK flag.
const ACK: u8 = 0x10;

/// A captured TCP segment's header.
pub(super) struct TcpHeader<'a> {
    /// The source port, then the destination port.
    pub ports: (u16, u16),
    /// The raw sequence number.
    seq: u32,
    /// The raw acknowledgment number.
    ack: u32,
    /// The header's length in bytes, options included.
    pub len: usize,
    pub flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
    options: &'a [u8],
}

impl<'a> TcpHeader<'a> {
    /// Reads the header at the start of `t`: `None` when `t` is shorter
    /// than the header, or the header's length field is below 20 bytes.
    pub fn read(t: &'a [u8]) -> Option<TcpHeader<'a>> {
        let len = usize::from(*t.get(12)? >> 4) * 4;
        if len < 20 || len > t.len() {
            return None;
        }
        Some(TcpHeader {
            ports: (be16(t, 0)?, be16(t, 2)?),
            seq: be32(t, 4)?,
            ack: be32(t, 8)?,
            len,
            flags: t[13],
            window: be16(t, 14)?,
            checksum: be16(t, 16)?,
            urgent: be16(t, 18)?,
            options: &t[20..len],
        })
    }

    /// Its options, as the layer and the list line name them.
    pub fn options(&self) -> Vec<String> {
        tcp_options(self.options)
    }

    /// The segment's layer, for a header at `at` in the packet. `relative`
    /// holds its sequence and acknowledgment numbers counted from the
    /// first each side sent; `payload` is how many bytes follow the header.
    pub fn layer(
        &self,
        at: usize,
        (rel_seq, rel_ack): (u32, u32),
        payload: usize,
        options: &[String],
    ) -> Layer {
        let (sport, dport) = self.ports;
        let r = |a: usize, b: usize| (at + a, at + b);
        let mut l = Layer::new("Transmission Control Protocol", 0, (at, at + self.len));
        l.summary = format!(
            "Src Port: {sport}, Dst Port: {dport}, Seq: {rel_seq}, Ack: {rel_ack}, Len: {payload}"
        );
        l.field("Source port", sport.to_string(), r(0, 2));
        l.field("Destination port", dport.to_string(), r(2, 4));
        l.field(
            "Sequence number",
            format!("{rel_seq} (raw {})", self.seq),
            r(4, 8),
        );
        l.field(
            "Acknowledgment number",
            format!("{rel_ack} (raw {})", self.ack),
            r(8, 12),
        );
        l.field("Header length", format!("{} bytes", self.len), r(12, 13));
        l.field(
            "Flags",
            format!(
                "0x{:03x} ({})",
                self.flags,
                flag_names(self.flags).join(", ")
            ),
            r(12, 14),
        );
        l.field("Window", self.window.to_string(), r(14, 16));
        l.field("Checksum", format!("0x{:04x}", self.checksum), r(16, 18));
        l.field("Urgent pointer", self.urgent.to_string(), r(18, 20));
        if !options.is_empty() {
            l.field("Options", options.join(", "), r(20, self.len));
        }
        l.note("Payload", format!("{payload} bytes"));
        l
    }

    /// The segment's line in the packet list, as for [`layer`](Self::layer).
    pub fn info(
        &self,
        (rel_seq, rel_ack): (u32, u32),
        payload: usize,
        options: &[String],
    ) -> String {
        let (sport, dport) = self.ports;
        let mut info = format!(
            "{sport} → {dport} [{}] Seq={rel_seq} ",
            flag_names(self.flags).join(", ")
        );
        if self.flags & ACK != 0 {
            push(&mut info, format_args!("Ack={rel_ack} "));
        }
        push(&mut info, format_args!("Win={} Len={payload}", self.window));
        if !options.is_empty() && self.flags & SYN != 0 {
            push(&mut info, format_args!(" {}", options.join(" ")));
        }
        info
    }
}

/// A captured UDP datagram's header.
pub(super) struct UdpHeader {
    /// The source port, then the destination port.
    pub ports: (u16, u16),
    /// The datagram's length, as its header says.
    length: u16,
    checksum: u16,
}

impl UdpHeader {
    /// Reads the header at the start of `u`: `None` when `u` is shorter
    /// than eight bytes.
    pub fn read(u: &[u8]) -> Option<UdpHeader> {
        Some(UdpHeader {
            ports: (be16(u, 0)?, be16(u, 2)?),
            length: be16(u, 4)?,
            checksum: be16(u, 6)?,
        })
    }

    /// The datagram's layer, for a header at `at` in the packet.
    pub fn layer(&self, at: usize) -> Layer {
        let (sport, dport) = self.ports;
        let mut l = Layer::new("User Datagram Protocol", 0, (at, at + 8));
        l.summary = format!("Src Port: {sport}, Dst Port: {dport}");
        l.field("Source port", sport.to_string(), (at, at + 2));
        l.field("Destination port", dport.to_string(), (at + 2, at + 4));
        l.field("Length", self.length.to_string(), (at + 4, at + 6));
        l.field(
            "Checksum",
            format!("0x{:04x}", self.checksum),
            (at + 6, at + 8),
        );
        l
    }

    /// The datagram's line in the packet list, with `payload` bytes after
    /// its header.
    pub fn info(&self, payload: usize) -> String {
        let (sport, dport) = self.ports;
        format!("{sport} → {dport} Len={payload}")
    }
}

/// A captured ICMP or ICMPv6 message's header, and what follows it that
/// the dissector shows.
pub(super) struct IcmpMessage<'a> {
    v6: bool,
    kind: u8,
    code: u8,
    checksum: u16,
    /// An echo's identifier and sequence number, and how many data bytes
    /// follow them.
    echo: Option<(u16, u16, usize)>,
    /// The start of the packet an error quotes, when it holds at least an
    /// IP header.
    quoted: Option<&'a [u8]>,
}

impl<'a> IcmpMessage<'a> {
    /// Reads the message `c`: `None` when it is shorter than its four
    /// bytes of type, code and checksum.
    pub fn read(c: &'a [u8], v6: bool) -> Option<IcmpMessage<'a>> {
        let (kind, code) = (*c.first()?, *c.get(1)?);
        let echo = if v6 {
            matches!(kind, 128 | 129)
        } else {
            matches!(kind, 0 | 8)
        };
        let quotes = if v6 {
            matches!(kind, 1..=4)
        } else {
            matches!(kind, 3 | 4 | 5 | 11 | 12)
        };
        Some(IcmpMessage {
            v6,
            kind,
            code,
            checksum: be16(c, 2)?,
            echo: match (echo, be16(c, 4), be16(c, 6)) {
                (true, Some(id), Some(seq)) => Some((id, seq, c.len() - 8)),
                _ => None,
            },
            quoted: c.get(8..).filter(|inner| quotes && inner.len() >= 20),
        })
    }

    /// The protocol's name in the packet list.
    pub fn protocol(&self) -> &'static str {
        if self.v6 { "ICMPv6" } else { "ICMP" }
    }

    /// The message's layer, for a message at `at..end` in the packet, and
    /// its line in the packet list.
    pub fn present(&self, at: usize, end: usize) -> (Layer, String) {
        let what = icmp_name(self.kind, self.code, self.v6);
        let mut l = Layer::new(
            if self.v6 {
                "Internet Control Message Protocol v6"
            } else {
                "Internet Control Message Protocol"
            },
            0,
            (at, end),
        );
        l.summary = what.clone();
        l.field("Type", format!("{} ({what})", self.kind), (at, at + 1));
        l.field("Code", self.code.to_string(), (at + 1, at + 2));
        l.field(
            "Checksum",
            format!("0x{:04x}", self.checksum),
            (at + 2, at + 4),
        );
        let mut info = what;
        if let Some((id, seq, data)) = self.echo {
            l.field("Identifier", format!("0x{id:04x}"), (at + 4, at + 6));
            l.field("Sequence number", seq.to_string(), (at + 6, at + 8));
            l.note("Data", format!("{data} bytes"));
            push(&mut info, format_args!(" id=0x{id:04x}, seq={seq}"));
        }
        if let Some(inner) = self.quoted {
            let summary = quoted_summary(inner);
            l.field("Original packet", summary.clone(), (at + 8, end));
            push(&mut info, format_args!(" ({summary})"));
        }
        (l, info)
    }
}

/// Appends `args` to `out`.
fn push(out: &mut String, args: std::fmt::Arguments<'_>) {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "fmt::Write for String never returns Err"
    )]
    let _ = out.write_fmt(args);
}

fn flag_names(flags: u8) -> Vec<&'static str> {
    let names = [
        (SYN, "SYN"),
        (ACK, "ACK"),
        (0x08, "PSH"),
        (0x01, "FIN"),
        (RST, "RST"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ];
    names
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

fn tcp_options(bytes: &[u8]) -> Vec<String> {
    use fictionet::stdlib::network::tcp::{OptionRead, TcpOption, read_options};
    read_options(bytes)
        .filter_map(|read| {
            Some(match read {
                OptionRead::End { .. } => return None,
                OptionRead::Malformed { bytes } => format!("malformed option {}", bytes[0]),
                OptionRead::Option { value, .. } => match value {
                    TcpOption::NoOperation => return None,
                    TcpOption::MaxSegmentSize(mss) => format!("MSS={mss}"),
                    TcpOption::WindowScale(shift) => format!("WS={}", 1u32 << shift.min(14)),
                    TcpOption::SackPermitted => "SACK_PERM".to_owned(),
                    TcpOption::Sack(blocks) => format!("SACK({} blocks)", blocks.len()),
                    TcpOption::Timestamps { tsval, tsecr } => {
                        format!("TSval={tsval} TSecr={tsecr}")
                    }
                    TcpOption::Unknown { kind, .. } => format!("option {kind}"),
                },
            })
        })
        .collect()
}

/// "10.0.0.2:5000 → 203.0.113.9:80 TCP" for a packet quoted in an ICMP
/// error.
fn quoted_summary(q: &[u8]) -> String {
    let Some(header) = Header::parse_truncated(q) else {
        return "a packet".into();
    };
    let (src, dst, proto, at) = (
        header.src,
        header.dst,
        header.protocol,
        header.payload.start,
    );
    let ports = (matches!(proto, 6 | 17)
        && header.fragment.is_none_or(|fragment| fragment.offset == 0)
        && header.payload.len() >= 4)
        .then(|| Some((be16(q, at)?, be16(q, at + 2)?)))
        .flatten();
    match ports {
        Some((sport, dport)) => format!(
            "{} → {} {}",
            SocketAddr::new(src, sport),
            SocketAddr::new(dst, dport),
            ip_proto_name(proto)
        ),
        None => format!("{src} → {dst} {}", ip_proto_name(proto)),
    }
}

/// `addr` with `port`, as the packet list shows an endpoint.
pub(super) fn endpoint(addr: IpAddr, port: u16) -> String {
    SocketAddr::new(addr, port).to_string()
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
