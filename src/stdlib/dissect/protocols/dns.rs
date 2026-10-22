use super::{Display, MAX_BUFFER};
use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::dissect::Transport;
use fictionet::stdlib::dissect::{Decoded, Layer, Match, Placement, Present, Registry};
use std::convert::Infallible;
use std::fmt::Write;

/// DNS capture messages, either one UDP datagram or length-prefixed TCP.
/// Oversized TCP messages emit their length header, then skip the payload.
pub struct Dns {
    tcp: bool,
    taken: bool,
    skip: usize,
}
impl Dns {
    /// Registers `dns` when either port is 53, on UDP or TCP.
    /// TCP messages use a two-byte length prefix.
    /// Uses 65,538 bytes of input read-ahead.
    pub fn register(registry: &mut Registry) {
        registry.register_with_buffer(
            "dns",
            |s| {
                if s.ports.0 == 53 || s.ports.1 == 53 {
                    Match::Yes
                } else {
                    Match::No
                }
            },
            65_538,
            |s| {
                [
                    Self::new(s.transport == Transport::Tcp),
                    Self::new(s.transport == Transport::Tcp),
                ]
            },
        );
    }
    /// `tcp` enables the two-byte length prefix. Otherwise EOF ends a datagram.
    pub fn new(tcp: bool) -> Self {
        Self {
            tcp,
            taken: false,
            skip: 0,
        }
    }
}
impl Decode for Dns {
    type Item = Display;
    type Error = Infallible;
    const NAME: &'static str = "DNS";
    fn capacity(&self) -> usize {
        if self.tcp { MAX_BUFFER } else { 65_536 }
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Display>, Infallible> {
        if self.skip != 0 {
            let n = self.skip.min(input.len());
            self.skip -= n;
            return Ok(if n == 0 { Step::Need } else { Step::Skip(n) });
        }
        let (offset, len): (usize, usize) = if self.tcp {
            let Some(header) = input.get(..2) else {
                return Ok(Step::Need);
            };
            (2, usize::from(u16::from_be_bytes([header[0], header[1]])))
        } else {
            if self.taken {
                return Ok(Step::End);
            }
            if input.len() >= self.capacity() {
                self.taken = true;
                return Ok(Step::End);
            }
            if !eof {
                return Ok(Step::Need);
            }
            if input.is_empty() {
                return Ok(Step::End);
            }
            (0, input.len())
        };
        if self.tcp && len > MAX_BUFFER - 2 && input.len() < len.saturating_add(2) {
            self.skip = len;
            let mut d = Decoded::default();
            let mut layer = Layer::new("Domain Name System", 0, (0, 2));
            layer.field("Length", len.to_string(), (0, 2));
            layer.summary = format!("a {len}-byte message, too long to decode here");
            d.push(layer);
            d.proto = "DNS".into();
            d.info = format!("DNS message of {len} bytes, not decoded");
            return Ok(Step::Item(Display::from_packet(d, "DNS message length"), 2));
        }
        let Some(end) = offset.checked_add(len) else {
            return Ok(Step::End);
        };
        let Some(bytes) = input.get(offset..end) else {
            return Ok(Step::Need);
        };
        self.taken = true;
        let mut item = dns_display(bytes);
        item.offset = offset;
        Ok(Step::Item(item, end))
    }
}
impl Present for Dns {
    display_presenter!();
    fn pending(&self) -> bool {
        self.skip != 0
    }
    fn reset(&mut self) {
        self.taken = false;
        self.skip = 0;
    }
}

// ---------------------------------------------------------------------------
// DNS and DHCP

fn dns_display(msg: &[u8]) -> Display {
    let mut packet = Decoded::default();
    let d = &mut packet;
    use fictionet::stdlib::protocols::dns::op::{Message, MessageType};
    let (buf, base) = (0, 0);
    let mut l = Layer::new("Domain Name System", buf, (base, base + msg.len()));
    let Ok(m) = Message::from_vec(msg) else {
        l.summary = "malformed".into();
        d.push(l);
        d.proto = "DNS".into();
        d.info = "Malformed DNS message".into();
        d.tag("malformed");
        return Display::from_packet(packet, "DNS message");
    };
    let md = &m.metadata;
    let response = md.message_type == MessageType::Response;
    l.field(
        "Transaction ID",
        format!("0x{:04x}", md.id),
        (base, base + 2),
    );
    let mut flags = vec![if response { "response" } else { "query" }.to_owned()];
    if md.recursion_desired {
        flags.push("recursion desired".into());
    }
    if md.recursion_available {
        flags.push("recursion available".into());
    }
    if md.authoritative {
        flags.push("authoritative".into());
    }
    if md.truncation {
        flags.push("truncated".into());
    }
    l.field("Flags", flags.join(", "), (base + 2, base + 4));
    if response {
        l.field(
            "Reply code",
            format!("{}", md.response_code),
            (base + 3, base + 4),
        );
    }
    let mut q_text = Vec::new();
    for q in &m.queries {
        let name = q.name().to_string();
        let name = name.trim_end_matches('.');
        l.note(
            "Query",
            format!("{name}: type {}, class {}", q.query_type(), q.query_class()),
        );
        q_text.push(format!("{} {name}", q.query_type()));
    }
    let mut a_text = Vec::new();
    for (section, records) in [
        ("Answer", &m.answers),
        ("Authority", &m.authorities),
        ("Additional", &m.additionals),
    ] {
        for r in records.iter() {
            let name = r.name.to_string();
            let data = r.data.to_string();
            l.note(
                section,
                format!(
                    "{}: type {}, TTL {}, {data}",
                    name.trim_end_matches('.'),
                    r.record_type(),
                    r.ttl
                ),
            );
            if section == "Answer" {
                a_text.push(format!("{} {data}", r.record_type()));
            }
        }
    }
    let mut text = format!(
        "Standard query{} 0x{:04x} {}",
        if response { " response" } else { "" },
        md.id,
        q_text.join(" ")
    );
    if response {
        let code = md.response_code.to_string();
        if code != "No Error" {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write for String never returns Err"
            )]
            let _ = write!(text, " {code}");
            d.tag("dns-error");
        }
        if !a_text.is_empty() {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write for String never returns Err"
            )]
            let _ = write!(text, " {}", a_text.join(" "));
        }
    }
    l.summary = text.clone();
    d.push(l);
    d.proto = "DNS".into();
    d.info = text;
    d.cap_info();
    Display::from_packet(packet, "DNS message")
}
