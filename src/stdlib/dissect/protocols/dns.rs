use super::{Display, MAX_BUFFER};
use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::dissect::{Decoded, Layer, Match, Placement, Present, Registry};
use fictionet::stdlib::network::Transport;
use std::convert::Infallible;
use std::fmt::Write;

/// DNS capture messages, either one UDP datagram or length-prefixed TCP.
/// Oversized TCP messages emit their length header, then skip the payload.
/// Past missing bytes, a TCP direction is not read again: only the length
/// before each message marks where it starts.
pub struct Dns {
    tcp: bool,
    taken: bool,
    skip: usize,
    /// Bytes went missing in this TCP direction.
    lost: bool,
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
            lost: false,
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
        Ok(match self.next(input, eof) {
            Next::Step(Step::Item(never, _)) => match never {},
            Next::Step(Step::Need) => Step::Need,
            Next::Step(Step::Skip(n)) => Step::Skip(n),
            Next::Step(Step::End) => Step::End,
            Next::Long(len) => {
                let mut d = Decoded::default();
                let mut layer = Layer::new("Domain Name System", 0, (0, 2));
                layer.field("Length", len.to_string(), (0, 2));
                layer.summary = format!("a {len}-byte message, too long to decode here");
                d.push(layer);
                d.proto = "DNS".into();
                d.info = format!("DNS message of {len} bytes, not decoded");
                Step::Item(Display::from_packet(d, "DNS message length"), 2)
            }
            Next::Message(offset, end) => {
                let mut item = dns_display(input.get(offset..end).unwrap_or_default());
                item.offset = offset;
                Step::Item(item, end)
            }
        })
    }
}

/// Where the next message is, by the framing alone.
enum Next {
    /// A step that shows nothing: more input, a skip, or the end.
    Step(Step<Infallible>),
    /// A TCP message too long to keep, of this length: its two length
    /// bytes are shown, and the message is skipped.
    Long(usize),
    /// A whole message, from the first offset to the second.
    Message(usize, usize),
}

impl Dns {
    /// The next step of the framing, before anything is shown.
    fn next(&mut self, input: &[u8], eof: bool) -> Next {
        if self.lost {
            return Next::Step(Step::End);
        }
        if self.skip != 0 {
            let n = self.skip.min(input.len());
            self.skip -= n;
            return Next::Step(if n == 0 { Step::Need } else { Step::Skip(n) });
        }
        let (offset, len): (usize, usize) = if self.tcp {
            let Some(header) = input.get(..2) else {
                return Next::Step(Step::Need);
            };
            (2, usize::from(u16::from_be_bytes([header[0], header[1]])))
        } else {
            if self.taken {
                return Next::Step(Step::End);
            }
            if input.len() >= self.capacity() {
                self.taken = true;
                return Next::Step(Step::End);
            }
            if !eof {
                return Next::Step(Step::Need);
            }
            if input.is_empty() {
                return Next::Step(Step::End);
            }
            (0, input.len())
        };
        if self.tcp && len > MAX_BUFFER - 2 && input.len() < len.saturating_add(2) {
            self.skip = len;
            return Next::Long(len);
        }
        let Some(end) = offset.checked_add(len) else {
            return Next::Step(Step::End);
        };
        if input.len() < end {
            return Next::Step(Step::Need);
        }
        self.taken = true;
        Next::Message(offset, end)
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
        self.lost = self.tcp;
    }
}

// ---------------------------------------------------------------------------
// DNS and DHCP

fn dns_display(msg: &[u8]) -> Display {
    let mut packet = Decoded::default();
    let d = &mut packet;
    use fictionet::stdlib::protocols::dns::op::{Message, MessageType, ResponseCode};
    use fictionet::stdlib::protocols::dns::rr::rdata::opt::EdnsCode;
    use fictionet::stdlib::protocols::dns::{Ede, Nsid, Padding};
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
    let opcode = u8::from(md.op_code);
    l.field("Opcode", opcode_name(opcode), (base + 2, base + 3));
    let mut flags = vec![if response { "response" } else { "query" }.to_owned()];
    for (set, name) in [
        (md.recursion_desired, "recursion desired"),
        (md.recursion_available, "recursion available"),
        (md.authoritative, "authoritative"),
        (md.truncation, "truncated"),
        (md.authentic_data, "authentic data"),
        (md.checking_disabled, "checking disabled"),
    ] {
        if set {
            flags.push(name.into());
        }
    }
    l.field("Flags", flags.join(", "), (base + 2, base + 4));
    let mut errors = Vec::new();
    if let Some(edns) = &m.edns {
        let mut text = format!(
            "version {}, UDP payload {}",
            edns.version(),
            edns.max_payload()
        );
        if edns.flags().dnssec_ok {
            text.push_str(", DNSSEC OK");
        }
        l.note("EDNS", text);
        for (_, option) in edns.options().as_ref() {
            if let Some(ede) = Ede::from_option(option) {
                errors.push(ede.code);
                l.note("Extended DNS Error", ede.to_string());
            } else if let Some(nsid) = Nsid::from_option(option) {
                let text = String::from_utf8_lossy(&nsid.0).into_owned();
                l.note(
                    "NSID",
                    if text.is_empty() {
                        "requested".into()
                    } else {
                        text
                    },
                );
            } else if let Some(padding) = Padding::from_option(option) {
                l.note("Padding", format!("{} bytes", padding.0));
            } else {
                let code = u16::from(EdnsCode::from(option));
                l.note(
                    "EDNS option",
                    format!("code {code}, {} bytes", option.len()),
                );
            }
        }
    }
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
        "{}{} 0x{:04x} {}",
        opcode_summary(opcode),
        if response { " response" } else { "" },
        md.id,
        q_text.join(" ")
    );
    if response {
        if md.response_code != ResponseCode::NoError {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write for String never returns Err"
            )]
            let _ = write!(text, " {}", md.response_code);
            d.tag("dns-error");
        }
        for code in &errors {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write for String never returns Err"
            )]
            let _ = write!(text, " EDE {}", code.0);
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

/// The IANA name of a DNS opcode, with its number.
fn opcode_name(opcode: u8) -> String {
    match opcode {
        0 => "Query (0)".into(),
        1 => "Inverse query (1, obsolete)".into(),
        2 => "Status (2)".into(),
        4 => "Notify (4)".into(),
        5 => "Update (5)".into(),
        6 => "DNS Stateful Operations (6)".into(),
        _ => format!("Unassigned ({opcode})"),
    }
}

/// The start of a message's one-line summary, by opcode.
fn opcode_summary(opcode: u8) -> String {
    match opcode {
        0 => "Standard query".into(),
        1 => "Inverse query".into(),
        2 => "Server status request".into(),
        4 => "Zone change notification".into(),
        5 => "Dynamic update".into(),
        6 => "DNS Stateful Operations".into(),
        _ => format!("Opcode {opcode}"),
    }
}

/// Bounded proofs over the DNS-over-TCP framing, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../../verification/dissector/kani/dns.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::dns::op::{
        Edns, Message, MessageType, OpCode, Query, ResponseCode,
    };
    use fictionet::stdlib::protocols::dns::rr::{Name, RecordType};
    use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Nsid, Padding};

    fn fields(item: &Display) -> Vec<(String, String)> {
        item.layer
            .as_ref()
            .unwrap()
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect()
    }

    #[test]
    fn edns_flags_and_extended_errors_are_shown() {
        let mut reply = Message::error_msg(7, OpCode::Query, ResponseCode::ServFail);
        reply.metadata.authentic_data = true;
        reply.metadata.checking_disabled = true;
        reply.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        let options = edns.options_mut();
        options.insert(
            Ede {
                code: EdeCode::NO_REACHABLE_AUTHORITY,
                text: Some("all servers timed out".into()),
            }
            .to_option(),
        );
        options.insert(Nsid(b"gw1".to_vec()).to_option());
        options.insert(Padding(16).to_option());
        reply.set_edns(edns);

        let item = dns_display(&reply.to_vec().unwrap());
        assert_eq!(
            item.info,
            "Standard query response 0x0007 A example.test Server Failure EDE 22"
        );
        let fields = fields(&item);
        let get = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(get("Opcode"), "Query (0)");
        assert_eq!(get("Flags"), "response, authentic data, checking disabled");
        assert_eq!(get("EDNS"), "version 0, UDP payload 1232, DNSSEC OK");
        assert_eq!(
            get("Extended DNS Error"),
            "22 (No Reachable Authority): all servers timed out"
        );
        assert_eq!(get("NSID"), "gw1");
        assert_eq!(get("Padding"), "16 bytes");
    }

    #[test]
    fn opcodes_are_named() {
        let mut notify = Message::new(9, MessageType::Query, OpCode::Notify);
        notify.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::SOA,
        ));
        let item = dns_display(&notify.to_vec().unwrap());
        assert_eq!(
            item.info,
            "Zone change notification 0x0009 SOA example.test"
        );
        assert!(fields(&item).contains(&("Opcode".into(), "Notify (4)".into())));
        assert_eq!(opcode_name(3), "Unassigned (3)");
        assert_eq!(opcode_summary(15), "Opcode 15");
    }
    #[test]
    fn response_codes_preserve_summary_and_error_tags() {
        for (code, suffix, tags) in [
            (ResponseCode::NoError, "", &[][..]),
            (
                ResponseCode::ServFail,
                " Server Failure",
                &["dns-error"][..],
            ),
            (
                ResponseCode::NXDomain,
                " Non-Existent Domain",
                &["dns-error"][..],
            ),
            (
                ResponseCode::Unknown(15),
                " Unknown response code",
                &["dns-error"][..],
            ),
        ] {
            let mut message = Message::response(0x1234, OpCode::Query);
            message.metadata.response_code = code;
            let display = dns_display(&message.to_vec().unwrap());
            assert_eq!(display.tags, tags);
            assert_eq!(
                display.info,
                format!("Standard query response 0x1234 {suffix}")
            );
            assert_eq!(display.summary(), display.info);

            message.metadata.message_type = MessageType::Query;
            let display = dns_display(&message.to_vec().unwrap());
            assert!(display.tags.is_empty());
            assert_eq!(display.info, "Standard query 0x1234 ");
        }
    }
}
