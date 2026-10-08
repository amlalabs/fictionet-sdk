use fictionet::stdlib::codec::Frames;
use fictionet::observe::{Decoded, KeyLine, Layer, Observed, Place, Placement, Present, Protocol};
use fictionet::stdlib::codec::{Decode, Fail, Step};
use fictionet::stdlib::http1;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt::Write;
use std::sync::{Arc, Mutex};

/// Bytes retained while an incomplete capture message is being framed.
const MAX_BUFFER: usize = 32 << 10;

/// A decoded item's relative layer and packet summary. Capture decoders
/// produce this value for the shared [`Present`] implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    layer: Option<Layer>,
    protocol: String,
    info: String,
    tags: Vec<&'static str>,
    buffer: &'static str,
    level: u8,
    offset: usize,
    detached: bool,
}

impl Display {
    /// Takes the packet's last layer, summary, and tags as one display item.
    /// Layer and field ranges must be relative to the item's raw bytes.
    /// `buffer` names the reassembly buffer used when the item spans packets.
    pub fn from_packet(mut packet: Decoded, buffer: &'static str) -> Self {
        let level = packet.level();
        Self {
            layer: packet.layers.pop(),
            protocol: packet.proto,
            info: packet.info,
            tags: packet.tags,
            buffer,
            level,
            offset: 0,
            detached: false,
        }
    }
    fn summary(&self) -> String {
        self.layer
            .as_ref()
            .map_or_else(String::new, |l| l.summary.clone())
    }
    fn fields(&self, layer: &mut Layer) {
        if let Some(source) = &self.layer {
            layer.fields = source.fields.clone();
        }
    }
    fn present(&self, raw: &[u8], start: u64, place: &Placement, packet: &mut Decoded) {
        let Some(source) = &self.layer else { return };
        let Some(bytes) = raw.get(self.offset..) else {
            return;
        };
        let mut layer = Layer::new(&source.name, 0, source.range);
        layer.summary = self.summary();
        self.fields(&mut layer);
        if self.detached {
            packet.push(layer);
        } else {
            place.push(
                packet,
                start.saturating_add(self.offset as u64),
                bytes,
                self.buffer,
                layer,
            );
        }
        for tag in &self.tags {
            packet.tag(tag);
        }
        if self.level == 0 {
            if !self.protocol.is_empty() {
                packet.proto.clone_from(&self.protocol);
                packet.info.clone_from(&self.info);
                packet.cap_info();
            }
        } else {
            packet.application(self.level, &self.protocol, &self.info);
        }
    }
}

macro_rules! display_presenter {
    () => {
        fn summary(item: &Display) -> String {
            item.summary()
        }
        fn fields(item: &Display, _: &[u8], layer: &mut Layer) {
            item.fields(layer);
        }
        fn present(
            item: &Display,
            bytes: &[u8],
            start: u64,
            place: &Placement,
            packet: &mut Decoded,
        ) {
            item.present(bytes, start, place, packet);
        }
    };
}

/// Modbus/TCP capture frames. Framing is provided by the stdlib decoder.
pub struct Modbus {
    frames: Frames::<fictionet::stdlib::modbus::Frame>,
    request: bool,
}
impl Modbus {
    /// Selects request or response presentation for this direction.
    pub fn new(request: bool) -> Self {
        Self {
            frames: Frames::<fictionet::stdlib::modbus::Frame>::new(),
            request,
        }
    }
}
impl Decode for Modbus {
    type Item = Display;
    type Error = fictionet::stdlib::modbus::Error;
    const NAME: &'static str = "Modbus/TCP";
    fn capacity(&self) -> usize {
        self.frames.capacity()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Display>, Self::Error> {
        Ok(match self.frames.decode(input, eof)? {
            Step::Item(frame, n) => Step::Item(modbus_display(&frame, n, self.request), n),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}
impl Present for Modbus {
    display_presenter!();
    // An unrecognized Modbus header makes the conversation opaque.
    fn error(_: &Fail<Self::Error>, _: &mut Decoded) {}
}

/// A Modbus/TCP conversation that stops both directions after a framing error.
/// Register with [`Registry::register_protocol`](fictionet::observe::Registry::register_protocol)
/// to keep the built-in session policy when copying this file.
pub struct ModbusSession {
    dirs: [Option<Observed<Modbus>>; 2],
    stopped: bool,
}
impl ModbusSession {
    /// Creates request and response decoders from the conversation's ports.
    /// A direction is a request when its destination is the Modbus port.
    pub fn new(ports: (u16, u16)) -> Self {
        Self {
            dirs: [
                Some(Observed::new(Modbus::new(
                    ports.1 == fictionet::stdlib::modbus::PORT,
                ))),
                Some(Observed::new(Modbus::new(
                    ports.0 == fictionet::stdlib::modbus::PORT,
                ))),
            ],
            stopped: false,
        }
    }
}
impl Protocol for ModbusSession {
    fn data(&mut self, reverse: bool, bytes: &[u8], at: Place, d: &mut Decoded, _: &[KeyLine]) {
        if self.stopped {
            return;
        }
        if let Some(dir) = &mut self.dirs[usize::from(reverse)] {
            dir.data(bytes, at, d);
            self.stopped = dir.failed().is_some();
        }
    }
    fn waiting(&self, reverse: bool) -> bool {
        !self.stopped
            && self.dirs[usize::from(reverse)]
                .as_ref()
                .is_some_and(Observed::waiting)
    }
    fn lost(&mut self, reverse: bool) {
        let slot = &mut self.dirs[usize::from(reverse)];
        *slot = slot.take().map(Observed::reset);
    }
}

/// DNS capture messages, either one UDP datagram or length-prefixed TCP.
/// Oversized TCP messages emit their length header, then skip the payload.
pub struct Dns {
    tcp: bool,
    taken: bool,
    skip: usize,
}
impl Dns {
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

/// One DHCP datagram, parsed at EOF with the stdlib message parser.
#[derive(Default)]
pub struct Dhcp {
    taken: bool,
}
impl Decode for Dhcp {
    type Item = Display;
    type Error = Infallible;
    const NAME: &'static str = "DHCP";
    fn capacity(&self) -> usize {
        65_536
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Display>, Infallible> {
        if self.taken || input.len() >= self.capacity() || (eof && input.is_empty()) {
            return Ok(Step::End);
        }
        if !eof {
            return Ok(Step::Need);
        }
        self.taken = true;
        Ok(Step::Item(dhcp_display(input), input.len()))
    }
}
impl Present for Dhcp {
    display_presenter!();
}

/// HTTP/1 capture parser. It shares a bounded request-method queue with
/// the other direction so HEAD and CONNECT responses retain their framing.
#[derive(Default)]
pub struct Http1 {
    state: Http1State,
    methods: Arc<Mutex<Methods>>,
    // The other decoder in a pair accounts for this shared queue.
    shared_methods: bool,
    scanned: usize,
    final_chunk: Option<usize>,
}
impl Http1 {
    /// Creates request and response decoders with one shared method queue.
    /// The first decoder accounts for its at most 64 bytes in `held()`.
    pub fn pair() -> [Self; 2] {
        let methods = Arc::default();
        [
            Self {
                state: Http1State::default(),
                methods: Arc::clone(&methods),
                shared_methods: false,
                scanned: 0,
                final_chunk: None,
            },
            Self {
                state: Http1State::default(),
                methods,
                shared_methods: true,
                scanned: 0,
                final_chunk: None,
            },
        ]
    }
    fn find(&mut self, input: &[u8], delimiter: &[u8]) -> Option<usize> {
        let from = self
            .scanned
            .saturating_sub(delimiter.len().saturating_sub(1));
        let found = input
            .get(from..)?
            .windows(delimiter.len())
            .position(|w| w == delimiter)
            .and_then(|n| from.checked_add(n));
        self.scanned = if found.is_some() { 0 } else { input.len() };
        found
    }
}
impl Decode for Http1 {
    type Item = Display;
    type Error = Infallible;
    const NAME: &'static str = "HTTP";
    fn capacity(&self) -> usize {
        MAX_BUFFER + 1
    }
    fn held(&self) -> usize {
        let preview = match &self.state {
            Http1State::Body { seen, .. } | Http1State::Chunked { seen, .. } => seen.len(),
            _ => 0,
        };
        if self.shared_methods {
            preview
        } else {
            let methods = self.methods.lock().unwrap_or_else(|e| e.into_inner());
            preview.saturating_add(methods.0.len())
        }
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Display>, Infallible> {
        if matches!(self.state, Http1State::Head) {
            let Some(end) = self.find(input, b"\r\n\r\n") else {
                if input.len() >= self.capacity() {
                    self.reset();
                    return Ok(Step::Skip(input.len()));
                }
                return Ok(Step::Need);
            };
            let Some(head) = input.get(..end.saturating_add(4)) else {
                return Ok(Step::Need);
            };
            let mut methods = self.methods.lock().unwrap_or_else(|e| e.into_inner());
            let Some((line, kind, body)) = read_head(head, &mut methods) else {
                return Ok(Step::Skip(head.len()));
            };
            drop(methods);
            self.state = body;
            let mut layer = Layer::new("Hypertext Transfer Protocol", 0, (0, head.len()));
            layer.summary.clone_from(&line);
            let mut at = 0usize;
            for (n, text) in head
                .get(..end)
                .unwrap_or_default()
                .split(|b| *b == b'\n')
                .enumerate()
            {
                let t = String::from_utf8_lossy(text).trim_end().to_owned();
                let range = (at, at.saturating_add(text.len()));
                at = at.saturating_add(text.len()).saturating_add(1);
                if n == 0 {
                    layer.field(
                        if kind == "request" {
                            "Request line"
                        } else {
                            "Status line"
                        },
                        t,
                        range,
                    );
                } else if let Some((k, v)) = t.split_once(':') {
                    layer.field(k.trim(), v.trim(), range);
                }
            }
            let mut d = Decoded::default();
            d.push(layer);
            d.application(2, "HTTP", &line);
            return Ok(Step::Item(
                Display::from_packet(d, "Reassembled HTTP head"),
                head.len(),
            ));
        }
        // Cache both line boundaries. Size and trailer lines are scanned
        // once even when every byte arrives in its own segment.
        if matches!(self.state, Http1State::Chunked { left: 0, .. }) {
            if self.final_chunk.is_none() {
                let skip = if input.starts_with(b"\r\n") {
                    2usize
                } else {
                    0
                };
                let tail = input.get(skip..).unwrap_or_default();
                let Some(end) = self.find(tail, b"\r\n") else {
                    if input.len() >= self.capacity() {
                        self.reset();
                        return Ok(Step::Skip(input.len()));
                    }
                    return Ok(Step::Need);
                };
                let line = String::from_utf8_lossy(tail.get(..end).unwrap_or_default());
                let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                    .unwrap_or(0);
                let used = skip.saturating_add(end).saturating_add(2);
                if size == 0 {
                    self.final_chunk = Some(used);
                } else if let Http1State::Chunked { left, total, .. } = &mut self.state {
                    *left = size;
                    *total = total.saturating_add(size);
                    return Ok(Step::Skip(used));
                }
            }
            if let Some(used) = self.final_chunk {
                let after = input.get(used..).unwrap_or_default();
                let Some(rest) = self.find(after, b"\r\n") else {
                    if input.len() >= self.capacity() {
                        self.reset();
                        return Ok(Step::Skip(input.len()));
                    }
                    return Ok(Step::Need);
                };
                self.final_chunk = None;
                let state = std::mem::take(&mut self.state);
                if let Http1State::Chunked { total, seen, .. } = state {
                    return Ok(Step::Item(
                        body_item(total, &seen),
                        used.saturating_add(rest).saturating_add(2),
                    ));
                }
            }
        }
        let fixed_body = matches!(self.state, Http1State::Body { .. });
        match &mut self.state {
            Http1State::Body { left, seen, total } | Http1State::Chunked { left, seen, total } => {
                if input.is_empty() {
                    return Ok(Step::Need);
                }
                let n = usize::try_from(*left)
                    .unwrap_or(usize::MAX)
                    .min(input.len());
                let take = n.min(4096usize.saturating_sub(seen.len()));
                seen.extend_from_slice(input.get(..take).unwrap_or_default());
                *left = left.saturating_sub(n as u64);
                if *left == 0 && fixed_body {
                    let Http1State::Body { total, seen, .. } = std::mem::take(&mut self.state)
                    else {
                        return Ok(Step::End);
                    };
                    return Ok(Step::Item(body_item(total, &seen), n));
                }
                let _ = total;
                Ok(Step::Skip(n))
            }
            Http1State::ToClose | Http1State::Tunnel => Ok(if input.is_empty() {
                Step::Need
            } else {
                Step::Skip(input.len())
            }),
            Http1State::Head => Ok(Step::Need),
        }
    }
}
impl Present for Http1 {
    display_presenter!();
    fn reset(&mut self) {
        self.state = Http1State::default();
        self.scanned = 0;
        self.final_chunk = None;
    }
}
fn body_item(total: u64, seen: &[u8]) -> Display {
    let mut d = Decoded::default();
    body_layer(&mut d, total, seen);
    let mut item = Display::from_packet(d, "HTTP body");
    item.detached = true;
    item
}

/// A TLS record's capture metadata. Its exact bytes come from the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Payload length declared by the header.
    pub length: usize,
    /// Only the header was retained; the payload will be skipped.
    pub oversized: bool,
}

/// TLS record boundaries for a capture. Oversized records yield one
/// header-only item and skip their payload without allocating it.
#[derive(Default)]
pub struct TlsRecords {
    skip: usize,
}
impl Decode for TlsRecords {
    type Item = Record;
    type Error = Infallible;
    const NAME: &'static str = "TLS";
    fn capacity(&self) -> usize {
        MAX_BUFFER
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Record>, Infallible> {
        if self.skip != 0 {
            let n = self.skip.min(input.len());
            self.skip -= n;
            return Ok(if n == 0 { Step::Need } else { Step::Skip(n) });
        }
        let Some(header) = input.get(..5) else {
            return Ok(Step::Need);
        };
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let oversized = length > MAX_BUFFER - 5 && input.len() < length.saturating_add(5);
        let used = if oversized { 5 } else { length + 5 };
        if input.len() < used {
            return Ok(Step::Need);
        }
        if oversized {
            self.skip = length;
        }
        Ok(Step::Item(Record { length, oversized }, used))
    }
}
impl Present for TlsRecords {
    fn summary(item: &Record) -> String {
        if item.oversized {
            format!("a {}-byte record, longer than TLS allows", item.length)
        } else {
            format!("{}-byte record", item.length)
        }
    }
    fn fields(item: &Record, bytes: &[u8], layer: &mut Layer) {
        let Some(header) = bytes.get(..5) else { return };
        let kind = header[0];
        if item.oversized {
            layer.field("Content type", kind.to_string(), (0, 1));
        } else {
            let name = match kind {
                20 => "Change Cipher Spec",
                21 => "Alert",
                22 => "Handshake",
                23 => "Application Data",
                _ => "unknown",
            };
            layer.field("Content type", format!("{name} ({kind})"), (0, 1));
            layer.field(
                "Version",
                format!("0x{:04x}", u16::from_be_bytes([header[1], header[2]])),
                (1, 3),
            );
        }
        layer.field("Length", item.length.to_string(), (3, 5));
    }
    fn pending(&self) -> bool {
        self.skip != 0
    }
    fn reset(&mut self) {
        self.skip = 0;
    }
}

// ---------------------------------------------------------------------------
// DNS and DHCP

fn dns_display(msg: &[u8]) -> Display {
    let mut packet = Decoded::default();
    let d = &mut packet;
    use hickory_proto::op::{Message, MessageType};
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
            let _ = write!(text, " {code}");
            d.tag("dns-error");
        }
        if !a_text.is_empty() {
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

fn dhcp_display(bytes: &[u8]) -> Display {
    let mut packet = Decoded::default();
    let Ok(m) = <fictionet::stdlib::dhcp::Message as fictionet::stdlib::codec::Wire>::parse(bytes) else {
        return Display::from_packet(packet, "DHCP message");
    };
    let d = &mut packet;
    let range = (0, bytes.len());
    let kind = match m.message_type() {
        Some(1) => "Discover",
        Some(2) => "Offer",
        Some(3) => "Request",
        Some(4) => "Decline",
        Some(5) => "ACK",
        Some(6) => "NAK",
        Some(7) => "Release",
        Some(8) => "Inform",
        _ => "message",
    };
    let mut l = Layer::new("Dynamic Host Configuration Protocol", 0, range);
    l.summary = kind.into();
    l.field(
        "Transaction ID",
        format!("0x{:08x}", m.xid),
        (range.0 + 4, range.0 + 8),
    );
    l.field(
        "Your address",
        m.yiaddr.to_string(),
        (range.0 + 16, range.0 + 20),
    );
    for (code, value) in &m.options {
        let v = match (code, value.len()) {
            (1 | 3 | 6 | 50 | 54, n) if n % 4 == 0 && n > 0 => value
                .chunks(4)
                .map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3]))
                .collect::<Vec<_>>()
                .join(", "),
            (51, 4) => format!(
                "{} s",
                u32::from_be_bytes([value[0], value[1], value[2], value[3]])
            ),
            _ => format!("{} bytes", value.len()),
        };
        let name = match code {
            1 => "Subnet mask",
            3 => "Router",
            6 => "DNS servers",
            12 => "Host name",
            50 => "Requested address",
            51 => "Lease time",
            53 => "Message type",
            54 => "Server",
            _ => "Option",
        };
        l.note(
            name,
            if *code == 53 {
                kind.to_owned()
            } else {
                format!("{v} (option {code})")
            },
        );
    }
    d.push(l);
    d.proto = "DHCP".into();
    d.info = format!("DHCP {kind} - Transaction ID 0x{:08x}", m.xid);
    Display::from_packet(packet, "DHCP message")
}

fn modbus_display(frame: &fictionet::stdlib::modbus::Frame, used: usize, request: bool) -> Display {
    use fictionet::stdlib::modbus::{Request, Response};
    let mut decoded = Decoded::default();
    let d = &mut decoded;
    let (buf, base) = (0, 0);
    let mut l = Layer::new("Modbus/TCP", buf, (base, base + used));
    l.field(
        "Transaction identifier",
        frame.transaction.to_string(),
        (base, base + 2),
    );
    l.field("Protocol identifier", "0".to_owned(), (base + 2, base + 4));
    l.field(
        "Length",
        used.saturating_sub(6).to_string(),
        (base + 4, base + 6),
    );
    l.field(
        "Unit identifier",
        frame.unit.to_string(),
        (base + 6, base + 7),
    );
    let function = frame.function().unwrap_or(0);
    l.field(
        "Function code",
        format!("{} ({})", function & 0x7f, modbus_function(function & 0x7f)),
        (base + 7, base + 8),
    );
    let detail = if request {
        match Request::parse(&frame.pdu) {
            Ok(Request::ReadCoils { address, quantity })
            | Ok(Request::ReadDiscreteInputs { address, quantity })
            | Ok(Request::ReadHoldingRegisters { address, quantity })
            | Ok(Request::ReadInputRegisters { address, quantity }) => {
                format!("address {address}, quantity {quantity}")
            }
            Ok(Request::WriteSingleCoil { address, value }) => {
                format!("address {address}, {}", if value { "on" } else { "off" })
            }
            Ok(Request::WriteSingleRegister { address, value }) => {
                format!("address {address}, value {value}")
            }
            Ok(Request::WriteMultipleCoils { address, values }) => {
                format!("address {address}, {} coils", values.len())
            }
            Ok(Request::WriteMultipleRegisters { address, values }) => {
                format!("address {address}, values {values:?}")
            }
            Ok(Request::Other { data, .. }) => format!("{} bytes of data", data.len()),
            Err(e) => format!("malformed: a server answers {e}"),
        }
    } else {
        match Response::parse(&frame.pdu) {
            Ok((_, Response::Bits(bits))) => format!("{} bits", bits.len()),
            Ok((_, Response::Registers(regs))) => format!("registers {regs:?}"),
            Ok((_, Response::WriteSingleCoil { address, value })) => {
                format!("address {address}, {}", if value { "on" } else { "off" })
            }
            Ok((_, Response::WriteSingleRegister { address, value })) => {
                format!("address {address}, value {value}")
            }
            Ok((_, Response::WriteMultiple { address, quantity })) => {
                format!("address {address}, quantity {quantity}")
            }
            Ok((_, Response::Exception(e))) => format!("exception: {e}"),
            Ok((_, Response::Other(data))) => format!("{} bytes of data", data.len()),
            Err(_) => "malformed".to_owned(),
        }
    };
    let kind = if request { "Query" } else { "Response" };
    l.summary = format!(
        "{kind}, transaction {}, unit {}: {detail}",
        frame.transaction, frame.unit
    );
    l.note(if request { "Request" } else { "Response" }, detail.clone());
    d.push(l);
    d.application(
        2,
        "Modbus/TCP",
        &format!(
            "{kind}: Trans: {}; Unit: {}, Func: {}: {}",
            frame.transaction,
            frame.unit,
            function & 0x7f,
            modbus_function(function & 0x7f)
        ),
    );
    Display::from_packet(decoded, "Modbus/TCP frame")
}

fn modbus_function(f: u8) -> &'static str {
    match f {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        _ => "Other",
    }
}

/// HTTP/1.1 request methods waiting for their responses.
#[derive(Default)]
struct Methods(VecDeque<Method>);

#[repr(u8)]
enum Method {
    Head,
    Connect,
    Other,
}

impl Methods {
    fn push(&mut self, m: &str) {
        if self.0.len() >= 64 {
            self.0.pop_front();
        }
        self.0.push_back(match m {
            "HEAD" => Method::Head,
            "CONNECT" => Method::Connect,
            _ => Method::Other,
        });
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1

#[derive(Default)]
enum Http1State {
    /// Waiting for a request or status line and headers.
    #[default]
    Head,
    /// In a body of known length: bytes left, and the start of it.
    Body {
        left: u64,
        seen: Vec<u8>,
        total: u64,
    },
    /// In a chunked body: bytes left of the current chunk (0 between
    /// chunks), and the start of it.
    Chunked {
        left: u64,
        seen: Vec<u8>,
        total: u64,
    },
    /// In a body that lasts until the connection closes.
    ToClose,
    /// After a CONNECT was accepted: bytes of another protocol.
    Tunnel,
}

fn body_kind(headers: &[http1::Header], none: bool, response: bool) -> Http1State {
    if none {
        return Http1State::Head;
    }
    let get = |name: &str| {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(&h.value).to_string())
    };
    if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        return Http1State::Chunked {
            left: 0,
            seen: Vec::new(),
            total: 0,
        };
    }
    match get("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(0) => Http1State::Head,
        Some(n) => Http1State::Body {
            left: n,
            seen: Vec::new(),
            total: n,
        },
        None if response => Http1State::ToClose,
        None => Http1State::Head,
    }
}

/// Reads a request or response head: its first line, which it is, and
/// how its body is framed. The head is read by its syntax alone, with
/// [`http1`]'s lenient reader: a passive observer must not refuse a head
/// the endpoints took.
fn read_head(head: &[u8], methods: &mut Methods) -> Option<(String, &'static str, Http1State)> {
    if head.starts_with(b"HTTP/") {
        let (r, _) = http1::ResponseHead::parse_lenient(head).ok().flatten()?;
        let code = r.status;
        let line = format!("{} {code} {}", r.version.as_str(), String::from_utf8_lossy(&r.reason));
        let method = if (100..200).contains(&code) { None } else { methods.0.pop_front() };
        let body = match method {
            Some(Method::Connect) if (200..300).contains(&code) => Http1State::Tunnel,
            Some(Method::Head) => Http1State::Head,
            _ => body_kind(&r.headers, (100..200).contains(&code) || code == 204 || code == 304, true),
        };
        Some((line, "response", body))
    } else {
        let (r, _) = http1::RequestHead::parse_lenient(head).ok().flatten()?;
        let line = format!("{} {} {}", r.method, r.target, r.version.as_str());
        methods.push(&r.method);
        Some((line, "request", body_kind(&r.headers, false, false)))
    }
}

/// Text for a preview of bytes: the start, if it reads as text.
fn preview(b: &[u8]) -> Option<String> {
    let cut = &b[..b.len().min(160)];
    let text = std::str::from_utf8(cut).ok()?;
    if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
        let mut t = text.replace("\r\n", "\\r\\n").replace('\n', "\\n");
        if b.len() > cut.len() {
            t.push('…');
        }
        Some(t)
    } else {
        None
    }
}

fn body_layer(d: &mut Decoded, total: u64, seen: &[u8]) {
    let mut l = Layer::new("HTTP body", 0, (0, 0));
    l.summary = format!("{total} bytes");
    if let Some(text) = preview(seen) {
        l.note("Text", text);
    }
    d.push(l);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Lcg, Stream, contract::check_decode};

    #[test]
    fn long_http_methods_keep_only_bounded_framing_state() {
        let [request, response] = Http1::pair();
        let mut request = Stream::with_buffer(request, MAX_BUFFER + 1 + 65_535);
        let response = Stream::new(response);
        let mut bytes = vec![b'A'; 90_000];
        bytes.extend_from_slice(b" / HTTP/1.1\r\n\r\n");
        for count in 1..=65 {
            assert_eq!(request.push(&bytes[..32_000]), 32_000);
            assert!(request.next().is_none());
            assert_eq!(request.push(&bytes[32_000..]), bytes.len() - 32_000);
            assert!(request.next().unwrap().is_ok());
            assert!(request.next().is_none());
            assert_eq!(request.held() + response.held(), count.min(64));
        }
    }

    #[test]
    fn empty_datagrams_end_without_a_display_item() {
        assert!(matches!(Dns::new(false).decode(&[], true), Ok(Step::End)));
        assert!(matches!(Dhcp::default().decode(&[], true), Ok(Step::End)));
    }

    #[test]
    fn capture_decoders_follow_the_codec_contract() {
        let mut random = Lcg::new(17);
        for n in [0, 1, 5, 17, 64, 257] {
            let bytes = random.bytes(n);
            check_decode(|| Dns::new(true), &bytes);
            check_decode(|| Dns::new(false), &bytes);
            check_decode(Dhcp::default, &bytes);
            check_decode(Http1::default, &bytes);
            check_decode(TlsRecords::default, &bytes);
            check_decode(|| Modbus::new(true), &bytes);
            check_decode(|| Modbus::new(false), &bytes);
        }
        for bytes in [
            &b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /x HTTP/1.1\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3;ext\r\nllo\r\n0\r\n\r\nGET / HTTP/1.1\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n\r\na body until close"[..],
        ] { check_decode(Http1::default, bytes); }
        check_decode(
            || Dns::new(true),
            &[0, 12, 0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        check_decode(TlsRecords::default, &[23, 3, 3, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn oversized_records_emit_a_header_then_skip_and_resume() {
        let mut dns = Stream::new(Dns::new(true));
        assert_eq!(dns.push(&40_000u16.to_be_bytes()), 2);
        let (item, range) = dns.next_span().unwrap().unwrap();
        assert_eq!(range, 0..2);
        assert_eq!(
            item.summary(),
            "a 40000-byte message, too long to decode here"
        );
        for _ in 0..40 {
            assert_eq!(dns.push(&[0; 1000]), 1000);
            assert!(dns.next().is_none());
        }
        assert_eq!(dns.offset(), 40_002);
        assert_eq!(
            dns.push(&[0, 12, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            14
        );
        assert_eq!(dns.next_span().unwrap().unwrap().1, 40_002..40_016);

        let mut tls = Stream::new(TlsRecords::default());
        assert_eq!(tls.push(&[23, 3, 3, 0x9c, 0x40]), 5);
        let (item, range) = tls.next_span().unwrap().unwrap();
        assert_eq!(range, 0..5);
        assert!(item.oversized);
        for _ in 0..40 {
            assert_eq!(tls.push(&[0; 1000]), 1000);
            assert!(tls.next().is_none());
        }
        assert_eq!(tls.push(&[20, 3, 3, 0, 1, 1]), 6);
        let (item, range) = tls.next_span().unwrap().unwrap();
        assert!(!item.oversized);
        assert_eq!(range, 40_005..40_011);
    }

    #[test]
    fn http_size_and_trailer_scans_resume_without_rescanning() {
        let mut http = Http1 {
            state: Http1State::Chunked {
                left: 0,
                seen: Vec::new(),
                total: 0,
            },
            ..Http1::default()
        };
        let mut bytes = b"0\r\n".to_vec();
        for _ in 0..1000 {
            bytes.push(b'x');
            assert!(matches!(http.decode(&bytes, false), Ok(Step::Need)));
            assert_eq!(http.final_chunk, Some(3));
            assert_eq!(http.scanned, bytes.len() - 3);
        }
        bytes.extend_from_slice(b"\r\n");
        assert!(matches!(http.decode(&bytes, false), Ok(Step::Item(_, n)) if n == bytes.len()));
    }
}
