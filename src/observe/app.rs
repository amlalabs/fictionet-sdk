//! Application protocols: DNS, DHCP, HTTP/1.1, HTTP/2, Modbus/TCP, and TLS,
//! which is decrypted when the world's TLS stack gave its session keys.
//!
//! A [`Conversation`] is one TCP connection, both ways. It guesses the
//! protocol from the ports and the first bytes, then decodes each
//! direction's byte stream as it arrives. Each message it finds becomes a
//! [`Layer`] of the packet that completed it. When the whole message lies
//! in that packet, its fields point at the packet's own bytes; otherwise
//! the message gets a buffer of its own, as Wireshark's "Reassembled TCP".

use std::collections::VecDeque;
use std::fmt::Write;

use super::decode::{Decoded, Layer, be16, be32};
use super::hpack;
use crate::watch::KeyLine;

/// Where some bytes of a stream are: from stream offset `stream_start`,
/// `len` bytes, found at `offset` in buffer `buf` of the packet's
/// [`Decoded`], if they are all in one place there.
#[derive(Clone, Copy)]
pub(crate) struct Place {
    pub(crate) stream_start: u64,
    pub(crate) buf: usize,
    pub(crate) offset: Option<usize>,
    pub(crate) len: usize,
}

impl Place {
    /// The buffer and the start in it of the message at stream offset
    /// `start`, adding a buffer named `name` with `bytes` if the message
    /// is not all in this place.
    fn locate(&self, d: &mut Decoded, start: u64, bytes: &[u8], name: &str) -> (usize, usize) {
        if let Some(off) = self.offset
            && start >= self.stream_start
            && start + bytes.len() as u64 <= self.stream_start + self.len as u64
        {
            return (self.buf, off + (start - self.stream_start) as usize);
        }
        (d.buffer(name, bytes.to_vec()), 0)
    }
}

/// Sets the packet's protocol and info from a message at `level`: 1 for
/// TLS records, 2 for what they carry and for plain HTTP. A higher level
/// replaces what lower ones said; the same level adds to it.
fn info(d: &mut Decoded, level: u8, proto: &str, text: &str) {
    if level > d.level {
        d.level = level;
        d.proto = proto.into();
        d.info = text.to_owned();
    } else if level == d.level && text.starts_with("HEADERS") && !d.info.starts_with("HEADERS") {
        // Requests and responses go first, ahead of SETTINGS and the like,
        // so a cut-off line still shows them.
        d.info = format!("{text}, {}", d.info);
    } else if level == d.level {
        d.info.push_str(", ");
        d.info.push_str(text);
    }
    d.cap_info();
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

// ---------------------------------------------------------------------------
// DNS and DHCP

/// Decodes the DNS message `msg`, which starts at stream offset `start` of
/// the bytes at `place`.
pub(crate) fn dns(msg: &[u8], place: Place, start: u64, d: &mut Decoded) {
    use hickory_proto::op::{Message, MessageType};
    let (buf, base) = place.locate(d, start, msg, "DNS message");
    let mut l = Layer::new("Domain Name System", buf, (base, base + msg.len()));
    let Ok(m) = Message::from_vec(msg) else {
        l.summary = "malformed".into();
        d.push(l);
        d.proto = "DNS".into();
        d.info = "Malformed DNS message".into();
        d.tag("malformed");
        return;
    };
    let md = &m.metadata;
    let response = md.message_type == MessageType::Response;
    l.field("Transaction ID", format!("0x{:04x}", md.id), (base, base + 2));
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
        l.field("Reply code", format!("{}", md.response_code), (base + 3, base + 4));
    }
    let mut q_text = Vec::new();
    for q in &m.queries {
        let name = q.name().to_string();
        let name = name.trim_end_matches('.');
        l.note("Query", format!("{name}: type {}, class {}", q.query_type(), q.query_class()));
        q_text.push(format!("{} {name}", q.query_type()));
    }
    let mut a_text = Vec::new();
    for (section, records) in [("Answer", &m.answers), ("Authority", &m.authorities), ("Additional", &m.additionals)] {
        for r in records.iter() {
            let name = r.name.to_string();
            let data = r.data.to_string();
            l.note(section, format!("{}: type {}, TTL {}, {data}", name.trim_end_matches('.'), r.record_type(), r.ttl));
            if section == "Answer" {
                a_text.push(format!("{} {data}", r.record_type()));
            }
        }
    }
    let mut text = format!("Standard query{} 0x{:04x} {}", if response { " response" } else { "" }, md.id, q_text.join(" "));
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
}

/// Decodes a DHCP message at `range` of the packet.
pub(crate) fn dhcp(p: &[u8], range: (usize, usize), d: &mut Decoded) {
    let Some(m) = crate::stdlib::dhcp::Message::parse(&p[range.0..range.1]) else { return };
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
    l.field("Transaction ID", format!("0x{:08x}", m.xid), (range.0 + 4, range.0 + 8));
    l.field("Your address", m.yiaddr.to_string(), (range.0 + 16, range.0 + 20));
    for (code, value) in &m.options {
        let v = match (code, value.len()) {
            (1 | 3 | 6 | 50 | 54, n) if n % 4 == 0 && n > 0 => {
                value.chunks(4).map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3])).collect::<Vec<_>>().join(", ")
            }
            (51, 4) => format!("{} s", be32(value, 0)),
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
        l.note(name, if *code == 53 { kind.to_owned() } else { format!("{v} (option {code})") });
    }
    d.push(l);
    d.proto = "DHCP".into();
    d.info = format!("DHCP {kind} - Transaction ID 0x{:08x}", m.xid);
}

// ---------------------------------------------------------------------------
// TCP conversations

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Bytes a direction may hold while waiting for the end of a message. A
/// longer message whose length its header gives is shown by that header,
/// and the rest of it is skipped. One whose end cannot be found that way
/// is dropped. With at most 512 directions followed (see `stream`), and a
/// decrypted stream beside each, this bounds what a link's decoder holds
/// at 64 MiB, whatever the agent sends.
const MAX_BUFFER: usize = 32 << 10;
/// The longest HTTP/2 header block kept across CONTINUATION frames.
const MAX_HEADER_BLOCK: usize = 64 << 10;

enum Proto {
    Unknown,
    Dns,
    Tls(Box<Tls>),
    Http1,
    Http2,
    Modbus,
    /// Not a protocol this decodes.
    Opaque,
}

/// One direction's bytes not decoded yet.
#[derive(Default)]
struct Dir {
    buf: Vec<u8>,
    /// The stream offset of `buf[0]`.
    start: u64,
    /// Bytes still to come of a message too long to hold, which are
    /// dropped as they arrive.
    skip: u64,
    http1: Http1,
    http2: Http2,
}

impl Dir {
    fn push(&mut self, bytes: &[u8], place: &Place) {
        if self.buf.is_empty() {
            self.start = place.stream_start;
        }
        self.buf.extend_from_slice(bytes);
        let n = self.skip.min(self.buf.len() as u64);
        self.consume(n as usize);
        self.skip -= n;
    }

    fn consume(&mut self, n: usize) {
        self.buf.drain(..n);
        self.start += n as u64;
    }

    /// Consumes a message of `len` bytes at the start of `buf`, of which
    /// only some may have come: the rest is skipped when it comes.
    fn consume_message(&mut self, len: usize) {
        let n = len.min(self.buf.len());
        self.consume(n);
        self.skip = (len - n) as u64;
    }

    /// Bytes of this direction were lost, so the message buffered cannot
    /// be finished, and where the next one starts is not known.
    fn lose(&mut self) {
        self.buf.clear();
        self.skip = 0;
        self.http1 = Http1::default();
        self.http2.lose();
    }

    /// Drops what is buffered if it outgrew [`MAX_BUFFER`]: a message
    /// whose end could not be found.
    fn limit(&mut self) {
        if self.buf.len() > MAX_BUFFER {
            self.lose();
        }
    }
}

/// One TCP connection, both ways. Direction 0 is from the endpoint whose
/// address and port sort first.
pub(crate) struct Conversation {
    ports: (u16, u16),
    proto: Proto,
    dirs: [Dir; 2],
    /// The methods of HTTP/1.1 requests not yet answered, oldest first,
    /// since a response to HEAD or CONNECT is framed differently.
    methods: Methods,
}

/// HTTP/1.1 request methods waiting for their responses.
#[derive(Default)]
pub(crate) struct Methods(VecDeque<String>);

impl Methods {
    fn push(&mut self, m: &str) {
        if self.0.len() >= 64 {
            self.0.pop_front();
        }
        self.0.push_back(m.to_owned());
    }
}

fn looks_like_http1(b: &[u8]) -> bool {
    let methods: [&[u8]; 9] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    b.starts_with(b"HTTP/1.") || methods.iter().any(|m| b.starts_with(m))
}

impl Conversation {
    pub(crate) fn new(port_a: u16, port_b: u16) -> Conversation {
        Conversation {
            ports: (port_a, port_b),
            proto: Proto::Unknown,
            dirs: [Dir::default(), Dir::default()],
            methods: Methods::default(),
        }
    }

    /// Whether direction `dir` holds bytes of a message not yet complete.
    pub(crate) fn waiting(&self, dir: bool) -> bool {
        let d = &self.dirs[dir as usize];
        (!d.buf.is_empty() || d.skip > 0) && !matches!(self.proto, Proto::Opaque | Proto::Unknown)
    }

    /// Bytes of direction `dir` were lost: what was buffered cannot be
    /// finished, and HTTP/2's header tables are no longer known.
    pub(crate) fn lost(&mut self, dir: bool) {
        let i = dir as usize;
        self.dirs[i].lose();
        if let Proto::Tls(tls) = &mut self.proto {
            tls.inner[i].lose();
            tls.hs_plain[i].clear();
            tls.hs_sealed[i].clear();
        }
    }

    pub(crate) fn data(&mut self, dir: bool, bytes: &[u8], place: Place, d: &mut Decoded, keys: &[KeyLine]) {
        let i = dir as usize;
        self.dirs[i].push(bytes, &place);
        if matches!(self.proto, Proto::Unknown) {
            let b = &self.dirs[i].buf;
            self.proto = if self.ports.0 == 53 || self.ports.1 == 53 {
                Proto::Dns
            } else if self.ports.0 == MODBUS_PORT || self.ports.1 == MODBUS_PORT {
                Proto::Modbus
            } else if b.len() >= 2 && b[0] == 0x16 && b[1] == 0x03 {
                Proto::Tls(Box::default())
            } else if b.starts_with(HTTP2_PREFACE) || (b.len() < HTTP2_PREFACE.len() && HTTP2_PREFACE.starts_with(b)) {
                if b.len() < HTTP2_PREFACE.len() {
                    return;
                }
                Proto::Http2
            } else if looks_like_http1(b) {
                Proto::Http1
            } else if b.len() < 8 {
                return;
            } else {
                Proto::Opaque
            };
        }
        match &mut self.proto {
            Proto::Dns => dns_stream(&mut self.dirs[i], place, d),
            Proto::Http1 => http1(&mut self.dirs[i], &mut self.methods, place, d),
            Proto::Http2 => http2(&mut self.dirs[i], place, d),
            Proto::Modbus => {
                // Direction 0 is from the endpoint on `ports.0`.
                let to = if i == 0 { self.ports.1 } else { self.ports.0 };
                if !modbus_stream(&mut self.dirs[i], to == MODBUS_PORT, place, d) {
                    self.proto = Proto::Opaque;
                }
            }
            Proto::Tls(tls) => tls.data(i, &mut self.dirs[i], place, d, keys),
            Proto::Opaque | Proto::Unknown => {
                let n = self.dirs[i].buf.len();
                self.dirs[i].consume(n);
            }
        }
        self.dirs[i].limit();
    }
}

/// DNS over TCP: each message after its two-byte length.
fn dns_stream(dir: &mut Dir, place: Place, d: &mut Decoded) {
    while dir.buf.len() >= 2 {
        let len = usize::from(be16(&dir.buf, 0));
        if 2 + len > MAX_BUFFER && dir.buf.len() < 2 + len {
            let (buf, base) = place.locate(d, dir.start, &dir.buf[..2], "DNS message length");
            let mut l = Layer::new("Domain Name System", buf, (base, base + 2));
            l.field("Length", len.to_string(), (base, base + 2));
            l.summary = format!("a {len}-byte message, too long to decode here");
            d.push(l);
            d.proto = "DNS".into();
            d.info = format!("DNS message of {len} bytes, not decoded");
            dir.consume_message(2 + len);
            continue;
        }
        if dir.buf.len() < 2 + len {
            break;
        }
        let msg = dir.buf[2..2 + len].to_vec();
        dns(&msg, place, dir.start + 2, d);
        dir.consume(2 + len);
    }
}

// ---------------------------------------------------------------------------
// Modbus/TCP

const MODBUS_PORT: u16 = crate::stdlib::modbus::PORT;

/// Modbus/TCP: frames after their 7-byte header. `request` says whether
/// this direction goes to the server. Returns false if the stream is not
/// Modbus, so the conversation stops decoding it.
fn modbus_stream(dir: &mut Dir, request: bool, place: Place, d: &mut Decoded) -> bool {
    use crate::stdlib::modbus::{Frame, Request, Response};
    loop {
        let (frame, used) = match Frame::parse(&dir.buf) {
            Ok(Some(f)) => f,
            Ok(None) => return true,
            Err(_) => return false,
        };
        let (buf, base) = place.locate(d, dir.start, &dir.buf[..used], "Modbus/TCP frame");
        let mut l = Layer::new("Modbus/TCP", buf, (base, base + used));
        l.field("Transaction identifier", frame.transaction.to_string(), (base, base + 2));
        l.field("Protocol identifier", "0".to_owned(), (base + 2, base + 4));
        l.field("Length", (used - 6).to_string(), (base + 4, base + 6));
        l.field("Unit identifier", frame.unit.to_string(), (base + 6, base + 7));
        let function = frame.function().unwrap_or(0);
        l.field("Function code", format!("{} ({})", function & 0x7f, modbus_function(function & 0x7f)), (base + 7, base + 8));
        let detail = if request {
            match Request::parse(&frame.pdu) {
                Ok(Request::ReadCoils { address, quantity })
                | Ok(Request::ReadDiscreteInputs { address, quantity })
                | Ok(Request::ReadHoldingRegisters { address, quantity })
                | Ok(Request::ReadInputRegisters { address, quantity }) => format!("address {address}, quantity {quantity}"),
                Ok(Request::WriteSingleCoil { address, value }) => format!("address {address}, {}", if value { "on" } else { "off" }),
                Ok(Request::WriteSingleRegister { address, value }) => format!("address {address}, value {value}"),
                Ok(Request::WriteMultipleCoils { address, values }) => format!("address {address}, {} coils", values.len()),
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
                Ok((_, Response::WriteSingleRegister { address, value })) => format!("address {address}, value {value}"),
                Ok((_, Response::WriteMultiple { address, quantity })) => format!("address {address}, quantity {quantity}"),
                Ok((_, Response::Exception(e))) => format!("exception: {e}"),
                Ok((_, Response::Other(data))) => format!("{} bytes of data", data.len()),
                Err(_) => "malformed".to_owned(),
            }
        };
        let kind = if request { "Query" } else { "Response" };
        l.summary = format!("{kind}, transaction {}, unit {}: {detail}", frame.transaction, frame.unit);
        l.note(if request { "Request" } else { "Response" }, detail.clone());
        d.push(l);
        info(
            d,
            2,
            "Modbus/TCP",
            &format!("{kind}: Trans: {}; Unit: {}, Func: {}: {}", frame.transaction, frame.unit, function & 0x7f, modbus_function(function & 0x7f)),
        );
        dir.consume(used);
    }
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

// ---------------------------------------------------------------------------
// HTTP/1.1

#[derive(Default)]
enum Http1 {
    /// Waiting for a request or status line and headers.
    #[default]
    Head,
    /// In a body of known length: bytes left, and the start of it.
    Body { left: u64, seen: Vec<u8>, total: u64 },
    /// In a chunked body: bytes left of the current chunk (0 between
    /// chunks), and the start of it.
    Chunked { left: u64, seen: Vec<u8>, total: u64 },
    /// In a body that lasts until the connection closes.
    ToClose,
    /// After a CONNECT was accepted: bytes of another protocol.
    Tunnel,
}

fn http1(dir: &mut Dir, methods: &mut Methods, place: Place, d: &mut Decoded) {
    loop {
        match &mut dir.http1 {
            Http1::Head => {
                let Some(end) = dir.buf.windows(4).position(|w| w == b"\r\n\r\n") else { return };
                let head = dir.buf[..end + 4].to_vec();
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let (line, kind, body) = if head.starts_with(b"HTTP/") {
                    let mut r = httparse::Response::new(&mut headers);
                    if !matches!(r.parse(&head), Ok(httparse::Status::Complete(_))) {
                        dir.consume(end + 4);
                        continue;
                    }
                    let code = r.code.unwrap_or(0);
                    let line = format!("HTTP/1.{} {code} {}", r.version.unwrap_or(1), r.reason.unwrap_or(""));
                    // A 1xx response is followed by the real one, for the
                    // same request.
                    let method = if (100..200).contains(&code) { None } else { methods.0.pop_front() };
                    let body = match method.as_deref() {
                        // What follows a CONNECT's 2xx is a tunnel, not HTTP.
                        Some("CONNECT") if (200..300).contains(&code) => Http1::Tunnel,
                        Some("HEAD") => Http1::Head,
                        _ => body_kind(r.headers, (100..200).contains(&code) || code == 204 || code == 304, true),
                    };
                    (line, "response", body)
                } else {
                    let mut r = httparse::Request::new(&mut headers);
                    if !matches!(r.parse(&head), Ok(httparse::Status::Complete(_))) {
                        dir.consume(end + 4);
                        continue;
                    }
                    let line =
                        format!("{} {} HTTP/1.{}", r.method.unwrap_or("?"), r.path.unwrap_or("?"), r.version.unwrap_or(1));
                    methods.push(r.method.unwrap_or("?"));
                    let body = body_kind(r.headers, false, false);
                    (line, "request", body)
                };
                let (buf, base) = place.locate(d, dir.start, &head, "Reassembled HTTP head");
                let mut l = Layer::new("Hypertext Transfer Protocol", buf, (base, base + head.len()));
                l.summary = line.clone();
                // Each header line, with its bytes.
                let mut at = 0;
                for (n, text) in head[..end].split(|b| *b == b'\n').enumerate() {
                    let t = String::from_utf8_lossy(text).trim_end().to_owned();
                    let range = (base + at, base + at + text.len());
                    at += text.len() + 1;
                    if n == 0 {
                        l.field(if kind == "request" { "Request line" } else { "Status line" }, t, range);
                    } else if let Some((k, v)) = t.split_once(':') {
                        l.field(k.trim(), v.trim(), range);
                    }
                }
                d.push(l);
                info(d, 2, "HTTP", &line);
                dir.consume(end + 4);
                dir.http1 = body;
            }
            Http1::Body { left, seen, total } => {
                if dir.buf.is_empty() {
                    return;
                }
                let n = (*left).min(dir.buf.len() as u64) as usize;
                if seen.len() < 4096 {
                    seen.extend_from_slice(&dir.buf[..n.min(4096 - seen.len())]);
                }
                *left -= n as u64;
                let (done, total, seen) = (*left == 0, *total, std::mem::take(seen));
                dir.consume(n);
                if !done {
                    if let Http1::Body { seen: s, .. } = &mut dir.http1 {
                        *s = seen;
                    }
                    return;
                }
                body_layer(d, total, &seen);
                dir.http1 = Http1::Head;
            }
            Http1::Chunked { left, seen, total } => {
                if *left == 0 {
                    // A chunk size line, after the CRLF that ends the chunk before.
                    let skip = if dir.buf.starts_with(b"\r\n") { 2 } else { 0 };
                    let Some(end) = dir.buf[skip..].windows(2).position(|w| w == b"\r\n") else { return };
                    let line = String::from_utf8_lossy(&dir.buf[skip..skip + end]).to_string();
                    let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
                    if size == 0 {
                        // The last chunk, and the trailer's empty line.
                        let Some(rest) = dir.buf[skip + end + 2..].windows(2).position(|w| w == b"\r\n") else { return };
                        let (total, seen) = (*total, std::mem::take(seen));
                        dir.consume(skip + end + 2 + rest + 2);
                        body_layer(d, total, &seen);
                        dir.http1 = Http1::Head;
                        continue;
                    }
                    *left = size;
                    *total += size;
                    dir.consume(skip + end + 2);
                    continue;
                }
                if dir.buf.is_empty() {
                    return;
                }
                let n = (*left).min(dir.buf.len() as u64) as usize;
                if seen.len() < 4096 {
                    seen.extend_from_slice(&dir.buf[..n.min(4096 - seen.len())]);
                }
                *left -= n as u64;
                dir.consume(n);
            }
            Http1::ToClose | Http1::Tunnel => {
                let n = dir.buf.len();
                dir.consume(n);
                return;
            }
        }
    }
}

fn body_kind(headers: &[httparse::Header<'_>], none: bool, response: bool) -> Http1 {
    if none {
        return Http1::Head;
    }
    let get = |name: &str| headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| String::from_utf8_lossy(h.value).to_string());
    if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        return Http1::Chunked { left: 0, seen: Vec::new(), total: 0 };
    }
    match get("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(0) => Http1::Head,
        Some(n) => Http1::Body { left: n, seen: Vec::new(), total: n },
        None if response => Http1::ToClose,
        None => Http1::Head,
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

// ---------------------------------------------------------------------------
// HTTP/2

#[derive(Default)]
struct Http2 {
    /// The connection preface has been read (the client's direction).
    started: bool,
    hpack: hpack::Decoder,
    /// A header block that goes on in CONTINUATION frames.
    block: Option<Pending>,
    /// Bytes of this direction were lost, so where frames start is not
    /// known: the rest of it is not decoded.
    lost: bool,
}

impl Http2 {
    fn lose(&mut self) {
        self.block = None;
        self.hpack.forget();
        self.lost = true;
    }
}

/// A header block that a HEADERS or PUSH_PROMISE frame began without
/// ending it.
struct Pending {
    stream: u32,
    /// The block so far, or `None` once it is too long to keep.
    bytes: Option<Vec<u8>>,
}

fn frame_type(t: u8) -> &'static str {
    match t {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

fn h2_error(code: u32) -> String {
    let name = match code {
        0 => "NO_ERROR",
        1 => "PROTOCOL_ERROR",
        2 => "INTERNAL_ERROR",
        3 => "FLOW_CONTROL_ERROR",
        5 => "STREAM_CLOSED",
        7 => "REFUSED_STREAM",
        8 => "CANCEL",
        11 => "ENHANCE_YOUR_CALM",
        _ => return format!("error {code}"),
    };
    name.to_owned()
}

fn http2(dir: &mut Dir, place: Place, d: &mut Decoded) {
    if dir.http2.lost {
        let n = dir.buf.len();
        dir.consume(n);
        return;
    }
    // The client's direction starts with the preface, which may come in
    // pieces: wait for all of it.
    if !dir.http2.started && dir.buf.len() < HTTP2_PREFACE.len() && HTTP2_PREFACE.starts_with(&dir.buf) {
        return;
    }
    if !dir.http2.started && dir.buf.starts_with(HTTP2_PREFACE) {
        let (buf, base) = place.locate(d, dir.start, HTTP2_PREFACE, "HTTP/2 preface");
        let mut l = Layer::new("HyperText Transfer Protocol 2", buf, (base, base + HTTP2_PREFACE.len()));
        l.summary = "Connection preface".into();
        d.push(l);
        info(d, 2, "HTTP/2", "Magic");
        dir.consume(HTTP2_PREFACE.len());
    }
    dir.http2.started = true;
    while dir.buf.len() >= 9 {
        let len = (usize::from(dir.buf[0]) << 16) | usize::from(be16(&dir.buf, 1));
        // A frame too long to hold is shown by its header, and the rest of
        // it is skipped as it comes.
        let whole = dir.buf.len() >= 9 + len;
        if !whole && 9 + len <= MAX_BUFFER {
            return;
        }
        let frame = dir.buf[..if whole { 9 + len } else { 9 }].to_vec();
        let (kind, flags, stream) = (frame[3], frame[4], be32(&frame, 5) & 0x7fff_ffff);
        let (buf, base) = place.locate(d, dir.start, &frame, "Reassembled HTTP/2 frame");
        let payload = whole.then(|| &frame[9..]);
        let mut l = Layer::new("HyperText Transfer Protocol 2", buf, (base, base + frame.len()));
        let mut fl = Vec::new();
        let names: &[(u8, &str)] = match kind {
            0 => &[(0x1, "END_STREAM"), (0x8, "PADDED")],
            1 => &[(0x1, "END_STREAM"), (0x4, "END_HEADERS"), (0x8, "PADDED"), (0x20, "PRIORITY")],
            4 | 6 => &[(0x1, "ACK")],
            5 => &[(0x4, "END_HEADERS"), (0x8, "PADDED")],
            9 => &[(0x4, "END_HEADERS")],
            _ => &[],
        };
        for (bit, name) in names {
            if flags & bit != 0 {
                fl.push(*name);
            }
        }
        l.field("Length", len.to_string(), (base, base + 3));
        l.field("Type", format!("{} ({kind})", frame_type(kind)), (base + 3, base + 4));
        l.field("Flags", if fl.is_empty() { format!("0x{flags:02x}") } else { fl.join(", ") }, (base + 4, base + 5));
        l.field("Stream", stream.to_string(), (base + 5, base + 9));
        let p0 = base + 9;
        let mut text = format!("{}[{stream}]", frame_type(kind));
        // A header block goes on only in CONTINUATION frames of its own
        // stream, with no other frame between them (RFC 9113, 6.10).
        if let Some(pending) = &dir.http2.block
            && !(kind == 9 && stream == pending.stream)
        {
            dir.http2.block = None;
            dir.http2.hpack.forget();
            l.note("Header block", "the one before was cut off by this frame, so later headers may not be known");
            d.tag("malformed");
        }
        if payload.is_none() {
            l.note("Payload", format!("{len} bytes, too long to keep"));
        }
        let body = payload.unwrap_or(&[]);
        match kind {
            0 => {
                let data = match unpad(body, flags) {
                    Some(data) => data,
                    None => {
                        l.note("Padding", "longer than the frame");
                        d.tag("malformed");
                        &[]
                    }
                };
                let size = if payload.is_some() { data.len() } else { len };
                l.field("Data", format!("{size} bytes"), (p0, p0 + body.len()));
                if let Some(t) = preview(data) {
                    l.note("Text", t);
                }
                let _ = write!(text, " {size} bytes");
                if flags & 1 != 0 {
                    text.push_str(", end");
                }
            }
            1 | 5 | 9 => {
                header_block(&mut dir.http2, kind, flags, stream, payload, &mut l, &mut text, d);
                if kind == 1 && flags & 1 != 0 {
                    text.push_str(", end");
                }
            }
            3 if body.len() >= 4 => {
                let e = h2_error(be32(body, 0));
                l.field("Error", e.clone(), (p0, p0 + 4));
                let _ = write!(text, " {e}");
                d.tag("reset");
            }
            4 => {
                for (n, s) in body.chunks(6).enumerate() {
                    if s.len() < 6 {
                        break;
                    }
                    let name = match be16(s, 0) {
                        1 => "HEADER_TABLE_SIZE",
                        2 => "ENABLE_PUSH",
                        3 => "MAX_CONCURRENT_STREAMS",
                        4 => "INITIAL_WINDOW_SIZE",
                        5 => "MAX_FRAME_SIZE",
                        6 => "MAX_HEADER_LIST_SIZE",
                        8 => "ENABLE_CONNECT_PROTOCOL",
                        _ => "setting",
                    };
                    l.field(name, be32(s, 2).to_string(), (p0 + n * 6, p0 + n * 6 + 6));
                }
                text = if flags & 1 != 0 { "SETTINGS ack".into() } else { "SETTINGS".into() };
            }
            6 => text = if flags & 1 != 0 { "PING ack".into() } else { "PING".into() },
            7 if body.len() >= 8 => {
                let e = h2_error(be32(body, 4));
                l.field("Last stream", (be32(body, 0) & 0x7fff_ffff).to_string(), (p0, p0 + 4));
                l.field("Error", e.clone(), (p0 + 4, p0 + 8));
                text = format!("GOAWAY {e}");
            }
            8 if body.len() >= 4 => {
                let inc = be32(body, 0) & 0x7fff_ffff;
                l.field("Window increment", inc.to_string(), (p0, p0 + 4));
                let _ = write!(text, " +{inc}");
            }
            _ => {}
        }
        l.summary = text.clone();
        d.push(l);
        info(d, 2, "HTTP/2", &text);
        dir.consume_message(9 + len);
    }
}

/// Follows the header block that a HEADERS, PUSH_PROMISE or CONTINUATION
/// frame carries, or part of. `payload` is the frame's, or `None` if it
/// was too long to keep.
///
/// Every block changes the direction's HPACK table, so a block that is
/// not decoded, whatever the reason, makes the decoder forget its table.
#[allow(clippy::too_many_arguments)]
fn header_block(
    h2: &mut Http2,
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Option<&[u8]>,
    l: &mut Layer,
    text: &mut String,
    d: &mut Decoded,
) {
    // The part of the payload that is the block.
    let fragment = payload.and_then(|p| match kind {
        1 => {
            let b = unpad(p, flags)?;
            if flags & 0x20 != 0 { b.get(5..) } else { Some(b) }
        }
        5 => {
            let b = unpad(p, flags)?;
            let id = be32(b.get(..4)?, 0) & 0x7fff_ffff;
            l.note("Promised stream", id.to_string());
            let _ = write!(text, " promised {id}");
            Some(&b[4..])
        }
        _ => Some(p),
    });
    if payload.is_some() && fragment.is_none() {
        l.note("Header block", "the frame is too short for its padding or fields");
        d.tag("malformed");
    }
    let mut pending = if kind == 9 {
        // The caller has dropped a block of another stream.
        let Some(pending) = h2.block.take() else {
            l.note("Header block", "a CONTINUATION with no header block to continue");
            d.tag("malformed");
            h2.hpack.forget();
            return;
        };
        pending
    } else {
        Pending { stream, bytes: Some(Vec::new()) }
    };
    match (&mut pending.bytes, fragment) {
        (Some(bytes), Some(f)) if bytes.len() + f.len() <= MAX_HEADER_BLOCK => bytes.extend_from_slice(f),
        (Some(_), f) => {
            // Too long to keep, or not readable: its headers are not
            // shown, and the table that later blocks rely on is unsure.
            if f.is_some() {
                l.note("Header block", "longer than the 64 KiB kept");
            }
            pending.bytes = None;
            h2.hpack.forget();
        }
        (None, _) => {}
    }
    let Some(bytes) = &pending.bytes else {
        l.note("Header block", "not decoded, so later headers may not be known");
        if flags & 0x4 == 0 {
            h2.block = Some(pending);
        }
        return;
    };
    if flags & 0x4 == 0 {
        l.note("Header block", "continues in the next frame");
        h2.block = Some(pending);
        return;
    }
    let Some(block) = h2.hpack.decode(bytes, d.room()) else {
        l.note("Header block", "could not be decoded: it is malformed");
        d.tag("malformed");
        return;
    };
    let get = |n: &str| block.headers.iter().find(|h| h.name.as_deref() == Some(n)).and_then(|h| h.value.clone());
    if let Some(status) = get(":status") {
        let _ = write!(text, ": {status}");
    } else if let (Some(m), Some(p)) = (get(":method"), get(":path")) {
        let _ = write!(text, ": {m} {p}");
        if let Some(a) = get(":authority") {
            let _ = write!(text, " ({a})");
        }
    }
    const UNKNOWN: &str = "not known: it names a table entry that a header block not decoded may have changed";
    for h in block.headers {
        match (h.name, h.value) {
            (Some(name), Some(value)) => l.note(&name, value),
            (None, Some(value)) => l.note("Header", format!("{value} (its name is {UNKNOWN})")),
            _ => l.note("Header", UNKNOWN),
        }
    }
    if block.more > 0 {
        l.note("Header block", format!("{} more headers, not shown", block.more));
    }
}

/// A padded frame's payload without its padding. `None` if the padding
/// does not fit in the frame, which is a protocol error (RFC 9113, 6.1).
fn unpad(payload: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & 0x8 == 0 {
        return Some(payload);
    }
    let (&pad, rest) = payload.split_first()?;
    rest.len().checked_sub(usize::from(pad)).map(|end| &rest[..end])
}

// ---------------------------------------------------------------------------
// TLS

/// One TLS connection: what its hellos said, and its keys.
#[derive(Default)]
struct Tls {
    client_random: Option<Vec<u8>>,
    /// Which direction is the client's.
    client: Option<usize>,
    sni: Option<String>,
    cipher: Option<u16>,
    tls13: bool,
    alpn: Option<String>,
    /// Each direction's decryption, once the keys are known.
    keys: [Option<DirKeys>; 2],
    /// The decrypted stream of each direction, and its protocol.
    inner: [Dir; 2],
    inner_proto: Option<bool>,
    inner_methods: Methods,
    /// Handshake messages cut across records, plain and decrypted, until
    /// they are whole.
    hs_plain: [Vec<u8>; 2],
    hs_sealed: [Vec<u8>; 2],
    /// A KeyUpdate came in this direction: its next records use new keys.
    key_update: [bool; 2],
}

/// The longest handshake message put together from several records.
const MAX_HANDSHAKE: usize = 64 << 10;

/// The whole handshake messages at the start of `b`: how many bytes they
/// take.
fn whole_messages(b: &[u8]) -> usize {
    let mut at = 0;
    while at + 4 <= b.len() {
        let len = (usize::from(b[at + 1]) << 16) | usize::from(be16(b, at + 2));
        if at + 4 + len > b.len() {
            break;
        }
        at += 4 + len;
    }
    at
}

/// An AEAD key and its IV.
type Key = (ring::aead::LessSafeKey, [u8; 12]);

/// The keys of one direction. It holds two keys at most, whatever the
/// peer sends: the handshake key until the application key takes over,
/// and the application key, which each KeyUpdate replaces.
struct DirKeys {
    /// The handshake key, until a record opens with the application key.
    handshake: Option<Key>,
    app: Key,
    /// The sequence number of the next record, under the key in use.
    seq: u64,
    cipher: u16,
    /// The secret `app` was made from, from which a KeyUpdate derives the
    /// next.
    secret: Vec<u8>,
}

impl DirKeys {
    /// Moves to the key that follows a KeyUpdate (RFC 8446, 4.6.3 and
    /// 7.2). Every later record of this direction uses it, from sequence
    /// number 0, and the old key opens nothing more.
    fn update(&mut self) {
        let (hash, len) = if self.cipher == 0x1302 { (ring::hkdf::HKDF_SHA384, 48) } else { (ring::hkdf::HKDF_SHA256, 32) };
        let prk = ring::hkdf::Prk::new_less_safe(hash, &self.secret);
        if let Some(next) = expand_label(&prk, "traffic upd", len)
            && let Some(key) = traffic_key(self.cipher, &next)
        {
            self.app = key;
            self.secret = next;
            self.seq = 0;
        }
    }
}

fn cipher_name(c: u16) -> String {
    match c {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        c => format!("0x{c:04x}"),
    }
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        13 => "Certificate Request",
        15 => "Certificate Verify",
        20 => "Finished",
        24 => "Key Update",
        _ => "Handshake",
    }
}

/// HKDF-Expand-Label from TLS 1.3, with an empty context.
fn expand_label(prk: &ring::hkdf::Prk, label: &str, len: usize) -> Option<Vec<u8>> {
    struct Len(usize);
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let full = format!("tls13 {label}");
    let info = [&(len as u16).to_be_bytes()[..], &[full.len() as u8], full.as_bytes(), &[0u8]];
    let okm = prk.expand(&info, Len(len)).ok()?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

/// The key and IV for `secret` with TLS 1.3 cipher suite `cipher`.
fn traffic_key(cipher: u16, secret: &[u8]) -> Option<(ring::aead::LessSafeKey, [u8; 12])> {
    use ring::{aead, hkdf};
    let (alg, hash, key_len): (&aead::Algorithm, hkdf::Algorithm, usize) = match cipher {
        0x1301 => (&aead::AES_128_GCM, hkdf::HKDF_SHA256, 16),
        0x1302 => (&aead::AES_256_GCM, hkdf::HKDF_SHA384, 32),
        0x1303 => (&aead::CHACHA20_POLY1305, hkdf::HKDF_SHA256, 32),
        _ => return None,
    };
    let prk = hkdf::Prk::new_less_safe(hash, secret);
    let key = expand_label(&prk, "key", key_len)?;
    let iv: [u8; 12] = expand_label(&prk, "iv", 12)?.try_into().ok()?;
    Some((aead::LessSafeKey::new(aead::UnboundKey::new(alg, &key).ok()?), iv))
}

/// Decrypts one TLS 1.3 record, its 5-byte header and its body, with
/// `key` at sequence number `seq`: the inner content type and the
/// plaintext.
fn open_with(key: &Key, seq: u64, header: &[u8], body: &[u8]) -> Option<(u8, Vec<u8>)> {
    use ring::aead::{Aad, Nonce};
    let (key, iv) = key;
    let mut nonce = *iv;
    for (n, b) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *n ^= b;
    }
    let mut buf = body.to_vec();
    let plain = key.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(header), &mut buf).ok()?;
    let mut plain = plain.to_vec();
    while plain.last() == Some(&0) {
        plain.pop();
    }
    let kind = plain.pop()?;
    Some((kind, plain))
}

impl DirKeys {
    /// Decrypts one TLS 1.3 record. During the handshake it tries the
    /// handshake key, then the application key from sequence number 0,
    /// since the one gives way to the other after the Finished message.
    /// The flag says whether the application key opened it.
    fn open(&mut self, header: &[u8], body: &[u8]) -> Option<(u8, Vec<u8>, bool)> {
        if let Some(hs) = &self.handshake {
            if let Some((kind, plain)) = open_with(hs, self.seq, header, body) {
                self.seq += 1;
                return Some((kind, plain, false));
            }
            let (kind, plain) = open_with(&self.app, 0, header, body)?;
            self.handshake = None;
            self.seq = 1;
            return Some((kind, plain, true));
        }
        let (kind, plain) = open_with(&self.app, self.seq, header, body)?;
        self.seq += 1;
        Some((kind, plain, true))
    }
}

impl Tls {
    /// Sets up decryption for both directions, once the hellos and the
    /// keys are known.
    fn find_keys(&mut self, keys: &[KeyLine]) {
        let (Some(random), Some(cipher), Some(client)) = (&self.client_random, self.cipher, self.client) else { return };
        if !self.tls13 || self.keys.iter().all(Option::is_some) {
            return;
        }
        let secret = |label: &str| keys.iter().find(|k| k.label == label && &k.client_random == random).map(|k| k.secret.clone());
        for (dir, side) in [(client, "CLIENT"), (1 - client, "SERVER")] {
            if self.keys[dir].is_some() {
                continue;
            }
            let hs = secret(&format!("{side}_HANDSHAKE_TRAFFIC_SECRET")).and_then(|s| traffic_key(cipher, &s));
            let app_secret = secret(&format!("{side}_TRAFFIC_SECRET_0"));
            let app = app_secret.as_ref().and_then(|s| traffic_key(cipher, s));
            if let (Some(hs), Some(app), Some(app_secret)) = (hs, app, app_secret) {
                self.keys[dir] = Some(DirKeys { handshake: Some(hs), app, seq: 0, cipher, secret: app_secret });
            }
        }
    }

    fn data(&mut self, i: usize, dir: &mut Dir, place: Place, d: &mut Decoded, keys: &[KeyLine]) {
        while dir.buf.len() >= 5 {
            let len = usize::from(be16(&dir.buf, 3));
            if 5 + len > MAX_BUFFER && dir.buf.len() < 5 + len {
                // Far longer than TLS allows (RFC 8446, 5.2): shown by its
                // header, and skipped.
                let header = dir.buf[..5].to_vec();
                let (buf, base) = place.locate(d, dir.start, &header, "TLS record header");
                let mut l = Layer::new("Transport Layer Security", buf, (base, base + 5));
                l.field("Content type", header[0].to_string(), (base, base + 1));
                l.field("Length", len.to_string(), (base + 3, base + 5));
                l.summary = format!("a {len}-byte record, longer than TLS allows");
                d.push(l);
                d.tag("malformed");
                info(d, 1, "TLS", "Record too long");
                dir.consume_message(5 + len);
                continue;
            }
            if dir.buf.len() < 5 + len {
                return;
            }
            let record = dir.buf[..5 + len].to_vec();
            let (buf, base) = place.locate(d, dir.start, &record, "Reassembled TLS record");
            dir.consume(5 + len);
            self.record(i, &record, buf, base, d, keys);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(&mut self, i: usize, record: &[u8], buf: usize, base: usize, d: &mut Decoded, keys: &[KeyLine]) {
        let kind = record[0];
        let body = &record[5..];
        let version = |tls: &Tls| if tls.tls13 { "TLSv1.3" } else if tls.cipher.is_some() { "TLSv1.2" } else { "TLS" };
        let mut l = Layer::new("Transport Layer Security", buf, (base, base + record.len()));
        let kind_name = match kind {
            20 => "Change Cipher Spec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application Data",
            _ => "unknown",
        };
        l.field("Content type", format!("{kind_name} ({kind})"), (base, base + 1));
        l.field("Version", format!("0x{:04x}", be16(record, 1)), (base + 1, base + 3));
        l.field("Length", body.len().to_string(), (base + 3, base + 5));
        match kind {
            22 => {
                let names = self.handshake_records(i, body, buf, base + 5, d, &mut l, false);
                let version = version(self);
                l.summary = format!("{version} Handshake: {}", names.join(", "));
                d.push(l);
                info(d, 1, version, &names.join(", "));
            }
            20 => {
                let version = version(self);
                l.summary = "Change Cipher Spec".into();
                d.push(l);
                info(d, 1, version, "Change Cipher Spec");
            }
            21 if body.len() >= 2 => {
                let version = version(self);
                l.summary = format!("Alert: level {}, description {}", body[0], body[1]);
                d.push(l);
                info(d, 1, version, &format!("Alert ({})", body[1]));
            }
            23 => {
                let version = version(self);
                self.find_keys(keys);
                let opened = self.keys[i].as_mut().and_then(|k| k.open(&record[..5], body));
                match opened {
                    None => {
                        l.summary = format!("{version} Application Data, encrypted");
                        let why = if !self.tls13 {
                            "only TLS 1.3 is decrypted; download the capture to decrypt it in Wireshark"
                        } else if self.keys[i].is_none() {
                            "no keys: the handshake happened before anyone observed the world"
                        } else {
                            "could not be decrypted"
                        };
                        l.note("Decryption", why);
                        d.push(l);
                        info(d, 1, version, "Application Data");
                    }
                    Some((inner, plain, app)) => {
                        d.tag("decrypted");
                        let pb = d.buffer("Decrypted TLS", plain.clone());
                        l.note("Decryption", format!("decrypted {} bytes", plain.len()));
                        match inner {
                            22 => {
                                let mut hl = Layer::new("TLS handshake (decrypted)", pb, (0, plain.len()));
                                let names = self.handshake_records(i, &plain, pb, 0, d, &mut hl, true);
                                // A KeyUpdate counts only under the application key.
                                if std::mem::take(&mut self.key_update[i])
                                    && app
                                    && let Some(k) = self.keys[i].as_mut()
                                {
                                    k.update();
                                }
                                l.summary = format!("{version} Application Data: {}", names.join(", "));
                                hl.summary = names.join(", ");
                                d.push(l);
                                d.push(hl);
                                info(d, 1, version, &names.join(", "));
                            }
                            21 => {
                                l.summary = format!("{version} Alert (decrypted)");
                                d.push(l);
                                info(d, 1, version, "Encrypted Alert");
                            }
                            _ => {
                                l.summary = format!("{version} Application Data, {} bytes decrypted", plain.len());
                                d.push(l);
                                let inner_place = Place { stream_start: self.inner[i].start + self.inner[i].buf.len() as u64, buf: pb, offset: Some(0), len: plain.len() };
                                self.inner_data(i, &plain, inner_place, d);
                            }
                        }
                    }
                }
            }
            _ => {
                l.summary = format!("Record type {kind}");
                d.push(l);
            }
        }
    }

    /// Feeds decrypted application data to HTTP/1.1 or HTTP/2.
    fn inner_data(&mut self, i: usize, plain: &[u8], place: Place, d: &mut Decoded) {
        let dir = &mut self.inner[i];
        dir.push(plain, &place);
        if self.inner_proto.is_none() {
            self.inner_proto = match self.alpn.as_deref() {
                Some("h2") => Some(true),
                Some(_) => Some(false),
                None if dir.buf.starts_with(HTTP2_PREFACE) => Some(true),
                None if looks_like_http1(&dir.buf) => Some(false),
                None => None,
            };
        }
        match self.inner_proto {
            Some(true) => http2(dir, place, d),
            Some(false) => http1(dir, &mut self.inner_methods, place, d),
            None => {
                let n = dir.buf.len();
                dir.consume(n);
            }
        }
        dir.limit();
    }

    /// Decodes the handshake messages that `body`, at `base` in buffer
    /// `buf`, completes, keeping a message cut across records until the
    /// rest comes. Returns their names.
    #[allow(clippy::too_many_arguments)]
    fn handshake_records(
        &mut self,
        i: usize,
        body: &[u8],
        buf: usize,
        base: usize,
        d: &mut Decoded,
        l: &mut Layer,
        decrypted: bool,
    ) -> Vec<String> {
        let held = if decrypted { &mut self.hs_sealed[i] } else { &mut self.hs_plain[i] };
        if held.is_empty() {
            let whole = whole_messages(body);
            if whole == body.len() {
                return self.handshake(i, body, base, l, decrypted);
            }
            if body.len() - whole <= MAX_HANDSHAKE {
                held.extend_from_slice(&body[whole..]);
            }
            let mut names = self.handshake(i, &body[..whole], base, l, decrypted);
            names.push("part of a handshake message".into());
            return names;
        }
        held.extend_from_slice(body);
        let joined = std::mem::take(held);
        let whole = whole_messages(&joined);
        if joined.len() - whole <= MAX_HANDSHAKE {
            let held = if decrypted { &mut self.hs_sealed[i] } else { &mut self.hs_plain[i] };
            held.extend_from_slice(&joined[whole..]);
        }
        if whole == 0 {
            return vec!["part of a handshake message".into()];
        }
        let _ = buf;
        let rb = d.buffer("Reassembled TLS handshake", joined[..whole].to_vec());
        let mut rl = Layer::new("TLS handshake (reassembled)", rb, (0, whole));
        let names = self.handshake(i, &joined[..whole], 0, &mut rl, decrypted);
        rl.summary = names.join(", ");
        d.push(rl);
        names
    }

    /// Decodes handshake messages, returning their names.
    fn handshake(&mut self, i: usize, b: &[u8], base: usize, l: &mut Layer, decrypted: bool) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = 0;
        while at + 4 <= b.len() {
            let t = b[at];
            let len = (usize::from(b[at + 1]) << 16) | usize::from(be16(b, at + 2));
            let end = (at + 4 + len).min(b.len());
            let m = &b[at + 4..end];
            names.push(handshake_name(t).to_owned());
            l.field("Handshake", handshake_name(t), (base + at, base + end));
            match t {
                24 if decrypted => self.key_update[i] = true,
                1 if m.len() >= 34 && !decrypted => {
                    self.client_random = Some(m[2..34].to_vec());
                    self.client = Some(i);
                    l.field("Random", super::packets::hex(&m[2..34]), (base + at + 6, base + at + 38));
                    for (ext, data) in extensions(m, true) {
                        match ext {
                            0 if data.len() > 5 => {
                                let name = String::from_utf8_lossy(&data[5..]).to_string();
                                l.note("Server name (SNI)", name.clone());
                                self.sni = Some(name);
                            }
                            16 => l.note("ALPN offered", alpn_list(data).join(", ")),
                            _ => {}
                        }
                    }
                    if let Some(sni) = &self.sni {
                        let last = names.last_mut().unwrap();
                        *last = format!("Client Hello ({sni})");
                    }
                }
                2 if m.len() >= 38 && !decrypted => {
                    let sid = usize::from(m[34]);
                    if m.len() >= 35 + sid + 2 {
                        let c = be16(m, 35 + sid);
                        self.cipher = Some(c);
                        l.note("Cipher suite", cipher_name(c));
                    }
                    for (ext, data) in extensions(m, false) {
                        if ext == 43 && data.len() == 2 && be16(data, 0) == 0x0304 {
                            self.tls13 = true;
                            l.note("Version", "TLS 1.3");
                        }
                    }
                }
                8 => {
                    for (ext, data) in extensions_at(m, 0) {
                        if ext == 16 {
                            let chosen = alpn_list(data);
                            if let Some(p) = chosen.first() {
                                l.note("ALPN chosen", p.clone());
                                self.alpn = Some(p.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
            at = end;
        }
        names
    }
}

fn alpn_list(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 2;
    while i < data.len() {
        let n = usize::from(data[i]);
        if i + 1 + n > data.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&data[i + 1..i + 1 + n]).to_string());
        i += 1 + n;
    }
    out
}

/// The extensions of a Client Hello or Server Hello body.
fn extensions(m: &[u8], client: bool) -> Vec<(u16, &[u8])> {
    // version (2), random (32), session id.
    let mut i = 34;
    let Some(&sid) = m.get(i) else { return Vec::new() };
    i += 1 + usize::from(sid);
    if client {
        if i + 2 > m.len() {
            return Vec::new();
        }
        i += 2 + usize::from(be16(m, i));
        let Some(&comp) = m.get(i) else { return Vec::new() };
        i += 1 + usize::from(comp);
    } else {
        i += 3;
    }
    extensions_at(m, i)
}

/// The extension list starting at `i` with its 2-byte length.
fn extensions_at(m: &[u8], mut i: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if i + 2 > m.len() {
        return out;
    }
    let end = (i + 2 + usize::from(be16(m, i))).min(m.len());
    i += 2;
    while i + 4 <= end {
        let (t, n) = (be16(m, i), usize::from(be16(m, i + 2)));
        if i + 4 + n > end {
            break;
        }
        out.push((t, &m[i + 4..i + 4 + n]));
        i += 4 + n;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Feeds one direction's next bytes, `chunk` bytes at a time, as
    /// separate packets. Returns what the last packet decoded to.
    struct Feeder {
        c: Conversation,
        at: [u64; 2],
    }

    impl Feeder {
        fn new(ports: (u16, u16)) -> Feeder {
            Feeder { c: Conversation::new(ports.0, ports.1), at: [0, 0] }
        }

        fn send(&mut self, dir: bool, bytes: &[u8], chunk: usize) -> Decoded {
            let mut d = Decoded::default();
            for piece in bytes.chunks(chunk) {
                d = Decoded::default();
                let place = Place { stream_start: self.at[dir as usize], buf: 0, offset: Some(0), len: piece.len() };
                self.c.data(dir, piece, place, &mut d, &[]);
                self.at[dir as usize] += piece.len() as u64;
            }
            d
        }

        /// An HTTP/2 connection whose client has sent its preface.
        fn h2() -> Feeder {
            let mut f = Feeder::new((40000, 80));
            f.send(false, HTTP2_PREFACE, 1500);
            f
        }
    }

    /// Every field with no bytes of its own, as (name, value).
    fn notes(d: &Decoded) -> Vec<(String, String)> {
        let fields = d.layers.iter().flat_map(|l| &l.fields);
        fields.filter(|f| f.range.is_none()).map(|f| (f.name.clone(), f.value.clone())).collect()
    }

    fn has(d: &Decoded, name: &str, value: &str) -> bool {
        notes(d).iter().any(|(n, v)| n == name && v == value)
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    const X_OLD: &str = "4001 7803 6f6c 64";
    const X_NEW: &str = "4001 7803 6e65 77";

    /// A header block whose padding does not fit is not decoded, and the
    /// table it may have changed is forgotten.
    #[test]
    fn bad_padding_is_not_decoded() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        // PADDED, a pad length of 64, and seven bytes that read as x: new.
        let d = f.send(true, &frame(1, 0xc, 3, &hex("40 4001 7803 6e65 77")[1..]), 1500);
        assert!(d.tags.contains(&"malformed"));
        assert!(!has(&d, "x", "new"));
        let d = f.send(true, &frame(1, 0x4, 5, &[0x88, 0xbe]), 1500);
        assert!(!has(&d, "x", "new") && !has(&d, "x", "old"), "{:?}", notes(&d));
    }

    /// A PUSH_PROMISE's header block changes the table that later blocks
    /// rely on, so it is decoded too.
    #[test]
    fn push_promise_headers_update_the_table() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        let mut promise = vec![0, 0, 0, 2];
        promise.extend(hex(X_NEW));
        let d = f.send(true, &frame(5, 0x4, 1, &promise), 1500);
        assert!(has(&d, "Promised stream", "2"));
        assert!(has(&d, "x", "new"));
        let d = f.send(true, &frame(1, 0x4, 2, &[0x88, 0xbe]), 1500);
        assert!(has(&d, "x", "new"), "{:?}", notes(&d));
        assert!(d.info.starts_with("HEADERS[2]: 200"), "{}", d.info);
    }

    /// A header block goes on only in CONTINUATION frames of its own
    /// stream. One that is cut off is not joined to another frame's
    /// bytes, and the table it may have changed is forgotten.
    #[test]
    fn a_continuation_of_another_stream_is_not_joined() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        // An unfinished block on stream 1, "completed" on stream 3.
        f.send(true, &frame(1, 0, 3, &hex("4001 7903 6f")), 1500);
        let d = f.send(true, &frame(9, 0x4, 5, &hex("6c64")), 1500);
        assert!(d.tags.contains(&"malformed"));
        assert!(!notes(&d).iter().any(|(n, _)| n == "y"), "{:?}", notes(&d));
        // Entry 62 was x: old, but the cut-off block may have added one.
        let d = f.send(true, &frame(1, 0x4, 7, &[0x88, 0xbe]), 1500);
        assert!(!has(&d, "x", "old"), "{:?}", notes(&d));
        assert!(notes(&d).iter().any(|(n, v)| n == "Header" && v.starts_with("not known")), "{:?}", notes(&d));
        // A HEADERS frame does not continue an unfinished block either.
        f.send(true, &frame(1, 0, 9, &hex("82")), 1500);
        let d = f.send(true, &frame(1, 0x4, 9, &hex("82")), 1500);
        assert!(d.tags.contains(&"malformed"));
    }

    /// After lost bytes, where HTTP/2 frames start is not known, so the
    /// direction is not decoded further.
    #[test]
    fn lost_bytes_end_http2_decoding() {
        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        f.c.lost(true);
        let d = f.send(true, &frame(1, 0x4, 3, &[0x88, 0xbe]), 1500);
        assert!(d.layers.is_empty());
        assert!(f.c.dirs[1].http2.lost);
    }

    /// A DATA frame longer than the buffer is shown by its header and
    /// skipped, and the frames after it are still found.
    #[test]
    fn a_long_http2_frame_is_skipped_not_lost() {
        let mut f = Feeder::h2();
        let mut bytes = frame(0, 0, 1, &vec![b'a'; 40_000]);
        bytes.extend(frame(1, 0x5, 1, &[0x88]));
        let mut seen = Vec::new();
        for piece in bytes.chunks(1400) {
            let d = f.send(true, piece, 1400);
            seen.push(d.info);
        }
        assert!(seen.iter().any(|i| i == "DATA[1] 40000 bytes"), "{seen:?}");
        assert_eq!(seen.last().unwrap(), "HEADERS[1]: 200, end");
    }

    /// A DNS message over TCP longer than the buffer is skipped, and the
    /// next one is decoded.
    #[test]
    fn a_long_dns_message_is_skipped_not_lost() {
        let mut f = Feeder::new((40000, 53));
        let mut bytes = 39_959u16.to_be_bytes().to_vec();
        bytes.extend(vec![0; 39_959]);
        bytes.extend([0, 12, 0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut infos = Vec::new();
        for piece in bytes.chunks(1400) {
            infos.push(f.send(true, piece, 1400).info);
        }
        assert_eq!(infos[0], "DNS message of 39959 bytes, not decoded");
        assert!(infos.last().unwrap().starts_with("Standard query response 0x1234"), "{infos:?}");
    }

    #[test]
    fn modbus_requests_and_responses() {
        // Port 40000 sorts first, so direction 0 (false) is the client's.
        let mut f = Feeder::new((40000, 502));
        let query = [0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1];
        // Split across packets, it is decoded when the last byte comes.
        let d = f.send(false, &query, 5);
        assert_eq!(d.proto, "Modbus/TCP");
        assert_eq!(d.info, "Query: Trans: 7; Unit: 1, Func: 3: Read Holding Registers");
        assert!(has(&d, "Request", "address 2, quantity 1"));
        let d = f.send(true, &[0, 7, 0, 0, 0, 5, 1, 3, 2, 0x04, 0xd2], 1500);
        assert!(has(&d, "Response", "registers [1234]"));
        let d = f.send(true, &[0, 8, 0, 0, 0, 3, 1, 0x83, 2], 1500);
        assert!(has(&d, "Response", "exception: illegal data address"));
        // Bytes that are not Modbus stop the decoding.
        let d = f.send(false, &[0, 9, 0, 5, 0, 6, 1, 3, 0, 0, 0, 1], 1500);
        assert_ne!(d.proto, "Modbus/TCP");
        let d = f.send(false, &query, 1500);
        assert_ne!(d.proto, "Modbus/TCP");
    }

    /// Seals one TLS 1.3 record with the key from `secret`.
    fn seal(secret: &[u8], seq: u64, kind: u8, plain: &[u8]) -> Vec<u8> {
        use ring::aead::{Aad, Nonce};
        let (key, iv) = traffic_key(0x1301, secret).unwrap();
        let mut inner = plain.to_vec();
        inner.push(kind);
        let len = inner.len() + 16;
        let header = [23, 3, 3, (len >> 8) as u8, len as u8];
        let mut nonce = iv;
        for (n, b) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= b;
        }
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(header), &mut inner).unwrap();
        [&header[..], &inner].concat()
    }

    fn next_secret(secret: &[u8]) -> Vec<u8> {
        expand_label(&ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, secret), "traffic upd", 32).unwrap()
    }

    /// After a KeyUpdate, the next records use the new key from sequence
    /// number 0, and the old key opens nothing more. The decoder holds one
    /// application key, however many KeyUpdates come.
    #[test]
    fn a_key_update_replaces_the_key() {
        let (hs, app) = ([2u8; 32], [1u8; 32]);
        let keys = DirKeys {
            handshake: traffic_key(0x1301, &hs),
            app: traffic_key(0x1301, &app).unwrap(),
            seq: 0,
            cipher: 0x1301,
            secret: app.to_vec(),
        };
        let mut tls = Tls { tls13: true, cipher: Some(0x1301), keys: [Some(keys), None], ..Tls::default() };
        let mut at = 0u64;
        let mut feed = |tls: &mut Tls, record: &[u8]| {
            let mut d = Decoded::default();
            let mut dir = Dir::default();
            let place = Place { stream_start: at, buf: 0, offset: Some(0), len: record.len() };
            at += record.len() as u64;
            dir.push(record, &place);
            tls.data(0, &mut dir, place, &mut d, &[]);
            d.tags.contains(&"decrypted")
        };
        const KEY_UPDATE: [u8; 5] = [24, 0, 0, 1, 0];
        assert!(feed(&mut tls, &seal(&hs, 0, 22, &[20, 0, 0, 0])), "the handshake key opens");
        assert!(feed(&mut tls, &seal(&app, 0, 22, &KEY_UPDATE)), "then the application key");
        // The old key, at the next sequence number, opens nothing more.
        for seq in 1..1000 {
            assert!(!feed(&mut tls, &seal(&app, seq, 22, &KEY_UPDATE)));
        }
        let mut secret = next_secret(&app);
        for _ in 0..100 {
            assert!(feed(&mut tls, &seal(&secret, 0, 22, &KEY_UPDATE)));
            secret = next_secret(&secret);
        }
        assert!(feed(&mut tls, &seal(&secret, 0, 23, b"hello")));
        assert!(tls.keys[0].as_ref().unwrap().handshake.is_none());
    }
}
