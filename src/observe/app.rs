//! Application protocols: DNS, DHCP, HTTP/1.1, HTTP/2, Modbus/TCP, and TLS,
//! which is decrypted when the world's TLS stack gave its session keys.
//!
//! A [`Conversation`] is one TCP connection, both ways. It guesses the
//! protocol through the public registry, using ports or first bytes, then decodes each
//! direction's byte stream as it arrives. Each message it finds becomes a
//! [`Layer`] of the packet that completed it. When the whole message lies
//! in that packet, its fields point at the packet's own bytes; otherwise
//! the message gets a buffer of its own, as Wireshark's "Reassembled TCP".

use std::fmt::Write;

use super::decode::{Decoded, Layer, be16, be32};
use super::hpack;
use crate::watch::KeyLine;

use super::{Match, Observed, Place, Placement, Present, Protocol, Registry, Selection, Transport};
use super::protocols;
use super::protocols::{MAX_BUFFER, preview};

/// Sets the packet's protocol and info from a message at `level`: 1 for
/// TLS records, 2 for what they carry and for plain HTTP. A higher level
/// replaces what lower ones said; the same level adds to it.
pub(super) fn info(d: &mut Decoded, level: u8, proto: &str, text: &str) {
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

// ---------------------------------------------------------------------------
// TCP conversations

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
// Bytes a direction may hold while waiting for the end of a message. A
// longer message whose length its header gives is shown by that header,
// and the rest of it is skipped. One whose end cannot be found that way
// is dropped. TCP follows at most 512 directions (see `stream`). HTTP/1
// permits capacity + 65,535 bytes of read-ahead, for one IP packet. Its
// aggregate input storage is at most 96 MiB, including the codec buffer
// compaction space. Decoder state and TLS record/handshake buffers have
// separate bounds. User decoders declare their own capacities.
/// The longest HTTP/2 header block kept across CONTINUATION frames.
const MAX_HEADER_BLOCK: usize = 64 << 10;

/// One direction's bytes not decoded yet.
#[derive(Default)]
struct Dir {
    buf: Vec<u8>,
    /// The stream offset of `buf[0]`.
    start: u64,
    /// Bytes still to come of a message too long to hold, which are
    /// dropped as they arrive.
    skip: u64,
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
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
        self.start = self.start.saturating_add(n as u64);
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
    alpn: Option<String>,
    registry: Registry,
    protocol: Option<Box<dyn Protocol>>,
    prefix: [Vec<u8>; 2],
    prefix_start: [u64; 2],
    rejected: bool,
}

fn looks_like_http1(b: &[u8]) -> bool {
    let methods: [&[u8]; 9] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    b.starts_with(b"HTTP/1.") || methods.iter().any(|m| b.starts_with(m))
}

impl Conversation {
    #[cfg(test)]
    pub(crate) fn new(port_a: u16, port_b: u16) -> Self {
        Self::with_registry(port_a, port_b, Registry::default())
    }

    pub(crate) fn with_registry(port_a: u16, port_b: u16, registry: Registry) -> Self {
        Self { ports: (port_a, port_b), alpn: None, registry, protocol: None, prefix: [Vec::new(), Vec::new()], prefix_start: [0; 2], rejected: false }
    }

    pub(crate) fn waiting(&self, dir: bool) -> bool {
        !self.prefix[usize::from(dir)].is_empty()
            || self.protocol.as_ref().is_some_and(|p| p.waiting(dir))
    }

    pub(crate) fn lost(&mut self, dir: bool) {
        if let Some(protocol) = &mut self.protocol { protocol.lost(dir); }
        if let Some(prefix) = self.prefix.get_mut(usize::from(dir)) { prefix.clear(); }
    }

    pub(crate) fn data(&mut self, dir: bool, bytes: &[u8], place: Place, d: &mut Decoded, keys: &[KeyLine]) {
        if self.rejected { return; }
        if let Some(protocol) = &mut self.protocol {
            protocol.data(dir, bytes, place, d, keys);
            return;
        }
        let i = usize::from(dir);
        let Some(prefix) = self.prefix.get_mut(i) else { return };
        let old = prefix.len();
        if old == 0 { self.prefix_start[i] = place.stream_start; }
        prefix.extend_from_slice(bytes.get(..bytes.len().min(64usize.saturating_sub(old))).unwrap_or_default());
        match self.registry.open(Selection { transport: Transport::Tcp, ports: self.ports, first: prefix, alpn: self.alpn.as_deref() }) {
            Ok(mut protocol) => {
                prefix.truncate(old);
                // Selection applies to both directions. Flush every earlier
                // prefix now, including a peer that may never send again.
                for j in [1 - i, i] {
                    let held = &mut self.prefix[j];
                    if !held.is_empty() {
                        protocol.data(j != 0, held, Place {
                            stream_start: self.prefix_start[j], len: held.len(), ..Place::default()
                        }, d, keys);
                        held.clear();
                    }
                }
                protocol.data(dir, bytes, place, d, keys);
                self.protocol = Some(protocol);
            }
            Err(decision) => {
                if prefix.len() >= 64 || (decision == Match::No && prefix.len() >= 8) {
                    self.rejected = true;
                    self.prefix.iter_mut().for_each(Vec::clear);
                }
            }
        }
    }
}

fn register_http(registry: &mut Registry) {
    registry.register_with_buffer("http1", |s| {
        if s.transport == Transport::Tcp && looks_like_http1(s.first) { Match::Yes } else { Match::No }
    }, MAX_BUFFER + 1 + 65_535, |_| protocols::Http1::pair());
    registry.register_protocol("http2", |s| {
        if s.transport != Transport::Tcp { Match::No }
        else if s.first.starts_with(HTTP2_PREFACE) { Match::Yes }
        else if HTTP2_PREFACE.starts_with(s.first) { Match::More }
        else { Match::No }
    }, |_, _| Box::new(H2Session { dirs: [Dir::default(), Dir::default()] }));
}

pub(super) fn register(registry: &mut Registry) {
    register_http(registry);
    registry.register_protocol("tls", |s| {
        if s.transport == Transport::Tcp && s.first.starts_with(&[0x16, 0x03]) { Match::Yes } else { Match::No }
    }, |s, registry| Box::new(TlsSession::new(s.ports, registry.clone())));
    registry.register_protocol("modbus", |s| {
        if s.transport == Transport::Tcp && (s.ports.0 == MODBUS_PORT || s.ports.1 == MODBUS_PORT) { Match::Yes } else { Match::No }
    }, |s, _| Box::new(ModbusSession { dirs: [Some(Observed::new(protocols::Modbus::new(s.ports.1 == MODBUS_PORT))), Some(Observed::new(protocols::Modbus::new(s.ports.0 == MODBUS_PORT)))], stopped: false }));
    registry.register("dhcp", |s| {
        if s.transport == Transport::Udp && matches!(s.ports, (67, 68) | (68, 67)) { Match::Yes } else { Match::No }
    }, |_| [protocols::Dhcp::default(), protocols::Dhcp::default()]);
    registry.register_with_buffer("dns", |s| {
        if s.ports.0 == 53 || s.ports.1 == 53 { Match::Yes } else { Match::No }
    }, 65_538, |s| [protocols::Dns::new(s.transport == Transport::Tcp), protocols::Dns::new(s.transport == Transport::Tcp)]);
}

struct H2Session { dirs: [Dir; 2] }
impl Protocol for H2Session {
    fn data(&mut self, reverse: bool, bytes: &[u8], at: Place, d: &mut Decoded, _: &[KeyLine]) {
        let dir = &mut self.dirs[usize::from(reverse)];
        dir.push(bytes, &at);
        http2(dir, at, d);
        dir.limit();
    }
    fn waiting(&self, reverse: bool) -> bool {
        let dir = &self.dirs[usize::from(reverse)];
        !dir.buf.is_empty() || dir.skip > 0
    }
    fn lost(&mut self, reverse: bool) { self.dirs[usize::from(reverse)].lose(); }
}

struct ModbusSession {
    dirs: [Option<Observed<protocols::Modbus>>; 2],
    stopped: bool,
}
impl Protocol for ModbusSession {
    fn data(&mut self, reverse: bool, bytes: &[u8], at: Place, d: &mut Decoded, _: &[KeyLine]) {
        if self.stopped { return; }
        if let Some(dir) = &mut self.dirs[usize::from(reverse)] {
            dir.data(bytes, at, d);
            self.stopped = dir.failed().is_some();
        }
    }
    fn waiting(&self, reverse: bool) -> bool {
        !self.stopped && self.dirs[usize::from(reverse)].as_ref().is_some_and(Observed::waiting)
    }
    fn lost(&mut self, reverse: bool) {
        let slot = &mut self.dirs[usize::from(reverse)];
        *slot = slot.take().map(Observed::reset);
    }
}

// ---------------------------------------------------------------------------
// Modbus/TCP

const MODBUS_PORT: u16 = crate::stdlib::modbus::PORT;

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
    registry: Registry,
    ports: (u16, u16),
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
    inner: Option<Conversation>,
    inner_offsets: [u64; 2],
    /// Handshake messages cut across records, plain and decrypted, until
    /// they are whole.
    hs_plain: [Vec<u8>; 2],
    hs_sealed: [Vec<u8>; 2],
    /// A KeyUpdate came in this direction: its next records use new keys.
    key_update: [bool; 2],
}

struct TlsSession {
    tls: Tls,
    dirs: [Option<Observed<protocols::TlsRecords>>; 2],
}
impl TlsSession {
    fn new(ports: (u16, u16), registry: Registry) -> Self {
        Self { tls: Tls { ports, registry, ..Tls::default() }, dirs: std::array::from_fn(|_| Some(Observed::with_buffer(protocols::TlsRecords::default(), 65_540))) }
    }
}
impl Protocol for TlsSession {
    fn data(&mut self, reverse: bool, bytes: &[u8], at: Place, d: &mut Decoded, keys: &[KeyLine]) {
        let i = usize::from(reverse);
        if let Some(dir) = &mut self.dirs[i] {
            dir.data_with(bytes, at, d, |item, raw, start, place, d| self.tls.present_record(i, item, raw, start, place, d, keys));
        }
    }
    fn waiting(&self, reverse: bool) -> bool {
        self.dirs[usize::from(reverse)].as_ref().is_some_and(Observed::waiting)
    }
    fn lost(&mut self, reverse: bool) {
        let i = usize::from(reverse);
        let slot = &mut self.dirs[i];
        *slot = slot.take().map(Observed::reset);
        if let Some(inner) = &mut self.tls.inner { inner.lost(reverse); }
        self.tls.hs_plain[i].clear();
        self.tls.hs_sealed[i].clear();
    }
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
                self.seq = self.seq.checked_add(1)?;
                return Some((kind, plain, false));
            }
            let (kind, plain) = open_with(&self.app, 0, header, body)?;
            self.handshake = None;
            self.seq = 1;
            return Some((kind, plain, true));
        }
        let (kind, plain) = open_with(&self.app, self.seq, header, body)?;
        self.seq = self.seq.checked_add(1)?;
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

    #[allow(clippy::too_many_arguments)]
    fn present_record(&mut self, i: usize, item: protocols::Record, record: &[u8], start: u64, place: &Placement, d: &mut Decoded, keys: &[KeyLine]) {
        if item.oversized {
            let mut layer = Layer::new("Transport Layer Security", 0, (0, record.len()));
            layer.summary = protocols::TlsRecords::summary(&item);
            protocols::TlsRecords::fields(&item, record, &mut layer);
            place.push(d, start, record, "TLS record header", layer);
            d.tag("malformed");
            info(d, 1, "TLS", "Record too long");
        } else {
            let (buf, base) = place.locate(d, start, record, "Reassembled TLS record");
            self.record(i, record, buf, base, d, keys);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record(&mut self, i: usize, record: &[u8], buf: usize, base: usize, d: &mut Decoded, keys: &[KeyLine]) {
        let kind = record[0];
        let body = &record[5..];
        let version = |tls: &Tls| if tls.tls13 { "TLSv1.3" } else if tls.cipher.is_some() { "TLSv1.2" } else { "TLS" };
        let place = Placement::new(Place { stream_start: 0, buf, offset: Some(base), len: record.len() });
        let push = |d: &mut Decoded, layer| place.push(d, 0, record, "Reassembled TLS record", layer);
        let mut l = Layer::new("Transport Layer Security", 0, (0, record.len()));
        protocols::TlsRecords::fields(&protocols::Record { length: body.len(), oversized: false }, record, &mut l);
        match kind {
            22 => {
                let names = self.handshake_records(i, body, buf, 5, d, &mut l, false);
                let version = version(self);
                l.summary = format!("{version} Handshake: {}", names.join(", "));
                push(d, l);
                info(d, 1, version, &names.join(", "));
            }
            20 => {
                let version = version(self);
                l.summary = "Change Cipher Spec".into();
                push(d, l);
                info(d, 1, version, "Change Cipher Spec");
            }
            21 if body.len() >= 2 => {
                let version = version(self);
                l.summary = format!("Alert: level {}, description {}", body[0], body[1]);
                push(d, l);
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
                        push(d, l);
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
                                push(d, l);
                                d.push(hl);
                                info(d, 1, version, &names.join(", "));
                            }
                            21 => {
                                l.summary = format!("{version} Alert (decrypted)");
                                push(d, l);
                                info(d, 1, version, "Encrypted Alert");
                            }
                            _ => {
                                l.summary = format!("{version} Application Data, {} bytes decrypted", plain.len());
                                push(d, l);
                                let inner_place = Place { stream_start: self.inner_offsets[i], buf: pb, offset: Some(0), len: plain.len() };
                                self.inner_data(i, &plain, inner_place, d);
                            }
                        }
                    }
                }
            }
            _ => {
                l.summary = format!("Record type {kind}");
                push(d, l);
            }
        }
    }

    /// Feeds decrypted application data through the public selection mechanism.
    fn inner_data(&mut self, i: usize, plain: &[u8], place: Place, d: &mut Decoded) {
        self.inner_offsets[i] = self.inner_offsets[i].saturating_add(plain.len() as u64);
        if self.inner.is_none() {
            let mut registry = self.registry.clone();
            registry.automatic(Transport::Tcp);
            let hint = match self.alpn.as_deref() {
                Some("h2") => Some("http2"),
                Some("http/1.1") => Some("http1"),
                _ => None,
            };
            if let Some(name) = hint {
                // Unknown names leave automatic selection in place.
                registry.choose(Transport::Tcp, name);
            }
            let mut inner = Conversation::with_registry(self.ports.0, self.ports.1, registry);
            inner.alpn.clone_from(&self.alpn);
            self.inner = Some(inner);
        }
        if let Some(conversation) = &mut self.inner { conversation.data(i != 0, plain, place, d, &[]); }
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
        // `held` starts with one incomplete message. Checking its length
        // is constant work until it is complete; append without copying
        // that prefix on every record.
        held.extend_from_slice(body);
        let whole = whole_messages(held);
        if whole == 0 {
            if held.len() > MAX_HANDSHAKE {
                held.clear();
            }
            return vec!["part of a handshake message".into()];
        }
        let joined = std::mem::take(held);
        if joined.len() - whole <= MAX_HANDSHAKE {
            let held = if decrypted { &mut self.hs_sealed[i] } else { &mut self.hs_plain[i] };
            held.extend_from_slice(&joined[whole..]);
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
                    if let Some(sni) = &self.sni && let Some(last) = names.last_mut() {
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
        assert!(!f.c.waiting(true));
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
    fn a_complete_large_item_keeps_its_packet_bytes() {
        let mut dns = Feeder::new((40000, 53));
        let mut message = 40_000u16.to_be_bytes().to_vec();
        message.resize(40_002, 0);
        let d = dns.send(false, &message, message.len());
        assert_eq!(d.layers[0].range, (2, message.len()));
        assert_eq!(d.layers[0].buf, 0);
        assert!(d.extra.is_empty());

        let mut tls = Feeder::new((40000, 443));
        tls.send(false, &[22, 3, 3, 0, 0], 1500);
        let mut record = vec![23, 3, 3, 0x9c, 0x40];
        record.resize(40_005, 1);
        let d = tls.send(false, &record, record.len());
        assert_eq!(d.layers[0].range, (0, record.len()));
        assert!(!d.tags.contains(&"malformed"));
        assert_eq!(d.info, "Application Data");

        let mut http = Feeder::new((40000, 80));
        let request = format!("GET /{} HTTP/1.1\r\n\r\n", "x".repeat(40_000));
        let d = http.send(false, request.as_bytes(), request.len());
        assert_eq!(d.layers[0].range, (0, request.len()));
        assert_eq!(d.layers[0].buf, 0);
        assert!(d.info.starts_with("GET /"));
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

    struct Tiny;
    impl crate::stdlib::codec::Decode for Tiny {
        type Item = Vec<u8>;
        type Error = std::convert::Infallible;
        const NAME: &'static str = "Tiny";
        fn capacity(&self) -> usize {
            256
        }
        fn decode(
            &mut self,
            input: &[u8],
            _: bool,
        ) -> Result<crate::stdlib::codec::Step<Vec<u8>>, Self::Error> {
            use crate::stdlib::codec::Step;
            let Some(&len) = input.first() else {
                return Ok(Step::Need);
            };
            let end = 1 + usize::from(len);
            Ok(match input.get(1..end) {
                Some(bytes) => Step::Item(bytes.to_vec(), end),
                None => Step::Need,
            })
        }
    }
    impl Present for Tiny {
        fn summary(item: &Vec<u8>) -> String {
            String::from_utf8_lossy(item).into_owned()
        }
        fn fields(_: &Vec<u8>, _: &[u8], _: &mut Layer) {}
    }

    fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind, 0, (body.len() >> 8) as u8, body.len() as u8];
        message.extend_from_slice(body);
        message
    }

    fn tls_user_protocol(alpn: Option<&str>, replacement: bool, http_builtins: bool) {
        let mut registry = if http_builtins {
            Registry::default()
        } else {
            let mut registry = Registry::new();
            registry.register_protocol(
                "tls",
                |s| {
                    if s.first.starts_with(&[22, 3]) {
                        Match::Yes
                    } else {
                        Match::No
                    }
                },
                |s, registry| Box::new(TlsSession::new(s.ports, registry.clone())),
            );
            registry
        };
        let expected_alpn = alpn.map(str::to_owned);
        registry.register(
            if replacement { "http1" } else { "tiny" },
            move |s| {
                if replacement {
                    return Match::No;
                }
                if s.ports != (40000, 9443) {
                    return Match::No;
                }
                if expected_alpn.as_deref() == Some("alpn-only") {
                    return if s.alpn == Some("alpn-only") {
                        Match::Yes
                    } else {
                        Match::No
                    };
                }
                if s.first.starts_with(b"\x05hello") {
                    assert_eq!(s.alpn, expected_alpn.as_deref());
                    Match::Yes
                } else if b"\x05hello".starts_with(s.first) {
                    Match::More
                } else {
                    Match::No
                }
            },
            |_| [Tiny, Tiny],
        );
        let mut conversation = Conversation::with_registry(40000, 9443, registry);
        let keys: Vec<_> = [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_TRAFFIC_SECRET_0",
        ]
        .into_iter()
        .map(|label| KeyLine {
            label: label.into(),
            client_random: vec![7; 32],
            secret: vec![if label.contains("HANDSHAKE") { 2 } else { 1 }; 32],
        })
        .collect();
        let mut offsets = [0; 2];
        let mut feed = |reverse: bool, record: &[u8]| {
            let i = usize::from(reverse);
            let mut packet = Decoded::default();
            conversation.data(
                reverse,
                record,
                Place {
                    stream_start: offsets[i],
                    offset: Some(0),
                    len: record.len(),
                    ..Place::default()
                },
                &mut packet,
                &keys,
            );
            offsets[i] += record.len() as u64;
            packet
        };
        let clear_record = |message: &[u8]| {
            let mut record = vec![22, 3, 3, (message.len() >> 8) as u8, message.len() as u8];
            record.extend_from_slice(message);
            record
        };
        let mut client = vec![3, 3];
        client.extend_from_slice(&[7; 32]);
        client.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        feed(false, &clear_record(&handshake_message(1, &client)));
        let mut server = vec![3, 3];
        server.extend_from_slice(&[8; 32]);
        server.extend_from_slice(&[0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        feed(true, &clear_record(&handshake_message(2, &server)));
        if let Some(alpn) = alpn {
            let mut extension = vec![
                0,
                16,
                0,
                (alpn.len() + 3) as u8,
                0,
                (alpn.len() + 1) as u8,
                alpn.len() as u8,
            ];
            extension.extend_from_slice(alpn.as_bytes());
            let mut body = (extension.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&extension);
            feed(true, &seal(&[2; 32], 0, 22, &handshake_message(8, &body)));
        }
        // Split the plaintext prefix across records to exercise deferred selection.
        feed(false, &seal(&[1; 32], 0, 23, b"\x05he"));
        let packet = feed(false, &seal(&[1; 32], 1, 23, b"llo"));
        assert!(packet.tags.contains(&"decrypted"));
        assert_eq!(packet.proto, "Tiny");
        assert_eq!(packet.info, "hello");
        assert_eq!(packet.extra.last().unwrap().1, b"\x05hello");
    }

    #[test]
    fn tls_selects_a_user_protocol_with_custom_alpn() {
        tls_user_protocol(Some("tiny"), false, true);
    }

    #[test]
    fn tls_selects_a_user_protocol_without_alpn() {
        tls_user_protocol(None, false, true);
    }

    #[test]
    fn tls_uses_a_user_replacement_for_http1() {
        tls_user_protocol(Some("http/1.1"), true, true);
    }

    #[test]
    fn tls_matchers_can_use_alpn_and_missing_http_hints_fall_back() {
        tls_user_protocol(Some("alpn-only"), false, true);
        for alpn in ["h2", "http/1.1"] {
            tls_user_protocol(Some(alpn), false, false);
        }
    }

    #[test]
    fn selection_flushes_the_other_directions_prefix() {
        for partial in [false, true] {
            let mut registry = Registry::new();
            registry.register(
                "tiny",
                |s| {
                    if s.first == b"\x01b" {
                        Match::Yes
                    } else {
                        Match::More
                    }
                },
                |_| [Tiny, Tiny],
            );
            let mut f = Feeder {
                c: Conversation::with_registry(1, 2, registry),
                at: [0, 0],
            };
            let prefix: &[u8] = if partial { b"\x05he" } else { b"\x01a" };
            f.send(false, prefix, prefix.len());
            assert!(f.c.waiting(false));
            let packet = f.send(true, b"\x01b", 2);
            assert!(f.c.prefix.iter().all(Vec::is_empty));
            assert_eq!(f.c.waiting(false), partial);
            if partial {
                assert_eq!(f.send(false, b"llo", 3).info, "hello");
                assert!(!f.c.waiting(false));
            } else {
                assert_eq!(packet.info, "a, b");
                assert_eq!(packet.extra[0].1, prefix);
            }
        }
    }

    #[test]
    fn partial_handshakes_append_without_reallocating_the_held_prefix() {
        for decrypted in [false, true] {
            let mut tls = Tls::default();
            let held = if decrypted {
                &mut tls.hs_sealed[0]
            } else {
                &mut tls.hs_plain[0]
            };
            *held = Vec::with_capacity(MAX_HANDSHAKE);
            let allocation = held.as_ptr();
            let message = handshake_message(11, &[0; 4096]);
            for (i, byte) in message.iter().enumerate() {
                let mut packet = Decoded::default();
                let mut layer = Layer::new("TLS", 0, (0, 1));
                let names =
                    tls.handshake_records(0, &[*byte], 0, 0, &mut packet, &mut layer, decrypted);
                let held = if decrypted {
                    &tls.hs_sealed[0]
                } else {
                    &tls.hs_plain[0]
                };
                if i + 1 < message.len() {
                    assert_eq!(held.as_ptr(), allocation);
                    assert_eq!(held.len(), i + 1);
                } else {
                    assert!(held.is_empty());
                    assert_eq!(names, ["Certificate"]);
                    assert_eq!(packet.extra[0].1, message);
                }
            }
        }
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
            let mut dir = Observed::new(protocols::TlsRecords::default());
            let place = Place { stream_start: at, buf: 0, offset: Some(0), len: record.len() };
            at += record.len() as u64;
            dir.data_with(record, place, &mut d, |item, raw, start, place, d| tls.present_record(0, item, raw, start, place, d, &[]));
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
