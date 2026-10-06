//! Application protocols: DNS, DHCP, HTTP/1.1, HTTP/2, Modbus/TCP, and TLS,
//! which is decrypted when the world's TLS stack gave its session keys.
//!
//! A [`Conversation`](super::Conversation) is one TCP connection, both ways.
//! It guesses the protocol through the public registry, using ports or first
//! bytes, then decodes each
//! direction's byte stream as it arrives. Each message it finds becomes a
//! [`Layer`] of the packet that completed it. When the whole message lies
//! in that packet, its fields point at the packet's own bytes; otherwise
//! the message gets a buffer of its own, as Wireshark's "Reassembled TCP".

use std::fmt::Write;

use fictionet::stdlib::hpack;

use super::decode::{Decoded, Layer, be16, be32};
use crate::watch::KeyLine;

use super::protocols;
use super::tls::TlsSession;
use super::{Match, Place, Protocol, Registry, Transport};
const MAX_BUFFER: usize = 32 << 10;

/// Text for a preview of bytes: the start, if it reads as text.
fn preview(b: &[u8]) -> Option<String> {
    let cut = &b[..b.len().min(160)];
    let text = std::str::from_utf8(cut).ok()?;
    if text
        .chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
    {
        let mut t = text.replace("\r\n", "\\r\\n").replace('\n', "\\n");
        if b.len() > cut.len() {
            t.push('…');
        }
        Some(t)
    } else {
        None
    }
}

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
// TCP follows at most 512 directions per watched link (see `stream`).
// Plain HTTP/1 input uses at most 2 * (32,769 + 65,535) bytes per direction,
// or 96 MiB per link, including codec buffer compaction space. TLS adds an
// outer record buffer of 2 * 65,540 bytes and an inner conversation with
// the same HTTP/1 bound. Its two handshake buffers each retain at most
// 2 * 65,536 bytes between records. Together these input/handshake buffers
// can retain about 288 MiB per link. Appending a record can temporarily
// grow one handshake allocation to 256 KiB; completion, overflow, and gaps
// release it. Decoder tables, TCP reassembly, and packet output have separate
// bounds. User decoders declare their own capacities.
/// The longest HTTP/2 header block kept across CONTINUATION frames.
const MAX_HEADER_BLOCK: usize = 64 << 10;

/// One direction's bytes not decoded yet.
#[derive(Default)]
struct Dir {
    /// Bytes received; those before `head` are already decoded.
    raw: Vec<u8>,
    /// Where the bytes not decoded yet start in `raw`. Consuming a frame
    /// only moves this, so a chunk of many small frames costs time in
    /// proportion to its size; the decoded bytes are dropped once, when
    /// the next chunk arrives.
    head: usize,
    /// The stream offset of the first byte not decoded yet.
    start: u64,
    /// Bytes still to come of a message too long to hold, which are
    /// dropped as they arrive.
    skip: u64,
    http2: Http2,
}

impl Dir {
    /// The bytes not decoded yet.
    fn buf(&self) -> &[u8] {
        &self.raw[self.head..]
    }

    fn push(&mut self, bytes: &[u8], place: &Place) {
        if self.head > 0 {
            self.raw.drain(..self.head);
            self.head = 0;
        }
        if self.raw.is_empty() {
            self.start = place.stream_start;
        }
        self.raw.extend_from_slice(bytes);
        let n = self.skip.min(self.buf().len() as u64);
        self.consume(n as usize);
        self.skip -= n;
    }

    fn consume(&mut self, n: usize) {
        let n = n.min(self.buf().len());
        self.head += n;
        self.start = self.start.saturating_add(n as u64);
        if self.head == self.raw.len() {
            self.raw.clear();
            self.head = 0;
        }
    }

    /// Consumes a message of `len` bytes at the start of `buf`, of which
    /// only some may have come: the rest is skipped when it comes.
    fn consume_message(&mut self, len: usize) {
        let n = len.min(self.buf().len());
        self.consume(n);
        self.skip = (len - n) as u64;
    }

    /// Bytes of this direction were lost, so the message buffered cannot
    /// be finished, and where the next one starts is not known.
    fn lose(&mut self) {
        self.raw.clear();
        self.head = 0;
        self.skip = 0;
        self.http2.lose();
    }

    /// Drops what is buffered if it outgrew [`MAX_BUFFER`]: a message
    /// whose end could not be found.
    fn limit(&mut self) {
        if self.buf().len() > MAX_BUFFER {
            self.lose();
        }
    }
}

fn looks_like_http1(b: &[u8]) -> bool {
    let methods: [&[u8]; 9] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    b.starts_with(b"HTTP/1.") || methods.iter().any(|m| b.starts_with(m))
}

fn register_http(registry: &mut Registry) {
    registry.register_with_buffer(
        "http1",
        |s| {
            if s.transport == Transport::Tcp && looks_like_http1(s.first) {
                Match::Yes
            } else {
                Match::No
            }
        },
        MAX_BUFFER + 1 + 65_535,
        |_| protocols::Http1::pair(),
    );
    registry.register_protocol(
        "http2",
        |s| {
            if s.transport != Transport::Tcp {
                Match::No
            } else if s.first.starts_with(HTTP2_PREFACE) {
                Match::Yes
            } else if HTTP2_PREFACE.starts_with(s.first) {
                Match::More
            } else {
                Match::No
            }
        },
        |_, _| {
            Box::new(H2Session {
                dirs: [Dir::default(), Dir::default()],
            })
        },
    );
}

pub(super) fn register(registry: &mut Registry) {
    register_http(registry);
    registry.register_protocol(
        "tls",
        |s| {
            if s.transport == Transport::Tcp && s.first.starts_with(&[0x16, 0x03]) {
                Match::Yes
            } else {
                Match::No
            }
        },
        |s, registry| Box::new(TlsSession::new(s.ports, registry.clone())),
    );
    registry.register_protocol(
        "modbus",
        |s| {
            if s.transport == Transport::Tcp
                && (s.ports.0 == crate::stdlib::modbus::PORT
                    || s.ports.1 == crate::stdlib::modbus::PORT)
            {
                Match::Yes
            } else {
                Match::No
            }
        },
        |s, _| Box::new(protocols::ModbusSession::new(s.ports)),
    );
    registry.register(
        "dhcp",
        |s| {
            if s.transport == Transport::Udp && matches!(s.ports, (67, 68) | (68, 67)) {
                Match::Yes
            } else {
                Match::No
            }
        },
        |_| [protocols::Dhcp::default(), protocols::Dhcp::default()],
    );
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
                protocols::Dns::new(s.transport == Transport::Tcp),
                protocols::Dns::new(s.transport == Transport::Tcp),
            ]
        },
    );
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
        !dir.buf().is_empty() || dir.skip > 0
    }
    fn lost(&mut self, reverse: bool) { self.dirs[usize::from(reverse)].lose(); }
}

// ---------------------------------------------------------------------------
// HTTP/2

struct Http2 {
    /// The connection preface has been read (the client's direction).
    started: bool,
    hpack: hpack::Table,
    /// A header block that goes on in CONTINUATION frames.
    block: Option<Pending>,
    /// Bytes of this direction were lost, so where frames start is not
    /// known: the rest of it is not decoded.
    lost: bool,
}

impl Default for Http2 {
    fn default() -> Self {
        Self {
            started: false,
            hpack: hpack::Table::for_observation(),
            block: None,
            lost: false,
        }
    }
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
        let n = dir.buf().len();
        dir.consume(n);
        return;
    }
    // The client's direction starts with the preface, which may come in
    // pieces: wait for all of it.
    if !dir.http2.started && dir.buf().len() < HTTP2_PREFACE.len() && HTTP2_PREFACE.starts_with(dir.buf()) {
        return;
    }
    if !dir.http2.started && dir.buf().starts_with(HTTP2_PREFACE) {
        let (buf, base) = place.locate(d, dir.start, HTTP2_PREFACE, "HTTP/2 preface");
        let mut l = Layer::new("HyperText Transfer Protocol 2", buf, (base, base + HTTP2_PREFACE.len()));
        l.summary = "Connection preface".into();
        d.push(l);
        info(d, 2, "HTTP/2", "Magic");
        dir.consume(HTTP2_PREFACE.len());
    }
    dir.http2.started = true;
    while dir.buf().len() >= 9 {
        let len = (usize::from(dir.buf()[0]) << 16) | usize::from(be16(dir.buf(), 1));
        // A frame too long to hold is shown by its header, and the rest of
        // it is skipped as it comes.
        let whole = dir.buf().len() >= 9 + len;
        if !whole && 9 + len <= MAX_BUFFER {
            return;
        }
        let frame = dir.buf()[..if whole { 9 + len } else { 9 }].to_vec();
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
    let Ok(block) = h2.hpack.decode_block(bytes, d.room()) else {
        l.note("Header block", "could not be decoded: it is malformed");
        d.tag("malformed");
        return;
    };
    let get = |n: &str| {
        block.headers.iter().find(|h| h.name.as_deref() == Some(n.as_bytes()))
            .and_then(|h| h.value.as_deref().map(|v| String::from_utf8_lossy(v).into_owned()))
    };
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
            (Some(name), Some(value)) => l.note(&String::from_utf8_lossy(&name), String::from_utf8_lossy(&value)),
            (None, Some(value)) => l.note("Header", format!("{} (its name is {UNKNOWN})", String::from_utf8_lossy(&value))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::Conversation;

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
            Feeder {
                c: Conversation::with_registry(ports.0, ports.1, Registry::default()),
                at: [0, 0],
            }
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

    #[test]
    fn expanded_huffman_headers_keep_dynamic_references() {
        use fictionet::stdlib::{codec::Wire, prefix_int::Integer};

        let mut f = Feeder::h2();
        f.send(true, &frame(1, 0x4, 1, &hex(X_OLD)), 1500);
        let mut block = vec![0, 1, b'x'];
        Integer::<7> {
            flags: 0x80,
            value: 60_000,
        }
        .write(&mut block)
        .unwrap();
        block.extend(vec![0; 60_000]);
        let mut chunks = block.chunks(16_000).peekable();
        let mut kind = 1;
        while let Some(chunk) = chunks.next() {
            let flags = if chunks.peek().is_none() { 0x4 } else { 0 };
            let d = f.send(true, &frame(kind, flags, 3, chunk), 1500);
            assert!(!d.tags.contains(&"malformed"));
            kind = 9;
        }
        let d = f.send(true, &frame(1, 0x4, 5, &[0x88, 0xbe]), 1500);
        assert!(!d.tags.contains(&"malformed"));
        assert!(has(&d, "x", "old"));
    }

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
        let mut session = H2Session {
            dirs: [Dir::default(), Dir::default()],
        };
        let mut packet = Decoded::default();
        session.data(false, HTTP2_PREFACE, Place::default(), &mut packet, &[]);
        session.data(
            true,
            &frame(1, 0x4, 1, &hex(X_OLD)),
            Place::default(),
            &mut packet,
            &[],
        );
        assert!(has(&packet, "x", "old"));
        session.data(
            true,
            &frame(1, 0, 3, &[0x88]),
            Place::default(),
            &mut packet,
            &[],
        );
        assert!(session.dirs[1].http2.block.is_some());
        session.lost(true);
        assert!(session.dirs[1].http2.lost);
        assert!(session.dirs[1].http2.block.is_none());
        let mut packet = Decoded::default();
        session.data(
            true,
            &frame(1, 0x4, 3, &[0x88, 0xbe]),
            Place::default(),
            &mut packet,
            &[],
        );
        assert!(packet.layers.is_empty());
        assert!(!session.waiting(true));
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


    /// A large chunk of tiny HTTP/2 frames takes time in proportion to its
    /// size. Consuming each frame used to move the rest of the buffer, so a
    /// chunk of n frames took n^2 work.
    #[test]
    fn many_tiny_http2_frames_in_one_chunk_take_linear_time() {
        let one = frame(0xff, 0, 1, &[]);
        let time = |n: usize| {
            let bytes = one.repeat(n);
            let mut f = Feeder::h2();
            let started = std::time::Instant::now();
            let d = f.send(false, &bytes, bytes.len());
            assert!(d.layers.len() + d.cut > 0);
            started.elapsed()
        };
        let small = time(20_000);
        let large = time(160_000);
        // Eight times the frames: linear work takes about eight times as
        // long; quadratic work, about 64 times.
        assert!(large < small * 24 + std::time::Duration::from_millis(50), "{small:?} for 20,000 frames, {large:?} for 160,000");
    }
}
