use super::{Display, MAX_BUFFER};
use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::dissect::{Decoded, Layer, Match, Placement, Present, Registry};
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::http1;
use fictionet::sync::Mutex;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;

/// HTTP/1 framing capacity plus one packet of read-ahead.
const HTTP1_READ_AHEAD: usize = MAX_BUFFER + 1 + 65_535;

fn looks_like_http1(b: &[u8]) -> bool {
    let methods: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    b.starts_with(b"HTTP/1.") || methods.iter().any(|m| b.starts_with(m))
}

/// HTTP/1 capture parser. It shares a bounded request-method queue with
/// the other direction so HEAD and CONNECT responses retain their framing.
/// Bodies are read by [`http1::BodyEvents`], the body framing the server
/// uses, told to skip chunk extensions and trailers as a passive observer
/// must. Chunked bodies finish after the empty line ending the trailer
/// section; trailers are not included in body previews. Spaces and tabs
/// around a chunk size are tolerated. Framing the body reader refuses, such
/// as an invalid or overflowing chunk size, emits a `malformed` item with
/// the raw line and the body preview so far, then skips bytes until close
/// because framing is lost.
#[derive(Default)]
pub struct Http1 {
    state: Http1State,
    methods: Arc<Mutex<Methods>>,
    // The other decoder in a pair accounts for this shared queue.
    shared_methods: bool,
    scanned: usize,
    /// Whether this direction carries requests, once it read a head.
    requests: Option<bool>,
}
impl Http1 {
    /// Registers `http1` for TCP method or response prefixes, or `http/1.1` ALPN.
    /// The `h2` ALPN excludes prefix matching. Uses bounded packet read-ahead.
    pub fn register(registry: &mut Registry) {
        registry.register_with_buffer(
            "http1",
            |s| {
                if s.transport == Transport::Tcp
                    && (s.alpn == Some("http/1.1")
                        || (s.alpn != Some("h2") && looks_like_http1(s.first)))
                {
                    Match::Yes
                } else {
                    Match::No
                }
            },
            HTTP1_READ_AHEAD,
            |_| Self::pair(),
        );
    }
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
                requests: None,
            },
            Self {
                state: Http1State::default(),
                methods,
                shared_methods: true,
                scanned: 0,
                requests: None,
            },
        ]
    }
    /// Messages of this direction were missed or skipped: tells the method
    /// queue. A direction that has not read a head may carry responses.
    fn miss(&mut self) {
        let requests = self.requests == Some(true);
        self.methods.lock().missed(requests);
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
            Http1State::Body { seen, .. } => seen.len(),
            _ => 0,
        };
        if self.shared_methods {
            preview
        } else {
            let methods = self.methods.lock();
            preview.saturating_add(methods.waiting.len())
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
            let mut methods = self.methods.lock();
            let read = read_head(head, &mut methods);
            drop(methods);
            let Some((line, kind, body, unpaired)) = read else {
                // A head that cannot be read is a message missed.
                self.miss();
                return Ok(Step::Skip(head.len()));
            };
            self.requests = Some(kind == "request");
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
            if unpaired {
                layer.note(
                    "Body",
                    "not read: bytes went missing, so which request this answers is not known",
                );
            }
            let mut d = Decoded::default();
            d.push(layer);
            d.application(2, "HTTP", &line);
            return Ok(Step::Item(
                Display::from_packet(d, "Reassembled HTTP head"),
                head.len(),
            ));
        }
        match &self.state {
            Http1State::Body { .. } => Ok(self.body(input)),
            Http1State::ToClose | Http1State::Tunnel => Ok(if input.is_empty() {
                Step::Need
            } else {
                Step::Skip(input.len())
            }),
            Http1State::Head => Ok(Step::Need),
        }
    }
}
impl Http1 {
    /// One step through a body, by the shared body framing. Framing steps
    /// in a row are taken together, so a body block or the body's end
    /// carries the framing bytes before it. The end of a capture is not
    /// the end of a body: one it cuts off stays incomplete.
    fn body(&mut self, input: &[u8]) -> Step<Display> {
        let capacity = self.capacity();
        let mut used = 0usize;
        loop {
            let rest = input.get(used..).unwrap_or_default();
            let Http1State::Body { body, seen, total } = &mut self.state else {
                return Step::Skip(used);
            };
            let Ok(step) = body.decode(rest, false) else {
                return self.malformed(rest, used);
            };
            match step {
                Step::Item(http1::Event::Body(data), n) => {
                    let take = data.len().min(PREVIEW.saturating_sub(seen.len()));
                    seen.extend_from_slice(&data[..take]);
                    *total = total.saturating_add(data.len() as u64);
                    used = used.saturating_add(n);
                }
                Step::Skip(n) if n > 0 => used = used.saturating_add(n),
                Step::Item(http1::Event::Done, n) => {
                    used = used.saturating_add(n);
                    let Http1State::Body { total, seen, .. } = std::mem::take(&mut self.state)
                    else {
                        return Step::Skip(used);
                    };
                    return Step::Item(body_item(total, &seen), used);
                }
                Step::Item(http1::Event::Head(never), _) => match never {},
                _ if used > 0 => return Step::Skip(used),
                _ if input.len() >= capacity => {
                    self.reset();
                    return Step::Skip(input.len());
                }
                _ => return Step::Need,
            }
        }
    }

    /// The body's framing was refused at the start of `rest`, `start`
    /// bytes into the input: a `malformed` item naming the refused line,
    /// with the body so far. Nothing after it can be framed.
    fn malformed(&mut self, rest: &[u8], start: usize) -> Step<Display> {
        let Http1State::Body { body, seen, total } = std::mem::take(&mut self.state) else {
            return Step::Skip(start);
        };
        let (what, field) = if body.in_trailers() {
            ("Malformed HTTP trailer", "Trailer")
        } else {
            ("Malformed HTTP chunk size", "Chunk size")
        };
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(rest.len());
        let line = &rest[..end];
        let used = start
            .saturating_add(end)
            .saturating_add(if end < rest.len() { 2 } else { 0 });
        let mut d = Decoded::default();
        body_layer(&mut d, total, &seen);
        let mut layer = Layer::new("Hypertext Transfer Protocol", 0, (start, used));
        layer.summary = what.into();
        layer.field(
            field,
            String::from_utf8_lossy(line).escape_debug().to_string(),
            (start, start + end),
        );
        // Display retains one layer, including the body preview here.
        for body in d.layers.drain(..) {
            layer.note("Body received", body.summary);
            layer.fields.extend(body.fields);
        }
        d.application(2, "HTTP", &layer.summary);
        d.push(layer);
        d.tag("malformed");
        self.state = Http1State::ToClose;
        self.miss();
        self.scanned = 0;
        Step::Item(Display::from_packet(d, what), used)
    }
}
impl Present for Http1 {
    display_presenter!();
    /// Starts over at the next head: bytes were missed, or skipped since
    /// framing was lost, and the method queue is told.
    fn reset(&mut self) {
        self.state = Http1State::default();
        self.scanned = 0;
        self.miss();
    }
}
fn body_item(total: u64, seen: &[u8]) -> Display {
    let mut d = Decoded::default();
    body_layer(&mut d, total, seen);
    let mut item = Display::from_packet(d, "HTTP body");
    item.detached = true;
    item
}

/// The most of a body kept for its preview.
const PREVIEW: usize = 4096;

/// The limits the body reader keeps within a capture's buffer: a chunk
/// line or a trailer line, with its line ending, may fill the buffer, and
/// a trailer section may hold any number of fields.
fn body_limits() -> http1::Limits {
    http1::Limits {
        header_line: MAX_BUFFER - 1,
        head: MAX_BUFFER,
        headers: usize::MAX,
        ..http1::Limits::default()
    }
}

/// HTTP/1.1 request methods waiting for their responses, in order. Which
/// request a response answers is known only while no request and no
/// response was missed: a missed request leaves [`Method::Lost`] where its
/// method would be, and once responses reach it, or once a response was
/// missed, it is not known again.
#[derive(Default)]
struct Methods {
    waiting: VecDeque<Method>,
    /// Which request a response answers is no longer known.
    unknown: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Head,
    Connect,
    Other,
    /// Requests from here on were missed, or not kept.
    Lost,
}

impl Methods {
    /// The most methods kept waiting.
    const MAX: usize = 64;

    fn push(&mut self, method: Method) {
        if self.unknown || self.waiting.back() == Some(&Method::Lost) {
            return;
        }
        if self.waiting.len() >= Self::MAX {
            // No room: the newest request and those after it go unpaired.
            if let Some(newest) = self.waiting.back_mut() {
                *newest = Method::Lost;
            }
            return;
        }
        self.waiting.push_back(method);
    }

    fn request(&mut self, m: &str) {
        self.push(match m {
            "HEAD" => Method::Head,
            "CONNECT" => Method::Connect,
            _ => Method::Other,
        });
    }

    /// The method of the request the next response answers, or
    /// [`Method::Lost`] when that is not known. With no request waiting,
    /// the request was not seen, as when the capture began after it, and
    /// it is taken to be neither HEAD nor CONNECT.
    fn answer(&mut self) -> Method {
        if self.unknown {
            return Method::Lost;
        }
        match self.waiting.pop_front() {
            Some(Method::Lost) => {
                self.forget();
                Method::Lost
            }
            Some(method) => method,
            None => Method::Other,
        }
    }

    /// Bytes of one direction were missed or skipped. If it carries
    /// requests, those already waiting are still answered in order, and
    /// what follows them is not known. Otherwise responses were missed,
    /// and which request any later response answers is not known.
    fn missed(&mut self, requests: bool) {
        if requests {
            self.push(Method::Lost);
        } else {
            self.forget();
        }
    }

    fn forget(&mut self) {
        self.waiting = VecDeque::new();
        self.unknown = true;
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.1

#[derive(Default)]
enum Http1State {
    /// Waiting for a request or status line and headers.
    #[default]
    Head,
    /// In a body framed by its length or by chunks: its reader, the start
    /// of it, and how many bytes it has had.
    Body {
        body: http1::BodyEvents,
        seen: Vec<u8>,
        total: u64,
    },
    /// In a body that lasts until the connection closes, or after framing is lost.
    ToClose,
    /// After a CONNECT was accepted: bytes of another protocol.
    Tunnel,
}

fn body_kind<'a>(
    headers: impl Iterator<Item = http1::FieldRef<'a>> + Clone,
    none: bool,
    response: bool,
) -> Http1State {
    if none {
        return Http1State::Head;
    }
    let get = |name: &str| {
        headers
            .clone()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).to_string())
    };
    let framing =
        if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            http1::Framing::Chunked
        } else {
            match get("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
                Some(0) => return Http1State::Head,
                Some(n) => http1::Framing::Length(n),
                None if response => return Http1State::ToClose,
                None => return Http1State::Head,
            }
        };
    Http1State::Body {
        body: http1::BodyEvents::with_limits(framing, body_limits()).skip_chunk_extras(),
        seen: Vec::new(),
        total: 0,
    }
}

/// Reads a request or response head: its first line, which it is, and
/// how its body is framed. The head is read by its syntax alone, with
/// [`http1`]'s lenient reader: a passive observer must not refuse a head
/// the endpoints took.
/// The flag says whether a response's body framing depends on a request
/// that is not known, so the body is not read: a response to HEAD has no
/// body, and a 2xx response to CONNECT starts a tunnel.
fn read_head(
    head: &[u8],
    methods: &mut Methods,
) -> Option<(String, &'static str, Http1State, bool)> {
    if head.starts_with(b"HTTP/") {
        let (r, _) = http1::ResponseHead::parse_lenient(head).ok().flatten()?;
        let code = r.status;
        let line = format!(
            "{} {code} {}",
            r.version.as_str(),
            String::from_utf8_lossy(&r.reason)
        );
        let method = if (100..200).contains(&code) {
            None
        } else {
            Some(methods.answer())
        };
        let success = (200..300).contains(&code);
        let framed = || {
            body_kind(
                r.headers.iter().map(http1::FieldRef::from),
                (100..200).contains(&code) || code == 204 || code == 304,
                true,
            )
        };
        let (body, unpaired) = match method {
            Some(Method::Connect) if success => (Http1State::Tunnel, false),
            Some(Method::Head) => (Http1State::Head, false),
            // Without the request, only a response with no body under any
            // method is framed: one that is not 2xx and has no body.
            Some(Method::Lost) => match framed() {
                Http1State::Head if !success => (Http1State::Head, false),
                _ => (Http1State::ToClose, true),
            },
            _ => (framed(), false),
        };
        Some((line, "response", body, unpaired))
    } else {
        let (r, _) = fictionet::stdlib::web::Head::parse_lenient(head)
            .ok()
            .flatten()?;
        let line = format!("{} {} {}", r.method(), r.target(), r.version().as_str());
        methods.request(r.method());
        Some((line, "request", body_kind(r.headers(), false, false), false))
    }
}

/// Previews the first 160 bytes as UTF-8, escaping CRLF and LF.
/// Rejects other controls except CR and TAB, and appends an ellipsis if truncated.
pub fn body_preview(b: &[u8]) -> Option<String> {
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

fn body_layer(d: &mut Decoded, total: u64, seen: &[u8]) {
    let mut l = Layer::new("HTTP body", 0, (0, 0));
    l.summary = format!("{total} bytes");
    if let Some(text) = body_preview(seen) {
        l.note("Text", text);
    }
    d.push(l);
}

/// Bounded proofs over `Http1::find`, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../../verification/dissector/kani/find.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Stream;

    #[test]
    fn body_previews_keep_byte_boundaries_and_text_policy() {
        assert_eq!(body_preview(b""), Some(String::new()));
        assert_eq!(
            body_preview(b"a\r\nb\n\t\r"),
            Some("a\\r\\nb\\n\t\r".into())
        );
        assert_eq!(body_preview(b"a\0"), None);
        assert_eq!(
            body_preview(&[b'x'; 161]),
            Some(format!("{}…", "x".repeat(160)))
        );
        assert_eq!(
            body_preview(format!("{}é", "x".repeat(159)).as_bytes()),
            None
        );
    }

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

    fn assert_malformed_chunk_size(line: &[u8], value: &str) {
        for body in [false, true] {
            let mut http = Http1::default();
            let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
            assert!(matches!(http.decode(head, false), Ok(Step::Item(_, _))));
            let mut bytes = Vec::new();
            if body {
                assert!(matches!(http.decode(b"3\r\n", false), Ok(Step::Skip(3))));
                assert!(matches!(http.decode(b"abc", false), Ok(Step::Skip(3))));
                bytes.extend_from_slice(b"\r\n");
            }
            let start = bytes.len();
            bytes.extend_from_slice(line);
            bytes.extend_from_slice(b"\r\n\r\n");
            let Step::Item(item, used) = http.decode(&bytes, false).unwrap() else {
                panic!("no malformed chunk diagnostic for {line:?}");
            };
            assert!(item.tags.contains(&"malformed"), "{line:?}");
            assert_eq!(item.summary(), "Malformed HTTP chunk size");
            assert_eq!(item.info, "Malformed HTTP chunk size");
            assert_eq!(item.protocol, "HTTP");
            assert_eq!(item.level, 2);
            assert_eq!(used, start + line.len() + 2);
            let layer = item.layer.as_ref().unwrap();
            let size = layer
                .fields
                .iter()
                .find(|f| f.name == "Chunk size")
                .unwrap();
            assert_eq!(size.value, value);
            assert_eq!(size.range, Some((start, start + line.len())));
            let preview = layer.fields.iter().find(|f| f.name == "Text").unwrap();
            assert_eq!(preview.value, if body { "abc" } else { "" });
            let received = layer
                .fields
                .iter()
                .find(|f| f.name == "Body received")
                .unwrap();
            assert_eq!(received.value, if body { "3 bytes" } else { "0 bytes" });
            assert!(matches!(http.state, Http1State::ToClose));
            assert_eq!(http.scanned, 0);
            assert_eq!(http.held(), 0);
            assert!(matches!(
                http.decode(&bytes[used..], false),
                Ok(Step::Skip(2))
            ));
            let next = b"HTTP/1.1 204 No Content\r\n\r\n";
            assert!(matches!(http.decode(next, false), Ok(Step::Skip(n)) if n == next.len()));
        }
    }

    #[test]
    fn invalid_chunk_size_not_end() {
        for line in ["zz", "", "+1", "-1", "0x1", ";ext", "1 2"] {
            assert_malformed_chunk_size(line.as_bytes(), line);
        }
        assert_malformed_chunk_size(b" \t", " \\t");
        assert_malformed_chunk_size(b"z\0\n\x7f\xff", "z\\0\\n\\u{7f}\u{fffd}");
    }

    #[test]
    fn overflowing_chunk_size() {
        assert_malformed_chunk_size(b"10000000000000000", "10000000000000000");
    }

    #[test]
    fn chunk_sizes_allow_ows_extensions_and_u64_max() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        // A size with whitespace around it and an extension frames its
        // chunk: the body that follows completes with that many bytes.
        let mut http = Http1::default();
        assert!(matches!(http.decode(head, false), Ok(Step::Item(_, _))));
        let line = b" \tA \t;ext\r\n";
        assert!(matches!(http.decode(line, false), Ok(Step::Skip(n)) if n == line.len()));
        let rest = b"0123456789\r\n0\r\n\r\n";
        let Ok(Step::Item(item, used)) = http.decode(rest, false) else {
            panic!("the chunk did not complete the body");
        };
        assert_eq!(used, rest.len());
        assert_eq!(item.summary(), "10 bytes");
        assert!(!item.tags.contains(&"malformed"));
        // The largest size is a chunk too: its data is taken as body.
        let mut http = Http1::default();
        assert!(matches!(http.decode(head, false), Ok(Step::Item(_, _))));
        let line = b"ffffffffFFFFFFFF\r\n";
        assert!(matches!(http.decode(line, false), Ok(Step::Skip(n)) if n == line.len()));
        let data = vec![b'x'; 8192];
        assert!(matches!(http.decode(&data, false), Ok(Step::Skip(n)) if n == data.len()));
    }

    #[test]
    fn http_trailers_preserve_pipelined_responses_at_every_split() {
        for trailers in [
            "",
            "X-Test: yes\r\n",
            "X-Test: yes\r\nX-Other: two\r\nX-End: three\r\n",
        ] {
            for body in ["", "1\r\nx\r\n"] {
                let first = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}0\r\n{trailers}\r\n"
                );
                let next = "HTTP/1.1 204 No Content\r\n\r\n";
                let head = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n";
                let bytes = format!("{first}{next}{head}{next}");
                for split in 0..=bytes.len() + 1 {
                    let [request, response] = Http1::pair();
                    let methods = Arc::clone(&response.methods);
                    let mut request = Stream::new(request);
                    let requests = b"GET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\nHEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n";
                    assert_eq!(request.push(requests), requests.len());
                    for _ in 0..4 {
                        request.next().unwrap().unwrap();
                    }
                    assert!(request.next().is_none());
                    let mut response = Stream::new(response);
                    let pieces = if split > bytes.len() {
                        bytes.as_bytes().chunks(1).collect::<Vec<_>>()
                    } else {
                        vec![&bytes.as_bytes()[..split], &bytes.as_bytes()[split..]]
                    };
                    let mut items = Vec::new();
                    for piece in pieces {
                        assert_eq!(response.push(piece), piece.len());
                        while let Some(item) = response.next_span() {
                            items.push(item.unwrap());
                        }
                    }
                    assert_eq!(items.len(), 5, "trailers={trailers:?}, split={split}");
                    let summaries: Vec<_> = items.iter().map(|(item, _)| item.summary()).collect();
                    assert_eq!(
                        summaries,
                        [
                            "HTTP/1.1 200 OK",
                            if body.is_empty() {
                                "0 bytes"
                            } else {
                                "1 bytes"
                            },
                            "HTTP/1.1 204 No Content",
                            "HTTP/1.1 200 OK",
                            "HTTP/1.1 204 No Content",
                        ]
                    );
                    let preview = &items[1].0.layer.as_ref().unwrap().fields[0];
                    assert_eq!(preview.name, "Text");
                    assert_eq!(preview.value, if body.is_empty() { "" } else { "x" });
                    assert_eq!(items[1].1.end, first.len() as u64);
                    assert_eq!(
                        items[2].1,
                        first.len() as u64..(first.len() + next.len()) as u64
                    );
                    assert_eq!(response.offset(), bytes.len() as u64);
                    assert!(methods.lock().waiting.is_empty());
                }
            }
        }
    }

    /// Every item a stream of responses decodes to, piece by piece.
    fn responses(response: Http1, pieces: &[&[u8]]) -> Vec<Display> {
        let mut response = Stream::new(response);
        let mut items = Vec::new();
        for piece in pieces {
            assert_eq!(response.push(piece), piece.len());
            while let Some(item) = response.next() {
                items.push(item.unwrap());
            }
        }
        items
    }

    /// Whether some item shows `text` as body bytes.
    fn as_body(items: &[Display], text: &str) -> bool {
        items.iter().any(|item| {
            item.layer
                .iter()
                .flat_map(|l| &l.fields)
                .any(|f| f.name == "Text" && f.value.contains(text))
        })
    }

    /// Requests lost from the capture leave the responses after them
    /// without the method that frames them: a response to a lost HEAD does
    /// not take the next response as its body. The responses to requests
    /// read before the gap keep their methods.
    #[test]
    fn responses_past_lost_requests_are_not_framed_by_the_wrong_method() {
        let [request, response] = Http1::pair();
        let mut request = Stream::new(request);
        let first = b"HEAD /1 HTTP/1.1\r\n\r\n";
        assert_eq!(request.push(first), first.len());
        request.next().unwrap().unwrap();
        // The bytes of a HEAD request go missing: the decoder starts over.
        let (_, mut lost) = request.into_parts();
        Present::reset(&mut lost);
        let mut request = Stream::new(lost);
        let third = b"GET /3 HTTP/1.1\r\n\r\n";
        assert_eq!(request.push(third), third.len());
        request.next().unwrap().unwrap();
        let next = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
        let to_head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", next.len());
        let items = responses(
            response,
            &[
                to_head.as_bytes(),
                to_head.as_bytes(),
                next,
                b"HTTP/1.1 204 No Content\r\n\r\n",
            ],
        );
        // The answer to the HEAD read before has no body, so the next
        // response is found; the answer to the lost one is shown too.
        assert_eq!(items[0].summary(), "HTTP/1.1 200 OK");
        assert_eq!(items[1].summary(), "HTTP/1.1 200 OK");
        assert!(!as_body(&items, "404 Not Found"), "{items:?}");
    }

    /// More requests waiting than the queue holds: the responses past it
    /// are not framed by a later request's method.
    #[test]
    fn a_full_method_queue_does_not_shift_later_responses() {
        let [request, response] = Http1::pair();
        let mut request = Stream::new(request);
        let mut requests = b"GET / HTTP/1.1\r\n\r\n".repeat(63);
        requests.extend_from_slice(b"HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n");
        for piece in requests.chunks(1000) {
            assert_eq!(request.push(piece), piece.len());
            while request.next().is_some() {}
        }
        let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let next = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
        let to_head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", next.len());
        let mut pieces: Vec<&[u8]> = vec![ok; 63];
        pieces.extend([to_head.as_bytes(), next]);
        let items = responses(response, &pieces);
        assert!(!as_body(&items, "404 Not Found"), "{items:?}");
    }

    /// What a stream of `bytes`, ended or not, decodes to.
    fn items(bytes: &[u8], end: bool) -> Vec<Display> {
        let mut stream = Stream::new(Http1::default());
        assert_eq!(stream.push(bytes), bytes.len());
        if end {
            stream.end();
        }
        let mut items = Vec::new();
        while let Some(Ok(item)) = stream.next() {
            items.push(item);
        }
        items
    }

    #[test]
    fn http_truncated_trailers_do_not_complete_the_body() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let ending = b"0\r\nX-Test: yes\r\nX-Other: two\r\n\r\n";
        for end in 0..ending.len() {
            let mut bytes = head.to_vec();
            bytes.extend_from_slice(&ending[..end]);
            for eof in [false, true] {
                let items = items(&bytes, eof);
                assert_eq!(items.len(), 1, "{end} {eof}");
                assert_eq!(items[0].summary(), "HTTP/1.1 200 OK");
            }
        }
        let mut bytes = head.to_vec();
        bytes.extend_from_slice(ending);
        let items = items(&bytes, true);
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].summary(), "0 bytes");
    }

    #[test]
    fn http_unterminated_trailers_keep_the_buffer_bound() {
        let mut http = Http1::default();
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(http.decode(head, false), Ok(Step::Item(_, _))));
        assert!(matches!(http.decode(b"0\r\n", false), Ok(Step::Skip(3))));
        // A trailer line may fill the buffer, short of its last byte.
        let mut line = b"X-Test: ".to_vec();
        line.resize(http.capacity() - 1, b'x');
        assert!(matches!(http.decode(&line, false), Ok(Step::Need)));
        // One more byte and the framing is given up, not the bound.
        line.push(b'x');
        let Ok(Step::Item(item, used)) = http.decode(&line, false) else {
            panic!("the decoder kept waiting past its buffer");
        };
        assert_eq!(used, line.len());
        assert!(item.tags.contains(&"malformed"));
        assert_eq!(item.summary(), "Malformed HTTP trailer");
        assert_eq!(http.held(), 0);
        let next = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert!(matches!(http.decode(next, false), Ok(Step::Skip(n)) if n == next.len()));
    }

    #[test]
    fn http_size_and_trailer_lines_fed_a_byte_at_a_time_complete_the_body_once() {
        let mut bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let head = bytes.len();
        bytes.extend_from_slice(b"0\r\n");
        for n in 0..3 {
            bytes.extend_from_slice(format!("X-{n}: ").as_bytes());
            bytes.resize(bytes.len() + 1000, b'x');
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        let mut stream = Stream::new(Http1::default());
        let mut items = Vec::new();
        for (at, byte) in bytes.iter().enumerate() {
            assert_eq!(stream.push(std::slice::from_ref(byte)), 1);
            while let Some(item) = stream.next_span() {
                items.push((at, item.unwrap()));
            }
        }
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, head - 1);
        let (at, (body, span)) = &items[1];
        assert_eq!(*at, bytes.len() - 1);
        assert_eq!(body.summary(), "0 bytes");
        assert_eq!(span.end, bytes.len() as u64);
    }
}
