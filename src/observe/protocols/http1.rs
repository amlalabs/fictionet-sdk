use super::{Display, MAX_BUFFER};
use fictionet::observe::{Decoded, Layer, Placement, Present};
use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::http1;
use fictionet::sync::Mutex;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;

/// HTTP/1 capture parser. It shares a bounded request-method queue with
/// the other direction so HEAD and CONNECT responses retain their framing.
/// Chunked bodies finish after the empty line ending the complete trailer
/// section. Trailers are scanned incrementally within the capture buffer
/// limit and are not included in body previews.
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
            let methods = self.methods.lock();
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
            let mut methods = self.methods.lock();
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
        // Cache each line boundary. Size and trailer lines are scanned
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
            while let Some(used) = self.final_chunk {
                let after = input.get(used..).unwrap_or_default();
                let Some(rest) = self.find(after, b"\r\n") else {
                    if input.len() >= self.capacity() {
                        self.reset();
                        return Ok(Step::Skip(input.len()));
                    }
                    return Ok(Step::Need);
                };
                let end = used.saturating_add(rest).saturating_add(2);
                if rest != 0 {
                    self.final_chunk = Some(end);
                    continue;
                }
                self.final_chunk = None;
                let state = std::mem::take(&mut self.state);
                if let Http1State::Chunked { total, seen, .. } = state {
                    return Ok(Step::Item(body_item(total, &seen), end));
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
        let line = format!(
            "{} {code} {}",
            r.version.as_str(),
            String::from_utf8_lossy(&r.reason)
        );
        let method = if (100..200).contains(&code) {
            None
        } else {
            methods.0.pop_front()
        };
        let body = match method {
            Some(Method::Connect) if (200..300).contains(&code) => Http1State::Tunnel,
            Some(Method::Head) => Http1State::Head,
            _ => body_kind(
                &r.headers,
                (100..200).contains(&code) || code == 204 || code == 304,
                true,
            ),
        };
        Some((line, "response", body))
    } else {
        let (r, _) = http1::RequestHead::parse_lenient(head).ok().flatten()?;
        let line = format!("{} {} {}", r.method, r.target, r.version.as_str());
        methods.push(&r.method);
        Some((line, "request", body_kind(&r.headers, false, false)))
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
                    assert!(methods.lock().0.is_empty());
                }
            }
        }
    }

    #[test]
    fn http_truncated_trailers_do_not_complete_the_body() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let ending = b"0\r\nX-Test: yes\r\nX-Other: two\r\n\r\n";
        for end in 0..ending.len() {
            let mut http = Http1::default();
            assert!(matches!(http.decode(head, false), Ok(Step::Item(_, _))));
            for n in 0..=end {
                assert!(matches!(http.decode(&ending[..n], false), Ok(Step::Need)));
            }
            assert!(matches!(http.decode(&ending[..end], true), Ok(Step::Need)));
            assert!(matches!(http.state, Http1State::Chunked { .. }));
        }
    }

    #[test]
    fn http_unterminated_trailers_keep_the_buffer_bound() {
        let mut http = Http1::default();
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(http.decode(head, false), Ok(Step::Item(_, _))));
        let mut bytes = b"0\r\nX-Test: ".to_vec();
        bytes.resize(http.capacity() - 1, b'x');
        assert!(matches!(http.decode(&bytes, false), Ok(Step::Need)));
        bytes.push(b'x');
        assert!(matches!(http.decode(&bytes, false), Ok(Step::Skip(n)) if n == bytes.len()));
        assert!(matches!(http.state, Http1State::Head));
        assert_eq!(http.scanned, 0);
        assert_eq!(http.final_chunk, None);
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
        for _ in 0..3 {
            let start = bytes.len();
            for _ in 0..1000 {
                bytes.push(b'x');
                assert!(matches!(http.decode(&bytes, false), Ok(Step::Need)));
                assert_eq!(http.final_chunk, Some(start));
                assert_eq!(http.scanned, bytes.len() - start);
            }
            bytes.extend_from_slice(b"\r\n");
            assert!(matches!(http.decode(&bytes, false), Ok(Step::Need)));
            assert_eq!(http.final_chunk, Some(bytes.len()));
            assert_eq!(http.scanned, 0);
        }
        bytes.extend_from_slice(b"\r\n");
        assert!(matches!(http.decode(&bytes, false), Ok(Step::Item(_, n)) if n == bytes.len()));
    }
}
