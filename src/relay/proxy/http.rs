//! The HTTP door, `--type https_proxy`: an HTTP/1.1 proxy.
//!
//! - **`CONNECT host:port`**, which `HTTPS_PROXY` clients send for
//!   `https://` URLs: attach opens the connection and answers `200`, then
//!   copies bytes both ways. TLS stays end to end, between the client and
//!   the world's site.
//! - **An absolute URI** (`GET http://host/path`), which `HTTP_PROXY`
//!   clients send for `http://` URLs: attach opens the connection, sends
//!   the request in origin form (`GET /path`) without the proxy's own
//!   headers, and passes the answer back. Each such request gets its own
//!   connection to the world and ends with `Connection: close`, so the
//!   client opens a new connection for its next one. A request that asks
//!   to switch protocols (`Connection: upgrade` with `Upgrade`, as a
//!   WebSocket handshake does) keeps both fields, and so does a `101`
//!   answer; after it, bytes go both ways until either side closes.
//!
//! Every request must carry the token in `Proxy-Authorization`, or gets
//! `407`. A connection that cannot be made gets `502`, `503` or `504`,
//! with the reason in an `X-Fictionet-Error` header and the body.
//!
//! The door relays: the world's site is the client's server, and the
//! client is the site's. So it reads heads both ways by their syntax
//! alone, with [`RequestHead::parse_lenient`] and
//! [`ResponseHead::parse_lenient`], and leaves the framing rules to the
//! two ends. A request the site would take is not refused here, nor an
//! answer the client would take turned into a `502`.

use crate::stdlib::http1::{Header, RequestHead, ResponseHead};

use super::Host;

/// The most bytes a request head, or an answer's head, may take.
pub const MAX_HEAD: usize = 64 * 1024;
/// The most header fields in a request head.
pub const MAX_HEADERS: usize = 128;

/// Where a request goes.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// `CONNECT host:port`.
    Connect { host: Host, port: u16 },
    /// An absolute URI: `http://authority/path`.
    Forward { host: Host, port: u16, authority: String, path: String },
}

/// A request head, read.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The head as the client sent it.
    pub head: RequestHead,
    /// Where it goes.
    pub target: Target,
}

impl Request {
    /// The first field named `name`, in any case.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.head.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_slice())
    }
}

/// An answer that ends the exchange: a status, and why.
#[derive(Debug, PartialEq, Eq)]
pub struct Reject {
    pub status: u16,
    pub why: String,
}

fn reject(status: u16, why: impl Into<String>) -> Reject {
    Reject { status, why: why.into() }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "Connection established",
        400 => "Bad Request",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// Reads a request head. `Ok(None)`: not all of it yet.
pub fn parse_request(bytes: &[u8]) -> Result<Option<(Request, usize)>, Reject> {
    let (head, len) = match RequestHead::parse_lenient(bytes) {
        Ok(Some(found)) => found,
        Ok(None) => return Ok(None),
        Err(e) => return Err(reject(400, format!("cannot read the request: {e}"))),
    };
    if head.headers.len() > MAX_HEADERS {
        return Err(reject(431, "too many header fields"));
    }
    let target = if head.method == "CONNECT" {
        let (host, port) =
            authority(&head.target, None).ok_or_else(|| reject(400, format!("cannot read the CONNECT target {:?}", head.target)))?;
        Target::Connect { host, port }
    } else {
        absolute_uri(&head.target)?
    };
    Ok(Some((Request { head, target }, len)))
}

/// Reads `host:port`, or `[v6]:port`. Without a port, `default` is used,
/// if given.
fn authority(s: &str, default: Option<u16>) -> Option<(Host, u16)> {
    let (host, port) = if s.starts_with('[') {
        let end = s.find(']')?;
        let (host, rest) = s.split_at(end + 1);
        match rest.strip_prefix(':') {
            Some(p) => (host, Some(p)),
            None if rest.is_empty() => (host, None),
            None => return None,
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    let port = match port {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse::<u16>().ok().filter(|&p| p != 0)?,
        Some(_) => return None,
        None => default?,
    };
    Some((Host::parse(host)?, port))
}

/// Reads an absolute `http://` URI.
fn absolute_uri(uri: &str) -> Result<Target, Reject> {
    let lower = uri.get(..8).unwrap_or(uri).to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &uri[7..]
    } else if lower.starts_with("https://") {
        return Err(reject(400, "this proxy takes https:// URLs only through CONNECT"));
    } else if uri.starts_with('/') {
        return Err(reject(400, "this is a proxy: send the full URL (http://host/path), or CONNECT"));
    } else {
        return Err(reject(400, format!("cannot read the URL {uri:?}")));
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority_part, path) = rest.split_at(end);
    // user:password@ in the URL is not for the site.
    let authority_part = authority_part.rsplit_once('@').map_or(authority_part, |(_, a)| a);
    let (host, port) =
        authority(authority_part, Some(80)).ok_or_else(|| reject(400, format!("cannot read the host in {uri:?}")))?;
    let path = path.split('#').next().unwrap_or("");
    let path = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    Ok(Target::Forward { host, port, authority: authority_part.to_owned(), path })
}

/// Whether a head asks to switch protocols, or agrees to: an `Upgrade`
/// field, and `upgrade` among the `Connection` options.
fn upgrades(headers: &[Header]) -> bool {
    let has_upgrade = headers.iter().any(|h| h.name.eq_ignore_ascii_case("upgrade"));
    has_upgrade
        && headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("connection")
                && String::from_utf8_lossy(&h.value).split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
}

/// Header fields that belong to one hop, never passed on: the standard
/// ones, the proxy's own, and any that `Connection` names. The `Upgrade`
/// field of a head that [`upgrades`] is kept: the upgrade goes end to end.
fn hop_by_hop(headers: &[Header]) -> Vec<String> {
    let keep_upgrade = upgrades(headers);
    let mut names: Vec<String> =
        ["connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer", "upgrade"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    for h in headers {
        if h.name.eq_ignore_ascii_case("connection") || h.name.eq_ignore_ascii_case("proxy-connection") {
            for token in String::from_utf8_lossy(&h.value).split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() && !t.eq_ignore_ascii_case("close") && !t.eq_ignore_ascii_case("keep-alive") {
                    names.push(t);
                }
            }
        }
    }
    if keep_upgrade {
        names.retain(|n| n != "upgrade");
    }
    names
}

/// The `Connection` field that ends a forwarded head.
fn connection(headers: &[Header]) -> &'static [u8] {
    if upgrades(headers) { b"Connection: upgrade\r\n\r\n" } else { b"Connection: close\r\n\r\n" }
}

fn push_headers(out: &mut Vec<u8>, headers: &[Header], skip: &[String]) {
    for h in headers {
        if skip.iter().any(|s| h.name.eq_ignore_ascii_case(s)) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&h.value);
        out.extend_from_slice(b"\r\n");
    }
}

/// The request head as the world's site gets it: origin form, no
/// hop-by-hop fields, a `Host` if the client sent none, and
/// `Connection: close`, or `Connection: upgrade` with its `Upgrade` field
/// for a request that asks to switch protocols.
pub fn forward_head(req: &Request) -> Vec<u8> {
    let Target::Forward { authority, path, .. } = &req.target else { unreachable!("only absolute-URI requests are forwarded") };
    let mut out = format!("{} {} {}\r\n", req.head.method, path, req.head.version.as_str()).into_bytes();
    if req.header("host").is_none() {
        out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    push_headers(&mut out, &req.head.headers, &hop_by_hop(&req.head.headers));
    out.extend_from_slice(connection(&req.head.headers));
    out
}

/// An answer's head, rewritten for the client.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    /// The head as the client gets it.
    pub head: Vec<u8>,
    pub status: u16,
    /// A `1xx` answer, with the real one still to come.
    pub interim: bool,
    /// How many bytes of the site's head this was.
    pub len: usize,
}

/// An answer's head from the site, as the client gets it: no hop-by-hop
/// fields, and `Connection: close`; a `101` keeps its `Upgrade` field and
/// says `Connection: upgrade`. Interim answers (`1xx` but `101`) are
/// passed on as they are. `Ok(None)`: not all of it yet.
pub fn rewrite_response(head: &[u8]) -> Result<Option<Answer>, String> {
    let (res, len) = match ResponseHead::parse_lenient(head) {
        Ok(Some(found)) => found,
        Ok(None) => return Ok(None),
        Err(e) => return Err(format!("cannot read the site's answer: {e}")),
    };
    let status = res.status;
    if (100..200).contains(&status) && status != 101 {
        return Ok(Some(Answer { head: head[..len].to_vec(), status, interim: true, len }));
    }
    // The status line as the site sent it, after any empty lines.
    let start = head.iter().position(|b| !matches!(b, b'\r' | b'\n')).unwrap_or(0);
    let line = head[start..len].split(|&b| b == b'\n').next().unwrap_or_default();
    let mut out = line.strip_suffix(b"\r").unwrap_or(line).to_vec();
    out.extend_from_slice(b"\r\n");
    let headers = if status == 101 { res.headers } else { res.headers.into_iter().filter(|h| !h.name.eq_ignore_ascii_case("upgrade")).collect() };
    push_headers(&mut out, &headers, &hop_by_hop(&headers));
    out.extend_from_slice(if status == 101 { connection(&headers) } else { b"Connection: close\r\n\r\n" });
    Ok(Some(Answer { head: out, status, interim: false, len }))
}

/// An answer that ends the exchange, with the reason in
/// `X-Fictionet-Error` and the body. `407` asks for Basic credentials.
pub fn error_response(status: u16, why: &str) -> Vec<u8> {
    let why = why.replace(['\r', '\n'], " ");
    let challenge = if status == 407 { "Proxy-Authenticate: Basic realm=\"fictionet\"\r\n" } else { "" };
    format!(
        "HTTP/1.1 {status} {}\r\n{challenge}X-Fictionet-Error: {why}\r\nContent-Type: text/plain\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{why}\n",
        reason(status),
        why.len() + 1
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn parse(head: &str) -> Result<Request, Reject> {
        parse_request(head.as_bytes()).map(|r| r.expect("a whole head").0)
    }

    #[test]
    fn connect_targets() {
        let r = parse("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n").unwrap();
        assert_eq!(r.target, Target::Connect { host: Host::Name("example.test".into()), port: 443 });
        let r = parse("CONNECT 203.0.113.10:8443 HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(r.target, Target::Connect { host: Host::V4(Ipv4Addr::new(203, 0, 113, 10)), port: 8443 });
        assert_eq!(r.head.version, crate::stdlib::http1::Version::Http10);
        let r = parse("CONNECT [fd00::1]:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.target, Target::Connect { host: Host::V6("fd00::1".parse().unwrap()), port: 443 });
        for bad in ["example.test", "example.test:", "example.test:0", "example.test:65536", "example.test:+1", "[fd00::1]", "a b:1", ":443"] {
            let e = parse(&format!("CONNECT {bad} HTTP/1.1\r\n\r\n")).unwrap_err();
            assert_eq!(e.status, 400, "{bad}");
        }
    }

    #[test]
    fn absolute_uris() {
        let r = parse("GET http://plain.test/x?y=1 HTTP/1.1\r\nHost: plain.test\r\n\r\n").unwrap();
        assert_eq!(
            r.target,
            Target::Forward { host: Host::Name("plain.test".into()), port: 80, authority: "plain.test".into(), path: "/x?y=1".into() }
        );
        let r = parse("GET HTTP://Plain.Test:8080 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            r.target,
            Target::Forward { host: Host::Name("plain.test".into()), port: 8080, authority: "Plain.Test:8080".into(), path: "/".into() }
        );
        let r = parse("GET http://u:p@198.18.0.1?q#frag HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            r.target,
            Target::Forward { host: Host::V4(Ipv4Addr::new(198, 18, 0, 1)), port: 80, authority: "198.18.0.1".into(), path: "/?q".into() }
        );
        assert!(parse("GET https://example.test/ HTTP/1.1\r\n\r\n").unwrap_err().why.contains("CONNECT"));
        assert!(parse("GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err().why.contains("this is a proxy"));
        assert_eq!(parse("GET ftp://x/ HTTP/1.1\r\n\r\n").unwrap_err().status, 400);
        assert_eq!(parse("GET http:///x HTTP/1.1\r\n\r\n").unwrap_err().status, 400);
    }

    #[test]
    fn heads_that_are_partial_bad_or_too_big() {
        assert_eq!(parse_request(b"CONNECT example.test:443 HTTP/1.1\r\nHost: x"), Ok(None));
        assert_eq!(parse_request(b"").unwrap(), None);
        // Another protocol is refused before any line ends.
        assert_eq!(parse_request(b"\x05\x01\x00").unwrap_err().status, 400);
        let many: String = (0..200).map(|i| format!("X-{i}: y\r\n")).collect();
        let e = parse(&format!("GET http://a/ HTTP/1.1\r\n{many}\r\n")).unwrap_err();
        assert_eq!(e.status, 431);
    }

    #[test]
    fn forwarded_heads_drop_hop_by_hop_fields() {
        let r = parse(
            "POST http://plain.test/upload HTTP/1.1\r\nHost: plain.test\r\nProxy-Authorization: Basic eDp5\r\n\
             Proxy-Connection: keep-alive\r\nConnection: keep-alive, X-Secret\r\nX-Secret: 1\r\nKeep-Alive: 5\r\n\
             TE: trailers\r\nUpgrade: h2c\r\nContent-Length: 3\r\nX-Kept: yes\r\n\r\n",
        )
        .unwrap();
        let head = String::from_utf8(forward_head(&r)).unwrap();
        assert_eq!(
            head,
            "POST /upload HTTP/1.1\r\nHost: plain.test\r\nContent-Length: 3\r\nX-Kept: yes\r\nConnection: close\r\n\r\n"
        );
        // No Host: one is added from the URL. HTTP/1.0 stays 1.0.
        let r = parse("GET http://plain.test:81/ HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(String::from_utf8(forward_head(&r)).unwrap(), "GET / HTTP/1.0\r\nHost: plain.test:81\r\nConnection: close\r\n\r\n");
        // A WebSocket handshake keeps its upgrade, both ways.
        let r = parse(
            "GET http://ws.test/echo HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\
             Sec-WebSocket-Key: k\r\nProxy-Authorization: x\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(forward_head(&r)).unwrap(),
            "GET /echo HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\nConnection: upgrade\r\n\r\n"
        );
        let a = rewrite_response(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: a\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(
            String::from_utf8(a.head).unwrap(),
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nsec-websocket-accept: a\r\nConnection: upgrade\r\n\r\n"
        );
    }

    #[test]
    fn answers_are_rewritten() {
        let a = rewrite_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\nhello",
        )
        .unwrap()
        .unwrap();
        assert_eq!(String::from_utf8(a.head).unwrap(), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n");
        assert_eq!((a.status, a.interim, a.len), (200, false, 85));
        let a = rewrite_response(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n").unwrap().unwrap();
        assert_eq!((a.head.as_slice(), a.status, a.interim), (&b"HTTP/1.1 100 Continue\r\n\r\n"[..], 100, true));
        assert_eq!(rewrite_response(b"HTTP/1.1 200 OK\r\nContent-"), Ok(None));
        assert!(rewrite_response(b"garbage\r\n\r\n").is_err());
        // The door relays what the client would take: framing it would
        // refuse as a server is the client's to judge.
        let a = rewrite_response(b"HTTP/1.1 200 OK\nContent-Length: 1\nContent-Length: 2\n\n").unwrap().unwrap();
        assert_eq!(String::from_utf8(a.head).unwrap(), "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
    }

    #[test]
    fn error_answers_say_why() {
        let r = String::from_utf8(error_response(502, "no such name in the world")).unwrap();
        assert!(r.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{r}");
        assert!(r.contains("\r\nX-Fictionet-Error: no such name in the world\r\n"), "{r}");
        assert!(r.ends_with("\r\n\r\nno such name in the world\n"), "{r}");
        assert!(r.contains("Content-Length: 26\r\n"), "{r}");
        let r = String::from_utf8(error_response(407, "no token")).unwrap();
        assert!(r.contains("Proxy-Authenticate: Basic realm=\"fictionet\"\r\n"), "{r}");
        // A reason cannot add header lines.
        let r = String::from_utf8(error_response(502, "a\r\nX-Evil: 1")).unwrap();
        assert!(!r.contains("\r\nX-Evil"), "{r}");
    }
}
