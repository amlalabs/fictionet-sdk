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

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::auth::Token;
use super::log;
use super::pump::{self, WorldStream};
use super::stack::{Fail, Host, Stack};

/// The most bytes a request head, or an answer's head, may take.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
/// The most header fields in one head.
const MAX_HEADERS: usize = 128;
/// A client must send its whole request head within this.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a request goes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// `CONNECT host:port`.
    Connect { host: Host, port: u16 },
    /// An absolute URI: `http://authority/path`.
    Forward { host: Host, port: u16, authority: String, path: String },
}

/// A request head, read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) target: Target,
    /// The minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub(crate) version: u8,
    /// Every header field, in order, as sent.
    pub(crate) headers: Vec<(String, Vec<u8>)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }
}

/// An answer that ends the exchange: a status, and why.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Reject {
    pub(crate) status: u16,
    pub(crate) why: String,
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

/// The status a failed connection gets.
pub(crate) fn status_for(fail: &Fail) -> u16 {
    match fail {
        Fail::TimedOut => 504,
        Fail::WorldGone => 503,
        Fail::Dns(_) => 502,
        Fail::NoSuchName | Fail::Refused | Fail::Unreachable(_) | Fail::BadAddress(_) => 502,
    }
}

/// Reads a request head. `Ok(None)`: not all of it yet.
pub(crate) fn parse_request(head: &[u8]) -> Result<Option<(Request, usize)>, Reject> {
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut fields);
    let len = match req.parse(head) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => return Err(reject(431, "too many header fields")),
        Err(e) => return Err(reject(400, format!("cannot read the request: {e}"))),
    };
    let method = req.method.unwrap_or_default().to_owned();
    let path = req.path.unwrap_or_default();
    let version = req.version.unwrap_or(1);
    let target = if method == "CONNECT" {
        let (host, port) = authority(path, None).ok_or_else(|| reject(400, format!("cannot read the CONNECT target {path:?}")))?;
        Target::Connect { host, port }
    } else {
        absolute_uri(path)?
    };
    let headers = req.headers.iter().map(|h| (h.name.to_owned(), h.value.to_vec())).collect();
    Ok(Some((Request { method, target, version, headers }, len)))
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
fn upgrades(headers: &[(String, Vec<u8>)]) -> bool {
    let has_upgrade = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("upgrade"));
    has_upgrade
        && headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("connection") && String::from_utf8_lossy(v).split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
}

/// Header fields that belong to one hop, never passed on: the standard
/// ones, the proxy's own, and any that `Connection` names. The `Upgrade`
/// field of a head that [`upgrades`] is kept: the upgrade goes end to end.
fn hop_by_hop(headers: &[(String, Vec<u8>)]) -> Vec<String> {
    let keep_upgrade = upgrades(headers);
    let mut names: Vec<String> =
        ["connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer", "upgrade"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    for (n, v) in headers {
        if n.eq_ignore_ascii_case("connection") || n.eq_ignore_ascii_case("proxy-connection") {
            for token in String::from_utf8_lossy(v).split(',') {
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
fn connection(headers: &[(String, Vec<u8>)]) -> &'static [u8] {
    if upgrades(headers) { b"Connection: upgrade\r\n\r\n" } else { b"Connection: close\r\n\r\n" }
}

fn push_headers(out: &mut Vec<u8>, headers: &[(String, Vec<u8>)], skip: &[String]) {
    for (n, v) in headers {
        if skip.iter().any(|s| n.eq_ignore_ascii_case(s)) {
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
}

/// The request head as the world's site gets it: origin form, no
/// hop-by-hop fields, a `Host` if the client sent none, and
/// `Connection: close`, or `Connection: upgrade` with its `Upgrade` field
/// for a request that asks to switch protocols.
pub(crate) fn forward_head(req: &Request) -> Vec<u8> {
    let Target::Forward { authority, path, .. } = &req.target else { unreachable!("only absolute-URI requests are forwarded") };
    let mut out = format!("{} {} HTTP/1.{}\r\n", req.method, path, req.version).into_bytes();
    if req.header("host").is_none() {
        out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    push_headers(&mut out, &req.headers, &hop_by_hop(&req.headers));
    out.extend_from_slice(connection(&req.headers));
    out
}

/// An answer's head, rewritten for the client.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The head as the client gets it.
    pub(crate) head: Vec<u8>,
    pub(crate) status: u16,
    /// A `1xx` answer, with the real one still to come.
    pub(crate) interim: bool,
    /// How many bytes of the site's head this was.
    pub(crate) len: usize,
}

/// An answer's head from the site, as the client gets it: no hop-by-hop
/// fields, and `Connection: close`; a `101` keeps its `Upgrade` field and
/// says `Connection: upgrade`. Interim answers (`1xx` but `101`) are
/// passed on as they are. `Ok(None)`: not all of it yet.
pub(crate) fn rewrite_response(head: &[u8]) -> Result<Option<Answer>, String> {
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut res = httparse::Response::new(&mut fields);
    let len = match res.parse(head) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(format!("cannot read the site's answer: {e}")),
    };
    let status = res.code.unwrap_or(0);
    if (100..200).contains(&status) && status != 101 {
        return Ok(Some(Answer { head: head[..len].to_vec(), status, interim: true, len }));
    }
    let line_end = head.windows(2).position(|w| w == b"\r\n").unwrap_or(0);
    let mut out = head[..line_end + 2].to_vec();
    let headers: Vec<(String, Vec<u8>)> = res.headers.iter().map(|h| (h.name.to_owned(), h.value.to_vec())).collect();
    let headers = if status == 101 { headers } else { headers.into_iter().filter(|(n, _)| !n.eq_ignore_ascii_case("upgrade")).collect() };
    push_headers(&mut out, &headers, &hop_by_hop(&headers));
    out.extend_from_slice(if status == 101 { connection(&headers) } else { b"Connection: close\r\n\r\n" });
    Ok(Some(Answer { head: out, status, interim: false, len }))
}

/// An answer that ends the exchange, with the reason in
/// `X-Fictionet-Error` and the body. `407` asks for Basic credentials.
pub(crate) fn error_response(status: u16, why: &str) -> Vec<u8> {
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

/// Reads from `r` into `buf` until `parse` finds a whole head in it.
/// Returns what `parse` returned. `Ok(None)`: the other side closed first.
/// `buf` never grows past [`MAX_HEAD`], so a head that `parse` finds is at
/// most that long; a longer one gets `too_long()`.
async fn read_head<R, T, E>(
    r: &mut R,
    buf: &mut Vec<u8>,
    mut parse: impl FnMut(&[u8]) -> Result<Option<T>, E>,
    too_long: impl FnOnce() -> E,
) -> std::io::Result<Result<Option<T>, E>>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 8192];
    loop {
        if !buf.is_empty() {
            match parse(buf) {
                Ok(Some(t)) => return Ok(Ok(Some(t))),
                Ok(None) => {}
                Err(e) => return Ok(Err(e)),
            }
        }
        if buf.len() >= MAX_HEAD {
            return Ok(Err(too_long()));
        }
        let room = (MAX_HEAD - buf.len()).min(chunk.len());
        let n = r.read(&mut chunk[..room]).await?;
        if n == 0 {
            return Ok(Ok(None));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn answer<W: AsyncWrite + Unpin>(w: &mut W, status: u16, why: &str) {
    let _ = w.write_all(&error_response(status, why)).await;
    let _ = w.shutdown().await;
}

/// Serves one client connection.
pub(crate) async fn serve(mut client: TcpStream, stack: Stack, token: Token) {
    let mut buf = Vec::with_capacity(4096);
    let parsed = tokio::time::timeout(
        HEAD_TIMEOUT,
        read_head(&mut client, &mut buf, parse_request, || reject(431, "the request head is longer than 64 KiB")),
    )
    .await;
    let (req, len) = match parsed {
        Err(_) => {
            log("rejected a request: 408 no whole request head within 30 s");
            return answer(&mut client, 408, "no whole request head within 30 s").await;
        }
        Ok(Err(_)) | Ok(Ok(Ok(None))) => return,
        Ok(Ok(Err(r))) => {
            log(&format!("rejected a request: {} {}", r.status, r.why));
            return answer(&mut client, r.status, &r.why).await;
        }
        Ok(Ok(Ok(Some(found)))) => found,
    };
    let what = match &req.target {
        Target::Connect { host, port } => format!("CONNECT {host}:{port}"),
        Target::Forward { host, port, path, .. } => format!("{} http://{host}:{port}{path}", req.method),
    };
    if !req.header("proxy-authorization").is_some_and(|v| token.check_header(v)) {
        let why = if req.header("proxy-authorization").is_some() { "wrong token" } else { "no token" };
        log(&format!("{what} 407 {why}"));
        return answer(&mut client, 407, &format!("{why}: give the sandbox's token as the proxy password")).await;
    }
    let started = Instant::now();
    let (host, port) = match &req.target {
        Target::Connect { host, port } | Target::Forward { host, port, .. } => (host.clone(), *port),
    };
    let (conn, addr) = match stack.connect(&host, port).await {
        Ok(c) => c,
        Err(fail) => {
            let status = status_for(&fail);
            log(&format!("{what} {status} {fail}"));
            return answer(&mut client, status, &fail.to_string()).await;
        }
    };
    let mut world = WorldStream::new(conn, stack.cx());
    let rest = buf.split_off(len);
    match req.target {
        Target::Connect { .. } => {
            if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
                return log(&format!("{what} ({addr}) 200, but the client closed the connection first"));
            }
            if !rest.is_empty() && world.write_all(&rest).await.is_err() {
                return log(&format!("{what} ({addr}) 200, but the site closed the connection first"));
            }
            let (moved, error) = pump::tunnel(&mut client, &mut world).await;
            let end = error.map(|e| format!(", ended early by {e}")).unwrap_or_default();
            log(&format!(
                "{what} ({addr}) 200, {} bytes up, {} down, {:.3} s{end}",
                moved.up + rest.len() as u64,
                moved.down,
                started.elapsed().as_secs_f64()
            ));
        }
        Target::Forward { .. } => forward(client, world, &req, rest, &what, addr, started).await,
    }
}

/// Sends a plain-HTTP request on and passes the answer back.
async fn forward(
    client: TcpStream,
    world: WorldStream,
    req: &Request,
    body_start: Vec<u8>,
    what: &str,
    addr: std::net::Ipv4Addr,
    started: Instant,
) {
    let (mut cr, mut cw) = client.into_split();
    let (mut wr, mut ww) = tokio::io::split(world);
    let mut head = forward_head(req);
    head.extend_from_slice(&body_start);
    if ww.write_all(&head).await.is_err() {
        log(&format!("{what} ({addr}) 502, the site closed the connection"));
        return answer(&mut cw, 502, "the site closed the connection").await;
    }
    let up = async {
        let n = tokio::io::copy(&mut cr, &mut ww).await;
        let _ = ww.shutdown().await;
        n
    };
    let down = async {
        let mut rbuf = Vec::new();
        let status;
        loop {
            let found = read_head(&mut wr, &mut rbuf, rewrite_response, || "the answer's head is longer than 64 KiB".to_string()).await;
            let Answer { head: out, status: code, interim, len } = match found {
                Ok(Ok(Some(f))) => f,
                Ok(Ok(None)) => {
                    answer(&mut cw, 502, "the site closed the connection without an answer").await;
                    return Err(502);
                }
                Ok(Err(why)) => {
                    answer(&mut cw, 502, &why).await;
                    return Err(502);
                }
                Err(e) => {
                    answer(&mut cw, 502, &format!("reading the site's answer: {e}")).await;
                    return Err(502);
                }
            };
            if cw.write_all(&out).await.is_err() {
                return Err(0);
            }
            rbuf.drain(..len);
            if !interim {
                status = code;
                break;
            }
        }
        if cw.write_all(&rbuf).await.is_err() {
            return Err(status);
        }
        let n = tokio::io::copy(&mut wr, &mut cw).await.unwrap_or(0) + rbuf.len() as u64;
        let _ = cw.shutdown().await;
        Ok((status, n, started.elapsed()))
    };
    let (up, down) = pump::until_down_ends(up, down).await;
    let up = up.and_then(|r| r.ok()).unwrap_or(0) + body_start.len() as u64;
    match down {
        Ok((status, n, took)) => log(&format!(
            "{what} ({addr}) {status}, {up} bytes up, {n} down, {:.3} s",
            took.as_secs_f64()
        )),
        Err(status) => log(&format!("{what} ({addr}) {status}, no answer from the site")),
    }
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
        assert_eq!(r.version, 0);
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
        assert_eq!(parse_request(b"\x05\x01\x00").unwrap_err().status, 400);
        let many: String = (0..200).map(|i| format!("X-{i}: y\r\n")).collect();
        let e = parse(&format!("GET http://a/ HTTP/1.1\r\n{many}\r\n")).unwrap_err();
        assert_eq!(e.status, 431);
    }

    /// Runs `read_head` with `parse_request` on `input`, which arrives in
    /// two parts: no read returns bytes of both. Returns the head's length
    /// and every byte after it, read or not.
    fn read_request(input: &[u8], split: usize) -> Result<(usize, Vec<u8>), Reject> {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let (a, b) = input.split_at(split);
        let mut r = a.chain(b);
        let mut buf = Vec::new();
        rt.block_on(async {
            let (_, len) = read_head(&mut r, &mut buf, parse_request, || reject(431, "too long")).await.unwrap()?.unwrap();
            let mut rest = buf.split_off(len);
            r.read_to_end(&mut rest).await.unwrap();
            Ok((len, rest))
        })
    }

    /// A request head of exactly `len` bytes.
    fn head_of(len: usize) -> Vec<u8> {
        let start = b"GET http://a/ HTTP/1.1\r\nX: ";
        let end = b"\r\n\r\n";
        [&start[..], &vec![b'y'; len - start.len() - end.len()], end].concat()
    }

    #[test]
    fn heads_are_held_to_64_kib() {
        // A head of exactly 64 KiB is read, and what follows it is left
        // for the body.
        let mut input = head_of(MAX_HEAD);
        input.extend_from_slice(b"body");
        assert_eq!(read_request(&input, MAX_HEAD - 1).unwrap(), (MAX_HEAD, b"body".to_vec()));
        // A longer head gets 431, even when its end arrives in the same
        // read as the bytes that take it past the limit.
        for (len, split) in [(MAX_HEAD + 1, 0), (MAX_HEAD + 3, MAX_HEAD - 1), (MAX_HEAD + 4000, MAX_HEAD - 10)] {
            let e = read_request(&head_of(len), split).unwrap_err();
            assert_eq!(e.status, 431, "{len} bytes, split at {split}");
        }
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

    #[test]
    fn failures_map_to_statuses() {
        assert_eq!(status_for(&Fail::NoSuchName), 502);
        assert_eq!(status_for(&Fail::Refused), 502);
        assert_eq!(status_for(&Fail::Unreachable(1)), 502);
        assert_eq!(status_for(&Fail::TimedOut), 504);
        assert_eq!(status_for(&Fail::WorldGone), 503);
    }
}
