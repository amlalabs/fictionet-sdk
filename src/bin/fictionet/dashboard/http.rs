use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use fictionet::stdlib::codec::ascii::{is_tchar, trim_ows_str};

/// Request-head bytes, including the terminating blank line.
const MAX_HEAD: usize = 16 << 10;

/// A request: only what the dashboard needs of one.
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) host: Option<String>,
    /// `Sec-Fetch-Site` and `Origin`, which browsers send to say which
    /// site a request comes from.
    pub(crate) fetch_site: Option<String>,
    pub(crate) origin: Option<String>,
    pub(super) authorization: Option<String>,
}

pub(crate) fn parse_request(buf: &[u8]) -> Option<Request> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    if end + 4 > MAX_HEAD {
        return None;
    }
    let text = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?;
    let version = first.next()?;
    if method.is_empty()
        || !method.bytes().all(is_tchar)
        || !target.starts_with('/')
        || !target.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || first.next().is_some()
    {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (unescape(k), unescape(v))
        })
        .collect();
    let (mut host, mut fetch_site, mut origin) = (None, None, None);
    let (mut authorization, mut cookie) = (None, None);
    let mut content_length = None;
    for line in lines {
        let (k, v) = line.split_once(':')?;
        if k.is_empty()
            || !k.bytes().all(is_tchar)
            || v.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return None;
        }
        let v = trim_ows_str(v);
        let field = match k.to_ascii_lowercase().as_str() {
            "authorization" => &mut authorization,
            // Cookies never authenticate; retain this only to reject duplicates.
            "cookie" => &mut cookie,
            "host" => &mut host,
            "sec-fetch-site" => &mut fetch_site,
            "origin" => &mut origin,
            "transfer-encoding" => return None,
            "content-length" => {
                if v.is_empty() || !v.bytes().all(|b| b == b'0') {
                    return None;
                }
                &mut content_length
            }
            _ => continue,
        };
        if field.replace(v.to_owned()).is_some() {
            return None;
        }
    }
    Some(Request {
        method,
        path: path.to_owned(),
        query,
        host,
        fetch_site,
        origin,
        authorization,
    })
}

/// Undoes `%xx` and `+` in a query part.
pub(super) fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
                {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a request with this `Host` header may be served.
///
/// Only an IP address, or `localhost`, is accepted. A page on another site
/// could otherwise point a name of its own at 127.0.0.1 and read the
/// dashboard from the viewer's browser (DNS rebinding).
pub(crate) fn host_allowed(host: Option<&str>, bound: SocketAddr) -> bool {
    let Some(host) = host else { return false };
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match name.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip == bound.ip() || bound.ip().is_unspecified(),
        Err(_) => false,
    }
}

/// Whether an API request comes from the dashboard's own page, or from no
/// page at all (a script, curl). A page on another site may still send
/// requests to 127.0.0.1, even if it cannot read the answers; this keeps
/// such requests from starting packet copies.
pub(crate) fn same_site(req: &Request) -> bool {
    if let Some(site) = &req.fetch_site
        && site != "same-origin"
        && site != "none"
    {
        return false;
    }
    match (&req.origin, &req.host) {
        (Some(origin), Some(host)) => origin.split_once("://").is_some_and(|(_, h)| h == host),
        (Some(_), None) => false,
        (None, _) => true,
    }
}

/// Reads one bounded request head before its deadline.
pub(super) fn read_head(
    deadline: Instant,
    mut read: impl FnMut(Duration, &mut [u8]) -> io::Result<usize>,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if end + 4 > MAX_HEAD {
                return Ok(None);
            }
            buf.truncate(end + 4);
            return Ok(Some(buf));
        }
        if buf.len() >= MAX_HEAD {
            return Ok(None);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let n = read(remaining, &mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn only_the_first_request_head_is_read_and_parsed() {
        let head = b"GET /api/keylog HTTP/1.1\r\nHost: evil.example\r\nOrigin: http://evil.example\r\nSec-Fetch-Site: cross-site\r\n\r\n";
        for suffix in [
            b"GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nSec-Fetch-Site: same-origin\r\nAuthorization: Bearer secret\r\nCookie: fictionet_token=secret\r\n\r\n".as_slice(),
            b"Authorization: Bearer secret\r\nCookie: fictionet_token=secret\r\n\r\n",
            b"\xff\x00",
        ] {
            let wire = [head.as_slice(), suffix].concat();
            let req = parse_request(&wire).unwrap();
            assert_eq!(req.path, "/api/keylog");
            assert_eq!(req.host.as_deref(), Some("evil.example"));
            assert_eq!(req.origin.as_deref(), Some("http://evil.example"));
            assert_eq!(req.fetch_site.as_deref(), Some("cross-site"));
            assert!(req.authorization.is_none());
            for split in 0..=wire.len() {
                let mut input = (&wire[..split]).chain(&wire[split..]);
                let result = read_head(Instant::now() + Duration::from_secs(10), |_, chunk| {
                    input.read(chunk)
                })
                .unwrap()
                .unwrap();
                assert_eq!(result, head, "split at {split}");
            }
        }
    }

    #[test]
    fn request_heads_require_valid_lines_and_unambiguous_fields() {
        for line in [
            "GET /",
            "GET / HTTP/2.0",
            "GET / http/1.1",
            "GET / HTTP/1.10",
            "GET / HTTP/1.1 extra",
            "GET  / HTTP/1.1",
            "GET\t/ HTTP/1.1",
            "G(ET / HTTP/1.1",
            " / HTTP/1.1",
            "GET /\t HTTP/1.1",
            "GET /\x7f HTTP/1.1",
            "GET /#fragment HTTP/1.1",
            "GET http://localhost/ HTTP/1.1",
        ] {
            let head = format!("{line}\r\nHost: localhost\r\n\r\n");
            assert!(parse_request(head.as_bytes()).is_none(), "{line:?}");
        }
        for fields in [
            "Host : localhost",
            " Host: localhost",
            ": value",
            "Bad(Name: value",
            "Missing-Colon",
            "X: one\r\n two",
            "X: one\ntwo",
            "X: one\rtwo",
            "X: \x00",
            "X: \x7f",
            "Content-Length: 1",
            "Content-Length: -0",
            "Content-Length:",
            "Content-Length: 0, 0",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: identity",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
        ] {
            let head = format!("GET / HTTP/1.1\r\n{fields}\r\n\r\n");
            assert!(parse_request(head.as_bytes()).is_none(), "{fields:?}");
        }
        for name in [
            "Host",
            "Authorization",
            "Cookie",
            "Origin",
            "Sec-Fetch-Site",
            "Content-Length",
        ] {
            let head = format!(
                "GET / HTTP/1.1\r\n{name}: 0\r\n{}: 0\r\n\r\n",
                name.to_ascii_lowercase()
            );
            assert!(parse_request(head.as_bytes()).is_none(), "{name}");
        }
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: localhost\r\n").is_none());
        for version in ["HTTP/1.0", "HTTP/1.1"] {
            let head = format!(
                "GET / {version}\r\nHost: localhost\r\nContent-Length:\t000 \t\r\nX: a\r\nX: b\r\n\r\n"
            );
            assert!(parse_request(head.as_bytes()).is_some());
        }
    }

    #[test]
    fn the_head_limit_includes_the_terminator_but_not_the_suffix() {
        for size in [(16 << 10) - 1, 16 << 10, (16 << 10) + 1, (16 << 10) + 1024] {
            let mut head = String::from("GET / HTTP/1.1\r\nHost: localhost\r\nX-Padding: ");
            head.push_str(&"x".repeat(size - head.len() - 4));
            head.push_str("\r\n\r\n");
            let wire = format!("{head}ignored suffix");
            assert_eq!(parse_request(wire.as_bytes()).is_some(), size <= 16 << 10);
            for chunk_size in [1, 1023, 1024] {
                let mut input = wire.as_bytes();
                let result = read_head(Instant::now() + Duration::from_secs(10), |_, chunk| {
                    input.read(&mut chunk[..chunk_size])
                })
                .unwrap();
                assert!(
                    result.as_deref() == (size <= 16 << 10).then_some(head.as_bytes()),
                    "size {size}, chunks of {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn header_progress_cannot_extend_the_deadline() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let mut reads = 0;
        let result = read_head(deadline, |remaining, chunk| {
            reads += 1;
            assert_eq!(reads, 1, "read again after the deadline");
            assert!(remaining <= Duration::from_millis(20));
            std::thread::sleep(remaining + Duration::from_millis(1));
            chunk[0] = b'G';
            Ok(1)
        })
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn cross_site_requests_are_told_apart() {
        let req = |extra: &str| {
            parse_request(
                format!("GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1:7878\r\n{extra}\r\n")
                    .as_bytes(),
            )
            .unwrap()
        };
        assert!(same_site(&req("")));
        assert!(same_site(&req(
            "Sec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:7878\r\n"
        )));
        assert!(same_site(&req("Sec-Fetch-Site: none\r\n")));
        assert!(!same_site(&req("Sec-Fetch-Site: cross-site\r\n")));
        assert!(!same_site(&req("Sec-Fetch-Site: same-site\r\n")));
        assert!(!same_site(&req("Origin: https://evil.example\r\n")));
        assert!(!same_site(&req("Origin: http://127.0.0.1:9000\r\n")));
    }

    #[test]
    fn only_addresses_and_localhost_are_allowed_hosts() {
        let lo: SocketAddr = "127.0.0.1:7878".parse().unwrap();
        assert!(host_allowed(Some("127.0.0.1:7878"), lo));
        assert!(host_allowed(Some("localhost:7878"), lo));
        assert!(host_allowed(Some("[::1]:7878"), lo));
        assert!(!host_allowed(Some("evil.example:7878"), lo));
        assert!(!host_allowed(Some("10.0.0.5:7878"), lo));
        assert!(!host_allowed(None, lo));
        let any: SocketAddr = "0.0.0.0:7878".parse().unwrap();
        assert!(host_allowed(Some("10.0.0.5:7878"), any));
        assert!(!host_allowed(Some("evil.example"), any));
    }
}
