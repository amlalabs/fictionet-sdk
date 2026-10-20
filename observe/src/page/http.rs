use std::io;
use std::time::Duration;

use fictionet::stdlib::codec::ascii::{is_tchar, trim_ows_str};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) const MAX_HEAD: usize = 16 << 10;
pub(super) const MAX_BODY: usize = 64 << 10;
pub(super) const IO_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const SECURITY: &str = concat!(
    "Content-Security-Policy: default-src 'none'; ",
    "script-src 'self'; ",
    "style-src 'self'; ",
    "img-src 'self' data: blob:; ",
    "font-src 'self'; ",
    "connect-src 'self'; ",
    "frame-ancestors 'none'; ",
    "base-uri 'none'; ",
    "form-action 'none'\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cache-Control: no-store\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
);

pub(super) struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub host: Option<String>,
    pub origin: Option<String>,
    pub fetch_site: Option<String>,
    pub authorization: Option<String>,
    pub upgrade: Option<String>,
    pub length: usize,
    pub body: Vec<u8>,
    pub fields: Vec<(String, String)>,
    pub early: Vec<u8>,
}

pub(super) fn parse_request(buf: &[u8]) -> Option<Request> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    if end + 4 > MAX_HEAD {
        return None;
    }
    let text = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?;
    let target = first.next()?;
    let version = first.next()?;
    if method.is_empty()
        || !method.bytes().all(is_tchar)
        || !target.starts_with('/')
        || !target.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
        || version != "HTTP/1.1"
        || first.next().is_some()
    {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut req = Request {
        method: method.into(),
        path: path.into(),
        query: query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let (k, v) = s.split_once('=').unwrap_or((s, ""));
                Some((unescape(k)?, unescape(v)?))
            })
            .collect::<Option<_>>()?,
        host: None,
        origin: None,
        fetch_site: None,
        authorization: None,
        upgrade: None,
        length: 0,
        body: Vec::new(),
        fields: Vec::new(),
        early: Vec::new(),
    };
    let (mut cookie, mut length) = (None, None);
    for line in lines {
        let (k, v) = line.split_once(':')?;
        if k.is_empty()
            || !k.bytes().all(is_tchar)
            || v.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return None;
        }
        let v = trim_ows_str(v);
        req.fields.push((k.to_owned(), v.to_owned()));
        let field = match k.to_ascii_lowercase().as_str() {
            "host" => &mut req.host,
            "origin" => &mut req.origin,
            "sec-fetch-site" => &mut req.fetch_site,
            "authorization" => &mut req.authorization,
            "cookie" => &mut cookie,
            "upgrade" => &mut req.upgrade,
            "content-length" => {
                if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                req.length = v.parse().ok()?;
                if req.length > MAX_BODY {
                    return None;
                }
                &mut length
            }
            "transfer-encoding" => return None,
            _ => continue,
        };
        if field.replace(v.to_owned()).is_some() {
            return None;
        }
    }
    if matches!(method, "POST" | "DELETE") && length.is_none() {
        return None;
    }
    Some(req)
}

fn unescape(s: &str) -> Option<String> {
    let mut bytes = s.bytes();
    let mut out = Vec::with_capacity(s.len());
    while let Some(b) = bytes.next() {
        out.push(match b {
            b'+' => b' ',
            b'%' => {
                let a = (bytes.next()? as char).to_digit(16)?;
                let b = (bytes.next()? as char).to_digit(16)?;
                (a * 16 + b) as u8
            }
            b => b,
        });
    }
    String::from_utf8(out).ok()
}

pub(super) fn allowed(req: &Request, port: u16) -> bool {
    let ip = format!("127.0.0.1:{port}");
    let name = format!("localhost:{port}");
    if !matches!(req.host.as_deref(), Some(h) if h == ip || h == name)
        || req
            .fetch_site
            .as_deref()
            .is_some_and(|s| s != "same-origin" && s != "none")
    {
        return false;
    }
    match &req.origin {
        Some(origin) => origin == &format!("http://{ip}") || origin == &format!("http://{name}"),
        None => !matches!(req.method.as_str(), "POST" | "DELETE") && req.upgrade.is_none(),
    }
}

pub(super) async fn read_request(
    conn: &mut (impl AsyncRead + Unpin),
    timeout: Duration,
) -> io::Result<Option<Request>> {
    tokio::time::timeout(timeout, async {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0; 1024];
        let end = loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
            if buf.len() >= MAX_HEAD {
                return Ok(None);
            }
            let n = conn.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let Some(mut req) = parse_request(&buf) else {
            return Ok(None);
        };
        req.body
            .extend_from_slice(&buf[end..][..req.length.min(buf.len() - end)]);
        req.early.extend_from_slice(&buf[end + req.body.len()..]);
        let read = req.body.len();
        req.body.resize(req.length, 0);
        conn.read_exact(&mut req.body[read..]).await?;
        Ok(Some(req))
    })
    .await
    .map_err(io::Error::other)?
}

/// Resolves when a stream's client closes its connection. The client sends
/// nothing after its request, so any further bytes also end the stream.
/// Without this, a closed stream would hold its place until a write failed.
pub(super) async fn hangup(conn: &TcpStream) {
    let mut byte = [0; 1];
    loop {
        if conn.readable().await.is_err() {
            return;
        }
        match conn.try_read(&mut byte) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            _ => return,
        }
    }
}

pub(super) async fn write(conn: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    tokio::time::timeout(IO_TIMEOUT, conn.write_all(bytes))
        .await
        .map_err(io::Error::other)?
}

pub(super) async fn headers(
    conn: &mut TcpStream,
    status: u16,
    kind: &str,
    extra: &str,
) -> io::Result<()> {
    headers_with_policy(conn, status, kind, extra, SECURITY).await
}

async fn headers_with_policy(
    conn: &mut TcpStream,
    status: u16,
    kind: &str,
    extra: &str,
    security: &str,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\n{security}{extra}\
         Connection: close\r\n\r\n"
    );
    write(conn, head.as_bytes()).await
}

pub(super) async fn page(conn: &mut TcpStream) -> io::Result<()> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let body = super::assets::HTML.replace("PAGE_NONCE", &nonce);
    // xterm injects style elements; style attributes in markup remain blocked.
    let security = SECURITY
        .replace(
            "script-src 'self';",
            &format!("script-src 'self' 'nonce-{nonce}';"),
        )
        .replace(
            "style-src 'self';",
            "style-src 'self'; style-src-elem 'self' 'unsafe-inline';",
        );
    headers_with_policy(
        conn,
        200,
        "text/html; charset=utf-8",
        &format!("Content-Length: {}\r\n", body.len()),
        &security,
    )
    .await?;
    write(conn, body.as_bytes()).await
}

pub(super) async fn respond(
    conn: &mut TcpStream,
    status: u16,
    kind: &str,
    body: &[u8],
) -> io::Result<()> {
    let framing = if status == 204 {
        String::new()
    } else {
        format!("Content-Length: {}\r\n", body.len())
    };
    headers(conn, status, kind, &framing).await?;
    write(conn, body).await
}

pub(super) async fn json(
    conn: &mut TcpStream,
    status: u16,
    value: &impl serde::Serialize,
) -> io::Result<()> {
    respond(
        conn,
        status,
        "application/json",
        &serde_json::to_vec(value)?,
    )
    .await
}

pub(super) async fn error(conn: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    json(
        conn,
        status,
        &super::ErrorReply {
            error: message.into(),
        },
    )
    .await
}
