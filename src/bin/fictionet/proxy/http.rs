//! The HTTP door, `--type https_proxy`, served over a client's TCP
//! connection. What it reads and answers is in
//! [`fictionet::relay::proxy::http`].

use std::time::{Duration, Instant};

use fictionet::relay::proxy::auth::Token;
use fictionet::relay::proxy::http::{Answer, MAX_HEAD, Reject, Request, Target, error_response, forward_head, parse_request, rewrite_response};
use fictionet::stdlib::tcp::TcpConnection;
use fictionet::tokio::{Compat, ConnectionTokioExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::log;
use super::pump;
use super::stack::{Fail, Stack};

/// A client must send its whole request head within this.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// The status a failed connection gets.
pub(crate) fn status_for(fail: &Fail) -> u16 {
    match fail {
        Fail::TimedOut => 504,
        Fail::WorldGone => 503,
        Fail::Dns(_) => 502,
        Fail::NoSuchName | Fail::Refused | Fail::Unreachable(_) | Fail::BadAddress(_) => 502,
    }
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
        read_head(&mut client, &mut buf, parse_request, || Reject { status: 431, why: "the request head is longer than 64 KiB".into() }),
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
        Target::Forward { host, port, path, .. } => format!("{} http://{host}:{port}{path}", req.head.method),
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
    let mut world = conn.into_tokio(stack.cx());
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
    world: Compat<TcpConnection>,
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

    /// Runs `read_head` with `parse_request` on `input`, which arrives in
    /// two parts: no read returns bytes of both. Returns the head's length
    /// and every byte after it, read or not.
    fn read_request(input: &[u8], split: usize) -> Result<(usize, Vec<u8>), Reject> {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let (a, b) = input.split_at(split);
        let mut r = a.chain(b);
        let mut buf = Vec::new();
        rt.block_on(async {
            let too_long = || Reject { status: 431, why: "too long".into() };
            let (_, len) = read_head(&mut r, &mut buf, parse_request, too_long).await.unwrap()?.unwrap();
            let mut rest = buf.split_off(len);
            r.read_to_end(&mut rest).await.unwrap();
            Ok((len, rest))
        })
    }

    /// A request head of exactly `len` bytes.
    fn head_of(len: usize) -> Vec<u8> {
        let start = b"GET http://a/ HTTP/1.1\r\nHost: a\r\nX: ";
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
    fn failures_map_to_statuses() {
        assert_eq!(status_for(&Fail::NoSuchName), 502);
        assert_eq!(status_for(&Fail::Refused), 502);
        assert_eq!(status_for(&Fail::Unreachable(1)), 502);
        assert_eq!(status_for(&Fail::TimedOut), 504);
        assert_eq!(status_for(&Fail::WorldGone), 503);
    }
}
