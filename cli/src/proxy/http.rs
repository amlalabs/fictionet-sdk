//! The HTTP door, `--type http_proxy`, served over a client's TCP
//! connection. What it reads and answers is in
//! [`fictionet_cli::attach_proxy::http`].

use std::io;
use std::time::{Duration, Instant};

use fictionet::stdlib::http1::header_line_ok;
use fictionet::stdlib::tcp::TcpConnection;
use fictionet::tokio::{Compat, ConnectionTokioExt};
use fictionet_cli::attach_proxy::auth::Token;
use fictionet_cli::attach_proxy::http::{
    Answer, MAX_HEAD, Reject, Request, Target, error_response, forward_head, parse_request,
    rewrite_response,
};
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

/// Reads from `r` into `buf`, checking each complete line once.
/// Calls `parse` on the start line and on the whole head at its empty line.
/// Checks at most seven bytes of an incomplete start line after each read.
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
    let mut scanned = 0;
    let mut line_start = 0;
    let mut first = true;
    loop {
        while scanned < buf.len() {
            let byte = buf[scanned];
            scanned += 1;
            if byte != b'\n' {
                continue;
            }
            let line = &buf[line_start..scanned - 1];
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            line_start = scanned;
            if first {
                if line.is_empty() {
                    continue;
                }
                // The parser checks the request or status line, without
                // needing a second copy of either grammar here.
                if let Err(e) = parse(&buf[..scanned]) {
                    return Ok(Err(e));
                }
                first = false;
            } else if line.is_empty() {
                return Ok(parse(buf));
            } else {
                if !header_line_ok(line) {
                    // Keep the parser's error wording for malformed fields.
                    match parse(&buf[..scanned]) {
                        Ok(None) => {}
                        result => return Ok(result),
                    }
                }
            }
        }
        if first && line_start < buf.len() {
            // Skip leading empty lines and bound the work before a newline.
            // Seven bytes cover the response prefix "HTTP/1." and the start
            // of a request's method token.
            let end = buf.len().min(line_start + 7);
            match parse(&buf[line_start..end]) {
                Ok(None) => {}
                result => return Ok(result),
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
    #[expect(
        clippy::let_underscore_must_use,
        reason = "every caller has logged the error status; this reply only informs a client that may be gone"
    )]
    let _ = w.write_all(&error_response(status, why)).await;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "every caller has logged the error status; closing a client that may be gone"
    )]
    let _ = w.shutdown().await;
}

/// Serves one client connection.
pub(crate) async fn serve(mut client: TcpStream, stack: Stack, token: Token) {
    let mut buf = Vec::with_capacity(4096);
    let parsed = tokio::time::timeout(
        HEAD_TIMEOUT,
        read_head(&mut client, &mut buf, parse_request, || Reject {
            status: 431,
            why: "the request head is longer than 64 KiB".into(),
        }),
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
        Target::Forward {
            host, port, path, ..
        } => format!("{} http://{host}:{port}{path}", req.head.method),
    };
    if !req
        .header("proxy-authorization")
        .is_some_and(|v| token.check_header(v))
    {
        let why = if req.header("proxy-authorization").is_some() {
            "wrong token"
        } else {
            "no token"
        };
        log(&format!("{what} 407 {why}"));
        return answer(
            &mut client,
            407,
            &format!("{why}: give the sandbox's token as the proxy password"),
        )
        .await;
    }
    let started = Instant::now();
    let (host, port) = match &req.target {
        Target::Connect { host, port } | Target::Forward { host, port, .. } => {
            (host.clone(), *port)
        }
    };
    let (conn, addr) = match stack.connect(&host, port).await {
        Ok(c) => c,
        Err(fail) => {
            let status = status_for(&fail);
            log(&format!("{what} {status} {fail}"));
            return answer(&mut client, status, &fail.to_string()).await;
        }
    };
    let mut world = conn.into_tokio(stack.fcx());
    let rest = buf.split_off(len);
    match req.target {
        Target::Connect { .. } => {
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
            {
                return log(&format!(
                    "{what} ({addr}) 200, but the client closed the connection first"
                ));
            }
            if !rest.is_empty() && world.write_all(&rest).await.is_err() {
                return log(&format!(
                    "{what} ({addr}) 200, but the site closed the connection first"
                ));
            }
            let (moved, error) = pump::tunnel(&mut client, &mut world).await;
            let end = error
                .map(|e| format!(", ended early by {e}"))
                .unwrap_or_default();
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
    mut client: TcpStream,
    world: Compat<TcpConnection>,
    req: &Request,
    body_start: Vec<u8>,
    what: &str,
    addr: std::net::Ipv4Addr,
    started: Instant,
) {
    use pump::Side::{Client, World};

    let (mut cr, mut cw) = client.split();
    let (mut wr, mut ww) = tokio::io::split(world);
    let mut moved = pump::Moved::default();
    let failures = Failures::default();
    let up = async {
        let copied = async {
            ww.write_all(&forward_head(req))
                .await
                .map_err(|e| (World, e))?;
            pump::write_counting(&mut ww, &body_start, &mut moved.up)
                .await
                .map_err(|e| (World, e))?;
            pump::copy_counting(&mut cr, &mut ww, &mut moved.up, Client).await
        }
        .await;
        if let Err((side, e)) = copied {
            failures.record(side, e);
            // A failed upload must still tell the site there are no more bytes.
            if let Err(e) = ww.shutdown().await {
                failures.record(World, e);
            }
        }
    };
    let down = async {
        let response = forward_response(&mut wr, &mut cw, &mut moved.down, &failures).await;
        (response, started.elapsed())
    };
    let (_, (response, took)) =
        pump::until_down_ends(up, down, |(response, _)| !response.reset).await;
    let mut end = failures.suffix();
    if response.reset
        && let Err(e) = client.set_zero_linger()
    {
        end.push_str(&format!(", could not reset the client: {e}"));
    }
    log(&format!(
        "{what} ({addr}) {}, {} bytes up, {} down, {:.3} s{}{end}",
        response.status(),
        moved.up,
        moved.down,
        took.as_secs_f64(),
        if response.no_answer {
            ", no answer from the site"
        } else {
            ""
        },
    ));
}

/// The first reportable failure on each side, recorded before another await
/// can fail or the upload grace can cancel a pending shutdown.
#[derive(Default)]
struct Failures(std::sync::Mutex<[Option<String>; 2]>);

impl Failures {
    fn record(&self, side: pump::Side, e: io::Error) {
        if let Some(why) = side.why(e) {
            let i = match side {
                pump::Side::World => 0,
                pump::Side::Client => 1,
            };
            self.0.lock().unwrap()[i].get_or_insert(why);
        }
    }

    fn suffix(self) -> String {
        let mut end = String::new();
        for why in self.0.into_inner().unwrap().into_iter().flatten() {
            end.push_str(&format!(", ended early by {why}"));
        }
        end
    }
}

#[derive(Default)]
struct Response {
    status: Option<u16>,
    no_answer: bool,
    reset: bool,
}

impl Response {
    fn status(&self) -> String {
        self.status
            .map_or_else(|| "no final response".to_string(), |code| code.to_string())
    }
}

/// Sends the site's response, or a proxy error before the upload grace starts.
async fn forward_response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    wr: &mut R,
    cw: &mut W,
    count: &mut u64,
    failures: &Failures,
) -> Response {
    use pump::Side::{Client, World};

    let mut response = Response::default();
    let copied = async {
        let mut rbuf = Vec::new();
        loop {
            let found = read_head(wr, &mut rbuf, rewrite_response, || {
                "the answer's head is longer than 64 KiB".to_string()
            })
            .await
            .map_err(|e| (World, e))?;
            let Answer {
                head: out,
                status: code,
                interim,
                len,
            } = found
                .map_err(|why| (World, io::Error::new(io::ErrorKind::InvalidData, why)))?
                .ok_or_else(|| {
                    (
                        World,
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the site closed the connection without an answer",
                        ),
                    )
                })?;
            if !interim {
                response.status = Some(code);
            }
            cw.write_all(&out).await.map_err(|e| (Client, e))?;
            rbuf.drain(..len);
            if !interim {
                break;
            }
        }
        pump::write_counting(cw, &rbuf, count)
            .await
            .map_err(|e| (Client, e))?;
        pump::copy_counting(wr, cw, count, World).await
    }
    .await;
    if let Err((side, e)) = copied {
        let why = e.to_string();
        failures.record(side, e);
        if matches!(side, World) && response.status.is_none() {
            // No final head reached the client, so a proxy error can still
            // be sent. Its bytes are not part of the site's body count.
            response.status = Some(502);
            response.no_answer = true;
            let sent = async {
                cw.write_all(&error_response(502, &why)).await?;
                cw.shutdown().await
            }
            .await;
            if let Err(e) = sent {
                failures.record(Client, e);
            }
        } else if matches!(side, World) {
            response.reset = true;
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, pending, poll_fn};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    #[derive(Default)]
    struct Writer {
        bytes: Vec<u8>,
        write_error: Option<io::ErrorKind>,
        shutdown_error: Option<io::ErrorKind>,
        shut: bool,
    }

    impl AsyncWrite for Writer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(kind) = self.write_error {
                return Poll::Ready(Err(kind.into()));
            }
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shut = true;
            Poll::Ready(self.shutdown_error.map_or(Ok(()), |kind| Err(kind.into())))
        }
    }

    #[tokio::test]
    async fn proxy_error_is_sent_before_upload_grace() {
        let mut site = &b""[..];
        let mut client = Writer::default();
        let mut count = 0;
        let failures = Failures::default();
        let mut response = None;
        {
            let down = async {
                response =
                    Some(forward_response(&mut site, &mut client, &mut count, &failures).await);
                response.as_ref().unwrap().reset
            };
            let mut transfer =
                std::pin::pin!(pump::until_down_ends(pending::<()>(), down, |reset| !reset));
            // One poll sends the error and reaches the still-pending upload
            // grace. No clock advance or elapsed-time assertion is needed.
            poll_fn(|cx| {
                assert!(transfer.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        let response = response.expect("download must finish before the upload grace");
        assert_eq!(response.status(), "502");
        assert!(response.no_answer);
        assert!(!response.reset);
        assert_eq!(
            client.bytes,
            error_response(502, "the site closed the connection without an answer")
        );
        assert!(client.shut);
        assert_eq!(count, 0);
        assert!(failures.suffix().contains("ended early by the world"));
    }

    #[tokio::test]
    async fn only_failed_body_skips_upload_grace() {
        struct End {
            reset: bool,
        }

        impl AsyncRead for End {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(if self.reset {
                    Err(io::ErrorKind::ConnectionReset.into())
                } else {
                    Ok(())
                })
            }
        }

        for reset in [false, true] {
            let head = b"HTTP/1.1 200 OK\r\n\r\nbody";
            let mut site = head.as_slice().chain(End { reset });
            let mut client = Writer::default();
            let mut uploaded = Vec::new();
            let mut moved = pump::Moved::default();
            let failures = Failures::default();
            let mut response = None;
            {
                let up = async {
                    pump::write_counting(&mut uploaded, b"prefix", &mut moved.up)
                        .await
                        .unwrap();
                    pending::<()>().await;
                };
                let down = async {
                    response = Some(
                        forward_response(&mut site, &mut client, &mut moved.down, &failures).await,
                    );
                    response.as_ref().unwrap().reset
                };
                let mut transfer = std::pin::pin!(pump::until_down_ends(up, down, |reset| !reset));
                // A failed body must finish in this poll; a complete response
                // must still wait for the pending upload. No clock is advanced.
                poll_fn(|cx| {
                    let result = transfer.as_mut().poll(cx);
                    assert_eq!(result.is_ready(), reset);
                    if let Poll::Ready((up, _)) = result {
                        assert!(up.is_none());
                    }
                    Poll::Ready(())
                })
                .await;
            }
            let response = response.expect("download must finish in the first poll");
            assert_eq!(response.status(), "200");
            assert!(!response.no_answer);
            assert_eq!(response.reset, reset);
            assert!(client.bytes.ends_with(b"\r\n\r\nbody"));
            assert_eq!(client.shut, !reset);
            assert_eq!(uploaded, b"prefix");
            assert_eq!(moved.up, 6);
            assert_eq!(moved.down, 4);
            assert_eq!(
                failures.suffix().contains("ended early by the world"),
                reset
            );
        }
    }

    #[tokio::test]
    async fn failed_interim_head_does_not_claim_a_proxy_error() {
        for kind in [
            io::ErrorKind::Other,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
        ] {
            let mut site = &b"HTTP/1.1 100 Continue\r\n\r\n"[..];
            let mut client = Writer {
                write_error: Some(kind),
                ..Writer::default()
            };
            let mut count = 0;
            let failures = Failures::default();
            let response = forward_response(&mut site, &mut client, &mut count, &failures).await;
            assert_eq!(response.status(), "no final response");
            assert!(!response.no_answer);
            assert!(!response.reset);
            assert!(client.bytes.is_empty());
            assert!(!client.shut);
            assert_eq!(count, 0);
            let end = failures.suffix();
            if kind == io::ErrorKind::Other {
                assert!(end.contains("ended early by the client"), "{end}");
            } else {
                assert!(end.is_empty(), "{end}");
            }
        }
    }

    #[tokio::test]
    async fn proxy_error_write_and_shutdown_failures_are_reported() {
        for writing in [true, false] {
            let mut site = &b""[..];
            let mut client = Writer {
                write_error: writing.then_some(io::ErrorKind::Other),
                shutdown_error: (!writing).then_some(io::ErrorKind::Other),
                ..Writer::default()
            };
            let mut count = 0;
            let failures = Failures::default();
            let response = forward_response(&mut site, &mut client, &mut count, &failures).await;
            assert_eq!(response.status(), "502");
            assert!(response.no_answer);
            assert_eq!(client.shut, !writing);
            assert_eq!(count, 0);
            let end = failures.suffix();
            assert_eq!(end.matches("ended early by the world").count(), 1, "{end}");
            assert_eq!(end.matches("ended early by the client").count(), 1, "{end}");
        }
    }

    #[test]
    fn failures_keep_the_first_per_side_and_report_world_first() {
        use pump::Side::{Client, World};

        let failures = Failures::default();
        failures.record(Client, io::ErrorKind::ConnectionReset.into());
        failures.record(Client, io::ErrorKind::BrokenPipe.into());
        failures.record(Client, io::Error::other("client copy"));
        failures.record(World, io::Error::other("upload copy"));
        failures.record(World, io::Error::other("upload shutdown"));
        failures.record(World, io::Error::other("download copy"));
        failures.record(Client, io::Error::other("client shutdown"));
        assert_eq!(
            failures.suffix(),
            ", ended early by the world: upload copy, ended early by the client: client copy"
        );
    }

    /// Runs `read_head` with `parse_request` on `input`, which arrives in
    /// two parts: no read returns bytes of both. Returns the head's length
    /// and every byte after it, read or not.
    fn read_request(input: &[u8], split: usize) -> Result<(usize, Vec<u8>), Reject> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (a, b) = input.split_at(split);
        let mut r = a.chain(b);
        let mut buf = Vec::new();
        rt.block_on(async {
            let too_long = || Reject {
                status: 431,
                why: "too long".into(),
            };
            let (_, len) = read_head(&mut r, &mut buf, parse_request, too_long)
                .await
                .unwrap()?
                .unwrap();
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

    #[tokio::test]
    async fn fragmented_heads_have_bounded_parsing_work() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::ReadBuf;

        struct Bytes<'a>(&'a [u8]);
        impl AsyncRead for Bytes<'_> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if let Some((&byte, rest)) = self.0.split_first() {
                    buf.put_slice(&[byte]);
                    self.0 = rest;
                }
                Poll::Ready(Ok(()))
            }
        }
        let input = b"\n\r\nGET http://a/ HTTP/1.1\nHost: a\r\nX: one\nY: two\r\n\nbody";
        let mut reader = Bytes(input);
        let mut buf = Vec::new();
        let mut parsed_bytes = 0;
        let mut prefix_bytes = 0;
        let found = read_head(
            &mut reader,
            &mut buf,
            |bytes| {
                if bytes.ends_with(b"\n") {
                    parsed_bytes += bytes.len();
                } else {
                    assert!(bytes.len() <= 7);
                    prefix_bytes += bytes.len();
                }
                parse_request(bytes)
            },
            || panic!("short head"),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(found, parse_request(input).unwrap().unwrap());
        assert_eq!(reader.0, b"body");
        assert!(parsed_bytes <= 2 * found.1, "parsed {parsed_bytes} bytes");
        assert!(
            prefix_bytes <= 7 * found.1,
            "parsed {prefix_bytes} prefix bytes"
        );
    }

    #[tokio::test]
    async fn non_http_prefix_fails_before_the_next_read() {
        let input = b"\x16\x03\x01\0\x01";
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(input).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            read_head(&mut reader, &mut Vec::new(), parse_request, || {
                panic!("short head")
            }),
        )
        .await
        .expect("non-HTTP bytes must fail while the writer remains open")
        .unwrap();
        assert!(result.is_err());
        assert_eq!(result, parse_request(input));
    }

    #[tokio::test]
    async fn incomplete_header_fallback_keeps_reading() {
        let mut reader = (&b"GET / HTTP/1.1\nMissing colon\n"[..]).chain(&b"\n"[..]);
        let result = read_head(
            &mut reader,
            &mut Vec::new(),
            |bytes| Ok::<_, ()>(bytes.ends_with(b"\n\n").then_some(bytes.len())),
            || panic!("short head"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, Some(b"GET / HTTP/1.1\nMissing colon\n\n".len()));
    }

    #[tokio::test]
    async fn complete_invalid_lines_fail_without_a_head_terminator() {
        for input in [
            &b"bad request\n"[..],
            b"GET http://a/ HTTP/1.1\nMissing colon\n",
            b"GET http://a/ HTTP/1.1\nBad Name: value\n",
            b"GET http://a/ HTTP/1.1\nX: bad\0value\n",
        ] {
            let mut reader = input;
            let result = read_head(&mut reader, &mut Vec::new(), parse_request, || {
                panic!("short head")
            })
            .await
            .unwrap();
            assert_eq!(result, parse_request(input));
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn buffered_interim_and_final_answers_keep_the_body() {
        let input = b"\r\nHTTP/1.1 100 Continue\n\nHTTP/1.1 200 OK\r\nX: \xff\r\n\r\nbody";
        let mut buf = input.to_vec();
        let mut reader = &b""[..];
        let interim = read_head(&mut reader, &mut buf, rewrite_response, || {
            panic!("short head")
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(interim.interim);
        assert_eq!(interim.status, 100);
        buf.drain(..interim.len);
        let answer = read_head(&mut reader, &mut buf, rewrite_response, || {
            panic!("short head")
        })
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert!(!answer.interim);
        assert_eq!(answer.status, 200);
        assert_eq!(&buf[answer.len..], b"body");
    }

    #[test]
    fn heads_are_held_to_64_kib() {
        // A head of exactly 64 KiB is read, and what follows it is left
        // for the body.
        let mut input = head_of(MAX_HEAD);
        input.extend_from_slice(b"body");
        assert_eq!(
            read_request(&input, MAX_HEAD - 1).unwrap(),
            (MAX_HEAD, b"body".to_vec())
        );
        // A longer head gets 431, even when its end arrives in the same
        // read as the bytes that take it past the limit.
        for (len, split) in [
            (MAX_HEAD + 1, 0),
            (MAX_HEAD + 3, MAX_HEAD - 1),
            (MAX_HEAD + 4000, MAX_HEAD - 10),
        ] {
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
