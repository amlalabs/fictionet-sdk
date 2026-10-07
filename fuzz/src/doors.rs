//! The bodies of the proxy fuzz targets: the doors' protocol side, in
//! `fictionet::relay::proxy`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use arbitrary::Arbitrary;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use fictionet::relay::proxy::auth::{Token, base64_decode};
use fictionet::relay::proxy::dns;
use fictionet::relay::proxy::http::{Target, error_response, forward_head, parse_request, rewrite_response};
use fictionet::relay::proxy::socks5::handshake;
use fictionet::relay::proxy::Host;
use fictionet::stdlib::http1::{RequestHead, ResponseHead};

/// The HTTP door: a request head, the token check, and the answer's head.
pub fn http(data: &[u8]) {
    let token = Token::new(b"s3cret-token").unwrap();
    if let Ok(Some((req, len))) = parse_request(data) {
        assert!(len <= data.len());
        for h in &req.head.headers {
            if h.name.eq_ignore_ascii_case("proxy-authorization") {
                let _ = token.check_header(&h.value);
            }
        }
        match &req.target {
            Target::Connect { port, .. } => assert_ne!(*port, 0),
            Target::Forward { port, path, .. } => {
                assert_ne!(*port, 0);
                assert!(path.starts_with('/'));
                // The head sent on to the site is one request: the client
                // cannot add lines to it through the target or a field.
                let head = forward_head(&req);
                let text = String::from_utf8_lossy(&head);
                assert!(text.ends_with("Connection: close\r\n\r\n"));
                match RequestHead::parse_lenient(&head) {
                    Ok(Some((_, n))) => assert_eq!(n, head.len()),
                    other => panic!("the forwarded head does not parse: {other:?}\n{text}"),
                }
            }
        }
    }
    let _ = rewrite_response(data);
    let _ = token.check_header(data);
    let _ = base64_decode(data);
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(Host::Name(n)) = Host::parse(s) {
            assert_eq!(dns::normalize(&n).as_deref(), Some(n.as_str()));
            // hickory may still refuse it (a label that starts with a
            // hyphen); the stack then answers "no such name".
            let _ = dns::query(&n, 7);
        }
        // Text from the client reaches a reason only quoted, as `{:?}`.
        let r = error_response(400, &format!("cannot read the URL {s:?}"));
        assert!(matches!(ResponseHead::parse_lenient(&r), Ok(Some(_))), "an error answer does not parse");
    }
}

/// A client stream: its bytes, and the sizes of the reads that give them.
#[derive(Arbitrary, Debug)]
pub struct Input {
    pub pieces: Vec<u8>,
    pub bytes: Vec<u8>,
}

struct Stream {
    bytes: Vec<u8>,
    at: usize,
    pieces: Vec<u8>,
    piece: usize,
    written: Vec<u8>,
}

impl AsyncRead for Stream {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let want = self.pieces.get(self.piece).map_or(usize::MAX, |&n| n.max(1) as usize);
        self.piece += 1;
        let n = want.min(buf.remaining()).min(self.bytes.len() - self.at);
        let at = self.at;
        buf.put_slice(&self.bytes[at..at + n]);
        self.at += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.written.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}


/// The SOCKS5 door: the handshake up to the target.
pub fn socks5(input: Input) {
    let token = Token::new(b"s3cret-token").unwrap();
    let mut s = Stream { bytes: input.bytes, at: 0, pieces: input.pieces, piece: 0, written: Vec::new() };
    // The stream never waits, so the handshake finishes in one poll.
    let result = fictionet::block_on(handshake(&mut s, &token));
    if result.is_ok() {
        // Only a client that gave the token gets a target: the token must
        // be in what it sent, whatever the door answered.
        assert!(s.bytes.windows(12).any(|w| w == b"s3cret-token"), "a target without the token");
        assert!(s.written.ends_with(&[1, 0]), "a target without the login answered: {:?}", s.written);
    }
    assert!(s.written.len() <= 2 + 2 + 10);
}

/// The proxy's resolver reading a datagram from the world's DNS server.
pub fn dns_answer(data: &[u8]) {
    let server: std::net::SocketAddr = "10.0.0.1:53".parse().unwrap();
    // The answer's own ID, so a well-formed answer gets past that check.
    let id = data.get(..2).map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    for name in ["example.test", "a.b.c"] {
        if let Some(Ok((_, ttl))) = dns::answer(data, server, server, name, id) {
            assert!(ttl <= dns::MAX_TTL);
        }
    }
}
