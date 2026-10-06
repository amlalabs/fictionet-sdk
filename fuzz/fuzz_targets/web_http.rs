//! HTTP as `web::Sites` serves it (`httpd::Http1`, and hyper's HTTP/2, through
//! `httpd::serve_connection`), reached the way a sandbox reaches it: a DNS lookup, a
//! TCP connection to the site's machine, and TLS when the input asks for
//! it. The request bytes are the fuzzer's. One more mode sends the bytes to
//! the gateway's DNS server over TCP instead.
#![no_main]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};

use fictionet::Cx;
use fictionet::prelude::*;
use fictionet::stdlib::ConnError;
use fictionet::stdlib::tcp::TcpConnection;
use fictionet_fuzz::web::{Client, NAMES, client_config, serve};
use fictionet_fuzz::{poll_once, settle, world};
use libfuzzer_sys::fuzz_target;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The first byte: bits 0 and 1 pick plain TCP to port 80, or TLS to 443
/// with ALPN `http/1.1`, `h2`, or none; bits 2 to 4 pick the name; bit 5
/// closes the sending side after the bytes; bit 6 puts the HTTP/2 preface
/// in front; bit 7 sends the bytes to the gateway's DNS over TCP instead. The second byte: how many bytes each write takes, 0 for all
/// at once. The rest: the bytes.
struct Input {
    dns: bool,
    mode: u8,
    name: &'static str,
    half_close: bool,
    chunk: usize,
    bytes: Vec<u8>,
}

impl Input {
    fn read(data: &[u8]) -> Option<Input> {
        let [flags, chunk, rest @ ..] = data else { return None };
        let mut bytes = Vec::new();
        if flags & 0x40 != 0 {
            bytes.extend_from_slice(PREFACE);
        }
        bytes.extend_from_slice(rest);
        Some(Input {
            dns: flags & 0x80 != 0,
            mode: flags & 3,
            name: NAMES[(flags >> 2 & 7) as usize % NAMES.len()],
            half_close: flags & 0x20 != 0,
            chunk: *chunk as usize,
            bytes,
        })
    }
}

/// Reads from `conn`, giving the world turns while nothing comes. `None`
/// once it has stayed quiet.
async fn read_quiet(cx: &Cx, conn: &mut TcpConnection, buf: &mut [u8]) -> Option<Result<usize, ConnError>> {
    for _ in 0..64 {
        if let Some(r) = poll_once(conn.read(cx, buf)).await {
            return Some(r);
        }
        settle(cx, 1).await;
    }
    None
}

async fn write_quiet(cx: &Cx, conn: &mut TcpConnection, mut data: &[u8]) -> bool {
    for _ in 0..4096 {
        if data.is_empty() {
            return true;
        }
        match poll_once(conn.write(cx, data)).await {
            Some(Ok(n)) => data = &data[n..],
            Some(Err(_)) => return false,
            None => settle(cx, 1).await,
        }
    }
    false
}

/// TLS on top of the connection, as a client.
struct Tls {
    conn: TcpConnection,
    tls: rustls::ClientConnection,
}

impl Tls {
    async fn flush(&mut self, cx: &Cx) -> bool {
        let mut out = Vec::new();
        while self.tls.wants_write() {
            if self.tls.write_tls(&mut out).is_err() {
                return false;
            }
        }
        write_quiet(cx, &mut self.conn, &out).await
    }

    /// Reads one piece from the connection into rustls. False at the end.
    async fn fill(&mut self, cx: &Cx) -> bool {
        let mut buf = vec![0u8; 16 * 1024];
        match read_quiet(cx, &mut self.conn, &mut buf).await {
            Some(Ok(n)) if n > 0 => {
                let mut at = &buf[..n];
                while !at.is_empty() {
                    match self.tls.read_tls(&mut at) {
                        Ok(0) | Err(_) => return false,
                        Ok(_) => {}
                    }
                    if self.tls.process_new_packets().is_err() {
                        return false;
                    }
                }
                true
            }
            _ => false,
        }
    }

    async fn handshake(&mut self, cx: &Cx) -> bool {
        while self.tls.is_handshaking() {
            if !self.flush(cx).await || !self.fill(cx).await {
                return false;
            }
        }
        self.flush(cx).await
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = Input::read(data) else { return };
    world(move |cx| async move {
        let attacher = serve(&cx);
        let client = Client::new(&cx, &attacher, "agent", Ipv4Addr::new(10, 0, 0, 2));
        let (addr, port) = if input.dns {
            (Ipv4Addr::new(10, 0, 0, 1), 53)
        } else {
            let Some(addr) = client.lookup(&cx, input.name).await else { return };
            (addr, if input.mode == 0 { 80 } else { 443 })
        };
        let Ok(mut conn) = client.tcp.connect(&cx, SocketAddr::new(addr.into(), port)).await else { return };
        let chunk = if input.chunk == 0 { usize::MAX } else { input.chunk };
        if input.mode == 0 || input.dns {
            for piece in input.bytes.chunks(chunk.min(input.bytes.len().max(1))) {
                if !write_quiet(&cx, &mut conn, piece).await {
                    return;
                }
                settle(&cx, 2).await;
            }
            if input.half_close {
                let _ = conn.shutdown(&cx).await;
            }
            let mut buf = vec![0u8; 64 * 1024];
            while let Some(Ok(n)) = read_quiet(&cx, &mut conn, &mut buf).await {
                if n == 0 {
                    break;
                }
            }
            return;
        }
        let alpn: &[&[u8]] = match input.mode {
            1 => &[b"http/1.1"],
            2 => &[b"h2"],
            _ => &[],
        };
        let name = rustls::pki_types::ServerName::try_from(input.name.to_owned()).unwrap();
        let tls = rustls::ClientConnection::new(client_config(alpn), name).unwrap();
        let mut tls = Tls { conn, tls };
        if !tls.handshake(&cx).await {
            return;
        }
        for piece in input.bytes.chunks(chunk.min(input.bytes.len().max(1))) {
            if tls.tls.writer().write_all(piece).is_err() || !tls.flush(&cx).await {
                return;
            }
            settle(&cx, 2).await;
        }
        if input.half_close {
            tls.tls.send_close_notify();
            let _ = tls.flush(&cx).await;
        }
        let mut buf = vec![0u8; 64 * 1024];
        while tls.fill(&cx).await {
            while let Ok(n) = tls.tls.reader().read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
            let _ = tls.flush(&cx).await;
        }
    });
});
