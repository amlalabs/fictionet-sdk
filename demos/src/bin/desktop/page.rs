//! The desktop demo's page, on 127.0.0.1: noVNC, embedded in this program,
//! and a WebSocket bridge from the page to the guest's VNC server. The bridge
//! reaches Xvnc, which listens only on the guest's loopback, through the
//! admin's SSH session (a `direct-tcpip` channel, as `ssh -L` opens), so the
//! only service the guest offers its network is sshd.
//!
//! The page and the bridge answer only requests whose `Host` names this
//! listener, and the bridge answers only WebSockets this page opened. The
//! HTTP heads and the WebSocket frames go through the stdlib's codecs.

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use fictionet::stdlib::codec::{AssembleError, Fail, Side, Stream, Wire};
use fictionet::stdlib::protocols::http1::RequestHead;
use fictionet::stdlib::protocols::websocket::{self, Close, Message, Messages};
use russh::ChannelStream;
use russh::client::Msg;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use fictionet_demo::kit::ssh;

/// The page itself, which loads noVNC from `/novnc/`.
const PAGE: &str = include_str!("desktop.html");

/// The longest request head the page reads.
const HEAD_LIMIT: usize = 16 << 10;

/// The path the page opens its WebSocket at.
const SOCKET: &str = "/websockify";

/// Xvnc's port (display :1) on the guest's loopback.
const VNC_PORT: u16 = 5901;

/// The admin's SSH session, once it is up: the bridge's way to the guest.
pub type Tunnel = Arc<OnceLock<Arc<ssh::Session>>>;

/// The listener, bound before the guest boots so a port in use fails early.
pub struct Page {
    listener: TcpListener,
    port: u16,
}

impl Page {
    /// Listens on `port` of 127.0.0.1.
    pub async fn bind(port: u16) -> io::Result<Page> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("127.0.0.1:{port}: {e}")))?;
        let port = listener.local_addr()?.port();
        Ok(Page { listener, port })
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Serves the page, bridging each WebSocket to the guest's VNC server
    /// through `tunnel`'s session, until the task is dropped.
    pub async fn serve(self, tunnel: Tunnel) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        connections.spawn(connection(stream, tunnel.clone(), self.port));
                    }
                    Err(error) => eprintln!("page: accepting a connection: {error}"),
                },
                Some(_) = connections.join_next() => {}
            }
        }
    }
}

async fn connection(stream: TcpStream, tunnel: Tunnel, port: u16) {
    if let Err(error) = request(stream, &tunnel, port).await {
        eprintln!("page: {error}");
    }
}

/// Answers one request, closing the connection after it unless it opens the
/// WebSocket.
async fn request(mut stream: TcpStream, tunnel: &Tunnel, port: u16) -> io::Result<()> {
    let mut buf = Vec::new();
    let (head, used) = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        match RequestHead::parse_lenient(&buf) {
            Ok(Some(parsed)) => break parsed,
            Ok(None) if buf.len() < HEAD_LIMIT => {}
            _ => return respond(&mut stream, 400, "text/plain", b"bad request\n").await,
        }
    };
    let fields: Vec<(String, String)> = head
        .headers
        .iter()
        .map(|h| {
            (
                h.name.clone(),
                String::from_utf8_lossy(&h.value).into_owned(),
            )
        })
        .collect();
    let field = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let ours = |value: Option<&str>, scheme: &str| {
        value.is_some_and(|v| {
            [
                format!("{scheme}127.0.0.1:{port}"),
                format!("{scheme}localhost:{port}"),
            ]
            .iter()
            .any(|allowed| allowed == v)
        })
    };
    if !ours(field("host"), "") {
        return respond(&mut stream, 403, "text/plain", b"forbidden\n").await;
    }
    if head.method != "GET" {
        return respond(&mut stream, 405, "text/plain", b"method not allowed\n").await;
    }
    let path = head.target.split('?').next().unwrap_or_default();
    if path == SOCKET {
        if !ours(field("origin"), "http://") {
            return respond(&mut stream, 403, "text/plain", b"forbidden\n").await;
        }
        return bridge(stream, &fields, &buf[used..], tunnel).await;
    }
    let file = match path {
        "/" => Some(("index.html", PAGE.as_bytes())),
        _ => path.strip_prefix("/novnc/").and_then(|name| {
            fictionet_observe::page::vendored(&format!("novnc/{name}")).map(|bytes| (name, bytes))
        }),
    };
    match file {
        Some((name, bytes)) => respond(&mut stream, 200, content_type(name), bytes).await,
        None => respond(&mut stream, 404, "text/plain", b"not found\n").await,
    }
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        _ => "text/plain; charset=utf-8",
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Bad Gateway",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

/// Completes the WebSocket handshake, opens a tunnel to the guest's VNC
/// server through the SSH session, and carries VNC's bytes both ways as
/// binary messages until either end closes.
async fn bridge(
    mut stream: TcpStream,
    fields: &[(String, String)],
    early: &[u8],
    tunnel: &Tunnel,
) -> io::Result<()> {
    let upgrade = match websocket::check_request(fields) {
        Ok(upgrade) => upgrade,
        Err(error) => {
            return respond(
                &mut stream,
                400,
                "text/plain",
                format!("{error}\n").as_bytes(),
            )
            .await;
        }
    };
    let vnc = match open_tunnel(tunnel, stream.peer_addr()?.port()).await {
        Ok(vnc) => vnc,
        Err(error) => {
            return respond(
                &mut stream,
                502,
                "text/plain",
                format!("{error}\n").as_bytes(),
            )
            .await;
        }
    };
    let protocol = upgrade
        .protocols
        .iter()
        .any(|p| p == "binary")
        .then_some("binary");
    let mut head = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    for (name, value) in upgrade
        .response_headers(protocol)
        .map_err(io::Error::other)?
    {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    let (page_read, page_write) = stream.into_split();
    let (vnc_read, vnc_write) = tokio::io::split(vnc);
    carry(page_read, page_write, early, vnc_read, vnc_write).await
}

/// Forwards to Xvnc on the guest's loopback through the session, for the
/// browser's connection from `originator`'s port.
async fn open_tunnel(tunnel: &Tunnel, originator: u16) -> io::Result<ChannelStream<Msg>> {
    let session = tunnel
        .get()
        .ok_or_else(|| io::Error::other("the guest's SSH session is not up yet"))?;
    session.forward("127.0.0.1", VNC_PORT, originator).await
}

async fn carry(
    mut page_read: OwnedReadHalf,
    mut page_write: OwnedWriteHalf,
    early: &[u8],
    mut vnc_read: impl AsyncRead + Unpin,
    mut vnc_write: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    // A viewer's messages are input events and update requests, a few bytes
    // each; a clipboard paste is the largest.
    let mut messages = Stream::new(Messages::for_receiver(Side::Server).with_limit(1 << 20));
    let mut taken = messages.push(early);
    let mut vnc_buf = vec![0u8; 64 << 10];
    loop {
        while let Some(message) = messages.next() {
            match message {
                Ok(Message::Binary(data)) => vnc_write.write_all(&data).await?,
                Ok(Message::Ping(payload)) => send(&mut page_write, Message::Pong(payload)).await?,
                Ok(Message::Text(_) | Message::Pong(_)) => {}
                Ok(Message::Close(_)) => {
                    return send(&mut page_write, Message::Close(Some(Close::new(1000)))).await;
                }
                Err(error) => {
                    let code = match &error {
                        Fail::Protocol(AssembleError::Inner(e)) => e.close_code(),
                        Fail::Protocol(AssembleError::TooLong { .. }) => 1009,
                        _ => 1002,
                    };
                    let _ = send(&mut page_write, Message::Close(Some(Close::new(code)))).await;
                    return Err(io::Error::other(format!("the page's WebSocket: {error}")));
                }
            }
        }
        if taken < early.len() {
            taken += messages.push(&early[taken..]);
            continue;
        }
        tokio::select! {
            n = page_read.read(messages.spare()) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                messages.commit(n);
            }
            n = vnc_read.read(&mut vnc_buf) => {
                let n = n?;
                if n == 0 {
                    return send(&mut page_write, Message::Close(Some(Close::new(1000)))).await;
                }
                send(&mut page_write, Message::Binary(vnc_buf[..n].to_vec())).await?;
            }
        }
    }
}

/// Sends one message as an unmasked frame, as a server does.
async fn send(write: &mut OwnedWriteHalf, message: Message) -> io::Result<()> {
    let frame = message.to_frame(None).map_err(io::Error::other)?;
    let bytes = Wire::to_bytes(&frame).map_err(io::Error::other)?;
    write.write_all(&bytes).await
}

/// Connects through the page, captures the guest's screen over RFB, and writes
/// it to `out` as a PNG.
pub async fn capture_page(port: u16, out: &Path) -> io::Result<fictionet_demo::kit::rfb::Capture> {
    let (stream, bridge) = WsConn::connect(port).await?.into_stream();
    let result = fictionet_demo::kit::rfb::capture(stream, out).await;
    if result.is_err() {
        bridge.await.map_err(io::Error::other)??;
    } else {
        bridge.abort();
        let _ = bridge.await;
    }
    result
}

/// A WebSocket connection to the page's VNC bridge, carrying RFB bytes as
/// binary messages. The server (the page) sends unmasked frames; this client
/// masks its own, as RFC 6455 requires.
struct WsConn {
    stream: TcpStream,
    messages: Stream<Messages>,
    rx: Vec<u8>,
}

impl WsConn {
    async fn connect(port: u16) -> io::Result<WsConn> {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
        let mut nonce = [0u8; 16];
        fictionet_demo::kit::getrandom(&mut nonce);
        let headers = websocket::request_headers(&format!("127.0.0.1:{port}"), nonce, &["binary"])
            .map_err(io::Error::other)?;
        let mut request = String::from("GET /websockify HTTP/1.1\r\n");
        for (name, value) in &headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!("Origin: http://127.0.0.1:{port}\r\n\r\n"));
        stream.write_all(request.as_bytes()).await?;

        let mut head = Vec::new();
        let body_at = loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::other("the viewer closed before replying"));
            }
            head.extend_from_slice(&chunk[..n]);
            if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            if head.len() > 16 << 10 {
                return Err(io::Error::other("the viewer's reply head was too long"));
            }
        };
        let line = String::from_utf8_lossy(&head[..body_at]);
        let status = line.lines().next().unwrap_or_default();
        if !status.starts_with("HTTP/1.1 101") {
            return Err(io::Error::other(format!(
                "the viewer did not upgrade: {status}"
            )));
        }
        let mut messages = Stream::new(Messages::for_receiver(Side::Client).with_limit(1 << 20));
        let early = head.split_off(body_at);
        let mut taken = 0;
        while taken < early.len() {
            taken += messages.push(&early[taken..]);
        }
        let mut conn = WsConn {
            stream,
            messages,
            rx: Vec::new(),
        };
        conn.drain_messages()?;
        Ok(conn)
    }

    /// Moves any decoded binary-message payloads into the RFB byte buffer.
    fn drain_messages(&mut self) -> io::Result<()> {
        while let Some(message) = self.messages.next() {
            match message.map_err(|e| io::Error::other(format!("the viewer's WebSocket: {e}")))? {
                Message::Binary(data) => self.rx.extend_from_slice(&data),
                Message::Close(_) => return Err(io::Error::other("the viewer closed the stream")),
                _ => {}
            }
        }
        Ok(())
    }

    fn into_stream(
        self,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let (client, bridge) = tokio::io::duplex(64 << 10);
        let task = tokio::spawn(self.bridge(bridge));
        (client, task)
    }

    async fn bridge(mut self, mut stream: tokio::io::DuplexStream) -> io::Result<()> {
        let mut input = [0u8; 16 << 10];
        loop {
            if !self.rx.is_empty() {
                stream.write_all(&self.rx).await?;
                self.rx.clear();
            }
            tokio::select! {
                read = self.stream.read(self.messages.spare()) => {
                    let n = read?;
                    if n == 0 {
                        return Err(io::Error::other("the viewer's WebSocket closed"));
                    }
                    self.messages.commit(n);
                    self.drain_messages()?;
                }
                read = stream.read(&mut input) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }
                    let mut mask = [0u8; 4];
                    fictionet_demo::kit::getrandom(&mut mask);
                    let frame = Message::Binary(input[..n].to_vec())
                        .to_frame(Some(mask))
                        .map_err(io::Error::other)?;
                    let wire = Wire::to_bytes(&frame).map_err(io::Error::other)?;
                    self.stream.write_all(&wire).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn page_capture_reports_websocket_failure() {
        let out = std::env::temp_dir().join(format!("{}.png", fictionet_demo::kit::random_uuid()));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .await
                .unwrap();
            stream.write_all(b"\x82\x0cRFB 003.008\n").await.unwrap();
            let mut banner = [0; 18];
            stream.read_exact(&mut banner).await.unwrap();
            stream.write_all(b"\x88\x00").await.unwrap();
        });
        let error = capture_page(port, &out).await.err().unwrap();
        peer.await.unwrap();
        assert_eq!(error.to_string(), "the viewer closed the stream");
    }
}
