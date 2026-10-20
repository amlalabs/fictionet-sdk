//! Browser authentication and console byte streams for demo gates.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::stdlib::codec::{Side, Stream, Wire};
use fictionet::stdlib::protocols::{
    http1,
    websocket::{self, Message, Messages},
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// A page console capability.
#[derive(Clone, Copy)]
pub enum Capability {
    /// RFB bytes.
    Screen,
    /// Terminal input and output bytes.
    Terminal,
}
impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Self::Screen => "screen",
            Self::Terminal => "terminal",
        }
    }
}

/// A single-use console credential and its input session identity.
pub struct Ticket {
    /// Credential for the WebSocket upgrade.
    pub ticket: String,
    /// Identity used by the page input lease API.
    pub session: String,
}

/// An HTTP reply, including bodies returned for refused requests.
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Complete HTTP status line.
    pub status_line: String,
    /// Decoded response body.
    pub body: Vec<u8>,
}

/// A client for the signed loopback URL printed by a kit run.
pub struct PageClient {
    authority: String,
    token: String,
    port: u16,
}
impl PageClient {
    /// Parses http://127.0.0.1:PORT/#token=HEX (also accepts localhost).
    pub fn from_url(url: impl AsRef<str>) -> io::Result<Self> {
        let invalid =
            || io::Error::other("expected http://127.0.0.1:PORT/#token=HEX from Run::page_url");
        let (authority, token) = url
            .as_ref()
            .strip_prefix("http://")
            .and_then(|s| s.split_once("/#token="))
            .ok_or_else(invalid)?;
        let (host, port) = authority.split_once(':').ok_or_else(invalid)?;
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if !matches!(host, "127.0.0.1" | "localhost")
            || port == 0
            || token.len() != 64
            || !token.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(invalid());
        }
        Ok(Self {
            authority: authority.into(),
            token: token.into(),
            port,
        })
    }

    /// Signs in with the bearer and the page's Origin; requires HTTP 204.
    pub async fn bootstrap(&self) -> io::Result<()> {
        let reply = self.request("POST", "/api/bootstrap", None, true).await?;
        require(&reply, 204)
    }

    /// Sends a plain API request, optionally attaching the run bearer.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        bearer: bool,
    ) -> io::Result<Response> {
        let body = body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
        let mut headers = self.headers(bearer);
        headers.push(http1::Header {
            name: "Content-Length".into(),
            value: body.len().to_string().into_bytes(),
        });
        if !body.is_empty() {
            headers.push(http1::Header {
                name: "Content-Type".into(),
                value: b"application/json".to_vec(),
            });
        }
        let mut stream = self.send(method, path, headers, body).await?;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        let reply = http1::Response::parse(&bytes).map_err(io::Error::other)?;
        Ok(Response {
            status: reply.head.status,
            status_line: status_line(&reply.head),
            body: reply.body,
        })
    }

    /// Sends GET with the bearer and decodes the JSON reply. Any status but 200
    /// is an error that names the path, the status line and the body.
    pub async fn get_json(&self, path: &str) -> io::Result<Value> {
        let reply = self.request("GET", path, None, true).await?;
        require(&reply, 200).map_err(|error| io::Error::other(format!("GET {path}: {error}")))?;
        Ok(serde_json::from_slice(&reply.body)?)
    }

    /// Posts a command to a page control and returns the page's JSON reply.
    /// The reply must be `applied` with HTTP 200 or `rejected` with HTTP 409;
    /// anything else is an error with the status line and the body.
    pub async fn command(
        &self,
        control: &str,
        request_id: &str,
        command: Value,
    ) -> io::Result<Value> {
        let path = format!("/api/command/{control}");
        let body = json!({"request_id": request_id, "command": command});
        let reply = self.request("POST", &path, Some(&body), true).await?;
        let refused = |detail: &dyn std::fmt::Display| {
            io::Error::other(format!("POST {path}: {}: {detail}", reply.status_line))
        };
        let value: Value = serde_json::from_slice(&reply.body)
            .map_err(|_| refused(&String::from_utf8_lossy(&reply.body)))?;
        match (reply.status, value["status"].as_str()) {
            (200, Some("applied")) | (409, Some("rejected")) => Ok(value),
            _ => Err(refused(&value)),
        }
    }

    /// Returns at most 1000 events after sequence number `after`, as the
    /// page's `{"events", "last", "dropped"}` reply.
    pub async fn events(&self, after: u64) -> io::Result<Value> {
        self.get_json(&format!("/api/events?after={after}&max=1000"))
            .await
    }

    /// Reads GET `path` every `interval` until `done` accepts its JSON, and
    /// returns that JSON. `done` can end the wait with its own error. A wait
    /// longer than `timeout` is a `TimedOut` error.
    pub async fn wait_for(
        &self,
        path: &str,
        timeout: Duration,
        interval: Duration,
        mut done: impl FnMut(&Value) -> io::Result<bool>,
    ) -> io::Result<Value> {
        let wait = async {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let value = self.get_json(path).await?;
                if done(&value)? {
                    return Ok(value);
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("GET {path} did not reach the expected state within {timeout:?}"),
            )
        })?
    }

    /// The sequence number of the run's newest event.
    pub async fn last_event(&self) -> io::Result<u64> {
        self.events(0).await?["last"]
            .as_u64()
            .ok_or_else(|| io::Error::other("the events reply has no last sequence number"))
    }

    /// Reads every event after `*cursor`, a page at a time, until `matches`
    /// accepts one, and returns it. The cursor moves past each event read, so
    /// the next call starts after the match. Returns None once no events are
    /// left. `matches` can end the read with its own error.
    pub async fn find_event(
        &self,
        cursor: &mut u64,
        mut matches: impl FnMut(&Value) -> io::Result<bool>,
    ) -> io::Result<Option<Value>> {
        loop {
            let mut batch = self.events(*cursor).await?;
            let Some(events) = batch["events"].as_array_mut() else {
                return Err(io::Error::other("the events reply has no events"));
            };
            if events.is_empty() {
                return Ok(None);
            }
            for event in events.iter_mut() {
                *cursor = event["seq"]
                    .as_u64()
                    .ok_or_else(|| io::Error::other("an event has no sequence number"))?;
                if matches(event)? {
                    return Ok(Some(event.take()));
                }
            }
        }
    }

    /// Reads the events after sequence number `after` every `interval` until
    /// `matches` accepts one, and returns that event. Each read starts after
    /// the last event already read. `matches` can end the wait with its own
    /// error. A wait longer than `timeout` is a `TimedOut` error.
    pub async fn wait_for_event(
        &self,
        after: u64,
        timeout: Duration,
        interval: Duration,
        mut matches: impl FnMut(&Value) -> io::Result<bool>,
    ) -> io::Result<Value> {
        let wait = async {
            let mut cursor = after;
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Some(event) = self.find_event(&mut cursor, &mut matches).await? {
                    return Ok(event);
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no matching event arrived within {timeout:?}"),
            )
        })?
    }

    /// Opens the page's state stream for `topics`, as a browser tab does.
    pub async fn state_stream(&self, topics: &[&str]) -> io::Result<StateStream> {
        if topics.is_empty()
            || topics.iter().any(|topic| {
                topic.is_empty()
                    || !topic
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            })
        {
            return Err(io::Error::other("invalid state topic names"));
        }
        let path = format!("/api/states/stream?topics={}", topics.join(","));
        let stream = self.send("GET", &path, self.headers(true), vec![]).await?;
        let mut stream = StateStream(tokio::io::BufReader::new(stream));
        let mut line = String::new();
        stream.0.read_line(&mut line).await?;
        if !line.starts_with("HTTP/1.1 200 ") {
            return Err(io::Error::other(format!(
                "state stream refused: {}",
                line.trim_end()
            )));
        }
        loop {
            line.clear();
            if stream.0.read_line(&mut line).await? == 0 {
                return Err(io::Error::other("state stream closed in its headers"));
            }
            if line == "\r\n" {
                return Ok(stream);
            }
        }
    }

    /// Requests a single-use credential for a declared host console.
    pub async fn ticket(&self, host: &str, capability: Capability) -> io::Result<Ticket> {
        let reply = self
            .request(
                "POST",
                "/api/ticket",
                Some(&json!({"host":host,"capability":capability.name()})),
                true,
            )
            .await?;
        require(&reply, 200)?;
        let value: Value = serde_json::from_slice(&reply.body)?;
        let field = |name| {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other(format!("ticket reply has no {name}")))
        };
        Ok(Ticket {
            ticket: field("ticket")?,
            session: field("session")?,
        })
    }

    /// Opens masked binary payloads as a byte stream. None exercises a missing credential.
    /// Refused upgrades include the HTTP status line and error body.
    pub async fn open(
        &self,
        host: &str,
        capability: Capability,
        ticket: Option<&str>,
    ) -> io::Result<Socket> {
        let mut nonce = [0; 16];
        super::getrandom(&mut nonce);
        let headers =
            websocket::request_headers(&self.authority, nonce, &[]).map_err(io::Error::other)?;
        let key = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Sec-WebSocket-Key"))
            .unwrap()
            .1
            .clone();
        let mut headers: Vec<_> = headers
            .into_iter()
            .map(|(name, value)| http1::Header {
                name,
                value: value.into_bytes(),
            })
            .collect();
        headers.push(http1::Header {
            name: "Origin".into(),
            value: format!("http://{}", self.authority).into_bytes(),
        });
        if !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            || ticket.is_some_and(|t| !t.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(io::Error::other("invalid console host or credential"));
        }
        let path = format!(
            "/ws/{}/{}{}",
            capability.name(),
            host,
            ticket.map(|t| format!("?ticket={t}")).unwrap_or_default()
        );
        let mut stream = self.send("GET", &path, headers, vec![]).await?;
        let mut bytes = Vec::new();
        let (head, end) = loop {
            if let Some(head) =
                http1::ResponseHead::parse_lenient(&bytes).map_err(io::Error::other)?
            {
                break head;
            }
            if bytes.len() > 16 << 10 {
                return Err(io::Error::other("page response head exceeds 16 KiB"));
            }
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::other("page closed before replying"));
            }
            bytes.extend_from_slice(&chunk[..n]);
        };
        if head.status != 101 {
            stream.read_to_end(&mut bytes).await?;
            let reply = http1::Response::parse(&bytes).map_err(io::Error::other)?;
            return Err(io::Error::other(format!(
                "{}: {}",
                status_line(&head),
                String::from_utf8_lossy(&reply.body)
            )));
        }
        let headers: Vec<_> = head
            .headers
            .iter()
            .map(|h| (h.name.as_str(), String::from_utf8_lossy(&h.value)))
            .collect();
        websocket::check_response(&headers, &key, &[]).map_err(io::Error::other)?;
        Ok(Socket::new(stream, bytes.split_off(end), capability))
    }

    fn headers(&self, bearer: bool) -> Vec<http1::Header> {
        let mut values = vec![
            ("Host", self.authority.clone()),
            ("Origin", format!("http://{}", self.authority)),
        ];
        if bearer {
            values.push(("Authorization", format!("Bearer {}", self.token)));
        }
        values
            .into_iter()
            .map(|(name, value)| http1::Header {
                name: name.into(),
                value: value.into_bytes(),
            })
            .collect()
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: Vec<http1::Header>,
        body: Vec<u8>,
    ) -> io::Result<TcpStream> {
        let request = http1::Request {
            head: http1::RequestHead {
                method: method.into(),
                target: path.into(),
                version: http1::Version::Http11,
                headers,
            },
            body,
        };
        let wire = request.to_bytes().map_err(io::Error::other)?;
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, self.port)).await?;
        stream.write_all(&wire).await?;
        Ok(stream)
    }
}
fn status_line(head: &http1::ResponseHead) -> String {
    format!(
        "HTTP/1.1 {} {}",
        head.status,
        String::from_utf8_lossy(&head.reason)
    )
}
fn require(reply: &Response, status: u16) -> io::Result<()> {
    if reply.status == status {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{}: {}",
            reply.status_line,
            String::from_utf8_lossy(&reply.body)
        )))
    }
}

/// A page's state stream: each topic's snapshots as the page publishes them.
pub struct StateStream(tokio::io::BufReader<TcpStream>);
impl StateStream {
    /// The longest line the stream may send.
    const MAX_LINE: usize = 128 << 10;

    /// Waits up to 10 s for a snapshot of `topic` that `matches` accepts,
    /// and returns it. A snapshot over the topic's bound, or a line over
    /// 128 KiB, is an error.
    pub async fn next(
        &mut self,
        topic: &str,
        matches: impl Fn(&Value) -> bool,
    ) -> io::Result<Value> {
        let read = async {
            loop {
                let mut line = String::new();
                if self.0.read_line(&mut line).await? == 0 {
                    return Err(io::Error::other("state stream closed"));
                }
                if line.len() > Self::MAX_LINE {
                    return Err(io::Error::other("state stream line exceeds its bound"));
                }
                let Some(data) = line.strip_prefix("data: ") else {
                    continue;
                };
                let snapshot: Value = serde_json::from_str(data.trim())?;
                if snapshot["topic"] != topic {
                    continue;
                }
                if snapshot["status"]["too_large"] != false {
                    return Err(io::Error::other(format!(
                        "state stream: {topic} exceeded its bound"
                    )));
                }
                if matches(&snapshot) {
                    return Ok(snapshot);
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("the state stream showed no matching {topic} snapshot within 10 s"),
                )
            })?
    }
}

/// Binary WebSocket payloads. Dropping the stream cancels its connection task.
pub struct Socket {
    stream: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<()>,
    error: Arc<Mutex<Option<io::Error>>>,
}
impl Socket {
    fn new(stream: TcpStream, early: Vec<u8>, capability: Capability) -> Self {
        let (client, bridge) = tokio::io::duplex(64 << 10);
        let error = Arc::new(Mutex::new(None));
        let failure = error.clone();
        let task = tokio::spawn(async move {
            let mut bridge = bridge;
            if let Err(error) = bridge_socket(stream, &mut bridge, early, capability).await {
                *failure.lock().unwrap() = Some(error);
            }
        });
        Self {
            stream: client,
            task,
            error,
        }
    }
}
impl Socket {
    /// Reads until `expected` appears in the output, keeping only enough
    /// bytes to match across reads. Fails if the socket closes first or
    /// `max_bytes` arrive without a match.
    pub async fn read_until(&mut self, expected: &[u8], max_bytes: usize) -> io::Result<()> {
        let mut window = Vec::new();
        let mut chunk = [0; 4096];
        let mut read = 0;
        loop {
            let n = self.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "the console closed before showing {:?}",
                        String::from_utf8_lossy(expected)
                    ),
                ));
            }
            read += n;
            window.extend_from_slice(&chunk[..n]);
            if window
                .windows(expected.len())
                .any(|bytes| bytes == expected)
            {
                return Ok(());
            }
            if read > max_bytes {
                return Err(io::Error::other(format!(
                    "the console showed {read} bytes without {:?}",
                    String::from_utf8_lossy(expected)
                )));
            }
            window.drain(
                ..window
                    .len()
                    .saturating_sub(expected.len().saturating_sub(1)),
            );
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.stream).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => {
                Poll::Ready(self.error.lock().unwrap().take().map_or(Ok(()), Err))
            }
            result => result,
        }
    }
}
impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
async fn send_message(stream: &mut TcpStream, message: Message) -> io::Result<()> {
    let mut mask = [0; 4];
    super::getrandom(&mut mask);
    let wire = message
        .to_frame(Some(mask))
        .map_err(io::Error::other)?
        .to_bytes()
        .map_err(io::Error::other)?;
    stream.write_all(&wire).await
}
async fn bridge_socket(
    mut socket: TcpStream,
    stream: &mut tokio::io::DuplexStream,
    early: Vec<u8>,
    capability: Capability,
) -> io::Result<()> {
    let mut messages = Stream::new(Messages::for_receiver(Side::Client).with_limit(2 << 20));
    let mut pending = early.as_slice();
    let mut input = [0; 16 << 10];
    loop {
        if !pending.is_empty() {
            let n = messages.push(pending);
            pending = &pending[n..];
        }
        while let Some(message) = messages.next() {
            match message.map_err(io::Error::other)? {
                Message::Binary(data) => {
                    stream.write_all(&data).await?;
                    if matches!(capability, Capability::Terminal) {
                        send_message(
                            &mut socket,
                            Message::Text(json!({"type":"ack","bytes":data.len()}).to_string()),
                        )
                        .await?;
                    }
                }
                Message::Ping(data) => send_message(&mut socket, Message::Pong(data)).await?,
                Message::Close(close) => {
                    return Err(io::Error::other(format!(
                        "page WebSocket closed: {close:?}"
                    )));
                }
                Message::Pong(_) => {}
                Message::Text(_) => return Err(io::Error::other("expected binary console output")),
            }
        }
        if !pending.is_empty() {
            continue;
        }
        tokio::select! {
            read = socket.read(messages.spare()) => {
                let n = read?; if n == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "page WebSocket disconnected without a close frame")); } messages.commit(n);
            }
            read = stream.read(&mut input) => {
                let n = read?; if n == 0 { return Ok(()); }
                send_message(&mut socket, Message::Binary(input[..n].to_vec())).await?;
            }
        }
    }
}
