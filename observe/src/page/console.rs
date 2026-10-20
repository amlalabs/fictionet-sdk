use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use fictionet::stdlib::codec::{Side, Stream, Wire};
use fictionet::stdlib::protocols::websocket::{self, Close, Message, Messages};
use fictionet::sync::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{Host, Shared, StateLimits, StateTopic, http, rfb};

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Capability {
    Screen,
    Terminal,
}

struct Ticket {
    host: String,
    capability: Capability,
    session: String,
    expires: Duration,
}

#[derive(Clone, Serialize)]
pub(super) struct Lease {
    holder: Option<String>,
}

#[derive(Default)]
struct Inner {
    tickets: BTreeMap<String, Ticket>,
    active: BTreeMap<String, (String, Capability)>,
    leases: BTreeMap<String, Lease>,
}

pub(super) struct Sessions {
    inner: Mutex<Inner>,
    pub topic: StateTopic<BTreeMap<String, Lease>>,
}

impl Sessions {
    pub fn new(hosts: &[Host]) -> Self {
        let inner = Inner {
            leases: hosts
                .iter()
                .map(|h| (h.name.clone(), Lease { holder: None }))
                .collect(),
            ..Inner::default()
        };
        let topic = StateTopic::new(StateLimits {
            max_bytes: serde_json::to_vec(&inner.leases)
                .expect("lease map is serializable")
                .len()
                + 64 * hosts.len(),
            deltas: 0,
        });
        topic
            .publish(
                fictionet::time::Instant::from_since_start(Duration::ZERO),
                &inner.leases,
            )
            .expect("lease map is serializable");
        Self {
            inner: Mutex::new(inner),
            topic,
        }
    }
    fn publish(&self, inner: &Inner, at: Duration) {
        self.topic
            .publish(
                fictionet::time::Instant::from_since_start(at),
                &inner.leases,
            )
            .expect("lease map is serializable");
    }
    fn holds(&self, host: &str, session: &str) -> bool {
        self.inner
            .lock()
            .leases
            .get(host)
            .is_some_and(|lease| lease.holder.as_deref() == Some(session))
    }
}

fn random() -> io::Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketRequest {
    host: String,
    capability: Capability,
}

pub(super) async fn ticket(
    conn: &mut TcpStream,
    shared: &Shared,
    req: &http::Request,
) -> io::Result<()> {
    let request: TicketRequest = match serde_json::from_slice(&req.body) {
        Ok(value) => value,
        Err(error) => return http::error(conn, 400, &error.to_string()).await,
    };
    let Some(host) = shared.page.hosts.iter().find(|h| h.name == request.host) else {
        return http::error(conn, 404, "no such host").await;
    };
    if !match request.capability {
        Capability::Screen => host.screen,
        Capability::Terminal => host.terminal,
    } {
        return http::error(conn, 404, "host does not offer that console").await;
    }
    let ticket = random()?;
    let session = random()?;
    let now = (shared.page.clock)();
    let added = {
        let mut inner = shared.consoles.inner.lock();
        inner.tickets.retain(|_, t| t.expires > now);
        if inner.tickets.len() >= 64 {
            false
        } else {
            inner.tickets.insert(
                ticket.clone(),
                Ticket {
                    host: request.host,
                    capability: request.capability,
                    session: session.clone(),
                    expires: now.saturating_add(Duration::from_secs(30)),
                },
            );
            true
        }
    };
    if !added {
        return http::error(conn, 503, "too many outstanding tickets").await;
    }
    http::json(
        conn,
        200,
        &serde_json::json!({"ticket":ticket, "session":session, "expires_in":30}),
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRequest {
    host: String,
    session: String,
    #[serde(default)]
    take: bool,
}

pub(super) async fn lease(
    conn: &mut TcpStream,
    shared: &Shared,
    req: &http::Request,
) -> io::Result<()> {
    let request: LeaseRequest = match serde_json::from_slice(&req.body) {
        Ok(value) => value,
        Err(error) => return http::error(conn, 400, &error.to_string()).await,
    };
    let result = {
        let mut inner = shared.consoles.inner.lock();
        if !inner
            .active
            .get(&request.session)
            .is_some_and(|(host, capability)| {
                host == &request.host && *capability == Capability::Screen
            })
        {
            Err((400, "session is not an open screen for this host"))
        } else {
            let lease = inner.leases.get_mut(&request.host).unwrap();
            if req.method == "DELETE" {
                if lease.holder.as_ref() == Some(&request.session) {
                    lease.holder = None;
                }
                let reply = lease.clone();
                shared.consoles.publish(&inner, (shared.page.clock)());
                Ok(reply)
            } else if lease.holder.is_none()
                || lease.holder.as_ref() == Some(&request.session)
                || request.take
            {
                lease.holder = Some(request.session);
                let reply = lease.clone();
                shared.consoles.publish(&inner, (shared.page.clock)());
                Ok(reply)
            } else {
                Err((
                    409,
                    "host input lease is held; send take:true to take control",
                ))
            }
        }
    };
    match result {
        Ok(value) => http::json(conn, 200, &value).await,
        Err((code, error)) => http::error(conn, code, error).await,
    }
}

struct Active<'a> {
    shared: &'a Shared,
    session: String,
    host: String,
}
impl Drop for Active<'_> {
    fn drop(&mut self) {
        let mut inner = self.shared.consoles.inner.lock();
        inner.active.remove(&self.session);
        let lease = inner.leases.get_mut(&self.host).unwrap();
        if lease.holder.as_ref() == Some(&self.session) {
            lease.holder = None;
            self.shared
                .consoles
                .publish(&inner, (self.shared.page.clock)());
        }
    }
}

pub(super) async fn upgrade(
    conn: &mut TcpStream,
    shared: &Shared,
    req: &http::Request,
) -> io::Result<()> {
    if req.origin.is_none() {
        return http::error(conn, 403, "Origin required for WebSockets").await;
    }
    let (capability, name) = if let Some(name) = req.path.strip_prefix("/ws/screen/") {
        (Capability::Screen, name)
    } else if let Some(name) = req.path.strip_prefix("/ws/terminal/") {
        (Capability::Terminal, name)
    } else {
        return http::error(conn, 404, "no such console route").await;
    };
    let upgrade = match websocket::check_request(&req.fields) {
        Ok(value) => value,
        Err(error) => return http::error(conn, 400, &error.to_string()).await,
    };
    let [(key, ticket)] = req.query.as_slice() else {
        return http::error(conn, 401, "one ticket required").await;
    };
    if key != "ticket" {
        return http::error(conn, 401, "one ticket required").await;
    }
    let result = {
        let mut inner = shared.consoles.inner.lock();
        match inner.tickets.remove(ticket) {
            Some(ticket)
                if ticket.host == name
                    && ticket.capability == capability
                    && ticket.expires > (shared.page.clock)() =>
            {
                if inner
                    .active
                    .values()
                    .filter(|(host, cap)| host == name && *cap == capability)
                    .count()
                    >= 4
                {
                    Err((503, "host console session limit reached"))
                } else {
                    inner
                        .active
                        .insert(ticket.session.clone(), (name.into(), capability));
                    Ok(ticket.session)
                }
            }
            _ => Err((401, "invalid, expired or consumed ticket")),
        }
    };
    let session = match result {
        Ok(session) => session,
        Err((code, error)) => return http::error(conn, code, error).await,
    };
    let active = Active {
        shared,
        session,
        host: name.into(),
    };
    let host = shared.page.hosts.iter().find(|h| h.name == name).unwrap();
    let console = host.console.as_ref().unwrap();
    let mut head = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    let protocol = upgrade
        .protocols
        .iter()
        .any(|p| p == "binary")
        .then_some("binary");
    for (name, value) in upgrade
        .response_headers(protocol)
        .map_err(io::Error::other)?
    {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(http::SECURITY);
    head.push_str("\r\n");
    http::write(conn, head.as_bytes()).await?;
    let result = match capability {
        Capability::Screen => match console.screen() {
            Some(open) => match tokio::time::timeout(http::IO_TIMEOUT, open).await {
                Ok(Ok(stream)) => screen(conn, stream, &req.early, &active).await,
                Ok(Err(error)) => Err(error),
                Err(error) => Err(io::Error::other(error)),
            },
            None => Err(io::Error::other("screen is unavailable")),
        },
        Capability::Terminal => match console.terminal(80, 24) {
            Some(open) => match tokio::time::timeout(http::IO_TIMEOUT, open).await {
                Ok(Ok(mut pty)) => {
                    let result = terminal(conn, &mut *pty, &req.early).await;
                    let _ = tokio::time::timeout(http::IO_TIMEOUT, pty.close()).await;
                    result
                }
                Ok(Err(error)) => Err(error),
                Err(error) => Err(io::Error::other(error)),
            },
            None => Err(io::Error::other("terminal is unavailable")),
        },
    };
    let (code, reason) = match result {
        Ok(()) => (1000, String::new()),
        Err(error) => (1008, error.to_string()),
    };
    let mut reason = reason;
    while reason.len() > 123 {
        reason.pop();
    }
    send(conn, Message::Close(Some(Close { code, reason }))).await
}

async fn send(write: &mut (impl AsyncWrite + Unpin), message: Message) -> io::Result<()> {
    let frame = message.to_frame(None).map_err(io::Error::other)?;
    let bytes = Wire::to_bytes(&frame).map_err(io::Error::other)?;
    tokio::time::timeout(http::IO_TIMEOUT, write.write_all(&bytes))
        .await
        .map_err(io::Error::other)?
}

fn messages(limit: usize, early: &[u8]) -> Stream<Messages> {
    let mut messages = Stream::new(Messages::for_receiver(Side::Server).with_limit(limit));
    // The HTTP reader retains at most one read chunk beyond the head.
    let n = messages.push(early);
    assert_eq!(n, early.len());
    messages
}

async fn screen(
    conn: &mut TcpStream,
    stream: Box<dyn super::Duplex>,
    early: &[u8],
    active: &Active<'_>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(conn);
    let (mut output, mut input) = tokio::io::split(stream);
    let mut messages = messages((1 << 20) + 8, early);
    let mut gateway = rfb::Gateway::default();
    let mut bytes = [0; 16 << 10];
    loop {
        while let Some(message) = messages.next() {
            match message.map_err(io::Error::other)? {
                Message::Binary(bytes) => {
                    for byte in bytes {
                        for decision in gateway.feed(&[byte], || {
                            active.shared.consoles.holds(&active.host, &active.session)
                        }) {
                            match decision {
                                rfb::Decision::Pass(bytes) => {
                                    tokio::time::timeout(http::IO_TIMEOUT, input.write_all(&bytes))
                                        .await
                                        .map_err(io::Error::other)??;
                                }
                                rfb::Decision::Drop => {}
                                rfb::Decision::Close(reason) => {
                                    return Err(io::Error::other(reason));
                                }
                            }
                        }
                    }
                }
                Message::Text(_) => {
                    return Err(io::Error::other("screen accepts binary frames only"));
                }
                Message::Ping(bytes) => send(&mut writer, Message::Pong(bytes)).await?,
                Message::Pong(_) => {}
                Message::Close(_) => return Ok(()),
            }
        }
        tokio::select! {
            read = reader.read(messages.spare()) => {
                let n = read?;
                if n == 0 { return Ok(()); }
                messages.commit(n);
            }
            read = output.read(&mut bytes) => {
                let n = read?;
                if n == 0 { return Ok(()); }
                send(&mut writer, Message::Binary(bytes[..n].to_vec())).await?;
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TerminalControl {
    Resize { cols: u16, rows: u16 },
    Ack { bytes: usize },
}

async fn terminal(conn: &mut TcpStream, pty: &mut dyn super::Pty, early: &[u8]) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(conn);
    let mut messages = messages(64 << 10, early);
    let mut unacked = 0usize;
    let mut paused = false;
    loop {
        while let Some(message) = messages.next() {
            match message.map_err(io::Error::other)? {
                Message::Binary(bytes) => {
                    tokio::time::timeout(http::IO_TIMEOUT, pty.write(&bytes))
                        .await
                        .map_err(io::Error::other)??;
                }
                Message::Text(text) => match serde_json::from_str::<TerminalControl>(&text)? {
                    TerminalControl::Resize { cols, rows } => {
                        if cols == 0 || rows == 0 {
                            return Err(io::Error::other("terminal dimensions must be positive"));
                        }
                        tokio::time::timeout(http::IO_TIMEOUT, pty.resize(cols, rows))
                            .await
                            .map_err(io::Error::other)??;
                    }
                    TerminalControl::Ack { bytes } => {
                        unacked = unacked.checked_sub(bytes).ok_or_else(|| {
                            io::Error::other("ack exceeds outstanding terminal bytes")
                        })?;
                        if unacked < 32 << 10 {
                            paused = false;
                        }
                    }
                },
                Message::Ping(bytes) => send(&mut writer, Message::Pong(bytes)).await?,
                Message::Pong(_) => {}
                Message::Close(_) => return Ok(()),
            }
        }
        tokio::select! {
            read = reader.read(messages.spare()) => {
                let n = read?;
                if n == 0 { return Ok(()); }
                messages.commit(n);
            }
            read = pty.read(), if !paused => {
                let Some(bytes) = read? else { return Ok(()); };
                unacked = unacked
                    .checked_add(bytes.len())
                    .ok_or_else(|| io::Error::other("terminal output overflow"))?;
                paused = unacked > 128 << 10;
                for chunk in bytes.chunks(64 << 10) {
                    send(&mut writer, Message::Binary(chunk.to_vec())).await?;
                }
            }
        }
    }
}
