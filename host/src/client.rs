//! The host HTTP/1.1 client behind `web::proxy` and `web::forward`.
//!
//! Each exchange runs on a helper thread that drives one nonblocking socket
//! with poll(2). It connects, does TLS, and writes the request while it
//! reads the response, so a server that answers early or echoes the upload
//! keeps going. The world's future and the thread pass request and response
//! pieces through one-slot channels, and an eventfd wakes the thread when
//! the world puts or takes a piece or drops the exchange. Name lookups run
//! on a small pool of their own, since getaddrinfo(3) cannot be interrupted.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body::{Body as _, Frame, SizeHint};

use fictionet::Error;
use fictionet::stdlib::codec::{Decode, Fail, Step, Stream, Wire};
use fictionet::stdlib::{protocols::http1, web::httpd::Body};
use fictionet::sync::Mutex;

/// The most exchanges one client runs at once. Each holds a host thread and
/// a socket while its response streams, and the agent decides how many
/// requests to start, so later ones wait for a free slot.
const EXCHANGES: usize = 64;
/// Threads for name lookups, shared by every client. A lookup that a
/// dropped request left behind keeps its thread until the resolver answers.
const RESOLVERS: usize = 4;
/// The time to look up the name, connect and finish the TLS handshake.
/// After that nothing times out, as with hyper before. A model API may
/// think for minutes before it answers, and an event stream may be quiet
/// for as long.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long one connection attempt runs before the next address starts
/// alongside it (RFC 8305 section 5).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// How long an idle connection stays pooled.
const IDLE_FOR: Duration = Duration::from_secs(90);
/// The largest piece of request body handed to the thread at once, and the
/// most bytes the thread holds for the socket before it takes another.
const PIECE: usize = 64 * 1024;
/// The largest response head, and the longest line in one. Real sites send
/// long Content-Security-Policy fields and dozens of Set-Cookie fields.
/// hyper, which this client replaced, took heads of about 400 KiB with no
/// limit on a line.
const HEAD: usize = 400 * 1024;

/// A bounded HTTP/1.1 client using host DNS, sockets and verified TLS.
pub struct Client {
    tls: Arc<rustls::ClientConfig>,
    idle: Mutex<Vec<Idle>>,
    slots: Mutex<Slots>,
    exchanges: usize,
    connect_timeout: Duration,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl fictionet::stdlib::web::Upstream for Client {
    fn request(self: Arc<Self>, request: Request<Body>) -> fictionet::stdlib::web::UpstreamFuture {
        Box::pin(self.send(request))
    }
}

struct Idle {
    origin: String,
    since: Instant,
    conn: Connection,
}

#[derive(Default)]
struct Slots {
    busy: usize,
    waiting: Vec<Waker>,
}

/// What the thread needs to know about one request.
struct Job {
    origin: String,
    host: String,
    port: u16,
    tls: bool,
    method: Method,
    head: Vec<u8>,
    /// The body's length, or `None` to send it chunked.
    length: Option<u64>,
}

type Event = http1::Event<http1::ResponseHead>;

impl Client {
    /// Creates a client with the Mozilla root store.
    pub fn new() -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: Arc::new(tls),
            idle: Mutex::default(),
            slots: Mutex::default(),
            exchanges: EXCHANGES,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

    async fn send(self: Arc<Self>, request: Request<Body>) -> Result<Response<Body>, Error> {
        let (mut parts, body) = request.into_parts();
        let authority = parts
            .uri
            .authority()
            .ok_or_else(|| Error::msg("missing upstream authority"))?
            .clone();
        if !parts.headers.contains_key(http::header::HOST) {
            parts
                .headers
                .insert(http::header::HOST, authority.as_str().parse()?);
        }
        let declared = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .map(|v| v.to_str()?.parse::<u64>().map_err(Error::from))
            .transpose()?;
        let length = declared.or_else(|| body.size_hint().exact());
        match length {
            // An empty request whose method expects no content says nothing
            // about its length (RFC 9110 section 8.6).
            Some(0) if declared.is_none() && !expects_content(&parts.method) => {}
            Some(length) => {
                parts
                    .headers
                    .insert(http::header::CONTENT_LENGTH, length.into());
            }
            None => {
                parts.headers.insert(
                    http::header::TRANSFER_ENCODING,
                    http::HeaderValue::from_static("chunked"),
                );
            }
        }
        let wire = http1::RequestHead {
            method: parts.method.to_string(),
            target: parts
                .uri
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_owned(),
            version: http1::Version::Http11,
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| http1::Header {
                    name: name.to_string(),
                    value: value.as_bytes().to_vec(),
                })
                .collect(),
        }
        .to_bytes()?;
        // Preserve the conventional header spacing sent by the upstream client.
        let mut head = Vec::with_capacity(wire.len() + parts.headers.len());
        for (index, line) in wire.split_inclusive(|b| *b == b'\n').enumerate() {
            if index != 0
                && let Some(colon) = line.iter().position(|b| *b == b':')
            {
                head.extend_from_slice(&line[..=colon]);
                head.push(b' ');
                head.extend_from_slice(&line[colon + 1..]);
            } else {
                head.extend_from_slice(line);
            }
        }
        let tls = parts.uri.scheme_str() == Some("https");
        let job = Job {
            origin: format!("{}://{authority}", parts.uri.scheme_str().unwrap_or("http")),
            host: authority.host().trim_matches(['[', ']']).to_owned(),
            port: authority.port_u16().unwrap_or(if tls { 443 } else { 80 }),
            tls,
            method: parts.method.clone(),
            head,
            length,
        };
        let head_only = parts.method == Method::HEAD;

        let permit = self.permit().await;
        let signal = Arc::new(Signal::new()?);
        let (sender, incoming) = channel();
        let (outgoing, mut download) = channel();
        let abort = Abort(signal.clone());
        std::thread::Builder::new()
            .name("fictionet-upstream".into())
            .spawn(move || {
                let _permit = permit;
                if let Err(error) = self.exchange(job, incoming, &outgoing, &signal) {
                    let _ = fictionet::block_on(outgoing.send(Err(error)));
                }
            })?;
        let mut upload = Upload {
            body: Some(body),
            data: Bytes::new(),
            piece: None,
            sender: Some(sender),
        };
        let head = poll_fn(|cx| {
            if let Err(error) = upload.poll(cx) {
                return Poll::Ready(Err(error));
            }
            download.poll_recv(cx).map(Ok)
        })
        .await?;
        let head = match head.transpose()? {
            Some(http1::Event::Head(head)) => head,
            _ => return Err(Error::msg("the upstream closed before its response")),
        };
        let mut response = Response::builder()
            .status(head.status)
            .version(match head.version {
                http1::Version::Http10 => http::Version::HTTP_10,
                http1::Version::Http11 => http::Version::HTTP_11,
            });
        let remaining = if head_only || matches!(head.status, 204 | 304) {
            Some(0)
        } else if head
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        {
            None
        } else {
            head.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .and_then(|h| std::str::from_utf8(&h.value).ok()?.parse().ok())
        };
        for header in head.headers {
            response = response.header(header.name, header.value);
        }
        Ok(response.body(Body::new(Incoming {
            download,
            upload,
            _abort: abort,
            remaining,
            done: false,
        }))?)
    }

    /// Waits for one of the client's exchange slots.
    async fn permit(self: &Arc<Self>) -> Permit {
        poll_fn(|cx| {
            let mut slots = self.slots.lock();
            if slots.busy < self.exchanges {
                slots.busy += 1;
                return Poll::Ready(Permit(self.clone()));
            }
            if !slots.waiting.iter().any(|w| w.will_wake(cx.waker())) {
                slots.waiting.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    fn exchange(
        &self,
        mut job: Job,
        upload: Receiver<Bytes>,
        download: &Sender<Result<Event, Error>>,
        signal: &Arc<Signal>,
    ) -> Result<(), Error> {
        let (conn, replay) = match self.pooled(&job.origin) {
            Some(conn) => (conn, idempotent(&job.method)),
            None => (self.connect(&job, signal)?, false),
        };
        Exchange {
            stream: response_stream(&job.method)?,
            out: std::mem::take(&mut job.head),
            client: self,
            job,
            signal,
            conn,
            replay,
            written: 0,
            upload: Some(upload),
            sent: 0,
            complete: false,
            refused: None,
            pending: None,
            final_head: false,
            reuse: false,
        }
        .run(download)
    }

    fn pooled(&self, origin: &str) -> Option<Connection> {
        let mut idle = self.idle.lock();
        idle.retain(|entry| entry.since.elapsed() < IDLE_FOR);
        while let Some(at) = idle.iter().rposition(|entry| entry.origin == origin) {
            let mut conn = idle.swap_remove(at).conn;
            if conn.is_open() {
                return Some(conn);
            }
        }
        None
    }

    fn connect(&self, job: &Job, signal: &Arc<Signal>) -> Result<Connection, Error> {
        let deadline = Instant::now() + self.connect_timeout;
        let timed_out = || {
            Error::msg(format!(
                "connecting timed out after {:?}",
                self.connect_timeout
            ))
        };
        let addresses = match job.host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, job.port)],
            Err(_) => resolve(&job.host, job.port, signal, deadline)?.ok_or_else(timed_out)?,
        };
        let tcp = race(addresses, signal, deadline)?.ok_or_else(timed_out)?;
        tcp.set_nodelay(true)?;
        if !job.tls {
            return Ok(Connection::Plain(tcp));
        }
        handshake(self.tls.clone(), tcp, &job.host, signal, deadline)?
            .map(|tls| Connection::Tls(Box::new(tls)))
            .ok_or_else(timed_out)
    }
}

struct Permit(Arc<Client>);
impl Drop for Permit {
    fn drop(&mut self) {
        let waiting = {
            let mut slots = self.0.slots.lock();
            slots.busy -= 1;
            std::mem::take(&mut slots.waiting)
        };
        for waker in waiting {
            waker.wake();
        }
    }
}

/// Whether sending a request twice has the effect of sending it once
/// (RFC 9110 section 9.2.2). Only these go again when a pooled
/// connection closes unanswered: the upstream may have acted on the first
/// copy.
fn idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

/// Whether a request with this method carries content, so that an empty
/// body still says `Content-Length: 0`.
fn expects_content(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET
            | Method::HEAD
            | Method::DELETE
            | Method::OPTIONS
            | Method::TRACE
            | Method::CONNECT
    )
}

fn response_stream(method: &Method) -> Result<Stream<ResponseDecoder>, Error> {
    let mut decoder = http1::ResponseEvents::with_limits(http1::Limits {
        header_line: HEAD,
        head: HEAD,
        ..http1::Limits::default()
    });
    decoder.skip_chunk_extras();
    decoder.expect_method(method.as_str())?;
    Ok(Stream::new(ResponseDecoder {
        inner: decoder,
        close: false,
    }))
}

/// Streams close-delimited bytes without waiting for a full decoder block.
struct ResponseDecoder {
    inner: http1::ResponseEvents,
    close: bool,
}

impl Decode for ResponseDecoder {
    type Item = Event;
    type Error = http1::Error;
    const NAME: &'static str = <http1::ResponseEvents as Decode>::NAME;

    fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    fn held(&self) -> usize {
        self.inner.held()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Event>, Self::Error> {
        if self.close && !input.is_empty() {
            let n = input.len().min(http1::Limits::default().body_chunk);
            return Ok(Step::Item(http1::Event::Body(input[..n].to_vec()), n));
        }
        // The core still validates heads and framed bodies and ends at EOF.
        self.inner.decode(input, eof)
    }
}

/// One request and its response on one connection.
struct Exchange<'a> {
    client: &'a Client,
    job: Job,
    signal: &'a Arc<Signal>,
    conn: Connection,
    /// The connection came from the pool, the method is idempotent, and
    /// nothing of the response has come back, so `out` still holds every
    /// byte written to it.
    replay: bool,
    /// Bytes for the socket. The first `written` of them went out.
    out: Vec<u8>,
    written: usize,
    upload: Option<Receiver<Bytes>>,
    sent: u64,
    /// The end of the body is in `out`.
    complete: bool,
    /// Why the upstream stopped taking the request.
    refused: Option<io::Error>,
    stream: Stream<ResponseDecoder>,
    pending: Option<Result<Event, Error>>,
    final_head: bool,
    reuse: bool,
}

impl Exchange<'_> {
    fn run(mut self, download: &Sender<Result<Event, Error>>) -> Result<(), Error> {
        let waker = Waker::from(self.signal.clone());
        let mut cx = Context::from_waker(&waker);
        loop {
            if self.signal.cancelled() {
                return Ok(());
            }
            let mut progress = self.frame(&mut cx)?;
            progress |= self.write()?;
            loop {
                if self.pending.is_some() {
                    match download.poll_send(&mut self.pending, &mut cx) {
                        Poll::Ready(true) => progress = true,
                        Poll::Ready(false) => return Ok(()),
                        Poll::Pending => break,
                    }
                }
                let event = match self.stream.next() {
                    Some(Ok(event)) => event,
                    Some(Err(fail)) => return Err(malformed(fail)),
                    None if self.stream.is_done() => return Err(self.unanswered()),
                    None => break,
                };
                match &event {
                    http1::Event::Head(head) if head.status == 101 => {
                        return Err(Error::msg("upstream protocol upgrades are unsupported"));
                    }
                    http1::Event::Head(head) if head.status < 200 => continue,
                    http1::Event::Head(head) => {
                        self.final_head = true;
                        self.stream.decoder().close = self.job.method != Method::HEAD
                            && !matches!(head.status, 204 | 304)
                            && !(self.job.method == Method::CONNECT
                                && (200..300).contains(&head.status))
                            && !head.headers.iter().any(|h| {
                                h.name.eq_ignore_ascii_case("content-length")
                                    || (h.name.eq_ignore_ascii_case("transfer-encoding")
                                        && h.value.split(|b| *b == b',').any(|coding| {
                                            coding.trim_ascii().eq_ignore_ascii_case(b"chunked")
                                        }))
                            });
                        self.reuse = self.job.method != Method::CONNECT
                            && head.keep_alive()?
                            && (self.job.method == Method::HEAD
                                || matches!(head.status, 204 | 304)
                                || head.headers.iter().any(|h| {
                                    h.name.eq_ignore_ascii_case("content-length")
                                        || h.name.eq_ignore_ascii_case("transfer-encoding")
                                }));
                    }
                    http1::Event::Done if !self.final_head => continue,
                    http1::Event::Done => {
                        self.finish(download);
                        return Ok(());
                    }
                    http1::Event::Body(_) => {}
                }
                self.pending = Some(Ok(event));
                progress = true;
            }
            if self.pending.is_none() && !self.stream.is_eof() {
                progress |= self.read()?;
            }
            if !progress {
                let mut events = 0;
                if self.pending.is_none() && !self.stream.is_eof() {
                    events |= libc::POLLIN;
                }
                if self.refused.is_none()
                    && (self.written < self.out.len() || self.conn.wants_write())
                {
                    events |= libc::POLLOUT;
                }
                self.signal.wait(&[(self.conn.fd(), events)], None)?;
            }
        }
    }

    /// Frames the request body pieces the world has put, while there is room.
    fn frame(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let mut progress = false;
        while self.refused.is_none() && self.out.len() - self.written < PIECE {
            let Some(upload) = &mut self.upload else {
                break;
            };
            match upload.poll_recv(cx) {
                Poll::Ready(Some(piece)) => {
                    self.sent += piece.len() as u64;
                    match self.job.length {
                        Some(length) if self.sent > length => {
                            return Err(Error::msg(
                                "the request body is longer than its Content-Length",
                            ));
                        }
                        Some(_) => self.out.extend_from_slice(&piece),
                        None => {
                            write!(self.out, "{:x}\r\n", piece.len())?;
                            self.out.extend_from_slice(&piece);
                            self.out.extend_from_slice(b"\r\n");
                        }
                    }
                }
                Poll::Ready(None) if upload.finished() => {
                    match self.job.length {
                        Some(length) if self.sent != length => {
                            return Err(Error::msg(
                                "the request body is shorter than its Content-Length",
                            ));
                        }
                        Some(_) => {}
                        None => self.out.extend_from_slice(b"0\r\n\r\n"),
                    }
                    self.upload = None;
                    self.complete = true;
                }
                // The world dropped the exchange, or the body failed there.
                // The request must not look finished upstream.
                Poll::Ready(None) => return Err(Error::msg("the request body was cut off")),
                Poll::Pending => break,
            }
            progress = true;
        }
        Ok(progress)
    }

    /// Writes what the socket takes now.
    fn write(&mut self) -> Result<bool, Error> {
        if self.refused.is_some() {
            return Ok(false);
        }
        let result = if self.written < self.out.len() {
            self.conn.send(&self.out[self.written..])
        } else {
            self.conn.flush().map(|()| 0)
        };
        let n = match result {
            Ok(n) => n,
            Err(e) if self.replay && closed(&e) => {
                self.retry()?;
                return Ok(true);
            }
            Err(e) => {
                // A server may answer early, then close without reading the
                // rest. Stop sending and read its answer.
                self.refused = Some(e);
                self.upload = None;
                return Ok(true);
            }
        };
        self.written += n;
        if self.replay && self.out.len() > PIECE {
            self.replay = false;
        }
        if !self.replay && self.written > 0 {
            self.out.drain(..self.written);
            self.written = 0;
        }
        Ok(n > 0)
    }

    /// Reads what has arrived into the decoder.
    fn read(&mut self) -> Result<bool, Error> {
        let spare = self.stream.spare();
        if spare.is_empty() {
            return Err(Error::msg("the upstream response decoder stopped"));
        }
        match self.conn.receive(spare) {
            Ok(None) => return Ok(false),
            Ok(Some(0)) if self.replay => self.retry()?,
            Ok(Some(0)) => self.stream.end(),
            Ok(Some(n)) => {
                self.stream.commit(n);
                self.replay = false;
            }
            Err(e) if self.replay && closed(&e) => self.retry()?,
            Err(e) => {
                return Err(match self.refused.take() {
                    Some(refused) => failure("sending the request", &refused),
                    None => failure("reading the response", &e),
                });
            }
        }
        Ok(true)
    }

    /// Sends an idempotent request again on a new connection. A server may
    /// close an idle connection just as a request goes out on it, and then
    /// none of the request was answered.
    fn retry(&mut self) -> Result<(), Error> {
        self.conn = self.client.connect(&self.job, self.signal)?;
        self.replay = false;
        self.written = 0;
        self.stream = response_stream(&self.job.method)?;
        Ok(())
    }

    fn unanswered(&mut self) -> Error {
        match self.refused.take() {
            Some(refused) => failure("sending the request", &refused),
            None => Error::msg("the upstream closed before its response"),
        }
    }

    /// Pools the connection if it can carry another request, then tells
    /// the world the response is complete.
    fn finish(self, download: &Sender<Result<Event, Error>>) {
        let reuse = self.reuse
            && self.complete
            && self.refused.is_none()
            && self.written == self.out.len()
            && !self.conn.wants_write()
            && self.stream.unread().is_empty()
            && !self.stream.is_eof()
            && !self.signal.cancelled();
        if reuse {
            self.client.idle.lock().push(Idle {
                origin: self.job.origin,
                since: Instant::now(),
                conn: self.conn,
            });
        }
        // Dropping the upload here stops the world sending the rest of a
        // body that the upstream answered without reading.
        drop(self.upload);
        let _ = fictionet::block_on(download.send(Ok(http1::Event::Done)));
    }
}

/// Whether a socket error means the server closed the connection.
fn closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Words for a socket error that say what happened, where the system's
/// own text often names only an errno.
fn failure(doing: &str, error: &io::Error) -> Error {
    use io::ErrorKind::*;
    let what = match error.kind() {
        ConnectionRefused => "the connection was refused",
        ConnectionReset => "the upstream reset the connection",
        ConnectionAborted => "the connection was aborted",
        BrokenPipe | UnexpectedEof => "the upstream closed the connection",
        TimedOut => "timed out",
        HostUnreachable => "the host is unreachable",
        NetworkUnreachable => "the network is unreachable",
        _ => return Error::msg(format!("{doing}: {error}")),
    };
    Error::msg(format!("{doing}: {what}"))
}

fn malformed(fail: Fail<http1::Error>) -> Error {
    Error::msg(match fail {
        Fail::Protocol(http1::Error::Incomplete) | Fail::Truncated { .. } => {
            "the upstream closed before its response ended".to_owned()
        }
        Fail::Protocol(error) => format!("the upstream response is malformed: {error}"),
        fail => format!("reading the upstream response: {fail}"),
    })
}

/// Looks the name up on the shared resolver threads. `None` when the
/// deadline passes first.
fn resolve(
    host: &str,
    port: u16,
    signal: &Arc<Signal>,
    deadline: Instant,
) -> Result<Option<Vec<SocketAddr>>, Error> {
    struct Abandon<'a>(&'a Lookup);
    impl Drop for Abandon<'_> {
        fn drop(&mut self) {
            self.0.wanted.store(false, Ordering::Relaxed);
        }
    }
    let lookup = Arc::new(Lookup {
        host: host.to_owned(),
        port,
        waker: Waker::from(signal.clone()),
        wanted: AtomicBool::new(true),
        answer: Mutex::new(None),
    });
    let _abandon = Abandon(&lookup);
    {
        let mut lookups = LOOKUPS.lock();
        lookups.queue.push_back(lookup.clone());
        if lookups.threads < RESOLVERS {
            match std::thread::Builder::new()
                .name("fictionet-resolve".into())
                .spawn(resolve_queued)
            {
                Ok(_) => lookups.threads += 1,
                Err(e) if lookups.threads == 0 => {
                    lookups.queue.pop_back();
                    return Err(e.into());
                }
                Err(_) => {}
            }
        }
    }
    loop {
        if let Some(answer) = lookup.answer.lock().take() {
            return answer
                .map(Some)
                .map_err(|e| Error::msg(format!("looking up {host}: {e}")));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        signal.wait(&[], Some(deadline))?;
    }
}

struct Lookup {
    host: String,
    port: u16,
    waker: Waker,
    wanted: AtomicBool,
    answer: Mutex<Option<io::Result<Vec<SocketAddr>>>>,
}

struct Lookups {
    queue: VecDeque<Arc<Lookup>>,
    threads: usize,
}

static LOOKUPS: Mutex<Lookups> = Mutex::new(Lookups {
    queue: VecDeque::new(),
    threads: 0,
});

/// Answers queued lookups until there are none left.
fn resolve_queued() {
    loop {
        let lookup = {
            let mut lookups = LOOKUPS.lock();
            let Some(lookup) = lookups.queue.pop_front() else {
                lookups.threads -= 1;
                return;
            };
            lookup
        };
        if !lookup.wanted.load(Ordering::Relaxed) {
            continue;
        }
        let answer = (lookup.host.as_str(), lookup.port)
            .to_socket_addrs()
            .map(Iterator::collect);
        *lookup.answer.lock() = Some(answer);
        lookup.waker.wake_by_ref();
    }
}

/// Connects to the first address that answers, as RFC 8305 describes.
/// Addresses alternate between families. Each attempt gets `ATTEMPT_DELAY`
/// before the next one starts beside it, and a failed attempt starts the
/// next one at once. `None` when the deadline passes first.
fn race(
    addresses: Vec<SocketAddr>,
    signal: &Signal,
    deadline: Instant,
) -> Result<Option<TcpStream>, Error> {
    let first_v6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
    let (first, second): (Vec<_>, Vec<_>) =
        addresses.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut second = second.into_iter();
    let mut next: Vec<_> = first
        .into_iter()
        .flat_map(|a| [Some(a), second.next()])
        .flatten()
        .collect();
    next.extend(second);
    let mut next = next.into_iter();
    let mut trying: Vec<(SocketAddr, TcpStream)> = Vec::new();
    let mut failed: Option<(SocketAddr, io::Error)> = None;
    let mut start_next = Instant::now();
    loop {
        while trying.is_empty() || Instant::now() >= start_next {
            let Some(address) = next.next() else {
                break;
            };
            match begin_connect(address) {
                Ok(tcp) => {
                    trying.push((address, tcp));
                    start_next = Instant::now() + ATTEMPT_DELAY;
                }
                Err(e) => failed = Some((address, e)),
            }
        }
        if trying.is_empty() {
            return Err(match failed {
                Some((address, e)) => failure(&format!("connecting to {address}"), &e),
                None => Error::msg("the upstream name has no addresses"),
            });
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let wake = if next.len() > 0 {
            start_next.min(deadline)
        } else {
            deadline
        };
        let sockets: Vec<_> = trying
            .iter()
            .map(|(_, tcp)| (tcp.as_raw_fd(), libc::POLLOUT))
            .collect();
        let ready = signal.wait(&sockets, Some(wake))?;
        // In reverse, so that removing an attempt leaves earlier indices in place.
        for (i, events) in ready.into_iter().enumerate().rev() {
            if events == 0 {
                continue;
            }
            let (address, tcp) = trying.swap_remove(i);
            match tcp.take_error() {
                Ok(None) => return Ok(Some(tcp)),
                Ok(Some(e)) | Err(e) => {
                    failed = Some((address, e));
                    start_next = Instant::now();
                }
            }
        }
    }
}

/// Starts a nonblocking connect, which poll reports writable when it ends.
fn begin_connect(address: SocketAddr) -> io::Result<TcpStream> {
    // SAFETY: all-zero bytes are a valid sockaddr_storage.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let (domain, len) = match address {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in.
            unsafe { std::ptr::write((&raw mut storage).cast(), sin) };
            (libc::AF_INET, size_of::<libc::sockaddr_in>())
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in6.
            unsafe { std::ptr::write((&raw mut storage).cast(), sin6) };
            (libc::AF_INET6, size_of::<libc::sockaddr_in6>())
        }
    };
    // SAFETY: socket takes no pointers.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new descriptor that nothing else owns.
    let tcp = unsafe { TcpStream::from_raw_fd(fd) };
    // SAFETY: `storage` holds a socket address of `len` bytes.
    let started = unsafe { libc::connect(fd, (&raw const storage).cast(), len as libc::socklen_t) };
    if started == 0 {
        return Ok(tcp);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINPROGRESS) {
        Ok(tcp)
    } else {
        Err(error)
    }
}

/// Runs the TLS handshake. `None` when the deadline passes first.
fn handshake(
    config: Arc<rustls::ClientConfig>,
    mut tcp: TcpStream,
    host: &str,
    signal: &Signal,
    deadline: Instant,
) -> Result<Option<Tls>, Error> {
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
    let mut conn = rustls::ClientConnection::new(config, name)?;
    while conn.is_handshaking() {
        let mut progress = false;
        while conn.wants_write() {
            match conn.write_tls(&mut tcp) {
                Ok(_) => progress = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(failure("the TLS handshake", &e)),
            }
        }
        match conn.read_tls(&mut tcp) {
            Ok(0) => {
                return Err(Error::msg("the upstream closed during the TLS handshake"));
            }
            Ok(_) => {
                if let Err(e) = conn.process_new_packets() {
                    // Tell the server why, as far as the socket takes it.
                    let _ = conn.write_tls(&mut tcp);
                    return Err(Error::msg(format!("the TLS handshake failed: {e}")));
                }
                progress = true;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(failure("the TLS handshake", &e)),
        }
        if !progress {
            if Instant::now() >= deadline {
                return Ok(None);
            }
            let mut events = libc::POLLIN;
            if conn.wants_write() {
                events |= libc::POLLOUT;
            }
            signal.wait(&[(tcp.as_raw_fd(), events)], Some(deadline))?;
        }
    }
    Ok(Some(Tls { conn, tcp }))
}

/// A connected, nonblocking socket.
enum Connection {
    Plain(TcpStream),
    Tls(Box<Tls>),
}

struct Tls {
    conn: rustls::ClientConnection,
    tcp: TcpStream,
}

impl Tls {
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.tcp) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// `None` for a nonblocking call that has nothing to do yet.
fn ready(result: io::Result<usize>) -> io::Result<Option<usize>> {
    match result {
        Ok(n) => Ok(Some(n)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

impl Connection {
    fn fd(&self) -> RawFd {
        match self {
            Self::Plain(tcp) => tcp.as_raw_fd(),
            Self::Tls(tls) => tls.tcp.as_raw_fd(),
        }
    }

    fn wants_write(&self) -> bool {
        matches!(self, Self::Tls(tls) if tls.conn.wants_write())
    }

    /// Sends as much of `bytes` as the socket takes now.
    fn send(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => Ok(ready(tcp.write(bytes))?.unwrap_or(0)),
            Self::Tls(tls) => {
                tls.flush()?;
                if tls.conn.wants_write() {
                    return Ok(0);
                }
                let n = tls.conn.writer().write(bytes)?;
                tls.flush()?;
                Ok(n)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(_) => Ok(()),
            Self::Tls(tls) => tls.flush(),
        }
    }

    /// Reads what has arrived: `Some(0)` at the end, `None` if nothing has.
    fn receive(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let tls = match self {
            Self::Plain(tcp) => return ready(tcp.read(buf)),
            Self::Tls(tls) => tls,
        };
        loop {
            match tls.conn.reader().read(buf) {
                Ok(n) => return Ok(Some(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // Many servers close without close_notify. The framing
                // tells a cut-off body from a finished one.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Some(0)),
                Err(e) => return Err(e),
            }
            if ready(tls.conn.read_tls(&mut tls.tcp))?.is_none() {
                return Ok(None);
            }
            tls.conn
                .process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
    }

    /// Whether a pooled connection can carry another request.
    fn is_open(&mut self) -> bool {
        match self {
            Self::Plain(tcp) => {
                matches!(tcp.peek(&mut [0]), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
            }
            Self::Tls(tls) => {
                // Session tickets may arrive after the response body.
                loop {
                    match tls.conn.read_tls(&mut tls.tcp) {
                        Ok(0) => return false,
                        Ok(_) => {
                            if tls.conn.process_new_packets().is_err() {
                                return false;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => return false,
                    }
                }
                matches!(
                    tls.conn.reader().read(&mut [0]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock
                )
            }
        }
    }
}

/// Wakes an exchange's thread when the world puts or takes a piece, a
/// lookup answers, or the world drops the exchange.
struct Signal {
    eventfd: OwnedFd,
    cancelled: AtomicBool,
}

impl Signal {
    fn new() -> io::Result<Self> {
        // SAFETY: eventfd takes no pointers.
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: eventfd returned a new descriptor that nothing else owns.
            eventfd: unsafe { OwnedFd::from_raw_fd(fd) },
            cancelled: AtomicBool::new(false),
        })
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn notify(&self) {
        let one = 1u64;
        // SAFETY: writes the eight bytes of `one` to an eventfd this owns.
        unsafe { libc::write(self.eventfd.as_raw_fd(), (&raw const one).cast(), 8) };
    }

    /// Waits until a socket is ready for the events asked of it, the signal
    /// fires, or the deadline passes. Returns each socket's ready events,
    /// or an error once the world has dropped the exchange.
    fn wait(
        &self,
        sockets: &[(RawFd, libc::c_short)],
        deadline: Option<Instant>,
    ) -> Result<Vec<libc::c_short>, Error> {
        let mut fds = vec![libc::pollfd {
            fd: self.eventfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // A socket asked for nothing is left out, or a hangup on it would
        // end every wait at once.
        fds.extend(sockets.iter().map(|&(fd, events)| libc::pollfd {
            fd: if events == 0 { -1 } else { fd },
            events,
            revents: 0,
        }));
        loop {
            if self.cancelled() {
                return Err(Error::msg("the request was dropped"));
            }
            let timeout = deadline.map_or(-1, |deadline| {
                let left = deadline.saturating_duration_since(Instant::now());
                i32::try_from(left.as_micros().div_ceil(1000)).unwrap_or(i32::MAX)
            });
            // SAFETY: `fds` is a live array of `fds.len()` pollfd entries.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if fds[0].revents != 0 {
                let mut count = [0u8; 8];
                // SAFETY: reads at most eight bytes into `count`.
                unsafe { libc::read(self.eventfd.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
            }
            if self.cancelled() {
                return Err(Error::msg("the request was dropped"));
            }
            return Ok(fds[1..].iter().map(|fd| fd.revents).collect());
        }
    }
}

impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.notify();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

/// Stops the exchange's thread when the world drops the exchange.
struct Abort(Arc<Signal>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.notify();
    }
}

/// The request body on its way to the exchange's thread.
struct Upload {
    body: Option<Body>,
    data: Bytes,
    piece: Option<Bytes>,
    sender: Option<Sender<Bytes>>,
}

impl Upload {
    /// Moves request body bytes to the thread while it takes them, and says
    /// when the body ends. Returns the body's error, which leaves the
    /// request unfinished upstream.
    fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        loop {
            let Some(sender) = &self.sender else {
                return Ok(());
            };
            if self.piece.is_none() && !self.data.is_empty() {
                self.piece = Some(self.data.split_to(self.data.len().min(PIECE)));
            }
            if self.piece.is_some() {
                match sender.poll_send(&mut self.piece, cx) {
                    Poll::Ready(true) => continue,
                    // The thread wants no more of the body.
                    Poll::Ready(false) => {
                        self.sender = None;
                        self.body = None;
                        return Ok(());
                    }
                    Poll::Pending => return Ok(()),
                }
            }
            let Some(body) = &mut self.body else {
                if let Some(sender) = self.sender.take() {
                    sender.finish();
                }
                return Ok(());
            };
            match Pin::new(&mut *body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.data = data;
                    }
                    // Finishing with the last piece lets the thread send the
                    // body's end in the same write.
                    if body.is_end_stream() {
                        self.body = None;
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.sender = None;
                    self.body = None;
                    return Err(error);
                }
                Poll::Ready(None) => self.body = None,
                Poll::Pending => return Ok(()),
            }
        }
    }
}

struct Incoming {
    download: Receiver<Result<Event, Error>>,
    upload: Upload,
    _abort: Abort,
    remaining: Option<u64>,
    done: bool,
}
impl http_body::Body for Incoming {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        // A server may stream its answer while it still reads the request.
        if let Err(error) = this.upload.poll(cx) {
            this.done = true;
            return Poll::Ready(Some(Err(error)));
        }
        match std::task::ready!(this.download.poll_recv(cx)) {
            Some(Ok(http1::Event::Body(bytes))) => {
                if let Some(n) = &mut this.remaining {
                    *n = n.saturating_sub(bytes.len() as u64);
                }
                Poll::Ready(Some(Ok(Frame::data(bytes.into()))))
            }
            Some(Ok(http1::Event::Done)) => {
                this.done = true;
                Poll::Ready(None)
            }
            Some(Err(error)) => {
                this.done = true;
                Poll::Ready(Some(Err(error)))
            }
            _ => {
                this.done = true;
                Poll::Ready(Some(Err(Error::msg("upstream body cut off"))))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
    fn size_hint(&self) -> SizeHint {
        self.remaining
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

// One slot bounds memory even when the upstream is faster than the world.
struct Slot<T> {
    value: Option<T>,
    closed: bool,
    finished: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
struct Sender<T>(Arc<Mutex<Slot<T>>>);
struct Receiver<T>(Arc<Mutex<Slot<T>>>);
fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let slot = Arc::new(Mutex::new(Slot {
        value: None,
        closed: false,
        finished: false,
        reader: None,
        writer: None,
    }));
    (Sender(slot.clone()), Receiver(slot))
}
impl<T> Sender<T> {
    /// Moves `value` into the slot once it is free. False once the
    /// receiver is gone.
    fn poll_send(&self, value: &mut Option<T>, cx: &mut Context<'_>) -> Poll<bool> {
        let mut slot = self.0.lock();
        if slot.closed {
            return Poll::Ready(false);
        }
        if slot.value.is_some() {
            slot.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        slot.value = value.take();
        let wake = slot.reader.take();
        drop(slot);
        if let Some(wake) = wake {
            wake.wake();
        }
        Poll::Ready(true)
    }
    async fn send(&self, value: T) -> bool {
        let mut value = Some(value);
        poll_fn(|cx| self.poll_send(&mut value, cx)).await
    }
    /// Closes the channel after its last value, so the receiver knows that
    /// nothing was cut off.
    fn finish(self) {
        self.0.lock().finished = true;
    }
}
impl<T> Receiver<T> {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut slot = self.0.lock();
        if let Some(value) = slot.value.take() {
            let wake = slot.writer.take();
            drop(slot);
            if let Some(wake) = wake {
                wake.wake();
            }
            Poll::Ready(Some(value))
        } else if slot.closed {
            Poll::Ready(None)
        } else {
            slot.reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    /// Whether the sender finished, rather than went away.
    fn finished(&self) -> bool {
        self.0.lock().finished
    }
}
fn close<T>(slot: &Mutex<Slot<T>>) {
    let mut slot = slot.lock();
    slot.closed = true;
    let wakes = [slot.reader.take(), slot.writer.take()];
    drop(slot);
    for wake in wakes.into_iter().flatten() {
        wake.wake();
    }
}
impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        close(&self.0);
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        close(&self.0);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
