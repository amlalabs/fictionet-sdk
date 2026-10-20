use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fictionet::sync::Mutex;

use crate::{DashboardHandle, Value};

const MAX_MESSAGE: usize = 65_536;
const MORE: u8 = 1;
const END: u8 = 2;
const BINARY: u8 = 4;
const HELLO: u8 = 1;
const ACCEPT: u8 = 2;
const REFUSE: u8 = 3;
const REQUEST: u8 = 4;
const REPLY: u8 = 5;
const VERSION: u32 = 2;
const PROTOCOL: &str = "fictionet-observe";
const TIMEOUT: Duration = Duration::from_secs(10);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
fn wall() -> Option<Duration> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()
}

fn send(stream: &UnixStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_MESSAGE {
        return Err(invalid("message exceeds 65,536 bytes"));
    }
    let mut stream = stream;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

#[derive(Default)]
struct Reader {
    header: [u8; 4],
    header_read: usize,
    body: Vec<u8>,
    body_read: usize,
}

impl Reader {
    fn read(&mut self, stream: &UnixStream) -> io::Result<Option<Vec<u8>>> {
        self.read_until(stream, None)
    }
    fn read_until(
        &mut self,
        mut stream: &UnixStream,
        deadline: Option<Instant>,
    ) -> io::Result<Option<Vec<u8>>> {
        let remaining = || -> io::Result<()> {
            if let Some(deadline) = deadline {
                let wait = deadline.saturating_duration_since(Instant::now());
                if wait.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                stream.set_read_timeout(Some(wait))?;
            }
            Ok(())
        };
        while self.header_read < 4 {
            remaining()?;
            let n = stream.read(&mut self.header[self.header_read..])?;
            if n == 0 {
                return if self.header_read == 0 {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            self.header_read += n;
        }
        let len = u32::from_be_bytes(self.header) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Err(invalid("invalid message length; maximum is 65,536 bytes"));
        }
        self.body.resize(len, 0);
        while self.body_read < len {
            remaining()?;
            let n = stream.read(&mut self.body[self.body_read..])?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.body_read += n;
        }
        self.header_read = 0;
        self.body_read = 0;
        Ok(Some(std::mem::take(&mut self.body)))
    }
}

fn send_value(stream: &UnixStream, value: Value) -> io::Result<()> {
    let mut chunks = value.bytes.chunks(MAX_MESSAGE - 6).peekable();
    let mut first = true;
    while first || chunks.peek().is_some() {
        first = false;
        let chunk = chunks.next().unwrap_or(&[]);
        let mut flags = if value.binary { BINARY } else { 0 };
        if chunks.peek().is_some() {
            flags |= MORE;
        } else if value.end {
            flags |= END;
        }
        let mut frame = Vec::with_capacity(6 + chunk.len());
        frame.push(REPLY);
        frame.extend_from_slice(&value.id.to_be_bytes());
        frame.push(flags);
        frame.extend_from_slice(chunk);
        send(stream, &frame)?;
    }
    Ok(())
}

struct Shared {
    stopping: AtomicBool,
    limit: AtomicUsize,
    sockets: Mutex<Vec<Arc<UnixStream>>>,
}

struct Slot {
    shared: Arc<Shared>,
    socket: Arc<UnixStream>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.shared
            .sockets
            .lock()
            .retain(|socket| !Arc::ptr_eq(socket, &self.socket));
    }
}

/// A private observation socket. Dropping it closes and joins all sessions
/// and removes the socket, without ending the observed run.
pub struct Endpoint {
    path: PathBuf,
    identity: (u64, u64),
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl Endpoint {
    /// Changes admission for new sessions. Existing sessions are unaffected.
    /// The default is 64, including sessions still completing their hello.
    pub fn set_session_limit(&self, limit: usize) {
        self.shared.limit.store(limit, Ordering::Release);
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        for socket in self.shared.sockets.lock().iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        let _ = UnixStream::connect(&self.path);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Installs a run's observers in `options`: the world's own `observer`, if
/// any, and a [`DashboardObserver`](crate::DashboardObserver) whose handle is
/// served at `path`, if a path is given. Both sit behind one
/// [`Aggregate`](crate::Aggregate). With neither, `options` gets no observer
/// and the run skips observation work. Keep the returned endpoint alive for
/// the run; it is `None` without a path.
///
/// ```no_run
/// use std::{path::PathBuf, sync::Arc};
/// use fictionet::{RunOptions, Seed};
/// use fictionet_observe::{Memory, serve_observation};
///
/// // The optional observation socket from the command line, such as
/// // /run/fictionet/observe.sock.
/// let path = std::env::args_os().nth(1).map(PathBuf::from);
/// let grader = Arc::new(Memory::default());
/// let (options, _endpoint) =
///     serve_observation(RunOptions::new(Seed::random()), path, Some(grader.clone()))?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn serve_observation(
    options: fictionet::RunOptions,
    path: Option<PathBuf>,
    observer: Option<Arc<dyn fictionet::events::Observer>>,
) -> io::Result<(fictionet::RunOptions, Option<Endpoint>)> {
    let Some(path) = path else {
        return Ok(match observer {
            Some(observer) => (
                options.observer(Arc::new(crate::Aggregate::new(observer))),
                None,
            ),
            None => (options, None),
        });
    };
    let dashboard = crate::DashboardObserver::new(Default::default());
    let endpoint = serve(dashboard.handle(), path)?;
    let observer: Arc<dyn fictionet::events::Observer> = match observer {
        Some(observer) => Arc::new(fictionet::events::Fanout::new(vec![
            dashboard.observer(),
            observer,
        ])),
        None => dashboard.observer(),
    };
    Ok((
        options.observer(Arc::new(crate::Aggregate::new(observer))),
        Some(endpoint),
    ))
}

/// Binds a private Unix observation socket and starts its accept thread.
/// Live sockets and non-socket paths are never replaced. Stale sockets are
/// replaced. The socket is private before its public path becomes visible.
pub fn serve(handle: DashboardHandle, path: impl AsRef<Path>) -> io::Result<Endpoint> {
    let path = path.as_ref().to_path_buf();
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "observation path is not a socket",
            ));
        }
        match UnixStream::connect(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "observation socket is live",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                let current = fs::symlink_metadata(&path)?;
                if (current.dev(), current.ino()) != (meta.dev(), meta.ino()) {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "observation socket changed",
                    ));
                }
                fs::remove_file(&path)?;
            }
            Err(error) => return Err(error),
        }
    }
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let private = parent.join(format!(
        ".observe-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&private)?;
    let socket_path = private.join("socket");
    let bound = (|| {
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        fs::hard_link(&socket_path, &path)?;
        Ok::<_, io::Error>(listener)
    })();
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_dir(&private);
    let listener = bound?;
    let metadata = fs::symlink_metadata(&path)?;
    let shared = Arc::new(Shared {
        stopping: AtomicBool::new(false),
        limit: AtomicUsize::new(64),
        sockets: Mutex::new(Vec::new()),
    });
    let state = shared.clone();
    let worker = thread::Builder::new()
        .name("fictionet-observe".into())
        .spawn(move || {
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                if state.stopping.load(Ordering::Acquire) {
                    break;
                }
                let mut pending = Vec::new();
                for worker in workers.drain(..) {
                    if worker.is_finished() {
                        let _ = worker.join();
                    } else {
                        pending.push(worker);
                    }
                }
                workers = pending;
                let _ = socket.set_write_timeout(Some(TIMEOUT));
                let mut sockets = state.sockets.lock();
                if sockets.len() >= state.limit.load(Ordering::Acquire) {
                    drop(sockets);
                    let mut message = vec![REFUSE];
                    message.extend_from_slice(b"too many observation sessions");
                    let _ = send(&socket, &message);
                    continue;
                }
                let socket = Arc::new(socket);
                sockets.push(socket.clone());
                drop(sockets);
                let slot = Slot {
                    shared: state.clone(),
                    socket,
                };
                let handle = handle.clone();
                if let Ok(worker) = thread::Builder::new()
                    .name("fictionet-observe-session".into())
                    .spawn(move || {
                        let _ = session(&handle, &slot);
                    })
                {
                    workers.push(worker);
                }
            }
            for socket in state.sockets.lock().iter() {
                let _ = socket.shutdown(Shutdown::Both);
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
    match worker {
        Ok(worker) => Ok(Endpoint {
            path,
            identity: (metadata.dev(), metadata.ino()),
            shared,
            worker: Some(worker),
        }),
        Err(error) => {
            let _ = fs::remove_file(path);
            Err(error)
        }
    }
}

fn session(handle: &DashboardHandle, slot: &Slot) -> io::Result<()> {
    let socket = &slot.socket;
    socket.set_read_timeout(Some(TIMEOUT))?;
    let mut reader = Reader::default();
    let Some(hello) = reader.read_until(socket, Some(Instant::now() + TIMEOUT))? else {
        return Ok(());
    };
    let version = hello
        .get(1..5)
        .map(|bytes| u32::from_be_bytes(bytes.try_into().expect("four bytes")));
    let name = hello
        .get(5..)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or("invalid");
    if hello.first() != Some(&HELLO) || version != Some(VERSION) || name != PROTOCOL {
        let mut refusal = vec![REFUSE];
        refusal.extend_from_slice(
            format!(
                "expected {PROTOCOL} version {VERSION}; received {name} version {}",
                version.map_or_else(|| "invalid".into(), |v| v.to_string())
            )
            .as_bytes(),
        );
        return send(socket, &refusal);
    }
    send(socket, &[ACCEPT])?;
    let mut session = handle.session();
    while !slot.shared.stopping.load(Ordering::Acquire) {
        for value in session.poll(Instant::now(), wall()) {
            send_value(socket, value)?;
        }
        let now = Instant::now();
        let wait = session.next_poll().map_or(Duration::from_secs(1), |next| {
            next.saturating_duration_since(now)
        });
        if wait.is_zero() {
            continue;
        }
        socket.set_read_timeout(Some(wait))?;
        match reader.read_until(socket, Some(now + wait)) {
            Ok(Some(request)) if request.first() == Some(&REQUEST) && request.len() >= 5 => {
                let id = u32::from_be_bytes(request[1..5].try_into().expect("four bytes"));
                let text = std::str::from_utf8(&request[5..])
                    .map_err(|_| invalid("request is not UTF-8"))?;
                for value in session.request(id, text, Instant::now(), wall()) {
                    send_value(socket, value)?;
                }
            }
            Ok(None) => break,
            Ok(Some(_)) => return Err(invalid("expected a request")),
            Err(error) if timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A client of the separate observation endpoint. No attach fallback is used.
pub struct Client {
    socket: UnixStream,
    next_id: u32,
    reader: Reader,
    partial: Option<Value>,
}
impl Client {
    /// Connects and completes the protocol and version handshake. Refusal
    /// reasons are returned unchanged. Hello times out after 11 seconds.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::hello(UnixStream::connect(path)?, TIMEOUT + Duration::from_secs(1))
    }
    fn hello(socket: UnixStream, timeout: Duration) -> io::Result<Self> {
        socket.set_write_timeout(Some(timeout))?;
        socket.set_read_timeout(Some(timeout))?;
        let mut hello = vec![HELLO];
        hello.extend_from_slice(&VERSION.to_be_bytes());
        hello.extend_from_slice(PROTOCOL.as_bytes());
        // A full endpoint sends its refusal and closes at once, so the
        // hello can fail to send. The refusal is still there to read.
        if let Err(error) = send(&socket, &hello)
            && !matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            )
        {
            return Err(error);
        }
        let mut reader = Reader::default();
        let answer = reader
            .read_until(&socket, Some(Instant::now() + timeout))?
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        match answer.as_slice() {
            [ACCEPT] => {}
            [REFUSE, reason @ ..] => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    String::from_utf8_lossy(reason).into_owned(),
                ));
            }
            _ => return Err(invalid("expected observation acceptance")),
        }
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        Ok(Self {
            socket,
            next_id: 1,
            reader,
            partial: None,
        })
    }
    /// Sends a flat JSON request and returns its session id.
    pub fn request(&mut self, json: &str) -> io::Result<u32> {
        if json.len() > MAX_MESSAGE - 5 {
            return Err(invalid("request exceeds 65,536 bytes"));
        }
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or_else(|| invalid("request ids exhausted"))?;
        let mut message = vec![REQUEST];
        message.extend_from_slice(&id.to_be_bytes());
        message.extend_from_slice(json.as_bytes());
        send(&self.socket, &message)?;
        Ok(id)
    }
    /// Reads a whole value. Timeouts preserve partial messages and values.
    /// EOF between values returns none; EOF within a value is unexpected.
    /// Invalid flags or continuations close the session with `InvalidData`.
    pub fn next_value(&mut self) -> io::Result<Option<Value>> {
        let result = self.read_value();
        if result.as_ref().is_err_and(|error| !timeout(error)) {
            self.partial = None;
            self.reader = Reader::default();
            let _ = self.socket.shutdown(Shutdown::Both);
        }
        result
    }
    fn read_value(&mut self) -> io::Result<Option<Value>> {
        loop {
            let Some(frame) = self.reader.read(&self.socket)? else {
                return if self.partial.is_some() {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the world closed during a reply value",
                    ))
                } else {
                    Ok(None)
                };
            };
            if frame.len() < 6 || frame[0] != REPLY {
                return Err(invalid("not a reply"));
            }
            let id = u32::from_be_bytes(frame[1..5].try_into().expect("four bytes"));
            let flags = frame[5];
            let binary = flags & BINARY != 0;
            if flags & !(MORE | END | BINARY) != 0
                || flags & (MORE | END) == MORE | END
                || self
                    .partial
                    .as_ref()
                    .is_some_and(|v| v.id != id || v.binary != binary)
            {
                return Err(invalid("invalid reply flags or continuation"));
            }
            let value = self.partial.get_or_insert_with(|| Value {
                id,
                bytes: Vec::new(),
                binary,
                end: false,
            });
            value.bytes.extend_from_slice(&frame[6..]);
            value.end = flags & END != 0;
            if flags & MORE == 0 {
                return Ok(self.partial.take());
            }
        }
    }
    /// Sends a request and returns the next whole value of any request.
    pub fn call(&mut self, json: &str) -> io::Result<Value> {
        self.request(json)?;
        self.next_value()?
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }
    /// Sets a reply read timeout, or none to wait indefinitely.
    pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DashboardObserver, DashboardOptions, Envelope};
    use fictionet::events::{Event, Observation, Stamp, Stream};
    use fictionet::time::Instant as RunTime;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "observe-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn socket(&self) -> PathBuf {
            self.0.join("observe.sock")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn dashboard() -> DashboardObserver {
        let dashboard = DashboardObserver::new(DashboardOptions::default());
        emit(&dashboard, 1, Event::new("run", "start"));
        dashboard
    }
    fn emit(dashboard: &DashboardObserver, seq: u64, event: Event) {
        dashboard.observer().observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: RunTime::ZERO,
            },
            Observation::Event(&event),
        );
    }
    fn client_peer() -> (Client, UnixStream) {
        let (socket, peer) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || Client::hello(socket, Duration::from_secs(1)).unwrap());
        let hello = Reader::default().read(&peer).unwrap().unwrap();
        assert_eq!(&hello[5..], PROTOCOL.as_bytes());
        send(&peer, &[ACCEPT]).unwrap();
        (worker.join().unwrap(), peer)
    }
    fn reply_frame(id: u32, flags: u8, bytes: &[u8]) -> Vec<u8> {
        let mut frame = vec![REPLY];
        frame.extend_from_slice(&id.to_be_bytes());
        frame.push(flags);
        frame.extend_from_slice(bytes);
        frame
    }
    fn assert_equal(a: &Value, b: &Value) {
        assert_eq!(
            (a.id, &a.bytes, a.binary, a.end),
            (b.id, &b.bytes, b.binary, b.end)
        );
    }

    #[test]
    fn serve_observation_fans_the_run_out_to_its_socket_and_the_world_observer() {
        let run = |options| {
            fictionet::block_on(fictionet::lab(options, |fcx| async move {
                fcx.emit("shop", "order", |event| event.field("item", "tea"));
                Ok(())
            }))
            .unwrap();
        };
        let directory = Directory::new();
        let grader = Arc::new(crate::Memory::default());
        let (options, endpoint) = serve_observation(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            Some(directory.socket()),
            Some(grader.clone()),
        )
        .unwrap();
        assert!(endpoint.is_some());
        run(options);
        assert_eq!(grader.checked_of("shop", "order").unwrap().len(), 1);
        let mut client = Client::connect(directory.socket()).unwrap();
        client.set_timeout(Some(Duration::from_secs(2))).unwrap();
        let reply = client.call(r#"{"op":"events","after":0}"#).unwrap();
        let text = String::from_utf8(reply.bytes).unwrap();
        assert!(text.contains(r#""source":"shop","kind":"order""#), "{text}");

        // Without a path the world's own observer still hears the run.
        let grader = Arc::new(crate::Memory::default());
        let (options, endpoint) = serve_observation(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            None,
            Some(grader.clone()),
        )
        .unwrap();
        assert!(endpoint.is_none());
        run(options);
        assert_eq!(grader.checked_of("shop", "order").unwrap().len(), 1);
    }

    #[test]
    fn endpoint_and_handle_return_the_same_bytes_and_late_changes() {
        let directory = Directory::new();
        let dashboard = dashboard();
        let endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
        let mut client = Client::connect(directory.socket()).unwrap();
        client.set_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut direct = dashboard.handle().session();
        let now = Instant::now();
        for (index, text) in [
            r#"{"op":"world"}"#,
            r#"{"op":"graph"}"#,
            r#"{"op":"events","after":0,"max":1}"#,
            r#"{"op":"counters"}"#,
            r#"{"op":"link","link":"e7"}"#,
            r#"{"op":"keylog"}"#,
            r#"{"op":"unknown"}"#,
        ]
        .iter()
        .enumerate()
        {
            let direct = direct.request(index as u32 + 1, text, now, None).remove(0);
            assert_equal(&direct, &client.call(text).unwrap());
        }
        let text = r#"{"op":"watch","after":0}"#;
        let id = client.request(text).unwrap();
        direct.request(id, text, now, None);
        for direct in direct.poll(now, None) {
            assert_equal(&direct, &client.next_value().unwrap().unwrap());
        }
        for direct in direct.poll(now, None) {
            assert_equal(&direct, &client.next_value().unwrap().unwrap());
        }
        emit(&dashboard, 2, Event::new("test", "changed"));
        for direct in direct.poll(now + Duration::from_millis(250), None) {
            assert_equal(&direct, &client.next_value().unwrap().unwrap());
        }
        let cancel = format!(r#"{{"op":"cancel","id":{id}}}"#);
        let cancel_id = client.request(&cancel).unwrap();
        for direct in direct.request(cancel_id, &cancel, now, None) {
            assert_equal(&direct, &client.next_value().unwrap().unwrap());
        }
        drop(endpoint);
        assert!(client.next_value().unwrap().is_none());
        assert!(!directory.socket().exists());
    }

    #[test]
    fn socket_is_private_and_only_stale_sockets_are_replaced() {
        let directory = Directory::new();
        let dashboard = dashboard();
        let stale = UnixListener::bind(directory.socket()).unwrap();
        drop(stale);
        let endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
        assert_eq!(
            fs::metadata(directory.socket())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            matches!(serve(dashboard.handle(), directory.socket()), Err(error) if error.kind() == io::ErrorKind::AddrInUse)
        );
        drop(endpoint);
        fs::write(directory.socket(), "keep").unwrap();
        assert!(serve(dashboard.handle(), directory.socket()).is_err());
        assert_eq!(fs::read(directory.socket()).unwrap(), b"keep");
    }

    #[test]
    fn endpoint_limits_sessions_and_closes_silent_handshakes_on_drop() {
        let directory = Directory::new();
        let dashboard = dashboard();
        let endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
        endpoint.set_session_limit(1);
        let mut client = Client::connect(directory.socket()).unwrap();
        for _ in 0..3 {
            assert!(
                matches!(Client::connect(directory.socket()), Err(error) if error.to_string() == "too many observation sessions")
            );
        }
        endpoint.set_session_limit(2);
        let mut second = Client::connect(directory.socket()).unwrap();
        endpoint.set_session_limit(0);
        assert!(
            matches!(Client::connect(directory.socket()), Err(error) if error.to_string() == "too many observation sessions")
        );
        assert!(client.call(r#"{"op":"world"}"#).unwrap().end);
        assert!(second.call(r#"{"op":"world"}"#).unwrap().end);
        endpoint.set_session_limit(3);
        let silent = UnixStream::connect(directory.socket()).unwrap();
        // A request confirms the original session remains usable at capacity.
        assert!(client.call(r#"{"op":"world"}"#).unwrap().end);
        drop(endpoint);
        assert!(client.next_value().unwrap().is_none());
        assert!(second.next_value().unwrap().is_none());
        silent
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(Reader::default().read(&silent).unwrap().is_none());
    }

    #[test]
    fn session_slots_release_on_disconnect_and_failed_thread_creation() {
        for fail in [false, true] {
            let shared = Arc::new(Shared {
                stopping: AtomicBool::new(false),
                limit: AtomicUsize::new(1),
                sockets: Mutex::new(Vec::new()),
            });
            let (socket, peer) = UnixStream::pair().unwrap();
            let socket = Arc::new(socket);
            shared.sockets.lock().push(socket.clone());
            let slot = Slot {
                shared: shared.clone(),
                socket,
            };
            assert_eq!(shared.sockets.lock().len(), 1);
            let builder = if fail {
                thread::Builder::new().stack_size(usize::MAX)
            } else {
                thread::Builder::new()
            };
            let worker = builder.spawn(move || session(&dashboard().handle(), &slot));
            if fail {
                assert!(worker.is_err());
            } else {
                let client = Client::hello(peer, Duration::from_secs(1)).unwrap();
                assert_eq!(shared.sockets.lock().len(), 1);
                drop(client);
                worker.unwrap().join().unwrap().unwrap();
            }
            assert!(shared.sockets.lock().is_empty());
            let (socket, _peer) = UnixStream::pair().unwrap();
            let socket = Arc::new(socket);
            shared.sockets.lock().push(socket.clone());
            let reused = Slot {
                shared: shared.clone(),
                socket,
            };
            assert_eq!(shared.sockets.lock().len(), 1);
            drop(reused);
            assert!(shared.sockets.lock().is_empty());
        }
    }

    #[test]
    fn endpoint_refuses_protocol_and_version_mismatches() {
        let directory = Directory::new();
        let endpoint = serve(dashboard().handle(), directory.socket()).unwrap();
        for (name, version) in [(PROTOCOL, 1u32), ("attach", VERSION)] {
            let socket = UnixStream::connect(directory.socket()).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = vec![HELLO];
            hello.extend_from_slice(&version.to_be_bytes());
            hello.extend_from_slice(name.as_bytes());
            send(&socket, &hello).unwrap();
            let refusal = Reader::default().read(&socket).unwrap().unwrap();
            assert_eq!(refusal[0], REFUSE);
            let reason = std::str::from_utf8(&refusal[1..]).unwrap();
            assert!(reason.contains("fictionet-observe version 2"));
            assert!(reason.contains(&format!("{name} version {version}")));
            let (client, peer) = UnixStream::pair().unwrap();
            let worker = thread::spawn(move || Client::hello(client, Duration::from_secs(1)));
            Reader::default().read(&peer).unwrap().unwrap();
            send(&peer, &refusal).unwrap();
            assert!(matches!(worker.join().unwrap(), Err(error) if error.to_string() == reason));
        }
        drop(endpoint);
    }

    #[test]
    fn hello_times_out_and_acceptance_clears_the_read_timeout() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        assert!(
            matches!(Client::hello(socket, Duration::from_millis(10)), Err(error) if timeout(&error))
        );
        let (client, _peer) = client_peer();
        assert_eq!(client.socket.read_timeout().unwrap(), None);
        assert_eq!(client.socket.write_timeout().unwrap(), Some(TIMEOUT));
    }

    #[test]
    fn long_and_empty_values_keep_flags_and_bytes() {
        for bytes in [Vec::new(), vec![42; MAX_MESSAGE - 6], vec![43; 150_000]] {
            let (mut client, peer) = client_peer();
            let expected = bytes.clone();
            let worker = thread::spawn(move || {
                send_value(
                    &peer,
                    Value {
                        id: 9,
                        bytes,
                        binary: true,
                        end: true,
                    },
                )
                .unwrap()
            });
            let value = client.next_value().unwrap().unwrap();
            assert_eq!(value.id, 9);
            assert_eq!(value.bytes, expected);
            assert!(value.binary && value.end);
            worker.join().unwrap();
        }
    }

    #[test]
    fn long_values_are_chunked() {
        let (socket, peer) = UnixStream::pair().unwrap();
        let bytes: Vec<_> = (0..150_000u32).map(|i| i as u8).collect();
        let expected = bytes.clone();
        let worker = thread::spawn(move || {
            send_value(
                &socket,
                Value {
                    id: 9,
                    bytes,
                    binary: true,
                    end: true,
                },
            )
            .unwrap()
        });
        let mut reader = Reader::default();
        let mut got = Vec::new();
        let mut flags = Vec::new();
        loop {
            let frame = reader.read(&peer).unwrap().unwrap();
            assert!(frame.len() <= MAX_MESSAGE);
            assert_eq!(frame[0], REPLY);
            assert_eq!(u32::from_be_bytes(frame[1..5].try_into().unwrap()), 9);
            flags.push(frame[5]);
            got.extend_from_slice(&frame[6..]);
            if frame[5] & MORE == 0 {
                break;
            }
        }
        assert_eq!(got, expected);
        assert_eq!(flags, [BINARY | MORE, BINARY | MORE, BINARY | END]);
        worker.join().unwrap();
    }

    #[test]
    fn oversized_and_truncated_greetings_close_the_client() {
        for size in [MAX_MESSAGE + 1, MAX_MESSAGE + 2] {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            let worker = thread::spawn(move || Client::hello(socket, Duration::from_secs(1)));
            Reader::default().read(&peer).unwrap().unwrap();
            peer.write_all(&(size as u32).to_be_bytes()).unwrap();
            assert_eq!(
                worker.join().unwrap().err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
        for bytes in [vec![0], vec![0, 0, 0, 10, ACCEPT]] {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            let worker = thread::spawn(move || Client::hello(socket, Duration::from_secs(1)));
            Reader::default().read(&peer).unwrap().unwrap();
            peer.write_all(&bytes).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            assert_eq!(
                worker.join().unwrap().err().unwrap().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn partial_frames_and_values_survive_timeouts() {
        for binary in [0, BINARY] {
            for end in [0, END] {
                let (mut client, mut peer) = client_peer();
                client.set_timeout(Some(Duration::from_millis(10))).unwrap();
                let frame = reply_frame(7, binary | MORE, b"first");
                let mut wire = (frame.len() as u32).to_be_bytes().to_vec();
                wire.extend_from_slice(&frame);
                for fragment in [&wire[..2], &wire[2..7], &wire[7..]] {
                    peer.write_all(fragment).unwrap();
                    for _ in 0..2 {
                        assert!(timeout(&client.next_value().unwrap_err()));
                    }
                }
                send(&peer, &reply_frame(7, binary | MORE, b" middle")).unwrap();
                for _ in 0..2 {
                    assert!(timeout(&client.next_value().unwrap_err()));
                }
                send(&peer, &reply_frame(7, binary | end, b" last")).unwrap();
                let value = client.next_value().unwrap().unwrap();
                assert_eq!(value.id, 7);
                assert_eq!(value.bytes, b"first middle last");
                assert_eq!(value.binary, binary != 0);
                assert_eq!(value.end, end != 0);
                send(&peer, &reply_frame(8, END, b"{}")).unwrap();
                let value = client.next_value().unwrap().unwrap();
                assert_eq!(value.id, 8);
                assert_eq!(value.bytes, b"{}");
                assert!(!value.binary && value.end);
                drop(peer);
                assert!(client.next_value().unwrap().is_none());
            }
        }
    }

    #[test]
    fn malformed_flags_continuations_and_messages_close_the_client() {
        for first in [None, Some(0), Some(BINARY)] {
            let mut invalid = vec![(7, MORE | END), (7, 8)];
            if let Some(binary) = first {
                invalid.extend([(8, binary | END), (7, (binary ^ BINARY) | END)]);
            }
            for (id, flags) in invalid {
                let (mut client, mut peer) = client_peer();
                if let Some(binary) = first {
                    client.set_timeout(Some(Duration::from_millis(10))).unwrap();
                    send(&peer, &reply_frame(7, binary | MORE, b"first")).unwrap();
                    assert!(timeout(&client.next_value().unwrap_err()));
                }
                send(&peer, &reply_frame(id, flags, b"last")).unwrap();
                assert_eq!(
                    client.next_value().unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(peer.read(&mut [0]).unwrap(), 0);
                assert!(client.next_value().unwrap().is_none());
            }
        }
        for bytes in [vec![REPLY], vec![ACCEPT]] {
            let (mut client, mut peer) = client_peer();
            send(&peer, &bytes).unwrap();
            assert_eq!(
                client.next_value().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            assert!(client.next_value().unwrap().is_none());
        }
        for size in [65_537u32, 65_538] {
            let (mut client, mut peer) = client_peer();
            peer.write_all(&size.to_be_bytes()).unwrap();
            assert_eq!(
                client.next_value().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            assert!(client.next_value().unwrap().is_none());
        }
    }

    #[test]
    fn eof_inside_a_message_or_value_is_unexpected() {
        for bytes in [vec![0], vec![0, 0, 0, 10, REPLY]] {
            let (mut client, mut peer) = client_peer();
            peer.write_all(&bytes).unwrap();
            drop(peer);
            assert_eq!(
                client.next_value().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        for timed_out in [false, true] {
            let (mut client, peer) = client_peer();
            client.set_timeout(Some(Duration::from_millis(10))).unwrap();
            send(&peer, &reply_frame(7, MORE, b"first")).unwrap();
            if timed_out {
                assert!(timeout(&client.next_value().unwrap_err()));
            }
            drop(peer);
            let error = client.next_value().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            assert_eq!(error.to_string(), "the world closed during a reply value");
            assert!(client.next_value().unwrap().is_none());
        }
    }

    #[test]
    fn ended_runs_replay_snapshot_events_and_end_to_late_clients() {
        let directory = Directory::new();
        let dashboard = dashboard();
        emit(&dashboard, 2, Event::new("test", "tick"));
        dashboard.observer().end(RunTime::ZERO);
        let _endpoint = serve(dashboard.handle(), directory.socket()).unwrap();
        let mut client = Client::connect(directory.socket()).unwrap();
        client.set_timeout(Some(Duration::from_secs(2))).unwrap();
        client.request(r#"{"op":"watch","after":0}"#).unwrap();
        for expected in ["snapshot", "event", "event", "end"] {
            let value = client.next_value().unwrap().unwrap();
            assert!(
                matches!(value.envelope(), Some(Envelope::Event { name, .. }) if name == expected)
            );
            assert_eq!(value.end, expected == "end");
        }
    }
}
