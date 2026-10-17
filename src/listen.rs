use fictionet::sync::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use crate::attach::NameGuard;
use crate::cx::CancelWait;
use crate::relay::unix::cvt;
use crate::relay::{self, Message, PacketQueue, unix};
use crate::{Attacher, Attachment, Cx, Packet, RecvError};

/// Where a world listens for attach and observers.
///
/// [`listen`] takes one. Its text form is the one `fictionet attach --world`
/// and the other subcommands take, so a program can read it from its
/// command line with [`str::parse`] and print it back with `Display`:
///
/// ```
/// use fictionet::WorldSocket;
///
/// let socket: WorldSocket = "unix:/run/fictionet/world.sock".parse().unwrap();
/// assert_eq!(socket, WorldSocket::UnixSocket("/run/fictionet/world.sock".into()));
/// assert_eq!(socket.to_string(), "unix:/run/fictionet/world.sock");
/// assert!("/run/fictionet/world.sock".parse::<WorldSocket>().is_err());
/// ```
///
/// The enum is `#[non_exhaustive]` so that other transports, such as the
/// [TLS transport for remote sandboxes](crate::roadmap#remote-attach-a-tls-transport),
/// can join it as variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WorldSocket {
    /// A Unix `SOCK_SEQPACKET` socket at this path. Its text form is
    /// `unix:<path>`.
    UnixSocket(PathBuf),
}

impl std::str::FromStr for WorldSocket {
    type Err = ParseWorldSocketError;

    /// Parses `unix:<path>`. The path must not be empty.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_prefix("unix:") {
            Some(path) if !path.is_empty() => Ok(WorldSocket::UnixSocket(path.into())),
            _ => Err(ParseWorldSocketError {
                input: s.to_owned(),
            }),
        }
    }
}

impl std::fmt::Display for WorldSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorldSocket::UnixSocket(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

/// The error from parsing a [`WorldSocket`]: the text was not
/// `unix:<path>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseWorldSocketError {
    input: String,
}

impl std::fmt::Display for ParseWorldSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "expected unix:<path>, not {:?}", self.input)
    }
}

impl std::error::Error for ParseWorldSocketError {}

/// Opens the world socket that `socket` names, so that `fictionet attach`
/// can attach sandboxes to the world. Each sandbox that attaches is added to
/// `attacher`, and the world receives it from the matching
/// [`Attachments`](crate::Attachments).
///
/// `listen` binds the socket and returns immediately. Accepting
/// connections continues on a helper thread that Fictionet starts, so
/// `listen` is not async and works the same under any executor, tokio or
/// [`block_on`](crate::block_on). It fails if the socket cannot be made,
/// for example when another live world is already listening at that path.
/// A socket file left behind by a world that has exited is replaced.
///
/// The socket speaks the [relay protocol](crate::proto).
/// With `observe` enabled, it admits at most 64 observer sessions,
/// including idle clients. [`Listening::set_observer_limit`] changes
/// that ceiling. See the [observer budgets](crate::observe#resource-limits).
/// Dropping the returned [`Listening`] closes the socket, so no more
/// sandboxes can attach. Sandboxes already attached stay attached, and the
/// helper thread keeps running until the last of them detaches.
/// If a sandbox detaches before the world takes its attachment, the helper
/// thread reclaims its socket and buffers, even when the world is not
/// polling [`Attachments`](crate::Attachments).
/// If the kernel refuses to watch a sandbox connection, it is closed and
/// any existing attachment's next receive reports [`RecvError::Closed`].
///
/// The attachment hub is marked as fed by a real listener. Using its
/// [`Attachments`](crate::Attachments) in a [`lab`](crate::lab), through
/// `get`, `next`, or `map`, fails that region before handing out an
/// attachment. The marker remains after the listener is dropped.
///
/// # How packets move
///
/// The helper thread does not carry packets. An [`Attachment`](crate::Attachment)
/// reads its connection directly, without blocking, on the thread that polls
/// the world, up to 64 packets per turn. Only when nothing is waiting does
/// it hand the connection to the helper thread, which waits for it to
/// become readable and then wakes the world. So a busy attachment never
/// waits on the helper thread, and one that was idle pays one wake-up,
/// some microseconds.
///
/// Sending never waits either. A packet is written to the connection
/// immediately, as one whole datagram. If the connection's buffer is full, the
/// packet waits in a queue inside the world, and the queue is written out
/// as attach makes room, in order. The helper thread writes it out, so
/// this happens whether or not the world is reading from that attachment.
///
/// The queue has a budget of 32 MiB. Each waiting packet counts its length
/// plus 64 bytes, so a flood of tiny packets is bounded too. A packet that
/// would go past the budget is dropped. This is loss in the transport, not
/// loss the world adds on purpose, and it makes the sandbox's TCP send data
/// again, often after a delay. The large budget absorbs bursts, such as
/// many downloads running side by side, so they are not lost. Enough
/// traffic can still fill any budget.
///
/// Each connection's buffers are also raised to 4 MiB. Going past the
/// system limit (`net.core.wmem_max`, about 200 KiB, a hundred full-size
/// packets) needs CAP_NET_ADMIN, so give the world's container that
/// capability. Without it, more packets wait in the queue.
///
#[doc = include_str!("../docs/diagrams/listen.svg")]
///
/// The wall-clock timers behind [`Cx::sleep`](crate::Cx::sleep) work the
/// same way: one helper thread waits for the earliest deadline and wakes
/// the world. Fictionet has no reactor of its own, and needs none from the
/// executor.
///
/// ```no_run
/// # use fictionet::{Attachments, Cx, Result};
/// # async fn world(_fcx: Cx, _attachments: Attachments) -> Result { Ok(()) }
/// # fn main() -> Result {
/// let (attacher, attachments) = fictionet::attachments();
/// let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
/// let _listening = fictionet::listen(socket, attacher)?;
/// fictionet::block_on(fictionet::run(fictionet::Seed::random(), |fcx| world(fcx, attachments)))
/// # }
/// ```
pub fn listen(socket: WorldSocket, attacher: Attacher) -> std::io::Result<Listening> {
    listen_with_ops(socket, attacher, ListenOps { epoll_ctl, accept4 })
}

/// The listener's registration and accept operations.
pub(crate) struct ListenOps {
    epoll_ctl: fn(RawFd, libc::c_int, RawFd, u32, u64) -> io::Result<()>,
    accept4: fn(RawFd) -> io::Result<OwnedFd>,
}

pub(crate) fn listen_with_ops(
    socket: WorldSocket,
    attacher: Attacher,
    ops: ListenOps,
) -> io::Result<Listening> {
    attacher.mark_listener()?;
    let WorldSocket::UnixSocket(path) = socket;
    let listener = bind(&path)?;
    // SAFETY: plain syscalls; each fd is owned from here.
    let epoll = unsafe { OwnedFd::from_raw_fd(cvt(libc::epoll_create1(libc::EPOLL_CLOEXEC))?) };
    let wake_fd = unsafe {
        OwnedFd::from_raw_fd(cvt(libc::eventfd(
            0,
            libc::EFD_NONBLOCK | libc::EFD_CLOEXEC,
        ))?)
    };
    (ops.epoll_ctl)(
        epoll.as_raw_fd(),
        libc::EPOLL_CTL_ADD,
        listener.as_raw_fd(),
        libc::EPOLLIN as u32,
        LISTEN_TOKEN,
    )?;
    (ops.epoll_ctl)(
        epoll.as_raw_fd(),
        libc::EPOLL_CTL_ADD,
        wake_fd.as_raw_fd(),
        libc::EPOLLIN as u32,
        WAKE_TOKEN,
    )?;
    let shared = Arc::new(ListenShared {
        epoll,
        wake_fd,
        ops,
        conns: Mutex::new(HashMap::new()),
        closing: AtomicBool::new(false),
        #[cfg(feature = "observe")]
        sessions: Arc::default(),
    });
    let (closed_tx, closed_rx) = mpsc::channel();
    let helper_shared = shared.clone();
    let helper_attacher = attacher.clone();
    std::thread::Builder::new()
        .name("fictionet-listen".into())
        .spawn(move || helper(helper_shared, listener, helper_attacher, closed_tx))?;
    Ok(Listening {
        shared,
        path,
        closed: closed_rx,
        attacher,
    })
}

fn epoll_ctl(epoll: RawFd, op: libc::c_int, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
    let mut event = libc::epoll_event { events, u64: token };
    // SAFETY: `event` is valid for the call.
    cvt(unsafe { libc::epoll_ctl(epoll, op, fd, &mut event) })?;
    Ok(())
}

fn accept4(listener: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the returned fd is owned from here.
    unsafe {
        Ok(OwnedFd::from_raw_fd(cvt(libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        ))?))
    }
}

/// Makes the listening socket. A socket file left behind by a world that is
/// gone is replaced; a live one is an error.
fn bind(path: &Path) -> io::Result<OwnedFd> {
    let (addr, len) = unix::address(path)?;
    let fd = unix::socket(true)?;
    // SAFETY: `addr` is a valid sockaddr_un of length `len`.
    let bound =
        |fd: &OwnedFd| cvt(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) });
    if let Err(e) = bound(&fd) {
        if e.raw_os_error() != Some(libc::EADDRINUSE) {
            return Err(e);
        }
        use std::os::unix::fs::FileTypeExt;
        let is_socket = std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false);
        let stale = is_socket
            && matches!(unix::connect(path), Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED));
        if !stale {
            return Err(e);
        }
        std::fs::remove_file(path)?;
        bound(&fd)?;
    }
    // SAFETY: plain syscall.
    cvt(unsafe { libc::listen(fd.as_raw_fd(), 128) })?;
    Ok(fd)
}

const LISTEN_TOKEN: u64 = 0;
const WAKE_TOKEN: u64 = 1;

/// What the helper thread and the attachments of one [`listen`] share.
pub(crate) struct ListenShared {
    epoll: OwnedFd,
    ops: ListenOps,
    /// An eventfd that wakes the helper thread.
    wake_fd: OwnedFd,
    /// Accepted connections, by epoll token.
    conns: Mutex<HashMap<u64, Arc<ConnSlot>>>,
    /// The [`Listening`] was dropped.
    closing: AtomicBool,
    #[cfg(feature = "observe")]
    sessions: Arc<crate::observe::Sessions>,
}

impl ListenShared {
    fn unwatch(&self, fd: RawFd) {
        // Removing a watch is best-effort teardown. It grants no
        // readiness and clears no retry state, unlike ADD and MOD.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "removing a watch is teardown; it grants no readiness and clears no retry state"
        )]
        let _ = (self.ops.epoll_ctl)(self.epoll.as_raw_fd(), libc::EPOLL_CTL_DEL, fd, 0, 0);
    }

    fn wake_helper(&self) {
        let one: u64 = 1;
        // SAFETY: writes 8 bytes from `one`. A full counter is fine: the
        // helper is awake then anyway.
        unsafe { libc::write(self.wake_fd.as_raw_fd(), (&raw const one).cast(), 8) };
    }
}

/// One accepted connection, shared by its [`SocketLink`] and the helper
/// thread.
struct ConnSlot {
    fd: OwnedFd,
    /// The connection's epoll token.
    token: u64,
    /// The world, waiting for a packet.
    waker: Mutex<Option<Waker>>,
    /// The connection's name, held until it closes from either side.
    name: Mutex<Option<NameGuard>>,
    /// Packets that found the connection full. The world adds to it in
    /// `send`; the helper thread writes it out when attach makes room, so
    /// it drains even while the world reads nothing.
    out: Mutex<OutQueue>,
}

impl ConnSlot {
    fn release_name(&self) {
        let guard = self.name.lock().take();
        drop(guard);
    }

    /// Writes queued packets until the connection is full again or the
    /// queue is empty, and watches for room only while packets wait.
    fn flush(&self, out: &mut OutQueue, shared: &ListenShared) {
        let fd = self.fd.as_raw_fd();
        while let Some(packet) = out.queue.front() {
            match unix::send_parts(fd, &[&[relay::PACKET], &packet.0], true) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    out.dropped += out.queue.len() as u64;
                    out.queue.clear();
                    break;
                }
            }
            out.queue.pop().expect("front was there");
        }
        // If MOD fails, want_out stays true: EPOLLOUT remains registered,
        // and the helper ignores it while the queue is empty.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "if MOD fails, want_out stays true and EPOLLOUT stays registered, which the helper ignores while the queue is empty"
        )]
        let _ = self.watch_out(out, shared, false);
    }

    /// Asks epoll to report when the connection has room (`true`), or to
    /// stop (`false`). The helper thread then flushes the queue.
    fn watch_out(&self, out: &mut OutQueue, shared: &ListenShared, on: bool) -> io::Result<()> {
        if out.want_out == on {
            return Ok(());
        }
        let mut events = (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
        if on {
            events |= libc::EPOLLOUT as u32;
        }
        (shared.ops.epoll_ctl)(
            shared.epoll.as_raw_fd(),
            libc::EPOLL_CTL_MOD,
            self.fd.as_raw_fd(),
            events,
            self.token,
        )?;
        out.want_out = on;
        Ok(())
    }
}

/// The packets of one connection that wait for room, oldest first.
#[derive(Default)]
struct OutQueue {
    queue: PacketQueue,
    /// The connection is registered for writability.
    want_out: bool,
    /// The connection is closed: nothing more is queued.
    closed: bool,
    /// Packets dropped because the connection and the queue were full, or
    /// the connection closed.
    dropped: u64,
}

/// A connection in its handshake, owned by the helper thread.
struct Handshake {
    fd: OwnedFd,
    deadline: Instant,
}

/// The helper thread: accepts connections, runs their handshakes, and wakes
/// idle attachments when their connection becomes readable.
fn helper(
    shared: Arc<ListenShared>,
    listener: OwnedFd,
    attacher: Attacher,
    closed: mpsc::Sender<()>,
) {
    let epoll = shared.epoll.as_raw_fd();
    let mut listener = Some(listener);
    // Expiry and shutdown close handshake sockets in token order.
    let mut handshakes: BTreeMap<u64, Handshake> = BTreeMap::new();
    let mut next_token: u64 = 2;
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
    // While the process is out of descriptors or memory, pause accepts to
    // avoid spinning. Keep retrying until the listening socket is watched.
    let mut accept_paused: Option<Instant> = None;
    loop {
        if shared.closing.load(Ordering::Acquire) {
            if let Some(fd) = listener.take() {
                shared.unwatch(fd.as_raw_fd());
                drop(fd);
                handshakes.clear();
                accept_paused = None;
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "POL-TEARDOWN: tells Drop the listener is closed; Drop may have stopped waiting"
                )]
                let _ = closed.send(());
            }
            if shared.conns.lock().is_empty() {
                return;
            }
        }
        let now = Instant::now();
        if let (Some(until), Some(fd)) = (accept_paused, &listener)
            && until <= now
        {
            accept_paused = match (shared.ops.epoll_ctl)(
                epoll,
                libc::EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                libc::EPOLLIN as u32,
                LISTEN_TOKEN,
            ) {
                Ok(()) => None,
                Err(_) => Some(now + ACCEPT_RETRY),
            };
        }
        let timeout = handshakes
            .values()
            .map(|h| h.deadline)
            .chain(accept_paused)
            .map(|d| d.saturating_duration_since(now))
            .min()
            .map(|d| d.as_millis().min(i32::MAX as u128) as i32 + 1)
            .unwrap_or(-1);
        // SAFETY: `events` is valid for 64 entries.
        let n =
            unsafe { libc::epoll_wait(epoll, events.as_mut_ptr(), events.len() as i32, timeout) };
        let n = if n < 0 { 0 } else { n as usize };
        for event in &events[..n] {
            let (token, flags) = (event.u64, event.events);
            match token {
                LISTEN_TOKEN => {
                    let Some(fd) = &listener else { continue };
                    if accept_all(fd.as_raw_fd(), &shared, &mut handshakes, &mut next_token)
                        .is_err()
                    {
                        shared.unwatch(fd.as_raw_fd());
                        accept_paused = Some(Instant::now() + ACCEPT_RETRY);
                    }
                }
                WAKE_TOKEN => {
                    let mut count = [0u8; 8];
                    // SAFETY: reads 8 bytes into `count`.
                    unsafe { libc::read(shared.wake_fd.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
                }
                token if handshakes.contains_key(&token) => {
                    let handshake = handshakes.remove(&token).unwrap();
                    if let Some(handshake) =
                        handshake_step(&shared, &attacher, token, handshake, &mut buf)
                    {
                        handshakes.insert(token, handshake);
                    }
                }
                token => {
                    let slot = shared.conns.lock().get(&token).cloned();
                    let Some(slot) = slot else { continue };
                    let hangup = (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32;
                    if flags & hangup != 0 {
                        slot.release_name();
                    }
                    if flags & libc::EPOLLOUT as u32 != 0 {
                        let mut out = slot.out.lock();
                        if !out.queue.is_empty() {
                            slot.flush(&mut out, &shared);
                        }
                    }
                    if flags & (libc::EPOLLIN as u32 | hangup) != 0 {
                        let waker = slot.waker.lock().take();
                        if let Some(w) = waker {
                            w.wake();
                        }
                    }
                }
            }
        }
        let now = Instant::now();
        handshakes.retain(|_, h| h.deadline > now);
    }
}

/// How long the helper waits before it accepts again after running out of
/// descriptors or memory.
const ACCEPT_RETRY: std::time::Duration = std::time::Duration::from_millis(100);

/// Accepts every waiting connection. An error means the process is out of
/// descriptors or memory, and the connections still wait.
fn accept_all(
    listener: RawFd,
    shared: &ListenShared,
    handshakes: &mut BTreeMap<u64, Handshake>,
    next_token: &mut u64,
) -> io::Result<()> {
    loop {
        let fd = match (shared.ops.accept4)(listener) {
            Ok(fd) => fd,
            Err(err) => match err.raw_os_error() {
                Some(libc::EINTR) | Some(libc::ECONNABORTED) => continue,
                Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => {
                    return Err(err);
                }
                _ => return Ok(()),
            },
        };
        unix::raise_buffers(fd.as_raw_fd());
        let token = *next_token;
        *next_token += 1;
        if (shared.ops.epoll_ctl)(
            shared.epoll.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            libc::EPOLLIN as u32,
            token,
        )
        .is_ok()
        {
            handshakes.insert(
                token,
                Handshake {
                    fd,
                    deadline: Instant::now() + relay::HANDSHAKE_TIMEOUT,
                },
            );
        }
    }
}

/// Reads a `hello` if one is there. Gives the handshake back if it still
/// waits for one; otherwise the connection is accepted or closed.
fn handshake_step(
    shared: &Arc<ListenShared>,
    attacher: &Attacher,
    token: u64,
    handshake: Handshake,
    buf: &mut [u8],
) -> Option<Handshake> {
    let fd = handshake.fd.as_raw_fd();
    let n = match unix::recv(fd, buf, true) {
        Ok(0) => return None,
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Some(handshake),
        Err(_) => return None,
    };
    let refuse = |reason: &str| {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "POL-TEARDOWN: the handshake is dropped either way; this reply only informs a client that may be gone"
        )]
        let _ = unix::send(fd, &Message::Refuse(reason.to_owned()).encode(), true);
    };
    let hello = match relay::decode(&buf[..n]) {
        Ok(Message::Hello(hello)) => hello,
        // Anything else first, including `auth`, which the local socket
        // does not use, closes the connection.
        _ => return None,
    };
    if hello.version != relay::VERSION {
        refuse(&format!("unsupported protocol version {}", hello.version));
        return None;
    }
    if hello.kind != relay::OBSERVE && hello.kind.starts_with(relay::OBSERVE) {
        // Kept for later versions of the observe API.
        refuse(&format!("unsupported observer type {}", hello.kind));
        return None;
    }
    #[cfg(not(feature = "observe"))]
    if hello.kind == relay::OBSERVE {
        refuse("observer sessions are disabled");
        return None;
    }
    #[cfg(feature = "observe")]
    if hello.kind == relay::OBSERVE {
        // An observer is not a sandbox: it takes no name and never becomes
        // an Attachment. Its session runs on a thread of its own.
        let Some(slot) = shared.sessions.reserve() else {
            refuse("this listener has too many observer sessions");
            return None;
        };
        if unix::send(fd, &Message::Accept.encode(), true).is_err() {
            return None;
        }
        shared.unwatch(fd);
        crate::observe::serve_session(attacher.clone(), handshake.fd, slot);
        return None;
    }
    let guard = match attacher.reserve(&hello.name) {
        Ok(guard) => guard,
        Err(crate::AttachError::Taken) => {
            refuse(&format!("{} is already attached", hello.name));
            return None;
        }
        Err(crate::AttachError::BadName) => {
            refuse("name must be 1 to 255 bytes");
            return None;
        }
    };
    let events = (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
    if let Err(error) = (shared.ops.epoll_ctl)(
        shared.epoll.as_raw_fd(),
        libc::EPOLL_CTL_MOD,
        fd,
        events,
        token,
    ) {
        refuse(&format!("cannot watch connection: {error}"));
        return None;
    }
    if unix::send(fd, &Message::Accept.encode(), true).is_err() {
        return None;
    }
    let slot = Arc::new(ConnSlot {
        fd: handshake.fd,
        token,
        waker: Mutex::new(None),
        name: Mutex::new(Some(guard)),
        out: Mutex::new(OutQueue::default()),
    });
    shared.conns.lock().insert(token, slot.clone());
    let link = SocketLink {
        listen: shared.clone(),
        token,
        slot,
        buf: vec![0u8; relay::MAX_MESSAGE + 1],
        budget: BUDGET,
        closed: false,
        wait: CancelWait::default(),
    };
    attacher.deliver(Attachment::from_socket(hello.name, hello.mtu, link));
    None
}

/// Packets an attachment reads in a row before it gives the thread back.
const BUDGET: u32 = 64;

/// How many bytes of packets may wait for room in a connection, counting
/// [`crate::PACKET_COST`] for each. Past that, packets are dropped.
const QUEUE_LIMIT: usize = 32 << 20;

/// The connection behind an [`Attachment`] made by [`listen`].
pub(crate) struct SocketLink {
    listen: Arc<ListenShared>,
    token: u64,
    slot: Arc<ConnSlot>,
    buf: Vec<u8>,
    /// Packets left in this turn.
    budget: u32,
    /// The connection is closed: every `recv` is `Closed`.
    closed: bool,
    /// Where a receiver outside the run waits for a cancel.
    wait: CancelWait,
}

impl SocketLink {
    /// Whether attach is known to have closed the connection.
    pub(crate) fn peer_gone(&self) -> bool {
        self.closed || self.slot.name.lock().is_none()
    }

    /// A check for [`peer_gone`](SocketLink::peer_gone) that works without
    /// this link. It does not keep the connection open: once the link is
    /// dropped, it says gone.
    pub(crate) fn peer_gone_check(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let slot = Arc::downgrade(&self.slot);
        move || slot.upgrade().is_none_or(|s| s.name.lock().is_none())
    }

    fn close(&mut self) {
        self.closed = true;
        {
            let mut out = self.slot.out.lock();
            out.closed = true;
            out.queue.clear();
        }
        unix::shutdown(self.slot.fd.as_raw_fd());
        self.slot.release_name();
    }

    pub(crate) fn poll_recv(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Packet, RecvError>> {
        // A cancel comes first, as it does for every wait.
        if fcx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        if self.closed {
            return Poll::Ready(Err(RecvError::Closed));
        }
        if self.budget == 0 {
            self.budget = BUDGET;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let fd = self.slot.fd.as_raw_fd();
        let mut registered = false;
        loop {
            match unix::recv(fd, &mut self.buf, true) {
                Ok(n) if (1..=relay::MAX_MESSAGE).contains(&n) && self.buf[0] == relay::PACKET => {
                    self.budget -= 1;
                    return Poll::Ready(Ok(Packet(self.buf[1..n].to_vec())));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if registered {
                        self.budget = BUDGET;
                        return Poll::Pending;
                    }
                    // Hand the connection to the helper thread, then read
                    // once more: a packet may have come in before the
                    // waker was in place.
                    *self.slot.waker.lock() = Some(cx.waker().clone());
                    registered = true;
                    if fcx.register_cancel(cx.waker(), &mut self.wait) {
                        return Poll::Ready(Err(RecvError::Cancelled));
                    }
                }
                _ => {
                    // EOF, oversized datagrams, wrong kinds, and terminal errors close.
                    self.close();
                    return Poll::Ready(Err(RecvError::Closed));
                }
            }
        }
    }

    pub(crate) fn send(&mut self, packet: Packet) {
        if self.closed {
            return;
        }
        let mut out = self.slot.out.lock();
        if out.closed {
            return;
        }
        if !out.queue.is_empty() {
            self.slot.flush(&mut out, &self.listen);
        }
        if out.queue.is_empty() {
            match unix::send_parts(
                self.slot.fd.as_raw_fd(),
                &[&[relay::PACKET], &packet.0],
                true,
            ) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // Attach is gone; the next `recv` says so.
                Err(_) => {
                    out.dropped += 1;
                    return;
                }
            }
        }
        if out.queue.try_push(packet, Some(QUEUE_LIMIT)).is_err() {
            out.dropped += 1;
            return;
        }
        if self.slot.watch_out(&mut out, &self.listen, true).is_err() {
            out.dropped += out.queue.len() as u64;
            // The helper must not flush packets counted as dropped.
            out.queue.clear();
            drop(out);
            self.close();
        }
    }
}

impl Drop for SocketLink {
    fn drop(&mut self) {
        self.listen.unwatch(self.slot.fd.as_raw_fd());
        let last = {
            let mut conns = self.listen.conns.lock();
            conns.remove(&self.token);
            conns.is_empty()
        };
        self.slot.release_name();
        if last && self.listen.closing.load(Ordering::Acquire) {
            self.listen.wake_helper();
        }
    }
}

/// A world socket that sandboxes can attach to. Made by [`listen`].
///
/// Dropping it closes the socket. Attachments already made keep working.
/// When the world's run has ended, dropping it first waits, up to a
/// second, for observers' streams to send their end, so a world that exits
/// right after its run tells them it ended.
pub struct Listening {
    shared: Arc<ListenShared>,
    path: PathBuf,
    /// The helper thread says here that it closed the socket.
    closed: mpsc::Receiver<()>,
    /// The world's channel, to see whether observers still follow an
    /// ended run.
    attacher: Attacher,
}

/// How long dropping a [`Listening`] waits for observers of an ended run.
const OBSERVERS_LINGER: std::time::Duration = std::time::Duration::from_secs(1);

impl Listening {
    /// Sets the maximum number of observer sessions on this listener.
    /// The default is 64, including sessions with no subscriptions.
    /// A full listener refuses new observers before starting a thread.
    /// Attachments are unaffected.
    ///
    /// Lowering the limit leaves existing sessions connected. New ones
    /// are refused until the count falls below the limit. Zero refuses all
    /// new observers. Each listener has its own limit, even when listeners
    /// share an [`Attacher`].
    #[cfg(feature = "observe")]
    pub fn set_observer_limit(&self, limit: usize) {
        self.shared.sessions.set_limit(limit);
    }

    /// Binds a socket with a new attachment channel.
    /// Keep the returned guard alive while accepting attachments.
    /// Existing attachments survive when the guard is dropped.
    pub fn bind(socket: WorldSocket) -> std::io::Result<(Self, crate::Attachments)> {
        let (attacher, attachments) = crate::attachments();
        let listening = listen(socket, attacher)?;
        Ok((listening, attachments))
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        let deadline = Instant::now() + OBSERVERS_LINGER;
        while let Some(graph) = self.attacher.graph()
            && graph.state().ended
            && graph.observed()
            && Instant::now() < deadline
        {
            drop(graph);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.shared.closing.store(true, Ordering::Release);
        self.shared.wake_helper();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "POL-TEARDOWN: Drop waits a bounded time for the helper to close the listener, then removes the socket file either way"
        )]
        let _ = self.closed.recv_timeout(std::time::Duration::from_secs(5));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "POL-TEARDOWN: removes the listener's socket file in Drop"
        )]
        let _ = std::fs::remove_file(&self.path);
    }
}

impl std::fmt::Debug for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listening")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, InterfaceExt, Seed, attachments, block_on, run};
    use std::future::{Future, poll_fn};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn socket(tag: &str) -> WorldSocket {
        WorldSocket::UnixSocket(std::env::temp_dir().join(format!(
            "fictionet-listen-{}-{tag}.sock",
            std::process::id()
        )))
    }

    struct Client(OwnedFd);

    impl Client {
        fn hello(path: &Path, name: &str) -> Self {
            let fd = unix::connect(path).unwrap();
            unix::set_timeout(fd.as_raw_fd(), libc::SO_RCVTIMEO, Some(TIMEOUT)).unwrap();
            let hello = Message::Hello(relay::Hello {
                version: relay::VERSION,
                mtu: 1500,
                kind: "tun".into(),
                name: name.into(),
            });
            unix::send(fd.as_raw_fd(), &hello.encode(), false).unwrap();
            Self(fd)
        }

        fn recv(&self) -> Vec<u8> {
            let mut buf = vec![0; relay::MAX_MESSAGE + 1];
            let n =
                unix::recv(self.0.as_raw_fd(), &mut buf, false).expect("receive before timeout");
            buf.truncate(n);
            buf
        }
    }

    #[test]
    fn accepts_resume_after_accept_and_registration_resource_errors() {
        static ACCEPTS: AtomicUsize = AtomicUsize::new(0);
        static ADDS: AtomicUsize = AtomicUsize::new(0);
        static PAUSED: std::sync::Mutex<Option<mpsc::Sender<()>>> = std::sync::Mutex::new(None);
        let (paused_tx, paused_rx) = mpsc::channel();
        *PAUSED.lock().unwrap() = Some(paused_tx);
        let ops = ListenOps {
            accept4: |fd| {
                if ACCEPTS.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(io::Error::from_raw_os_error(libc::EMFILE))
                } else {
                    accept4(fd)
                }
            },
            epoll_ctl: |epoll, op, fd, events, token| {
                if op == libc::EPOLL_CTL_ADD
                    && token == LISTEN_TOKEN
                    && ADDS.fetch_add(1, Ordering::SeqCst) == 1
                {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    epoll_ctl(epoll, op, fd, events, token)?;
                    if op == libc::EPOLL_CTL_DEL
                        && let Some(tx) = PAUSED.lock().unwrap().take()
                    {
                        tx.send(()).unwrap();
                    }
                    Ok(())
                }
            },
        };
        let (attacher, _attachments) = attachments();
        let listening = listen_with_ops(socket("accept-retry"), attacher, ops).unwrap();
        let first = Client::hello(&listening.path, "first");
        paused_rx.recv_timeout(TIMEOUT).expect("accepts paused");
        let late = Client::hello(&listening.path, "late");
        assert_eq!(late.recv(), [relay::ACCEPT]);
        assert_eq!(first.recv(), [relay::ACCEPT]);
        assert_eq!(ADDS.load(Ordering::SeqCst), 3);
        assert!(ACCEPTS.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn failed_send_watch_closes_the_attachment_and_drops_queued_packets() {
        static FAILURES: AtomicUsize = AtomicUsize::new(0);
        let ops = ListenOps {
            epoll_ctl: |epoll, op, fd, events, token| {
                if op == libc::EPOLL_CTL_MOD && events & libc::EPOLLOUT as u32 != 0 {
                    FAILURES.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    epoll_ctl(epoll, op, fd, events, token)
                }
            },
            accept4,
        };
        let (attacher, mut attachments) = attachments();
        let listening = listen_with_ops(socket("send-watch"), attacher.clone(), ops).unwrap();
        let client = Client::hello(&listening.path, "agent");
        assert_eq!(client.recv(), [relay::ACCEPT]);
        let shared = listening.shared.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let world = std::thread::spawn(move || {
            let result = block_on(run(Seed::from_u64(0), move |fcx| async move {
                let mut agent = attachments.get(&fcx, "agent").await?;
                let slot = shared.conns.lock().get(&2).unwrap().clone();
                // The client does not drain the burst, so it exceeds even
                // the raised socket buffer and needs EPOLLOUT.
                for _ in 0..10_000 {
                    agent.send(Packet(vec![0; 1400]));
                }
                assert_eq!(agent.recv(&fcx).await, Err(RecvError::Closed));
                let out = slot.out.lock();
                assert!(out.closed);
                assert!(!out.want_out);
                assert!(out.queue.is_empty());
                assert_eq!(out.dropped, 1);
                Ok(())
            }));
            done_tx.send(result).unwrap();
        });
        done_rx
            .recv_timeout(TIMEOUT)
            .expect("the world's receive must report Closed")
            .unwrap();
        world.join().unwrap();
        assert_eq!(FAILURES.load(Ordering::SeqCst), 1);
        assert!(attacher.reserve("agent").is_ok(), "name must be released");
    }

    #[test]
    fn failed_handshake_watch_refuses_without_delivering_an_attachment() {
        static FAILURES: AtomicUsize = AtomicUsize::new(0);
        let ops = ListenOps {
            epoll_ctl: |epoll, op, fd, events, token| {
                if op == libc::EPOLL_CTL_MOD {
                    FAILURES.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    epoll_ctl(epoll, op, fd, events, token)
                }
            },
            accept4,
        };
        let (attacher, mut attachments) = attachments();
        let listening = listen_with_ops(socket("handshake-watch"), attacher.clone(), ops).unwrap();
        let client = Client::hello(&listening.path, "agent");
        let response = client.recv();
        assert!(matches!(
            relay::decode(&response),
            Ok(Message::Refuse(reason)) if reason.starts_with("cannot watch connection:")
        ));
        assert!(client.recv().is_empty(), "the connection must close");
        assert_eq!(FAILURES.load(Ordering::SeqCst), 1);
        assert!(listening.shared.conns.lock().is_empty());
        assert!(attacher.reserve("agent").is_ok(), "name must be released");
        block_on(run(Seed::from_u64(0), move |fcx| async move {
            let mut next = std::pin::pin!(attachments.next(&fcx));
            poll_fn(|cx| {
                assert!(
                    next.as_mut().poll(cx).is_pending(),
                    "no attachment delivered"
                );
                Poll::Ready(())
            })
            .await;
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn failed_watch_removal_keeps_writability_registered() {
        static MODS: AtomicUsize = AtomicUsize::new(0);
        let ops = ListenOps {
            epoll_ctl: |epoll, op, fd, events, token| {
                // Handshake, enable EPOLLOUT, then fail disabling it once.
                if op == libc::EPOLL_CTL_MOD && MODS.fetch_add(1, Ordering::SeqCst) == 2 {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                } else {
                    epoll_ctl(epoll, op, fd, events, token)
                }
            },
            accept4,
        };
        let (attacher, mut attachments) = attachments();
        let listening = listen_with_ops(socket("watch-removal"), attacher, ops).unwrap();
        let client = Client::hello(&listening.path, "agent");
        assert_eq!(client.recv(), [relay::ACCEPT]);
        let shared = listening.shared.clone();
        block_on(run(Seed::from_u64(0), move |fcx| async move {
            let _agent = attachments.get(&fcx, "agent").await?;
            let slot = shared.conns.lock().get(&2).unwrap().clone();
            let mut out = slot.out.lock();
            slot.watch_out(&mut out, &shared, true).unwrap();
            slot.flush(&mut out, &shared);
            assert!(out.want_out);
            assert!(!out.closed);
            assert_eq!(MODS.load(Ordering::SeqCst), 3);
            slot.watch_out(&mut out, &shared, false).unwrap();
            assert!(!out.want_out);
            assert_eq!(MODS.load(Ordering::SeqCst), 4);
            Ok(())
        }))
        .unwrap();
    }
}
