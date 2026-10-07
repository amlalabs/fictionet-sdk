use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use crate::attach::NameGuard;
use crate::cx::CancelWait;
use crate::relay::{self, Message, unix};
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
            _ => Err(ParseWorldSocketError { input: s.to_owned() }),
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
/// Dropping the returned [`Listening`] closes the socket, so no more
/// sandboxes can attach. Sandboxes already attached stay attached, and the
/// helper thread keeps running until the last of them detaches.
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
/// # async fn world(_cx: Cx, _attachments: Attachments) -> Result { Ok(()) }
/// # fn main() -> Result {
/// let (attacher, attachments) = fictionet::attachments();
/// let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
/// let _listening = fictionet::listen(socket, attacher)?;
/// fictionet::block_on(fictionet::run(|cx| world(cx, attachments)))
/// # }
/// ```
pub fn listen(socket: WorldSocket, attacher: Attacher) -> std::io::Result<Listening> {
    let WorldSocket::UnixSocket(path) = socket;
    let listener = bind(&path)?;
    // SAFETY: plain syscalls; each fd is owned from here.
    let epoll = unsafe { OwnedFd::from_raw_fd(cvt(libc::epoll_create1(libc::EPOLL_CLOEXEC))?) };
    let wake_fd =
        unsafe { OwnedFd::from_raw_fd(cvt(libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC))?) };
    epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, listener.as_raw_fd(), libc::EPOLLIN as u32, LISTEN_TOKEN)?;
    epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, wake_fd.as_raw_fd(), libc::EPOLLIN as u32, WAKE_TOKEN)?;
    let shared = Arc::new(ListenShared {
        epoll,
        wake_fd,
        conns: Mutex::new(HashMap::new()),
        closing: AtomicBool::new(false),
    });
    let (closed_tx, closed_rx) = mpsc::channel();
    let helper_shared = shared.clone();
    let helper_attacher = attacher.clone();
    std::thread::Builder::new()
        .name("fictionet-listen".into())
        .spawn(move || helper(helper_shared, listener, helper_attacher, closed_tx))?;
    Ok(Listening { shared, path, closed: closed_rx, attacher })
}

fn cvt(n: libc::c_int) -> io::Result<libc::c_int> {
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n) }
}

fn epoll_ctl(epoll: RawFd, op: libc::c_int, fd: RawFd, events: u32, token: u64) -> io::Result<()> {
    let mut event = libc::epoll_event { events, u64: token };
    // SAFETY: `event` is valid for the call.
    cvt(unsafe { libc::epoll_ctl(epoll, op, fd, &mut event) })?;
    Ok(())
}

/// Makes the listening socket. A socket file left behind by a world that is
/// gone is replaced; a live one is an error.
fn bind(path: &Path) -> io::Result<OwnedFd> {
    let (addr, len) = unix::address(path)?;
    let fd = unix::socket(true)?;
    // SAFETY: `addr` is a valid sockaddr_un of length `len`.
    let bound = |fd: &OwnedFd| cvt(unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) });
    if let Err(e) = bound(&fd) {
        if e.raw_os_error() != Some(libc::EADDRINUSE) {
            return Err(e);
        }
        use std::os::unix::fs::FileTypeExt;
        let is_socket = std::fs::symlink_metadata(path).map(|m| m.file_type().is_socket()).unwrap_or(false);
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
    /// An eventfd that wakes the helper thread.
    wake_fd: OwnedFd,
    /// Accepted connections, by epoll token.
    conns: Mutex<HashMap<u64, Arc<ConnSlot>>>,
    /// The [`Listening`] was dropped.
    closing: AtomicBool,
}

impl ListenShared {
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
        let guard = self.name.lock().unwrap().take();
        drop(guard);
    }

    /// Writes queued packets until the connection is full again or the
    /// queue is empty, and watches for room only while packets wait.
    fn flush(&self, out: &mut OutQueue, epoll: RawFd) {
        let fd = self.fd.as_raw_fd();
        while let Some(packet) = out.queue.front() {
            match unix::send_parts(fd, &[&[relay::PACKET], &packet.0], true) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    out.dropped += out.queue.len() as u64;
                    out.queue.clear();
                    out.queued = 0;
                    break;
                }
            }
            let packet = out.queue.pop_front().expect("front was there");
            out.queued -= packet.0.len() + QUEUE_OVERHEAD;
        }
        self.watch_out(out, epoll, false);
    }

    /// Asks epoll to report when the connection has room (`true`), or to
    /// stop (`false`). The helper thread then flushes the queue.
    fn watch_out(&self, out: &mut OutQueue, epoll: RawFd, on: bool) {
        if out.want_out == on {
            return;
        }
        out.want_out = on;
        let mut events = (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
        if on {
            events |= libc::EPOLLOUT as u32;
        }
        let _ = epoll_ctl(epoll, libc::EPOLL_CTL_MOD, self.fd.as_raw_fd(), events, self.token);
    }
}

/// The packets of one connection that wait for room, oldest first.
#[derive(Default)]
struct OutQueue {
    queue: std::collections::VecDeque<Packet>,
    /// Their size, as counted against [`QUEUE_LIMIT`].
    queued: usize,
    /// The connection is registered for writability.
    want_out: bool,
    /// The connection is closed: nothing more is queued.
    closed: bool,
    /// Packets dropped because the connection and the queue were full, or
    /// attach was gone.
    dropped: u64,
}

/// A connection in its handshake, owned by the helper thread.
struct Handshake {
    fd: OwnedFd,
    deadline: Instant,
}

/// The helper thread: accepts connections, runs their handshakes, and wakes
/// idle attachments when their connection becomes readable.
fn helper(shared: Arc<ListenShared>, listener: OwnedFd, attacher: Attacher, closed: mpsc::Sender<()>) {
    let epoll = shared.epoll.as_raw_fd();
    let mut listener = Some(listener);
    let mut handshakes: HashMap<u64, Handshake> = HashMap::new();
    let mut next_token: u64 = 2;
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
    // While the process is out of descriptors, the listening socket is out
    // of epoll until this time, so its readiness does not spin the thread.
    let mut accept_paused: Option<Instant> = None;
    loop {
        if shared.closing.load(Ordering::Acquire) {
            if let Some(fd) = listener.take() {
                let _ = epoll_ctl(epoll, libc::EPOLL_CTL_DEL, fd.as_raw_fd(), 0, 0);
                drop(fd);
                handshakes.clear();
                accept_paused = None;
                let _ = closed.send(());
            }
            if shared.conns.lock().unwrap().is_empty() {
                return;
            }
        }
        let now = Instant::now();
        if let (Some(until), Some(fd)) = (accept_paused, &listener)
            && until <= now
        {
            accept_paused = None;
            let _ = epoll_ctl(epoll, libc::EPOLL_CTL_ADD, fd.as_raw_fd(), libc::EPOLLIN as u32, LISTEN_TOKEN);
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
        let n = unsafe { libc::epoll_wait(epoll, events.as_mut_ptr(), events.len() as i32, timeout) };
        let n = if n < 0 { 0 } else { n as usize };
        for event in &events[..n] {
            let (token, flags) = (event.u64, event.events);
            match token {
                LISTEN_TOKEN => {
                    let Some(fd) = &listener else { continue };
                    if accept_all(fd.as_raw_fd(), epoll, &mut handshakes, &mut next_token).is_err() {
                        let _ = epoll_ctl(epoll, libc::EPOLL_CTL_DEL, fd.as_raw_fd(), 0, 0);
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
                    if let Some(handshake) = handshake_step(&shared, &attacher, token, handshake, &mut buf) {
                        handshakes.insert(token, handshake);
                    }
                }
                token => {
                    let slot = shared.conns.lock().unwrap().get(&token).cloned();
                    let Some(slot) = slot else { continue };
                    let hangup = (libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR) as u32;
                    if flags & hangup != 0 {
                        slot.release_name();
                    }
                    if flags & libc::EPOLLOUT as u32 != 0 {
                        let mut out = slot.out.lock().unwrap();
                        if !out.queue.is_empty() {
                            slot.flush(&mut out, epoll);
                        }
                    }
                    if flags & (libc::EPOLLIN as u32 | hangup) != 0 {
                        let waker = slot.waker.lock().unwrap().take();
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
    epoll: RawFd,
    handshakes: &mut HashMap<u64, Handshake>,
    next_token: &mut u64,
) -> io::Result<()> {
    loop {
        // SAFETY: plain syscall; the fd is owned from here.
        let fd = unsafe {
            libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC)
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) | Some(libc::ECONNABORTED) => continue,
                Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => return Err(err),
                _ => return Ok(()),
            }
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        unix::raise_buffers(fd.as_raw_fd());
        let token = *next_token;
        *next_token += 1;
        if epoll_ctl(epoll, libc::EPOLL_CTL_ADD, fd.as_raw_fd(), libc::EPOLLIN as u32, token).is_ok() {
            handshakes.insert(token, Handshake { fd, deadline: Instant::now() + relay::HANDSHAKE_TIMEOUT });
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
    if hello.kind == relay::OBSERVE {
        // An observer is not a sandbox: it takes no name and never becomes
        // an Attachment. Its session runs on a thread of its own.
        if unix::send(fd, &Message::Accept.encode(), true).is_err() {
            return None;
        }
        let _ = epoll_ctl(shared.epoll.as_raw_fd(), libc::EPOLL_CTL_DEL, fd, 0, 0);
        crate::observe::serve_session(attacher.clone(), handshake.fd);
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
    shared.conns.lock().unwrap().insert(token, slot.clone());
    let events = (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
    let _ = epoll_ctl(shared.epoll.as_raw_fd(), libc::EPOLL_CTL_MOD, fd, events, token);
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
/// [`QUEUE_OVERHEAD`] for each. Past that, packets are dropped.
const QUEUE_LIMIT: usize = 32 << 20;
/// What a waiting packet costs beyond its bytes, so a flood of tiny
/// packets is bounded too.
const QUEUE_OVERHEAD: usize = 64;

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
        self.closed || self.slot.name.lock().unwrap().is_none()
    }

    /// A check for [`peer_gone`](SocketLink::peer_gone) that works without
    /// this link. It does not keep the connection open: once the link is
    /// dropped, it says gone.
    pub(crate) fn peer_gone_check(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let slot = Arc::downgrade(&self.slot);
        move || slot.upgrade().is_none_or(|s| s.name.lock().unwrap().is_none())
    }

    fn close(&mut self) {
        self.closed = true;
        {
            let mut out = self.slot.out.lock().unwrap();
            out.closed = true;
            out.queue.clear();
            out.queued = 0;
        }
        unix::shutdown(self.slot.fd.as_raw_fd());
        self.slot.release_name();
    }

    pub(crate) fn poll_recv(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        // A cancel comes first, as it does for every wait.
        if cx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        if self.closed {
            return Poll::Ready(Err(RecvError::Closed));
        }
        if self.budget == 0 {
            self.budget = BUDGET;
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        let fd = self.slot.fd.as_raw_fd();
        let mut registered = false;
        loop {
            match unix::recv(fd, &mut self.buf, true) {
                Ok(0) => {
                    self.close();
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Ok(n) if n > relay::MAX_MESSAGE => {
                    // Longer than the protocol allows, and cut short by the
                    // buffer: never hand it on as a packet.
                    self.close();
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Ok(n) if self.buf[0] == relay::PACKET => {
                    self.budget -= 1;
                    return Poll::Ready(Ok(Packet(self.buf[1..n].to_vec())));
                }
                Ok(_) => {
                    // Any other message after the handshake closes the
                    // connection.
                    self.close();
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if registered {
                        self.budget = BUDGET;
                        return Poll::Pending;
                    }
                    // Hand the connection to the helper thread, then read
                    // once more: a packet may have come in before the
                    // waker was in place.
                    *self.slot.waker.lock().unwrap() = Some(task.waker().clone());
                    registered = true;
                    if cx.register_cancel(task.waker(), &mut self.wait) {
                        return Poll::Ready(Err(RecvError::Cancelled));
                    }
                }
                Err(_) => {
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
        let epoll = self.listen.epoll.as_raw_fd();
        let mut out = self.slot.out.lock().unwrap();
        if out.closed {
            return;
        }
        if !out.queue.is_empty() {
            self.slot.flush(&mut out, epoll);
        }
        if out.queue.is_empty() {
            match unix::send_parts(self.slot.fd.as_raw_fd(), &[&[relay::PACKET], &packet.0], true) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // Attach is gone; the next `recv` says so.
                Err(_) => {
                    out.dropped += 1;
                    return;
                }
            }
        }
        let cost = packet.0.len() + QUEUE_OVERHEAD;
        if out.queued + cost > QUEUE_LIMIT {
            out.dropped += 1;
            return;
        }
        out.queued += cost;
        out.queue.push_back(packet);
        self.slot.watch_out(&mut out, epoll, true);
    }
}

impl Drop for SocketLink {
    fn drop(&mut self) {
        let _ = epoll_ctl(self.listen.epoll.as_raw_fd(), libc::EPOLL_CTL_DEL, self.slot.fd.as_raw_fd(), 0, 0);
        let last = {
            let mut conns = self.listen.conns.lock().unwrap();
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
        let _ = self.closed.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_file(&self.path);
    }
}

impl std::fmt::Debug for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listening").field("path", &self.path).finish()
    }
}
