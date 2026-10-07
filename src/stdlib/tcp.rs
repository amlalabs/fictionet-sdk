//! TCP: listeners and connections for a machine on the simulated network.
//!
//! Use this module to give a machine TCP, so that a sandbox can connect to
//! it, or so that it can connect out. [`endpoint`] takes an [`Interface`]
//! that carries the machine's TCP packets, and the machine's address. It
//! returns an [`Endpoint`], one machine's TCP. From it you
//! [`listen`](Endpoint::listen) on a port and [`accept`](Listener::accept)
//! connections, or [`connect`](Endpoint::connect) to another machine. Each
//! connection is a [`TcpConnection`], which implements [`Connection`].
//!
//! Inside, an endpoint is one background task that runs the smoltcp TCP
//! stack. The interface it takes comes from
//! [`ip::split_protocols`](crate::stdlib::ip::split_protocols), which
//! splits a machine's packets so that only TCP, and ICMP errors about it,
//! reach this layer.
//!
//! This builds a machine at `104.18.32.7` and accepts connections on its
//! port 443. The other end of the [`pair`](crate::pair) goes to a router,
//! as the [`route`](crate::stdlib::route) page shows:
//!
//! ```
//! # use fictionet::{Cx, Result, pair};
//! # use fictionet::stdlib::{ip, tcp};
//! # async fn stripe(cx: Cx) -> Result {
//! // A link between the router and Stripe's machine.
//! let (router_side, stripe_side) = pair();
//! // ...give router_side to the router for 104.18.32.7/32...
//!
//! let (tcp, _udp, _icmp, _other) = ip::split_protocols(&cx, stripe_side);
//! let stripe = tcp::endpoint(&cx, tcp, "104.18.32.7".parse()?);
//! let mut listener = stripe.listen(443)?;
//! while let Ok(conn) = listener.accept(&cx).await {
//!     // TLS, then HTTP
//! #   drop(conn);
//! }
//! # drop(router_side);
//! # Ok(())
//! # }
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use smoltcp::iface::{Config, Interface as Iface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self as stcp, State as TcpState};
use smoltcp::wire::{HardwareAddress, IpCidr};

use crate::cx::CancelWait;
use crate::stdlib::ip::{Header, protocol::TCP, set_header_checksum, strip_extension_headers, transport_checksum};
use crate::stdlib::{ConnError, Connection};
use crate::time::{Duration, Instant};
use crate::{Cx, Error, Interface, Packet};

/// The MTU the endpoint assumes. Segments it sends are at most the smaller
/// of this and what the peer's MSS option allows.
const MTU: usize = 1500;
/// Receive and send buffer per connection, unless [`Options::buffer`] says
/// otherwise. The receive buffer is the window.
const BUFFER: usize = 256 * 1024;
/// The smallest and largest buffers [`Options::buffer`] allows.
const MIN_BUFFER: usize = 4 * 1024;
const MAX_BUFFER: usize = 64 * 1024 * 1024;
/// How often buffers of connections that went quiet are given back to the
/// system.
const RELEASE_EVERY: Duration = Duration::from_secs(1);
/// A connection whose peer sends nothing for this long while it waits for
/// an answer (a SYN, unacknowledged data, a keepalive) is given up.
const TIMEOUT: Duration = Duration::from_secs(120);
/// A connection whose handle was dropped is given up when the peer sends
/// nothing for this long, for example in FIN-WAIT-2 with a peer that never
/// closes its side.
const ORPHAN_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle connections send a keepalive this often, so a peer that is gone is
/// noticed within `TIMEOUT`.
const KEEPALIVE: Duration = Duration::from_secs(45);
/// Connections per port that have arrived but not been accepted yet,
/// unless [`Options::backlog`] says otherwise. More connection attempts get
/// a RST.
const BACKLOG: usize = 4096;
/// The largest backlog [`Options::backlog`] allows.
const MAX_BACKLOG: usize = 65_536;
/// Of those, at most this many from one peer address. More attempts from
/// that address are dropped, so one peer that never finishes its
/// handshakes (a SYN flood) cannot fill the backlog for the others.
const BACKLOG_PER_PEER: usize = 256;
/// The first local port for outgoing connections.
const EPHEMERAL: u16 = 49152;
/// smoltcp's delayed-ACK wait. A dropped connection in TIME-WAIT is kept
/// this long after the peer's FIN, so the ACK it owes is sent.
const ACK_DELAY: Duration = Duration::from_millis(10);

/// Starts TCP for a machine with address `addr`, on the TCP packets of
/// `inner`.
///
/// Starts a background task and returns immediately with an [`Endpoint`].
/// The task takes TCP packets sent to `addr` and drops the rest. A
/// connection attempt to a port with no listener gets a RST, because that
/// is part of TCP's job. Everything it sends goes into `inner`.
///
/// The task stops when the caller's [region](crate::Cx#regions) is
/// cancelled or `inner` closes. The endpoint's listeners and connections
/// then fail with [`ConnError::Closed`].
///
/// Each connection has 256 KiB buffers each way, a 1,500-byte MTU, no
/// Nagle delay, and Reno congestion control. Each listening port holds up
/// to 4,096 connections that have not been accepted yet. [`endpoint_with`]
/// takes other buffer sizes and backlogs. Buffer memory is used only
/// as data passes through: once a connection's buffers are empty, their
/// pages go back to the system within about two seconds, though the
/// connection stays open, and closing frees them. A connection gives up with
/// [`ConnError::TimedOut`] when the peer has not answered for two minutes:
/// a SYN, data that is not acknowledged, or a keepalive (sent after 45
/// seconds of quiet). A connection whose handle was dropped finishes
/// closing in the background, and is given up when the peer has sent
/// nothing for one minute, as when it never closes its side. ICMP messages
/// that reach this layer are dropped, so it does no path MTU discovery.
#[track_caller]
pub fn endpoint(cx: &Cx, inner: impl Interface, addr: IpAddr) -> Endpoint {
    endpoint_with(cx, inner, addr, Options::default())
}

/// Settings for [`endpoint_with`]. The default is what [`endpoint`] uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    buffer: usize,
    backlog: usize,
}

impl Default for Options {
    fn default() -> Options {
        Options { buffer: BUFFER, backlog: BACKLOG }
    }
}

impl Options {
    /// Sets the size of each connection's receive buffer and of its send
    /// buffer, in bytes. The default is 256 KiB. Sizes below 4 KiB or above
    /// 64 MiB are raised or lowered to those limits.
    ///
    /// The buffers bound how fast one connection can go over a link with
    /// delay. The receive buffer is the window: the most the peer may send
    /// before this side acknowledges it. The send buffer holds what this
    /// side has sent until the peer acknowledges it. Either way, a
    /// connection carries at most one buffer of data per round trip, so its
    /// rate is at most the buffer size divided by the round-trip time. With
    /// 256 KiB that is about 13 MB/s at a 20 ms round trip, and 2.6 MB/s at
    /// 100 ms. Both ends need the larger buffer: a sender is held to the
    /// smaller of its own send buffer and the receiver's window.
    ///
    /// On a link with 10 ms of delay each way, one connection moving 16 MiB
    /// ran at a median of 9.2 MB/s with 256 KiB buffers at both ends, and
    /// 27 MB/s with 1 MiB buffers. With 50 ms each way, moving 8 MiB, it
    /// ran at 1.9 and 3.9 MB/s. These come from the `delay` group of the performance
    /// suite, described in `CONTRIBUTING.md`.
    ///
    /// Larger buffers cost memory only as data passes through them, but they
    /// let each connection put more packets in flight at once. Interfaces
    /// with a size limit on the way, such as those of
    /// [`split_protocols`](crate::stdlib::ip::split_protocols), drop what
    /// does not fit, and TCP then sends it again.
    pub fn buffer(self, bytes: usize) -> Options {
        Options { buffer: bytes.clamp(MIN_BUFFER, MAX_BUFFER), ..self }
    }

    /// Sets how many connections each listening port holds that have
    /// arrived but not been accepted yet: handshakes under way, and
    /// connections waiting for [`Listener::accept`]. The default is 4,096.
    /// Values below 1 or above 65,536 are raised or lowered to those
    /// limits. Past the backlog, a connection attempt gets a RST, as from
    /// a full listen queue. At most 256 of them come from one peer address,
    /// whatever the backlog, so a single peer cannot fill it.
    ///
    /// Each connection in the backlog has its buffers from its first SYN.
    /// Their pages cost memory only once data arrives, but each connection
    /// holds one memory mapping, and Linux allows a process 65,530 of them
    /// by default (`vm.max_map_count`). Spoofed SYNs from many addresses
    /// fill the backlog of every port they reach, so a world with many
    /// listening ports may want a smaller one.
    pub fn backlog(self, connections: usize) -> Options {
        Options { backlog: connections.clamp(1, MAX_BACKLOG), ..self }
    }
}

/// Starts TCP for a machine, as [`endpoint`] does, with other
/// [`Options`].
///
/// This one gives every connection 1 MiB buffers, for fast transfers over
/// a link with delay:
///
/// ```
/// # use fictionet::{Cx, End, Result};
/// # use fictionet::stdlib::tcp;
/// # fn machine(cx: &Cx, tcp_packets: End) -> Result {
/// let options = tcp::Options::default().buffer(1 << 20);
/// let machine = tcp::endpoint_with(cx, tcp_packets, "10.0.0.1".parse()?, options);
/// # drop(machine);
/// # Ok(())
/// # }
/// ```
#[track_caller]
pub fn endpoint_with(cx: &Cx, inner: impl Interface, addr: IpAddr, options: Options) -> Endpoint {
    let mut dev = Dev::default();
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = cx.random_u64();
    let mut iface = Iface::new(config, &mut dev, smol_now(cx));
    iface.update_ip_addrs(|addrs| {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        addrs.push(IpCidr::new(addr.into(), prefix)).expect("one address fits");
    });
    let shared = Arc::new(Shared {
        addr,
        state: Mutex::new(State {
            iface,
            sockets: SocketSet::new(Vec::new()),
            handles: HashMap::new(),
            next_id: 0,
            slots: 0,
            pages: HashMap::new(),
            dirty: HashSet::new(),
            next_release: None,
            next_tidy: None,
            dev,
            listeners: HashMap::new(),
            conns: HashMap::new(),
            by_tuple: HashMap::new(),
            ports: HashMap::new(),
            next_port: EPHEMERAL + (cx.random_u64() % (65536 - EPHEMERAL as u64)) as u16,
            orphans: Vec::new(),
            stopped: false,
            driver: None,
            buffer: options.buffer,
            backlog: options.backlog,
        }),
    });
    let driver = shared.clone();
    cx.spawn_as(|| "tcp::endpoint".into(), move |cx| async move {
        drive(&cx, &driver, inner).await;
        driver.stop();
        Ok(())
    });
    Endpoint { shared }
}

fn smol_now(cx: &Cx) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros(cx.now().since_start().as_micros() as i64)
}

/// The packets going into and out of smoltcp.
#[derive(Default)]
struct Dev {
    rx: Option<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.take()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct Shared {
    addr: IpAddr,
    state: Mutex<State>,
}

/// A socket's name inside [`State`]. smoltcp's handles are slot numbers
/// that change when the socket set is compacted; these never change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Id(u64);

/// Compact the socket set when at least this many slots exist and at most
/// a quarter of them hold a socket. smoltcp walks every slot, empty or
/// not, on every packet, and its slot list never shrinks by itself.
const COMPACT_SLOTS: usize = 256;

struct State {
    iface: Iface,
    sockets: SocketSet<'static>,
    /// Each socket's slot in `sockets`.
    handles: HashMap<Id, SocketHandle>,
    next_id: u64,
    /// Slots in `sockets`, empty ones included: the most sockets it held
    /// at once since it was made.
    slots: usize,
    /// The buffers of each socket that has its own pages. Declared after
    /// `sockets`, so they outlive the sockets that borrow them.
    pages: HashMap<Id, Pages>,
    /// Sockets whose buffers may hold pages that could be given back.
    dirty: HashSet<Id>,
    /// When `dirty` is next looked at.
    next_release: Option<smoltcp::time::Instant>,
    /// When `housekeeping` must run again to remove an orphan in TIME-WAIT
    /// that still owed an ACK.
    next_tidy: Option<smoltcp::time::Instant>,
    dev: Dev,
    listeners: HashMap<u16, Listen>,
    /// Every socket that is or was a connection, by handle.
    conns: HashMap<Id, Conn>,
    /// Connections by (local, remote), to note RSTs and FINs.
    by_tuple: HashMap<(SocketAddr, SocketAddr), Id>,
    /// Local ports in use by listeners (counted once) and connections.
    ports: HashMap<u16, usize>,
    next_port: u16,
    /// Connections whose handle was dropped, removed once they close.
    orphans: Vec<Id>,
    stopped: bool,
    /// The driver task, woken when a handle has work for it.
    driver: Option<Waker>,
    /// Each new socket's receive and send buffer, in bytes.
    buffer: usize,
    /// Connections per listening port not accepted yet: [`Options::backlog`].
    backlog: usize,
}

/// One listening port.
#[derive(Default)]
struct Listen {
    /// Sockets in LISTEN, waiting for a SYN.
    idle: Vec<Id>,
    /// Sockets that got a SYN and wait for the handshake to finish.
    embryonic: Vec<Id>,
    /// Connections ready for `accept`.
    ready: VecDeque<Id>,
    /// How many of `embryonic` and `ready` each peer address has.
    per_peer: HashMap<IpAddr, usize>,
    waker: Option<Waker>,
}

impl Listen {
    /// One connection from `peer` left `embryonic` or `ready` for good.
    fn left(&mut self, peer: IpAddr) {
        if let Some(n) = self.per_peer.get_mut(&peer) {
            *n -= 1;
            if *n == 0 {
                self.per_peer.remove(&peer);
            }
        }
    }
}

struct Conn {
    local: SocketAddr,
    remote: SocketAddr,
    /// A RST arrived for this connection.
    rst: bool,
    /// A FIN arrived for this connection.
    fin: bool,
    /// When the last segment with a FIN arrived.
    fin_at: Option<smoltcp::time::Instant>,
    /// This side called shutdown.
    shut: bool,
    /// This side connected, so it holds its local port.
    client: bool,
    /// The peer's initial sequence number, from its SYN.
    irs: Option<u32>,
    /// Bytes the application has read, modulo 2^32.
    read: u32,
    /// The acknowledgment number and window of the last segment from the
    /// peer that smoltcp was given.
    last_fed: Option<(u32, u16)>,
    /// The highest sequence number past data from the peer, so far.
    rx_end: Option<u32>,
    /// Kept until the socket is gone, after the handle is dropped too: see
    /// [`TcpConnection::hold_until_gone`].
    held: Vec<Box<dyn std::any::Any + Send>>,
    /// Woken when a RST arrives or this side aborts, and when the
    /// connection is forgotten: see [`GoneWatch`].
    gone: Vec<Waker>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.wake_gone();
    }
}

impl Conn {
    fn new(local: SocketAddr, remote: SocketAddr, client: bool) -> Conn {
        Conn {
            local,
            remote,
            rst: false,
            fin: false,
            fin_at: None,
            shut: false,
            client,
            irs: None,
            read: 0,
            last_fed: None,
            rx_end: None,
            held: Vec::new(),
            gone: Vec::new(),
        }
    }

    fn wake_gone(&mut self) {
        for w in self.gone.drain(..) {
            w.wake();
        }
    }

    /// Whether smoltcp may hold data from the peer past what it has made
    /// readable (out of order, waiting for a gap to fill). `recv_queue` is
    /// what is readable now.
    fn may_hold_more(&self, recv_queue: usize) -> bool {
        let Some(end) = self.rx_end else { return false };
        let Some(irs) = self.irs else { return true };
        let next = irs.wrapping_add(1).wrapping_add(self.read).wrapping_add(recv_queue as u32);
        (end.wrapping_sub(next) as i32) > 0
    }
}

/// A socket's two buffers, in an anonymous mapping of their own.
///
/// smoltcp buffers are fixed slices. Taking them from the heap would keep
/// their pages after the connection goes quiet or closes: the allocator
/// zeroes fresh chunks (so even an idle connection costs its full 512
/// KiB) and keeps freed memory. With a mapping of its own, a page costs
/// memory only once it is written, the pages of an empty buffer can be
/// given back while the connection stays open ([`Pages::release`]), and
/// closing returns all of it.
#[cfg(not(target_arch = "wasm32"))]
struct Pages {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: `Pages` owns its mapping; the raw pointer is only an address.
// Every access goes through the endpoint's mutex.
#[cfg(not(target_arch = "wasm32"))]
unsafe impl Send for Pages {}

#[cfg(not(target_arch = "wasm32"))]
impl Pages {
    /// Maps two buffers of `buffer` bytes, or `None` if the system says no.
    fn map(buffer: usize) -> Option<Pages> {
        let len = 2 * buffer;
        // SAFETY: a fresh private anonymous mapping; no existing memory is
        // touched.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        (ptr != libc::MAP_FAILED).then_some(Pages { ptr: ptr.cast(), len })
    }

    /// The receive and send halves.
    ///
    /// SAFETY: the caller hands each half to exactly one socket, and
    /// removes that socket before the `Pages` is dropped.
    unsafe fn halves(&self) -> (&'static mut [u8], &'static mut [u8]) {
        // SAFETY: the mapping is `len` bytes, readable and writable, and
        // the two halves do not overlap.
        let half = self.len / 2;
        unsafe { (std::slice::from_raw_parts_mut(self.ptr, half), std::slice::from_raw_parts_mut(self.ptr.add(half), half)) }
    }

    /// Gives the pages of both halves back to the system. They read as
    /// zeros after, and cost memory again only once written.
    ///
    /// SAFETY: the socket that holds the halves (see [`Pages::halves`])
    /// must hold nothing in them: no bytes to read, none to send or
    /// resend, and nothing received out of order. Its buffers are
    /// `&'static mut` slices of this mapping, and this changes their bytes
    /// behind them.
    unsafe fn release(&self) {
        // SAFETY: the range is this mapping. MADV_DONTNEED on a private
        // anonymous mapping only makes its pages read as zeros, and the
        // caller has checked that the socket holds no data in them.
        unsafe { libc::madvise(self.ptr.cast(), self.len, libc::MADV_DONTNEED) };
    }

    /// How many of the pages are in memory now.
    #[cfg(test)]
    fn resident(&self) -> usize {
        let page = 4096;
        let mut v = vec![0u8; self.len.div_ceil(page)];
        // SAFETY: `v` has one byte per page of the mapping.
        unsafe { libc::mincore(self.ptr.cast(), self.len, v.as_mut_ptr().cast()) };
        v.iter().filter(|b| *b & 1 != 0).count()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: this unmaps exactly the mapping made in `map`, after the
        // socket that borrowed it was removed.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

/// A browser has no `mmap`, so there every socket's buffers come from the
/// heap and no `Pages` is ever made.
#[cfg(target_arch = "wasm32")]
enum Pages {}

#[cfg(target_arch = "wasm32")]
impl Pages {
    fn map(_buffer: usize) -> Option<Pages> {
        None
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn halves(&self) -> (&'static mut [u8], &'static mut [u8]) {
        match *self {}
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn release(&self) {
        match *self {}
    }
}

/// A socket with two buffers of `buffer` bytes.
fn new_socket(buffer: usize) -> (stcp::Socket<'static>, Option<Pages>) {
    let pages = Pages::map(buffer);
    let mut s = match &pages {
        Some(p) => {
            // SAFETY: the halves go to this one socket, and `State` removes
            // it before dropping the pages (`State::remove_socket`, and
            // field order for the whole state).
            let (rx, tx) = unsafe { p.halves() };
            stcp::Socket::new(stcp::SocketBuffer::new(rx), stcp::SocketBuffer::new(tx))
        }
        None => stcp::Socket::new(stcp::SocketBuffer::new(vec![0; buffer]), stcp::SocketBuffer::new(vec![0; buffer])),
    };
    s.set_nagle_enabled(false);
    s.set_timeout(Some(TIMEOUT.into()));
    s.set_keep_alive(Some(KEEPALIVE.into()));
    (s, pages)
}

impl State {
    fn kick(&mut self) {
        if let Some(w) = self.driver.take() {
            w.wake();
        }
    }

    /// Adds a socket made by [`new_socket`].
    fn add_socket(&mut self, (s, pages): (stcp::Socket<'static>, Option<Pages>)) -> Id {
        let h = Id(self.next_id);
        self.next_id += 1;
        self.handles.insert(h, self.sockets.add(s));
        self.slots = self.slots.max(self.handles.len());
        if let Some(p) = pages {
            self.pages.insert(h, p);
        }
        h
    }

    /// Removes a socket, then unmaps its buffers.
    fn remove_socket(&mut self, h: Id) {
        let slot = self.handles.remove(&h).expect("a socket has a slot");
        self.sockets.remove(slot);
        self.pages.remove(&h);
        self.dirty.remove(&h);
    }

    /// Notes that a socket's buffers may have pages to give back later.
    fn soiled(&mut self, h: Id) {
        if self.pages.contains_key(&h) {
            self.dirty.insert(h);
        }
    }

    /// Gives back the pages of every noted socket whose buffers are now
    /// empty. Sockets that still hold data stay noted.
    fn release_quiet(&mut self) {
        let dirty: Vec<Id> = self.dirty.iter().copied().collect();
        for h in dirty {
            let s = self.get(h);
            let (rq, sq) = (s.recv_queue(), s.send_queue());
            let held = self.conns.get(&h).is_some_and(|c| c.may_hold_more(rq));
            if rq == 0 && sq == 0 && !held {
                // SAFETY: the socket holds nothing in its buffers, as just
                // checked: nothing to read or send, and nothing out of order.
                unsafe { self.pages[&h].release() };
                self.dirty.remove(&h);
            }
        }
    }

    fn sock(&mut self, h: Id) -> &mut stcp::Socket<'static> {
        self.sockets.get_mut::<stcp::Socket>(self.handles[&h])
    }

    fn get(&self, h: Id) -> &stcp::Socket<'static> {
        self.sockets.get::<stcp::Socket>(self.handles[&h])
    }

    /// Moves every socket into a new set without empty slots, once most
    /// slots are empty. Sockets keep their [`Id`], their state and their
    /// buffers.
    fn compact(&mut self) {
        if self.slots < COMPACT_SLOTS || self.handles.len() * 4 > self.slots {
            return;
        }
        let mut sockets = SocketSet::new(Vec::with_capacity(self.handles.len()));
        for slot in self.handles.values_mut() {
            *slot = sockets.add(self.sockets.remove(*slot));
        }
        self.sockets = sockets;
        self.slots = self.handles.len();
    }

    fn take_port(&mut self, port: u16) {
        *self.ports.entry(port).or_default() += 1;
    }

    fn free_port(&mut self, port: u16) {
        if let Some(n) = self.ports.get_mut(&port) {
            *n -= 1;
            if *n == 0 {
                self.ports.remove(&port);
            }
        }
    }

    /// Forgets a connection socket entirely.
    fn remove_conn(&mut self, h: Id) {
        if let Some(c) = self.conns.remove(&h) {
            self.by_tuple.remove(&(c.local, c.remote));
            if c.client {
                self.free_port(c.local.port());
            }
        }
        self.remove_socket(h);
    }

    /// Hands a socket whose handle is gone to the driver, which removes it
    /// once it has closed. Unread data means the application lost bytes,
    /// so the peer gets a RST, as from a kernel.
    fn orphan(&mut self, h: Id, abort: bool) {
        if self.stopped {
            self.remove_conn(h);
            return;
        }
        let s = self.sock(h);
        if abort || s.can_recv() {
            s.abort();
        } else {
            s.close();
        }
        // A FIN-WAIT-2 orphan should not live on keepalives, and a peer
        // that never closes its side keeps it only for a minute, as Linux
        // does (tcp_fin_timeout).
        s.set_keep_alive(None);
        s.set_timeout(Some(ORPHAN_TIMEOUT.into()));
        self.orphans.push(h);
        self.kick();
    }

    /// Why a connection can no longer carry bytes, once its socket closed.
    fn closed_reason(&self, h: Id) -> ConnError {
        let c = &self.conns[&h];
        if self.stopped {
            ConnError::Closed
        } else if c.rst {
            ConnError::Reset
        } else {
            ConnError::TimedOut
        }
    }

    /// Feeds one packet from the interface into smoltcp. Returns whether it was
    /// a TCP segment for this endpoint that carried data.
    fn ingress(&mut self, addr: IpAddr, now: smoltcp::time::Instant, packet: Vec<u8>) -> bool {
        let Some(ip) = Header::parse_whole(&packet) else { return false };
        if ip.protocol != TCP || ip.dst != addr || ip.payload.len() < 20 {
            return false;
        }
        // smoltcp takes TCP only right after the IPv6 header. `parse_whole` has
        // checked the extension headers in between, so they are taken out,
        // as `split_protocols` does before packets get here.
        if ip.payload.start != 40 && ip.dst.is_ipv6() {
            return match strip_extension_headers(&packet) {
                Ok(Some(stripped)) => self.ingress(addr, now, stripped),
                _ => false,
            };
        }
        let t = &packet[ip.payload.start..];
        let data_len = ip.payload.len().saturating_sub(((t[12] >> 4) as usize) * 4);
        let data = data_len > 0;
        let src = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let dst = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
        let flags = t[13];
        let (fin, syn, rst, ack) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 16 != 0);
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let mut listening = false;
        if syn && !ack && let Some(l) = self.listeners.get(&dst.port()) {
            let known = self.by_tuple.contains_key(&(dst, src));
            if !known && l.per_peer.get(&src.ip()).is_some_and(|&n| n >= BACKLOG_PER_PEER) {
                return false;
            }
            listening = true;
            if l.idle.is_empty() && l.embryonic.len() + l.ready.len() < self.backlog {
                let mut s = new_socket(self.buffer);
                s.0.listen(dst.port()).expect("a new socket can listen");
                let h = self.add_socket(s);
                self.listeners.get_mut(&dst.port()).unwrap().idle.push(h);
            }
        }
        let mut packet = packet;
        let mut extra = None;
        if let Some(&h) = self.by_tuple.get(&(dst, src)) {
            let c = self.conns.get_mut(&h).unwrap();
            c.rst |= rst;
            c.fin |= fin;
            if rst {
                c.wake_gone();
            }
            if data {
                let end = seq.wrapping_add(data_len as u32);
                if c.rx_end.is_none_or(|e| (end.wrapping_sub(e) as i32) > 0) {
                    c.rx_end = Some(end);
                }
                if self.pages.contains_key(&h) {
                    self.dirty.insert(h);
                }
            }
            if syn && ack {
                c.irs = Some(seq);
            } else if ack && !syn && !rst {
                extra = repair_ack(c, self.sockets.get::<stcp::Socket>(self.handles[&h]), &ip, &mut packet);
            }
            if fin {
                // ACK a FIN immediately, as Linux does, not after the delayed-ACK
                // wait. A handle dropped right after reading to the end
                // leaves the socket in TIME-WAIT, and `housekeeping` removes
                // it: an ACK it still owed would never be sent, and the peer
                // would hold its side of the connection until it sent its
                // FIN again, a second later. An ACK already waiting for
                // earlier data still waits, so `housekeeping` keeps the
                // socket for that wait too (`fin_at`).
                c.fin_at = Some(now);
                self.sockets.get_mut::<stcp::Socket>(self.handles[&h]).set_ack_delay(None);
            }
        }
        if let Some(p) = extra {
            self.dev.rx = Some(p);
            self.iface.poll_ingress_single(now, &mut self.dev, &mut self.sockets);
        }
        self.dev.rx = Some(packet);
        self.iface.poll_ingress_single(now, &mut self.dev, &mut self.sockets);
        self.dev.rx = None;
        if listening {
            // At most one idle socket took the SYN.
            let l = self.listeners.get_mut(&dst.port()).unwrap();
            let (sockets, handles) = (&self.sockets, &self.handles);
            if let Some(i) = l.idle.iter().position(|&h| sockets.get::<stcp::Socket>(handles[&h]).state() != TcpState::Listen) {
                let h = l.idle.swap_remove(i);
                l.embryonic.push(h);
                let s = self.sockets.get::<stcp::Socket>(self.handles[&h]);
                let local = s.local_endpoint().map(SocketAddr::from).unwrap_or(dst);
                let remote = s.remote_endpoint().map(SocketAddr::from).unwrap_or(src);
                *l.per_peer.entry(remote.ip()).or_default() += 1;
                let mut c = Conn::new(local, remote, false);
                c.irs = Some(seq);
                self.conns.insert(h, c);
                self.by_tuple.insert((local, remote), h);
            }
        }
        data
    }

    /// Moves finished handshakes to the accept queues and removes orphans
    /// that have closed.
    fn housekeeping(&mut self, now: smoltcp::time::Instant) {
        let mut woken = Vec::new();
        // Removed after the loop: `listeners` is borrowed in it.
        let mut gone = Vec::new();
        for l in self.listeners.values_mut() {
            let mut i = 0;
            let mut moved = false;
            while i < l.embryonic.len() {
                let h = l.embryonic[i];
                match self.sockets.get::<stcp::Socket>(self.handles[&h]).state() {
                    TcpState::SynReceived => i += 1,
                    // A RST in SYN-RECEIVED puts the socket back in LISTEN.
                    // One spare listening socket is enough (`ingress` makes
                    // one when there is none), and every socket costs a
                    // little on every packet, so a burst of SYNs must not
                    // leave a pool behind.
                    TcpState::Listen => {
                        l.embryonic.swap_remove(i);
                        if let Some(c) = self.conns.remove(&h) {
                            self.by_tuple.remove(&(c.local, c.remote));
                            l.left(c.remote.ip());
                        }
                        if l.idle.is_empty() {
                            l.idle.push(h);
                        } else {
                            gone.push(h);
                        }
                    }
                    TcpState::Closed | TcpState::TimeWait => {
                        l.embryonic.swap_remove(i);
                        if let Some(c) = self.conns.remove(&h) {
                            self.by_tuple.remove(&(c.local, c.remote));
                            l.left(c.remote.ip());
                        }
                        gone.push(h);
                    }
                    _ => {
                        l.embryonic.swap_remove(i);
                        l.ready.push_back(h);
                        moved = true;
                    }
                }
            }
            if moved && let Some(w) = l.waker.take() {
                woken.push(w);
            }
        }
        for h in gone {
            self.remove_socket(h);
        }
        let mut i = 0;
        self.next_tidy = None;
        while i < self.orphans.len() {
            let h = self.orphans[i];
            let state = self.get(h).state();
            // In TIME-WAIT, an ACK for the peer's FIN may still wait for
            // smoltcp's delayed-ACK timer. Keep the socket until it is sent.
            let owed = (state == TcpState::TimeWait)
                .then(|| self.conns.get(&h).and_then(|c| c.fin_at))
                .flatten()
                .map(|t| t + ACK_DELAY.into())
                .filter(|&until| now < until);
            if let Some(until) = owed {
                self.next_tidy = Some(self.next_tidy.map_or(until, |t| t.min(until)));
                i += 1;
            } else if matches!(state, TcpState::Closed | TcpState::TimeWait) {
                self.orphans.swap_remove(i);
                self.remove_conn(h);
            } else {
                i += 1;
            }
        }
        self.compact();
        for w in woken {
            w.wake();
        }
    }
}

/// Works around two places where smoltcp ignores what an ACK says.
///
/// 1. smoltcp reads the acknowledgment of a segment only if the segment's
///    sequence number is inside its receive window. Window scaling rounds
///    the window down, so the window's right edge can move left by a few
///    bytes. A peer that sent up to the old edge then sends every ACK with
///    a sequence number past the new one, and smoltcp ignores them all. If
///    the application is waiting for room to write before it reads again,
///    neither side moves. RFC 9293 says to accept valid ACKs even when the
///    window is closed. So when a segment from the peer starts past what
///    this side has received and carries a new acknowledgment or window,
///    smoltcp first gets a copy without data at the expected sequence
///    number, which it always accepts. This returns that copy.
/// 2. smoltcp counts an ACK as a duplicate (for fast retransmit) only if
///    the window is unchanged. Linux's duplicate ACKs often change the
///    window by a little, so smoltcp waits for its retransmission timer
///    (at least one second) instead. A pure ACK with SACK blocks that
///    repeats the last acknowledgment is a duplicate (RFC 6675), so its
///    window is set back to the last one smoltcp saw.
fn repair_ack(c: &mut Conn, s: &stcp::Socket<'static>, ip: &Header, packet: &mut Vec<u8>) -> Option<Vec<u8>> {
    let irs = c.irs?;
    let t = &packet[ip.payload.clone()];
    let off = ((t[12] >> 4) as usize) * 4;
    if off < 20 || off > t.len() {
        return None;
    }
    // Only a packet smoltcp would accept may be changed, so it is checked
    // before it is copied or changed.
    let intact = || transport_checksum(ip.src, ip.dst, TCP, t) == 0;
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
    let win = u16::from_be_bytes([t[14], t[15]]);
    let fin = t[13] & 1 != 0;
    let fin_in = matches!(s.state(), TcpState::CloseWait | TcpState::LastAck | TcpState::Closing | TcpState::TimeWait);
    let rcv_nxt = irs.wrapping_add(1).wrapping_add(c.read).wrapping_add(s.recv_queue() as u32).wrapping_add(fin_in as u32);
    let ahead = (seq.wrapping_sub(rcv_nxt) as i32) > 0;
    let last = c.last_fed.replace((ack, win));
    if ahead && last != Some((ack, win)) && intact() {
        // A copy with no data and no FIN, at the expected sequence number.
        let tcp_at = ip.payload.start;
        let mut copy = packet[..tcp_at + off].to_vec();
        copy[tcp_at + 4..tcp_at + 8].copy_from_slice(&rcv_nxt.to_be_bytes());
        copy[tcp_at + 13] = 0x10;
        fix_lengths(&mut copy, tcp_at, ip.src, ip.dst);
        return Some(copy);
    }
    let pure = off == t.len() && !fin;
    if !ahead && pure && let Some((last_ack, last_win)) = last
        && last_ack == ack && last_win != win && has_sack(&t[20..off]) && intact()
    {
        let tcp_at = ip.payload.start;
        packet[tcp_at + 14..tcp_at + 16].copy_from_slice(&last_win.to_be_bytes());
        packet.truncate(ip.payload.end);
        fix_lengths(packet, tcp_at, ip.src, ip.dst);
        c.last_fed = Some((ack, last_win));
    }
    None
}

/// Whether TCP options hold a SACK block.
fn has_sack(mut opts: &[u8]) -> bool {
    while let [kind, rest @ ..] = opts {
        match kind {
            0 => return false,
            1 => opts = rest,
            5 => return true,
            _ => {
                let Some(&len) = rest.first() else { return false };
                if len < 2 || len as usize > opts.len() {
                    return false;
                }
                opts = &opts[len as usize..];
            }
        }
    }
    false
}

/// Sets the IP length fields and the checksums of a TCP packet that ends at
/// `packet.len()` and whose TCP header starts at `tcp_at`.
fn fix_lengths(packet: &mut [u8], tcp_at: usize, src: IpAddr, dst: IpAddr) {
    let len = packet.len();
    if src.is_ipv4() {
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        let ihl = (packet[0] & 15) as usize * 4;
        set_header_checksum(&mut packet[..ihl]);
    } else {
        packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    }
    packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&[0, 0]);
    let sum = transport_checksum(src, dst, TCP, &packet[tcp_at..]);
    packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&sum.to_be_bytes());
}

impl Shared {
    /// The endpoint stopped: every wait ends with an error.
    fn stop(&self) {
        let mut st = self.state.lock().unwrap();
        st.stopped = true;
        let mut wakers: Vec<Waker> = st.listeners.values_mut().filter_map(|l| l.waker.take()).collect();
        wakers.extend(st.driver.take());
        // Aborting wakes each socket's reader and writer.
        let handles: Vec<Id> = st.conns.keys().copied().collect();
        for h in handles {
            st.sock(h).abort();
        }
        for h in std::mem::take(&mut st.orphans) {
            st.remove_conn(h);
        }
        drop(st);
        for w in wakers {
            w.wake();
        }
    }
}

/// The endpoint's one task: packets in, smoltcp, packets out, timers.
async fn drive(cx: &Cx, shared: &Shared, mut inner: impl Interface) {
    let mut timer = crate::cx::Timer::default();
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(64);
    let mut out: Vec<Vec<u8>> = Vec::new();
    poll_fn(|task| {
        if cx.is_cancelled() {
            return Poll::Ready(());
        }
        let received;
        let mut closed = false;
        while batch.len() < 64 {
            match inner.poll_recv(cx, task) {
                Poll::Ready(Ok(p)) => batch.push(p.0),
                Poll::Ready(Err(_)) => {
                    closed = true;
                    break;
                }
                Poll::Pending => break,
            }
        }
        let next = {
            let mut st = shared.state.lock().unwrap();
            match &st.driver {
                Some(w) if w.will_wake(task.waker()) => {}
                _ => st.driver = Some(task.waker().clone()),
            }
            let now = smol_now(cx);
            st.iface.poll_maintenance(now);
            received = batch.len();
            let st = &mut *st;
            for p in batch.drain(..) {
                // After a packet with data, egress immediately, so smoltcp can
                // ACK every second segment as it means to. With one egress
                // per batch, a whole window of data got one ACK. The
                // sender's slow start grows by one segment per ACK, so its
                // window then grew by one segment per round trip. Pure ACKs
                // are still handled as a batch.
                if st.ingress(shared.addr, now, p) {
                    while st.iface.poll_egress(now, &mut st.dev, &mut st.sockets) != smoltcp::iface::PollResult::None {}
                }
            }
            while st.iface.poll_egress(now, &mut st.dev, &mut st.sockets) != smoltcp::iface::PollResult::None {}
            st.housekeeping(now);
            std::mem::swap(&mut out, &mut st.dev.tx);
            if st.dirty.is_empty() {
                st.next_release = None;
            } else {
                match st.next_release {
                    Some(at) if at <= now => {
                        st.release_quiet();
                        st.next_release = (!st.dirty.is_empty()).then(|| now + RELEASE_EVERY.into());
                    }
                    Some(_) => {}
                    None => st.next_release = Some(now + RELEASE_EVERY.into()),
                }
            }
            let at = st.iface.poll_at(now, &st.sockets);
            [at, st.next_release, st.next_tidy].into_iter().flatten().min()
        };
        for p in out.drain(..) {
            inner.send(Packet(p));
        }
        if closed {
            return Poll::Ready(());
        }
        if received == 64 {
            // Maybe more is waiting: give the rest of the run a turn, then
            // come back.
            task.waker().wake_by_ref();
            return Poll::Pending;
        }
        let deadline = next.map(|t| Instant::from_since_start(Duration::from_micros(t.total_micros().max(0) as u64)));
        match deadline {
            None => timer.clear(),
            Some(d) => {
                if timer.poll_until(cx, task, d).is_ready() {
                    // A timer is due, or the region was cancelled. Come back
                    // next turn, so a timer that keeps asking to run now
                    // cannot hold the thread.
                    timer.clear();
                    task.waker().wake_by_ref();
                }
            }
        }
        Poll::Pending
    })
    .await
}

/// One machine's TCP, made by [`endpoint`].
///
/// An `Endpoint` is a handle to the endpoint's task. Clones share the same
/// machine.
#[derive(Clone)]
pub struct Endpoint {
    shared: Arc<Shared>,
}

impl Endpoint {
    /// The machine's address.
    pub fn addr(&self) -> IpAddr {
        self.shared.addr
    }

    /// Ends every connection with `peer` immediately, discarding what was
    /// still to be sent to it. Handles see [`ConnError::Reset`]. For a
    /// peer that is gone for good, whose address someone else may take
    /// next.
    pub fn abort_peer(&self, peer: IpAddr) {
        let mut st = self.shared.state.lock().unwrap();
        let hs: Vec<Id> = st.conns.iter().filter(|(_, c)| c.remote.ip() == peer).map(|(h, _)| *h).collect();
        if hs.is_empty() {
            return;
        }
        for h in hs {
            let c = st.conns.get_mut(&h).expect("listed above");
            c.rst = true;
            c.wake_gone();
            st.sock(h).abort();
        }
        st.kick();
    }

    /// Listens on `port`.
    ///
    /// Fails if `port` is 0, if something already listens there, or if an
    /// outgoing connection uses the port. Dropping the listener frees the
    /// port.
    pub fn listen(&self, port: u16) -> Result<Listener, Error> {
        let mut st = self.shared.state.lock().unwrap();
        if port == 0 {
            return Err("TCP port 0 cannot be listened on".into());
        }
        if st.listeners.contains_key(&port) || st.ports.contains_key(&port) {
            return Err(format!("TCP port {port} is already in use on {}", self.shared.addr).into());
        }
        st.listeners.insert(port, Listen::default());
        st.take_port(port);
        Ok(Listener { shared: self.shared.clone(), port, wait: CancelWait::default() })
    }

    /// Opens a connection from this machine to `to`.
    ///
    /// Fails with [`ConnError::Refused`] if the other side answers with a
    /// RST. It also fails with `Refused` immediately, without sending
    /// anything, if `to` has port 0, an
    /// unspecified address, or not the same IP version as this machine's
    /// address, or if every local port from 49152 up is taken. Fails with
    /// [`ConnError::TimedOut`] if nothing answers for two minutes, and with
    /// [`ConnError::Closed`] once the endpoint has stopped.
    pub async fn connect(&self, cx: &Cx, to: SocketAddr) -> Result<TcpConnection, ConnError> {
        if cx.is_cancelled() {
            return Err(ConnError::Cancelled);
        }
        let addr = self.shared.addr;
        if to.port() == 0 || to.is_ipv4() != addr.is_ipv4() || to.ip().is_unspecified() {
            return Err(ConnError::Refused);
        }
        let conn = {
            let mut st = self.shared.state.lock().unwrap();
            if st.stopped {
                return Err(ConnError::Closed);
            }
            let mut port = None;
            for _ in 0..(65536 - EPHEMERAL as u32) {
                let p = st.next_port;
                st.next_port = if p == u16::MAX { EPHEMERAL } else { p + 1 };
                if !st.ports.contains_key(&p) {
                    port = Some(p);
                    break;
                }
            }
            // Every ephemeral port is taken: the kernel says EADDRNOTAVAIL.
            let Some(port) = port else { return Err(ConnError::Refused) };
            let local = SocketAddr::new(addr, port);
            let mut s = new_socket(st.buffer);
            let st = &mut *st;
            if s.0.connect(st.iface.context(), to, local).is_err() {
                return Err(ConnError::Refused);
            }
            let h = st.add_socket(s);
            st.conns.insert(h, Conn::new(local, to, true));
            st.by_tuple.insert((local, to), h);
            st.take_port(port);
            st.kick();
            TcpConnection { shared: self.shared.clone(), handle: h, local, remote: to, read_wait: CancelWait::default(), write_wait: CancelWait::default() }
        };
        let mut wait = CancelWait::default();
        poll_fn(|task| {
            if cx.is_cancelled() {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            {
                let mut st = conn.shared.state.lock().unwrap();
                if st.stopped {
                    return Poll::Ready(Err(ConnError::Closed));
                }
                let s = st.sock(conn.handle);
                match s.state() {
                    TcpState::SynSent | TcpState::SynReceived => s.register_send_waker(task.waker()),
                    TcpState::Closed => {
                        return Poll::Ready(Err(match st.closed_reason(conn.handle) {
                            ConnError::Reset => ConnError::Refused,
                            e => e,
                        }));
                    }
                    _ => return Poll::Ready(Ok(())),
                }
            }
            if cx.register_cancel(task.waker(), &mut wait) {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            Poll::Pending
        })
        .await?;
        Ok(conn)
    }
}

/// Waits for incoming connections on one port.
pub struct Listener {
    shared: Arc<Shared>,
    port: u16,
    wait: CancelWait,
}

impl Listener {
    /// Waits for the next connection.
    ///
    /// Returns early with [`ConnError::Cancelled`] if `cx`'s
    /// [region](crate::Cx#regions) is cancelled, and fails with
    /// [`ConnError::Closed`] once the endpoint has stopped.
    ///
    /// Up to 16,384 connections wait here for `accept`, counting those
    /// still in their handshake. Beyond that, connection attempts get a
    /// RST. At most 256 of them may come from one peer address. Beyond
    /// that, that address's connection attempts are dropped until some of
    /// its connections are accepted or give up. So one peer that sends
    /// SYNs and never finishes the handshake cannot lock others out.
    pub async fn accept(&mut self, cx: &Cx) -> Result<TcpConnection, ConnError> {
        let port = self.port;
        let shared = &self.shared;
        let wait = &mut self.wait;
        poll_fn(|task| {
            if cx.is_cancelled() {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            {
                let mut st = shared.state.lock().unwrap();
                if st.stopped {
                    return Poll::Ready(Err(ConnError::Closed));
                }
                let l = st.listeners.get_mut(&port).expect("a listener has its port");
                if let Some(h) = l.ready.pop_front() {
                    let c = &st.conns[&h];
                    let (local, remote) = (c.local, c.remote);
                    st.listeners.get_mut(&port).expect("a listener has its port").left(remote.ip());
                    return Poll::Ready(Ok(TcpConnection {
                        shared: shared.clone(),
                        handle: h,
                        local,
                        remote,
                        read_wait: CancelWait::default(),
                        write_wait: CancelWait::default(),
                    }));
                }
                match &l.waker {
                    Some(w) if w.will_wake(task.waker()) => {}
                    _ => l.waker = Some(task.waker().clone()),
                }
            }
            if cx.register_cancel(task.waker(), wait) {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            Poll::Pending
        })
        .await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut st = self.shared.state.lock().unwrap();
        let Some(l) = st.listeners.remove(&self.port) else { return };
        st.free_port(self.port);
        for h in l.idle {
            st.remove_socket(h);
        }
        // Connections that never reached accept are reset.
        for h in l.embryonic.into_iter().chain(l.ready) {
            st.orphan(h, true);
        }
    }
}

/// One TCP connection. Implements [`Connection`].
///
/// Dropping it closes the connection: a FIN after the bytes already
/// written, or a RST if bytes it received were never read.
pub struct TcpConnection {
    shared: Arc<Shared>,
    handle: Id,
    local: SocketAddr,
    remote: SocketAddr,
    read_wait: CancelWait,
    write_wait: CancelWait,
}

impl TcpConnection {
    /// The other side's address and port.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    /// This side's address and port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Closes the connection with a RST immediately. Its socket is removed
    /// without waiting for the peer.
    ///
    /// Dropping a connection whose received bytes were all read closes it
    /// with a FIN instead. Its socket then stays until the peer has finished
    /// closing too, or has sent nothing for a minute, so a peer that keeps
    /// sending keeps the socket. A server that must bound how many sockets
    /// a peer can hold, such as one that turns connections away past a
    /// limit, resets each connection it is done with.
    pub fn reset(self) {
        let mut st = self.shared.state.lock().unwrap();
        st.sock(self.handle).abort();
        st.kick();
    }

    /// A watch that says when this connection has been reset, by either
    /// side, or is gone, without reading from it. For a server that is not
    /// reading, such as HTTP/1.1 while a handler works.
    pub fn gone_watch(&self) -> GoneWatch {
        GoneWatch { shared: self.shared.clone(), handle: self.handle }
    }

    /// Keeps `item` until the connection's socket is gone, which may be
    /// after this handle is dropped: closing waits for the peer (FIN-WAIT,
    /// LAST-ACK) for up to a minute. Limits that count connections hold
    /// their count here, so a peer that never finishes closing cannot open
    /// more past the limit. Each call keeps one more item.
    pub fn hold_until_gone(&self, item: Box<dyn std::any::Any + Send>) {
        self.gone_watch().hold_until_gone(item);
    }
}

/// Says when a connection has been reset or is gone, without reading
/// from it. See [`TcpConnection::gone_watch`].
#[derive(Clone)]
pub struct GoneWatch {
    shared: Arc<Shared>,
    handle: Id,
}

impl GoneWatch {
    /// Ready once the connection was reset, or is gone.
    pub fn poll_gone(&self, task: &mut Context<'_>) -> Poll<()> {
        poll_gone(&self.shared, self.handle, task)
    }

    /// Resets the connection, as [`TcpConnection::reset`] does, after the
    /// connection itself was handed on.
    pub fn reset(&self) {
        let mut st = self.shared.state.lock().unwrap();
        if st.conns.contains_key(&self.handle) {
            st.sock(self.handle).abort();
            st.kick();
        }
    }

    /// Keeps `item` until the connection's socket is gone: see
    /// [`TcpConnection::hold_until_gone`]. Works after the connection
    /// itself was handed on, such as boxed behind TLS.
    pub fn hold_until_gone(&self, item: Box<dyn std::any::Any + Send>) {
        let mut st = self.shared.state.lock().unwrap();
        match st.conns.get_mut(&self.handle) {
            Some(c) => c.held.push(item),
            None => drop(item),
        }
    }
}

/// Ready once the connection `handle` was reset, or is gone.
fn poll_gone(shared: &Shared, handle: Id, task: &mut Context<'_>) -> Poll<()> {
    let mut st = shared.state.lock().unwrap();
    if st.stopped {
        return Poll::Ready(());
    }
    match st.conns.get_mut(&handle) {
        None => Poll::Ready(()),
        Some(c) if c.rst => Poll::Ready(()),
        Some(c) => {
            if !c.gone.iter().any(|w| w.will_wake(task.waker())) {
                c.gone.push(task.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut st = self.shared.state.lock().unwrap();
        let h = self.handle;
        st.orphan(h, false);
    }
}

impl Connection for TcpConnection {
    fn poll_read(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        if cx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        {
            let mut st = self.shared.state.lock().unwrap();
            if st.stopped {
                return Poll::Ready(Err(ConnError::Closed));
            }
            let h = self.handle;
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            match st.sock(h).recv_slice(buf) {
                Ok(0) => st.sock(h).register_recv_waker(task.waker()),
                Ok(n) => {
                    let c = st.conns.get_mut(&h).unwrap();
                    c.read = c.read.wrapping_add(n as u32);
                    st.kick();
                    return Poll::Ready(Ok(n));
                }
                Err(stcp::RecvError::Finished) => return Poll::Ready(Ok(0)),
                Err(stcp::RecvError::InvalidState) => {
                    let c = &st.conns[&h];
                    if c.fin && !c.rst {
                        return Poll::Ready(Ok(0));
                    }
                    return Poll::Ready(Err(st.closed_reason(h)));
                }
            }
        }
        if cx.register_cancel(task.waker(), &mut self.read_wait) {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        Poll::Pending
    }

    fn poll_write(&mut self, cx: &Cx, task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        if cx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        {
            let mut st = self.shared.state.lock().unwrap();
            if st.stopped {
                return Poll::Ready(Err(ConnError::Closed));
            }
            let h = self.handle;
            if st.conns[&h].shut {
                return Poll::Ready(Err(ConnError::Closed));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let s = st.sock(h);
            match s.state() {
                TcpState::Established | TcpState::CloseWait => match s.send_slice(data) {
                    Ok(0) => s.register_send_waker(task.waker()),
                    Ok(n) => {
                        st.soiled(h);
                        st.kick();
                        return Poll::Ready(Ok(n));
                    }
                    Err(_) => return Poll::Ready(Err(st.closed_reason(h))),
                },
                TcpState::Closed => return Poll::Ready(Err(st.closed_reason(h))),
                // The FIN went out already.
                _ => return Poll::Ready(Err(ConnError::Closed)),
            }
        }
        if cx.register_cancel(task.waker(), &mut self.write_wait) {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        Poll::Pending
    }

    /// Sends a FIN, after every byte already written. Returns immediately.
    fn poll_shutdown(&mut self, cx: &Cx, _task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        if cx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        let mut st = self.shared.state.lock().unwrap();
        if st.stopped {
            return Poll::Ready(Err(ConnError::Closed));
        }
        let h = self.handle;
        if st.sock(h).state() == TcpState::Closed && !st.conns[&h].shut {
            return Poll::Ready(Err(st.closed_reason(h)));
        }
        st.sock(h).close();
        st.conns.get_mut(&h).unwrap().shut = true;
        st.kick();
        Poll::Ready(Ok(()))
    }
    fn poll_gone(&self, task: &mut Context<'_>) -> Poll<()> {
        poll_gone(&self.shared, self.handle, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::ConnectionExt;
    use crate::{InterfaceExt, block_on, pair, run};

    /// Resident pages of every socket's buffers on `e`.
    fn resident(e: &Endpoint) -> usize {
        let st = e.shared.state.lock().unwrap();
        st.pages.values().map(Pages::resident).sum()
    }

    fn pattern(n: usize, salt: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt)).collect()
    }

    /// A TCP segment from `src` to `dst` with no options.
    fn segment(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8) -> Packet {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&src.port().to_be_bytes());
        t[2..4].copy_from_slice(&dst.port().to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let sum = transport_checksum(src.ip(), dst.ip(), TCP, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        crate::stdlib::ip::packet(src.ip(), dst.ip(), TCP, &t)
    }

    /// A listening port holds at most its backlog of connections not
    /// accepted yet. Further SYNs get a RST.
    #[test]
    fn syns_past_the_backlog_get_a_rst() {
        assert_eq!(Options::default().backlog, 4096);
        assert_eq!((Options::default().backlog(0).backlog, Options::default().backlog(1 << 20).backlog), (1, MAX_BACKLOG));
        let result = block_on(run(|cx| async move {
            let (mut raw, side) = pair();
            let server = endpoint_with(&cx, side, "10.0.0.1".parse().unwrap(), Options::default().backlog(4));
            let _listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            for port in 1000..1010u16 {
                raw.send(segment(SocketAddr::new("10.0.0.2".parse().unwrap(), port), to, 7, 0, 0x02));
            }
            let (mut syn_acks, mut rsts) = (0, 0);
            while syn_acks + rsts < 10 {
                let p = raw.recv(&cx).await?;
                let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
                match t[13] {
                    0x12 => syn_acks += 1,
                    f if f & 0x04 != 0 => rsts += 1,
                    f => panic!("flags {f:#x}"),
                }
            }
            assert_eq!((syn_acks, rsts), (4, 6));
            Err::<(), crate::Error>("done".into())
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// A burst of handshakes that the peer resets in SYN-RECEIVED leaves
    /// at most one spare listening socket, not one per SYN.
    #[test]
    fn a_burst_of_reset_handshakes_leaves_no_pool_of_sockets() {
        let result = block_on(run(|cx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&cx, side, "10.0.0.1".parse().unwrap());
            let _listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            for port in 1000..1250u16 {
                raw.send(segment(SocketAddr::new("10.0.0.2".parse().unwrap(), port), to, 7, 0, 0x02));
            }
            let mut acks = 0;
            while acks < 250 {
                let p = raw.recv(&cx).await?;
                let ip = Header::parse_whole(&p.0).unwrap();
                let t = ip.payload(&p.0);
                assert_eq!(t[13], 0x12, "a SYN-ACK");
                let port = u16::from_be_bytes([t[2], t[3]]);
                let isn = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
                let from = SocketAddr::new("10.0.0.2".parse().unwrap(), port);
                raw.send(segment(from, to, 8, isn.wrapping_add(1), 0x04));
                acks += 1;
            }
            cx.sleep(Duration::from_millis(100)).await?;
            let st = server.shared.state.lock().unwrap();
            let l = &st.listeners[&80];
            assert!(l.embryonic.is_empty() && l.ready.is_empty());
            assert!(l.idle.len() <= 1, "{} spare listening sockets", l.idle.len());
            assert!(st.sockets.iter().count() <= 1);
            drop(st);
            Err::<(), crate::Error>("done".into())
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// After many connections come and go, the socket set is rebuilt
    /// without its empty slots, and a connection that stayed open keeps
    /// working.
    #[test]
    fn the_socket_set_shrinks_after_a_crowd_leaves() {
        let result = block_on(run(|cx| async move {
            let (a, b) = pair();
            let server = endpoint(&cx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&cx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let mut keep_c = client.connect(&cx, "10.0.0.1:80".parse().unwrap()).await?;
            let mut keep_s = listener.accept(&cx).await?;
            let mut crowd = Vec::new();
            for _ in 0..400 {
                let c = client.connect(&cx, "10.0.0.1:80".parse().unwrap()).await?;
                let s = listener.accept(&cx).await?;
                crowd.push((c, s));
            }
            assert!(server.shared.state.lock().unwrap().slots >= 401);
            drop(crowd);
            cx.sleep(Duration::from_millis(300)).await?;
            for e in [&server, &client] {
                let st = e.shared.state.lock().unwrap();
                assert!(st.handles.len() <= 3, "{} sockets left", st.handles.len());
                // Compacted on the way down: fewer than 256 slots remain,
                // not the 401 it had.
                assert!(st.slots < COMPACT_SLOTS, "{} slots left", st.slots);
                assert_eq!(st.sockets.iter().count(), st.handles.len());
            }
            let data = pattern(1 << 20, 9);
            let writer = {
                let data = data.clone();
                cx.spawn(move |cx| async move {
                    keep_s.write_all(&cx, &data).await?;
                    Ok(())
                })
            };
            let mut got = vec![0u8; 1 << 20];
            let mut at = 0;
            while at < got.len() {
                at += keep_c.read(&cx, &mut got[at..]).await?;
            }
            writer.join(&cx).await?;
            assert!(got == data, "the connection that stayed open still works");
            Err::<(), crate::Error>("done".into())
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// A connection whose handle is dropped waits for the peer for at most
    /// a minute, not the two minutes of an open one.
    #[test]
    fn a_dropped_connection_waits_a_minute_at_most() {
        let result = block_on(run(|cx| async move {
            let (a, b) = pair();
            let server = endpoint(&cx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&cx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let _c = client.connect(&cx, "10.0.0.1:80".parse().unwrap()).await?;
            let s = listener.accept(&cx).await?;
            let h = s.handle;
            assert_eq!(server.shared.state.lock().unwrap().get(h).timeout(), Some(TIMEOUT.into()));
            drop(s);
            cx.sleep(Duration::from_millis(50)).await?;
            let st = server.shared.state.lock().unwrap();
            assert_eq!(st.get(h).state(), TcpState::FinWait2, "the client never closes its side");
            assert_eq!(st.get(h).timeout(), Some(ORPHAN_TIMEOUT.into()));
            drop(st);
            Err::<(), crate::Error>("done".into())
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    #[test]
    fn options_set_the_buffers_of_every_connection() {
        assert_eq!(Options::default().buffer(1).buffer, MIN_BUFFER);
        assert_eq!(Options::default().buffer(usize::MAX).buffer, MAX_BUFFER);
        for size in [MIN_BUFFER, 1 << 20] {
            let result = block_on(run(move |cx| async move {
                let (a, b) = pair();
                let options = Options::default().buffer(size);
                let server = endpoint_with(&cx, a, "10.0.0.1".parse().unwrap(), options);
                let client = endpoint_with(&cx, b, "10.0.0.2".parse().unwrap(), options);
                let mut listener = server.listen(80)?;
                let mut c = client.connect(&cx, "10.0.0.1:80".parse().unwrap()).await?;
                let mut s = listener.accept(&cx).await?;
                for (ep, h) in [(&server, s.handle), (&client, c.handle)] {
                    let st = ep.shared.state.lock().unwrap();
                    assert_eq!(st.get(h).recv_capacity(), size);
                    assert_eq!(st.get(h).send_capacity(), size);
                }
                // 3 MiB arrive unchanged, through buffers smaller and larger
                // than the default.
                let data = pattern(3 << 20, 7);
                let sent = data.clone();
                let writer = cx.spawn(move |cx| async move { Ok(s.write_all(&cx, &sent).await?) });
                let mut got = vec![0u8; data.len()];
                let mut at = 0;
                while at < got.len() {
                    at += c.read(&cx, &mut got[at..]).await?;
                }
                assert!(got == data, "the data came through unchanged with {size}-byte buffers");
                writer.join(&cx).await?;
                Err::<(), crate::Error>("done".into())
            }));
            assert_eq!(result.unwrap_err().to_string(), "done");
        }
    }

    #[test]
    fn quiet_connections_give_their_buffer_pages_back() {
        let result = block_on(run(|cx| async move {
            let (a, b) = pair();
            let server = endpoint(&cx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&cx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let mut c = client.connect(&cx, "10.0.0.1:80".parse().unwrap()).await?;
            let mut s = listener.accept(&cx).await?;
            // A fresh connection costs (almost) no pages.
            assert!(resident(&server) <= 4, "{}", resident(&server));

            for round in 0..2u8 {
                // 1 MiB down and 1 MiB up, through the 256 KiB buffers.
                let down = pattern(1 << 20, round);
                let up = pattern(1 << 20, round + 100);
                let slot = Arc::new(Mutex::new(None));
                let writer = {
                    let (down, slot) = (down.clone(), slot.clone());
                    cx.spawn(move |cx| async move {
                        s.write_all(&cx, &down).await?;
                        let mut got = vec![0u8; 1 << 20];
                        let mut at = 0;
                        while at < got.len() {
                            at += s.read(&cx, &mut got[at..]).await?;
                        }
                        *slot.lock().unwrap() = Some((s, got));
                        Ok(())
                    })
                };
                let mut got = vec![0u8; 1 << 20];
                let mut at = 0;
                while at < got.len() {
                    at += c.read(&cx, &mut got[at..]).await?;
                }
                assert!(got == down, "the download came through unchanged in round {round}");
                c.write_all(&cx, &up).await?;
                writer.join(&cx).await?;
                let (back, got_up) = slot.lock().unwrap().take().unwrap();
                s = back;
                assert!(got_up == up, "the upload came through unchanged in round {round}");
                // Both sides wrote whole buffers.
                assert!(resident(&server) >= 64, "{}", resident(&server));
                // Once the connection is quiet, its pages go back, while it
                // stays open.
                cx.sleep(Duration::from_millis(2500)).await?;
                assert_eq!(resident(&server), 0);
                assert_eq!(resident(&client), 0);
            }
            drop((c, s));
            // Err ends the run, and with it the endpoints' drivers.
            Err::<(), crate::Error>("done".into())
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}
