//! The standard library: everything in Fictionet that knows about
//! networking.
//!
//! The core of Fictionet only moves packets between [`Interface`]s. It
//! never reads them. This module adds everything that does: IP addresses,
//! routing, TCP and UDP, TLS, DNS, and whole websites. Read it once you have a world running and want to give
//! the sandbox something to talk to.
//!
//! # What you build with it
//!
//! A world is a network of small pieces joined by interfaces. The pieces
//! you use most are:
//!
//! - **Machines.** A machine is one IP address on the simulated network. You
//!   build one from an interface: [`ip::split_protocols`] splits its packets
//!   by protocol, and [`tcp::endpoint`] and [`udp::endpoint`] give the TCP
//!   and UDP parts listeners, connections and sockets.
//! - **Networks.** [`route::router`] forwards packets between routes by
//!   destination address. [`route::lan`] joins machines on one IP subnet and
//!   floods broadcast and multicast traffic to its members.
//! - **Links.** [`delay`] and [`bottleneck`] sit on an interface and change
//!   how its packets travel, as a slow or distant link would. [`filter`]
//!   shows each packet to your code, which can drop it.
//! - **Websites.** [`web::Sites`] builds all of the above for you: DNS,
//!   addresses, a router, one machine per address, TLS and HTTP. Start
//!   there if the world is a set of websites.
//!
//! Every piece is ordinary code built from the same public items, so you
//! can wire a network by hand when `Sites` does not fit. To put a link in
//! front of every sandbox, wrap the sandboxes with
//! [`Attachments::map`](crate::Attachments::map). The
//! [recipes](crate::recipes) show both ways, with commands to run.
//!
//! To customize a protocol, copy its module file into your crate and edit it.
//! Its `fictionet::stdlib::...` imports need no change. Plug the copy's
//! [`codec::Decode`] and [`codec::Wire`] implementations into [`codec::Stream`]
//! and the generic codec tools. Named sibling modules stay SDK dependencies.
//! See the `custom_protocol` example for a copied Modbus module.
//!
//! # Three kinds of functions
//!
//! Every function in the stdlib is one of three kinds. The kind tells you
//! whether it takes a [`Cx`], whether you `.await` it, and whether anything
//! keeps running after it returns.
//!
//! **Functions that start a task.** These take a [`&Cx`](Cx) and one or more
//! [`Interface`]s. They start a background task that keeps moving packets,
//! and return immediately, usually with new interfaces or a handle. You do
//! not `.await` them. The task belongs to the caller's
//! [region](Cx#regions), so it stops when the region is cancelled. It also
//! stops when it has nothing left to do, which depends on the function:
//!
//! - [`delay`], [`bottleneck`] and [`filter`] stop when either of their
//!   interfaces closes.
//! - The splits in [`ip`] stop when the interface they split closes, or when
//!   all of the interfaces they returned have closed.
//! - [`route::router`] stops when the last of its interfaces has closed and
//!   no [`Router`](route::Router) handle is left to add more.
//! - [`route::lan`] stops when its last member has closed and no
//!   [`Lan`](route::Lan) handle is left to add more.
//! - [`tcp::endpoint`] and [`udp::endpoint`] stop when their interface
//!   closes.
//!
//! [`web::Sites::serve`] is the one function that starts many tasks: one
//! for each part of the network it builds. Each task yields after at most 64
//! packets in a row, so a busy interface cannot starve the rest of the run
//! (see [`Cx::yield_now`]).
//!
//! | Function | Takes | Gives back |
//! |---|---|---|
//! | [`delay`] | an interface | the same packets, later |
//! | [`bottleneck`] | an interface | the same packets, at most a given rate, with a queue that drops when full |
//! | [`filter`] | an interface, and a callback | the packets the callback keeps |
//! | [`ip::split_versions`] | an interface | IPv4, IPv6 and other packets, split apart |
//! | [`ip::split_protocols`] | an interface | TCP, UDP, ICMP and other packets, split apart |
//! | [`route::router`] | many interfaces with prefixes | a handle for adding routes later; it forwards between them |
//! | [`route::lan`] | interfaces with addresses on one subnet | a handle for adding members; it forwards unicast and floods IP group traffic |
//! | [`tcp::endpoint`] | TCP packets and an address | listeners and connections |
//! | [`udp::endpoint`] | UDP packets and an address | sockets |
//! | [`web::Sites::serve`] | the attachments, and a callback that gives the site for a hostname | nothing: it builds DNS, routing, machines, TLS and HTTP |
//!
//! **Functions you await.** These are `async`. They take `&Cx`, as every
//! wait in Fictionet does, and run inside the task that awaits them. They
//! start no task of their own. When the caller's region is cancelled, they
//! return early with an error. Examples are [`tls::server`],
//! [`tcp::Listener::accept`] and [`ConnectionExt::read`].
//!
//! **Plain functions.** These read or build values. They never wait, take
//! no context, and start nothing. Examples are [`icmp::echo_reply`], parsing
//! a [`Prefix`](route::Prefix), and everything in [`dns`]. A builder such as
//! [`tls::config_builder`] takes a `Cx` only to read its clock and random
//! numbers. It never waits and starts nothing either.
//!
//! # A small example
//!
//! This world gives the sandbox named `agent` a 50 ms link, and puts one
//! machine at `10.0.0.1` behind it that accepts TCP connections on port 80.
//! First, `get` waits for the sandbox to attach. The next three calls start
//! tasks and return immediately. Then `accept` waits for each connection.
//!
//! ```
//! use fictionet::{Attachments, Cx, Result, stdlib, time::ms};
//! use fictionet::stdlib::{ip, tcp};
//!
//! async fn world(cx: Cx, mut attachments: Attachments) -> Result {
//!     let agent = attachments.get(&cx, "agent").await?;
//!     let link = stdlib::delay(&cx, ms(50), agent);
//!     let (tcp, _udp, _icmp, _other) = ip::split_protocols(&cx, link);
//!     let machine = tcp::endpoint(&cx, tcp, "10.0.0.1".parse()?);
//!     let mut listener = machine.listen(80)?;
//!     while let Ok(conn) = listener.accept(&cx).await {
//!         // serve `conn`, usually in a task of its own
//!         drop(conn);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! The sandbox here talks to one machine directly, with no router. Every
//! packet it sends goes to that machine, which drops any packet not
//! addressed to `10.0.0.1`. A real world puts a [`route::router`] between
//! them, as [`route`] shows.

use std::collections::{BTreeSet, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

use crate::cx::CancelWait;
use crate::time::{Duration, Instant};
use crate::cable::PACKET_COST;
use crate::{Cx, End, Interface, Packet, RecvError};

mod connection;
mod wire;
pub mod amqp;
pub mod asn1;
pub mod bacnet;
pub mod bgp;
pub mod coap;
pub mod codec;
pub mod cotp;
pub mod dcerpc;
#[doc(hidden)]
pub mod dhcp;
pub mod dhcpv6;
pub mod diameter;
pub mod dnp3;
pub mod dns;
pub mod dtls;
pub mod enip;
pub mod fastcgi;
pub mod ftp;
pub mod geneve;
pub mod git_protocol;
pub mod gre;
pub mod grpc;
pub mod http3;
pub mod icmp;
pub mod iec104;
pub mod igmp;
pub mod ike;
pub mod imap;
pub mod imf;
pub mod ip;
pub mod ipp;
pub mod ipsec;
pub mod json;
pub mod kafka;
pub mod kerberos;
pub mod l2tp;
pub mod ldap;
pub mod memcache;
pub mod mime_multipart;
pub mod modbus;
pub mod mongodb;
pub mod mqtt;
pub mod mysql;
pub mod nbdgm;
pub mod nbns;
pub mod nbss;
pub mod nfs;
pub mod ntlmssp;
pub mod ntp;
pub mod ocsp;
pub mod onc_rpc;
pub mod opcua;
pub mod openvpn;
pub mod ospf;
pub mod pcp;
pub mod pim;
pub mod pop3;
pub mod portmap;
pub mod postgres;
pub mod protobuf;
pub mod proxy_protocol;
pub mod qpack;
pub mod quic;
pub mod radius;
pub mod rdp;
pub mod resp;
pub mod rfb;
pub mod rip;
pub mod route;
pub mod rtcp;
pub mod rtp;
pub mod rtsp;
pub mod sdp;
pub mod sftp;
pub mod sip;
pub mod smb2;
pub mod smtp;
pub mod snmp;
pub mod socks;
pub mod spnego;
pub mod ssh;
pub mod stun;
pub mod syslog;
pub mod tcp;
pub mod tds;
pub mod telnet;
pub mod tftp;
pub mod thrift;
pub mod tls;
pub mod tpkt;
#[doc(hidden)]
pub mod transport;
pub mod udp;
pub mod urlencoded_form;
pub mod vrrp;
pub mod vxlan;
pub mod wake_on_lan;
pub mod web;
pub mod websocket;
pub mod whois;
pub mod wireguard;
pub mod x509;
pub mod xml;
pub mod zabbix;

pub use connection::{ConnError, Connection, ConnectionExt};

/// Delays every packet by `by`, in both directions, as a link with fixed
/// latency does.
///
/// Put it between a sandbox and the rest of the world to make every
/// destination feel far away. It starts a background task and returns
/// immediately with a new [`End`]. Use that end where you would have used
/// `inner`:
///
/// - Packets that come out of `inner` come out of the returned end `by`
///   later.
/// - Packets sent into the returned end reach `inner` `by` later.
///
/// So a round trip through `delay(&cx, ms(50), ..)` takes 100 ms. Each
/// packet is delayed on its own: ten packets sent together all arrive `by`
/// later, together.
///
/// A delay also caps how fast one TCP connection can go, as it does on a
/// real long link: a connection carries at most one buffer of data per
/// round trip. With the stdlib's default 256 KiB buffers, a 100 ms round
/// trip allows about 2.6 MB/s. [`tcp::Options::buffer`] sets larger ones.
///
/// The task stops when either interface closes, or when the caller's
/// [region](Cx#regions) is cancelled. Packets it still holds are lost.
///
/// A delay holds at most 32 MiB of packets in each direction, counting each
/// packet's length plus 64 bytes. A packet that arrives while its direction
/// is full is dropped, as a real link drops what its buffer cannot hold.
/// That is about 21,000 full-size packets: with a 100 ms delay, a direction
/// fills only above about 320 MB/s. The returned end also holds at most
/// 32 MiB each way, counted the same way, while it waits to be read, and
/// drops what is sent past that. Without these limits, a sandbox that sends without pause, or a
/// world that never reads the returned end, would grow the world's memory
/// without end.
///
/// How it works: `delay` makes two connected interfaces with
/// [`pair`](crate::pair), returns one, and starts a task with
/// [`Cx::spawn`] that holds the other and `inner`. The task stamps each
/// packet with `cx.now() + by` and puts it in a queue for its direction. Because the delay is fixed, each queue is
/// already in the order packets leave. The task waits for whichever comes
/// first: a packet from either side, or the time at the front of a queue.
#[track_caller]
pub fn delay(cx: &Cx, by: Duration, inner: impl Interface) -> End {
    shape(cx, "delay", inner, move |queue: &Queue, now: Instant, _len: usize| {
        // Each packet waits `by` from when it arrived. The queue stays in
        // release order because `by` is fixed.
        let _ = queue;
        Some(later(now, by))
    })
}

/// Limits packets to `bits_per_second`, with a queue of at most `queue`
/// packets in each direction.
///
/// This models a slow link, and the way a real slow link loses packets.
/// Packets that arrive faster than the rate wait in the queue. When the
/// queue already holds `queue` packets, a new packet is dropped. This is
/// called tail drop.
///
/// A queue limit only matters where packets wait, and packets only wait
/// where something is slower than its input. That is why the limit comes
/// with a rate. Interfaces made by [`pair`](crate::pair) never fill up on
/// their own.
///
/// Whatever `queue` says, a direction also holds at most 32 MiB, counting
/// each packet's length plus 64 bytes, as [`delay`] does. The returned end
/// holds at most 32 MiB each way while it waits to be read, and drops what
/// is sent past that, so packets that have left the queue cannot pile up
/// in an end that is not read.
///
/// Each direction has its own rate and queue, as on a real link. Like
/// [`delay`], it starts a background task and returns immediately with a
/// new [`End`] to use in place of `inner`. The task stops when either
/// interface closes, or when the caller's [region](Cx#regions) is
/// cancelled.
///
/// ```
/// # use fictionet::{Attachment, Cx, stdlib};
/// # fn wire(cx: Cx, sandbox: Attachment) {
/// // A 10 Mbit/s link with room for 100 waiting packets each way.
/// let link = stdlib::bottleneck(&cx, 10_000_000, 100, sandbox);
/// # drop(link);
/// # }
/// ```
///
/// The queue counts every packet that has not left yet, including the one
/// being sent. A packet leaves when its last bit has been sent: a 1,000-byte
/// packet on a 1 Mbit/s link leaves 8 ms after the link started sending it.
/// So with `queue` 10, a burst of 11 packets loses the 11th. A rate of 0
/// sends nothing: the queue fills and every later packet is dropped.
#[track_caller]
pub fn bottleneck(cx: &Cx, bits_per_second: u64, queue: usize, inner: impl Interface) -> End {
    shape(cx, "bottleneck", inner, move |waiting: &Queue, now: Instant, len: usize| {
        if waiting.packets.len() >= queue {
            return None;
        }
        // The link starts on this packet when the one before it has left.
        let start = match waiting.packets.back() {
            Some((leaves, _)) if *leaves > now => *leaves,
            _ => now,
        };
        Some(later(start, send_time(len, bits_per_second)))
    })
}

/// Which way a packet is going through a [`filter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Out of `inner`, toward the returned end. When `inner` is an
    /// [`Attachment`](crate::Attachment), these are the packets the
    /// sandbox sends.
    FromInner,
    /// Into `inner`, from the returned end. When `inner` is an
    /// `Attachment`, these are the packets the sandbox receives.
    ToInner,
}

/// Calls `keep` for every packet that passes, in both directions, and
/// passes on only the packets it returns `true` for.
///
/// Use it to watch packets, or to drop some of them. Like [`delay`], it
/// starts a background task and returns immediately with a new [`End`] to
/// use in place of `inner`. Packets that `keep` lets through pass
/// unchanged and without delay, in the order they came. As with
/// [`delay`], the returned end holds at most 32 MiB each way while it
/// waits to be read, and drops what is sent past that.
///
/// This one drops 2% of the packets in each direction at random, as a
/// lossy link does:
///
/// ```
/// # use fictionet::{Attachment, Cx, stdlib};
/// # fn wire(cx: Cx, sandbox: Attachment) {
/// let lossy = stdlib::filter(&cx, sandbox, |cx, _direction, _packet| cx.random_f64() >= 0.02);
/// # drop(lossy);
/// # }
/// ```
///
/// `keep` runs inside the task, once per packet, so it must return quickly
/// and must not block. Every task of a world shares one thread, so a slow
/// `keep` slows the whole world. To write packets to a file, hand them to
/// a channel that never waits, and write them on another thread. The
/// [packet capture recipe](crate::recipes#packet-capture) does this.
///
/// The task stops when either interface closes, or when the caller's
/// [region](Cx#regions) is cancelled.
#[track_caller]
pub fn filter<F>(cx: &Cx, inner: impl Interface, mut keep: F) -> End
where
    F: FnMut(&Cx, Direction, &Packet) -> bool + Send + 'static,
{
    let (outer, mine) = link_pair();
    cx.spawn_as(|| "filter".into(), move |cx| async move {
        // Port 0 is `inner`, port 1 our end of the new pair.
        let mut ports = Ports::new(vec![Box::new(inner), Box::new(mine)]);
        loop {
            match ports.next(&cx, None, |_| Poll::Pending).await {
                Event::Packet(i, packet) => {
                    let direction = if i == 0 { Direction::FromInner } else { Direction::ToInner };
                    if keep(&cx, direction, &packet) {
                        ports.send(1 - i, packet);
                    }
                }
                Event::Timer => {}
                Event::Closed(_) | Event::Cancelled | Event::Extra => return Ok(()),
            }
        }
    });
    outer
}

/// How long `len` bytes take at `bits_per_second`, rounded up to the next
/// nanosecond. `Duration::MAX` for a rate of 0.
fn send_time(len: usize, bits_per_second: u64) -> Duration {
    if bits_per_second == 0 {
        return Duration::MAX;
    }
    let nanos = (len as u128 * 8 * 1_000_000_000).div_ceil(bits_per_second as u128);
    match u64::try_from(nanos) {
        Ok(n) => Duration::from_nanos(n),
        Err(_) => Duration::MAX,
    }
}

/// `at + d`, or a time so far away it never comes if that overflows.
fn later(at: Instant, d: Duration) -> Instant {
    match at.since_start().checked_add(d) {
        Some(t) => Instant::from_since_start(t),
        None => Instant::from_since_start(Duration::MAX),
    }
}

/// The packets waiting in one direction of a [`shape`]d link, each with the
/// time it leaves. Always in leaving order.
#[derive(Default)]
struct Queue {
    packets: VecDeque<(Instant, Packet)>,
    /// What `packets` holds, counted as for [`LINK_STORE`].
    bytes: usize,
}

/// The most a [`delay`] or [`bottleneck`] holds in each direction: packets
/// waiting to leave, each counted as its length plus 64 bytes. A packet
/// that would take a direction past this is dropped, as a full queue on a
/// real link drops it.
const LINK_STORE: usize = 32 << 20;

/// The most each direction of the interface returned by [`delay`],
/// [`bottleneck`] and [`filter`] holds while it waits to be read, counted
/// the same way. Past that, packets sent into it are dropped. TCP puts up
/// to a window of packets into it at once, so it is as large as the
/// windows of a hundred connections with the default buffers.
const LINK_OUTPUT: usize = 32 << 20;

/// The two ends that [`shape`] and [`filter`] make, with a size limit.
fn link_pair() -> (End, End) {
    crate::cable::pair_with_limit(LINK_OUTPUT)
}

/// The loop behind [`delay`] and [`bottleneck`]. For each packet,
/// `admit(queue, now, len)` gives the time it leaves, or `None` to drop it.
/// Leaving times must not go down within a direction.
#[track_caller]
fn shape<F>(cx: &Cx, name: &'static str, inner: impl Interface, admit: F) -> End
where
    F: Fn(&Queue, Instant, usize) -> Option<Instant> + Send + 'static,
{
    let (outer, mine) = link_pair();
    cx.spawn_as(move || name.into(), move |cx| async move {
        // Port 0 is `inner`, port 1 our end of the new pair. A packet from
        // port `i` waits in `queues[i]`, then goes out on port `1 - i`.
        let mut ports = Ports::new(vec![Box::new(inner), Box::new(mine)]);
        let mut queues = [Queue::default(), Queue::default()];
        loop {
            let deadline = queues.iter().filter_map(|q| q.packets.front().map(|(t, _)| *t)).min();
            match ports.next(&cx, deadline, |_| Poll::Pending).await {
                Event::Packet(i, packet) => {
                    let now = cx.now();
                    let cost = packet.0.len() + PACKET_COST;
                    let fits = queues[i].bytes + cost <= LINK_STORE;
                    if let Some(leaves) = admit(&queues[i], now, packet.0.len()).filter(|_| fits) {
                        queues[i].bytes += cost;
                        queues[i].packets.push_back((leaves, packet));
                    } else if cx.observed() {
                        let waiting = queues[i].packets.len();
                        crate::observe::note_drop(&cx, &packet, waiting);
                    }
                }
                Event::Timer => {
                    let now = cx.now();
                    let mut sent = 0;
                    for (i, queue) in queues.iter_mut().enumerate() {
                        while sent < BUDGET {
                            match queue.packets.front() {
                                Some((t, _)) if *t <= now => {}
                                _ => break,
                            }
                            let (_, packet) = queue.packets.pop_front().unwrap();
                            queue.bytes -= packet.0.len() + PACKET_COST;
                            ports.send(1 - i, packet);
                            sent += 1;
                        }
                    }
                    ports.spend(sent);
                }
                Event::Closed(_) | Event::Cancelled | Event::Extra => return Ok(()),
            }
        }
    });
    outer
}

/// How many packets a stdlib task handles in a row before it yields.
pub(crate) const BUDGET: usize = 64;

/// What [`Ports::next`] saw.
pub(crate) enum Event {
    /// A packet arrived on port `.0`.
    Packet(usize, Packet),
    /// Port `.0` closed. [`Ports`] has already dropped it.
    Closed(usize),
    /// The deadline passed.
    Timer,
    /// The extra source given to `next` is ready.
    Extra,
    /// The region was cancelled.
    Cancelled,
}

/// The interfaces one stdlib task serves, and the waiting that is common to
/// all of them. It waits for the first packet on any interface, a deadline,
/// or one extra source. It takes interfaces in turn, so that a busy one
/// cannot starve the others. It yields after [`BUDGET`] packets in a row.
///
/// Each interface is polled with its own waker, which puts the interface in
/// a queue of ready interfaces. A turn polls only the interfaces in that
/// queue, so the cost of a packet does not grow with the number of idle
/// interfaces. A
/// router with thousands of routes stays as fast as one with ten.
pub(crate) struct Ports {
    ports: Vec<Option<Box<dyn Interface>>>,
    /// One waker per slot, which marks the slot ready.
    wakers: Vec<Waker>,
    ready: Arc<Ready>,
    /// Closed slots, for reuse.
    free: BTreeSet<usize>,
    /// How many slots hold a port.
    open: usize,
    /// Packets handled since the task last waited or yielded.
    run: usize,
    wait: CancelWait,
}

/// The slots that may have something to say, in the order they spoke up,
/// and the task to wake when one does.
#[derive(Default)]
struct Ready {
    inner: Mutex<ReadyInner>,
}

#[derive(Default)]
struct ReadyInner {
    slots: VecDeque<usize>,
    /// Whether each slot is in `slots`, so that it is there at most once.
    queued: Vec<bool>,
    task: Option<Waker>,
}

impl ReadyInner {
    fn push(&mut self, slot: usize) {
        if self.queued.len() <= slot {
            self.queued.resize(slot + 1, false);
        }
        if !self.queued[slot] {
            self.queued[slot] = true;
            self.slots.push_back(slot);
        }
    }

    fn pop(&mut self) -> Option<usize> {
        let slot = self.slots.pop_front()?;
        self.queued[slot] = false;
        Some(slot)
    }
}

/// The waker of one slot.
struct SlotWaker {
    ready: Arc<Ready>,
    slot: usize,
}

impl Wake for SlotWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let task = {
            let mut r = self.ready.inner.lock().unwrap_or_else(|e| e.into_inner());
            r.push(self.slot);
            r.task.take()
        };
        if let Some(task) = task {
            task.wake();
        }
    }
}

#[allow(dead_code)]
impl Ports {
    pub(crate) fn new(ports: Vec<Box<dyn Interface>>) -> Ports {
        let mut p = Ports {
            ports: Vec::new(),
            wakers: Vec::new(),
            ready: Arc::default(),
            free: BTreeSet::new(),
            open: 0,
            run: 0,
            wait: CancelWait::default(),
        };
        for port in ports {
            p.add(port);
        }
        p
    }

    fn lock_ready(&self) -> MutexGuard<'_, ReadyInner> {
        self.ready.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many ports are still open.
    pub(crate) fn open(&self) -> usize {
        self.open
    }

    /// Whether port `i` is open.
    pub(crate) fn is_open(&self, i: usize) -> bool {
        matches!(self.ports.get(i), Some(Some(_)))
    }

    /// Adds a port and returns its index. Reuses a closed slot, the lowest
    /// one first.
    pub(crate) fn add(&mut self, port: Box<dyn Interface>) -> usize {
        let i = match self.free.pop_first() {
            Some(i) => i,
            None => {
                let i = self.ports.len();
                self.ports.push(None);
                self.wakers.push(Waker::from(Arc::new(SlotWaker { ready: self.ready.clone(), slot: i })));
                i
            }
        };
        self.ports[i] = Some(port);
        self.open += 1;
        // A new port may already hold packets.
        self.lock_ready().push(i);
        i
    }

    /// Puts `port` at `i`, dropping what was there, which closes its interface.
    pub(crate) fn replace(&mut self, i: usize, port: Box<dyn Interface>) {
        let old = self.ports[i].replace(port);
        if old.is_none() {
            self.open += 1;
            self.free.remove(&i);
        }
        drop(old);
        self.lock_ready().push(i);
    }

    /// Drops port `i`, which closes its interface.
    pub(crate) fn close(&mut self, i: usize) {
        if let Some(p) = self.ports.get_mut(i) && p.take().is_some() {
            self.open -= 1;
            self.free.insert(i);
        }
    }

    /// Sends a packet out on port `i`. Lost if the port is closed.
    pub(crate) fn send(&mut self, i: usize, packet: Packet) {
        if let Some(Some(p)) = self.ports.get_mut(i) {
            p.send(packet);
        }
    }

    /// Counts `n` packets handled outside [`next`](Ports::next), such as
    /// packets released by a timer, toward the budget.
    pub(crate) fn spend(&mut self, n: usize) {
        self.run += n;
    }

    /// Waits for the next event: a packet or a close on any port, the
    /// deadline, `extra` being ready, or a cancel. Yields first if the
    /// budget is spent.
    pub(crate) async fn next(
        &mut self,
        cx: &Cx,
        deadline: Option<Instant>,
        mut extra: impl FnMut(&mut Context<'_>) -> Poll<()>,
    ) -> Event {
        if self.run >= BUDGET {
            self.run = 0;
            if cx.yield_now().await.is_err() {
                return Event::Cancelled;
            }
        }
        if cx.is_cancelled() {
            return Event::Cancelled;
        }
        if let Some(d) = deadline && d <= cx.now() {
            self.run += 1;
            return Event::Timer;
        }
        let mut sleep = pin!(deadline.map(|d| cx.sleep_until(d)));
        let mut waited = false;
        let event = poll_fn(|task| {
            // The extra source first: a router takes new routes before it
            // forwards packets sent after they were added.
            if extra(task).is_ready() {
                return Poll::Ready(Event::Extra);
            }
            // Register the task before looking at the queue, so a slot that
            // becomes ready after the queue looked empty still wakes it.
            {
                let mut r = self.lock_ready();
                match &r.task {
                    Some(w) if w.will_wake(task.waker()) => {}
                    _ => r.task = Some(task.waker().clone()),
                }
            }
            loop {
                let Some(i) = self.lock_ready().pop() else { break };
                let Some(port) = self.ports[i].as_mut() else { continue };
                let mut slot_task = Context::from_waker(&self.wakers[i]);
                match port.poll_recv(cx, &mut slot_task) {
                    Poll::Ready(Ok(packet)) => {
                        // It may hold more. It goes to the back, after the
                        // others that are ready, so each gets its turn.
                        self.lock_ready().push(i);
                        return Poll::Ready(Event::Packet(i, packet));
                    }
                    Poll::Ready(Err(RecvError::Closed)) => {
                        self.close(i);
                        return Poll::Ready(Event::Closed(i));
                    }
                    Poll::Ready(Err(RecvError::Cancelled)) => return Poll::Ready(Event::Cancelled),
                    // Its waker puts it back in the queue when it has more.
                    Poll::Pending => {}
                }
            }
            if let Some(sleep) = sleep.as_mut().as_pin_mut() {
                match sleep.poll(task) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Event::Timer),
                    Poll::Ready(Err(_)) => return Poll::Ready(Event::Cancelled),
                    Poll::Pending => {}
                }
            }
            if cx.register_cancel(task.waker(), &mut self.wait) {
                return Poll::Ready(Event::Cancelled);
            }
            waited = true;
            Poll::Pending
        })
        .await;
        if waited {
            self.run = 0;
        }
        self.run += 1;
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InterfaceExt, block_on, pair, run};

    /// How many 1,500-byte packets fit in 32 MiB, at 64 bytes more each.
    const FIT: usize = (32 << 20) / (1500 + PACKET_COST);

    /// Sends `n` 1,500-byte packets into `inner`'s other end, giving the
    /// link's task turns as it goes.
    async fn flood(cx: &Cx, into: &mut End, n: usize) -> crate::Result {
        for i in 0..n {
            into.send(Packet(vec![0x45; 1500]));
            if i % 32 == 31 {
                cx.yield_now().await?;
            }
        }
        for _ in 0..1000 {
            cx.yield_now().await?;
        }
        Ok(())
    }

    /// Takes every packet that is ready on `end` now.
    async fn drain(cx: &Cx, end: &mut End) -> usize {
        let mut n = 0;
        while let Poll::Ready(Ok(_)) = poll_fn(|t| Poll::Ready(end.poll_recv(cx, t))).await {
            n += 1;
        }
        n
    }

    #[test]
    fn a_delay_drops_what_does_not_fit() {
        block_on(run(|cx| async move {
            let (mut sandbox, inner) = pair();
            let mut far = delay(&cx, Duration::from_secs(1), inner);
            flood(&cx, &mut sandbox, FIT + 500).await?;
            assert_eq!(drain(&cx, &mut far).await, 0, "nothing leaves before the delay");
            cx.sleep(Duration::from_millis(1200)).await?;
            assert_eq!(drain(&cx, &mut far).await, FIT, "the delay kept 32 MiB and dropped the rest");
            // Room again, once the queue has emptied.
            sandbox.send(Packet(vec![1; 100]));
            assert_eq!(far.recv(&cx).await?, Packet(vec![1; 100]));
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn an_unread_bottleneck_output_stops_growing() {
        block_on(run(|cx| async move {
            let (mut sandbox, inner) = pair();
            let mut far = bottleneck(&cx, u64::MAX, 64, inner);
            flood(&cx, &mut sandbox, FIT + 500).await?;
            assert_eq!(drain(&cx, &mut far).await, FIT, "the output kept 32 MiB and dropped the rest");
            Ok(())
        }))
        .unwrap();
    }
}
