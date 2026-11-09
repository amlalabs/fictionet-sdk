//! UDP: sockets for a machine on the simulated network.
//!
//! [`UdpLayer`] is a machine's UDP as a [layer]: whole IP packets below,
//! from the [IP layer](super::packet::IpLayer), and one child per bound
//! socket above, carrying datagrams with the peer's address ([`Udp`]). It
//! owns the sockets, their queues, the choice of ephemeral ports, multicast
//! membership and the answers to datagrams for closed ports.
//!
//! Use this module to give a machine UDP, for example to run a DNS server
//! (see [`dns`](fictionet::stdlib::protocols::dns)). [`endpoint`] takes an [`Interface`]
//! that carries the machine's UDP packets, and the machine's address. It returns an [`Endpoint`], on which you
//! [`bind`](Endpoint::bind) a [`Socket`] for each port. A socket receives
//! datagrams with [`recv`](Socket::recv) and sends them with
//! [`send_to`](Socket::send_to). The endpoint runs the IP layer and a
//! [`UdpLayer`] over the interface, and its sockets are that layer's
//! children.
//!
//! [`prepare_endpoint`] builds the same endpoint without starting a task,
//! so sockets can be bound before [`Prepared::start`]. Drop the driver and
//! its handles to discard the preparation.
//!
//! The interface comes from [`ip::split_protocols`](super::ip::split_protocols),
//! which splits a machine's packets so that only UDP, and ICMP errors
//! about it, reach this layer.
//! The [`ip`](super::ip) page shows a whole machine.
//!
//! [`Datagram`] borrows a complete UDP datagram from an IP payload.
//! [`Datagram::parse`] checks its length; [`Datagram::checksum_ok`] checks
//! its checksum separately. [`encode`] writes into a caller-owned buffer,
//! sized with [`encoded_len`]. Neither operation allocates or reassembles
//! fragments. The caller owns MTU and IP header policy.
//!
//! ```
//! use fictionet::stdlib::network::udp::{self, Datagram};
//! let src = "192.0.2.1:1000".parse().unwrap();
//! let dst = "192.0.2.2:53".parse().unwrap();
//! let mut bytes = [0; 32];
//! let len = udp::encode(src, dst, b"query", &mut bytes)?;
//! let datagram = Datagram::parse(&bytes[..len]).unwrap();
//! assert_eq!(datagram.payload(), b"query");
//! assert!(datagram.checksum_ok(src.ip(), dst.ip()));
//! # Ok::<(), udp::Error>(())
//! ```

mod sockets;
mod wire;
pub use sockets::{Dropped, Overrun, UdpLayer, UdpReport};
pub use wire::{Datagram, Error, encode, encoded_len};

use fictionet::sync::Mutex;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Poll, Waker};

use fictionet::CancelWait;
use fictionet::stdlib::layer::{
    self, Admit, Budget, Child, ChildId, Chunk, DatagramCommand, DatagramEvent, Driver,
    MessageCommand, MessageEvent, MuxCommand, MuxEvent, PacketCommand, PacketEvent,
};
use fictionet::stdlib::network::icmp;

use fictionet::stdlib::network::packet::{IpPacket, Scope};
use fictionet::stdlib::network::transport::{Request, Udp, UdpControl, UdpNotice};
use fictionet::{Cx, Interface, RecvError};

/// Choices for a machine's UDP that a world passes in with
/// [`Endpoint::settings`]. The default is what the standards say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// What a datagram to destination port 0 gets.
    pub port_zero: PortZero,
}

/// What a datagram to destination port 0 gets: [`Settings::port_zero`]. No
/// socket is ever bound there, since [`Endpoint::bind`] takes 0 to mean a
/// free port, so the choice is between the answer any other port with no
/// socket gets and none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PortZero {
    /// ICMP port unreachable, as for any other port with no socket
    /// (RFC 1122 section 4.1.3.1). The default.
    #[default]
    Unreachable,
    /// Nothing. The datagram is dropped.
    Silent,
}

/// Starts UDP for a machine with address `addr`, on the UDP packets of
/// `inner`.
///
/// Starts a background task and returns immediately with an [`Endpoint`].
/// The task hands each packet of `inner` to the IP layer and a
/// [`UdpLayer`], which take UDP packets sent to `addr`, and to the
/// multicast groups the endpoint [joined](Endpoint::join), and drop the
/// rest. A packet for `addr` and a port with no socket gets an ICMP "port
/// unreachable" reply, because that is part of UDP's job;
/// [`Settings::port_zero`] can make port 0 silent. Everything it sends goes
/// into `inner`. The [`UdpLayer`] page says which datagrams are dropped.
///
/// The task stops when the caller's [region](fictionet::Cx#regions) is
/// cancelled or `inner` closes. The endpoint's sockets then return
/// [`RecvError::Closed`] once their queued datagrams have been received.
///
/// A socket holds at most 1 MiB of datagrams it has not received yet,
/// counting 64 bytes more for each datagram. Further datagrams are dropped,
/// as with a full socket buffer. These queues are the endpoint's own
/// storage, bounded by those limits rather than by a budget: a stack
/// served on a socket ([`stack::datagrams`]) charges what it retains to the
/// budget it is given. ICMP messages that reach this layer, such as errors
/// about datagrams it sent, are dropped.
///
/// [`stack::datagrams`]: fictionet::stdlib::services::stack::datagrams
#[track_caller]
pub fn endpoint(fcx: &Cx, inner: impl Interface, addr: IpAddr) -> Endpoint {
    let (endpoint, task) = prepare_endpoint(fcx, inner, addr);
    task.start(fcx);
    endpoint
}

/// A UDP endpoint's driver, ready to start with its task name.
/// Dropping it discards the driver without starting a task.
pub struct Prepared<F> {
    task: F,
}

impl<F: Future<Output = fictionet::Result> + Send + 'static> Prepared<F> {
    /// Starts the endpoint in the context used to prepare it.
    #[track_caller]
    pub fn start(self, fcx: &Cx) {
        fcx.spawn(move |_| self.task);
    }
}

/// Builds a UDP endpoint and its driver without starting a task.
/// Sockets can be bound before the driver starts. Call [`Prepared::start`]
/// with `fcx` to run the endpoint, or drop the driver and all its handles to
/// discard the preparation. Uses `fcx` for randomness.
pub fn prepare_endpoint(
    fcx: &Cx,
    inner: impl Interface,
    addr: IpAddr,
) -> (
    Endpoint,
    Prepared<impl Future<Output = fictionet::Result> + Send + 'static>,
) {
    let (endpoint, udp) = prepare_transport(fcx, addr);
    let ip = super::packet::Factory::default().build(super::packet::Opening {
        cx: fcx.clone(),
        addr,
        budget: Budget::unlimited(),
    });
    let task = super::endpoint::drive(fcx.clone(), inner, None, Some(udp), None, ip);
    (endpoint, Prepared { task })
}

pub(crate) fn prepare_transport(fcx: &Cx, addr: IpAddr) -> (Endpoint, PacketDriver) {
    let mut driver = Driver::new(
        UdpLayer::new(Scope::ROOT, addr, fcx),
        Arc::new(fcx.clone()),
        Budget::unlimited(),
        fcx.now(),
    );
    driver.keep_observations(0);
    let shared = Arc::new(Shared {
        addr,
        inner: Mutex::new(Inner {
            driver,
            output: Vec::new(),
            wake: None,
            sockets: BTreeMap::new(),
            ports: BTreeMap::new(),
            next_request: 0,
            answers: Vec::new(),
            refused: Vec::new(),
            observe: None,
            stopped: false,
        }),
    });
    (
        Endpoint {
            shared: shared.clone(),
        },
        PacketDriver {
            shared,
            fcx: fcx.clone(),
        },
    )
}

pub(crate) struct PacketDriver {
    shared: Arc<Shared>,
    fcx: Cx,
}

impl PacketDriver {
    pub(crate) fn deliver(&mut self, packet: IpPacket) {
        self.shared.with(|inner| {
            inner.driver.set_now(self.fcx.now());
            inner.offer(PacketEvent::Packet(packet));
        });
    }

    pub(crate) fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        out: &mut Vec<Vec<u8>>,
    ) -> (bool, Option<fictionet::time::Instant>) {
        self.shared.with(|inner| {
            inner.wake = Some(cx.waker().clone());
            inner.driver.set_now(self.fcx.now());
            inner.pump();
            out.append(&mut inner.output);
            (inner.driver.exhausted(), inner.driver.deadline())
        })
    }
}

impl Drop for PacketDriver {
    fn drop(&mut self) {
        self.shared.with(Inner::stop);
    }
}

struct Shared {
    addr: IpAddr,
    inner: Mutex<Inner>,
}

struct Inner {
    driver: Driver<UdpLayer>,
    output: Vec<Vec<u8>>,
    wake: Option<Waker>,
    /// The sockets by port.
    sockets: BTreeMap<u16, Mailbox>,
    /// The ports of the sockets by child.
    ports: BTreeMap<ChildId, u16>,
    next_request: u64,
    /// What came up about binds and joins since the last one began.
    answers: Vec<Answer>,
    /// Refused datagrams to report once the lock is released.
    refused: Vec<(SocketAddr, SocketAddr)>,
    observe: Option<Arc<dyn Fn(SocketAddr, SocketAddr) + Send + Sync>>,
    stopped: bool,
}

/// What came up about a bind or a join.
enum Answer {
    Bound(Request, u16),
    BindFailed(Request),
    JoinFailed(IpAddr),
}

/// One socket's side of the endpoint: its child, and at most one datagram
/// the UDP layer has handed up for it.
struct Mailbox {
    child: Child,
    datagram: Option<(Vec<u8>, SocketAddr)>,
    /// Whether one unit of credit is granted and not yet used.
    asked: bool,
    /// The credit the UDP layer granted for this socket's datagrams.
    credit: u64,
    /// The UDP layer said the socket ended.
    ended: bool,
    /// Something came for the reader since it last looked.
    notify: bool,
    waker: Option<Waker>,
}

impl Shared {
    /// Runs `f` on the endpoint, then, with the lock released, wakes the
    /// readers it gave something to, in port order, and reports refused
    /// datagrams.
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let (result, wakers, refused, observe) = {
            let mut inner = self.inner.lock();
            let result = f(&mut inner);
            let mut wakers = Vec::new();
            for mailbox in inner.sockets.values_mut() {
                if std::mem::take(&mut mailbox.notify)
                    && let Some(waker) = mailbox.waker.take()
                {
                    wakers.push(waker);
                }
            }
            let refused = std::mem::take(&mut inner.refused);
            (result, wakers, refused, inner.observe.clone())
        };
        for waker in wakers {
            waker.wake();
        }
        if let Some(observe) = observe {
            for (peer, local) in refused {
                observe(peer, local);
            }
        }
        result
    }
}

impl Inner {
    /// Offers the stack an event from the interface, making room once if
    /// it refuses. An event it still refuses is lost, as a packet on a
    /// full link is.
    fn offer(&mut self, event: PacketEvent<IpPacket>) {
        let event = match self
            .driver
            .deliver(event)
            .expect("the IP layer never fails")
        {
            Admit::Blocked(event) => event,
            Admit::Taken | Admit::Closed(_) | Admit::Partial(_) => return self.pump(),
        };
        self.pump();
        let _ = self.driver.deliver(event);
        self.pump();
    }

    /// Gives the UDP layer a command from above, making room once if it
    /// refuses. It refuses only while it holds output, and the pump takes
    /// all of it.
    fn command(&mut self, command: MuxCommand<layer::Datagrams<SocketAddr>, Control>) {
        if let Admit::Blocked(command) = self.driver.command(command).expect("credit is kept") {
            self.pump();
            let _ = self.driver.command(command).expect("credit is kept");
        }
        self.pump();
    }

    /// Moves everything the stack has: packets into the interface, events
    /// to the sockets.
    fn pump(&mut self) {
        let Inner {
            driver,
            output,
            wake,
            sockets,
            ports,
            answers,
            refused,
            ..
        } = self;
        loop {
            let mut moved = driver.run().expect("credit is kept");
            moved |= driver.send_below(|command| {
                if output.len() == 64 {
                    return Admit::Blocked(command);
                }
                if let PacketCommand::Send(bytes) = command {
                    output.push(bytes.into_vec());
                    if let Some(waker) = wake.take() {
                        waker.wake();
                    }
                }
                Admit::Taken
            });
            moved |= driver.send_above(|event| {
                route(event, sockets, ports, answers, refused);
                Admit::Taken
            });
            if !moved && !driver.exhausted() {
                return;
            }
        }
    }

    /// Ends the stack's input, as the interface has, so each socket ends
    /// after the datagrams it holds, and wakes every reader.
    fn stop(&mut self) {
        self.stopped = true;
        self.offer(PacketEvent::Ended);
        for mailbox in self.sockets.values_mut() {
            mailbox.notify = true;
        }
    }
}

/// The control port of the UDP layer.
type Control = layer::Messages<UdpNotice, UdpControl>;

/// Takes one event from the UDP layer.
fn route(
    event: layer::EventOf<Udp>,
    sockets: &mut BTreeMap<u16, Mailbox>,
    ports: &mut BTreeMap<ChildId, u16>,
    answers: &mut Vec<Answer>,
    refused: &mut Vec<(SocketAddr, SocketAddr)>,
) {
    fn mailbox<'a>(
        sockets: &'a mut BTreeMap<u16, Mailbox>,
        ports: &BTreeMap<ChildId, u16>,
        id: ChildId,
    ) -> Option<&'a mut Mailbox> {
        ports.get(&id).and_then(|port| sockets.get_mut(port))
    }
    match event {
        MuxEvent::Opened(child, bound, _) => {
            let port = bound.local.port();
            answers.push(Answer::Bound(bound.request, port));
            ports.insert(child.id(), port);
            sockets.insert(
                port,
                Mailbox {
                    child,
                    datagram: None,
                    asked: false,
                    credit: 0,
                    ended: false,
                    notify: false,
                    waker: None,
                },
            );
        }
        MuxEvent::Child(id, DatagramEvent::Datagram(datagram)) => {
            if let Some(mailbox) = mailbox(sockets, ports, id) {
                let (payload, from) = datagram.into_parts();
                mailbox.datagram = Some((payload.into_vec(), from));
                mailbox.asked = false;
                mailbox.notify = true;
            }
        }
        MuxEvent::Child(id, DatagramEvent::Ended) => {
            if let Some(mailbox) = mailbox(sockets, ports, id) {
                mailbox.ended = true;
                mailbox.notify = true;
            }
        }
        MuxEvent::Credit(id, units) => {
            if let Some(mailbox) = mailbox(sockets, ports, id) {
                mailbox.credit += units;
            }
        }
        MuxEvent::Closed(id) => {
            if let Some(port) = ports.remove(&id) {
                sockets.remove(&port);
            }
        }
        MuxEvent::Control(MessageEvent::Message(notice)) => match notice {
            UdpNotice::Refused { peer, local } => refused.push((peer, local)),
            UdpNotice::BindFailed { request, .. } => answers.push(Answer::BindFailed(request)),
            UdpNotice::JoinFailed(group) => answers.push(Answer::JoinFailed(group)),
        },
        MuxEvent::Control(MessageEvent::Ended) => {}
    }
}

/// One machine's UDP, made by [`endpoint`].
///
/// An `Endpoint` is a handle to the endpoint's task. Clones share the same
/// machine.
#[derive(Clone)]
pub struct Endpoint {
    shared: Arc<Shared>,
}

impl Endpoint {
    pub(crate) fn on_refused(&self, observe: Arc<dyn Fn(SocketAddr, SocketAddr) + Send + Sync>) {
        let previous = self.shared.inner.lock().observe.replace(observe);
        drop(previous);
    }

    /// Sets the header choices for this endpoint's ICMP errors.
    pub fn icmp_options(&self, options: icmp::Options) {
        let mut inner = self.shared.inner.lock();
        inner.driver.layer_mut().set_icmp_options(options);
    }

    /// Sets the choices a world makes for this endpoint's UDP.
    pub fn settings(&self, settings: Settings) {
        let mut inner = self.shared.inner.lock();
        inner.driver.layer_mut().set_settings(settings);
    }

    /// Joins the multicast group `group`: datagrams sent to it reach this
    /// endpoint's sockets on their ports, as datagrams to its own address
    /// do. Delivering them is the network's job: a
    /// [`route::lan`](fictionet::stdlib::network::route::lan) floods multicast to every
    /// member.
    ///
    /// Fails if `group` is not a multicast address of the endpoint's family.
    pub fn join(&self, group: IpAddr) -> Result<(), fictionet::Error> {
        let failed = self.shared.with(|inner| {
            inner.answers.clear();
            inner.command(MuxCommand::control(MessageCommand::Send(UdpControl::Join(
                group,
            ))));
            inner
                .answers
                .iter()
                .any(|answer| matches!(answer, Answer::JoinFailed(g) if *g == group))
        });
        if failed {
            return Err(fictionet::Error::msg(format!(
                "{group} is not a multicast group {} can join",
                self.shared.addr
            )));
        }
        Ok(())
    }

    /// Leaves the multicast group `group`.
    pub fn leave(&self, group: IpAddr) {
        self.shared.with(|inner| {
            inner.command(MuxCommand::control(MessageCommand::Send(
                UdpControl::Leave(group),
            )));
        });
    }

    /// Whether a socket is open on `port`.
    pub fn is_bound(&self, port: u16) -> bool {
        let inner = self.shared.inner.lock();
        inner.driver.layer().is_bound(port)
    }

    /// Opens a socket on `port`.
    ///
    /// Port zero selects a free port from 49152 through 65535. Fails if
    /// that range is full or the requested port is already open. Dropping
    /// the socket frees the port.
    pub fn bind(&self, port: u16) -> Result<Socket, fictionet::Error> {
        let bound = self.shared.with(|inner| {
            inner.answers.clear();
            let request = Request(inner.next_request);
            inner.next_request += 1;
            inner.command(MuxCommand::control(MessageCommand::Send(
                UdpControl::Bind { request, port },
            )));
            inner.answers.iter().find_map(|answer| match answer {
                Answer::Bound(r, port) if *r == request => Some(Ok(*port)),
                Answer::BindFailed(r) if *r == request => Some(Err(())),
                _ => None,
            })
        });
        match bound.expect("a bind is answered at once") {
            Ok(port) => Ok(Socket {
                shared: self.shared.clone(),
                port,
                wait: CancelWait::default(),
            }),
            Err(()) if port == 0 => Err(fictionet::Error::msg("all ephemeral UDP ports are bound")),
            Err(()) => Err(fictionet::Error::msg(format!(
                "UDP port {port} is already bound on {}",
                self.shared.addr
            ))),
        }
    }
}

/// A UDP socket on one port: one child of the endpoint's [`UdpLayer`].
pub struct Socket {
    shared: Arc<Shared>,
    port: u16,
    wait: CancelWait,
}

impl fictionet::stdlib::network::DatagramSocket for Socket {
    async fn recv(&mut self, fcx: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
        Socket::recv(self, fcx).await
    }

    fn send_to(&mut self, data: &[u8], to: SocketAddr) {
        Socket::send_to(self, data, to);
    }
}

impl Socket {
    /// The address and port this socket receives on.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.shared.addr, self.port)
    }

    /// Waits for the next datagram. Returns its bytes and who sent it.
    ///
    /// Returns early with [`RecvError::Cancelled`] if `fcx`'s
    /// [region](fictionet::Cx#regions) is cancelled, and fails with
    /// [`RecvError::Closed`] once the endpoint has stopped and every
    /// datagram already queued for this socket has been received.
    pub async fn recv(&mut self, fcx: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
        let port = self.port;
        let shared = &self.shared;
        let wait = &mut self.wait;
        poll_fn(|cx| {
            if fcx.is_cancelled() {
                return Poll::Ready(Err(RecvError::Cancelled));
            }
            let got = shared.with(|inner| {
                if let Some(got) = inner.take(port) {
                    return Some(got);
                }
                // Ask the UDP layer for one datagram, which it hands up at
                // once if it holds one.
                let mailbox = inner.mailbox(port);
                if !mailbox.asked {
                    mailbox.asked = true;
                    let grant = mailbox.child.grant(1);
                    inner.command(grant);
                    if let Some(got) = inner.take(port) {
                        return Some(got);
                    }
                }
                let mailbox = inner.mailbox(port);
                let old = match &mailbox.waker {
                    Some(w) if w.will_wake(cx.waker()) => None,
                    _ => mailbox.waker.replace(cx.waker().clone()),
                };
                drop(old);
                None
            });
            if let Some(got) = got {
                return Poll::Ready(got);
            }
            if fcx.register_cancel(cx.waker(), wait) {
                return Poll::Ready(Err(RecvError::Cancelled));
            }
            Poll::Pending
        })
        .await
    }

    /// Sends `data` to `to`.
    ///
    /// Never waits, like [`Interface::send`]. If it cannot be delivered, it
    /// is lost, as UDP datagrams are. A datagram to an address of the other
    /// IP version than the endpoint's, or one too long for a single IP
    /// packet, is lost too. Datagrams are never split into fragments.
    pub fn send_to(&mut self, data: &[u8], to: SocketAddr) {
        let port = self.port;
        self.shared.with(|inner| {
            if inner.stopped {
                return;
            }
            // Every packet the stack made has gone into the interface, so
            // the UDP layer has given the socket's credit back.
            let mailbox = inner.mailbox(port);
            let Some(credit) = mailbox.credit.checked_sub(1) else {
                return;
            };
            mailbox.credit = credit;
            let datagram = layer::Datagram::new(Chunk::new(data.to_vec()), to);
            let send = mailbox.child.send(DatagramCommand::Send(datagram));
            inner.command(send);
        });
    }
}

impl Inner {
    /// The mailbox of the socket bound on `port`.
    fn mailbox(&mut self, port: u16) -> &mut Mailbox {
        self.sockets
            .get_mut(&port)
            .expect("a bound socket has a mailbox")
    }

    /// What a reader on `port` gets now, if anything: a datagram, or the
    /// end once the UDP layer has handed up the last one.
    fn take(&mut self, port: u16) -> Option<Result<(Vec<u8>, SocketAddr), RecvError>> {
        let mailbox = self.mailbox(port);
        if let Some(datagram) = mailbox.datagram.take() {
            return Some(Ok(datagram));
        }
        mailbox.ended.then_some(Err(RecvError::Closed))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let port = self.port;
        self.shared.with(|inner| {
            if let Some(mailbox) = inner.sockets.remove(&port) {
                inner.ports.remove(&mailbox.child.id());
                inner.command(mailbox.child.close());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::sockets::{DATAGRAM_COST, QUEUE};
    use super::*;
    use fictionet::InterfaceExt;
    use fictionet::Packet;
    use fictionet::stdlib::network::ip::{self, protocol};
    use fictionet::{block_on, pair, run};

    #[test]
    fn shutdown_wakes_readers_in_port_order() {
        struct WakeLog(u16, Arc<Mutex<Vec<u16>>>);
        impl std::task::Wake for WakeLog {
            fn wake(self: Arc<Self>) {
                self.1.lock().push(self.0);
            }
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let inside = log.clone();
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let keep = sockets.clone();
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (_raw, side) = pair();
            let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            for port in [9000, 53, 443, 22, 8080] {
                keep.lock().push(ep.bind(port)?);
                ep.shared.inner.lock().sockets.get_mut(&port).unwrap().waker =
                    Some(Waker::from(Arc::new(WakeLog(port, inside.clone()))));
            }
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
        assert_eq!(*log.lock(), [22, 53, 443, 8080, 9000]);
    }

    /// A UDP datagram from 10.0.0.2 to port 53 of 10.0.0.1, with a good
    /// checksum.
    fn datagram(data: &[u8]) -> Packet {
        let (src, dst): (IpAddr, IpAddr) =
            ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        let mut u = [
            &[0, 9, 0, 53][..],
            &((8 + data.len()) as u16).to_be_bytes(),
            &[0, 0],
            data,
        ]
        .concat();
        let sum = ip::transport_checksum(src, dst, protocol::UDP, &u);
        u[6..8].copy_from_slice(&sum.to_be_bytes());
        ip::packet(src, dst, protocol::UDP, &u)
    }

    #[test]
    fn closed_port_observations_follow_validation_and_release_the_lock() {
        block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let (mut raw, side) = pair();
                let endpoint = endpoint(&fcx, side, "10.0.0.1".parse()?);
                let shared = Arc::downgrade(&endpoint.shared);
                let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let count = observed.clone();
                endpoint.on_refused(Arc::new(move |_, _| {
                    assert!(shared.upgrade().unwrap().inner.try_lock().is_some());
                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }));
                let valid = datagram(b"query");
                let mut invalid = valid.clone();
                *invalid.0.last_mut().unwrap() ^= 1;
                raw.send(invalid);
                raw.send(valid);
                raw.recv(&fcx).await?;
                assert_eq!(observed.load(std::sync::atomic::Ordering::Relaxed), 1);
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A socket's queue is bounded by bytes, not by datagrams: before, it
    /// held 1,024 of any size, 64 MiB of the largest.
    #[test]
    fn a_socket_holds_at_most_its_queue_in_bytes() {
        let result = block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (mut raw, side) = pair();
            let mut socket = endpoint(&fcx, side, "10.0.0.1".parse().unwrap()).bind(53)?;
            let big = vec![7; 60_000];
            for _ in 0..40 {
                raw.send(datagram(&big));
            }
            fcx.sleep(fictionet::time::ms(10)).await?;
            let fits = QUEUE / (big.len() + DATAGRAM_COST);
            for _ in 0..fits {
                assert_eq!(socket.recv(&fcx).await?.0.len(), big.len());
            }
            // The rest were dropped, and the room is there again.
            raw.send(datagram(b"after"));
            assert_eq!(socket.recv(&fcx).await?.0, b"after");
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}
