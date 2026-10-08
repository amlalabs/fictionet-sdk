use std::collections::{HashSet, VecDeque};
use std::future::poll_fn;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use crate::cable::pair_with_guard;
use crate::cx::CancelWait;
#[cfg(not(target_arch = "wasm32"))]
use crate::listen::SocketLink;
use crate::watch::{Graph, Meter};
use crate::{Cancelled, Cx, End, Interface, Packet, RecvError};

/// One attached sandbox: its name, and the [`Interface`] that carries its
/// packets.
///
/// Whatever the world sends into an `Attachment`, the sandbox receives, and
/// whatever the sandbox sends comes out of it. Every attach type delivers
/// plain IP packets here. A `tun` attachment reads them from a TUN device
/// inside the sandbox. A `tap` attachment takes them out of a virtual
/// machine's Ethernet frames. For an `http_proxy` or `socks5` attachment,
/// `fictionet attach` plays the part of the sandbox's kernel: its own TCP/IP
/// stack turns each proxied connection into packets, so even a proxy client
/// shows up here as packets. The world is not told which attach type it
/// got. [`lowering`](crate::lowering) shows each type's path, and what the
/// world sees from it.
///
/// Dropping an `Attachment` closes it: the sandbox is cut off, and its
/// name is free to attach again.
///
/// When the sandbox detaches, the world reads the packets that already
/// arrived, and then [`recv`](crate::InterfaceExt::recv) returns
/// [`RecvError::Closed`]. Packets sent to it after that are dropped. A
/// detach cancels nothing, so the world's other tasks keep running (see
/// [What ends what](crate::running#what-ends-what)).
pub struct Attachment {
    name: String,
    mtu: u16,
    link: Link,
    /// Counts for the dashboard. Side 0 is the world, side 1 the sandbox.
    meter: Arc<Meter>,
    /// The last task seen polling this attachment.
    seen: u64,
    /// The wraps of [`Attachments::map`] still to run, closest to the
    /// sandbox first. They run when the world takes the attachment.
    wraps: Vec<Wrap>,
}

/// One [`Attachments::map`] call's wrap, waiting to run on an attachment.
type Wrap = Box<dyn FnOnce(Attachment) -> Attachment + Send>;

/// What carries an attachment's packets.
enum Link {
    /// An interface from [`Attacher::attach`].
    Cable(End),
    /// A connection from attach, accepted by [`listen`](crate::listen).
    #[cfg(not(target_arch = "wasm32"))]
    Socket(SocketLink),
    /// What [`Attachments::map`] made from another attachment, and a check
    /// for whether that attachment's sandbox has detached.
    Mapped { interface: Box<dyn Interface>, gone: Arc<dyn Fn() -> bool + Send + Sync> },
}

impl Attachment {
    /// The name given with `fictionet attach --name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The largest IP packet the sandbox accepts, as `fictionet attach`
    /// reported it when it connected. 1500 for an attachment that a test
    /// makes with [`Attacher::attach`].
    ///
    /// The world's TCP learns this from the handshake anyway. UDP and raw
    /// packet code can read it here, and drop or fragment larger packets.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Whether the sandbox is known to have detached already.
    fn detached(&self) -> bool {
        match &self.link {
            Link::Cable(end) => end.peer_gone(),
            #[cfg(not(target_arch = "wasm32"))]
            Link::Socket(link) => link.peer_gone(),
            Link::Mapped { gone, .. } => gone(),
        }
    }

    /// A check for [`detached`](Attachment::detached) that works after the
    /// attachment has moved elsewhere.
    fn detached_check(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        match &self.link {
            Link::Cable(end) => Arc::new(end.peer_gone_check()),
            #[cfg(not(target_arch = "wasm32"))]
            Link::Socket(link) => Arc::new(link.peer_gone_check()),
            Link::Mapped { gone, .. } => gone.clone(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn from_socket(name: String, mtu: u16, link: SocketLink) -> Attachment {
        let meter = Meter::new();
        meter.set_sandbox(&name);
        Attachment { name, mtu, link: Link::Socket(link), meter, seen: 0, wraps: Vec::new() }
    }

    /// Runs the wraps still waiting, in the order they were added. Called
    /// when the world takes the attachment.
    fn unwrap_pending(mut self) -> Attachment {
        let wraps = std::mem::take(&mut self.wraps);
        wraps.into_iter().fold(self, |attachment, wrap| wrap(attachment))
    }

}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment").field("name", &self.name).field("mtu", &self.mtu).finish()
    }
}

impl Interface for Attachment {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        match &mut self.link {
            Link::Cable(end) => end.poll_recv(fcx, cx),
            #[cfg(not(target_arch = "wasm32"))]
            Link::Socket(link) => {
                let current = crate::watch::current_task();
                if current != self.seen && current != 0 {
                    self.seen = current;
                    fcx.graph().owns(&self.meter, 0, current);
                }
                let polled = link.poll_recv(fcx, cx);
                if let Poll::Ready(Ok(packet)) = &polled {
                    self.meter.sent(1, packet);
                }
                polled
            }
            Link::Mapped { interface, .. } => interface.poll_recv(fcx, cx),
        }
    }

    fn send(&mut self, packet: Packet) {
        match &mut self.link {
            Link::Cable(end) => end.send(packet),
            #[cfg(not(target_arch = "wasm32"))]
            Link::Socket(link) => {
                self.meter.sent(0, &packet);
                link.send(packet)
            }
            Link::Mapped { interface, .. } => interface.send(packet),
        }
    }

    fn observe_link(&self) -> Option<crate::observe::LinkHandle> {
        match &self.link {
            Link::Mapped { interface, .. } => interface.observe_link(),
            _ => Some(crate::observe::LinkHandle::new(self.meter.clone())),
        }
    }
}

/// Makes the channel through which sandboxes reach a world.
///
/// It returns two halves. The world gets the [`Attachments`] and takes
/// sandboxes out of it. Whatever adds sandboxes keeps the [`Attacher`]: in
/// a real run, that is [`listen`](crate::listen), which adds each sandbox
/// that `fictionet attach` connects. In a test, the test keeps the
/// `Attacher` and attaches sandboxes itself.
///
/// This test attaches a sandbox called `agent` and holds the sandbox's end
/// of its link, so it can play the sandbox:
///
/// ```
/// # use fictionet::{Attachments, Cx, Result};
/// # async fn world(_fcx: Cx, _attachments: Attachments, _args: Vec<String>) -> Result { Ok(()) }
/// # fn main() -> Result {
/// let (attacher, attachments) = fictionet::attachments();
/// let agent = attacher.attach("agent")?; // the test holds the sandbox's end
/// let world = fictionet::run(|fcx| world(fcx, attachments, vec![]));
/// // send packets on `agent` and check what comes back while `world` runs
/// # drop(agent);
/// # fictionet::block_on(world)
/// # }
/// ```
pub fn attachments() -> (Attacher, Attachments) {
    let hub = Arc::new(Hub::default());
    (Attacher { hub: hub.clone() }, Attachments { hub })
}

/// What an [`Attacher`] and its [`Attachments`] share.
#[derive(Default)]
struct Hub {
    state: Mutex<HubState>,
}

#[derive(Default)]
struct HubState {
    /// Names that are taken.
    names: HashSet<String>,
    /// Attachments not yet handed out, in arrival order.
    pending: VecDeque<Attachment>,
    /// The world waiting in `get` or `next`.
    waker: Option<Waker>,
    /// The task of [`Attachments::map`] that feeds this hub, woken when
    /// the [`Attachments`] is dropped.
    feeder: Option<Waker>,
    /// The [`Attachments`] was dropped.
    closed: bool,
    /// What the run that takes these attachments tracks, so that an
    /// observer that connects to the world socket finds it.
    graph: Weak<Graph>,
}

/// Holds a name. Dropping it frees the name.
pub(crate) struct NameGuard {
    hub: Arc<Hub>,
    name: String,
}

impl Drop for NameGuard {
    fn drop(&mut self) {
        self.hub.state.lock().unwrap().names.remove(&self.name);
    }
}

/// The half of [`attachments`] that adds sandboxes to a world.
///
/// Each sandbox has a name, and two sandboxes cannot be attached under the
/// same name at the same time. Clones of an `Attacher` share one set of
/// names, so a test and a [`listen`](crate::listen) socket can add
/// sandboxes to the same world without clashing.
#[derive(Clone)]
pub struct Attacher {
    hub: Arc<Hub>,
}

impl Attacher {
    /// Attaches a sandbox called `name`, and returns the sandbox's end of
    /// its link. The world gets the other end as an [`Attachment`].
    ///
    /// Fails with [`AttachError::Taken`] if a sandbox with that name is
    /// attached, and with [`AttachError::BadName`] if the name is empty or
    /// longer than 255 bytes. The name stays taken until either end is
    /// dropped. Every attach goes through this check, including those from
    /// [`listen`](crate::listen): when it fails, `fictionet attach` gets a
    /// `refuse` message (see [`proto`](crate::proto)).
    pub fn attach(&self, name: &str) -> Result<End, AttachError> {
        let guard = self.reserve(name)?;
        let (world, sandbox) = pair_with_guard(Some(Box::new(guard)));
        let meter = world.meter().clone();
        meter.set_sandbox(name);
        self.deliver(Attachment {
            name: name.to_owned(),
            mtu: 1500,
            link: Link::Cable(world),
            meter,
            seen: 0,
            wraps: Vec::new(),
        });
        Ok(sandbox)
    }

    /// What the run that takes these attachments tracks, once the world
    /// has asked for one.
    pub(crate) fn graph(&self) -> Option<Arc<Graph>> {
        self.hub.state.lock().unwrap().graph.upgrade()
    }

    /// Takes `name` until the guard is dropped.
    pub(crate) fn reserve(&self, name: &str) -> Result<NameGuard, AttachError> {
        if name.is_empty() || name.len() > 255 {
            return Err(AttachError::BadName);
        }
        let mut state = self.hub.state.lock().unwrap();
        if !state.names.insert(name.to_owned()) {
            return Err(AttachError::Taken);
        }
        Ok(NameGuard { hub: self.hub.clone(), name: name.to_owned() })
    }

    /// Ready once the [`Attachments`] is dropped. Until then, `cx`'s waker is
    /// woken when it is.
    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.hub.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(());
        }
        match &state.feeder {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => state.feeder = Some(cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Hands `attachment` to the world.
    pub(crate) fn deliver(&self, attachment: Attachment) {
        let mut state = self.hub.state.lock().unwrap();
        if state.closed {
            // The world is gone. Dropping the attachment closes it, which
            // takes the lock to free its name.
            drop(state);
            drop(attachment);
            return;
        }
        state.pending.push_back(attachment);
        let waker = state.waker.take();
        drop(state);
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl std::fmt::Debug for Attacher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Attacher")
    }
}

/// Why [`Attacher::attach`] refused a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachError {
    /// A sandbox with this name is attached.
    Taken,
    /// The name is empty or longer than 255 bytes.
    BadName,
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AttachError::Taken => "name is already attached",
            AttachError::BadName => "name must be 1 to 255 bytes",
        })
    }
}

impl std::error::Error for AttachError {}

/// The sandboxes attached to this world, as they arrive.
///
/// Each `fictionet attach --name <name> ...` adds one, through an
/// [`Attacher`]. A sandbox can attach at any time while the world runs, so
/// this is a stream, not a list.
///
/// Each attachment is handed out once: either by [`get`](Attachments::get),
/// which waits for a given name, or by [`next`](Attachments::next), which
/// takes them in arrival order. Both take a `&Cx`, like every other wait.
/// A world that serves every sandbox the same way loops over `next`:
///
/// ```
/// # async fn world(fcx: fictionet::Cx, mut attachments: fictionet::Attachments) -> fictionet::Result {
/// loop {
///     let sandbox = attachments.next(&fcx).await?;
///     // wire `sandbox` into the world
/// #   drop(sandbox);
/// }
/// # }
/// ```
///
/// The loop ends when the world stops: `next` returns [`Cancelled`], and
/// `?` passes it up, which ends the task without failing it.
pub struct Attachments {
    hub: Arc<Hub>,
}

impl Attachments {
    /// Waits for the sandbox called `name` to attach, and returns it.
    ///
    /// Returns immediately if it is already attached and not yet handed
    /// out. A sandbox that detached before it was handed out is skipped, by
    /// `get` and [`next`](Attachments::next) alike, so if a sandbox
    /// detaches and attaches again under the same name, the new one is
    /// returned.
    ///
    /// Returns early with [`Cancelled`] if `fcx`'s [region](Cx#regions) is
    /// cancelled.
    pub async fn get(&mut self, fcx: &Cx, name: &str) -> Result<Attachment, Cancelled> {
        let mut wait = CancelWait::default();
        let found = poll_fn(|cx| self.poll_take(fcx, cx, &mut wait, |a| a.name == name)).await;
        found.map(Attachment::unwrap_pending)
    }

    /// Waits for the next sandbox that has not been handed out yet, in the
    /// order they attached.
    ///
    /// Returns early with [`Cancelled`] if `fcx`'s [region](Cx#regions) is
    /// cancelled.
    pub async fn next(&mut self, fcx: &Cx) -> Result<Attachment, Cancelled> {
        let mut wait = CancelWait::default();
        let found = poll_fn(|cx| self.poll_take(fcx, cx, &mut wait, |_| true)).await;
        found.map(Attachment::unwrap_pending)
    }

    /// Wraps every sandbox that arrives, and returns the wrapped sandboxes
    /// as a new `Attachments`.
    ///
    /// Use it to put something between every sandbox and the code that
    /// serves it, such as a [`delay`](crate::stdlib::delay) in front of
    /// [`web::Sites`](crate::stdlib::web::Sites):
    ///
    /// ```
    /// # use fictionet::{Attachments, Cx, Result, stdlib::{self, web}, time::ms};
    /// # fn site_for(_host: &str) -> Option<web::Site> { None }
    /// # fn world(fcx: Cx, attachments: Attachments) -> Result {
    /// let slow = attachments.map(&fcx, |fcx, sandbox| stdlib::delay(fcx, ms(200), sandbox));
    /// web::Sites::new(site_for).serve(&fcx, slow)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `map` returns immediately. It starts a background task in `fcx`'s
    /// [region](Cx#regions) that takes each sandbox as it attaches and
    /// passes it on to the new `Attachments`. When the world takes a
    /// sandbox from there, with [`get`](Attachments::get) or
    /// [`next`](Attachments::next), `map` calls `wrap` with it and hands
    /// what `wrap` returns to the world, as an [`Attachment`] with the same
    /// [`name`](Attachment::name) and [`mtu`](Attachment::mtu). `wrap` gets
    /// the `Cx` of `map`'s task, so the tasks it starts belong to `fcx`'s
    /// region. It can look at the sandbox's name to treat sandboxes
    /// differently. Calls to `map` can be chained, and the first one's
    /// `wrap` is closest to the sandbox.
    ///
    /// `wrap` waits for the world on purpose. A function such as
    /// [`filter`](crate::stdlib::filter) reads the sandbox's packets as fast
    /// as they come, and queues them for the interface it returns. If it
    /// started before the world took that interface, nothing would read the
    /// queue, and an agent that keeps sending would grow the world's memory
    /// without limit. Until the world takes the sandbox, its packets wait
    /// where an untouched attachment keeps them: in the socket from
    /// `fictionet attach`, whose buffer has a fixed size. Once the world
    /// has taken the sandbox, read what `wrap` returned, or drop it: like
    /// every interface from [`pair`](crate::pair), its queue has no size
    /// limit.
    ///
    /// Whatever `wrap` returns stands for the sandbox from then on.
    /// Dropping the new attachment drops that interface, and a stdlib
    /// function such as `delay` then stops and drops the sandbox's own
    /// attachment, which cuts the sandbox off. A sandbox that detaches
    /// before the world takes it from the new `Attachments` is skipped, as
    /// usual, and `wrap` is never called for it. After the world has taken
    /// it, a detach reaches the world through the wrapped interface: a
    /// `filter` passes on every packet that arrived before the detach, but
    /// a `delay` or a `bottleneck` stops immediately, and the packets it still
    /// holds are lost.
    ///
    /// The task stops when the region is cancelled, or when the returned
    /// `Attachments` is dropped. Either way, it drops `self`, so sandboxes
    /// that attach after that are turned away.
    pub fn map<F, I>(mut self, fcx: &Cx, wrap: F) -> Attachments
    where
        F: FnMut(&Cx, Attachment) -> I + Send + 'static,
        I: Interface,
    {
        let hub = Arc::new(Hub::default());
        let out = Attacher { hub: hub.clone() };
        let wrap = Arc::new(Mutex::new(wrap));
        fcx.spawn(move |fcx| async move {
            let mut wait = CancelWait::default();
            loop {
                let next = poll_fn(|cx| {
                    if out.poll_closed(cx).is_ready() {
                        return Poll::Ready(None);
                    }
                    self.poll_take(&fcx, cx, &mut wait, |_| true).map(Some)
                })
                .await;
                // `None`: the new `Attachments` was dropped. A cancel ends
                // the task with `Cancelled`.
                let Some(next) = next else { return Ok(()) };
                let mut sandbox = next?;
                // `wrap` runs only when the world takes the sandbox. What it
                // returns may read the sandbox's packets at once, as a
                // `filter` does, and before the world takes the sandbox
                // nothing would read them in turn: the agent could fill the
                // world's memory. Until then, the packets stay where the
                // sandbox's own attachment keeps them.
                let (wrap, fcx) = (wrap.clone(), fcx.clone());
                sandbox.wraps.push(Box::new(move |sandbox: Attachment| {
                    let (name, mtu, gone) = (sandbox.name.clone(), sandbox.mtu, sandbox.detached_check());
                    let interface = Box::new((wrap.lock().unwrap_or_else(|e| e.into_inner()))(&fcx, sandbox));
                    // The wrapped interface counts its own packets, so this
                    // meter stays unused: `observe_link` hands out the
                    // interface's.
                    let link = Link::Mapped { interface, gone };
                    Attachment { name, mtu, link, meter: Meter::new(), seen: 0, wraps: Vec::new() }
                }));
                out.deliver(sandbox);
            }
        });
        Attachments { hub }
    }

    /// Takes the first pending attachment that `wanted` picks.
    fn poll_take(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        wait: &mut CancelWait,
        wanted: impl Fn(&Attachment) -> bool,
    ) -> Poll<Result<Attachment, Cancelled>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(Cancelled));
        }
        let mut gone = VecDeque::new();
        {
            let mut state = self.hub.state.lock().unwrap();
            if !std::ptr::eq(state.graph.as_ptr(), Arc::as_ptr(fcx.graph())) {
                state.graph = Arc::downgrade(fcx.graph());
            }
            if state.pending.iter().any(Attachment::detached) {
                let (dead, live) = std::mem::take(&mut state.pending).into_iter().partition(Attachment::detached);
                state.pending = live;
                gone = dead;
            }
            if let Some(found) = state.pending.iter().position(&wanted).and_then(|i| state.pending.remove(i)) {
                drop(state);
                drop(gone);
                return Poll::Ready(Ok(found));
            }
            match &state.waker {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => state.waker = Some(cx.waker().clone()),
            }
        }
        // Dropped outside the lock: closing them frees their names, which
        // takes the lock.
        drop(gone);
        if fcx.register_cancel(cx.waker(), wait) {
            return Poll::Ready(Err(Cancelled));
        }
        Poll::Pending
    }
}

impl Drop for Attachments {
    fn drop(&mut self) {
        let (pending, feeder) = {
            let mut state = self.hub.state.lock().unwrap();
            state.closed = true;
            state.waker = None;
            (std::mem::take(&mut state.pending), state.feeder.take())
        };
        drop(pending);
        if let Some(w) = feeder {
            w.wake();
        }
    }
}
