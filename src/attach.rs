use fictionet::sync::Mutex;
use std::collections::{HashSet, VecDeque};
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::cable::pair_with_guard;
use crate::cx::CancelWait;
#[cfg(not(target_arch = "wasm32"))]
use crate::listen::SocketLink;
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
/// got. [`lowering`](crate::guide::lowering) shows each type's path, and what the
/// world sees from it.
///
/// Dropping an `Attachment` closes it: the sandbox is cut off, and its
/// name is free to attach again.
///
/// When the sandbox detaches, the world reads the packets that already
/// arrived, and then [`recv`](crate::InterfaceExt::recv) returns
/// [`RecvError::Closed`]. Packets sent to it after that are dropped. A
/// detach cancels nothing, so the world's other tasks keep running (see
/// [What ends what](crate::guide::running#what-ends-what)).
pub struct Attachment {
    name: Arc<str>,
    mtu: u16,
    link: Link,
}

/// What carries an attachment's packets.
enum Link {
    /// An interface from [`Attacher::attach`].
    Cable(End),
    /// A connection from attach, accepted by [`listen`](crate::listen).
    #[cfg(not(target_arch = "wasm32"))]
    Socket(SocketLink),
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
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn from_socket(name: String, mtu: u16, link: SocketLink) -> Attachment {
        let name: Arc<str> = name.into();
        Attachment {
            name,
            mtu,
            link: Link::Socket(link),
        }
    }
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl Interface for Attachment {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        match &mut self.link {
            Link::Cable(end) => end.poll_recv(fcx, cx),
            #[cfg(not(target_arch = "wasm32"))]
            Link::Socket(link) => link.poll_recv(fcx, cx),
        }
    }

    fn send(&mut self, packet: Packet) {
        match &mut self.link {
            Link::Cable(end) => end.send(packet),
            #[cfg(not(target_arch = "wasm32"))]
            Link::Socket(link) => link.send(packet),
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
/// # async fn world(_fcx: Cx, _attachments: Attachments) -> Result { Ok(()) }
/// # fn main() -> Result {
/// let (attacher, attachments) = fictionet::attachments();
/// let agent = attacher.attach("agent")?; // the test holds the sandbox's end
/// let world = fictionet::run(fictionet::Seed::random(), |fcx| world(fcx, attachments));
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

impl Hub {
    /// Reclaims attachments whose sandboxes have detached.
    fn reclaim_detached(&self) {
        let gone = self.state.lock().take_detached();
        drop(gone);
    }
}

#[derive(Default)]
struct HubState {
    /// Names that are taken.
    names: HashSet<String>,
    /// Attachments not yet handed out, in arrival order.
    pending: VecDeque<Attachment>,
    /// The world waiting in `get` or `next`.
    waker: Option<Waker>,
    /// The [`Attachments`] was dropped.
    closed: bool,
}

impl HubState {
    /// Removes detached attachments without dropping them under the lock.
    fn take_detached(&mut self) -> VecDeque<Attachment> {
        if !self.pending.iter().any(Attachment::detached) {
            return VecDeque::new();
        }
        let (gone, live) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(Attachment::detached);
        self.pending = live;
        gone
    }
}

/// Holds a name. Dropping it frees the name.
pub(crate) struct NameGuard {
    hub: Arc<Hub>,
    name: String,
}

impl Drop for NameGuard {
    fn drop(&mut self) {
        self.hub.state.lock().names.remove(&self.name);
        self.hub.reclaim_detached();
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
    /// `refuse` message (see [`proto`](crate::guide::proto)).
    pub fn attach(&self, name: &str) -> Result<End, AttachError> {
        let guard = self.reserve(name)?;
        let (world, sandbox) = pair_with_guard(Some(Box::new(guard)));
        let name: Arc<str> = name.into();
        self.deliver(Attachment {
            name,
            mtu: 1500,
            link: Link::Cable(world),
        });
        Ok(sandbox)
    }

    /// Takes `name` until the guard is dropped.
    pub(crate) fn reserve(&self, name: &str) -> Result<NameGuard, AttachError> {
        if name.is_empty() || name.len() > 255 {
            return Err(AttachError::BadName);
        }
        let mut state = self.hub.state.lock();
        if !state.names.insert(name.to_owned()) {
            return Err(AttachError::Taken);
        }
        Ok(NameGuard {
            hub: self.hub.clone(),
            name: name.to_owned(),
        })
    }

    /// Hands `attachment` to the world.
    pub(crate) fn deliver(&self, attachment: Attachment) {
        let mut state = self.hub.state.lock();
        if state.closed {
            // The world is gone. Dropping the attachment closes it, which
            // takes the lock to free its name.
            drop(state);
            drop(attachment);
            return;
        }
        state.pending.push_back(attachment);
        // A detach can race with delivery, while an attachment is passed on.
        let gone = state.take_detached();
        let waker = state.waker.take();
        drop(state);
        drop(gone);
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
///
/// A sandbox that detaches before the world takes it is discarded, along
/// with its queued packets. Its resources are reclaimed even if the world
/// is not polling this stream.
/// Attachments already taken by the world are left for it to drain or drop.
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
        poll_fn(|cx| self.poll_take(fcx, cx, &mut wait, |a| a.name() == name)).await
    }

    /// Waits for the next sandbox that has not been handed out yet, in the
    /// order they attached.
    ///
    /// Returns early with [`Cancelled`] if `fcx`'s [region](Cx#regions) is
    /// cancelled.
    pub async fn next(&mut self, fcx: &Cx) -> Result<Attachment, Cancelled> {
        let mut wait = CancelWait::default();
        poll_fn(|cx| self.poll_take(fcx, cx, &mut wait, |_| true)).await
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
        let gone;
        {
            let mut state = self.hub.state.lock();
            gone = state.take_detached();
            if let Some(found) = state
                .pending
                .iter()
                .position(&wanted)
                .and_then(|i| state.pending.remove(i))
            {
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
        let pending = {
            let mut state = self.hub.state.lock();
            state.closed = true;
            state.waker = None;
            std::mem::take(&mut state.pending)
        };
        drop(pending);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn detached_pending_attachments_are_reclaimed_without_polling() {
        let (attacher, attachments) = attachments();
        let first = attacher.attach("first").unwrap();
        let agent = attacher.attach("agent").unwrap();
        let last = attacher.attach("last").unwrap();
        drop(agent);
        for _ in 0..100 {
            let agent = attacher.attach("agent").unwrap();
            assert_eq!(attachments.hub.state.lock().pending.len(), 3);
            drop(agent);
            assert_eq!(attachments.hub.state.lock().pending.len(), 2);
        }
        let names: Vec<_> = attachments
            .hub
            .state
            .lock()
            .pending
            .iter()
            .map(|a| a.name().to_owned())
            .collect();
        assert_eq!(names, ["first", "last"]);
        drop((first, last));
        assert!(attachments.hub.state.lock().pending.is_empty());
    }

    #[test]
    fn delivery_reclaims_an_attachment_that_detached_in_transit() {
        let (attacher, attachments) = attachments();
        let agent = attacher.attach("agent").unwrap();
        let pending = attachments.hub.state.lock().pending.pop_front().unwrap();
        drop(agent);
        attacher.deliver(pending);
        assert!(attachments.hub.state.lock().pending.is_empty());
    }
}
