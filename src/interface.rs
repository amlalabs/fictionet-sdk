use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::{Cancelled, Cx, observe};

/// One IPv4 or IPv6 packet, exactly the bytes on the wire.
///
/// The core never parses a packet, so a program can send a broken one on
/// purpose. Parsing lives in [`stdlib`](crate::stdlib).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet(pub Vec<u8>);

/// Why [`recv`](InterfaceExt::recv) returned no packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvError {
    /// The other end is gone, and every packet it sent has been received.
    Closed,
    /// The [region](Cx#regions) of the `Cx` passed to `recv` was cancelled.
    Cancelled,
}

/// Something that sends and receives packets: one end of a two-way
/// packet link.
///
/// Whatever is sent into one end comes out of the other. An interface is
/// the one shape every part of a world shares. A sandbox reaches the world
/// as an [`Attachment`](crate::Attachment), which is an interface. [`pair`](crate::pair) makes two
/// connected interfaces inside the world. Every stdlib function that moves
/// packets takes interfaces and returns new ones, so the pieces of a
/// network plug into each other.
///
/// Dropping one end closes the link. The other end then receives every
/// packet that was already sent to it, and after that
/// [`recv`](InterfaceExt::recv) returns [`RecvError::Closed`]. That
/// holds for one interface. A chain of them, such as a sandbox behind a
/// [`stdlib::delay`](crate::stdlib::delay), may lose packets on the way: each stdlib task stops
/// when its region is cancelled, and on `Closed` by its own rule. A
/// `delay` stops as soon as either side closes, and drops what it still
/// holds. [Three kinds of functions](crate::stdlib#three-kinds-of-functions)
/// lists the rule of each.
///
/// An interface holds no borrowed references (it is `'static`), because
/// most interfaces end up inside background tasks. Such a task can outlive
/// the function that started it, but not its owning [region](Cx#regions)
/// (see [What ends what](crate::running#what-ends-what)).
///
/// An interface is `Send`: it can move to another thread, for example into
/// a tokio task.
///
/// # Using an interface
///
/// Call [`recv`](InterfaceExt::recv) and `.await` it, after
/// `use fictionet::prelude::*`. Call [`send`](Interface::send) directly.
/// The trait itself holds only the two methods a new kind of interface must
/// implement. Everything built on them is in [`InterfaceExt`].
///
/// Interfaces of different types can share one list as
/// `Box<dyn Interface>`, which is itself an `Interface`.
pub trait Interface: Send + 'static {
    /// Polls for the next packet from the other end.
    ///
    /// Returns `Poll::Pending` and arranges for `cx`'s waker to be woken when a
    /// packet arrives, the other end closes, or `fcx`'s region is cancelled.
    ///
    /// Callers use [`recv`](InterfaceExt::recv) instead. It is a polling
    /// method, not an `async fn`, so that `Box<dyn Interface>` works without
    /// allocating per packet. `std::future::Future` is built the same way.
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>>;

    /// Sends a packet to the other end.
    ///
    /// This never waits, so it takes no context and cannot be cancelled. If
    /// the other end is gone, the packet is lost, as on an unplugged network
    /// link.
    ///
    /// An interface from [`pair`](crate::pair) has no size limit, so its `send` never
    /// drops a packet while the other end exists. To model a link whose
    /// queue fills up and drops packets, add one on purpose with
    /// [`stdlib::bottleneck`](crate::stdlib::bottleneck).
    ///
    /// An [`Attachment`](crate::Attachment) is different, because its packets leave the
    /// process. When the connection to `fictionet attach` is full, the packet
    /// waits in a queue inside the world, and the queue is written out in
    /// order as attach makes room. The queue has a budget of 32 MiB. Each
    /// waiting packet counts its own length plus 64 bytes. A packet that
    /// would take the queue past that budget is dropped. See [`listen`](crate::listen).
    fn send(&mut self, packet: Packet);

    /// The link this interface is one end of, for the
    /// [dashboard](crate::observe#the-dashboard). Only [`End`](crate::End) and [`Attachment`](crate::Attachment) have
    /// one. Use [`observe::LinkHandle::label`] to name the link.
    fn observe_link(&self) -> Option<observe::LinkHandle> {
        None
    }
}

impl Interface for Box<dyn Interface> {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        (**self).poll_recv(fcx, cx)
    }

    fn send(&mut self, packet: Packet) {
        (**self).send(packet)
    }

    fn observe_link(&self) -> Option<observe::LinkHandle> {
        (**self).observe_link()
    }
}

/// What every [`Interface`] can do, built on its two methods.
///
/// Implemented for every interface. Imported by [`prelude`](crate::prelude).
pub trait InterfaceExt: Interface {
    /// Waits for the next packet from the other end.
    ///
    /// Returns [`RecvError::Closed`] once the other end is gone and every
    /// packet it sent has been received. Returns early with
    /// [`RecvError::Cancelled`] if `fcx`'s [region](Cx#regions) is cancelled.
    /// So a loop that waits on `recv` stops on its own when its region is
    /// cancelled, with no extra code.
    fn recv<'a>(&'a mut self, fcx: &'a Cx) -> Recv<'a, Self> {
        Recv {
            interface: self,
            fcx,
        }
    }
}

impl<I: Interface + ?Sized> InterfaceExt for I {}

/// The future returned by [`recv`](InterfaceExt::recv).
pub struct Recv<'a, I: ?Sized> {
    interface: &'a mut I,
    fcx: &'a Cx,
}

impl<I: Interface + ?Sized> Future for Recv<'_, I> {
    type Output = Result<Packet, RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.interface.poll_recv(this.fcx, cx)
    }
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvError::Closed => f.write_str("the other end of the interface is gone"),
            RecvError::Cancelled => f.write_str("the receive stopped"),
        }
    }
}

impl std::error::Error for RecvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RecvError::Closed => None,
            RecvError::Cancelled => Some(&Cancelled),
        }
    }
}

impl From<Cancelled> for RecvError {
    fn from(_: Cancelled) -> Self {
        RecvError::Cancelled
    }
}
