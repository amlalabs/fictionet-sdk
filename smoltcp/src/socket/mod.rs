/*! Communication between endpoints.

The `socket` module deals with *network endpoints* and *buffering*.
It provides interfaces for accessing buffers of data, and protocol state machines
for filling and emptying these buffers.

The programming interface implemented here differs greatly from the common Berkeley socket
interface. Specifically, in the Berkeley interface the buffering is implicit:
the operating system decides on the good size for a buffer and manages it.
The interface implemented by this module uses explicit buffering: you decide on the good
size for a buffer, allocate it, and let the networking stack use it.
*/

use crate::iface::Context;
use crate::time::Instant;

pub mod tcp;

mod waker;

pub(crate) use self::waker::WakerRegistration;

/// Gives an indication on the next time the socket should be polled.
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PollAt {
    /// The socket needs to be polled immediately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    Time(Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
}

/// A network socket.
///
/// This enumeration abstracts the various types of sockets based on the IP protocol.
/// To downcast a `Socket` value to a concrete socket, use the [AnySocket] trait,
/// e.g. to get `tcp::Socket`, call `tcp::Socket::downcast(socket)`.
///
/// It is usually more convenient to use [SocketSet::get] instead.
///
/// [AnySocket]: trait.AnySocket.html
/// [SocketSet::get]: ../iface/struct.SocketSet.html#method.get
#[derive(Debug)]
pub enum Socket<'a> {
    Tcp(tcp::Socket<'a>),
}

impl<'a> Socket<'a> {
    pub(crate) fn poll_at(&self, cx: &mut Context) -> PollAt {
        match self {
            Socket::Tcp(s) => s.poll_at(cx),
        }
    }
}

/// A conversion trait for network sockets.
pub trait AnySocket<'a> {
    fn upcast(self) -> Socket<'a>;
    fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self>
    where
        Self: Sized;
    fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self>
    where
        Self: Sized;
}

impl<'a> AnySocket<'a> for Socket<'a> {
    #[inline]
    fn upcast(self) -> Socket<'a> {
        self
    }

    #[inline]
    fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self>
    where
        Self: Sized,
    {
        Some(socket)
    }

    #[inline]
    fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self>
    where
        Self: Sized,
    {
        Some(socket)
    }
}

impl<'a> AnySocket<'a> for tcp::Socket<'a> {
    fn upcast(self) -> Socket<'a> {
        Socket::Tcp(self)
    }

    fn downcast<'c>(socket: &'c Socket<'a>) -> Option<&'c Self> {
        let Socket::Tcp(socket) = socket;
        Some(socket)
    }

    fn downcast_mut<'c>(socket: &'c mut Socket<'a>) -> Option<&'c mut Self> {
        let Socket::Tcp(socket) = socket;
        Some(socket)
    }
}
