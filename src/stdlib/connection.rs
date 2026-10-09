//! Contracts for byte connections, accepted streams, and datagram sockets.
//!
//! These traits let transports supply reads, writes, acceptance, and address
//! information to the serving driver. They provide no protocol parser,
//! session, service implementation, or encryption of their own.

use std::future::Future;
use std::task::{Context, Poll};

use fictionet::{Cancelled, Cx};

/// Accepts byte streams for the serving driver.
pub trait Accept: Send + 'static {
    /// The accepted connection and its transport lifetime.
    type Conn: Accepted;

    /// Waits for a connection, or returns cancellation or a transport error.
    fn accept(&mut self, fcx: &Cx) -> impl Future<Output = Result<Self::Conn, ConnError>> + Send;
}

/// An accepted stream with addresses and a transport lifetime.
pub trait Accepted: Connection {
    /// The local address of the connection.
    fn local_addr(&self) -> std::net::SocketAddr;
    /// The peer's address.
    fn peer_addr(&self) -> std::net::SocketAddr;
    /// Resets the connection without waiting for a graceful close.
    fn reset(self);
    /// Retains `item` until the transport is gone, including after this
    /// handle is dropped. This keeps closing sockets in the serving limit.
    fn hold_until_gone<T: Send + 'static>(&self, item: T);
}

/// A datagram socket for the serving driver.
pub trait DatagramSocket: Send + 'static {
    /// Waits for bytes and their sender. Drains queued datagrams before
    /// returning [`fictionet::RecvError::Closed`]. Cancellation ends the wait.
    fn recv(
        &mut self,
        fcx: &Cx,
    ) -> impl Future<Output = Result<(Vec<u8>, std::net::SocketAddr), fictionet::RecvError>> + Send;
    /// Sends a datagram without waiting. Undeliverable datagrams are lost.
    fn send_to(&mut self, data: &[u8], to: std::net::SocketAddr);
}

/// Anything that carries a byte stream both ways: TCP, TLS on top of TCP, a
/// logging middleware, a test pipe.
///
/// This is to byte streams what [`Interface`](fictionet::Interface) is to
/// packets. Middleware takes a connection and returns a connection, so code
/// that serves HTTP does not care whether TLS is underneath.
///
/// # Using a connection
///
/// Call [`read`](ConnectionExt::read), [`write`](ConnectionExt::write) and
/// the rest of [`ConnectionExt`], and `.await` them. Import them with
/// `use fictionet::prelude::*`. Every wait takes `&Cx` and returns early with
/// [`ConnError::Cancelled`] when that `Cx`'s [region](fictionet::Cx#regions) is
/// cancelled.
///
/// The trait itself holds only the three methods a new kind of connection
/// must implement. Everything built on them lives in `ConnectionExt`, so it
/// behaves the same for every connection and can grow without changing this
/// trait.
///
/// Connections of different types can share one list as
/// `Box<dyn Connection>`, which is itself a `Connection`.
///
/// For libraries that expect tokio's `AsyncRead` and `AsyncWrite`, such as
/// hyper and axum, call `conn.into_tokio(&fcx)` from the `fictionet::tokio`
/// module.
///
/// A connection knows nothing about addresses. To see who connected, ask
/// the TCP connection underneath:
/// [`TcpConnection::peer_addr`](fictionet::stdlib::tcp::TcpConnection::peer_addr).
///
/// Dropping a connection closes it.
pub trait Connection: Send + 'static {
    /// Polls to read into `buf`. `Ok(0)` means the other side will send
    /// nothing more.
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>>;

    /// Polls to write some of `data`. Returns how many bytes were taken.
    /// Pending while there is no room.
    ///
    /// After `Poll::Pending`, call again with the same bytes until the call
    /// returns `Poll::Ready`. A layer may already hold those bytes while it
    /// waits for the connection underneath. A TLS connection, for example,
    /// has encrypted them and reports them taken once they are sent.
    ///
    /// Never returns `Ok(0)` when `data` is not empty: a connection that can
    /// take no more bytes ever returns an error instead.
    ///
    /// Bytes that were taken are on their way. There is no separate flush,
    /// so a middleware such as TLS must hand its output on before it reports
    /// bytes as taken.
    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>>;

    /// Polls to say this side will send nothing more. For TCP this sends a
    /// FIN. For TLS it first sends `close_notify`. Reading still works.
    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>>;

    /// Ready once the other side has reset the connection, or it is gone,
    /// without reading from it: for a server that is busy with a request
    /// and not reading, such as HTTP/1.1 while a handler works. A
    /// connection that cannot tell, such as a test pipe, is never ready,
    /// which is the default. Middleware passes it on to the connection
    /// underneath.
    fn poll_gone(&self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Connection for Box<dyn Connection> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        (**self).poll_read(fcx, cx, buf)
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        (**self).poll_write(fcx, cx, data)
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        (**self).poll_shutdown(fcx, cx)
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        (**self).poll_gone(cx)
    }
}

/// What every [`Connection`] can do, built on its three `poll_` methods.
///
/// Implemented for every connection. Imported by
/// [`prelude`](fictionet::prelude).
pub trait ConnectionExt: Connection {
    /// Reads into `buf`. Returns how many bytes were read. `Ok(0)` means the
    /// other side will send nothing more.
    fn read<'a>(
        &'a mut self,
        fcx: &'a Cx,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, ConnError>> + Send + 'a {
        std::future::poll_fn(move |cx| self.poll_read(fcx, cx, buf))
    }

    /// Writes some of `data`. Returns how many bytes were taken, which may be
    /// fewer than `data.len()`. Waits only while there is no room at all.
    fn write<'a>(
        &'a mut self,
        fcx: &'a Cx,
        data: &'a [u8],
    ) -> impl Future<Output = Result<usize, ConnError>> + Send + 'a {
        std::future::poll_fn(move |cx| self.poll_write(fcx, cx, data))
    }

    /// Writes all of `data`, calling [`write`](ConnectionExt::write) until
    /// every byte is taken. If a connection breaks the `poll_write` contract
    /// and takes no bytes, this returns [`ConnError::Closed`] instead of
    /// looping forever.
    fn write_all<'a>(
        &'a mut self,
        fcx: &'a Cx,
        mut data: &'a [u8],
    ) -> impl Future<Output = Result<(), ConnError>> + Send + 'a {
        async move {
            while !data.is_empty() {
                let n = self.write(fcx, data).await?;
                if n == 0 {
                    return Err(ConnError::Closed);
                }
                data = &data[n..];
            }
            Ok(())
        }
    }

    /// Says this side will send nothing more. Reading still works.
    fn shutdown<'a>(
        &'a mut self,
        fcx: &'a Cx,
    ) -> impl Future<Output = Result<(), ConnError>> + Send + 'a {
        std::future::poll_fn(move |cx| self.poll_shutdown(fcx, cx))
    }
}

impl<C: Connection + ?Sized> ConnectionExt for C {}

/// Why a connection operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnError {
    /// The other side refused the connection. Only from connecting.
    Refused,
    /// The other side reset the connection.
    Reset,
    /// The other side stopped answering.
    TimedOut,
    /// What carried the connection stopped: its endpoint's task ended,
    /// because its region was cancelled or its interface closed. A write
    /// after this side shut down fails with it too.
    Closed,
    /// A layer got bytes it could not understand, such as a bad TLS record.
    Broken,
    /// The [region](fictionet::Cx#regions) of the `Cx` passed to the call was
    /// cancelled while it waited.
    Cancelled,
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ConnError::Refused => "connection refused",
            ConnError::Reset => "connection reset",
            ConnError::TimedOut => "connection timed out",
            ConnError::Closed => "the connection's carrier stopped",
            ConnError::Broken => "the connection got bytes it could not understand",
            ConnError::Cancelled => "the connection's wait stopped",
        })
    }
}

impl std::error::Error for ConnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnError::Cancelled => Some(&Cancelled),
            _ => None,
        }
    }
}

/// A connection's error as an [`std::io::Error`], for code that reads and
/// writes through `std::io` or tokio's traits, such as
/// [`Compat`](fictionet::tokio::Compat). The kind is the one std uses for the
/// same failure; the `ConnError` is the source, so
/// `e.get_ref().and_then(|e| e.downcast_ref::<ConnError>())` gets it back.
///
/// A cancel is [`ErrorKind::Other`](std::io::ErrorKind::Other), not
/// `Interrupted`: std's read loops retry `Interrupted`, and a cancelled
/// wait must end them.
impl From<ConnError> for std::io::Error {
    fn from(e: ConnError) -> Self {
        use std::io::ErrorKind;
        let kind = match e {
            ConnError::Refused => ErrorKind::ConnectionRefused,
            ConnError::Reset => ErrorKind::ConnectionReset,
            ConnError::TimedOut => ErrorKind::TimedOut,
            ConnError::Closed => ErrorKind::BrokenPipe,
            ConnError::Broken => ErrorKind::InvalidData,
            ConnError::Cancelled => ErrorKind::Other,
        };
        std::io::Error::new(kind, e)
    }
}

impl From<Cancelled> for ConnError {
    fn from(_: Cancelled) -> Self {
        ConnError::Cancelled
    }
}
