use std::future::Future;
use std::task::{Context, Poll};

use fictionet::{Cancelled, Cx};

/// Anything that carries a byte stream both ways: TCP, TLS on top of TCP, a
/// logging middleware, a test pipe.
///
/// This is to byte streams what [`Interface`](crate::Interface) is to
/// packets. Middleware takes a connection and returns a connection, so code
/// that serves HTTP does not care whether TLS is underneath.
///
/// # Using a connection
///
/// Call [`read`](ConnectionExt::read), [`write`](ConnectionExt::write) and
/// the rest of [`ConnectionExt`], and `.await` them. Import them with
/// `use fictionet::prelude::*`. Every wait takes `&Cx` and returns early with
/// [`ConnError::Cancelled`] when that `Cx`'s [region](crate::Cx#regions) is
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
/// hyper and axum, call `conn.into_tokio(&cx)` from the `fictionet::tokio`
/// module (feature `tokio`).
///
/// A connection knows nothing about addresses. To see who connected, ask
/// the TCP connection underneath:
/// [`TcpConnection::peer_addr`](crate::stdlib::tcp::TcpConnection::peer_addr).
///
/// Dropping a connection closes it.
pub trait Connection: Send + 'static {
    /// Polls to read into `buf`. `Ok(0)` means the other side will send
    /// nothing more.
    fn poll_read(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>>;

    /// Polls to write some of `data`. Returns how many bytes were taken.
    /// Pending while there is no room.
    ///
    /// Never returns `Ok(0)` when `data` is not empty: a connection that can
    /// take no more bytes ever returns an error instead.
    ///
    /// Bytes that were taken are on their way. There is no separate flush,
    /// so a middleware such as TLS must hand its output on before it reports
    /// bytes as taken.
    fn poll_write(&mut self, cx: &Cx, task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>>;

    /// Polls to say this side will send nothing more. For TCP this sends a
    /// FIN. For TLS it first sends `close_notify`. Reading still works.
    fn poll_shutdown(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>>;

    /// Ready once the other side has reset the connection, or it is gone,
    /// without reading from it: for a server that is busy with a request
    /// and not reading, such as HTTP/1.1 while a handler works. A
    /// connection that cannot tell, such as a test pipe, is never ready,
    /// which is the default. Middleware passes it on to the connection
    /// underneath.
    fn poll_gone(&self, _task: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Connection for Box<dyn Connection> {
    fn poll_read(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        (**self).poll_read(cx, task, buf)
    }

    fn poll_write(&mut self, cx: &Cx, task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        (**self).poll_write(cx, task, data)
    }

    fn poll_shutdown(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        (**self).poll_shutdown(cx, task)
    }

    fn poll_gone(&self, task: &mut Context<'_>) -> Poll<()> {
        (**self).poll_gone(task)
    }
}

/// What every [`Connection`] can do, built on its three `poll_` methods.
///
/// Implemented for every connection. Imported by
/// [`prelude`](crate::prelude).
pub trait ConnectionExt: Connection {
    /// Reads into `buf`. Returns how many bytes were read. `Ok(0)` means the
    /// other side will send nothing more.
    fn read<'a>(
        &'a mut self,
        cx: &'a Cx,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, ConnError>> + Send + 'a {
        std::future::poll_fn(move |task| self.poll_read(cx, task, buf))
    }

    /// Writes some of `data`. Returns how many bytes were taken, which may be
    /// fewer than `data.len()`. Waits only while there is no room at all.
    fn write<'a>(
        &'a mut self,
        cx: &'a Cx,
        data: &'a [u8],
    ) -> impl Future<Output = Result<usize, ConnError>> + Send + 'a {
        std::future::poll_fn(move |task| self.poll_write(cx, task, data))
    }

    /// Writes all of `data`, calling [`write`](ConnectionExt::write) until
    /// every byte is taken. If a connection breaks the `poll_write` contract
    /// and takes no bytes, this returns [`ConnError::Closed`] instead of
    /// looping forever.
    fn write_all<'a>(
        &'a mut self,
        cx: &'a Cx,
        mut data: &'a [u8],
    ) -> impl Future<Output = Result<(), ConnError>> + Send + 'a {
        async move {
            while !data.is_empty() {
                let n = self.write(cx, data).await?;
                if n == 0 {
                    return Err(ConnError::Closed);
                }
                data = &data[n..];
            }
            Ok(())
        }
    }

    /// Says this side will send nothing more. Reading still works.
    fn shutdown<'a>(&'a mut self, cx: &'a Cx) -> impl Future<Output = Result<(), ConnError>> + Send + 'a {
        std::future::poll_fn(move |task| self.poll_shutdown(cx, task))
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
    /// The [region](crate::Cx#regions) of the `Cx` passed to the call was
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
            ConnError::Cancelled => "the region was cancelled",
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
/// [`Compat`](crate::tokio::Compat). The kind is the one std uses for the
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
