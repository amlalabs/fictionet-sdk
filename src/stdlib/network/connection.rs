//! Contracts for byte connections and datagram sockets, and what is known
//! about a connection when it arrives.
//!
//! These traits let transports supply reads, writes and address
//! information to whatever runs a protocol over them, such as the
//! [stack runners](fictionet::stdlib::services::stack). They provide no
//! protocol parser, session or encryption of their own.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use fictionet::stdlib::layer::Chunk;
use fictionet::stdlib::network::tcp::Handshake;
use fictionet::stdlib::world::net::Sandbox;
use fictionet::{Cancelled, Cx};

/// How a connection's bytes travel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    /// A byte stream: TCP, or TLS over it.
    #[default]
    Tcp,
    /// Datagrams: UDP.
    Udp,
}

impl Transport {
    /// `tcp` or `udp`.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// What is known about a connection, or a UDP port's socket, when it
/// arrives: who it is between, how its bytes travel, and what its
/// handshakes settled. A stack factory such as
/// [`Host::tcp_stack`](fictionet::stdlib::world::net::Host::tcp_stack)'s
/// gets one, and handlers read it through their exchange.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ConnInfo {
    /// The connection's number, from whoever accepted it. [`Net`]
    /// numbers its connections from 1, on every port.
    ///
    /// [`Net`]: fictionet::stdlib::world::net::Net
    pub id: Option<u64>,
    /// The sandbox the connection came from, as it was when it arrived.
    pub sandbox: Option<Sandbox>,
    /// The world's side: the address and port the connection arrived on.
    pub local: Option<SocketAddr>,
    /// The other side.
    pub peer: Option<SocketAddr>,
    /// What the TCP handshake carried, for a TCP connection: the options
    /// of the peer's SYN, those the listener added to its SYN-ACK, and
    /// those of the ACK that completed it, including the SYN and SYN-ACK's
    /// typed IPv4 options. `None` for datagrams or a
    /// connection this side opened.
    pub handshake: Option<Handshake>,
    /// Whether the bytes arrived over TLS.
    pub tls: bool,
    /// The name the client sent in its TLS hello, in lowercase.
    pub sni: Option<Arc<str>>,
    /// The protocol the TLS handshake agreed on, such as `h2`.
    pub alpn: Option<Arc<[u8]>>,
    /// TCP or UDP. A service served both ways, such as a Kerberos KDC,
    /// answers by it: a reply too big for a datagram asks the client to
    /// use TCP.
    pub transport: Transport,
}

impl ConnInfo {
    /// A connection with this number between `local` and `peer`.
    pub fn new(id: u64, local: SocketAddr, peer: SocketAddr) -> ConnInfo {
        ConnInfo {
            id: Some(id),
            local: Some(local),
            peer: Some(peer),
            ..ConnInfo::default()
        }
    }

    /// The same, from `sandbox`.
    pub fn from_sandbox(mut self, sandbox: Option<Sandbox>) -> ConnInfo {
        self.sandbox = sandbox;
        self
    }

    /// The same, over TLS with this SNI and ALPN.
    pub fn over_tls(mut self, sni: Option<&str>, alpn: Option<&[u8]>) -> ConnInfo {
        self.tls = true;
        self.sni = sni.map(Arc::from);
        self.alpn = alpn.map(Arc::from);
        self
    }
}

/// A datagram socket, as the [datagram runner](fictionet::stdlib::services::stack::datagrams)
/// uses it.
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
/// module, which the opt-in `tokio` feature turns on.
///
/// A connection knows nothing about addresses. To see who connected, ask
/// the TCP connection underneath:
/// [`TcpConnection::peer_addr`](fictionet::stdlib::network::tcp::TcpConnection::peer_addr).
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
    /// Pending while there is no room, and then none of `data` was taken:
    /// the next call may offer other bytes, or none.
    ///
    /// Bytes that were taken belong to the connection, and it sends them
    /// once. A middleware such as TLS may still hold them, encrypted, until
    /// [`poll_flush`](Connection::poll_flush) hands them on.
    ///
    /// Never returns `Ok(0)` when `data` is not empty: a connection that can
    /// take no more bytes ever returns an error instead.
    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>>;

    /// Polls until every byte taken so far is on its way: handed to the
    /// connection underneath, or to the transport. A connection that hands
    /// bytes on as it takes them, such as TCP, is always flushed, which is
    /// the default. Middleware that holds bytes flushes them, then passes
    /// the flush on to the connection underneath.
    fn poll_flush(&mut self, _fcx: &Cx, _cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        Poll::Ready(Ok(()))
    }

    /// Polls to say this side will send nothing more. Bytes taken before go
    /// first. For TCP this sends a FIN. For TLS it first sends
    /// `close_notify`. Reading still works.
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

    /// Polls to read as [`poll_read`](Self::poll_read) does, except that a
    /// connection that already holds the bytes in a [`Chunk`] may hand the
    /// chunk over instead of copying it into `buf`: [`Read::Owned`], never
    /// empty and never longer than `buf`. It is still charged to whatever
    /// paid for it; the caller moves it to its own budget with
    /// [`Chunk::recharge`] before keeping it. `Read::Copied(0)` means the
    /// other side will send nothing more. The default reads into `buf`.
    fn poll_read_owned(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Read, ConnError>> {
        self.poll_read(fcx, cx, buf).map_ok(Read::Copied)
    }

    /// Polls to write some of `data`, exactly as
    /// [`poll_write`](Self::poll_write) does, except that a connection that
    /// keeps bytes in chunks may keep a piece of `data` without copying it.
    /// The default writes the bytes.
    fn poll_write_chunk(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &Chunk,
    ) -> Poll<Result<usize, ConnError>> {
        self.poll_write(fcx, cx, data)
    }
}

/// What [`Connection::poll_read_owned`] read.
#[derive(Debug)]
pub enum Read {
    /// This many bytes went into the caller's buffer. 0 is the end.
    Copied(usize),
    /// The connection handed over bytes it held.
    Owned(Chunk),
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

    fn poll_flush(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        (**self).poll_flush(fcx, cx)
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        (**self).poll_shutdown(fcx, cx)
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        (**self).poll_gone(cx)
    }

    fn poll_read_owned(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Read, ConnError>> {
        (**self).poll_read_owned(fcx, cx, buf)
    }

    fn poll_write_chunk(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &Chunk,
    ) -> Poll<Result<usize, ConnError>> {
        (**self).poll_write_chunk(fcx, cx, data)
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
    /// Dropped before it returns, it took nothing. Call
    /// [`flush`](ConnectionExt::flush) before waiting on anything other than
    /// this connection, so the bytes are on their way.
    fn write<'a>(
        &'a mut self,
        fcx: &'a Cx,
        data: &'a [u8],
    ) -> impl Future<Output = Result<usize, ConnError>> + Send + 'a {
        std::future::poll_fn(move |cx| self.poll_write(fcx, cx, data))
    }

    /// Writes all of `data`, calling [`write`](ConnectionExt::write) until
    /// every byte is taken, then flushes, so every byte is on its way when
    /// it returns. If a connection breaks the `poll_write` contract and
    /// takes no bytes, this returns [`ConnError::Closed`] instead of looping
    /// forever.
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
            self.flush(fcx).await
        }
    }

    /// Waits until every byte taken so far is on its way.
    fn flush<'a>(
        &'a mut self,
        fcx: &'a Cx,
    ) -> impl Future<Output = Result<(), ConnError>> + Send + 'a {
        std::future::poll_fn(move |cx| self.poll_flush(fcx, cx))
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
    /// An ICMPv4 destination-unreachable message quoted this connection's
    /// current SYN. Only from connecting. The value is the ICMP code:
    /// 0 for network, 1 for host, 3 for port, and so on.
    /// Code 4 (fragmentation needed) does not fail a TCP connect.
    Unreachable(u8),
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
            ConnError::Unreachable(0) => "network unreachable",
            ConnError::Unreachable(1) => "host unreachable",
            ConnError::Unreachable(3) => "port unreachable",
            ConnError::Unreachable(code) => {
                return write!(f, "destination unreachable (ICMP code {code})");
            }
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
/// An unreachable network (ICMP codes 0, 6, 9, 11) is `NetworkUnreachable`;
/// an unreachable port (3) is `ConnectionRefused`. Other unreachable codes
/// are `HostUnreachable`.
///
/// A cancel is [`ErrorKind::Other`](std::io::ErrorKind::Other), not
/// `Interrupted`: std's read loops retry `Interrupted`, and a cancelled
/// wait must end them.
impl From<ConnError> for std::io::Error {
    fn from(e: ConnError) -> Self {
        use std::io::ErrorKind;
        let kind = match e {
            ConnError::Refused => ErrorKind::ConnectionRefused,
            ConnError::Unreachable(0 | 6 | 9 | 11) => ErrorKind::NetworkUnreachable,
            ConnError::Unreachable(3) => ErrorKind::ConnectionRefused,
            ConnError::Unreachable(_) => ErrorKind::HostUnreachable,
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
