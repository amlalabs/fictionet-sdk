//! Hands stdlib connections to tokio-based libraries such as hyper and
//! axum.
//!
//! Read this page when a world serves a connection with a library that
//! expects tokio's `AsyncRead` and `AsyncWrite`. Fictionet's own
//! [`Connection`] trait is not tied to any runtime. Calling
//! [`into_tokio`](ConnectionTokioExt::into_tokio) on a connection wraps it
//! in a [`Compat`], which implements tokio's traits. Nothing in the core
//! depends on this module.
//!
//! A library that spawns tasks or sets timers on tokio needs the world to
//! run on a tokio runtime: [`block_on`](crate::block_on) is not one. Await
//! [`run`](crate::run) inside `#[tokio::main]` instead.
//!
//! Here a TLS connection is finished and written to with tokio's
//! `AsyncWriteExt`:
//!
//! ```
//! use fictionet::prelude::*;
//! use tokio::io::AsyncWriteExt;
//! # use std::sync::Arc;
//! # use fictionet::{Cx, Result, stdlib::{tcp, tls}};
//! # async fn serve(fcx: Cx, hello: tls::ClientHello<tcp::TcpConnection>, config: Arc<rustls::ServerConfig>) -> Result {
//!
//! let conn = hello.finish(&fcx, config).await?;
//! let mut io = conn.into_tokio(&fcx);
//! io.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Cx;
use crate::stdlib::Connection;

/// Adds [`into_tokio`](ConnectionTokioExt::into_tokio) to every
/// [`Connection`]. Imported by [`prelude`](crate::prelude).
pub trait ConnectionTokioExt: Connection + Sized {
    /// Wraps this connection in a [`Compat`], which implements tokio's
    /// `AsyncRead` and `AsyncWrite`.
    ///
    /// The wrapper keeps a clone of `fcx`, because tokio's traits take no
    /// context. Its reads and writes still stop when `fcx`'s
    /// [region](crate::Cx#regions) is cancelled: they fail with an I/O
    /// error whose source is
    /// [`ConnError::Cancelled`](crate::stdlib::ConnError::Cancelled), since
    /// an I/O error is the only way tokio's traits can report it. Every
    /// [`ConnError`](crate::stdlib::ConnError) converts the same way, with
    /// the matching I/O error kind, such as `ConnectionReset`, by
    /// `ConnError`'s `From` impl for `std::io::Error`.
    fn into_tokio(self, fcx: &Cx) -> Compat<Self> {
        Compat {
            inner: self,
            fcx: fcx.clone(),
        }
    }
}

impl<C: Connection> ConnectionTokioExt for C {}

/// A [`Connection`] with tokio's `AsyncRead` and `AsyncWrite`. Made by
/// [`into_tokio`](ConnectionTokioExt::into_tokio).
pub struct Compat<C> {
    inner: C,
    fcx: Cx,
}

impl<C> Compat<C> {
    /// Unwraps the connection inside.
    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: Connection + Unpin> ::tokio::io::AsyncRead for Compat<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ::tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this
            .inner
            .poll_read(&this.fcx, cx, buf.initialize_unfilled())
        {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> ::tokio::io::AsyncWrite for Compat<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.inner
            .poll_write(&this.fcx, cx, data)
            .map_err(std::io::Error::from)
    }

    /// A connection hands bytes on as soon as `poll_write` takes them, so
    /// there is nothing to flush.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.inner
            .poll_shutdown(&this.fcx, cx)
            .map_err(std::io::Error::from)
    }
}
