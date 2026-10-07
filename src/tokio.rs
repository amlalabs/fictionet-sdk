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
//! # async fn serve(cx: Cx, hello: tls::ClientHello<tcp::TcpConnection>, config: Arc<rustls::ServerConfig>) -> Result {
//!
//! let conn = hello.finish(&cx, config).await?;
//! let mut io = conn.into_tokio(&cx);
//! io.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::stdlib::Connection;
use crate::Cx;

/// Adds [`into_tokio`](ConnectionTokioExt::into_tokio) to every
/// [`Connection`]. Imported by [`prelude`](crate::prelude).
pub trait ConnectionTokioExt: Connection + Sized {
    /// Wraps this connection in a [`Compat`], which implements tokio's
    /// `AsyncRead` and `AsyncWrite`.
    ///
    /// The wrapper keeps a clone of `cx`, because tokio's traits take no
    /// context. Its reads and writes still stop when `cx`'s
    /// [region](crate::Cx#regions) is cancelled: they fail with an I/O
    /// error whose source is
    /// [`ConnError::Cancelled`](crate::stdlib::ConnError::Cancelled), since
    /// an I/O error is the only way tokio's traits can report it. Every
    /// [`ConnError`](crate::stdlib::ConnError) converts the same way, with
    /// the matching I/O error kind, such as `ConnectionReset`, by
    /// `ConnError`'s `From` impl for `std::io::Error`.
    fn into_tokio(self, cx: &Cx) -> Compat<Self> {
        Compat { inner: self, cx: cx.clone() }
    }
}

impl<C: Connection> ConnectionTokioExt for C {}

/// A [`Connection`] with tokio's `AsyncRead` and `AsyncWrite`. Made by
/// [`into_tokio`](ConnectionTokioExt::into_tokio).
pub struct Compat<C> {
    inner: C,
    cx: Cx,
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
        task: &mut Context<'_>,
        buf: &mut ::tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.inner.poll_read(&this.cx, task, buf.initialize_unfilled()) {
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
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.inner.poll_write(&this.cx, task, data).map_err(std::io::Error::from)
    }

    /// A connection hands bytes on as soon as `poll_write` takes them, so
    /// there is nothing to flush.
    fn poll_flush(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.inner.poll_shutdown(&this.cx, task).map_err(std::io::Error::from)
    }
}
