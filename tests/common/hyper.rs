//! Hyper transport and executor for simulated connections.

use fictionet::Cx;
use fictionet::stdlib::Connection;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct Io<C> {
    pub fcx: Cx,
    pub conn: C,
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut tmp = [0u8; 16 * 1024];
        let tmp = &mut tmp[..buf.remaining().min(16 * 1024)];
        match this.conn.poll_read(&this.fcx, cx, tmp) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&tmp[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn
            .poll_write(&this.fcx, cx, data)
            .map_err(std::io::Error::other)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn
            .poll_shutdown(&this.fcx, cx)
            .map_err(std::io::Error::other)
    }
}

#[derive(Clone)]
pub struct Exec(pub Cx);

impl<F: Future<Output = ()> + Send + 'static> hyper::rt::Executor<F> for Exec {
    fn execute(&self, fut: F) {
        self.0.spawn(move |_| async move {
            fut.await;
            Ok(())
        });
    }
}
