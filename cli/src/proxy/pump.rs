//! Moving bytes between a client's TCP socket and a connection into the
//! world.

use std::future::Future;
use std::io;
use std::task::Poll;
use std::time::Duration;

use fictionet::stdlib::network::tcp::TcpConnection;
use fictionet::tokio::Compat;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bytes are copied in pieces of up to this many, each way.
const PIECE: usize = 64 * 1024;

/// Bytes moved, each way.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Moved {
    pub(crate) up: u64,
    pub(crate) down: u64,
}

/// Copies both ways until both sides have closed their sending side. A
/// side that closes its sending side (a FIN) closes the other's too, so
/// half-closed connections work. An error on either side ends both.
/// Returns the bytes moved, and why it ended early, if it did: an error
/// on the world's side, or one on the client's side other than a reset.
/// Clients often close with a reset, such as curl with TLS data it did not
/// read, so that is an ordinary end.
pub(crate) async fn tunnel(
    client: &mut TcpStream,
    world: &mut Compat<TcpConnection>,
) -> (Moved, Option<String>) {
    let (mut cr, mut cw) = client.split();
    let (mut wr, mut ww) = tokio::io::split(world);
    let mut moved = Moved::default();
    let (mut up_done, mut down_done) = (false, false);
    let mut error = None;
    {
        let mut up = std::pin::pin!(copy_counting(&mut cr, &mut ww, &mut moved.up, Side::Client));
        let mut down = std::pin::pin!(copy_counting(
            &mut wr,
            &mut cw,
            &mut moved.down,
            Side::World
        ));
        std::future::poll_fn(|cx| {
            if !up_done && let Poll::Ready(r) = up.as_mut().poll(cx) {
                up_done = true;
                if let Err(e) = r {
                    error.get_or_insert(e);
                }
            }
            if !down_done && let Poll::Ready(r) = down.as_mut().poll(cx) {
                down_done = true;
                if let Err(e) = r {
                    error.get_or_insert(e);
                }
            }
            // An error on one side ends the other at once.
            if (up_done && down_done) || error.is_some() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
    let why = error.and_then(|(side, e)| side.why(e));
    (moved, why)
}

/// Which side of a transfer an error came from.
#[derive(Clone, Copy, Debug)]
pub(super) enum Side {
    Client,
    World,
}

impl Side {
    /// Describes an error, except for an ordinary client close.
    pub(super) fn why(self, e: io::Error) -> Option<String> {
        match self {
            Side::Client
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                None
            }
            Side::Client => Some(format!("the client: {e}")),
            Side::World => Some(format!("the world: {e}")),
        }
    }

    fn other(self) -> Side {
        match self {
            Side::Client => Side::World,
            Side::World => Side::Client,
        }
    }
}

/// Copies `from` (on side `from_side`) to `to` until `from` ends, then
/// shuts `to`'s sending side down. Counts the bytes in `count` as they go.
pub(super) async fn copy_counting<R, W>(
    from: &mut R,
    to: &mut W,
    count: &mut u64,
    from_side: Side,
) -> Result<(), (Side, io::Error)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; PIECE];
    loop {
        let n = from.read(&mut buf).await.map_err(|e| (from_side, e))?;
        if n == 0 {
            return to.shutdown().await.map_err(|e| (from_side.other(), e));
        }
        write_counting(to, &buf[..n], count)
            .await
            .map_err(|e| (from_side.other(), e))?;
    }
}

/// Counts each successful write, including a prefix before an error or
/// cancellation. `write_all` cannot report that prefix after an error.
pub(super) async fn write_counting<W: AsyncWrite + Unpin>(
    to: &mut W,
    mut buf: &[u8],
    count: &mut u64,
) -> io::Result<()> {
    while !buf.is_empty() {
        let n = to.write(buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        *count += n as u64;
        buf = &buf[n..];
    }
    Ok(())
}

/// Runs `up` (client to world) and `down` (world to client) together
/// until `down` ends. If `allow_grace` accepts its result, `up` gets five
/// seconds to finish the rest of a request body before it is dropped.
/// Otherwise, `up` is dropped at once. For a plain-HTTP request forwarded
/// with `Connection: close`, where the world's answer ends the exchange.
/// Returns `up`'s result, if it finished, and `down`'s.
pub(crate) async fn until_down_ends<U: Future, D: Future>(
    up: U,
    down: D,
    allow_grace: impl FnOnce(&D::Output) -> bool,
) -> (Option<U::Output>, D::Output) {
    let mut up = std::pin::pin!(up);
    let mut down = std::pin::pin!(down);
    let mut up_result = None;
    let down_result = std::future::poll_fn(|cx| {
        if up_result.is_none()
            && let Poll::Ready(r) = up.as_mut().poll(cx)
        {
            up_result = Some(r);
        }
        down.as_mut().poll(cx)
    })
    .await;
    if up_result.is_none() && allow_grace(&down_result) {
        up_result = tokio::time::timeout(Duration::from_secs(5), up).await.ok();
    }
    (up_result, down_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::Context;
    use tokio::io::ReadBuf;

    struct Writer {
        room: usize,
        end: Poll<io::Result<usize>>,
        shutdown: io::Result<()>,
    }

    impl AsyncWrite for Writer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.room == 0 {
                return std::mem::replace(&mut self.end, Poll::Pending);
            }
            let n = self.room.min(buf.len());
            self.room -= n;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(std::mem::replace(&mut self.shutdown, Ok(())))
        }
    }

    struct Reset;

    impl AsyncRead for Reset {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
    }

    #[tokio::test]
    async fn partial_writes_count_before_error_or_write_zero() {
        for end in [Err(io::Error::from(io::ErrorKind::BrokenPipe)), Ok(0)] {
            let expected = match &end {
                Err(e) => e.kind(),
                Ok(_) => io::ErrorKind::WriteZero,
            };
            let mut writer = Writer {
                room: 3,
                end: Poll::Ready(end),
                shutdown: Ok(()),
            };
            let mut count = 0;
            let (side, e) =
                copy_counting(&mut &b"abcdef"[..], &mut writer, &mut count, Side::Client)
                    .await
                    .unwrap_err();
            assert_eq!(count, 3);
            assert!(matches!(side, Side::World));
            assert_eq!(e.kind(), expected);
        }
    }

    #[tokio::test]
    async fn partial_writes_count_before_cancellation() {
        let mut writer = Writer {
            room: 3,
            end: Poll::Pending,
            shutdown: Ok(()),
        };
        let mut count = 0;
        {
            let mut reader = &b"abcdef"[..];
            let mut copy = std::pin::pin!(copy_counting(
                &mut reader,
                &mut writer,
                &mut count,
                Side::Client
            ));
            std::future::poll_fn(|cx| {
                assert!(copy.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn read_and_shutdown_errors_keep_counts_and_sides() {
        let mut writer = Vec::new();
        let mut count = 0;
        let (side, e) = copy_counting(
            &mut (&b"prefix"[..]).chain(Reset),
            &mut writer,
            &mut count,
            Side::World,
        )
        .await
        .unwrap_err();
        assert_eq!(writer, b"prefix");
        assert_eq!(count, 6);
        assert!(matches!(side, Side::World));
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);

        let mut writer = Writer {
            room: 6,
            end: Poll::Pending,
            shutdown: Err(io::ErrorKind::BrokenPipe.into()),
        };
        let mut count = 0;
        let (side, e) = copy_counting(&mut &b"prefix"[..], &mut writer, &mut count, Side::Client)
            .await
            .unwrap_err();
        assert_eq!(count, 6);
        assert!(matches!(side, Side::World));
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }
}
