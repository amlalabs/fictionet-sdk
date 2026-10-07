//! Moving bytes between a client's TCP socket and a connection into the
//! world.

use std::future::Future;
use std::io;
use std::task::Poll;
use std::time::Duration;

use fictionet::stdlib::tcp::TcpConnection;
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
pub(crate) async fn tunnel(client: &mut TcpStream, world: &mut Compat<TcpConnection>) -> (Moved, Option<String>) {
    let (mut cr, mut cw) = client.split();
    let (mut wr, mut ww) = tokio::io::split(world);
    let mut moved = Moved::default();
    let (mut up_done, mut down_done) = (false, false);
    let mut error = None;
    {
        let mut up = std::pin::pin!(copy_counting(&mut cr, &mut ww, &mut moved.up, Side::Client));
        let mut down = std::pin::pin!(copy_counting(&mut wr, &mut cw, &mut moved.down, Side::World));
        std::future::poll_fn(|task| {
            if !up_done && let Poll::Ready(r) = up.as_mut().poll(task) {
                up_done = true;
                if let Err(e) = r {
                    error.get_or_insert(e);
                }
            }
            if !down_done && let Poll::Ready(r) = down.as_mut().poll(task) {
                down_done = true;
                if let Err(e) = r {
                    error.get_or_insert(e);
                }
            }
            // An error on one side ends the other at once.
            if (up_done && down_done) || error.is_some() { Poll::Ready(()) } else { Poll::Pending }
        })
        .await;
    }
    let why = error.and_then(|(side, e)| match side {
        Side::Client if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => None,
        Side::Client => Some(format!("the client: {e}")),
        Side::World => Some(format!("the world: {e}")),
    });
    (moved, why)
}

/// Which side of a tunnel an error came from.
#[derive(Clone, Copy)]
enum Side {
    Client,
    World,
}

impl Side {
    fn other(self) -> Side {
        match self {
            Side::Client => Side::World,
            Side::World => Side::Client,
        }
    }
}

/// Copies `from` (on side `from_side`) to `to` until `from` ends, then
/// shuts `to`'s sending side down. Counts the bytes in `count` as they go.
async fn copy_counting<R, W>(from: &mut R, to: &mut W, count: &mut u64, from_side: Side) -> Result<(), (Side, io::Error)>
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
        to.write_all(&buf[..n]).await.map_err(|e| (from_side.other(), e))?;
        *count += n as u64;
    }
}

/// Runs `up` (client to world) and `down` (world to client) together
/// until `down` ends. Then `up` gets a few seconds to finish, such as the
/// rest of a request body, before it is dropped. For a plain-HTTP request
/// forwarded with `Connection: close`, where the world's answer ends the
/// exchange. Returns `up`'s result, if it finished, and `down`'s.
pub(crate) async fn until_down_ends<U: Future, D: Future>(up: U, down: D) -> (Option<U::Output>, D::Output) {
    let mut up = std::pin::pin!(up);
    let mut down = std::pin::pin!(down);
    let mut up_result = None;
    let down_result = std::future::poll_fn(|task| {
        if up_result.is_none()
            && let Poll::Ready(r) = up.as_mut().poll(task)
        {
            up_result = Some(r);
        }
        down.as_mut().poll(task)
    })
    .await;
    if up_result.is_none() {
        up_result = tokio::time::timeout(Duration::from_secs(5), up).await.ok();
    }
    (up_result, down_result)
}
