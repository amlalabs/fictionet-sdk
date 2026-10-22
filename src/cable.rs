use fictionet::sync::Mutex;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use crate::cx::CancelWait;
use crate::packet_queue::PacketQueue;
use crate::{Cx, Interface, Packet, RecvError};

/// Makes two connected [`Interface`]s and returns them.
///
/// A packet sent into one end comes out of the other, in order. Think of
/// the pair as a network cable with a plug at each end, as the diagram
/// below shows. Inside, it is two
/// queues, one for each direction, each with one sender and one receiver.
/// The queues have no size limit. Dropping either end closes both
/// directions.
///
#[doc = include_str!("../docs/diagrams/pair.svg")]
///
/// Both ends are `Send`, so they can be used from different threads.
///
/// `pair` is the basic building block: everything in
/// [`stdlib`](crate::stdlib) is wired together with it. A world uses it to
/// connect two pieces by hand, for example a
/// [router](crate::stdlib::network::route::router) and the machine behind one of its
/// routes. Sandboxes do not come from `pair`: each one reaches the
/// world as an [`Attachment`](crate::Attachment).
pub fn pair() -> (End, End) {
    make(None, None)
}

/// Makes a cable that drops `guard` when the cable closes, from either end.
/// [`Attacher`](crate::Attacher) uses this to hold a name until then.
pub(crate) fn pair_with_guard(guard: Option<Box<dyn Send>>) -> (End, End) {
    make(guard, None)
}

/// What a queued packet costs against a limit beyond its bytes: its place
/// in the queue. So a flood of tiny packets is bounded too.
pub const PACKET_COST: usize = 64;

/// Makes a [`pair`] whose queues each hold at most `limit` bytes, counting
/// each packet's length plus 64 bytes. A packet sent past that is dropped,
/// as on a congested link. Use it for links on the agent's path, where an
/// unlimited queue would let the agent grow the world's memory without
/// end.
pub fn pair_with_limit(limit: usize) -> (End, End) {
    make(None, Some(limit))
}

fn make(guard: Option<Box<dyn Send>>, limit: Option<usize>) -> (End, End) {
    let cable = Arc::new(Cable {
        dirs: [
            Mutex::new(Direction::default()),
            Mutex::new(Direction::default()),
        ],
        guard: Mutex::new(guard),
        limit,
    });
    (
        End {
            cable: cable.clone(),
            side: 0,
            wait: CancelWait::default(),
        },
        End {
            cable,
            side: 1,
            wait: CancelWait::default(),
        },
    )
}

/// The state both ends share.
struct Cable {
    /// `dirs[i]` carries the packets that end `i` receives.
    dirs: [Mutex<Direction>; 2],
    /// Dropped when the first end is dropped.
    guard: Mutex<Option<Box<dyn Send>>>,
    /// The most bytes each queue may hold, if limited.
    limit: Option<usize>,
}

/// One direction of a cable: a queue with one sender and one receiver.
#[derive(Default)]
struct Direction {
    queue: PacketQueue,
    /// The receiver waiting for a packet, if any.
    waker: Option<Waker>,
    /// One end was dropped.
    closed: bool,
}

/// One of the two connected [`Interface`]s made by [`pair`].
///
/// Dropping it closes the link. Packets still queued for this end are
/// lost. The other end receives what was already sent to it, and then
/// [`RecvError::Closed`].
pub struct End {
    cable: Arc<Cable>,
    /// Which end this is: 0 or 1. It receives from `dirs[side]` and sends
    /// into `dirs[1 - side]`.
    side: usize,
    /// Where a receiver outside the run waits for a cancel.
    wait: CancelWait,
}

impl Interface for End {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        {
            let mut dir = self.cable.dirs[self.side].lock();
            if let Some(packet) = dir.queue.pop() {
                return Poll::Ready(Ok(packet));
            }
            if dir.closed {
                return Poll::Ready(Err(RecvError::Closed));
            }
            match &dir.waker {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => dir.waker = Some(cx.waker().clone()),
            }
        }
        if fcx.register_cancel(cx.waker(), &mut self.wait) {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        Poll::Pending
    }

    fn send(&mut self, packet: Packet) {
        let waker = {
            let mut dir = self.cable.dirs[1 - self.side].lock();
            if dir.closed {
                return;
            }
            if dir.queue.try_push(packet, self.cable.limit).is_err() {
                return;
            }
            dir.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl Drop for End {
    fn drop(&mut self) {
        // Packets still queued for this end are lost. The other end reads
        // what is queued for it, then `Closed`.
        let lost = {
            let mut dir = self.cable.dirs[self.side].lock();
            dir.closed = true;
            dir.waker = None;
            std::mem::take(&mut dir.queue)
        };
        drop(lost);
        let waker = {
            let mut dir = self.cable.dirs[1 - self.side].lock();
            dir.closed = true;
            dir.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        let guard = self.cable.guard.lock().take();
        drop(guard);
    }
}

impl End {
    /// The bytes waiting for this end to read, counted as for a limit.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.cable.dirs[self.side].lock().queue.bytes()
    }

    /// Whether the other end is gone.
    pub(crate) fn peer_gone(&self) -> bool {
        self.cable.dirs[self.side].lock().closed
    }
}

impl std::fmt::Debug for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("End").field("side", &self.side).finish()
    }
}
