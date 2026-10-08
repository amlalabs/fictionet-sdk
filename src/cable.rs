use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use crate::cx::CancelWait;
use crate::watch::{Counted, Meter};
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
/// [router](crate::stdlib::route::router) and the machine behind one of its
/// routes. Sandboxes do not come from `pair`: each one reaches the
/// world as an [`Attachment`](crate::Attachment).
pub fn pair() -> (End, End) {
    pair_with_guard(None)
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
        dirs: [Mutex::new(Direction::default()), Mutex::new(Direction::default())],
        guard: Mutex::new(guard),
        meter: Meter::new(),
        limit,
    });
    let counted: Weak<dyn Counted> = Arc::downgrade(&cable) as Weak<Cable>;
    cable.meter.count_in(counted);
    (
        End { cable: cable.clone(), side: 0, wait: CancelWait::default(), seen: 0 },
        End { cable, side: 1, wait: CancelWait::default(), seen: 0 },
    )
}

/// The state both ends share.
struct Cable {
    /// `dirs[i]` carries the packets that end `i` receives.
    dirs: [Mutex<Direction>; 2],
    /// Dropped when the first end is dropped.
    guard: Mutex<Option<Box<dyn Send>>>,
    /// Counts for the dashboard.
    meter: Arc<Meter>,
    /// The most bytes each queue may hold, if limited.
    limit: Option<usize>,
}

/// One direction of a cable: a queue with one sender and one receiver.
#[derive(Default)]
struct Direction {
    queue: VecDeque<Packet>,
    /// What the queue holds, counted as for [`Cable::limit`].
    queued: usize,
    /// The receiver waiting for a packet, if any.
    waker: Option<Waker>,
    /// One end was dropped.
    closed: bool,
    /// Packets and bytes put into this queue, for the dashboard.
    packets: u64,
    bytes: u64,
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
    /// The last task seen polling this end, for the dashboard.
    seen: u64,
}

impl Interface for End {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        let current = crate::watch::current_task();
        if current != self.seen && current != 0 {
            self.seen = current;
            fcx.graph().owns(&self.cable.meter, self.side, current);
        }
        {
            let mut dir = self.cable.dirs[self.side].lock().unwrap();
            if let Some(packet) = dir.queue.pop_front() {
                dir.queued -= packet.0.len() + PACKET_COST;
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
            let mut dir = self.cable.dirs[1 - self.side].lock().unwrap();
            if dir.closed {
                return;
            }
            let cost = packet.0.len() + PACKET_COST;
            if self.cable.limit.is_some_and(|limit| dir.queued + cost > limit) {
                return;
            }
            dir.queued += cost;
            dir.packets += 1;
            dir.bytes += packet.0.len() as u64;
            self.cable.meter.copy(self.side, &packet);
            dir.queue.push_back(packet);
            dir.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn observe_link(&self) -> Option<crate::observe::LinkHandle> {
        Some(crate::observe::LinkHandle::new(self.cable.meter.clone()))
    }
}

impl Drop for End {
    fn drop(&mut self) {
        // Packets still queued for this end are lost. The other end reads
        // what is queued for it, then `Closed`.
        let lost = {
            let mut dir = self.cable.dirs[self.side].lock().unwrap();
            dir.closed = true;
            dir.waker = None;
            dir.queued = 0;
            std::mem::take(&mut dir.queue)
        };
        drop(lost);
        let waker = {
            let mut dir = self.cable.dirs[1 - self.side].lock().unwrap();
            dir.closed = true;
            dir.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
        let guard = self.cable.guard.lock().unwrap().take();
        drop(guard);
    }
}

impl End {
    /// The bytes waiting for this end to read, counted as for a limit.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.cable.dirs[self.side].lock().unwrap().queued
    }

    /// Whether the other end is gone.
    pub(crate) fn peer_gone(&self) -> bool {
        self.cable.dirs[self.side].lock().unwrap().closed
    }

    /// A check for [`peer_gone`](End::peer_gone) that works without this
    /// end, and holds nothing alive. Once both ends are dropped, it says
    /// gone.
    pub(crate) fn peer_gone_check(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let cable = Arc::downgrade(&self.cable);
        let side = self.side;
        move || cable.upgrade().is_none_or(|c| c.dirs[side].lock().unwrap().closed)
    }

    /// The counts and tap of this end's pair.
    pub(crate) fn meter(&self) -> &Arc<Meter> {
        &self.cable.meter
    }
}

impl Counted for Cable {
    fn totals(&self) -> [u64; 4] {
        // End `s` sends into `dirs[1 - s]`.
        let (p1, b1) = { let d = self.dirs[0].lock().unwrap(); (d.packets, d.bytes) };
        let (p0, b0) = { let d = self.dirs[1].lock().unwrap(); (d.packets, d.bytes) };
        [p0, b0, p1, b1]
    }
}

impl std::fmt::Debug for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("End").field("side", &self.side).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InterfaceExt, block_on, run};

    #[test]
    fn a_limited_cable_drops_what_does_not_fit_and_frees_what_is_read() {
        let result = block_on(run(|fcx| async move {
            // Room for exactly ten 36-byte packets.
            let (mut a, mut b) = pair_with_limit(10 * (36 + PACKET_COST));
            for i in 0..20u8 {
                a.send(Packet(vec![i; 36]));
            }
            for i in 0..10u8 {
                assert_eq!(b.recv(&fcx).await?, Packet(vec![i; 36]));
            }
            // The ten past the limit were dropped; reading made room again.
            a.send(Packet(vec![99; 36]));
            assert_eq!(b.recv(&fcx).await?, Packet(vec![99; 36]));
            assert_eq!(b.cable.dirs[b.side].lock().unwrap().queued, 0);
            Err::<(), crate::Error>(crate::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}
