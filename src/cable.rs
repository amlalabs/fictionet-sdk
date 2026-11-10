use fictionet::sync::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::task::{Context, Poll};

use crate::cx::CancelWait;
use crate::packet_queue::charge;
use crate::sync::Parked;
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
/// Sending and receiving take no lock while the receiver has packets
/// waiting: only a receiver that found its queue empty leaves a waker,
/// and only the send that finds it there takes the lock to wake it.
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
/// each packet's allocated capacity plus 64 bytes. A packet sent past that is dropped,
/// as on a congested link. Use it for links on the agent's path, where an
/// unlimited queue would let the agent grow the world's memory without
/// end.
pub fn pair_with_limit(limit: usize) -> (End, End) {
    make(None, Some(limit))
}

fn make(guard: Option<Box<dyn Send>>, limit: Option<usize>) -> (End, End) {
    let cable = Arc::new(Cable {
        dirs: [Direction::default(), Direction::default()],
        guard: Mutex::new(guard),
        limit,
    });
    // `to_0` carries what end 0 receives, `to_1` what end 1 receives.
    let (to_0, from_1) = channel();
    let (to_1, from_0) = channel();
    (
        End {
            cable: cable.clone(),
            side: 0,
            queue: Mutex::new(from_1),
            peer: to_1,
            wait: CancelWait::default(),
        },
        End {
            cable,
            side: 1,
            queue: Mutex::new(from_0),
            peer: to_0,
            wait: CancelWait::default(),
        },
    )
}

/// The state both ends share.
struct Cable {
    /// `dirs[i]` describes the queue that end `i` receives from.
    dirs: [Direction; 2],
    /// Dropped when the first end is dropped.
    guard: Mutex<Option<Box<dyn Send>>>,
    /// The most bytes each queue may hold, if limited.
    limit: Option<usize>,
}

/// One direction of a cable, beside its queue: who waits on it, what it
/// holds, and whether it is closed.
#[derive(Default)]
struct Direction {
    /// The receiver, once it found the queue empty.
    receiver: Parked,
    /// What the queued packets cost, as [`PacketQueue`](crate::relay::PacketQueue)
    /// counts it, on a cable with a limit. A sender adds a packet's cost
    /// before it queues the packet, and the receiver takes it off after it
    /// took the packet, so this is never less than what the queue holds. A
    /// cable without a limit counts nothing.
    bytes: AtomicUsize,
    /// One end was dropped.
    closed: AtomicBool,
}

impl Direction {
    /// Counts `packet` against `limit`. False, with nothing counted, past
    /// it.
    fn reserve(&self, packet: &Packet, limit: Option<usize>) -> bool {
        let Some(limit) = limit else {
            return true;
        };
        let Some(cost) = charge(packet) else {
            return false;
        };
        self.bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_add(cost).filter(|&total| total <= limit)
            })
            .is_ok()
    }

    /// Takes what [`reserve`](Direction::reserve) counted for `packet` off.
    fn release(&self, packet: &Packet, limit: Option<usize>) {
        if limit.is_some() {
            let cost = charge(packet).expect("a queued packet was counted");
            self.bytes.fetch_sub(cost, Ordering::Relaxed);
        }
    }
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
    /// The packets sent to this end. Only `&mut self` reads it, through
    /// [`Mutex::get_mut`], which takes no lock: the mutex is there because
    /// a `Receiver` is not `Sync`, and an `End` is.
    queue: Mutex<Receiver<Packet>>,
    /// Where this end sends: the other end's queue.
    peer: Sender<Packet>,
    /// Where a receiver outside the run waits for a cancel.
    wait: CancelWait,
}

impl End {
    /// A packet, or `Closed` once the queue is empty and the other end is
    /// gone. `None` when the queue is empty and the cable open.
    fn take(&mut self) -> Option<Result<Packet, RecvError>> {
        let dir = &self.cable.dirs[self.side];
        let queue = self.queue.get_mut();
        let packet = match queue.try_recv() {
            Ok(packet) => packet,
            Err(TryRecvError::Disconnected) => return Some(Err(RecvError::Closed)),
            Err(TryRecvError::Empty) => {
                if !dir.closed.load(Ordering::Acquire) {
                    return None;
                }
                // The other end sent its last packets before it closed, so
                // one more look sees them.
                match queue.try_recv() {
                    Ok(packet) => packet,
                    Err(_) => return Some(Err(RecvError::Closed)),
                }
            }
        };
        dir.release(&packet, self.cable.limit);
        Some(Ok(packet))
    }
}

impl Interface for End {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        if let Some(got) = self.take() {
            return Poll::Ready(got);
        }
        // Empty: leave the waker, then look once more, so a packet sent in
        // between is either seen here or wakes the waker.
        self.cable.dirs[self.side].receiver.park(cx.waker());
        if let Some(got) = self.take() {
            return Poll::Ready(got);
        }
        if fcx.register_cancel(cx.waker(), &mut self.wait) {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        Poll::Pending
    }

    fn send(&mut self, packet: Packet) {
        let dir = &self.cable.dirs[1 - self.side];
        if dir.closed.load(Ordering::Acquire) {
            return;
        }
        if !dir.reserve(&packet, self.cable.limit) {
            return;
        }
        if let Err(lost) = self.peer.send(packet) {
            // The other end is gone, and its queue with it.
            dir.release(&lost.0, self.cable.limit);
            return;
        }
        dir.receiver.wake();
    }
}

impl Drop for End {
    fn drop(&mut self) {
        // Packets still queued for this end are lost when `queue` drops,
        // after this. The other end reads what is queued for it, then
        // `Closed`.
        let own = &self.cable.dirs[self.side];
        own.closed.store(true, Ordering::Release);
        drop(own.receiver.take());
        let other = &self.cable.dirs[1 - self.side];
        other.closed.store(true, Ordering::Release);
        other.receiver.wake();
        let guard = self.cable.guard.lock().take();
        drop(guard);
    }
}

impl End {
    /// The bytes waiting for this end to read, counted as for a limit. A
    /// cable without a limit counts nothing.
    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.cable.dirs[self.side].bytes.load(Ordering::Relaxed)
    }

    /// Whether the other end is gone.
    pub(crate) fn peer_gone(&self) -> bool {
        self.cable.dirs[self.side].closed.load(Ordering::Acquire)
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
    use crate::InterfaceExt;
    use std::sync::Weak;
    use std::task::{Wake, Waker};
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(10);

    #[test]
    fn receiver_replacement_and_close_release_wakers_outside_the_lock() {
        struct CheckDrop(Weak<Cable>, usize, Arc<AtomicBool>);
        impl Wake for CheckDrop {
            fn wake(self: Arc<Self>) {
                panic!("replacing or releasing a waiter must not wake it");
            }
        }
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                let cable = self.0.upgrade().unwrap();
                assert!(cable.dirs[self.1].receiver.try_lock().is_some());
                self.2.store(true, Ordering::SeqCst);
            }
        }
        crate::block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
            for close in [false, true] {
                let (mut receiver, _sender) = pair();
                let dropped = Arc::new(AtomicBool::new(false));
                let waker = Waker::from(Arc::new(CheckDrop(
                    Arc::downgrade(&receiver.cable),
                    receiver.side,
                    dropped.clone(),
                )));
                receiver.cable.dirs[receiver.side].receiver.park(&waker);
                drop(waker);
                if close {
                    drop(receiver);
                } else {
                    assert!(
                        receiver
                            .poll_recv(&fcx, &mut Context::from_waker(Waker::noop()))
                            .is_pending()
                    );
                }
                assert!(dropped.load(Ordering::SeqCst));
            }
            Ok(())
        }))
        .unwrap();
    }

    #[derive(Default)]
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A receiver that returned `Pending` is woken by the next send, and
    /// by its peer's drop, once each.
    #[test]
    fn a_pending_receiver_is_woken_by_the_next_send_and_by_the_close() {
        crate::block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
            let (mut a, mut b) = pair();
            let count = Arc::new(Count::default());
            let waker = Waker::from(count.clone());
            let mut cx = Context::from_waker(&waker);
            assert!(a.poll_recv(&fcx, &mut cx).is_pending());
            b.send(Packet(vec![1]));
            assert_eq!(count.0.load(Ordering::SeqCst), 1);
            b.send(Packet(vec![2]));
            assert_eq!(count.0.load(Ordering::SeqCst), 1, "no one was parked");
            assert!(matches!(a.poll_recv(&fcx, &mut cx), Poll::Ready(Ok(p)) if p.0 == [1]));
            assert!(matches!(a.poll_recv(&fcx, &mut cx), Poll::Ready(Ok(p)) if p.0 == [2]));
            assert!(a.poll_recv(&fcx, &mut cx).is_pending());
            drop(b);
            assert_eq!(count.0.load(Ordering::SeqCst), 2);
            assert!(matches!(
                a.poll_recv(&fcx, &mut cx),
                Poll::Ready(Err(RecvError::Closed))
            ));
            Ok(())
        }))
        .unwrap();
    }

    /// While the receiver has packets waiting, neither the send nor the
    /// receive takes a lock: they go through with both locks held
    /// elsewhere.
    #[test]
    fn a_steady_exchange_takes_no_lock() {
        let (mut a, mut b) = pair();
        let cable = a.cable.clone();
        let held: Vec<_> = cable
            .dirs
            .iter()
            .map(|d| d.receiver.try_lock().unwrap())
            .collect();
        let (done, finished) = std::sync::mpsc::channel();
        let exchange = std::thread::spawn(move || {
            // The ends come back out of the lab: dropping an end takes the
            // locks, which waits for the test to let them go.
            let ends = Arc::new(Mutex::new(None));
            let back = ends.clone();
            let out = crate::block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
                let mut cx = Context::from_waker(Waker::noop());
                b.send(Packet(0u32.to_le_bytes().to_vec()));
                for i in 1..1000u32 {
                    b.send(Packet(i.to_le_bytes().to_vec()));
                    let Poll::Ready(Ok(got)) = a.poll_recv(&fcx, &mut cx) else {
                        panic!("a packet was queued");
                    };
                    assert_eq!(got.0, (i - 1).to_le_bytes());
                }
                *back.lock() = Some((a, b));
                Ok(())
            }));
            done.send(out.is_ok()).unwrap();
            ends.lock().take()
        });
        let finished = finished.recv_timeout(WAIT);
        drop(held);
        drop(exchange.join().unwrap());
        assert_eq!(finished, Ok(true), "a send or receive waited on a lock");
    }

    /// A splitmix64 step, for the stress test's yields.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A sender thread and a receiver task on another thread, each yielding
    /// at random: every packet arrives once and in order, and the receiver
    /// is never left asleep with a packet waiting. Half the sends wait for
    /// the receiver to catch up and then a random while, so many land
    /// as the receiver finds its queue empty and parks.
    #[test]
    fn packets_cross_threads_once_in_order_with_no_lost_wake() {
        const PACKETS: u32 = 20_000;
        for seed in 1..=4u64 {
            let (mut a, mut b) = pair();
            let taken = Arc::new(AtomicUsize::new(0));
            let seen = taken.clone();
            let sender = std::thread::spawn(move || {
                let give_up = std::time::Instant::now() + WAIT;
                let mut state = seed;
                for i in 0..PACKETS {
                    let r = next(&mut state);
                    if r.is_multiple_of(2) {
                        while seen.load(Ordering::Acquire) < i as usize
                            && std::time::Instant::now() < give_up
                        {
                            std::thread::yield_now();
                        }
                        for _ in 0..(r >> 54) {
                            std::hint::spin_loop();
                        }
                    } else if r % 8 == 1 {
                        std::thread::yield_now();
                    }
                    b.send(Packet(i.to_le_bytes().to_vec()));
                }
                b
            });
            let (done, finished) = std::sync::mpsc::channel();
            let receiver = std::thread::spawn(move || {
                let out =
                    crate::block_on(crate::run(crate::Seed::from_u64(seed), |fcx| async move {
                        let mut state = seed.wrapping_mul(31);
                        for want in 0..PACKETS {
                            let got = a.recv(&fcx).await?;
                            assert_eq!(got.0, want.to_le_bytes(), "seed {seed}");
                            taken.store(want as usize + 1, Ordering::Release);
                            if next(&mut state).is_multiple_of(4) {
                                std::thread::yield_now();
                            }
                        }
                        Ok(())
                    }));
                done.send(out.map_err(|e| e.to_string())).unwrap();
            });
            let finished = finished.recv_timeout(WAIT);
            assert_eq!(finished, Ok(Ok(())), "seed {seed}: the receiver stalled");
            receiver.join().unwrap();
            drop(sender.join().unwrap());
        }
    }

    /// A cable without a limit keeps no count, and still carries every
    /// packet.
    #[test]
    fn an_unlimited_cable_counts_nothing() {
        let (mut a, mut b) = pair();
        for i in 0..100u32 {
            b.send(Packet(i.to_le_bytes().to_vec()));
        }
        assert_eq!(a.queued(), 0);
        crate::block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
            let mut cx = Context::from_waker(Waker::noop());
            for i in 0..100u32 {
                let Poll::Ready(Ok(got)) = a.poll_recv(&fcx, &mut cx) else {
                    panic!("packet {i} was sent");
                };
                assert_eq!(got.0, i.to_le_bytes());
            }
            assert_eq!(a.queued(), 0);
            drop(b);
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn a_limited_queue_counts_until_the_receiver_takes_the_packet() {
        let limit = 2 * (PACKET_COST + 8);
        let (mut a, mut b) = pair_with_limit(limit);
        let packet = || {
            let mut bytes = Vec::with_capacity(8);
            bytes.push(7);
            Packet(bytes)
        };
        for _ in 0..3 {
            b.send(packet());
        }
        assert!(a.queued() <= limit);
        crate::block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
            let mut cx = Context::from_waker(Waker::noop());
            let mut got = 0;
            while let Poll::Ready(Ok(_)) = a.poll_recv(&fcx, &mut cx) {
                got += 1;
            }
            assert_eq!(got, 2, "the third packet was past the limit");
            assert_eq!(a.queued(), 0);
            b.send(packet());
            assert!(a.queued() > 0);
            Ok(())
        }))
        .unwrap();
    }
}
