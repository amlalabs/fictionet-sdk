//! Ready-slot polling for packet interfaces, deadlines and extra sources.
//!
//! `Ports` waits for packets, closures, a deadline, or a caller-supplied extra
//! source, with bounded work before yielding. It does not read or write
//! protocol values or implement sessions or services. Packet processing belongs
//! to the task that calls it.

use fictionet::sync::{Mutex, MutexGuard};
use std::collections::{BTreeSet, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use fictionet::CancelWait;
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, Interface, Packet, RecvError};

/// How many packets a stdlib task handles in a row before it yields.
pub const BUDGET: usize = 64;

/// What [`Ports::next`] saw.
#[derive(Debug)]
pub enum Event {
    /// A packet arrived on port `.0`.
    Packet(usize, Packet),
    /// Port `.0` closed. [`Ports`] has already dropped it.
    Closed(usize),
    /// The deadline passed.
    Timer,
    /// The extra source given to `next` is ready.
    Extra,
}

/// The interfaces one task serves, and the waiting that is common to all
/// of them. The stdlib's routers, filters and links are built on it, and
/// so can a world's own. It waits for the first packet on any interface, a deadline,
/// or one extra source. It takes interfaces in turn, so that a busy one
/// cannot starve the others. It yields after 64 packets in a row.
///
/// Each interface is polled with its own waker, which puts the interface in
/// a queue of ready interfaces. A turn polls only the interfaces in that
/// queue, so the cost of a packet does not grow with the number of idle
/// interfaces. A
/// router with thousands of routes stays as fast as one with ten.
pub struct Ports<I: Interface> {
    ports: Vec<Option<I>>,
    /// One waker per slot, which marks the slot ready.
    wakers: Vec<Waker>,
    ready: Arc<Ready>,
    /// Closed slots, for reuse.
    free: BTreeSet<usize>,
    /// How many slots hold a port.
    open: usize,
    /// Packets handled since the task last waited or yielded.
    run: usize,
    wait: CancelWait,
}

/// The slots that may have something to say, in the order they spoke up,
/// and the task to wake when one does.
#[derive(Default)]
struct Ready {
    inner: Mutex<ReadyInner>,
}

#[derive(Default)]
struct ReadyInner {
    slots: VecDeque<usize>,
    /// Whether each slot is in `slots`, so that it is there at most once.
    queued: Vec<bool>,
    task: Option<Waker>,
}

impl ReadyInner {
    fn push(&mut self, slot: usize) {
        if self.queued.len() <= slot {
            self.queued.resize(slot + 1, false);
        }
        if !self.queued[slot] {
            self.queued[slot] = true;
            self.slots.push_back(slot);
        }
    }

    fn pop(&mut self) -> Option<usize> {
        let slot = self.slots.pop_front()?;
        self.queued[slot] = false;
        Some(slot)
    }
}

/// The waker of one slot.
struct SlotWaker {
    ready: Arc<Ready>,
    slot: usize,
}

impl Wake for SlotWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let task = {
            let mut r = self.ready.inner.lock();
            r.push(self.slot);
            r.task.take()
        };
        if let Some(task) = task {
            task.wake();
        }
    }
}

impl<I: Interface> Ports<I> {
    /// Serves `ports`, numbered from 0 in order.
    pub fn new(ports: Vec<I>) -> Ports<I> {
        let mut p = Ports {
            ports: Vec::new(),
            wakers: Vec::new(),
            ready: Arc::default(),
            free: BTreeSet::new(),
            open: 0,
            run: 0,
            wait: CancelWait::default(),
        };
        for port in ports {
            p.add(port);
        }
        p
    }

    fn lock_ready(&self) -> MutexGuard<'_, ReadyInner> {
        self.ready.inner.lock()
    }

    /// How many ports are still open.
    pub fn open(&self) -> usize {
        self.open
    }

    /// Whether port `i` is open.
    pub fn is_open(&self, i: usize) -> bool {
        matches!(self.ports.get(i), Some(Some(_)))
    }

    /// Adds a port and returns its index. Reuses a closed slot, the lowest
    /// one first.
    pub fn add(&mut self, port: I) -> usize {
        let i = match self.free.pop_first() {
            Some(i) => i,
            None => {
                let i = self.ports.len();
                self.ports.push(None);
                self.wakers.push(Waker::from(Arc::new(SlotWaker {
                    ready: self.ready.clone(),
                    slot: i,
                })));
                i
            }
        };
        self.ports[i] = Some(port);
        self.open += 1;
        // A new port may already hold packets.
        self.lock_ready().push(i);
        i
    }

    /// Puts `port` at `i`, dropping what was there, which closes its interface.
    pub fn replace(&mut self, i: usize, port: I) {
        let old = self.ports[i].replace(port);
        if old.is_none() {
            self.open += 1;
            self.free.remove(&i);
        }
        drop(old);
        self.lock_ready().push(i);
    }

    /// Drops port `i`, which closes its interface.
    pub fn close(&mut self, i: usize) {
        if let Some(p) = self.ports.get_mut(i)
            && p.take().is_some()
        {
            self.open -= 1;
            self.free.insert(i);
        }
    }

    /// Sends a packet out on port `i`. Lost if the port is closed.
    #[inline]
    pub fn send(&mut self, i: usize, packet: Packet) {
        if let Some(Some(p)) = self.ports.get_mut(i) {
            p.send(packet);
        }
    }

    /// Counts `n` packets handled outside [`next`](Ports::next), such as
    /// packets released by a timer, toward the budget.
    #[inline]
    pub fn spend(&mut self, n: usize) {
        self.run += n;
    }

    /// Waits for the next event: a packet or a close on any port, the
    /// deadline, or `extra` being ready. Yields first if the budget is
    /// spent. Returns early with [`Cancelled`] if `fcx`'s
    /// [region](Cx#regions) is cancelled.
    pub async fn next(
        &mut self,
        fcx: &Cx,
        deadline: Option<Instant>,
        mut extra: impl FnMut(&mut Context<'_>) -> Poll<()>,
    ) -> Result<Event, Cancelled> {
        if self.run >= BUDGET {
            self.run = 0;
            fcx.yield_now().await?;
        }
        if fcx.is_cancelled() {
            return Err(Cancelled);
        }
        if let Some(d) = deadline
            && d <= fcx.now()
        {
            self.run += 1;
            return Ok(Event::Timer);
        }
        let mut sleep = pin!(deadline.map(|d| fcx.sleep_until(d)));
        let mut waited = false;
        let event = poll_fn(|cx| {
            // The extra source first: a router takes new routes before it
            // forwards packets sent after they were added.
            if extra(cx).is_ready() {
                return Poll::Ready(Ok(Event::Extra));
            }
            // Register the task before looking at the queue, so a slot that
            // becomes ready after the queue looked empty still wakes it.
            {
                let mut r = self.lock_ready();
                match &r.task {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => r.task = Some(cx.waker().clone()),
                }
            }
            loop {
                let Some(i) = self.lock_ready().pop() else {
                    break;
                };
                let Some(port) = self.ports[i].as_mut() else {
                    continue;
                };
                let mut slot_cx = Context::from_waker(&self.wakers[i]);
                match port.poll_recv(fcx, &mut slot_cx) {
                    Poll::Ready(Ok(packet)) => {
                        // It may hold more. It goes to the back, after the
                        // others that are ready, so each gets its turn.
                        self.lock_ready().push(i);
                        return Poll::Ready(Ok(Event::Packet(i, packet)));
                    }
                    Poll::Ready(Err(RecvError::Closed)) => {
                        self.close(i);
                        return Poll::Ready(Ok(Event::Closed(i)));
                    }
                    Poll::Ready(Err(RecvError::Cancelled)) => return Poll::Ready(Err(Cancelled)),
                    // Its waker puts it back in the queue when it has more.
                    Poll::Pending => {}
                }
            }
            if let Some(sleep) = sleep.as_mut().as_pin_mut() {
                match sleep.poll(cx) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Ok(Event::Timer)),
                    Poll::Ready(Err(Cancelled)) => return Poll::Ready(Err(Cancelled)),
                    Poll::Pending => {}
                }
            }
            if fcx.register_cancel(cx.waker(), &mut self.wait) {
                return Poll::Ready(Err(Cancelled));
            }
            waited = true;
            Poll::Pending
        })
        .await?;
        if waited {
            self.run = 0;
        }
        self.run += 1;
        Ok(event)
    }
}

fictionet::cfg_std! {
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_ports_reuse_slots_and_keep_event_priority() {
        fictionet::block_on(fictionet::run(fictionet::Seed::random(), |fcx| async move {
            let (a, mut peer) = fictionet::pair();
            let (b, _peer_b) = fictionet::pair();
            let (c, _peer_c) = fictionet::pair();
            let mut ports = Ports::new(vec![a, b, c]);
            peer.send(Packet(vec![1]));
            let now = fcx.now();
            assert!(matches!(ports.next(&fcx, Some(now), |_| Poll::Ready(())).await?, Event::Timer));
            assert!(matches!(ports.next(&fcx, None, |_| Poll::Ready(())).await?, Event::Extra));
            assert!(matches!(ports.next(&fcx, None, |_| Poll::Pending).await?, Event::Packet(0, Packet(p)) if p == [1]));
            ports.close(2);
            ports.close(0);
            let (a, _peer_a) = fictionet::pair();
            let (c, _peer_c) = fictionet::pair();
            assert_eq!(ports.add(a), 0);
            assert_eq!(ports.add(c), 2);
            assert_eq!(ports.open(), 3);
            drop(_peer_a);
            assert!(matches!(ports.next(&fcx, None, |_| Poll::Pending).await?, Event::Closed(0)));
            assert!(!ports.is_open(0));
            Ok(())
        })).unwrap();
    }
}

}
