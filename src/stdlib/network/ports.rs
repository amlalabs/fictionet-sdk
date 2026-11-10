//! Ready-slot polling for packet interfaces, deadlines and extra sources.
//!
//! `Ports` waits for packets, closures, a deadline, or a caller-supplied extra
//! source, with bounded work before yielding. It does not read or write
//! protocol values or implement sessions or services. Packet processing belongs
//! to the task that calls it.

use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use crate::sync::Parked;
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
/// Each interface is polled with its own waker, which sets the interface's
/// bit in a bitmap of ready interfaces, with no lock. A turn polls only the
/// interfaces whose bit is set, in order of their numbers from after the
/// last one served, so the cost of a packet does not grow with the number
/// of idle interfaces. A
/// router with thousands of routes stays as fast as one with ten.
pub struct Ports<I: Interface> {
    ports: Vec<Option<I>>,
    /// One waker per slot, which marks the slot ready.
    wakers: Vec<Waker>,
    ready: Ready,
    /// The task that serves the ports, once it found nothing to do.
    task: Arc<Parked>,
    /// Where the next search for a ready slot starts: after the slot served
    /// last.
    cursor: usize,
    /// Closed slots, for reuse.
    free: BTreeSet<usize>,
    /// How many slots hold a port.
    open: usize,
    /// Packets handled since the task last waited or yielded.
    run: usize,
    wait: CancelWait,
}

/// The slots that may have something to say: one bit per slot, in words of
/// 64, and one summary bit per word, which is set while the word may have a
/// bit set. A search reads the summary first, so it skips 4,096 idle slots
/// in one load. Only [`Ports`] grows the lists; the slot wakers hold their
/// own words.
#[derive(Default)]
struct Ready {
    /// `words[w]` holds the bits of slots `64 w` to `64 w + 63`.
    words: Vec<Arc<AtomicU64>>,
    /// `summary[s]` holds the bits of words `64 s` to `64 s + 63`.
    summary: Vec<Arc<AtomicU64>>,
}

/// One slot's bit and its word's summary bit.
struct Mark {
    word: Arc<AtomicU64>,
    bit: u64,
    summary: Arc<AtomicU64>,
    summary_bit: u64,
}

impl Mark {
    /// Sets the slot's bit, then its word's summary bit, so that a search
    /// that finds the summary bit finds the slot's bit too.
    fn set(&self) {
        self.word.fetch_or(self.bit, Ordering::Release);
        self.summary.fetch_or(self.summary_bit, Ordering::Release);
    }
}

impl Ready {
    /// The bit of slot `i`, which must exist.
    fn mark(&self, i: usize) -> Mark {
        let w = i / 64;
        Mark {
            word: self.words[w].clone(),
            bit: 1 << (i % 64),
            summary: self.summary[w / 64].clone(),
            summary_bit: 1 << (w % 64),
        }
    }

    /// Makes room for slot `i`, the next slot after the last.
    fn grow(&mut self, i: usize) {
        if i.is_multiple_of(64) {
            if self.words.len().is_multiple_of(64) {
                self.summary.push(Arc::default());
            }
            self.words.push(Arc::default());
        }
    }

    fn set(&self, i: usize) {
        let w = i / 64;
        self.words[w].fetch_or(1 << (i % 64), Ordering::Release);
        self.summary[w / 64].fetch_or(1 << (w % 64), Ordering::Release);
    }

    /// Clears slot `i`'s bit, and its word's summary bit if the word is
    /// left empty. A waker that sets a bit in that word meanwhile sets the
    /// summary bit after, or this sees its bit and sets the summary again.
    fn clear(&self, i: usize) {
        let w = i / 64;
        let bit = 1 << (i % 64);
        if self.words[w].fetch_and(!bit, Ordering::AcqRel) & !bit != 0 {
            return;
        }
        let summary = &self.summary[w / 64];
        let summary_bit = 1 << (w % 64);
        summary.fetch_and(!summary_bit, Ordering::AcqRel);
        if self.words[w].load(Ordering::Acquire) != 0 {
            summary.fetch_or(summary_bit, Ordering::Release);
        }
    }

    /// The first slot at or after `from` whose bit is set, wrapping around
    /// once to the slots before `from`.
    fn find(&self, from: usize) -> Option<usize> {
        let slots = self.words.len() * 64;
        if slots == 0 {
            return None;
        }
        let from = from % slots;
        self.find_in(from, slots).or_else(|| self.find_in(0, from))
    }

    /// The first set bit in slots `lo..hi`.
    fn find_in(&self, lo: usize, hi: usize) -> Option<usize> {
        if lo >= hi {
            return None;
        }
        let last = (hi - 1) / 64;
        let mut w = lo / 64;
        while w <= last {
            let above = self.summary[w / 64].load(Ordering::Acquire) >> (w % 64);
            if above == 0 {
                w = (w / 64 + 1) * 64;
                continue;
            }
            w += above.trailing_zeros() as usize;
            if w > last {
                return None;
            }
            let mut bits = self.words[w].load(Ordering::Acquire);
            if w == lo / 64 {
                bits &= u64::MAX << (lo % 64);
            }
            if w == last && !hi.is_multiple_of(64) {
                bits &= (1 << (hi % 64)) - 1;
            }
            if bits != 0 {
                return Some(w * 64 + bits.trailing_zeros() as usize);
            }
            w += 1;
        }
        None
    }
}

/// The waker of one slot.
struct SlotWaker {
    mark: Mark,
    task: Arc<Parked>,
}

impl Wake for SlotWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.mark.set();
        self.task.wake();
    }
}

impl<I: Interface> Ports<I> {
    /// Serves `ports`, numbered from 0 in order.
    pub fn new(ports: Vec<I>) -> Ports<I> {
        let mut p = Ports {
            ports: Vec::new(),
            wakers: Vec::new(),
            ready: Ready::default(),
            task: Arc::default(),
            cursor: 0,
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
                self.ready.grow(i);
                self.wakers.push(Waker::from(Arc::new(SlotWaker {
                    mark: self.ready.mark(i),
                    task: self.task.clone(),
                })));
                i
            }
        };
        self.ports[i] = Some(port);
        self.open += 1;
        // A new port may already hold packets.
        self.ready.set(i);
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
        self.ready.set(i);
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

    /// Polls the ready slots in turn, from after the one served last, until
    /// one has a packet or a close. `None` once no bit is set.
    fn serve(&mut self, fcx: &Cx) -> Option<Result<Event, Cancelled>> {
        while let Some(i) = self.ready.find(self.cursor) {
            self.ready.clear(i);
            self.cursor = i + 1;
            let Some(port) = self.ports[i].as_mut() else {
                continue;
            };
            let mut slot_cx = Context::from_waker(&self.wakers[i]);
            match port.poll_recv(fcx, &mut slot_cx) {
                Poll::Ready(Ok(packet)) => {
                    // It may hold more. The next search starts after it, so
                    // the others that are ready each get their turn first.
                    self.ready.set(i);
                    return Some(Ok(Event::Packet(i, packet)));
                }
                Poll::Ready(Err(RecvError::Closed)) => {
                    self.close(i);
                    return Some(Ok(Event::Closed(i)));
                }
                Poll::Ready(Err(RecvError::Cancelled)) => return Some(Err(Cancelled)),
                // Its waker sets its bit again when it has more.
                Poll::Pending => {}
            }
        }
        None
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
            if let Some(event) = self.serve(fcx) {
                return Poll::Ready(event);
            }
            // Nothing is ready: leave the task's waker, then look once more,
            // so a slot woken in between is either seen here or wakes the
            // task.
            self.task.park(cx.waker());
            if let Some(event) = self.serve(fcx) {
                return Poll::Ready(event);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn replacing_the_task_releases_its_waker_outside_the_lock() {
        use std::sync::Weak;
        use std::sync::atomic::AtomicBool;

        struct CheckDrop(Weak<Parked>, Arc<AtomicBool>);
        impl Wake for CheckDrop {
            fn wake(self: Arc<Self>) {
                panic!("replacing a waiter must not wake it");
            }
        }
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                assert!(self.0.upgrade().unwrap().try_lock().is_some());
                self.1.store(true, Ordering::SeqCst);
            }
        }

        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(0),
            |fcx| async move {
                let (port, _peer) = fictionet::pair();
                let mut ports = Ports::new(vec![port]);
                let dropped = Arc::new(AtomicBool::new(false));
                let waker = Waker::from(Arc::new(CheckDrop(
                    Arc::downgrade(&ports.task),
                    dropped.clone(),
                )));
                {
                    let mut next = pin!(ports.next(&fcx, None, |_| Poll::Pending));
                    assert!(
                        next.as_mut()
                            .poll(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                }
                drop(waker);
                assert!(
                    !dropped.load(Ordering::SeqCst),
                    "the task's waker is parked"
                );
                let mut next = pin!(ports.next(&fcx, None, |_| Poll::Pending));
                assert!(
                    next.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                assert!(dropped.load(Ordering::SeqCst));
                Ok(())
            },
        ))
        .unwrap();
    }

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

    /// A splitmix64 step.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Polls `ports.next` with no waker to speak of. `None` when it waits.
    fn poll_next(ports: &mut Ports<fictionet::End>, fcx: &Cx) -> Option<Event> {
        // A first Pending can be the budget's yield; a fresh call does not
        // yield again.
        for _ in 0..2 {
            let mut next = pin!(ports.next(fcx, None, |_| Poll::Pending));
            if let Poll::Ready(event) = next.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            {
                return Some(event.unwrap());
            }
        }
        None
    }

    /// Packets sent at random to ports at random, against a model of what
    /// each port holds: each packet comes out once, in its port's order; a
    /// port with a packet waiting sees at most one turn of every other open
    /// port before its own; and `next` waits only when no port holds
    /// anything. Port counts cross a word (64) and a summary word (4,096).
    #[test]
    fn every_waiting_port_is_served_within_one_turn_of_the_others() {
        for (seed, n) in [
            (1u64, 1usize),
            (2, 3),
            (3, 64),
            (4, 65),
            (5, 130),
            (6, 4100),
        ] {
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(seed),
                move |fcx| async move {
                    let mut peers = Vec::new();
                    let mut ends = Vec::new();
                    for _ in 0..n {
                        let (end, peer) = fictionet::pair();
                        ends.push(end);
                        peers.push(peer);
                    }
                    let mut ports = Ports::new(ends);
                    let mut state = seed;
                    let mut sent = vec![0u32; n];
                    let mut taken = vec![0u32; n];
                    // Other ports served since this one last was, while it held
                    // a packet.
                    let mut passed = vec![0usize; n];
                    for _ in 0..20_000 {
                        let r = next(&mut state);
                        if !r.is_multiple_of(3) {
                            let p = (r >> 8) as usize % n;
                            peers[p].send(Packet(sent[p].to_le_bytes().to_vec()));
                            sent[p] += 1;
                            continue;
                        }
                        match poll_next(&mut ports, &fcx) {
                            Some(Event::Packet(p, packet)) => {
                                assert_eq!(packet.0, taken[p].to_le_bytes(), "port {p}");
                                taken[p] += 1;
                                passed[p] = 0;
                                for q in (0..n).filter(|&q| q != p && sent[q] > taken[q]) {
                                    passed[q] += 1;
                                    assert!(passed[q] < n, "port {q} waited past a turn of {n}");
                                }
                            }
                            Some(other) => panic!("only packets were sent: {other:?}"),
                            None => assert_eq!(sent, taken, "next waited with packets queued"),
                        }
                    }
                    Ok(())
                },
            ))
            .unwrap();
        }
    }

    /// Senders on another thread, sending to ports at random with random
    /// pauses, and the task serving them on its own thread: every packet
    /// arrives once, in its port's order, and the task is never left asleep
    /// with a slot ready. Half the sends wait for the task to catch up and
    /// then a random while, so many land as the task parks.
    #[test]
    fn ports_across_threads_lose_no_wake() {
        use std::sync::atomic::AtomicUsize;
        const PACKETS: usize = 20_000;
        for (seed, n) in [(1u64, 2usize), (2, 70), (3, 200)] {
            let mut ends = Vec::new();
            let mut peers = Vec::new();
            for _ in 0..n {
                let (end, peer) = fictionet::pair();
                ends.push(end);
                peers.push(peer);
            }
            let taken = Arc::new(AtomicUsize::new(0));
            let seen = taken.clone();
            let sender = std::thread::spawn(move || {
                let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut state = seed;
                let mut sent = vec![0u32; n];
                for i in 0..PACKETS {
                    let r = next(&mut state);
                    if r.is_multiple_of(2) {
                        while seen.load(Ordering::Acquire) < i
                            && std::time::Instant::now() < give_up
                        {
                            std::thread::yield_now();
                        }
                        for _ in 0..(r >> 57) {
                            std::hint::spin_loop();
                        }
                    }
                    let p = (r >> 8) as usize % n;
                    peers[p].send(Packet(sent[p].to_le_bytes().to_vec()));
                    sent[p] += 1;
                }
                peers
            });
            let (done, finished) = std::sync::mpsc::channel();
            let task = std::thread::spawn(move || {
                let out = fictionet::block_on(fictionet::run(
                    fictionet::Seed::from_u64(seed),
                    move |fcx| async move {
                        let mut ports = Ports::new(ends);
                        let mut got = vec![0u32; n];
                        for i in 0..PACKETS {
                            match ports.next(&fcx, None, |_| Poll::Pending).await? {
                                Event::Packet(p, packet) => {
                                    assert_eq!(packet.0, got[p].to_le_bytes(), "port {p}");
                                    got[p] += 1;
                                }
                                other => panic!("only packets were sent: {other:?}"),
                            }
                            taken.store(i + 1, Ordering::Release);
                        }
                        Ok(())
                    },
                ));
                done.send(out.map_err(|e| e.to_string())).unwrap();
            });
            let finished = finished.recv_timeout(std::time::Duration::from_secs(10));
            assert_eq!(finished, Ok(Ok(())), "seed {seed}: the task stalled");
            task.join().unwrap();
            drop(sender.join().unwrap());
        }
    }

    /// While packets are waiting, `next` takes no lock: it serves them all
    /// with the task's lock held elsewhere.
    #[test]
    fn busy_ports_take_no_lock() {
        const EACH: u32 = 300;
        let mut ends = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..70 {
            let (end, mut peer) = fictionet::pair();
            for i in 0..EACH {
                peer.send(Packet(i.to_le_bytes().to_vec()));
            }
            ends.push(end);
            peers.push(peer);
        }
        let ports = Ports::new(ends);
        let task = ports.task.clone();
        let held = task.try_lock().unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        let back = Arc::new(Mutex::new(None));
        let out = back.clone();
        let serve = std::thread::spawn(move || {
            let result = fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(0),
                move |fcx| async move {
                    let mut ports = ports;
                    for _ in 0..70 * EACH {
                        let event = ports.next(&fcx, None, |_| Poll::Pending).await?;
                        assert!(matches!(event, Event::Packet(..)));
                    }
                    // Dropping the ports would park nothing, but keep them
                    // whole for the test to drop after it lets go.
                    *out.lock().unwrap() = Some(ports);
                    Ok(())
                },
            ));
            done.send(result.is_ok()).unwrap();
        });
        let finished = finished.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        serve.join().unwrap();
        drop(back.lock().unwrap().take());
        drop(peers);
        assert_eq!(finished, Ok(true), "next waited on the task's lock");
    }
}
