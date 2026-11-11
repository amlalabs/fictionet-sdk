//! Frames between the AF_XDP rings and the world's attachment queues.
//!
//! The UMEM is split in two fixed sets of 4 KiB frames. Receive frames
//! circulate between the fill ring, the kernel and the RX ring: each one
//! the RX ring hands over is copied out and goes straight back to the fill
//! ring, so no receive frame is ever held. Transmit frames sit on a free
//! list until a world frame is copied into one and posted on the TX ring;
//! the completion ring returns it. A frame is in exactly one of those
//! places at a time.

use std::fmt;
use std::ops::Range;
use std::ptr::NonNull;
use std::task::{Context, Poll};
use std::time::SystemTime;

use super::ring::{Consumer, Desc, Producer};
use crate::raw::{Command, Driver, EthernetFrame, MAX_FRAME, ReceivedFrame};

/// Bytes per UMEM frame. Amazon's ENA driver supports only 4 KiB AF_XDP
/// buffers.
pub(crate) const FRAME_SIZE: u32 = 4096;
/// Frames that carry received traffic.
pub(crate) const RX_FRAMES: u32 = 512;
/// Frames that carry transmitted traffic.
pub(crate) const TX_FRAMES: u32 = 512;
/// Slots in each of the four rings. The fill and TX rings can hold every
/// frame of their set, so returning a frame never finds them full.
pub(crate) const RING_SIZE: u32 = 512;
/// Bytes of the whole UMEM.
pub(crate) const UMEM_LEN: usize = (RX_FRAMES + TX_FRAMES) as usize * FRAME_SIZE as usize;
/// Received frames handled per step before the pump turns to transmit.
const RX_BATCH: usize = 64;
/// The smallest frame the attachment carries: an Ethernet header.
const MIN_FRAME: u32 = 14;

const _: () = assert!(RX_FRAMES <= RING_SIZE && TX_FRAMES <= RING_SIZE);
const _: () = assert!(MAX_FRAME as u32 <= FRAME_SIZE);

/// The four rings of one socket.
pub(crate) struct Rings {
    pub fill: Producer<u64>,
    pub rx: Consumer<Desc>,
    pub tx: Producer<Desc>,
    pub completion: Consumer<u64>,
}

/// A ring entry the kernel should never produce. The pump stops on one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// An RX descriptor outside the receive frames, or crossing a frame.
    Receive(Desc),
    /// A completion for a frame that was not in flight.
    Completion(u64),
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Receive(desc) => write!(
                f,
                "AF_XDP RX descriptor outside the receive frames: address {:#x}, length {}",
                desc.addr, desc.len
            ),
            Self::Completion(addr) => write!(
                f,
                "AF_XDP completion for a frame not in flight: address {addr:#x}"
            ),
        }
    }
}

impl std::error::Error for Fault {}

/// What one step did, for the pump's wait and wakeup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Step {
    /// The world's side is gone; the pump should stop.
    pub closed: bool,
    /// The RX ring may hold more frames than this step took.
    pub more_rx: bool,
    /// The TX ring holds descriptors the kernel has not taken, and it
    /// asked to be woken with `sendto`.
    pub kick: bool,
    /// A world frame or flush waits on transmit completions, which the
    /// socket does not signal through `poll`.
    pub awaiting_completion: bool,
}

/// The rings, the UMEM, and which transmit frames are free.
pub(crate) struct Datapath {
    rings: Rings,
    umem: NonNull<u8>,
    /// Transmit frames not in flight.
    tx_free: Vec<u64>,
    /// For each transmit frame, whether it is on the TX ring or waiting
    /// for its completion.
    in_flight: Vec<bool>,
    in_flight_count: u32,
    /// A command that waits for a transmit frame or for completions.
    pending: Option<Command>,
    /// Received frames discarded because their length was outside what the
    /// attachment carries.
    discarded: u64,
}

// SAFETY: the UMEM pointer refers to memory the socket owner keeps mapped
// for the datapath's life (contract of `Datapath::new`), touched only by
// the thread that owns the datapath and by the kernel under the ring
// protocol.
unsafe impl Send for Datapath {}

impl Datapath {
    /// Takes the rings and puts every receive frame on the fill ring.
    ///
    /// # Safety
    ///
    /// `umem` must point to [`UMEM_LEN`] bytes, valid for reads and writes
    /// for the life of the datapath, that the kernel reads and writes only
    /// as the rings direct, and that nothing else references.
    pub unsafe fn new(mut rings: Rings, umem: NonNull<u8>) -> Self {
        for frame in 0..RX_FRAMES {
            let pushed = rings.fill.push(u64::from(frame * FRAME_SIZE));
            assert!(pushed, "the fill ring holds every receive frame");
        }
        rings.fill.submit();
        let tx_free = (RX_FRAMES..RX_FRAMES + TX_FRAMES)
            .rev()
            .map(|frame| u64::from(frame * FRAME_SIZE))
            .collect();
        Self {
            rings,
            umem,
            tx_free,
            in_flight: vec![false; TX_FRAMES as usize],
            in_flight_count: 0,
            pending: None,
            discarded: 0,
        }
    }

    /// Received frames discarded for their length, since the start.
    pub fn discarded(&self) -> u64 {
        self.discarded
    }

    /// Reclaims completed transmit frames, moves received frames to the
    /// world, and moves world frames to the TX ring.
    pub fn step(&mut self, driver: &mut Driver, cx: &mut Context<'_>) -> Result<Step, Fault> {
        self.reclaim()?;
        let mut step = Step::default();
        let received = self.receive(driver)?;
        step.more_rx = received.taken == RX_BATCH;
        step.closed = received.closed || self.transmit(driver, cx);
        step.kick = self.rings.tx.outstanding() > 0 && self.rings.tx.needs_wakeup();
        step.awaiting_completion = self.pending.is_some() && self.in_flight_count > 0;
        Ok(step)
    }

    fn receive_range() -> Range<u64> {
        0..u64::from(RX_FRAMES * FRAME_SIZE)
    }

    fn transmit_range() -> Range<u64> {
        u64::from(RX_FRAMES * FRAME_SIZE)..UMEM_LEN as u64
    }

    fn reclaim(&mut self) -> Result<(), Fault> {
        while let Some(addr) = self.rings.completion.pop() {
            let slot = Self::transmit_range()
                .contains(&addr)
                .then(|| (addr - Self::transmit_range().start) / u64::from(FRAME_SIZE))
                .filter(|_| addr % u64::from(FRAME_SIZE) == 0)
                .map(|slot| slot as usize)
                .filter(|&slot| self.in_flight[slot])
                .ok_or(Fault::Completion(addr))?;
            self.in_flight[slot] = false;
            self.in_flight_count -= 1;
            self.tx_free.push(addr);
        }
        self.rings.completion.release();
        Ok(())
    }

    fn receive(&mut self, driver: &Driver) -> Result<Received, Fault> {
        let mut received = Received::default();
        while received.taken < RX_BATCH {
            let Some(desc) = self.rings.rx.pop() else {
                break;
            };
            received.taken += 1;
            let frame_start = desc.addr - desc.addr % u64::from(FRAME_SIZE);
            let end = desc.addr.checked_add(u64::from(desc.len));
            if !Self::receive_range().contains(&desc.addr)
                || end.is_none_or(|end| end > frame_start + u64::from(FRAME_SIZE))
            {
                return Err(Fault::Receive(desc));
            }
            if (MIN_FRAME..=MAX_FRAME as u32).contains(&desc.len) && !received.closed {
                let bytes = self.bytes(desc.addr, desc.len).to_vec();
                let frame = ReceivedFrame {
                    frame: EthernetFrame(bytes),
                    received_at: Some(SystemTime::now()),
                };
                // A full queue counts the frame in the receive stats.
                received.closed = driver
                    .receive_stats
                    .enqueue(&driver.incoming, frame)
                    .is_err();
            } else if !received.closed {
                self.discarded += 1;
            }
            let pushed = self.rings.fill.push(frame_start);
            assert!(pushed, "the fill ring holds every receive frame");
        }
        self.rings.rx.release();
        self.rings.fill.submit();
        Ok(received)
    }

    /// Posts world frames until the world has none, a frame waits for a
    /// transmit frame, or a flush waits for completions. Returns whether
    /// the world's sending side is gone.
    fn transmit(&mut self, driver: &mut Driver, cx: &mut Context<'_>) -> bool {
        let mut posted = false;
        let mut closed = false;
        loop {
            let command = match self.pending.take() {
                Some(command) => command,
                None => match driver.outgoing.poll_recv(cx) {
                    Poll::Ready(Some(command)) => command,
                    Poll::Ready(None) => {
                        closed = true;
                        break;
                    }
                    Poll::Pending => break,
                },
            };
            match command {
                Command::Frame(frame) => {
                    let Some(addr) = self.tx_free.pop() else {
                        self.pending = Some(Command::Frame(frame));
                        break;
                    };
                    let len = frame.0.len() as u32;
                    self.bytes_mut(addr, len).copy_from_slice(&frame.0);
                    let pushed = self.rings.tx.push(Desc {
                        addr,
                        len,
                        options: 0,
                    });
                    assert!(pushed, "the TX ring holds every transmit frame");
                    let slot =
                        ((addr - Self::transmit_range().start) / u64::from(FRAME_SIZE)) as usize;
                    self.in_flight[slot] = true;
                    self.in_flight_count += 1;
                    posted = true;
                }
                Command::Flush(done) => {
                    if self.in_flight_count == 0 {
                        let _ = done.send(());
                    } else {
                        self.pending = Some(Command::Flush(done));
                        break;
                    }
                }
            }
        }
        if posted {
            self.rings.tx.submit();
        }
        closed
    }

    fn bytes(&self, addr: u64, len: u32) -> &[u8] {
        debug_assert!(addr + u64::from(len) <= UMEM_LEN as u64);
        // SAFETY: callers pass a range inside one frame of the UMEM
        // (checked against the frame sets above). The frame was handed to
        // us by the RX ring and is not on the fill ring, so the kernel does
        // not write it while the slice lives.
        unsafe { std::slice::from_raw_parts(self.umem.as_ptr().add(addr as usize), len as usize) }
    }

    fn bytes_mut(&mut self, addr: u64, len: u32) -> &mut [u8] {
        debug_assert!(addr + u64::from(len) <= UMEM_LEN as u64);
        // SAFETY: `addr` is a free transmit frame and `len` is at most
        // MAX_FRAME, under FRAME_SIZE. A free frame is on no ring, so
        // neither the kernel nor any other slice touches it.
        unsafe {
            std::slice::from_raw_parts_mut(self.umem.as_ptr().add(addr as usize), len as usize)
        }
    }

    #[cfg(test)]
    fn tx_free(&self) -> &[u64] {
        &self.tx_free
    }

    #[cfg(test)]
    fn in_flight(&self) -> Vec<u64> {
        (0..TX_FRAMES as u64)
            .filter(|&slot| self.in_flight[slot as usize])
            .map(|slot| Self::transmit_range().start + slot * u64::from(FRAME_SIZE))
            .collect()
    }
}

#[derive(Default)]
struct Received {
    taken: usize,
    closed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::QueueStats;
    use crate::xdp::ring::double::RingMemory;
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{mpsc, oneshot};

    /// Copy mode puts XDP's headroom before the frame in each buffer.
    const HEADROOM: u64 = 256;
    /// Frames each attachment queue holds, as in `raw`.
    const WORLD_QUEUE: usize = 64;

    /// The kernel's side of one socket, over heap memory.
    struct Kernel {
        umem: NonNull<u8>,
        fill: Consumer<u64>,
        rx: Producer<Desc>,
        tx: Consumer<Desc>,
        completion: Producer<u64>,
        /// Fill entries taken and not yet used for a frame.
        held: Vec<u64>,
        /// TX descriptors taken and not yet completed.
        sending: Vec<Desc>,
        // Declared last so the rings above never outlive their memory.
        _memory: [RingMemory; 4],
    }

    impl Kernel {
        fn take_fill(&mut self) {
            while let Some(addr) = self.fill.pop() {
                self.held.push(addr);
            }
            self.fill.release();
        }

        fn deliver(&mut self, bytes: &[u8]) -> bool {
            if self.held.is_empty() {
                self.take_fill();
            }
            let Some(addr) = self.held.pop() else {
                return false;
            };
            let addr = addr + HEADROOM;
            // SAFETY: the frame came from the fill ring, so the datapath
            // does not touch it; the write stays inside the frame.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    self.umem.as_ptr().add(addr as usize),
                    bytes.len(),
                )
            };
            assert!(self.rx.push(Desc {
                addr,
                len: bytes.len() as u32,
                options: 0
            }));
            self.rx.submit();
            true
        }

        /// Takes every posted TX descriptor and returns its bytes.
        fn take_tx(&mut self) -> Vec<Vec<u8>> {
            let mut frames = Vec::new();
            while let Some(desc) = self.tx.pop() {
                // SAFETY: a posted frame is not written by the datapath
                // until its completion.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        self.umem.as_ptr().add(desc.addr as usize),
                        desc.len as usize,
                    )
                };
                frames.push(bytes.to_vec());
                self.sending.push(desc);
            }
            self.tx.release();
            frames
        }

        fn complete(&mut self, count: usize) {
            for desc in self.sending.drain(..count.min(self.sending.len())) {
                assert!(self.completion.push(desc.addr));
            }
            self.completion.submit();
        }
    }

    /// A datapath between a kernel double and the world's two queues.
    struct Setup {
        datapath: Datapath,
        kernel: Kernel,
        driver: Driver,
        /// What the world receives.
        to_world: mpsc::Receiver<ReceivedFrame>,
        /// What the world sends.
        from_world: Option<mpsc::Sender<Command>>,
        _umem: Box<[u8]>,
    }

    fn setup() -> Setup {
        let memory = [
            RingMemory::new::<u64>(RING_SIZE, 0),
            RingMemory::new::<Desc>(RING_SIZE, 0),
            RingMemory::new::<Desc>(RING_SIZE, u32::MAX - 100),
            RingMemory::new::<u64>(RING_SIZE, u32::MAX - 100),
        ];
        // Copy mode always asks for a TX wakeup.
        memory[2].set_need_wakeup(true);
        let mut umem = vec![0u8; UMEM_LEN].into_boxed_slice();
        let base = NonNull::new(umem.as_mut_ptr()).unwrap();
        let rings = Rings {
            fill: memory[0].producer(),
            rx: memory[1].consumer(),
            tx: memory[2].producer(),
            completion: memory[3].consumer(),
        };
        let kernel = Kernel {
            fill: memory[0].consumer(),
            rx: memory[1].producer(),
            tx: memory[2].consumer(),
            completion: memory[3].producer(),
            umem: base,
            held: Vec::new(),
            sending: Vec::new(),
            _memory: memory,
        };
        // SAFETY: `umem` is UMEM_LEN bytes that outlive the datapath in
        // `Setup`, and only the kernel double touches it otherwise.
        let datapath = unsafe { Datapath::new(rings, base) };
        let (incoming, to_world) = mpsc::channel(WORLD_QUEUE);
        let (from_world, outgoing) = mpsc::channel(WORLD_QUEUE);
        let driver = Driver {
            incoming,
            outgoing,
            receive_stats: QueueStats::default(),
            failure: Arc::new(Mutex::new(None)),
        };
        Setup {
            datapath,
            kernel,
            driver,
            to_world,
            from_world: Some(from_world),
            _umem: umem,
        }
    }

    impl Setup {
        fn try_step(&mut self) -> Result<Step, Fault> {
            self.datapath.step(
                &mut self.driver,
                &mut Context::from_waker(std::task::Waker::noop()),
            )
        }

        fn step(&mut self) -> Step {
            self.try_step().unwrap()
        }

        /// Queues a world frame if there is room.
        fn send(&self, bytes: Vec<u8>) -> bool {
            self.from_world
                .as_ref()
                .unwrap()
                .try_send(Command::Frame(EthernetFrame(bytes)))
                .is_ok()
        }

        /// Every frame the kernel holds, the datapath frees or has in
        /// flight, checked at a point where the kernel took the TX ring and
        /// the datapath reclaimed every completion.
        fn assert_ledger(&mut self) {
            let kernel = &mut self.kernel;
            kernel.take_fill();
            let receive: BTreeSet<u64> = kernel.held.iter().copied().collect();
            assert_eq!(kernel.held.len(), receive.len(), "no receive frame twice");
            let expected_rx: BTreeSet<u64> = (0..RX_FRAMES)
                .map(|frame| u64::from(frame * FRAME_SIZE))
                .collect();
            assert_eq!(
                receive, expected_rx,
                "every receive frame is back with the kernel"
            );

            assert_eq!(kernel.tx.pop(), None, "the kernel took every posted frame");
            assert_eq!(kernel.completion.outstanding(), 0, "completions reclaimed");
            let free = self.datapath.tx_free().to_vec();
            let flying = self.datapath.in_flight();
            let mut all: Vec<u64> = free.iter().chain(&flying).copied().collect();
            all.sort();
            let expected_tx: Vec<u64> = (RX_FRAMES..RX_FRAMES + TX_FRAMES)
                .map(|frame| u64::from(frame * FRAME_SIZE))
                .collect();
            assert_eq!(
                all, expected_tx,
                "transmit frames are free or in flight, once"
            );
            let mut sending: Vec<u64> = kernel.sending.iter().map(|desc| desc.addr).collect();
            sending.sort();
            assert_eq!(sending, flying, "in flight means the kernel is sending it");
        }
    }

    fn frame(tag: u16, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        bytes[..2].copy_from_slice(&tag.to_be_bytes());
        bytes
    }

    #[test]
    fn received_frames_reach_the_world_and_their_buffers_return() {
        let mut setup = setup();
        let length = |tag: u16| 60 + usize::from(tag % 1400);
        let mut sent = 0u16;
        let mut seen = 0u16;
        // More frames than the receive set, in rounds the world drains.
        for _ in 0..40 {
            for _ in 0..30 {
                assert!(setup.kernel.deliver(&frame(sent, length(sent))));
                sent += 1;
            }
            assert!(!setup.step().closed);
            while let Ok(received) = setup.to_world.try_recv() {
                assert_eq!(received.frame.0, frame(seen, length(seen)));
                assert!(received.received_at.is_some());
                seen += 1;
            }
            setup.assert_ledger();
        }
        assert_eq!(seen, sent);
        assert!(u32::from(sent) > RX_FRAMES, "buffers were reused");
        assert_eq!(setup.driver.receive_stats.queue_dropped(), 0);
    }

    #[test]
    fn a_full_world_queue_counts_drops_and_still_returns_buffers() {
        let mut setup = setup();
        for tag in 0..200 {
            assert!(setup.kernel.deliver(&frame(tag, 64)));
        }
        while setup.step().more_rx {}
        assert_eq!(
            setup.driver.receive_stats.queue_dropped(),
            200 - WORLD_QUEUE as u64
        );
        setup.assert_ledger();
    }

    #[test]
    fn frames_outside_the_attachment_bounds_are_counted_not_passed() {
        let mut setup = setup();
        assert!(setup.kernel.deliver(&frame(1, 13)));
        assert!(setup.kernel.deliver(&frame(2, MAX_FRAME + 1)));
        assert!(setup.kernel.deliver(&frame(3, 14)));
        setup.step();
        assert_eq!(setup.datapath.discarded(), 2);
        assert_eq!(setup.to_world.try_recv().unwrap().frame.0, frame(3, 14));
        assert!(setup.to_world.try_recv().is_err());
        setup.assert_ledger();
    }

    #[test]
    fn world_frames_go_out_and_flush_waits_for_completion() {
        let mut setup = setup();
        for tag in 0..10 {
            assert!(setup.send(frame(tag, 100)));
        }
        assert!(
            setup.step().kick,
            "posted frames need a sendto in copy mode"
        );
        let sent = setup.kernel.take_tx();
        assert_eq!(sent, (0..10).map(|tag| frame(tag, 100)).collect::<Vec<_>>());
        setup.assert_ledger();

        let (done, mut flushed) = oneshot::channel();
        assert!(
            setup
                .from_world
                .as_ref()
                .unwrap()
                .try_send(Command::Flush(done))
                .is_ok()
        );
        assert!(setup.step().awaiting_completion);
        assert!(flushed.try_recv().is_err(), "flush waits for completions");
        setup.kernel.complete(4);
        setup.step();
        assert!(flushed.try_recv().is_err());
        setup.kernel.complete(6);
        assert!(!setup.step().awaiting_completion);
        assert!(
            flushed.try_recv().is_ok(),
            "done once every frame completed"
        );
        assert_eq!(setup.datapath.tx_free().len(), TX_FRAMES as usize);
        setup.assert_ledger();
    }

    #[test]
    fn transmit_waits_for_frames_when_all_are_in_flight() {
        let mut setup = setup();
        let mut queued = 0u16;
        let mut posted = Vec::new();
        // Keep the world's queue topped up; the kernel never completes.
        loop {
            while setup.send(frame(queued, 64)) {
                queued += 1;
            }
            let before = posted.len();
            setup.step();
            posted.extend(setup.kernel.take_tx());
            setup.assert_ledger();
            if posted.len() == before {
                break;
            }
        }
        assert_eq!(posted.len(), TX_FRAMES as usize);
        assert!(setup.step().awaiting_completion);
        setup.kernel.complete(40);
        setup.step();
        posted.extend(setup.kernel.take_tx());
        assert_eq!(posted.len(), TX_FRAMES as usize + 40);
        for (tag, bytes) in posted.iter().enumerate() {
            assert_eq!(*bytes, frame(tag as u16, 64), "order is kept");
        }
        setup.assert_ledger();
    }

    #[test]
    fn closing_the_world_ends_the_step_loop() {
        let mut setup = setup();
        assert!(!setup.step().closed);
        setup.from_world = None;
        assert!(setup.step().closed);
    }

    #[test]
    fn a_completion_for_a_free_frame_is_a_fault() {
        let mut setup = setup();
        let free = setup.datapath.tx_free()[0];
        assert!(setup.kernel.completion.push(free));
        setup.kernel.completion.submit();
        assert_eq!(setup.try_step(), Err(Fault::Completion(free)));
    }

    #[test]
    fn an_rx_descriptor_outside_the_receive_frames_is_a_fault() {
        let mut setup = setup();
        let desc = Desc {
            addr: Datapath::transmit_range().start,
            len: 64,
            options: 0,
        };
        assert!(setup.kernel.rx.push(desc));
        setup.kernel.rx.submit();
        assert_eq!(setup.try_step(), Err(Fault::Receive(desc)));
    }
}
