//! The four AF_XDP rings, as the kernel shares them.
//!
//! Each ring is a power-of-two array of slots with a producer index, a
//! consumer index and a flags word in shared memory. Indexes are free-running
//! `u32` counters that wrap; a slot is `index & (size - 1)`. The producer
//! writes slots, then publishes its index with release ordering. The
//! consumer reads the producer index with acquire ordering, reads the slots,
//! then publishes its own index with release ordering [af_xdp].
//!
//! The process produces on the fill and TX rings and consumes the RX and
//! completion rings. Tests build both roles over one heap allocation, so
//! the same code plays the kernel's side.

use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

/// `XDP_RING_NEED_WAKEUP` in a ring's flags word.
const NEED_WAKEUP: u32 = libc::XDP_RING_NEED_WAKEUP;

/// A slot type the kernel shares: plain data, valid for any bit pattern.
pub(crate) trait Slot: Copy + sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for u64 {}
    impl Sealed for super::Desc {}
}

impl Slot for u64 {}
impl Slot for Desc {}

/// `struct xdp_desc`: one frame on the RX or TX ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Desc {
    /// Offset of the frame's first byte in the UMEM.
    pub addr: u64,
    /// Frame length in bytes.
    pub len: u32,
    /// Option flags, zero here: no multi-buffer frames, no metadata.
    pub options: u32,
}

/// Where a ring's parts are, relative to the start of its mapping
/// (`struct xdp_ring_offset`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    pub producer: usize,
    pub consumer: usize,
    pub flags: usize,
    pub desc: usize,
    /// Slots in the ring, a power of two.
    pub size: u32,
}

impl Layout {
    /// Bytes the ring's mapping must cover.
    pub fn len<T: Slot>(&self) -> usize {
        self.desc + self.size as usize * size_of::<T>()
    }
}

/// The shared parts of one ring.
struct Shared<T> {
    producer: NonNull<AtomicU32>,
    consumer: NonNull<AtomicU32>,
    flags: NonNull<AtomicU32>,
    slots: NonNull<T>,
    mask: u32,
    _slots: PhantomData<T>,
}

// SAFETY: `Shared` only points into memory the ring's owner keeps mapped
// for its lifetime (the contract of `Shared::new`). The indexes are atomics
// and slots are plain data handed over by the acquire/release protocol, so
// moving the owner to another thread is sound.
unsafe impl<T: Send> Send for Shared<T> {}

impl<T: Slot> Shared<T> {
    /// # Safety
    ///
    /// `base` must point to memory that is valid for reads and writes for
    /// `layout.len::<T>()` bytes and stays so for the life of the returned
    /// ring. The producer, consumer and flags offsets must be 4-byte
    /// aligned, the slot offset aligned for `T`, and none may overlap.
    /// The only other party writing the memory is one peer that follows
    /// the ring protocol in the opposite role.
    unsafe fn new(base: NonNull<u8>, layout: Layout) -> Self {
        assert!(layout.size.is_power_of_two());
        // SAFETY: each offset is inside the mapping by the caller's contract.
        let at = |offset: usize| unsafe { base.add(offset) };
        Self {
            producer: at(layout.producer).cast(),
            consumer: at(layout.consumer).cast(),
            flags: at(layout.flags).cast(),
            slots: at(layout.desc).cast(),
            mask: layout.size - 1,
            _slots: PhantomData,
        }
    }

    fn size(&self) -> u32 {
        self.mask + 1
    }

    fn producer(&self) -> &AtomicU32 {
        // SAFETY: aligned, in bounds and live for `self` (contract of `new`);
        // shared with the peer only through atomic operations.
        unsafe { self.producer.as_ref() }
    }

    fn consumer(&self) -> &AtomicU32 {
        // SAFETY: as for `producer`.
        unsafe { self.consumer.as_ref() }
    }

    fn flags(&self) -> &AtomicU32 {
        // SAFETY: as for `producer`.
        unsafe { self.flags.as_ref() }
    }

    /// The slot for free-running index `index`.
    fn slot(&self, index: u32) -> *mut T {
        // SAFETY: `index & mask` is below the ring size, so the slot is
        // inside the mapping (contract of `new`).
        unsafe { self.slots.as_ptr().add((index & self.mask) as usize) }
    }
}

/// The process's side of a ring it fills: the fill and TX rings.
pub(crate) struct Producer<T> {
    shared: Shared<T>,
    /// Our next index, published by [`Self::submit`].
    next: u32,
    /// The consumer index as last read.
    consumed: u32,
}

impl<T: Slot> Producer<T> {
    /// # Safety
    ///
    /// The contract of the ring memory in `Shared::new`, with this side
    /// the only producer.
    pub unsafe fn new(base: NonNull<u8>, layout: Layout) -> Self {
        // SAFETY: forwarded from the caller.
        let shared = unsafe { Shared::new(base, layout) };
        let next = shared.producer().load(Ordering::Relaxed);
        let consumed = shared.consumer().load(Ordering::Acquire);
        Self {
            shared,
            next,
            consumed,
        }
    }

    /// Slots free to write now.
    pub fn free(&mut self) -> u32 {
        let size = self.shared.size();
        if self.next.wrapping_sub(self.consumed) == size {
            self.consumed = self.shared.consumer().load(Ordering::Acquire);
        }
        size - self.next.wrapping_sub(self.consumed)
    }

    /// Writes `value` into the next slot, unpublished until [`Self::submit`].
    /// Returns `false` when the ring is full.
    pub fn push(&mut self, value: T) -> bool {
        if self.free() == 0 {
            return false;
        }
        // SAFETY: the slot is between the consumer and size slots past it,
        // so the peer does not read it until we publish.
        unsafe { self.shared.slot(self.next).write(value) };
        self.next = self.next.wrapping_add(1);
        true
    }

    /// Publishes every pushed slot to the consumer.
    pub fn submit(&mut self) {
        self.shared.producer().store(self.next, Ordering::Release);
    }

    /// Pushed or published slots the consumer has not released yet, read
    /// fresh from the consumer index.
    pub fn outstanding(&mut self) -> u32 {
        self.consumed = self.shared.consumer().load(Ordering::Acquire);
        self.next.wrapping_sub(self.consumed)
    }

    /// Whether the kernel asks to be woken with `sendto` or `poll`.
    pub fn needs_wakeup(&self) -> bool {
        self.shared.flags().load(Ordering::Relaxed) & NEED_WAKEUP != 0
    }
}

/// The process's side of a ring it drains: the RX and completion rings.
pub(crate) struct Consumer<T> {
    shared: Shared<T>,
    /// Our next index, published by [`Self::release`].
    next: u32,
    /// The producer index as last read.
    produced: u32,
}

impl<T: Slot> Consumer<T> {
    /// # Safety
    ///
    /// The contract of the ring memory in `Shared::new`, with this side
    /// the only consumer.
    pub unsafe fn new(base: NonNull<u8>, layout: Layout) -> Self {
        // SAFETY: forwarded from the caller.
        let shared = unsafe { Shared::new(base, layout) };
        let next = shared.consumer().load(Ordering::Relaxed);
        let produced = shared.producer().load(Ordering::Acquire);
        Self {
            shared,
            next,
            produced,
        }
    }

    /// Takes the next published slot, or `None` when the ring is empty.
    /// The slot is returned to the producer by [`Self::release`].
    pub fn pop(&mut self) -> Option<T> {
        if self.next == self.produced {
            self.produced = self.shared.producer().load(Ordering::Acquire);
            if self.next == self.produced {
                return None;
            }
        }
        // SAFETY: the slot is published (below the acquired producer index)
        // and not yet released, so the peer does not write it.
        let value = unsafe { self.shared.slot(self.next).read() };
        self.next = self.next.wrapping_add(1);
        Some(value)
    }

    /// Gives every taken slot back to the producer.
    pub fn release(&mut self) {
        self.shared.consumer().store(self.next, Ordering::Release);
    }
}

#[cfg(test)]
pub(crate) mod double {
    //! Ring memory on the heap, for tests: the code under test takes one
    //! role and the test plays the kernel in the other.

    use super::*;

    /// One ring's memory: three index words, then the slots. Every ring
    /// made from it points into the one allocation, which lives until the
    /// `RingMemory` drops; tests drop it last.
    pub struct RingMemory {
        base: NonNull<u64>,
        words: usize,
        layout: Layout,
    }

    impl RingMemory {
        /// A ring of `size` slots whose indexes both start at `start`, so
        /// tests can begin next to the `u32` wrap.
        pub fn new<T: Slot>(size: u32, start: u32) -> Self {
            let layout = Layout {
                producer: 0,
                consumer: 4,
                flags: 8,
                desc: 16,
                size,
            };
            let words = layout.len::<T>().div_ceil(8);
            let memory = Box::into_raw(vec![0u64; words].into_boxed_slice());
            let base = NonNull::new(memory.cast::<u64>()).unwrap();
            // SAFETY: offsets 0 and 4 are inside the fresh allocation,
            // 4-byte aligned, and nothing else references it yet.
            unsafe {
                base.cast::<u32>().write(start);
                base.cast::<u32>().add(1).write(start);
            }
            Self {
                base,
                words,
                layout,
            }
        }

        pub fn producer<T: Slot>(&self) -> Producer<T> {
            // SAFETY: the allocation is 8-byte aligned, covers the layout,
            // never moves, and outlives every ring a test makes from it.
            unsafe { Producer::new(self.base.cast(), self.layout) }
        }

        pub fn consumer<T: Slot>(&self) -> Consumer<T> {
            // SAFETY: as for `producer`.
            unsafe { Consumer::new(self.base.cast(), self.layout) }
        }

        pub fn set_need_wakeup(&self, on: bool) {
            // SAFETY: offset 8 is the aligned flags word inside the memory,
            // accessed only atomically.
            let flags = unsafe { self.base.cast::<u8>().add(8).cast::<AtomicU32>().as_ref() };
            flags.store(if on { NEED_WAKEUP } else { 0 }, Ordering::Relaxed);
        }
    }

    impl Drop for RingMemory {
        fn drop(&mut self) {
            let slice = std::ptr::slice_from_raw_parts_mut(self.base.as_ptr(), self.words);
            // SAFETY: the pointer came from `Box::into_raw` of a slice of
            // exactly `words` elements, and is freed once.
            drop(unsafe { Box::from_raw(slice) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::double::RingMemory;
    use super::*;

    #[test]
    fn values_cross_in_order_and_the_ring_holds_exactly_its_size() {
        let memory = RingMemory::new::<u64>(4, 0);
        let mut producer = memory.producer::<u64>();
        let mut consumer = memory.consumer::<u64>();
        assert_eq!(producer.free(), 4);
        for value in 10..14 {
            assert!(producer.push(value));
        }
        assert!(!producer.push(14), "a full ring refuses");
        assert_eq!(consumer.pop(), None, "nothing is visible before submit");
        producer.submit();
        assert_eq!(consumer.pop(), Some(10));
        assert_eq!(consumer.pop(), Some(11));
        assert_eq!(producer.free(), 0, "slots return only on release");
        consumer.release();
        assert_eq!(producer.free(), 2);
        assert_eq!(producer.outstanding(), 2);
        assert_eq!(consumer.pop(), Some(12));
        assert_eq!(consumer.pop(), Some(13));
        assert_eq!(consumer.pop(), None);
    }

    #[test]
    fn indexes_wrap_past_u32_max() {
        let memory = RingMemory::new::<Desc>(8, u32::MAX - 5);
        let mut producer = memory.producer::<Desc>();
        let mut consumer = memory.consumer::<Desc>();
        let mut sent = 0u64;
        let mut received = 0u64;
        // Twenty rounds of uneven batches carry both indexes across the wrap.
        for round in 0..20u64 {
            for _ in 0..(round % 8 + 1) {
                let desc = Desc {
                    addr: sent * 4096,
                    len: sent as u32,
                    options: 0,
                };
                if !producer.push(desc) {
                    break;
                }
                sent += 1;
            }
            producer.submit();
            for _ in 0..(round % 5 + 1) {
                let Some(desc) = consumer.pop() else { break };
                assert_eq!(desc.addr, received * 4096);
                assert_eq!(desc.len, received as u32);
                received += 1;
            }
            consumer.release();
            assert_eq!(u64::from(producer.outstanding()), sent - received);
        }
        while let Some(desc) = consumer.pop() {
            assert_eq!(desc.addr, received * 4096);
            received += 1;
        }
        assert_eq!(sent, received);
        assert!(sent > 8, "the test must cross the wrap");
    }

    #[test]
    fn need_wakeup_reads_the_flags_word() {
        let memory = RingMemory::new::<Desc>(4, 0);
        let producer = memory.producer::<Desc>();
        assert!(!producer.needs_wakeup());
        memory.set_need_wakeup(true);
        assert!(producer.needs_wakeup());
    }
}
