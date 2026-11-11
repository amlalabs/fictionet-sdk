//! A test binary's allocator: it counts and measures allocations on the
//! calling thread, and can refuse large requests. Include it with
//! `#[path]` as a module of the binary; it installs itself as the global
//! allocator. tests/it uses it, and the replays' cost bounds
//! (cost.rs beside it) read it.

// Each binary that includes it uses only part of it.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct RefusingAllocator;

std::thread_local! {
    static REFUSE_LARGE: Cell<bool> = const { Cell::new(false) };
    pub static MEASUREMENT: Cell<Option<Measurement>> = const { Cell::new(None) };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationStats {
    // Allocation and reallocation requests, including refused requests.
    pub allocations: usize,
    pub bytes_requested: usize,
    // Peak net live bytes above the fixture baseline at scope entry.
    pub peak_live_bytes: usize,
    pub largest_request: usize,
}

#[derive(Clone, Copy, Default)]
pub struct Measurement {
    stats: AllocationStats,
    // Signed because an operation can release a prebuilt fixture.
    live: i128,
}

fn record(request: Option<usize>, live_change: i128) {
    // TLS may be unavailable during thread teardown, after the scope ended.
    MEASUREMENT
        .try_with(|cell| {
            if let Some(mut measurement) = cell.get() {
                if let Some(size) = request {
                    let stats = &mut measurement.stats;
                    stats.allocations = stats.allocations.saturating_add(1);
                    stats.bytes_requested = stats.bytes_requested.saturating_add(size);
                    stats.largest_request = stats.largest_request.max(size);
                }
                measurement.live = measurement.live.saturating_add(live_change);
                measurement.stats.peak_live_bytes = measurement
                    .stats
                    .peak_live_bytes
                    .max(usize::try_from(measurement.live.max(0)).unwrap_or(usize::MAX));
                cell.set(Some(measurement));
            }
        })
        .unwrap_or(());
}

fn refuses(size: usize) -> bool {
    size >= 1024 && REFUSE_LARGE.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: Accepted requests and all deallocations use System with the original
// layout. Refused requests return null, as the allocator contract permits.
unsafe impl GlobalAlloc for RefusingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(Some(layout.size()), 0);
        let ptr = if refuses(layout.size()) {
            std::ptr::null_mut()
        } else {
            // SAFETY: GlobalAlloc callers supply a valid nonzero layout.
            unsafe { System.alloc(layout) }
        };
        record(
            None,
            if ptr.is_null() {
                0
            } else {
                layout.size() as i128
            },
        );
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(None, -(layout.size() as i128));
        // SAFETY: ptr and layout are the live System allocation supplied by the caller.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(Some(size), 0);
        let next = if refuses(size) {
            std::ptr::null_mut()
        } else {
            // SAFETY: the caller guarantees a live allocation, matching layout and valid new size.
            unsafe { System.realloc(ptr, layout, size) }
        };
        record(
            None,
            if next.is_null() {
                0
            } else {
                size as i128 - layout.size() as i128
            },
        );
        next
    }
}

#[global_allocator]
static ALLOCATOR: RefusingAllocator = RefusingAllocator;

pub fn refusing_large<T>(write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE_LARGE.set(false);
        }
    }
    REFUSE_LARGE.set(true);
    let _reset = Reset;
    write()
}

// Build fixtures before calling. Only allocator events on this thread count.
// Reallocation requests count their full new size; live bytes change only on
// success. Freeing fixture storage lowers net live bytes, not requested bytes.
pub fn measuring<T>(operation: impl FnOnce() -> T) -> (T, AllocationStats) {
    let (result, measurement) = measure(operation);
    let stats = measurement.stats;
    assert!(
        stats.allocations < usize::MAX
            && stats.bytes_requested < usize::MAX
            && stats.peak_live_bytes < usize::MAX
            && stats.largest_request < usize::MAX
            && measurement.live > i128::MIN,
        "allocation measurement saturated"
    );
    (result, stats)
}

/// As [`measuring`], and also the bytes `operation` left allocated, as
/// [`left_allocated`] gives them.
pub fn measuring_left<T>(operation: impl FnOnce() -> T) -> (T, AllocationStats, i128) {
    let (result, measurement) = measure(operation);
    (result, measurement.stats, measurement.live)
}

/// Runs `f` and counts the allocations and reallocations it makes on this
/// thread.
pub fn allocations<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let (value, stats) = measuring(f);
    (value, stats.allocations)
}

/// Runs `operation` and returns the bytes it left allocated on this
/// thread: what it allocated less what it freed, below zero when it freed
/// more than it allocated.
pub fn left_allocated<T>(operation: impl FnOnce() -> T) -> (T, i128) {
    let (result, measurement) = measure(operation);
    (result, measurement.live)
}

/// Runs `f` with this thread's measurement, if any, set aside: what `f`
/// allocates and frees is not counted.
pub fn unmeasured<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Measurement>);
    impl Drop for Restore {
        fn drop(&mut self) {
            MEASUREMENT.set(self.0.take());
        }
    }
    let _restore = Restore(MEASUREMENT.take());
    f()
}

fn measure<T>(operation: impl FnOnce() -> T) -> (T, Measurement) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MEASUREMENT.set(None);
        }
    }
    MEASUREMENT.with(|cell| {
        assert!(cell.get().is_none(), "nested allocation measurement");
        cell.set(Some(Measurement::default()));
    });
    let _reset = Reset;
    let result = operation();
    let measurement = MEASUREMENT.take().expect("active allocation measurement");
    (result, measurement)
}
