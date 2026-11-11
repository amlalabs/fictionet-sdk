//! Counts what the code under a Kani proof allocates.
//!
//! Kani ignores `#[global_allocator]`: its own C library defines
//! `__rust_alloc` and the rest. So a counted proof stubs the standard
//! library's allocation functions with the ones below, which take memory
//! from `malloc` and count it. Write a counted proof with [`counted_proof`]
//! in place of `#[kani::proof]`, call the code inside [`measure`], and
//! state the bound on the [`Cost`] it returns. Run it with
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates -Z restrict-vtable`.
//!
//! Include this file once per crate, at the crate root, as `counting`
//! (the macro names its stubs by `crate::counting`):
//!
//! ```ignore
//! #[cfg(kani)]
//! #[allow(unsafe_code)]
//! #[path = "<to the repository>/verification/resources/kani/counting.rs"]
//! mod counting;
//! ```
//!
//! What it counts. Every allocation, reallocation and zeroed allocation
//! the standard library makes for `Box`, `Vec`, `VecDeque`, `Arc` and the
//! rest goes through `alloc`, `alloc_zeroed` and the private
//! `realloc_nonnull` and `dealloc_nonnull` of `alloc::alloc`, the names in
//! Kani 0.68's toolchain. A reallocation counts as a new allocation of its
//! full new size, then a free of the old. A free gives back its layout's
//! size, which Rust guarantees is the size allocated. A pointer that is not
//! a live allocation is skipped: with the stubs in place, Kani 0.68 hands
//! `dealloc_nonnull` the dangling pointer of an empty boxed slice dropped
//! from a collection, with a size that is not zero, which the unstubbed
//! code never frees. Memory is never returned to CBMC, so every pointer the
//! counter handed out stays one it can tell from a dangling one.
//!
//! Build what a proof measures inside [`measure`]: a free of something
//! allocated before it fails the proof, as it would make `live` wrong.
//!
//! If a toolchain routes allocations around these names, the counter
//! misses them; `the_counter_sees_every_allocation` below fails then.

extern crate alloc as alloc_crate;

use std::alloc::Layout;
use std::ptr::NonNull;

unsafe extern "C" {
    fn malloc(size: usize) -> *mut core::ffi::c_void;
}

/// What a measured call allocated.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cost {
    /// Allocations and reallocations made.
    pub allocations: usize,
    /// Bytes they asked for, each reallocation at its full new size.
    pub requested: usize,
    /// The most bytes live at once.
    pub peak: usize,
    /// Bytes still live at the end.
    pub live: usize,
}

static mut COST: Cost = Cost {
    allocations: 0,
    requested: 0,
    peak: 0,
    live: 0,
};

/// Runs `f` and returns what it allocated.
pub fn measure<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    // SAFETY: a Kani proof runs on one thread.
    unsafe { COST = Cost::default() };
    let out = f();
    // SAFETY: as above.
    (out, unsafe { COST })
}

/// What the call being measured has allocated so far: read it before
/// and after one step inside [`measure`] to cost that step alone.
pub fn so_far() -> Cost {
    // SAFETY: a Kani proof runs on one thread.
    unsafe { COST }
}

fn take(size: usize) -> *mut u8 {
    // SAFETY: a Kani proof runs on one thread; `malloc` is CBMC's.
    unsafe {
        COST.allocations += 1;
        COST.requested += size;
        COST.live += size;
        COST.peak = COST.peak.max(COST.live);
        let ptr: *mut u8 = malloc(size).cast();
        // A failed allocation aborts: it is not a cost.
        kani::assume(!ptr.is_null());
        ptr
    }
}

fn give(ptr: *mut u8, size: usize) {
    if !kani::mem::can_dereference(ptr) {
        return;
    }
    // SAFETY: a Kani proof runs on one thread.
    unsafe {
        assert!(
            COST.live >= size,
            "a free of what was allocated before measure"
        );
        COST.live -= size;
    }
}

/// Stands for `std::alloc::alloc`.
pub unsafe fn alloc(layout: Layout) -> *mut u8 {
    take(layout.size())
}

/// Stands for `std::alloc::alloc_zeroed`.
pub unsafe fn alloc_zeroed(layout: Layout) -> *mut u8 {
    let ptr = take(layout.size());
    // SAFETY: `take` returned `layout.size()` writable bytes.
    unsafe { std::ptr::write_bytes(ptr, 0, layout.size()) };
    ptr
}

/// Stands for `alloc::alloc::dealloc_nonnull`.
pub unsafe fn dealloc_nonnull(ptr: NonNull<u8>, layout: Layout) {
    give(ptr.as_ptr(), layout.size())
}

/// Stands for `alloc::alloc::realloc_nonnull`.
pub unsafe fn realloc_nonnull(ptr: NonNull<u8>, layout: Layout, size: usize) -> *mut u8 {
    let new = take(size);
    // SAFETY: the old block holds `layout.size()` bytes and the new one
    // `size`; they are distinct objects.
    unsafe { std::ptr::copy_nonoverlapping(ptr.as_ptr(), new, layout.size().min(size)) };
    give(ptr.as_ptr(), layout.size());
    new
}

/// `#[kani::proof]` with the allocation functions stubbed by this
/// module's: write `counted_proof! { #[kani::unwind(n)] fn name() { ... } }`.
macro_rules! counted_proof {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        #[kani::proof]
        #[kani::stub(std::alloc::alloc, crate::counting::alloc)]
        #[kani::stub(std::alloc::alloc_zeroed, crate::counting::alloc_zeroed)]
        #[kani::stub(crate::counting::alloc_crate::alloc::dealloc_nonnull, crate::counting::dealloc_nonnull)]
        #[kani::stub(crate::counting::alloc_crate::alloc::realloc_nonnull, crate::counting::realloc_nonnull)]
        $(#[$meta])*
        fn $name() $body
    };
}
pub(crate) use counted_proof;

mod proofs {
    use super::{counted_proof, measure};
    use std::alloc::Layout;
    use std::collections::VecDeque;
    use std::sync::Arc;

    counted_proof! {
        /// The counter sees what `Box`, `Vec` (grown, so reallocated, and
        /// shrunk to a boxed slice), `VecDeque` and `Arc` allocate, at their
        /// layouts' sizes, and sees all of it freed.
        #[kani::unwind(20)]
        fn the_counter_sees_every_allocation() {
            let n: usize = kani::any();
            kani::assume(n >= 1 && n <= 4);
            let ((), cost) = measure(|| {
                let boxed = Box::new(0u64);
                let mut grown: Vec<u8> = Vec::with_capacity(1);
                grown.extend(std::iter::repeat_n(1u8, n + 1));
                let slice = grown.into_boxed_slice();
                let mut deque: VecDeque<(Arc<[u8]>, Box<[u8]>)> = VecDeque::new();
                let name: Arc<[u8]> = std::iter::repeat_n(0u8, n).collect();
                deque.reserve_exact(4);
                deque.push_front((name, Vec::new().into_boxed_slice()));
                drop((boxed, slice, deque));
            });
            let arc = Layout::new::<[usize; 2]>()
                .extend(Layout::array::<u8>(n).unwrap())
                .unwrap()
                .0
                .pad_to_align()
                .size();
            let slots = Layout::array::<(Arc<[u8]>, Box<[u8]>)>(4).unwrap().size();
            // A box, the vector's first block and its growth, the deque's
            // slots and the name: at least these, and nothing left.
            assert!(cost.allocations >= 5);
            assert!(cost.requested >= size_of::<u64>() + 1 + (n + 1) + slots + arc);
            assert!(cost.peak >= slots + arc);
            assert!(cost.live == 0);
        }
    }
}
