//! Kani proof over `services::stack::Counted`, the count a port server
//! keeps of its open connections. Included from
//! `src/stdlib/services/stack/mod.rs` under `cfg(kani)` as a child module.

use super::*;

/// `Counted::enter` never counts past the maximum, and a dropped count
/// makes room for one more.
#[kani::proof]
#[kani::unwind(5)]
fn connections_are_counted_up_to_the_maximum() {
    let max: usize = kani::any();
    kani::assume(max <= 3);
    let open = Arc::new(AtomicUsize::new(0));
    let mut guards: [Option<Counted>; 4] = [None, None, None, None];
    for (i, slot) in guards.iter_mut().enumerate() {
        *slot = Counted::enter(&open, max);
        assert_eq!(slot.is_some(), i < max);
        assert_eq!(open.load(Ordering::SeqCst), (i + 1).min(max));
    }
    if max > 0 {
        guards[max - 1] = None;
        assert_eq!(open.load(Ordering::SeqCst), max - 1);
        assert!(Counted::enter(&open, max).is_some());
    }
}
