//! Kani proofs over the window arithmetic of `Session`, the sans-I/O
//! direction in src/stdlib/protocols/http2.rs. Compiled only under
//! `cargo kani`, as a child module of that file, so each harness calls the
//! production function `Session` calls: `credited` (stream credit in
//! `Session::peer_window_update`) and `initial_fits` (the check of
//! SETTINGS_INITIAL_WINDOW_SIZE in `Session::apply_peer`).
//!
//! A stream's window here is `envelope + c`, where `c` is the credit the
//! sender was granted less the DATA it sent, and `envelope`, the largest
//! initial window the sender may still be under, is at least `latest`,
//! the one announced last. The sender's own window is `latest + c`, and
//! `latest + c <= 2^31 - 1` while the stream may send: the preconditions.
//! `c` is at least `-(2^31 - 1)` (DATA goes out only within a positive
//! window, so `latest + c >= 0` held at each send under some initial
//! window), with room for one frame below that.

use super::*;

const MAX: i64 = MAX_WINDOW as i64;

/// The sender's window and the window here, from the credit and the two
/// initial windows: the inputs the harnesses quantify over.
fn any_stream() -> (i64, u32, u32, i64) {
    let credit: i64 = kani::any();
    let envelope: u32 = kani::any();
    let latest: u32 = kani::any();
    kani::assume(latest <= envelope && envelope <= MAX_WINDOW);
    kani::assume((-MAX - MAX_FRAME_SIZE as i64..=MAX).contains(&credit));
    kani::assume(credit + i64::from(latest) <= MAX);
    (credit, envelope, latest, i64::from(envelope) + credit)
}

/// Credit of any increment the parser passes (1 to 2^31 - 1) is granted
/// exactly when the sender's window stays within 2^31 - 1, and then the
/// window here grows by exactly the increment; otherwise nothing changes.
/// A sender at exactly 2^31 - 1 after the credit is granted, one past it
/// refused, whatever larger initial window is not yet acknowledged.
#[kani::proof]
fn credit_counts_from_the_initial_window_announced_last() {
    let (credit, envelope, latest, window) = any_stream();
    let increment: u32 = kani::any();
    kani::assume(increment >= 1 && increment <= MAX_WINDOW);
    let sender = i64::from(latest) + credit;
    match credited(window, envelope, latest, increment) {
        Some(next) => {
            assert!(sender + i64::from(increment) <= MAX);
            assert_eq!(next, window + i64::from(increment));
        }
        None => assert!(sender + i64::from(increment) > MAX),
    }
    kani::cover!(sender + i64::from(increment) == MAX);
    kani::cover!(sender + i64::from(increment) == MAX + 1);
    kani::cover!(
        envelope > latest
            && window + i64::from(increment) > MAX
            && sender + i64::from(increment) <= MAX
    );
}

/// One SETTINGS frame whose initial windows reach at most `most` fails
/// exactly when the sender, applying its values in turn, takes the
/// stream past 2^31 - 1 at that value: whatever the window here counts
/// from, the sender's window there is `most + credit`.
#[kani::proof]
fn initial_windows_fail_exactly_past_the_maximum() {
    let (credit, envelope, _latest, window) = any_stream();
    let most: u32 = kani::any();
    kani::assume(most <= MAX_WINDOW);
    assert_eq!(
        initial_fits(window, envelope, most),
        i64::from(most) + credit <= MAX
    );
    kani::cover!(i64::from(most) + credit == MAX);
    kani::cover!(i64::from(most) + credit == MAX + 1);
}
