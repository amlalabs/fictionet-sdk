//! Kani proofs over the flow-control arithmetic of the HTTP/2 connection
//! layer, `Http2` in src/stdlib/web/httpd/http2.rs. Compiled only under
//! `cargo kani`, as a child module of http2.rs, so every harness calls the
//! production function the layer calls: `credit_back` (twice in
//! `Http2::release`), `sendable` (`Http2::send_one`), `grown` (the
//! WINDOW_UPDATE arm of `Http2::on_frame`), `shifted`
//! (`Http2::peer_setting`) and `more_credit` (`Http2::grant`).
//!
//! Every input is symbolic over its whole type unless a harness says
//! otherwise; Kani's overflow checks are on for every operation.

use super::*;

const MAX: i64 = wire::MAX_WINDOW as i64;

/// For a receive window anywhere from empty to full, and any room up to a
/// whole window (`release` passes `WINDOW` less the bytes the connection
/// holds, or a stream's unused child credit less its held bytes; either
/// may be below zero), `credit_back` tops the window up to exactly the
/// room once that adds at least half of what the client has left, and
/// otherwise returns nothing: the window never passes the room, so it
/// never passes `WINDOW` and never covers a held byte.
#[kani::proof]
fn credit_back_tops_the_window_up_to_the_room() {
    let window: i32 = kani::any();
    kani::assume((0..=WINDOW).contains(&window));
    let room: i64 = kani::any();
    kani::assume(room <= i64::from(WINDOW) && room >= -i64::from(u32::MAX) * 4096);
    let short = room - i64::from(window);
    match credit_back(window, room) {
        Some(back) => {
            assert!(back > 0);
            assert_eq!(i64::from(back), short);
            assert!(i64::from(back) >= i64::from(window / 2));
            assert_eq!(i64::from(window) + i64::from(back), room);
            assert!(i64::from(window) + i64::from(back) <= i64::from(WINDOW));
        }
        None => assert!(short <= 0 || short < i64::from(window / 2)),
    }
}

/// One DATA frame carries the least of the piece, both send windows (a
/// negative window counting as none) and the frame size, so neither
/// window goes below zero from a frame that went out.
#[kani::proof]
fn a_frame_fits_both_windows_and_the_frame_size() {
    let len: usize = kani::any();
    let connection: i32 = kani::any();
    let stream: i32 = kani::any();
    let frame: usize = kani::any();
    let n = sendable(len, connection, stream, frame);
    let conn_room = connection.max(0) as usize;
    let stream_room = stream.max(0) as usize;
    assert!(n <= len && n <= frame && n <= conn_room && n <= stream_room);
    assert!(n == len || n == frame || n == conn_room || n == stream_room);
    if n > 0 {
        assert!(connection - n as i32 >= 0);
        assert!(stream - n as i32 >= 0);
    }
}

/// A WINDOW_UPDATE of any increment up to 2^31 - 1 (the parser masks the
/// reserved bit and refuses zero) moves a window, negative ones included,
/// by exactly the increment, and is refused exactly when the result would
/// pass 2^31 - 1. A larger increment, which the parser never passes, is
/// refused rather than wrapped into a smaller window.
#[kani::proof]
fn window_updates_add_exactly_or_refuse_past_the_maximum() {
    let window: i32 = kani::any();
    let increment: u32 = kani::any();
    let sum = i64::from(window) + i64::from(increment);
    match grown(window, increment) {
        Some(n) => {
            assert!(i64::from(increment) <= MAX);
            assert_eq!(i64::from(n), sum);
            assert!(i64::from(n) <= MAX);
        }
        None => assert!(sum > MAX || i64::from(increment) > MAX),
    }
}

/// When the client moves its initial window from `old` to `new` (each
/// from 0 to 2^31 - 1, as the parser allows), a stream's send window moves
/// by exactly the change, and is refused exactly when it would pass
/// 2^31 - 1, never for going too low. A send window is the initial window
/// plus a sum the server's sends can lower only while the window is
/// positive, so it is never below `old - (2^31 - 1)`: the precondition.
#[kani::proof]
fn initial_window_changes_move_windows_exactly() {
    let old: i32 = kani::any();
    let new: i32 = kani::any();
    let window: i32 = kani::any();
    kani::assume(old >= 0 && new >= 0);
    kani::assume(i64::from(window) - i64::from(old) >= -MAX);
    let moved = i64::from(window) + i64::from(new) - i64::from(old);
    match shifted(window, old, new) {
        Some(n) => assert_eq!(i64::from(n), moved),
        None => assert!(moved > MAX),
    }
}

/// A child's body credit is topped back up to exactly `SEND_CREDIT` of
/// granted and queued bytes, and never past it.
#[kani::proof]
fn body_credit_tops_up_to_send_credit() {
    let granted: u64 = kani::any();
    let queued: u64 = kani::any();
    let more = more_credit(granted, queued);
    match granted.checked_add(queued) {
        Some(sum) if sum <= SEND_CREDIT => assert_eq!(sum + more, SEND_CREDIT),
        _ => assert_eq!(more, 0),
    }
}
