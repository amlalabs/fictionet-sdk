//! Kani proofs that the WebSocket message decoder holds no more than its
//! limit, and that `held()` says what it holds, with every allocation
//! counted (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/protocols/websocket.rs.
//!
//! What is charged. A [`Messages`] decoder's named limit bounds the
//! message it assembles, and whoever drives it charges what `held()`
//! reports beside its input buffer (`codec::Demux` charges
//! `allocated() + held()`). So what the message in progress keeps must be
//! at most `held()`, and `held()` at most the limit.
//!
//! The step. `Messages::decode` copies a frame's payload out of the input
//! (`Frame::from_header`, one allocation of exactly the payload), and a
//! first fragment's payload becomes the message's data. A continuation's
//! is appended with `Partial::append`, the step these harnesses run;
//! harnesses on the whole of `decode` ran CBMC out of 14 GiB. The vectors
//! in tests/it/websocket_costs.rs cost the whole of `decode`.
//!
//! The bounds:
//!
//! - **Within the charge**: after each append, the bytes live are at most
//!   `held()`, and `held()` is at most the limit.
//! - **The step's scratch**: the most bytes live at any moment of an
//!   append are at most `held()` before it plus the limit: a new
//!   allocation for the message while the old one is live.
//! - **Linear copying**: an append asks for at most the limit.
//!
//! Each payload has a fixed length, so every allocation size is a
//! constant.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// The decoder's limit.
const LIMIT: usize = 10;

/// Payloads to take from: an append's payload is a prefix.
const BYTES: [u8; LIMIT] = [0; LIMIT];

/// A message of `first` bytes, then appends of `next`, checked against the
/// bounds above.
fn within_limit(first: usize, next: &[usize]) {
    let ((), cost) = measure(|| {
        let mut message = Partial {
            opcode: Opcode::Binary,
            data: BYTES[..first].to_vec(),
            checked: 0,
        };
        for &len in next {
            let held = message.data.capacity();
            let before = so_far();
            message.append(&BYTES[..len], LIMIT);
            let after = so_far();
            let decoder = Messages {
                frames: Frames::for_receiver(Side::Client).with_limit(LIMIT),
                limit: LIMIT,
                partial: Some(message),
            };
            let reported = codec::Decode::held(&decoder);
            message = decoder.partial.unwrap();
            assert!(
                after.live <= reported,
                "the message holds more than held() says"
            );
            assert!(reported <= LIMIT, "held() is past the limit");
            assert!(
                after.requested - before.requested <= LIMIT,
                "the append asked for more than the limit"
            );
            assert!(
                after.peak <= before.peak.max(held + LIMIT),
                "the append held more than held() before and the limit"
            );
        }
        std::mem::forget(message);
    });
    assert!(cost.live <= LIMIT);
}

counted_proof! {
    /// Six bytes, then four: the append grows the message to exactly the
    /// limit. Before the growth was clamped it grew to twelve, with
    /// `held()` reporting ten.
    #[kani::unwind(12)]
    fn a_message_of_two_fragments_stays_within_its_limit() {
        within_limit(6, &[4]);
    }
}

counted_proof! {
    /// Three bytes, three, then four: a doubling, then a growth the limit
    /// cuts short.
    #[kani::unwind(12)]
    fn a_message_of_three_fragments_stays_within_its_limit() {
        within_limit(3, &[3, 4]);
    }
}
