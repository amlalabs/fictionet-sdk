//! Kani proofs that decoding an SSH packet copies no more than the packet
//! and keeps no more than its payload, with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/protocols/ssh/transport.rs.
//!
//! What is charged. The SSH layer charges the copy decoding makes before
//! it decodes: the bytes buffered, at most a packet
//! (`StandardTransport::poll`, services/ssh/transport.rs). Then the
//! payload's capacity and `scratch()` before the packet is handled.
//!
//! The step. `Direction::read` on a packet before keys are installed: it
//! copies the payload and the padding out of the input and keeps the
//! payload. Packets under keys are opened with ring's ChaCha20-Poly1305 or
//! AES-GCM, which these harnesses do not run; the replay of the
//! coverage traces costs those (transport/replay.rs).
//!
//! The bounds:
//!
//! - **Within the charge**: the most bytes live at any moment of the step
//!   are at most the packet's bytes, the copy the layer charged.
//! - **What is kept**: after the step, the bytes live are the payload's
//!   capacity, at most its length plus nothing: the packet's padding is
//!   gone.
//! - **Linear copying**: the step asks for at most the packet's bytes.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// A packet before keys, `N` bytes on the wire: its length, the padding
/// length `PAD`, a payload of any bytes, and the padding.
fn read_plain<const N: usize, const PAD: usize>() {
    let payload_len = N - 5 - PAD;
    let mut bytes = [0u8; N];
    bytes[..4].copy_from_slice(&((N - 4) as u32).to_be_bytes());
    bytes[4] = PAD as u8;
    for byte in &mut bytes[5..5 + payload_len] {
        *byte = kani::any();
    }
    let ((), cost) = measure(|| {
        let mut direction = Direction::plain();
        let before = so_far();
        let step = direction.read(&bytes);
        let after = so_far();
        let Ok(Step::Item(TransportEvent::Packet { payload, .. }, used)) = step else {
            panic!("a whole plain packet decodes");
        };
        assert!(used == N);
        assert!(payload.len() == payload_len);
        assert!(
            after.requested - before.requested <= N,
            "decoding asked for more than the packet"
        );
        assert!(
            after.live <= payload.capacity(),
            "decoding kept more than the payload"
        );
        assert!(
            payload.capacity() <= N,
            "the payload holds more than the packet"
        );
        std::mem::forget(payload);
    });
    assert!(cost.peak <= N, "decoding held more than the packet's copy");
}

counted_proof! {
    /// The shortest packet: twelve bytes after the length, four of padding.
    #[kani::unwind(20)]
    fn decoding_a_short_plain_packet_copies_only_the_packet() {
        read_plain::<16, 4>();
    }
}

counted_proof! {
    /// Two blocks, with more padding than the least.
    #[kani::unwind(36)]
    fn decoding_a_longer_plain_packet_copies_only_the_packet() {
        read_plain::<32, 9>();
    }
}
