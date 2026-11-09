// Kani harnesses over the observer's reassembly of one direction, `Flow`,
// included into `flow.rs` under `cfg(kani)`. They run the real `push` and
// `finish` on symbolic captures, for what Observer.tla leaves out: the
// wire's 32-bit sequence wrap and the byte values themselves.
//
// The sender sends `N` symbolic bytes after its SYN, then its FIN, from a
// symbolic initial sequence number, so a capture may cross the top of the
// sequence space anywhere. The capture is `SEGMENTS` segments, each a
// symbolic slice of what the sender sent, perhaps with the FIN, in any
// order: lost, repeated, reordered or overlapping. Then the capture ends.
//
// The flow holds nothing out of order (`Limits::segments` zero): a segment
// ahead of a hole is dropped. With a segment held, CBMC's symbolic
// execution of `BTreeMap` ran out of 10 GB; holding is Observer.tla's, and
// the randomized test `random_segments_keep_the_stream_rules`'.
//
// `run` checks every step the flow gives up against what the sender sent.
// Each `*_without_*` harness changes one thing as a layer without that
// rule would, and must fail on the assertion its comment names.

use super::*;

const N: usize = 2;
const SEGMENTS: usize = 2;
/// Room for every step one call gives up. A `Vec` that grows under CBMC
/// puts its elements in either of two allocations, and the case split on
/// every read of them took more than 10 GB.
const OUT: usize = 8;

/// One rule taken away, for the failing controls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Without {
    Nothing,
    /// Bytes already delivered are delivered again, untrimmed.
    Trim,
    /// A FIN ends the direction as soon as it is seen.
    FinInOrder,
    /// The capture names sequence numbers that stop at the top of the
    /// space instead of wrapping.
    Wrap,
    /// The capture's end ignores what the flow knows is missing.
    HolesTruncate,
}

/// What the layer above has seen of the direction so far.
struct Seen {
    /// The position the next step must start at.
    cursor: u64,
    ended: bool,
}

/// Checks `out` against what the sender sent: steps follow on from one
/// another, every position appears once, in data or inside a gap, data is
/// the sender's bytes at those positions, nothing passes the FIN, and the
/// FIN comes only after every position before it and is the last step.
fn check(out: &[Step], sent: &[u8; N], seen: &mut Seen) {
    let fin_at = N as u64 + 1;
    for step in out {
        assert!(!seen.ended, "nothing follows the end");
        match step {
            Step::Data {
                sequence, bytes, ..
            } => {
                assert!(
                    *sequence == seen.cursor,
                    "each step starts where the last one ended"
                );
                assert!(!bytes.is_empty(), "data is never empty");
                let mut at = *sequence;
                for byte in bytes {
                    assert!(at >= 1 && at < fin_at, "no data past the FIN");
                    assert!(
                        *byte == sent[(at - 1) as usize],
                        "each byte is the one the sender sent there"
                    );
                    at += 1;
                }
                seen.cursor = at;
            }
            Step::Gap { sequence, missing } => {
                assert!(
                    *sequence == seen.cursor,
                    "each step starts where the last one ended"
                );
                assert!(*missing > 0, "a gap is never empty");
                seen.cursor += *missing;
                assert!(seen.cursor <= fin_at, "no gap past the FIN");
            }
            Step::Fin => {
                assert!(
                    seen.cursor == fin_at,
                    "the FIN comes after every position before it"
                );
                seen.cursor += 1;
                seen.ended = true;
            }
        }
    }
}

fn run(without: Without) {
    let sent: [u8; N] = kani::any();
    let isn: u32 = kani::any();
    let mut store = Store {
        limits: Limits {
            buffered: 0,
            segments: 0,
            connections: 1,
            waiting: usize::MAX,
        },
        held: 0,
    };
    let mut flow = Flow::opened(isn, Some(0));
    let mut seen = Seen {
        cursor: 1,
        ended: false,
    };
    let mut fin_seen = false;
    // The position just past the last byte the capture carried.
    let mut carried_to: u64 = 1;
    for _ in 0..SEGMENTS {
        let start: usize = kani::any();
        let len: usize = kani::any();
        let fin: bool = kani::any();
        kani::assume(start < N && len <= N - start);
        kani::assume(!fin || start + len == N);
        let seq = match without {
            Without::Wrap => (u64::from(isn) + 1 + start as u64).min(u64::from(u32::MAX)) as u32,
            _ => isn.wrapping_add(1).wrapping_add(start as u32),
        };
        let mut out = Vec::with_capacity(OUT);
        let delivered = seen.cursor;
        flow.push(
            Segment {
                seq,
                flags: ACK | if fin { FIN } else { 0 },
                payload: Some(&sent[start..start + len]),
                source: None,
            },
            &mut store,
            &mut out,
        );
        // The controls add to what the flow gave up, checked in order:
        // bytes already delivered, before it, or the FIN seen, after it.
        if without == Without::Trim && len > 0 && (start as u64 + 1) < delivered && !seen.ended {
            let again = Step::Data {
                sequence: start as u64 + 1,
                bytes: sent[start..start + len].to_vec(),
                source: None,
            };
            check(core::slice::from_ref(&again), &sent, &mut seen);
        }
        fin_seen |= fin;
        if len > 0 {
            carried_to = carried_to.max(start as u64 + 1 + len as u64);
        }
        check(&out, &sent, &mut seen);
        if without == Without::FinInOrder && fin && !seen.ended {
            check(&[Step::Fin], &sent, &mut seen);
        }
    }
    kani::cover!(
        isn.checked_add(N as u32 + 1).is_none(),
        "the capture crosses the wrap"
    );
    if seen.ended {
        return;
    }
    assert!(
        !fin_seen || flow.holed(),
        "a FIN seen and not reached leaves the direction holed"
    );
    // What `Observer::finish` reads to choose Truncated over Finalized.
    let holed = flow.holed() && without != Without::HolesTruncate;
    let mut out = Vec::with_capacity(OUT);
    flow.finish(&mut store, &mut out);
    assert!(
        !out.iter().any(|step| matches!(step, Step::Fin)),
        "the capture's end is never a clean end"
    );
    check(&out, &sent, &mut seen);
    kani::cover!(
        seen.cursor < carried_to,
        "the capture ends before bytes it carried"
    );
    assert!(
        seen.cursor >= carried_to || holed,
        "bytes the capture carried that never came up end Truncated"
    );
    assert!(flow.ended(), "the capture's end ends the direction");
    assert!(
        store.held == 0,
        "the capture's end gives back what was held"
    );
}

/// Every byte comes up once, in order, as the sender sent it; the FIN only
/// after every byte before it; from any initial sequence number, under
/// loss, repeats, reordering and overlap; and a capture that ends before
/// bytes it carried came up says Truncated.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn observed_bytes_come_once_in_order() {
    run(Without::Nothing);
}

/// Must fail on "each step starts where the last one ended": bytes
/// already delivered come up again.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn observed_bytes_without_trim() {
    run(Without::Trim);
}

/// Must fail on "the FIN comes after every position before it": a FIN
/// seen before the bytes it follows ends the direction.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn observed_bytes_without_fin_in_order() {
    run(Without::FinInOrder);
}

/// Must fail on "each byte is the one the sender sent there": a capture
/// that crosses the top of the sequence space is placed as if it did not
/// wrap.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn observed_bytes_without_wrap() {
    run(Without::Wrap);
}

/// Must fail on "bytes the capture carried that never came up end
/// Truncated": the end ignores bytes dropped ahead of a hole.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn observed_bytes_without_holes_truncate() {
    run(Without::HolesTruncate);
}
