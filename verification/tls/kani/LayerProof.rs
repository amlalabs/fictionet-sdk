//! Kani proofs over the write accounting of `TlsLayer`: the ciphertext
//! emitted and completed, the plaintext write waiting for its ciphertext
//! (`plaintext_completion`, with its fence) and the completed plaintext
//! owed above, through the real `on_event`, `on_command`, `advance`,
//! `take_command` and `take_event`.
//! Compiled only under `cargo kani`, as a child module of `tls::layer`.
//!
//! rustls itself is too large for CBMC, so no harness builds a
//! `ServerConnection`: each starts from an accounting state the code
//! reaches after a write was accepted and its ciphertext produced.

use super::*;
use fictionet::Entropy;
use fictionet::stdlib::layer::{Budget, Observations};
use fictionet::time::Instant;
use std::mem::ManuallyDrop;

/// The layer never draws entropy itself; any draw is a failure.
struct NoEntropy;

impl Entropy for NoEntropy {
    fn fill_random(&self, _out: &mut [u8]) {
        panic!("the TLS layer drew entropy");
    }
}

/// A layer before any hello. It picks its config as work, which no
/// harness runs, so no `ServerConfig` is built. It is never dropped:
/// dropping its picker is a call through a vtable, which CBMC expands to
/// every function of that shape, and dropping is not what these proofs
/// are about.
fn fresh() -> ManuallyDrop<TlsLayer> {
    ManuallyDrop::new(TlsLayer::with(Select::With(Arc::new(|_, _| {
        unreachable!("no harness picks a config")
    }))))
}

/// Cumulative byte counts stay below 2^62: a connection does not move
/// 4 EiB, and the bound leaves room for every addition the code makes.
const LIMIT: u64 = 1 << 62;

/// A layer whose write accounting is any state the code can reach after a
/// write was accepted: `delivered <= produced`, at most one CHUNK of
/// plaintext pending, and a fence only while that plaintext is pending
/// and its ciphertext not yet all delivered.
fn accounting() -> ManuallyDrop<TlsLayer> {
    let mut layer = fresh();
    layer.ciphertext_emitted = kani::any();
    layer.ciphertext_completed = kani::any();
    kani::assume(
        layer.ciphertext_completed <= layer.ciphertext_emitted && layer.ciphertext_emitted <= LIMIT,
    );
    let pending: usize = kani::any();
    kani::assume(pending <= CHUNK);
    let end: Option<u64> = kani::any();
    if let Some(end) = end {
        kani::assume(pending != 0);
        kani::assume(layer.ciphertext_completed < end && end <= layer.ciphertext_emitted);
    }
    layer.plaintext_completion = (pending != 0).then_some(PlaintextCompletion {
        plaintext_bytes: pending,
        ciphertext_end: end,
    });
    layer.completed_plaintext_bytes = kani::any();
    kani::assume(layer.completed_plaintext_bytes <= LIMIT);
    layer
}

/// The plaintext bytes of the write waiting for its ciphertext, or 0.
fn pending(layer: &TlsLayer) -> usize {
    layer
        .plaintext_completion
        .map_or(0, |completion| completion.plaintext_bytes)
}

/// Where the waiting write's ciphertext ends, once rustls has written it
/// all: the fence its completion waits for.
fn fence(layer: &TlsLayer) -> Option<u64> {
    layer
        .plaintext_completion
        .and_then(|completion| completion.ciphertext_end)
}

/// A completion from below: refused, changing nothing, when it is more
/// than what is out; otherwise counted, and the pending write is credited
/// exactly when the completions reach its fence. Nothing is lost or made
/// up (`credit + pending_plaintext` is unchanged), and `take_event` hands
/// the whole credit up once.
#[kani::proof]
fn a_completion_credits_the_pending_write_once_at_its_fence() {
    let budget = Budget::unlimited();
    let mut observed = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &NoEntropy, &budget, &mut observed);
    let mut layer = accounting();
    let (produced, delivered) = (layer.ciphertext_emitted, layer.ciphertext_completed);
    let (waiting, fenced, credit) = (pending(&layer), fence(&layer), layer.completed_plaintext_bytes);
    let n: u64 = kani::any();

    let result = layer.on_event(&mut env, StreamEvent::Written(n));

    assert_eq!(layer.ciphertext_emitted, produced);
    if n > produced - delivered {
        assert!(result.is_err());
        assert_eq!(layer.ciphertext_completed, delivered);
        assert_eq!(pending(&layer), waiting);
        assert_eq!(fence(&layer), fenced);
        assert_eq!(layer.completed_plaintext_bytes, credit);
    } else {
        assert!(matches!(result, Ok(Admit::Taken)));
        assert_eq!(layer.ciphertext_completed, delivered + n);
        assert!(layer.ciphertext_completed <= layer.ciphertext_emitted);
        if fenced.is_some_and(|f| delivered + n >= f) {
            assert_eq!(layer.completed_plaintext_bytes, credit + waiting as u64);
            assert_eq!(pending(&layer), 0);
            assert_eq!(fence(&layer), None);
        } else {
            assert_eq!(layer.completed_plaintext_bytes, credit);
            assert_eq!(pending(&layer), waiting);
            assert_eq!(fence(&layer), fenced);
        }
    }
    assert_eq!(
        layer.completed_plaintext_bytes + pending(&layer) as u64,
        credit + waiting as u64
    );

    let owed = layer.completed_plaintext_bytes;
    match layer.take_event() {
        Some(StreamEvent::Written(m)) => assert!(owed != 0 && m == owed),
        None => assert_eq!(owed, 0),
        Some(_) => panic!("an event the layer never queued"),
    }
    assert_eq!(layer.completed_plaintext_bytes, 0);
    assert!(layer.take_event().is_none());
}

/// One accepted write of `p` bytes whose ciphertext, `c` bytes in any
/// number of chunks, the driver has taken, with the fence where the output
/// arm of `advance` puts it (`layer.rs:569-575`: at `produced` once rustls
/// has nothing more to write); then any schedule of six steps: the
/// carrier completing any part of what is out, or the application taking
/// events. At every step the accepted bytes are acknowledged, owed, or
/// still pending, never more (`acked + credit + pending == p`); the write
/// is credited exactly when the completions reach the fence; and
/// `produced == delivered + out`. Kani does not run `advance` here: its
/// output arm allocates a 16 KiB chunk, and with it in the harness CBMC
/// passed a 10 GB memory cap. Where the fence goes is `Layer.tla`'s.
#[kani::proof]
#[kani::unwind(8)]
fn a_write_is_acknowledged_once_after_its_ciphertext_completes() {
    let budget = Budget::unlimited();
    let mut observed = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &NoEntropy, &budget, &mut observed);
    let mut layer = fresh();
    let start: u64 = kani::any();
    let c: u64 = kani::any();
    kani::assume(start <= LIMIT && c != 0 && c <= LIMIT);
    let end = start + c;
    layer.ciphertext_completed = start;
    layer.ciphertext_emitted = end;
    let p: usize = kani::any();
    kani::assume(p != 0 && p <= CHUNK);
    // on_command accepted p bytes; advance fenced them where rustls had
    // nothing more to write.
    layer.plaintext_completion = Some(PlaintextCompletion {
        plaintext_bytes: p,
        ciphertext_end: Some(end),
    });

    let mut out = c; // taken by the driver, not yet completed
    let mut acked: u64 = 0;
    for _ in 0..6 {
        match kani::any::<bool>() {
            true => {
                let n: u64 = kani::any();
                kani::assume(n <= out);
                assert!(matches!(
                    layer.on_event(&mut env, StreamEvent::Written(n)),
                    Ok(Admit::Taken)
                ));
                out -= n;
            }
            false => match layer.take_event() {
                Some(StreamEvent::Written(m)) => acked += m,
                Some(_) => panic!("only credit was owed"),
                None => {}
            },
        }
        assert_eq!(
            acked + layer.completed_plaintext_bytes + pending(&layer) as u64,
            p as u64
        );
        assert!(layer.ciphertext_completed <= layer.ciphertext_emitted);
        if acked + layer.completed_plaintext_bytes != 0 {
            assert!(layer.ciphertext_completed >= end);
        } else {
            assert!(layer.ciphertext_completed < end);
        }
        assert_eq!(layer.ciphertext_emitted, layer.ciphertext_completed + out);
    }
}

/// A reset from above, from any accounting state: everything owed or
/// pending is dropped, completions that arrive later are refused as
/// closed and counted nowhere, nothing more is credited, and the only
/// command that follows is one Reset.
#[kani::proof]
fn a_reset_drops_what_is_owed_and_sends_only_a_reset() {
    let budget = Budget::unlimited();
    let mut observed = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &NoEntropy, &budget, &mut observed);
    let mut layer = accounting();

    assert!(matches!(
        layer.on_command(&mut env, StreamCommand::Reset),
        Ok(Admit::Taken)
    ));
    assert_eq!((layer.completed_plaintext_bytes, pending(&layer)), (0, 0));
    assert_eq!(fence(&layer), None);
    assert_eq!(layer.ciphertext_completed, layer.ciphertext_emitted);
    assert!(!layer.output_pending());

    let n: u64 = kani::any();
    let delivered = layer.ciphertext_completed;
    assert!(matches!(
        layer.on_event(&mut env, StreamEvent::Written(n)),
        Ok(Admit::Closed(StreamEvent::Written(m))) if m == n
    ));
    assert_eq!(layer.ciphertext_completed, delivered);
    assert!(layer.take_event().is_none());

    assert!(matches!(layer.advance(&mut env), Ok(true)));
    assert!(matches!(
        layer.take_command(&mut env),
        Some(StreamCommand::Reset)
    ));
    assert!(matches!(layer.advance(&mut env), Ok(false)));
    assert!(layer.take_command(&mut env).is_none());
    assert!(matches!(
        layer.on_command(&mut env, StreamCommand::Reset),
        Ok(Admit::Closed(StreamCommand::Reset))
    ));
}
