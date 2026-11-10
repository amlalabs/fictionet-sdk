//! Kani proofs over the write accounting of `TlsLayer`:
//! `ciphertext_emitted`, `ciphertext_completed`, `plaintext_completion` (the
//! write's plaintext bytes and the ciphertext end that completes it) and
//! `completed_plaintext_bytes`, through the real `on_event`, `on_command`,
//! `advance`, `take_command` and `take_event`. Compiled only under
//! `cargo kani`, as a child module of `tls::layer`.
//!
//! rustls itself is too large for CBMC, so no harness builds a connection:
//! each starts from an accounting state the code reaches after a write was
//! accepted and sealed (`pump`, where a sealed write's completion gets its
//! ciphertext end at once).

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

/// The plaintext bytes of the write waiting for its ciphertext.
fn pending(layer: &TlsLayer) -> usize {
    layer
        .plaintext_completion
        .map_or(0, |write| write.plaintext_bytes)
}

/// The ciphertext end that completes the waiting write.
fn fence(layer: &TlsLayer) -> Option<u64> {
    layer
        .plaintext_completion
        .and_then(|write| write.ciphertext_end)
}

/// A layer whose write accounting is any state the code can reach after a
/// write was accepted: completed at most what was emitted, at most one
/// record's plaintext waiting, with a ciphertext end not yet completed,
/// and any credit owed.
fn accounting() -> ManuallyDrop<TlsLayer> {
    let mut layer = fresh();
    layer.ciphertext_emitted = kani::any();
    layer.ciphertext_completed = kani::any();
    kani::assume(
        layer.ciphertext_completed <= layer.ciphertext_emitted && layer.ciphertext_emitted <= LIMIT,
    );
    if kani::any() {
        let plaintext_bytes: usize = kani::any();
        let end: u64 = kani::any();
        kani::assume(plaintext_bytes != 0 && plaintext_bytes <= PLAINTEXT);
        kani::assume(layer.ciphertext_completed < end && end <= layer.ciphertext_emitted);
        layer.plaintext_completion = Some(PlaintextCompletion {
            plaintext_bytes,
            ciphertext_end: Some(end),
        });
    }
    layer.completed_plaintext_bytes = kani::any();
    kani::assume(layer.completed_plaintext_bytes <= LIMIT);
    layer
}

/// A completion from below: refused, changing nothing, when it is more
/// than what is out; otherwise counted, and the waiting write is credited
/// exactly when the completions reach its ciphertext end. Nothing is lost
/// or made up (credit plus waiting plaintext is unchanged), and
/// `take_event` hands the whole credit up once.
#[kani::proof]
fn a_completion_credits_the_pending_write_once_at_its_fence() {
    let budget = Budget::unlimited();
    let mut observed = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &NoEntropy, &budget, &mut observed);
    let mut layer = accounting();
    let (emitted, completed) = (layer.ciphertext_emitted, layer.ciphertext_completed);
    let (waiting, end, credit) = (
        pending(&layer),
        fence(&layer),
        layer.completed_plaintext_bytes,
    );
    let n: u64 = kani::any();

    let result = layer.on_event(&mut env, StreamEvent::Written(n));

    assert_eq!(layer.ciphertext_emitted, emitted);
    if n > emitted - completed {
        assert!(result.is_err());
        assert_eq!(layer.ciphertext_completed, completed);
        assert_eq!(pending(&layer), waiting);
        assert_eq!(fence(&layer), end);
        assert_eq!(layer.completed_plaintext_bytes, credit);
    } else {
        assert!(matches!(result, Ok(Admit::Taken)));
        assert_eq!(layer.ciphertext_completed, completed + n);
        assert!(layer.ciphertext_completed <= layer.ciphertext_emitted);
        if end.is_some_and(|end| completed + n >= end) {
            assert_eq!(layer.completed_plaintext_bytes, credit + waiting as u64);
            assert!(layer.plaintext_completion.is_none());
        } else {
            assert_eq!(layer.completed_plaintext_bytes, credit);
            assert_eq!(pending(&layer), waiting);
            assert_eq!(fence(&layer), end);
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

/// One accepted write of `p` bytes whose ciphertext, `c` bytes in one
/// chunk, went down, with its end where `pump` puts it once the write is
/// sealed (at `ciphertext_emitted`); then any schedule of six steps: the
/// carrier completing any part of what is out, or the application taking
/// events. At every step the accepted bytes are acknowledged, owed, or
/// still waiting, never more (`acked + credit + waiting == p`); the write
/// is credited exactly when the completions reach its end; and `emitted ==
/// completed + out`. Kani does not run `pump` here: sealing is rustls's.
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
    kani::assume(p != 0 && p <= PLAINTEXT);
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
/// waiting is dropped, completions that arrive later are refused as closed
/// and counted nowhere, nothing more is credited, and the only command
/// that follows is one Reset.
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
    assert_eq!(layer.completed_plaintext_bytes, 0);
    assert!(layer.plaintext_completion.is_none());
    assert_eq!(layer.ciphertext_completed, layer.ciphertext_emitted);
    assert!(!layer.output_pending());

    let n: u64 = kani::any();
    let completed = layer.ciphertext_completed;
    assert!(matches!(
        layer.on_event(&mut env, StreamEvent::Written(n)),
        Ok(Admit::Closed(StreamEvent::Written(m))) if m == n
    ));
    assert_eq!(layer.ciphertext_completed, completed);
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
