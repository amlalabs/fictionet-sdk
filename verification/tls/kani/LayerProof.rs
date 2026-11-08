//! Kani proofs over the write accounting of `TlsLayer`: `produced`,
//! `delivered`, `pending_plaintext`, `fence` and `credit`, through the real
//! `on_event`, `on_command`, `advance`, `take_command` and `take_event`.
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
    layer.produced = kani::any();
    layer.delivered = kani::any();
    kani::assume(layer.delivered <= layer.produced && layer.produced <= LIMIT);
    layer.pending_plaintext = kani::any();
    kani::assume(layer.pending_plaintext <= CHUNK);
    layer.fence = kani::any();
    if let Some(fence) = layer.fence {
        kani::assume(layer.pending_plaintext != 0);
        kani::assume(layer.delivered < fence && fence <= layer.produced);
    }
    layer.credit = kani::any();
    kani::assume(layer.credit <= LIMIT);
    layer
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
    let (produced, delivered) = (layer.produced, layer.delivered);
    let (pending, fence, credit) = (layer.pending_plaintext, layer.fence, layer.credit);
    let n: u64 = kani::any();

    let result = layer.on_event(&mut env, StreamEvent::Written(n));

    assert_eq!(layer.produced, produced);
    if n > produced - delivered {
        assert!(result.is_err());
        assert_eq!(layer.delivered, delivered);
        assert_eq!(layer.pending_plaintext, pending);
        assert_eq!(layer.fence, fence);
        assert_eq!(layer.credit, credit);
    } else {
        assert!(matches!(result, Ok(Admit::Taken)));
        assert_eq!(layer.delivered, delivered + n);
        assert!(layer.delivered <= layer.produced);
        if fence.is_some_and(|f| delivered + n >= f) {
            assert_eq!(layer.credit, credit + pending as u64);
            assert_eq!(layer.pending_plaintext, 0);
            assert_eq!(layer.fence, None);
        } else {
            assert_eq!(layer.credit, credit);
            assert_eq!(layer.pending_plaintext, pending);
            assert_eq!(layer.fence, fence);
        }
    }
    assert_eq!(
        layer.credit + layer.pending_plaintext as u64,
        credit + pending as u64
    );

    let owed = layer.credit;
    match layer.take_event() {
        Some(StreamEvent::Written(m)) => assert!(owed != 0 && m == owed),
        None => assert_eq!(owed, 0),
        Some(_) => panic!("an event the layer never queued"),
    }
    assert_eq!(layer.credit, 0);
    assert!(layer.take_event().is_none());
}

/// One accepted write of `p` bytes whose ciphertext, `c` bytes in any
/// number of chunks, the driver has taken, with the fence where the output
/// arm of `advance` puts it (`layer.rs:565-571`: at `produced` once rustls
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
    layer.delivered = start;
    layer.produced = end;
    let p: usize = kani::any();
    kani::assume(p != 0 && p <= CHUNK);
    // on_command accepted p bytes (layer.rs:457); advance fenced them.
    layer.pending_plaintext = p;
    layer.fence = Some(end);

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
            acked + layer.credit + layer.pending_plaintext as u64,
            p as u64
        );
        assert!(layer.delivered <= layer.produced);
        if acked + layer.credit != 0 {
            assert!(layer.delivered >= end);
        } else {
            assert!(layer.delivered < end);
        }
        assert_eq!(layer.produced, layer.delivered + out);
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
    assert_eq!((layer.credit, layer.pending_plaintext), (0, 0));
    assert_eq!(layer.fence, None);
    assert_eq!(layer.delivered, layer.produced);
    assert!(!layer.output_pending());

    let n: u64 = kani::any();
    let delivered = layer.delivered;
    assert!(matches!(
        layer.on_event(&mut env, StreamEvent::Written(n)),
        Ok(Admit::Closed(StreamEvent::Written(m))) if m == n
    ));
    assert_eq!(layer.delivered, delivered);
    assert!(layer.take_event().is_none());

    assert!(matches!(layer.advance(&mut env), Ok(true)));
    assert!(matches!(layer.take_command(), Some(StreamCommand::Reset)));
    assert!(matches!(layer.advance(&mut env), Ok(false)));
    assert!(layer.take_command().is_none());
    assert!(matches!(
        layer.on_command(&mut env, StreamCommand::Reset),
        Ok(Admit::Closed(StreamCommand::Reset))
    ));
}
