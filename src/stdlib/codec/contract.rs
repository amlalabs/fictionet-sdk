//! Executable decoder and writer contracts for tests and fuzz targets.
//! Use only in test and fuzz targets. Contract failures panic.
//!
//! The harness asserts counts, stable suffixes, capacity, progress, held
//! growth across `Need`, EOF completion, and terminal driver behavior.
//! It compares items, terminal errors, and consumed offsets across fixed
//! and LCG chunkings. Each of the first 256 prefixes is also ended.
//!
//! It cannot inspect hidden memory, prove absence of panics on untested
//! input, or infer a protocol's held-state limit or exact wire grammar.
//! Use [`check_decode_with_held_limit`] for a named state limit and
//! [`check_decode_with_alloc_limit`] for a bound on the input buffer's
//! allocation. A decoder
//! must report its state accurately. Mode timing is enforced by the
//! one-item interface. [`check_wire_value`] tests constructed writer values,
//! including values a parser cannot produce.

use super::{
    Buffer, Decode, Fail, Lcg, Step, Stream, Wire,
    alloc::{rc::Rc, vec::Vec},
    test_support::{chunks, random_chunks},
};
use core::{cell::RefCell, fmt::Debug};

/// Maximum retained items in one harness run. Limits the harness itself
/// when a decoder produces many items without consuming bytes.
pub const MAX_ITEMS: usize = 1 << 20;

#[derive(Default)]
struct AuditState {
    calls: usize,
    consumed: u64,
    terminal: bool,
}
struct Audit<'a, D> {
    inner: D,
    state: Rc<RefCell<AuditState>>,
    source: &'a [u8],
    suffix_len: usize,
    held_limit: usize,
}
#[derive(Clone, Copy)]
struct Limits {
    held: usize,
    alloc: usize,
}
impl<D: Decode> Decode for Audit<'_, D> {
    type Item = D::Item;
    type Error = D::Error;
    const NAME: &'static str = D::NAME;
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    fn held(&self) -> usize {
        self.inner.held()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let mut state = self.state.borrow_mut();
        assert!(!state.terminal, "decoder called after Err or End");
        assert!(input.len() >= self.suffix_len, "unstable unread suffix");
        let at = usize::try_from(state.consumed).expect("input offset overflow");
        let expected = self
            .source
            .get(at..at + input.len())
            .expect("input outside source");
        assert_eq!(
            &input[self.suffix_len..],
            &expected[self.suffix_len..],
            "unstable unread suffix"
        );
        state.calls = state.calls.saturating_add(1);
        let before = self.inner.held();
        let result = self.inner.decode(input, eof);
        assert!(
            input.len() <= self.inner.capacity(),
            "buffered exceeds capacity"
        );
        assert!(
            self.inner.held() <= self.held_limit,
            "held exceeds named limit"
        );
        let used = match &result {
            Ok(Step::Item(_, n) | Step::Skip(n)) => {
                assert!(*n <= input.len(), "consumed count exceeds input");
                *n
            }
            Ok(Step::Need) => {
                assert!(self.inner.held() <= before, "held grew across Need");
                assert!(
                    eof || input.len() < self.inner.capacity(),
                    "Need at capacity"
                );
                0
            }
            Ok(Step::End) | Err(_) => {
                state.terminal = true;
                0
            }
        };
        // Compare each consumed byte once. Check the final suffix at EOF or End.
        let checked = if matches!(result, Ok(Step::End) | Err(_))
            || (eof && matches!(result, Ok(Step::Need)))
        {
            input.len()
        } else {
            used
        };
        assert_eq!(
            &input[..checked],
            &expected[..checked],
            "unstable unread suffix"
        );
        state.consumed = state
            .consumed
            .saturating_add(u64::try_from(used).unwrap_or(u64::MAX));
        self.suffix_len = input.len() - used;
        result
    }
}
#[derive(Debug, PartialEq)]
struct Outcome<T, E> {
    items: Vec<T>,
    failure: Option<Fail<E>>,
    consumed: u64,
}

fn drain<D: Decode>(
    stream: &mut Stream<Audit<'_, D>>,
    out: &mut Outcome<D::Item, D::Error>,
    accepted: usize,
    alloc_limit: usize,
) where
    D::Error: Clone,
{
    while let Some(result) = stream.next() {
        assert!(
            stream.buffered() <= stream.dec.capacity(),
            "buffered exceeds capacity"
        );
        assert!(
            stream.buf.allocated() <= alloc_limit,
            "buffer allocation exceeds limit"
        );
        assert_eq!(
            stream.offset(),
            stream.dec.state.borrow().consumed,
            "consumed accounting mismatch"
        );
        assert_eq!(
            stream.offset().saturating_add(stream.buffered() as u64),
            accepted as u64,
            "accepted accounting mismatch"
        );
        match result {
            Ok(item) => {
                assert!(out.items.len() < MAX_ITEMS, "harness item limit exceeded");
                out.items.push(item);
            }
            Err(e) => {
                assert!(!matches!(e, Fail::Stuck { .. }), "driver reported Stuck");
                assert!(out.failure.is_none(), "error reported more than once");
                out.failure = Some(e);
            }
        }
    }
    assert!(
        stream.buffered() <= stream.dec.capacity(),
        "buffered exceeds capacity"
    );
    assert!(
        stream.buf.allocated() <= alloc_limit,
        "buffer allocation exceeds limit"
    );
    assert_eq!(
        stream.offset(),
        stream.dec.state.borrow().consumed,
        "consumed accounting mismatch"
    );
    assert_eq!(
        stream.offset().saturating_add(stream.buffered() as u64),
        accepted as u64,
        "accepted accounting mismatch"
    );
}
fn run<'a, D: Decode>(
    dec: D,
    source: &'a [u8],
    input: impl Iterator<Item = &'a [u8]>,
    limits: Limits,
) -> Outcome<D::Item, D::Error>
where
    D::Error: Clone + PartialEq + Debug,
{
    assert!(
        dec.capacity() <= Buffer::MAX_LIMIT,
        "capacity exceeds buffer limit"
    );
    let Limits {
        held: held_limit,
        alloc: alloc_limit,
    } = limits;
    assert!(dec.held() <= held_limit, "held exceeds named limit");
    let state = Rc::new(RefCell::new(AuditState::default()));
    let mut stream = Stream::new(Audit {
        inner: dec,
        state: state.clone(),
        source,
        suffix_len: 0,
        held_limit,
    });
    let mut out = Outcome {
        items: Vec::new(),
        failure: None,
        consumed: 0,
    };
    let mut accepted = 0usize;
    for mut chunk in input {
        while !chunk.is_empty() && !stream.is_done() {
            let n = stream.push(chunk);
            accepted = accepted.saturating_add(n);
            chunk = chunk.get(n..).unwrap_or_default();
            let before = stream.offset();
            drain(&mut stream, &mut out, accepted, alloc_limit);
            assert!(
                n > 0 || stream.offset() > before || stream.is_done(),
                "push made no progress"
            );
        }
        if stream.is_done() {
            break;
        }
    }
    stream.end();
    drain(&mut stream, &mut out, accepted, alloc_limit);
    assert!(stream.is_done(), "driver did not finish after end");
    assert_eq!(
        stream.failed(),
        out.failure.as_ref(),
        "retained failure differs"
    );
    out.consumed = stream.offset();
    let calls = state.borrow().calls;
    assert_eq!(stream.push(b"after terminal result"), 21);
    stream.end();
    assert!(stream.next().is_none(), "item after terminal result");
    assert!(
        stream.next().is_none(),
        "repeated error after terminal result"
    );
    assert_eq!(
        state.borrow().calls,
        calls,
        "decoder called after terminal result"
    );
    out
}

/// Checks all observable decoder rules on this input and bounded prefixes.
/// Uses no inferred held-state limit; use [`check_decode_with_held_limit`]
/// when the protocol defines one. Panics on a contract violation.
pub fn check_decode<D: Decode>(make: impl Fn() -> D, data: &[u8])
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_decode_with_held_limit(make, data, usize::MAX);
}
/// Like [`check_decode`], also checking the protocol's named held-byte limit
/// initially and after every decode call.
pub fn check_decode_with_held_limit<D: Decode>(make: impl Fn() -> D, data: &[u8], held_limit: usize)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_limits(
        make,
        data,
        Limits {
            held: held_limit,
            alloc: usize::MAX,
        },
    );
}
/// Like [`check_decode`], also checking that the stream's input buffer
/// never has more than `alloc_limit` bytes allocated, measured by
/// [`Buffer::allocated`] after every push and every item. A [`Stream`]
/// keeps up to twice its limit allocated, so `2 * capacity` is the bound
/// for a decoder whose capacity never changes.
pub fn check_decode_with_alloc_limit<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
    alloc_limit: usize,
) where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_limits(
        make,
        data,
        Limits {
            held: usize::MAX,
            alloc: alloc_limit,
        },
    );
}
fn check_limits<D: Decode>(make: impl Fn() -> D, data: &[u8], limits: Limits)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let whole = run(make(), data, chunks(data, &[]), limits);
    for pattern in [&[1][..], &[7], &[64], &[3, 1, 1000]] {
        assert_eq!(
            run(make(), data, chunks(data, pattern), limits),
            whole,
            "chunking changed decoding"
        );
    }
    for seed in [0, 1, 0x1234_5678] {
        let mut rng = Lcg::new(seed);
        assert_eq!(
            run(make(), data, random_chunks(data, &mut rng, 97), limits),
            whole,
            "random chunking changed decoding"
        );
    }
    for cut in 0..=data.len().min(256) {
        let _ = run(
            make(),
            data.get(..cut).unwrap_or_default(),
            chunks(data.get(..cut).unwrap_or_default(), &[]),
            limits,
        );
    }
}
/// Checks a composed decoder with the same contract as each layer.
/// The generic interface has no layer oracle. Compare with separately run
/// layers in stack-specific tests when that comparison is needed.
pub fn check_stack<D: Decode>(make: impl Fn() -> D, data: &[u8])
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_decode(make, data);
}

/// Checks a constructed value's strict, transactional writer. Successful
/// output must reparse as the same value and re-encode identically. Refused
/// values must leave a nonempty destination unchanged. Panics on failure.
pub fn check_wire_value<M: Wire + PartialEq + Debug>(value: &M) {
    let prefix = [0x5a, 0xc3, 0x17];
    let mut out = prefix.to_vec();
    match value.write(&mut out) {
        Err(_) => assert_eq!(out, prefix, "writer changed destination on error"),
        Ok(()) => {
            assert!(
                out.starts_with(&prefix),
                "writer changed destination prefix"
            );
            let bytes = out.get(prefix.len()..).unwrap_or_default();
            let parsed = match M::parse(bytes) {
                Ok(v) => v,
                Err(_) => panic!("writer output does not parse"),
            };
            assert_eq!(&parsed, value, "wire round trip changed value");
            let encoded = match parsed.to_bytes() {
                Ok(b) => b,
                Err(_) => panic!("reparsed value does not write"),
            };
            assert_eq!(encoded, bytes, "wire re-encoding is not stable");
        }
    }
}
/// Checks round trips for a parsed value and appending into a nonempty
/// destination. A parsed value must write successfully. Invalid input is
/// allowed. Use [`check_wire_value`] to test writer refusal and rollback.
pub fn check_wire<M: Wire + PartialEq + Debug>(data: &[u8]) {
    if let Ok(value) = M::parse(data) {
        check_wire_value(&value);
        let bytes = match value.to_bytes() {
            Ok(b) => b,
            Err(_) => panic!("parsed value does not write"),
        };
        let parsed = match M::parse(&bytes) {
            Ok(v) => v,
            Err(_) => panic!("writer output does not parse"),
        };
        assert_eq!(parsed, value, "wire round trip changed value");
        let again = match parsed.to_bytes() {
            Ok(b) => b,
            Err(_) => panic!("reparsed value does not write"),
        };
        assert_eq!(again, bytes, "wire re-encoding is not stable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::tests::{Fault, TestError};

    #[test]
    #[should_panic(expected = "decoder called after Err or End")]
    fn audit_rejects_call_after_error() {
        let mut audit = Audit {
            inner: Fault::Error,
            state: Rc::new(RefCell::new(AuditState::default())),
            source: b"a",
            suffix_len: 0,
            held_limit: 0,
        };
        assert_eq!(audit.decode(&[], false), Err(TestError));
        let _ = audit.decode(&[], false);
    }

    #[test]
    #[should_panic(expected = "unstable unread suffix")]
    fn audit_rejects_changed_suffix() {
        let mut audit = Audit {
            inner: Fault::Need,
            state: Rc::new(RefCell::new(AuditState::default())),
            source: b"a",
            suffix_len: 0,
            held_limit: 0,
        };
        let _ = audit.decode(b"a", false);
        let _ = audit.decode(b"b", true);
    }
}
