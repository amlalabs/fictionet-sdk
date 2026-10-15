//! Executable decoder and writer contracts for tests and fuzz targets.
//! Use only in test and fuzz targets. Contract failures panic.
//!
//! The harness asserts counts, stable suffixes, capacity, progress, held
//! growth across `Need`, EOF completion, and terminal driver behavior.
//! It compares items, terminal errors, and consumed offsets across fixed
//! and LCG chunkings. Each of the first 256 prefixes is also ended.
//! Arbitrary input may fail to decode. Use [`check_decoded`] for known-valid
//! bytes: it asserts the expected items, terminal success, and full consumption.
//!
//! It cannot inspect hidden memory, prove absence of panics on untested
//! input, or infer a protocol's held-state limit or exact wire grammar.
//! Use [`check_decode_limits`] to check a named state limit and the input
//! buffer's allocation bound in one traversal. The separate
//! [`check_decode_with_held_limit`] and [`check_decode_with_alloc_limit`]
//! helpers check either bound alone. A decoder
//! must report its state accurately. Mode timing is enforced by the
//! one-item interface. [`check_wire_value`] tests constructed writer values,
//! including values a parser cannot produce.

extern crate alloc;

use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, fmt::Debug};
use fictionet::stdlib::codec::{Buffer, Decode, Fail, Lcg, Step, Stream, Wire};
use fictionet::stdlib::test_support::{chunks, random_chunks};

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
            stream.buffered() <= stream.decoder().capacity(),
            "buffered exceeds capacity"
        );
        assert!(
            stream.allocated() <= alloc_limit,
            "buffer allocation exceeds limit"
        );
        assert_eq!(
            stream.offset(),
            stream.decoder().state.borrow().consumed,
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
                assert!(
                    !matches!(e, Fail::Refused { .. }),
                    "driver reported Refused"
                );
                assert!(out.failure.is_none(), "error reported more than once");
                out.failure = Some(e);
            }
        }
    }
    assert!(
        stream.buffered() <= stream.decoder().capacity(),
        "buffered exceeds capacity"
    );
    assert!(
        stream.allocated() <= alloc_limit,
        "buffer allocation exceeds limit"
    );
    assert_eq!(
        stream.offset(),
        stream.decoder().state.borrow().consumed,
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
/// Returns the whole-input items and terminal failure.
/// The caller must assert the returned pair to check protocol semantics.
/// For known-valid input, use [`check_decoded`].
/// Uses no inferred held-state limit; use [`check_decode_with_held_limit`]
/// when the protocol defines one. Panics on a contract violation.
pub fn check_decode<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_decode_with_held_limit(make, data, usize::MAX)
}
/// Like [`check_decode`], also checking the protocol's named held-byte limit
/// initially and after every decode call.
/// The returned pair is for the caller to assert. Use [`check_decoded`] for
/// known-valid input.
pub fn check_decode_with_held_limit<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
    held_limit: usize,
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_decode_limits(make, data, held_limit, usize::MAX)
}
/// Like [`check_decode`], also checking that the stream's input buffer
/// never has more than `alloc_limit` bytes allocated, measured by
/// [`Buffer::allocated`] after every push and every item. A [`Stream`]
/// keeps up to twice its limit allocated, so `2 * capacity` is the bound
/// for a decoder whose capacity never changes.
/// The returned pair is for the caller to assert. Use [`check_decoded`] for
/// known-valid input.
pub fn check_decode_with_alloc_limit<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
    alloc_limit: usize,
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    check_decode_limits(make, data, usize::MAX, alloc_limit)
}

/// Like [`check_decode`], checking both memory bounds in one traversal of
/// the input schedules and bounded prefixes. Returns the whole-input items
/// and terminal failure. Panics on a contract violation.
/// The returned pair is for the caller to assert. Use [`check_decoded`] for
/// known-valid input.
///
/// Checks `held_limit` initially and after every decode call, as in
/// [`check_decode_with_held_limit`]. Checks `alloc_limit` after every push
/// and every item, as in [`check_decode_with_alloc_limit`].
///
/// ```
/// use fictionet::stdlib::{codec::{Ending, Lines}, test_support::contract};
/// let (items, failure) = contract::check_decode_limits(
///     || Lines::new(16, Ending::LfOrCrlf), b"one\ntwo\n", 0, 36,
/// );
/// assert_eq!(items, [Ok(b"one".to_vec()), Ok(b"two".to_vec())]);
/// assert_eq!(failure, None);
/// ```
pub fn check_decode_limits<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
    held_limit: usize,
    alloc_limit: usize,
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let whole = check_limits(
        make,
        data,
        Limits {
            held: held_limit,
            alloc: alloc_limit,
        },
    );
    (whole.items, whole.failure)
}

/// Checks decoding with an input allocation bound of twice the initial
/// capacity. The decoder's capacity must stay fixed.
/// The returned pair is for the caller to assert. Use [`check_decoded`] for
/// known-valid input.
pub fn check_decode_capacity<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let limit = 2 * make().capacity();
    check_decode_with_alloc_limit(make, data, limit)
}

/// Checks that known-valid bytes yield the expected items, finish without
/// failure, and consume the entire input. Panics if any assertion fails.
/// Checks the same decoder rules, chunkings, prefixes, and memory bounds as
/// [`check_decode_limits`] in one traversal. Use `usize::MAX` for a memory
/// bound that the protocol does not define.
///
/// ```
/// use fictionet::stdlib::{codec::{Ending, Lines}, test_support::contract};
/// contract::check_decoded(
///     || Lines::new(16, Ending::LfOrCrlf), b"one\ntwo\n",
///     &[Ok(b"one".to_vec()), Ok(b"two".to_vec())], 0, 36,
/// );
/// ```
pub fn check_decoded<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
    expected: &[D::Item],
    held_limit: usize,
    alloc_limit: usize,
) where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let whole = check_limits(
        make,
        data,
        Limits {
            held: held_limit,
            alloc: alloc_limit,
        },
    );
    assert_eq!(whole.failure, None, "known-valid input failed to decode");
    assert_eq!(whole.items, expected, "decoded items differ from expected");
    assert_eq!(
        whole.consumed,
        data.len() as u64,
        "decoder did not consume all known-valid input"
    );
}

fn check_limits<D: Decode>(
    make: impl Fn() -> D,
    data: &[u8],
    limits: Limits,
) -> Outcome<D::Item, D::Error>
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
    whole
}
/// Checks that every nonempty strict prefix of a complete unit is truncated.
/// Empty input must end cleanly.
///
/// ```
/// use fictionet::stdlib::{codec::Frames, test_support::contract, tpkt};
/// let bytes = [3, 0, 0, 7, 2, 0xf0, 0x80];
/// contract::check_truncated(Frames::<tpkt::Packet>::new, &bytes);
/// ```
pub fn check_truncated<D: Decode>(make: impl Fn() -> D, unit: &[u8])
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    assert_eq!(check_decode(&make, &[]), (Vec::new(), None));
    for cut in 1..unit.len() {
        assert_eq!(
            check_decode(&make, &unit[..cut]),
            (Vec::new(), Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }
}

/// Checks successful writing and wire round trips. Returns the written bytes.
///
/// ```
/// use fictionet::stdlib::{smtp, test_support::contract};
/// let value = smtp::Request::Helo("example.com".into());
/// assert_eq!(contract::check_written(&value), b"HELO example.com\r\n");
/// ```
pub fn check_written<M: Wire + PartialEq + Debug>(value: &M) -> Vec<u8> {
    let bytes = value.to_bytes().expect("test value must write");
    let parsed = M::parse(&bytes).expect("writer output does not parse");
    assert_eq!(&parsed, value, "wire round trip changed value");
    check_wire_value(value);
    check_wire::<M>(&bytes);
    bytes
}

/// Checks writing and exact parsing, including strict prefixes and trailing bytes.
///
/// ```
/// use fictionet::stdlib::{smtp, test_support::contract};
/// let value = smtp::Request::Helo("example.com".into());
/// assert_eq!(contract::check_exact(&value), b"HELO example.com\r\n");
/// ```
pub fn check_exact<M: Wire + PartialEq + Debug>(value: &M) -> Vec<u8> {
    let bytes = check_written(value);
    for cut in 0..bytes.len() {
        assert!(M::parse(&bytes[..cut]).is_err(), "prefix {cut}");
    }
    for tail in [0x00, 0xff] {
        let mut trailing = bytes.clone();
        trailing.push(tail);
        assert!(M::parse(&trailing).is_err(), "trailing byte {tail}");
    }
    bytes
}

/// Checks that a test value refuses writing without changing the destination.
/// Also checks that writing into a new vector fails. Returns the write error.
///
/// ```
/// use fictionet::stdlib::{smtp, test_support::contract};
/// let value = smtp::Request::Helo("bad\r\nhost".into());
/// assert_eq!(contract::check_refused(&value), smtp::Error::Unwritable);
/// ```
pub fn check_refused<M: Wire + Debug>(value: &M) -> M::WriteError {
    let prefix = [0x5a, 0xc3, 0x17];
    let mut out = prefix.to_vec();
    let error = value
        .write(&mut out)
        .expect_err("test value must refuse writing");
    assert_eq!(
        out, prefix,
        "writer changed destination on error: {value:?}"
    );
    assert!(
        value.to_bytes().is_err(),
        "refused value wrote into a new vector: {value:?}"
    );
    error
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

/// Checks collection against exact wire parsing, including limits and writer contracts.
pub fn check_collect<M>(data: &[u8], limit: usize) -> Result<M, M::ParseError>
where
    M: Wire + Clone + PartialEq + Debug,
    M::ParseError: Clone + PartialEq + Debug,
{
    use fictionet::stdlib::codec::{Collect, CollectError};
    use fictionet::stdlib::test_support::decode_all;
    let make = || Collect::<M>::new(limit);
    check_decode_with_alloc_limit(make, data, 2 * (limit + 1));
    check_wire::<M>(data);
    let parsed = M::parse(data);
    let (items, failure) = decode_all(make, data);
    if data.len() <= limit {
        assert_eq!(
            failure,
            parsed
                .clone()
                .err()
                .map(|e| Fail::Protocol(CollectError::Parse(e)))
        );
        assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
    } else {
        assert!(items.is_empty());
        assert_eq!(
            failure,
            Some(Fail::Protocol(CollectError::TooLong { limit }))
        );
    }
    parsed
}

/// Checks raw collection and a contextual parser whose errors remain items.
pub fn check_collect_with<T, E>(
    data: &[u8],
    limit: usize,
    parse: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<T, E>
where
    T: Clone + PartialEq + Debug,
    E: Clone + PartialEq + Debug,
{
    use fictionet::stdlib::codec::{Collect, CollectError};
    use fictionet::stdlib::test_support::decode_all;
    let make = || Collect::bytes(limit).map(|d| parse(&d));
    check_decode_with_alloc_limit(make, data, 2 * (limit + 1));
    assert_eq!(
        decode_all(|| Collect::bytes(limit), data),
        if data.len() <= limit {
            (vec![data.to_vec()], None)
        } else {
            (
                vec![],
                Some(Fail::Protocol(CollectError::TooLong { limit })),
            )
        }
    );
    let parsed = parse(data);
    let (items, failure) = decode_all(make, data);
    if data.len() <= limit {
        assert_eq!(failure, None);
        assert_eq!(items, vec![parsed.clone()]);
    } else {
        assert!(items.is_empty());
        assert_eq!(
            failure,
            Some(Fail::Protocol(CollectError::TooLong { limit }))
        );
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Error as TestError;

    #[derive(Debug, PartialEq)]
    struct Refusing;
    impl Wire for Refusing {
        type ParseError = TestError;
        type WriteError = TestError;

        fn parse(_: &[u8]) -> Result<Self, TestError> {
            Err(TestError)
        }

        fn write(&self, _: &mut Vec<u8>) -> Result<(), TestError> {
            Err(TestError)
        }
    }

    #[test]
    #[should_panic(expected = "test value must write")]
    fn check_written_rejects_refusing_writer() {
        check_written(&Refusing);
    }

    #[test]
    fn check_wire_value_allows_refusing_writer() {
        check_wire_value(&Refusing);
    }

    enum Fault {
        Error,
        Need,
        End,
    }
    impl Decode for Fault {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "fault";
        fn capacity(&self) -> usize {
            4
        }
        fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
            match self {
                Self::Error => Err(TestError),
                Self::Need => Ok(Step::Need),
                Self::End => Ok(Step::End),
            }
        }
    }

    #[test]
    #[should_panic(expected = "decoder did not consume all known-valid input")]
    fn decoded_requires_full_consumption() {
        check_decoded(|| Fault::End, b"a", &[], 0, 8);
    }

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
