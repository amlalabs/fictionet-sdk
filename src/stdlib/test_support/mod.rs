//! Deterministic data and chunking helpers shared by unit tests and fuzz targets.
//! Seeds are explicit. Chunk iterators borrow input and allocate no storage.
//! [`mutate`] edits a byte vector in place, and [`decode_all`] runs a decoder
//! over a whole input. [`decode_chunks`] exposes a chosen chunk schedule and
//! storage assertions against the real stream; [`assert_write`] checks one
//! transactional write and its semantic parse.
//! [`Scripted`] runs caller decisions before decoder calls and after items.
//!
//! [`rounds`] sizes randomized loops and large inputs, so a default
//! `cargo test` stays fast and a deep run is one environment variable away.
//! [`assert_linear_work`] and [`assert_constant_work`] compare counted work
//! across a named dimension without using a clock.
//! [`fictionet::assert_cases!`] checks calls or named input rows against expected
//! results in order.

extern crate alloc;

use alloc::vec::Vec;
use fictionet::stdlib::codec::{Decode, Fail, Lcg, Stream, finish, pump};

pub mod contract;

mod decode;
pub use decode::decode_chunks;
mod wire;
pub use wire::assert_write;

mod scripted;
pub use scripted::Scripted;

/// Checks each argument tuple against its expected result, in order.
/// Each row evaluates the callable, arguments, and expected value once.
/// A failed assertion names the callable and argument expressions.
///
/// ```
/// fictionet::assert_cases! {
///     str::len;
///     ("a") => 1,
///     ("longer") => 6,
/// }
/// ```
///
/// Named rows bind an input pattern in a separate closure for each row.
/// Input types are inferred independently, borrowed temporaries last through
/// the assertion, and inputs are dropped before the next row. A failed
/// assertion includes the row name.
///
/// ```
/// fictionet::assert_cases!(|text| str::parse::<u8>(text);
///     zero: "0" => Ok(0),
///     maximum: "255" => Ok(255),
/// );
/// fictionet::assert_cases!(|(a, b)| a + b;
///     sum: (2, 3) => 5,
/// );
/// ```
#[macro_export]
macro_rules! assert_cases {
    ($call:expr; $(($($arg:expr),+ $(,)?) => $expected:expr),+ $(,)?) => {
        $(
            assert_eq!(
                ($call)($($arg),+),
                $expected,
                "case {}({})",
                stringify!($call),
                stringify!($($arg),+)
            );
        )+
    };
    (|$input:pat_param| $evaluate:expr; $($name:ident: $value:expr => $expected:expr,)+) => {
        $({
            (|$input| assert_eq!($evaluate, $expected, "{}", stringify!($name)))($value);
        })+
    };
}

/// Parses pairs of hex digits for tests, skipping ASCII whitespace.
///
/// Panics on an odd digit count or a non-hex character.
///
/// ```
/// use fictionet::stdlib::test_support::hex;
/// assert_eq!(hex("0a b C\n01"), [10, 188, 1]);
/// ```
pub fn hex(text: &str) -> Vec<u8> {
    let mut digits = text.bytes().filter(|b| !b.is_ascii_whitespace());
    let mut out = Vec::new();
    while let Some(high) = digits.next() {
        let high = fictionet::stdlib::codec::ascii::hex_value(high)
            .expect("non-hex character in test data");
        let low = digits.next().expect("odd hex digit count in test data");
        let low = fictionet::stdlib::codec::ascii::hex_value(low)
            .expect("non-hex character in test data");
        out.push(high << 4 | low);
    }
    out
}

/// The most bytes one [`mutate`] call adds. Only inserting a byte and
/// duplicating a slice grow the input, by 1 and at most this many bytes.
pub const MUTATE_GROWTH: usize = 16;

/// Applies one random edit to `bytes`: set a byte, flip a bit, truncate,
/// insert a byte, or duplicate a slice of up to [`MUTATE_GROWTH`] bytes at
/// another position. One call grows the vector by at most [`MUTATE_GROWTH`]
/// bytes, so `k` calls grow it by at most `k * MUTATE_GROWTH`. An empty
/// vector gets one inserted byte. If the allocation for growth fails, the
/// vector is truncated instead.
pub fn mutate(rng: &mut Lcg, bytes: &mut Vec<u8>) {
    let len = bytes.len();
    let choice = if len == 0 { 3 } else { rng.below(5) };
    if choice >= 3 && bytes.try_reserve(MUTATE_GROWTH).is_err() {
        let at = rng.index(len);
        bytes.truncate(at);
        return;
    }
    match choice {
        0 => {
            let value = rng.next() as u8;
            if let Some(b) = bytes.get_mut(rng.index(len)) {
                *b = value;
            }
        }
        1 => {
            let bit = rng.below(8);
            if let Some(b) = bytes.get_mut(rng.index(len)) {
                *b ^= 1 << bit;
            }
        }
        2 => bytes.truncate(rng.index(len)),
        3 => {
            let at = rng.index(len.saturating_add(1));
            let value = rng.next() as u8;
            bytes.insert(at.min(len), value);
        }
        _ => {
            let start = rng.index(len);
            let n = rng
                .index(MUTATE_GROWTH.min(len.saturating_sub(start)))
                .saturating_add(1);
            let at = rng.index(len.saturating_add(1)).min(len);
            bytes.extend_from_within(start..start.saturating_add(n).min(len));
            // The copy sits at the end; rotate it into place at `at`.
            if let Some(tail) = bytes.get_mut(at..) {
                let n = n.min(tail.len());
                tail.rotate_right(n);
            }
        }
    }
}

/// Runs a fresh decoder over all of `data`, then marks EOF. Returns every
/// item delivered and the stream's terminal failure, if any. Bytes after
/// the decoder's `End` are not decoded; drive a [`Stream`] directly to hand
/// them to another decoder.
pub fn decode_all<D: Decode>(
    make: impl FnOnce() -> D,
    data: &[u8],
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Error: Clone,
{
    let mut stream = Stream::new(make());
    let mut items = Vec::new();
    if let Err(e) = pump(&mut stream, data, |item| items.push(item)) {
        return (items, Some(e));
    }
    let failure = finish(&mut stream, |item| items.push(item)).err();
    (items, failure)
}

/// Pumps bytes into a fresh stream and bounds measured buffer copies by input size.
#[cfg(test)]
pub(crate) fn pump_with_copy_bound<D: Decode>(
    stream: &mut Stream<D>,
    bytes: &[u8],
    on: impl FnMut(D::Item),
) -> Result<usize, Fail<D::Error>>
where
    D::Error: Clone,
{
    assert!(
        stream.moved() == 0 && stream.buffered() == 0,
        "copy bound requires a fresh stream"
    );
    let taken = pump(stream, bytes, on)?;
    let moved = stream.moved();
    assert!(moved < usize::MAX, "copy measurement saturated");
    assert!(
        moved <= bytes.len(),
        "input buffer copied {moved} bytes for {} input bytes",
        bytes.len()
    );
    Ok(taken)
}

/// Cyclic chunking over a borrowed slice.
pub struct Chunks<'a> {
    rest: &'a [u8],
    sizes: &'a [usize],
    at: usize,
}
/// Splits `data` using repeated `sizes`. Zero sizes become one. An empty
/// pattern gives the whole slice. Empty data produces no chunks.
pub fn chunks<'a>(data: &'a [u8], sizes: &'a [usize]) -> Chunks<'a> {
    Chunks {
        rest: data,
        sizes,
        at: 0,
    }
}
impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let n = self
            .sizes
            .get(self.at)
            .copied()
            .unwrap_or(self.rest.len())
            .max(1)
            .min(self.rest.len());
        self.at = if self.at.saturating_add(1) >= self.sizes.len() {
            0
        } else {
            self.at.saturating_add(1)
        };
        let part = self.rest.get(..n)?;
        self.rest = self.rest.get(n..).unwrap_or_default();
        Some(part)
    }
}

/// Random chunking using the shared [`Lcg`], without allocating a pattern.
pub struct RandomChunks<'a, 'r> {
    rest: &'a [u8],
    rng: &'r mut Lcg,
    max: usize,
}
/// Splits `data` into nonempty chunks of at most `max` bytes. Zero means
/// one. Consumes the passed generator, allowing reproducible test sequences.
pub fn random_chunks<'a, 'r>(data: &'a [u8], rng: &'r mut Lcg, max: usize) -> RandomChunks<'a, 'r> {
    RandomChunks {
        rest: data,
        rng,
        max: max.max(1),
    }
}
impl<'a> Iterator for RandomChunks<'a, '_> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let bound = self.max.min(self.rest.len());
        let n = (self.rng.below(u64::try_from(bound).unwrap_or(u64::MAX)) as usize)
            .saturating_add(1)
            .min(bound);
        let part = self.rest.get(..n)?;
        self.rest = self.rest.get(n..).unwrap_or_default();
        Some(part)
    }
}

/// Returns the iteration count for a randomized or large-input test.
pub fn rounds(n: usize) -> usize {
    n
}

/// Checks cumulative work with whole input, byte chunks, and repeated `Need` calls.
/// The allowance is `fixed_allowance + units_per_byte * accepted_bytes`.
/// `measured` must include speculative work and survive message resets.
/// Overflow, saturation, and decreasing measurements fail the check.
/// This measures counted work; assert decoded results separately.
///
/// ```
/// use fictionet::stdlib::{test_support::check_work, protocols::thrift::EncodedMessages};
/// check_work(EncodedMessages::new, &[0x82], EncodedMessages::examined, 16, 16);
/// ```
pub fn check_work<D: Decode>(
    make: impl Fn() -> D,
    bytes: &[u8],
    measured: impl Fn(&D) -> u64,
    fixed_allowance: u64,
    units_per_byte: u64,
) where
    D::Error: Clone,
{
    for chunk in [bytes.len().max(1), 1] {
        let mut stream = Stream::new(make());
        let mut accepted = 0usize;
        let mut previous = 0;
        let mut audit = |stream: &mut Stream<D>, accepted: usize| {
            let allowance = u64::try_from(accepted)
                .ok()
                .and_then(|n| units_per_byte.checked_mul(n))
                .and_then(|n| fixed_allowance.checked_add(n))
                .expect("work allowance overflow");
            let used = measured(stream.decoder());
            assert!(used < u64::MAX, "work measurement saturated");
            assert!(used >= previous, "work measurement decreased");
            assert!(
                used <= allowance,
                "work {used} exceeds allowance {allowance}"
            );
            previous = used;
        };
        audit(&mut stream, accepted);
        loop {
            if accepted < bytes.len() && !stream.is_done() {
                let end = accepted + chunk.min(bytes.len() - accepted);
                accepted += stream.push(&bytes[accepted..end]);
            } else {
                stream.end();
            }
            loop {
                let item = stream.next();
                audit(&mut stream, accepted);
                match item {
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                    None => {
                        for _ in 0..8 {
                            assert!(stream.next().is_none(), "repeated Need changed result");
                            audit(&mut stream, accepted);
                        }
                        break;
                    }
                }
            }
            if stream.is_done() || stream.failed().is_some() {
                break;
            }
        }
    }
}

/// Checks counted work at `n` and `4 * n` along `dimension`.
/// The larger run may use at most four times the work of the smaller run.
/// Each call must start a fresh measurement of the real operation. Count
/// actual scans, copies, or loop steps, including speculative work. Keep
/// other dimensions fixed. This helper does not measure time or count work.
/// Zero work is allowed, but then both runs must report zero.
///
/// ```
/// use fictionet::stdlib::{test_support::assert_linear_work, protocols::thrift::EncodedMessages};
/// use fictionet::stdlib::codec::{Stream, pump};
/// assert_linear_work("empty thrift calls", "messages", 16, |size| {
///     let bytes = [0x82, 0x21, 0, 0, 0].repeat(size);
///     let mut stream = Stream::new(EncodedMessages::new());
///     let mut count = 0;
///     pump(&mut stream, &bytes, |_| count += 1).unwrap();
///     assert_eq!(count, size);
///     stream.decoder().examined()
/// });
/// ```
///
/// # Panics
///
/// If `n` is zero, `4 * n` overflows, a measurement is saturated at
/// `u64::MAX`, or work exceeds the bound. `name` and `dimension` label failures.
pub fn assert_linear_work(
    name: &str,
    dimension: &str,
    n: usize,
    measured: impl FnMut(usize) -> u64,
) {
    compare_work(name, dimension, n, measured, 4);
}

/// Checks that counted work does not grow when `dimension` grows fourfold.
/// Measures fresh operations at `n` and `4 * n`. The larger run may use at
/// most the smaller run's work. Hold the operation count and all other
/// dimensions fixed. For example, vary retained bytes while reading the
/// same number of bytes. Zero work is allowed in both runs.
///
/// ```
/// use fictionet::stdlib::{test_support::assert_constant_work, protocols::thrift::EncodedMessages};
/// use fictionet::stdlib::codec::{Decode, Step};
/// assert_constant_work("first thrift call", "unread suffix bytes", 16, |size| {
///     let mut bytes = vec![0x82, 0x21, 0, 0, 0];
///     bytes.resize(5 + size, 0);
///     let mut decoder = EncodedMessages::new();
///     assert!(matches!(decoder.decode(&bytes, false).unwrap(), Step::Item(_, 5)));
///     decoder.examined()
/// });
/// ```
///
/// # Panics
///
/// If `n` is zero, `4 * n` overflows, a measurement is saturated at
/// `u64::MAX`, or work grows. `name` and `dimension` label failures.
pub fn assert_constant_work(
    name: &str,
    dimension: &str,
    n: usize,
    measured: impl FnMut(usize) -> u64,
) {
    compare_work(name, dimension, n, measured, 1);
}

fn compare_work(
    name: &str,
    dimension: &str,
    n: usize,
    mut measured: impl FnMut(usize) -> u64,
    factor: u128,
) {
    assert!(n > 0, "{name}: {dimension} must be positive");
    let large_n = n.checked_mul(4).expect("work dimension overflow");
    let small = measured(n);
    let large = measured(large_n);
    assert!(
        small < u64::MAX && large < u64::MAX,
        "{name}: {dimension} work measurement saturated"
    );
    let bound = u128::from(small) * factor;
    assert!(
        u128::from(large) <= bound,
        "{name}: {dimension} grew from {n} to {large_n}; work grew from \
         {small} to {large}, exceeding bound {bound}"
    );
}

/// Checks that a refused operation preserves the captured state.
/// Returns the operation's result so callers can check its error.
///
/// ```
/// use fictionet::stdlib::test_support::check_atomic;
/// let mut value = 7;
/// let result = check_atomic(&mut value, |_| Err::<(), _>("refused"), |v| *v);
/// assert_eq!(result, Err("refused"));
/// ```
pub fn check_atomic<T, R, E, S: PartialEq + core::fmt::Debug>(
    value: &mut T,
    operation: impl FnOnce(&mut T) -> Result<R, E>,
    capture: impl Fn(&T) -> S,
) -> Result<R, E> {
    let before = capture(value);
    let result = operation(value);
    if result.is_err() {
        assert_eq!(capture(value), before, "refused operation changed state");
    }
    result
}
