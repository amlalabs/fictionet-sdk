//! Deterministic data and chunking helpers shared by unit tests and fuzz targets.
//! Seeds are explicit. Chunk iterators borrow input and allocate no storage.
//! [`mutate`] edits a byte vector in place, and [`decode_all`] runs a decoder
//! over a whole input.
//!
//! [`rounds`] sizes randomized loops and large inputs, so a default
//! `cargo test` stays fast and a deep run is one environment variable away.
//! [`assert_linear`] checks that work grows linearly with input size by
//! comparing two sizes, instead of holding a test to a wall-clock limit.

extern crate alloc;

use alloc::vec::Vec;
use fictionet::stdlib::codec::{Decode, Fail, Lcg, Stream, finish, pump};

pub mod contract;

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
            #[allow(clippy::redundant_closure_call)]
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

/// The environment variable that scales [`rounds`]: a positive integer,
/// read once per process. Unset, empty or invalid means 1.
pub const SCALE_VAR: &str = "FICTIONET_TEST_SCALE";

/// The scale [`rounds`] multiplies by: [`SCALE_VAR`] if it holds a positive
/// integer, otherwise 1.
pub fn scale() -> usize {
    static SCALE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SCALE.get_or_init(|| {
        std::env::var(SCALE_VAR)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(1)
    })
}

/// Returns `n` times [`scale`]: the iteration count or input size for a
/// randomized or large-input test. Tests pass the count that keeps a default
/// run fast; `FICTIONET_TEST_SCALE=100 cargo test` runs a hundred times as
/// many rounds.
///
/// ```
/// use fictionet::stdlib::test_support::{rounds, scale};
/// assert_eq!(rounds(500), 500 * scale());
/// ```
pub fn rounds(n: usize) -> usize {
    n.saturating_mul(scale())
}

/// Checks that `run(size)` takes time linear in `size`, not quadratic.
/// Times `run(n)` and `run(4 * n)`, alternating, three times each, and
/// keeps the fastest of each. Linear work takes about 4 times as long at
/// 4 times the size, quadratic work about 16 times. The check fails when the
/// ratio exceeds 10. It times the CPU the calling thread uses, not the
/// clock on the wall, so other work on a busy machine does not count. Pick
/// `n` so that `run(n)` takes at least a millisecond, or timer noise decides
/// the ratio.
///
/// `run` builds its input and decodes it; building with `repeat` or a loop
/// is linear too, so it does not hide quadratic decoding.
///
/// # Panics
///
/// If the ratio exceeds 10. `name` labels the message.
pub fn assert_linear(name: &str, n: usize, mut run: impl FnMut(usize)) {
    let time = |run: &mut dyn FnMut(usize), size| {
        let started = thread_cpu_time();
        run(size);
        thread_cpu_time().saturating_sub(started)
    };
    let (mut small, mut large) = (core::time::Duration::MAX, core::time::Duration::MAX);
    for _ in 0..3 {
        small = small.min(time(&mut run, n));
        large = large.min(time(&mut run, n.saturating_mul(4)));
    }
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-6);
    assert!(
        ratio <= 10.0,
        "{name}: 4 times the input took {ratio:.1} times as long \
         ({small:?} for {n}, {large:?} for {}); linear work stays near 4",
        n.saturating_mul(4)
    );
}

/// Returns the CPU time used by the calling thread when available.
/// Otherwise returns elapsed wall time since the first fallback call.
pub fn thread_cpu_time() -> core::time::Duration {
    fictionet::cfg_std! {
    #[cfg(unix)]
    {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `t` is a valid, writable timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) } == 0 {
            return core::time::Duration::new(
                u64::try_from(t.tv_sec).unwrap_or_default(),
                u32::try_from(t.tv_nsec).unwrap_or_default(),
            );
        }
    }
    }
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

/// Checks cumulative work with whole input, byte chunks, and repeated `Need` calls.
/// The allowance is `fixed_allowance + units_per_byte * accepted_bytes`.
/// `measured` must include speculative work and survive message resets.
/// Overflow, saturation, and decreasing measurements fail the check.
/// This audits counted work; use contract checks for decoded results.
///
/// ```
/// use fictionet::stdlib::{test_support::check_work, thrift::EncodedMessages};
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

#[cfg(test)]
mod tests {
    use super::assert_linear;
    use core::hint::black_box;

    #[test]
    fn cases_evaluate_once_in_order() {
        let steps = core::cell::RefCell::new(Vec::new());
        let mark = |n| {
            steps.borrow_mut().push(n);
            n
        };
        fictionet::assert_cases! {
            { mark(0); |a, b| { mark(3); a + b } };
            (mark(1), mark(2)) => mark(4) - 1,
            (mark(5), mark(6)) => mark(7) + 4,
        }
        assert_eq!(*steps.borrow(), [0, 1, 2, 3, 4, 0, 5, 6, 3, 7]);
    }

    #[test]
    #[should_panic(expected = "case str::len(\"wrong\")")]
    fn cases_name_the_failed_input() {
        fn later() -> &'static str {
            panic!("continued after failure")
        }
        fictionet::assert_cases! {
            str::len;
            ("a") => 1,
            ("wrong") => 0,
            (later()) => 0,
        }
    }

    #[test]
    fn named_cases_keep_types_and_order() {
        let mut visited = Vec::new();
        fictionet::assert_cases!(|(name, value)| { visited.push(name); value };
            byte: ("byte", 7u8) => 7u8,
            text: ("text", "value") => "value",
        );
        assert_eq!(visited, ["byte", "text"]);
    }

    #[test]
    fn named_cases_borrow_temporaries_and_infer_closures() {
        fn apply(edit: &dyn Fn(&mut u8)) -> u8 {
            let mut value = 0;
            edit(&mut value);
            value
        }
        fictionet::assert_cases!(|edit| apply(edit);
            set: &|value| *value = 3 => 3,
            increment: &|value| *value += 1 => 1,
        );
        fictionet::assert_cases!(|bytes| bytes;
            borrowed_format: format!("{}", 42).as_bytes() => b"42",
            borrowed_repeat: "x".repeat(2).as_bytes() => b"xx",
        );
    }

    #[test]
    #[should_panic(expected = "boundary_case")]
    fn named_cases_report_failure_name() {
        fictionet::assert_cases!(|value| value;
            boundary_case: 1 => 2,
        );
    }

    #[test]
    fn cases_evaluate_once_in_order_and_borrow() {
        let order = core::cell::RefCell::new(Vec::new());
        fictionet::assert_cases!(|input| { order.borrow_mut().push(2); AsRef::<[i32]>::as_ref(&input) };
            one_element: { order.borrow_mut().push(1); [1] } => { order.borrow_mut().push(3); [1] },
            two_elements: { order.borrow_mut().push(4); [2, 3] } => { order.borrow_mut().push(5); [2, 3] },
        );
        assert_eq!(*order.borrow(), [1, 2, 3, 4, 2, 5]);
    }

    #[test]
    #[should_panic(expected = "case |input: [u8; 3]| input.len()([1, 2, 3])")]
    fn cases_name_the_failing_input() {
        fictionet::assert_cases!(|input: [u8; 3]| input.len(); ([1, 2, 3]) => 0);
    }

    #[test]
    fn hex_pairs_ignore_ascii_whitespace() {
        assert_eq!(super::hex(" 0 a B\tc\n01\r\x0c"), [10, 188, 1]);
        assert!(super::hex(" \t\n").is_empty());
    }

    #[test]
    #[should_panic(expected = "odd hex digit count")]
    fn hex_rejects_odd_digits() {
        super::hex("01 a");
    }

    #[test]
    #[should_panic(expected = "non-hex character")]
    fn hex_rejects_non_hex() {
        super::hex("0g");
    }

    #[test]
    #[should_panic(expected = "non-hex character")]
    fn hex_rejects_non_ascii_whitespace() {
        super::hex("01\u{a0}23");
    }

    #[derive(Default)]
    struct Counted(u64);
    impl super::Decode for Counted {
        type Item = ();
        type Error = core::convert::Infallible;
        const NAME: &'static str = "counted";
        fn capacity(&self) -> usize {
            1024
        }
        fn decode(
            &mut self,
            _: &[u8],
            _: bool,
        ) -> Result<fictionet::stdlib::codec::Step<()>, Self::Error> {
            self.0 += 1;
            Ok(fictionet::stdlib::codec::Step::Need)
        }
    }

    #[test]
    #[should_panic(expected = "exceeds allowance")]
    fn repeated_need_work_is_counted() {
        super::check_work(Counted::default, b"x", |d| d.0, 1, 0);
    }

    #[test]
    #[should_panic(expected = "work allowance overflow")]
    fn audit_overflow_fails() {
        super::check_work(Counted::default, b"x", |d| d.0, u64::MAX, 1);
    }

    #[test]
    #[should_panic(expected = "work measurement saturated")]
    fn saturated_measurement_fails() {
        super::check_work(|| Counted(u64::MAX), b"", |d| d.0, u64::MAX, 0);
    }

    #[test]
    #[should_panic(expected = "work measurement decreased")]
    fn decreasing_measurement_fails() {
        super::check_work(Counted::default, b"x", |d| 10 - d.0, 10, 0);
    }

    #[test]
    #[should_panic(expected = "refused operation changed state")]
    fn atomic_check_detects_mutation() {
        let _ = super::check_atomic(
            &mut 0,
            |v| {
                *v = 1;
                Err::<(), _>(())
            },
            |v| *v,
        );
    }

    #[test]
    fn atomic_check_allows_success() {
        assert_eq!(
            super::check_atomic(
                &mut 0,
                |v| {
                    *v = 1;
                    Ok::<_, ()>(2)
                },
                |v| *v
            ),
            Ok(2)
        );
    }

    fn work(steps: usize) {
        let mut x = 0u64;
        for i in 0..steps {
            x = black_box(x.wrapping_mul(31).wrapping_add(i as u64));
        }
        black_box(x);
    }

    #[test]
    fn linear_work_passes() {
        assert_linear("linear", 1_000_000, work);
    }

    #[test]
    #[should_panic(expected = "times as long")]
    fn quadratic_work_fails() {
        assert_linear("quadratic", 500, |n| work(n * n));
    }
}
