//! Deterministic data and chunking helpers shared by unit tests and fuzz targets.
//! Seeds are explicit. Chunk iterators borrow input and allocate no storage.
//! [`mutate`] edits a byte vector in place, and [`decode_all`] runs a decoder
//! over a whole input.
//!
//! [`rounds`] sizes randomized loops and large inputs, so a default
//! `cargo test` stays fast and a deep run is one environment variable away.
//! [`assert_linear`] checks that work grows linearly with input size by
//! comparing two sizes, instead of holding a test to a wall-clock limit.

use super::{
    Decode, Fail, Stream,
    alloc::{string::String, vec::Vec},
    finish, pump,
};

/// The LCG used by the SDK's protocol tests. This is not a cryptographic RNG.
#[derive(Clone, Debug)]
pub struct Lcg(u64);
impl Lcg {
    /// Starts the generator at an explicit seed.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    /// Advances the generator and returns its upper 31 bits.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    /// Returns a number below `n`. Returns zero when `n` is zero.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    /// Fills an existing, caller-bounded byte slice.
    pub fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next() as u8;
        }
    }
    /// Returns an index below `len`, or zero when `len` is zero. Draws
    /// through [`below`](Self::below), so it shares that method's 31-bit
    /// range and modulo reduction.
    pub fn index(&mut self, len: usize) -> usize {
        let n = self.below(u64::try_from(len).unwrap_or(u64::MAX));
        usize::try_from(n).unwrap_or_default()
    }
    /// Returns `true` or `false`, each about half the time.
    pub fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
    /// Returns up to `max` random bytes; the length is drawn from `0..=max`.
    /// Returns an empty vector if the allocation fails.
    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.index(max.saturating_add(1));
        let mut out = Vec::new();
        if out.try_reserve_exact(n).is_err() {
            return out;
        }
        out.resize(n, 0);
        self.fill(&mut out);
        out
    }
    /// Returns up to `max` printable ASCII characters (`' '` through `'~'`);
    /// the length is drawn from `0..=max`. Returns an empty string if the
    /// allocation fails.
    pub fn text(&mut self, max: usize) -> String {
        let n = self.index(max.saturating_add(1));
        let mut out = String::new();
        if out.try_reserve_exact(n).is_err() {
            return out;
        }
        for _ in 0..n {
            out.push(char::from(b' '.saturating_add(self.below(95) as u8)));
        }
        out
    }
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
/// use fictionet::stdlib::codec::test_support::{rounds, scale};
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

/// The CPU time the calling thread has used, where the platform reports it,
/// and the time since the first call otherwise.
fn thread_cpu_time() -> core::time::Duration {
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
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

#[cfg(test)]
mod tests {
    use super::assert_linear;
    use core::hint::black_box;

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
