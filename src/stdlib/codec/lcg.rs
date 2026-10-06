extern crate alloc;

use alloc::{string::String, vec::Vec};

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
