use std::sync::Mutex;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

/// The 32 bytes that initialize a run's ChaCha20 random stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed(pub [u8; 32]);

impl Seed {
    /// Draws a fresh seed from the operating system.
    pub fn random() -> Self {
        let mut bytes = [0; 32];
        crate::sys::random_bytes(&mut bytes).expect("operating system entropy unavailable");
        Self(bytes)
    }

    /// Expands a test seed using SHA-256 of `fictionet.seed.v1\0` followed
    /// by the eight little-endian bytes of `n`. This does not add entropy.
    pub fn from_u64(n: u64) -> Self {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"fictionet.seed.v1\0");
        hash.update(&n.to_le_bytes());
        Self(hash.finish().as_ref().try_into().unwrap())
    }
}

impl std::fmt::Display for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A source of random bytes for services and protocol fault decisions.
/// All methods consume the same byte stream, including partial fills.
pub trait Entropy: Send + Sync {
    /// Fills every byte, advancing the source by exactly the output length.
    fn fill_random(&self, out: &mut [u8]);

    /// Reads eight bytes and decodes them in little-endian order.
    fn random_u64(&self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_random(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    /// Reads eight bytes and maps their high 53 bits uniformly to [0, 1).
    fn random_f64(&self) -> f64 {
        (self.random_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Draws uniformly below `bound` by rejecting values below
    /// `bound.wrapping_neg() % bound`, then reducing modulo `bound`.
    /// A zero bound returns zero without consuming bytes.
    fn random_below(&self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let n = self.random_u64();
            if n >= threshold {
                return n % bound;
            }
        }
    }
}

impl<T: Entropy + ?Sized> Entropy for std::sync::Arc<T> {
    fn fill_random(&self, out: &mut [u8]) {
        (**self).fill_random(out);
    }
}

/// A standalone ChaCha20 source for codec tests and service harnesses.
/// A world uses its [`Cx`](crate::Cx) instead, sharing the run's stream.
pub struct SeededEntropy(Mutex<Stream>);

impl SeededEntropy {
    /// Starts the ChaCha20 stream at counter and stream number zero.
    pub fn new(seed: Seed) -> Self {
        Self(Mutex::new(Stream {
            rng: ChaCha20Rng::from_seed(seed.0),
            bytes: [0; 64],
            at: 64,
        }))
    }
}

struct Stream {
    rng: ChaCha20Rng,
    bytes: [u8; 64],
    at: usize,
}

impl Entropy for SeededEntropy {
    fn fill_random(&self, mut out: &mut [u8]) {
        let mut stream = self.0.lock().unwrap_or_else(|e| e.into_inner());
        while !out.is_empty() {
            if stream.at == 64 {
                let Stream { rng, bytes, at } = &mut *stream;
                rng.fill_bytes(bytes);
                *at = 0;
            }
            let n = out.len().min(64 - stream.at);
            out[..n].copy_from_slice(&stream.bytes[stream.at..stream.at + n]);
            stream.at += n;
            out = &mut out[n..];
        }
    }
}

pub(crate) struct RunEnvironment {
    pub(crate) seed: Seed,
    pub(crate) clock: std::sync::Arc<crate::clock::Clock>,
    pub(crate) entropy: SeededEntropy,
}

impl RunEnvironment {
    pub(crate) fn require_real_io(&self) -> std::io::Result<()> {
        if self.clock.mode() == crate::RunMode::Lab {
            Err(std::io::Error::other(
                "real I/O is unavailable in a lab run",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn new(seed: Seed, mode: crate::RunMode) -> Self {
        Self {
            seed,
            clock: crate::clock::Clock::new(mode),
            entropy: SeededEntropy::new(seed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_expansion_known_answer() {
        assert_eq!(
            Seed::from_u64(42).to_string(),
            "65d4f550c9c6f27273c52d03f070cf94c23b75a264efbd43521cbba4262e274c"
        );
    }

    #[test]
    fn chacha20_known_answer_and_mixed_reads() {
        let source = SeededEntropy::new(Seed([0; 32]));
        let mut first = [0; 64];
        source.fill_random(&mut first);
        let hex: String = first.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            concat!(
                "76b8e0ada0f13d90405d6ae55386bd28",
                "bdd219b8a08ded1aa836efcc8b770dc7",
                "da41597c5157488d7724e03fb8d84a37",
                "6a43b8f41518a11cc387b669b2ee6586"
            )
        );
        let source = SeededEntropy::new(Seed([0; 32]));
        let mut prefix = [0; 3];
        source.fill_random(&mut prefix);
        assert_eq!(prefix, first[..3]);
        assert_eq!(
            source.random_u64(),
            u64::from_le_bytes(first[3..11].try_into().unwrap())
        );
        let n = u64::from_le_bytes(first[11..19].try_into().unwrap());
        assert_eq!(source.random_f64(), (n >> 11) as f64 / (1u64 << 53) as f64);
        source.fill_random(&mut []);
        let mut tail = [0; 110];
        source.fill_random(&mut tail);
        let whole = SeededEntropy::new(Seed([0; 32]));
        let mut bytes = [0; 129];
        whole.fill_random(&mut bytes);
        assert_eq!(tail, bytes[19..]);
    }

    #[test]
    fn bounded_draw_rejects_without_modulo_bias() {
        struct Words(Mutex<std::collections::VecDeque<u64>>);
        impl Entropy for Words {
            fn fill_random(&self, out: &mut [u8]) {
                out.copy_from_slice(&self.0.lock().unwrap().pop_front().unwrap().to_le_bytes());
            }
        }
        let source = Words(Mutex::new([0, 5, 16, u64::MAX].into()));
        assert_eq!(source.random_below(0), 0);
        assert_eq!(source.random_below(10), 6);
        assert_eq!(source.random_below(u64::MAX), 0);
        assert!(source.0.lock().unwrap().is_empty());
    }
}
