use crate::entropy::{Seed, SeededEntropy};

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
