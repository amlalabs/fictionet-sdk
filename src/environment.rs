use crate::entropy::{Seed, SeededEntropy};

pub(crate) struct RunEnvironment {
    pub(crate) clock: std::sync::Arc<crate::clock::Clock>,
    pub(crate) entropy: SeededEntropy,
}

impl RunEnvironment {
    pub(crate) fn new(seed: Seed, mode: crate::RunMode) -> Self {
        Self {
            clock: crate::clock::Clock::new(mode),
            entropy: SeededEntropy::new(seed),
        }
    }
}
