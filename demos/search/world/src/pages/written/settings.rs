//! The written web's construction and what it reports about itself.

use super::*;

impl Written {
    /// A world on `store` that makes new pages with `maker`, or serves
    /// only the store's with none. Each new result list starts making the
    /// pages behind its first `prefetch` results ahead of time.
    pub fn open(seed: Seed, store: Store, maker: Option<Maker>, prefetch: usize) -> Self {
        let locks = Locks {
            local: Mutex::default(),
            dir: store.root().map(|root| root.join("locks")),
        };
        Self {
            seed,
            maker,
            prefetch,
            store: Mutex::new(store),
            originals: Default::default(),
            locks,
        }
    }

    /// Returns the seed used by this world.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The model that makes new pages, or the kind's name (`stored`,
    /// `replay`) when no model does.
    pub fn model(&self) -> String {
        match &self.maker {
            Some(Maker::Model(model)) => model.model.clone(),
            _ => self.generator_kind().as_str().into(),
        }
    }

    /// What makes new pages.
    pub fn generator_kind(&self) -> GeneratorKind {
        match &self.maker {
            Some(Maker::Stored) => GeneratorKind::Stored,
            Some(Maker::Model(model)) => GeneratorKind::Model(model.provider),
            None => GeneratorKind::Replay,
        }
    }

    /// Pages made ahead of time behind each new result list.
    pub fn prefetch(&self) -> usize {
        self.prefetch
    }

    /// The store, with what other worlds on it have added. If that cannot be
    /// read, the world goes on with what it has, and its next write fails.
    pub(super) fn store(&self) -> MutexGuard<'_, Store> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = store.catch_up();
        store
    }

    /// Whether new pages and result lists are made.
    pub(super) fn generating(&self) -> bool {
        self.maker.is_some()
    }
}
