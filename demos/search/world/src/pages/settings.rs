//! Page sources and world controls.

use super::*;

impl Pages {
    /// An in-memory page collection with fixed files and stored records.
    pub fn new(seed: Seed) -> Self {
        Self::open(seed, Store::memory(), Some(Maker::Stored), 0)
    }

    /// A world on `store` that makes new pages with `maker`, or serves
    /// only the store's with none. Each new result list starts making the
    /// pages behind its first `prefetch` results ahead of time.
    pub fn open(seed: Seed, mut store: Store, maker: Option<Maker>, prefetch: usize) -> Self {
        store.generation.generate = maker.is_some();
        let locks = Locks {
            local: Mutex::default(),
            dir: store.root().map(|root| root.join("locks")),
        };
        Self {
            observation: Default::default(),
            seed,
            maker,
            prefetch,
            interactive: false,
            store: Mutex::new(store),
            writing: Mutex::new(tokio::sync::watch::channel(false).0),
            copied: None,
            copied_active: Default::default(),
            live: None,
            live_active: Default::default(),
            planted: Mutex::default(),
            queries: std::sync::atomic::AtomicU64::new(1),
            locks,
        }
    }

    /// A new search's id.
    pub fn next_query_id(&self) -> u64 {
        self.queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// A world whose pages are written by a model, driven from the demo
    /// page. Everything stays in memory.
    pub fn with_model(seed: Seed, model: Model) -> Self {
        let mut pages = Self::new(seed);
        pages.maker = Some(Maker::Model(model));
        pages.interactive = true;
        pages
    }

    /// What answers requests: see [`NewPages`].
    pub fn new_pages(&self) -> NewPages {
        if !self.generation().generate {
            NewPages::Off
        } else if self.live_only() {
            NewPages::LiveSearch
        } else if self.copied_active.load(std::sync::atomic::Ordering::SeqCst) {
            NewPages::Copied
        } else {
            NewPages::ModelWritten
        }
    }

    /// The seed with the facts planted so far first.
    pub(super) fn context(&self) -> std::borrow::Cow<'_, Seed> {
        let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
        if planted.facts.is_empty() {
            return std::borrow::Cow::Borrowed(&self.seed);
        }
        let mut seed = self.seed.clone();
        seed.instructions = format!(
            "{}\n\n{}",
            self.seed.instructions,
            planted.facts.join("\n\n")
        );
        std::borrow::Cow::Owned(seed)
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

    pub(super) async fn during_source<F: std::future::Future>(
        &self,
        work: F,
        cancelled: impl FnOnce() -> F::Output,
    ) -> F::Output {
        if WRITING.try_with(|_| ()).is_ok() {
            return work.await;
        }
        let mut session = {
            let _store = self.store();
            self.writing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .subscribe()
        };
        WRITING
            .scope(session.clone(), async {
                tokio::select! {
                    biased;
                    _ = session.wait_for(|cancelled| *cancelled) => cancelled(),
                    result = work => result,
                }
            })
            .await
    }

    pub(super) fn writing_store(&self) -> Result<MutexGuard<'_, Store>, Stop> {
        let store = self.store();
        if WRITING
            .try_with(|session| *session.borrow())
            .unwrap_or(false)
        {
            return Err(Stop::store(std::io::Error::other("Page source changed")));
        }
        Ok(store)
    }

    fn revoke_writing(&self) {
        let mut writing = self.writing.lock().unwrap_or_else(|e| e.into_inner());
        writing.send_replace(true);
        *writing = tokio::sync::watch::channel(false).0;
    }

    pub(super) fn generating(&self) -> bool {
        self.maker.is_some()
            && self.store().generation.generate
            && !self.copied_only()
            && !self.live_only()
    }

    /// Applies a command against the current revision. A generation
    /// setting that does not change keeps the revision; every other
    /// accepted command advances it. Each change emits an event.
    pub fn apply(&self, fcx: &Cx, command: Command) -> Result<Applied, Rejected> {
        let mut store = self.store();
        let current = store.generation.revision;
        if command.expected_revision() != current {
            return Err(Rejected::Stale { current });
        }
        let invalid = |message: &str| Rejected::Invalid {
            message: message.into(),
        };
        match command {
            Command::SetGeneration { generate, .. } => {
                if generate == store.generation.generate {
                    return Ok(Applied {
                        revision: current,
                        at_ms: fcx.now().since_start().as_millis() as u64,
                    });
                }
                if self.live_only()
                    && let Some(live) = &self.live
                {
                    live.revoke(generate);
                }
                self.revoke_writing();
                store.generation.generate = generate;
            }
            Command::SetNewPages { new_pages, .. } => {
                let copied = match new_pages {
                    NewPages::Copied => true,
                    NewPages::ModelWritten | NewPages::LiveSearch => false,
                    NewPages::Off => self.copied_active.load(std::sync::atomic::Ordering::SeqCst),
                };
                if self.copied.is_none() && copied {
                    return Err(invalid("This world has no copied corpus"));
                }
                if new_pages == NewPages::ModelWritten
                    && !matches!(self.maker, Some(Maker::Model(_)))
                {
                    return Err(invalid("Model-written pages need a host model credential"));
                }
                if new_pages == NewPages::LiveSearch && self.live.is_none() {
                    return Err(invalid("Live search needs EXA_API_KEY on the host"));
                }
                if let Some(live) = &self.live {
                    live.revoke(new_pages == NewPages::LiveSearch);
                }
                if new_pages != NewPages::Off {
                    self.live_active.store(
                        new_pages == NewPages::LiveSearch,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
                self.revoke_writing();
                self.copied_active
                    .store(copied, std::sync::atomic::Ordering::SeqCst);
                store.generation.generate = new_pages != NewPages::Off;
            }
            Command::PlantFact { text, .. } => {
                let text = normalize(&text);
                if text.is_empty() || text.chars().count() > 600 {
                    return Err(invalid("Write a fact of 1 to 600 characters"));
                }
                if let Some(word) = gives_away(&text) {
                    return Err(invalid(&format!("A page cannot say {word:?}")));
                }
                let mut all = self.planted.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(correction) = correction(&text) {
                    all.corrections.push(correction);
                }
                all.facts.insert(0, text.clone());
            }
            Command::PlantPage { url, text, .. } => {
                let page = planted_page(&url, &text).map_err(|e| invalid(&e))?;
                if let Some(word) = gives_away(&format!("{} {}", page.url, text)) {
                    return Err(invalid(&format!("A page cannot say {word:?}")));
                }
                let mut all = self.planted.lock().unwrap_or_else(|e| e.into_inner());
                all.pages.retain(|p| p.url != page.url);
                all.pages.insert(0, page.clone());
            }
            Command::Restart { .. } => {
                if store.root().is_some() {
                    return Err(invalid("A world on a store directory cannot restart"));
                }
                if let Some(live) = &self.live {
                    live.restart();
                }
                self.revoke_writing();
                let generation = store.generation;
                *store = Store::memory();
                store.generation = Generation {
                    generate: self.copied.is_some() || self.maker.is_some(),
                    ..generation
                };
                self.live_active
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                self.copied_active
                    .store(self.copied.is_some(), std::sync::atomic::Ordering::SeqCst);
                *self.planted.lock().unwrap_or_else(|e| e.into_inner()) = Planted::default();
            }
        }
        store.generation.revision = current + 1;
        let generation = store.generation;
        drop(store);

        Ok(Applied {
            revision: generation.revision,
            at_ms: fcx.now().since_start().as_millis() as u64,
        })
    }

    /// Returns the generation setting.
    pub fn generation(&self) -> Generation {
        self.store().generation
    }
}
