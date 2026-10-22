//! Page sources, generation limits and world controls.

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
            observation: Mutex::new(None),
            seed,
            maker,
            prefetch,
            live_calls: None,
            store: Mutex::new(store),
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

    /// A world whose pages are written by a bounded model. Everything stays in memory.
    pub fn with_model(seed: Seed, model: Model) -> Self {
        let mut pages = Self::new(seed);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        pages.maker = Some(Maker::Model(model.live(calls.clone())));
        pages.prefetch = 5;
        pages.live_calls = Some(calls);
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
            _ => names::name(&self.generator_kind()),
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

    pub(super) fn generating(&self) -> bool {
        self.maker.is_some() && self.store().generation.generate
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
        let mut planted = None;
        match command {
            Command::SetGeneration { generate, .. } => {
                if generate == store.generation.generate {
                    return Ok(Applied {
                        revision: current,
                        at_ms: fcx.now().since_start().as_millis() as u64,
                    });
                }
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
                    return Err(invalid("Model-written pages need OPENROUTER_API_KEY"));
                }
                if new_pages == NewPages::LiveSearch && self.live.is_none() {
                    return Err(invalid("Live search needs EXA_API_KEY on the host"));
                }
                if new_pages != NewPages::Off {
                    self.live_active.store(
                        new_pages == NewPages::LiveSearch,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
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
                planted = Some(("fact", text, String::new()));
            }
            Command::PlantPage { url, text, .. } => {
                let page = planted_page(&url, &text).map_err(|e| invalid(&e))?;
                if let Some(word) = gives_away(&format!("{} {}", page.url, text)) {
                    return Err(invalid(&format!("A page cannot say {word:?}")));
                }
                let mut all = self.planted.lock().unwrap_or_else(|e| e.into_inner());
                all.pages.retain(|p| p.url != page.url);
                all.pages.insert(0, page.clone());
                planted = Some(("page", page.title, page.url));
            }
            Command::Restart { .. } => {
                if store.root().is_some() {
                    return Err(invalid("A world on a store directory cannot restart"));
                }
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
                fcx.emit("web", "restarted", |event| {
                    event
                        .summary(format_args!("run restarted at revision {}", current + 1))
                        .field("revision", current + 1)
                });
            }
        }
        store.generation.revision = current + 1;
        let generation = store.generation;
        let copied = self.copied_active.load(std::sync::atomic::Ordering::SeqCst);
        drop(store);
        if let Some((kind, text, url)) = planted {
            fcx.emit("web", "planted", |event| {
                event
                    .summary(format_args!("planted a {kind}: {text}"))
                    .field("plant", kind)
                    .field("text", text.as_str())
                    .field("url", url.as_str())
                    .field("revision", generation.revision)
            });
        }
        fcx.emit("web", "generation", |event| {
            event
                .summary(format_args!(
                    "generation {} at revision {}",
                    if generation.generate {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    generation.revision
                ))
                .field("generate", generation.generate)
                .field("copied", copied)
                .field("live_search", self.live_only())
                .field("revision", generation.revision)
        });
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
