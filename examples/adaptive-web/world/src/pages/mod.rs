//! What the world answers for one request, and the rules that keep its
//! pages consistent.
//!
//! Every request is one of:
//!
//! - a search (Google, DuckDuckGo, Bing): the result list is made once per
//!   query and kept. Each result is written down as a mention of its URL,
//!   with its title and snippet, before anyone asks for that URL.
//! - a fixed page from the seed: its bytes and response captured on first
//!   use, then served from the store even if the source changes.
//! - a page already in the store: served exactly as stored.
//! - a new page: made from the seed, its mentions (the searches and links
//!   that led to it) and what the world has already said, then stored. Of
//!   its first [`LINKS_PER_PAGE`](prompts::LINKS_PER_PAGE) link candidates,
//!   http(s) links to other hosts' and this host's pages that are not yet
//!   stored become mentions.
//! - a stylesheet: the host's stored design; other assets: a small fixed answer.
//!
//! A page takes the title its first mention showed, a result for a URL the
//! world already knows shows what the world said about it, and the search
//! snippets known when a page is made are checked for textual support in
//! it. Choosing a result's title and making the page it names share one
//! lock per URL, so a search and a request for the page publish one title.
//! Worlds sharing a store share these locks too (see [`store`]).
//!
//! [`Maker::Stub`] makes everything offline and deterministically;
//! [`Maker::Model`] asks a model. Without a maker
//! ([`GeneratorKind::Replay`]) nothing new is made: a URL the store does
//! not hold is a 404, and a query it does not hold has no results. The
//! same holds while generation is turned off.
//!
//! [`Pages::canned`] serves a store made ahead of time and has the offline
//! generator make what it lacks, ranking the stored pages first in new
//! result lists. [`NewPages`] switches between that store and the offline
//! generator's own, or turns new pages off.
//!
//! A run can also plant facts and pages ([`Command::PlantFact`],
//! [`Command::PlantPage`]). A planted fact goes into what is made after it;
//! one that corrects a value ("..., 7.2.5, not 7.2.4.") changes the value in
//! every result and page served after it. A planted page is served as
//! written in its site's layout, and leads every result list whose search
//! shares its words.

pub mod make;
pub mod meta;
pub mod model;
pub mod prompts;
pub mod render;
pub mod seed;
pub mod store;
pub mod text;

pub use meta::Meta;
pub use seed::Seed;

use crate::files::FileLock;
use crate::route::{Route, query_key, route};
use crate::search::{Cache, Reason};
use example_common::names;
use fictionet::Cx;
use fictionet::events::Fields;
use fictionet_extras::search::{self, Engine};
use meta::{Asked, Listing, Shown};
use model::{Failure, Ledger, Model, Provider, Usage};
use prompts::{Claim, HostPage, Person};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use store::{CastRecord, PageRecord, SearchRecord, Store};

/// New generations one world may start: searches, pages, prefetches and the
/// cast, failed ones included.
pub const GENERATION_BUDGET: usize = 200;

/// Output budgets, in tokens. A page asks for 200 to 450 words of content
/// plus a few header lines; a result list is ten short results. The limits
/// leave room above that, and cut off an answer that runs on.
const SEARCH_TOKENS: u32 = 1800;
const PAGE_TOKENS: u32 = 2000;
const CAST_TOKENS: u32 = 800;

/// A change to the world: its generation setting, what answers, or a
/// planted fact or page. Each carries the settings revision it expects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Make new result lists and pages, or serve only stored ones.
    SetGeneration {
        generate: bool,
        expected_revision: u64,
    },
    /// Choose what answers and whether new pages are made.
    SetNewPages {
        new_pages: NewPages,
        expected_revision: u64,
    },
    /// Add a fact to what is made from now on.
    PlantFact {
        text: String,
        expected_revision: u64,
    },
    /// Serve a page at `url`. The first line of `text` is its title when
    /// there is more than one line; the rest is its text.
    PlantPage {
        url: String,
        text: String,
        expected_revision: u64,
    },
    /// Forget what this run made and planted, and start from the canned
    /// pages again.
    Restart { expected_revision: u64 },
}

impl Command {
    fn expected_revision(&self) -> u64 {
        match self {
            Self::SetGeneration {
                expected_revision, ..
            }
            | Self::SetNewPages {
                expected_revision, ..
            }
            | Self::PlantFact {
                expected_revision, ..
            }
            | Self::PlantPage {
                expected_revision, ..
            }
            | Self::Restart { expected_revision } => *expected_revision,
        }
    }
}

/// What answers requests the store cannot: the canned pages first and the
/// offline generator for the rest, the offline generator alone, or nothing
/// new.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NewPages {
    Canned,
    Stub,
    Off,
}

/// The settings revision after an accepted command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    /// Run time when the command was applied, in milliseconds.
    pub at_ms: u64,
}

/// A command that did not change the settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    /// The caller's revision differs from the current settings revision.
    Stale { current: u64 },
    /// The command cannot apply, and why.
    Invalid { message: String },
}

/// The current generation setting and its revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub generate: bool,
    pub revision: u64,
}
impl Default for Generation {
    fn default() -> Self {
        Self {
            generate: true,
            revision: 0,
        }
    }
}

/// An answer, with what the log records about it in `meta`.
#[derive(Clone, Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Media type and optional charset.
    pub content_type: String,
    /// Full page bytes, including for HEAD requests.
    pub body: Vec<u8>,
    /// Extra headers, excluding content type and content length.
    pub headers: Vec<(String, String)>,
    /// What the log records about the answer.
    pub meta: Meta,
    /// How long a routed request took on the run's clock, in milliseconds.
    pub serve_ms: Option<u64>,
    pub carries: u64,
}
impl Response {
    fn new(
        status: u16,
        content_type: impl Into<String>,
        body: impl Into<Vec<u8>>,
        headers: Vec<(String, String)>,
        meta: Meta,
    ) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
            headers,
            meta,
            serve_ms: None,
            carries: 0,
        }
    }

    fn html(body: impl Into<String>, meta: Meta, status: u16, server: &str) -> Self {
        let headers = vec![("Server".into(), server.into())];
        let body = body.into().into_bytes();
        Self::new(status, "text/html; charset=utf-8", body, headers, meta)
    }

    /// The answer as fields of its request's event: [`Meta::fields`] and
    /// `serve_ms`.
    pub fn fields(&self) -> Fields {
        let mut fields = self.meta.fields();
        if !matches!(self.meta, Meta::Search(_)) {
            fields.set("carries", self.carries);
        }
        if let Some(ms) = self.serve_ms {
            fields.set("serve_ms", ms);
        }
        fields
    }
}

/// What makes new pages, as `--generator` names it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorKind {
    /// The offline generator ([`make`]).
    #[default]
    Stub,
    /// Nothing new: the world serves what its store holds.
    Replay,
    /// A model, named by its provider.
    #[serde(untagged)]
    Model(Provider),
}

impl GeneratorKind {
    /// Every kind.
    pub const ALL: [Self; 4] = [
        Self::Stub,
        Self::Model(Provider::OpenRouter),
        Self::Model(Provider::Anthropic),
        Self::Replay,
    ];
}

/// What makes new result lists and pages.
pub enum Maker {
    /// The offline generator ([`make`]).
    Stub,
    /// A model ([`model`]).
    Model(Model),
}

impl Maker {
    /// What a store made with this generator records.
    pub fn identity(&self) -> Value {
        match self {
            Self::Stub => json!({"provider": "stub", "model": "stub"}),
            Self::Model(model) => model.identity(),
        }
    }
}

/// A generation's result: what was made and what it cost.
struct Made<T> {
    fields: T,
    usage: Usage,
}

/// Why nothing was made.
enum Stop {
    /// The generation budget is spent.
    Budget,
    /// The generator or the store failed.
    Failed {
        error: String,
        usage: Option<Box<Usage>>,
    },
}

impl Stop {
    fn store(error: std::io::Error) -> Self {
        Self::Failed {
            error: format!("cannot record what the world made: {error}"),
            usage: None,
        }
    }
    /// The answer for a stopped search or page: the plain 503 page a busy
    /// server shows. The log keeps why.
    fn response(self, asked: Asked) -> Response {
        let meta = match self {
            Self::Budget => Meta::Budget(asked),
            Self::Failed { error, usage } => Meta::Error {
                error: error.chars().take(400).collect(),
                usage,
            },
        };
        let headers = vec![("Server".into(), "nginx".into())];
        Response::new(503, "text/html", UNAVAILABLE, headers, meta)
    }
}

const UNAVAILABLE: &[u8] = b"<html><head><title>503 Service Temporarily Unavailable</title></head>\
<body><center><h1>503 Service Temporarily Unavailable</h1></center><hr><center>nginx</center>\
</body></html>";

/// One lock per key, made on first use. A URL's lock covers choosing its
/// title and making its page; a query's lock covers making its list. Within
/// the world it is an async lock; for a store kept in a directory it is
/// also a file in the store's `locks/`, which other worlds on the store
/// take too.
struct Locks {
    local: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    dir: Option<std::path::PathBuf>,
}

/// A key's lock, held until dropped.
struct KeyLock {
    _local: tokio::sync::OwnedMutexGuard<()>,
    _file: Option<FileLock>,
}

impl Locks {
    async fn lock(&self, cx: &Cx, key: String) -> std::io::Result<KeyLock> {
        let local = self
            .local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone();
        let local = local.lock_owned().await;
        let Some(dir) = &self.dir else {
            return Ok(KeyLock {
                _local: local,
                _file: None,
            });
        };
        std::fs::create_dir_all(dir)?;
        // Keys that share a file name only wait for each other.
        let name: String = key
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .take(200)
            .collect();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(name))?;
        // Another world may hold it while it makes the item, for seconds,
        // so this world waits without blocking its thread.
        loop {
            if let Some(held) = FileLock::try_take(&file)? {
                return Ok(KeyLock {
                    _local: local,
                    _file: Some(held),
                });
            }
            if cx
                .sleep(std::time::Duration::from_millis(50))
                .await
                .is_err()
            {
                return Err(std::io::Error::other("the world stopped"));
            }
        }
    }
}

fn page_key(host: &str, target: &str) -> String {
    format!("page {host}{target}")
}

/// Returns host, target and anchor of the first
/// [`LINKS_PER_PAGE`](prompts::LINKS_PER_PAGE) links on a page, resolved
/// against its URL, in source order: http(s) links with a host that is not
/// a search engine, with anchor text, cut at
/// [`ANCHOR_CHARS`](prompts::ANCHOR_CHARS).
pub fn links(url: &str, markup: &str) -> Vec<(String, String, String)> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let link = LINK.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)[^"']*["'][^>]*>(.*?)</a>"#).unwrap()
    });
    link.captures_iter(markup)
        .take(prompts::LINKS_PER_PAGE)
        .filter_map(|c| {
            let absolute = text::join(url, &text::unescape(c[1].trim()))?;
            if !absolute.starts_with("http://") && !absolute.starts_with("https://") {
                return None;
            }
            let (host, target) = text::target_of(&absolute);
            if host.is_empty() || crate::route::SEARCH_HOSTS.contains(&host.as_str()) {
                return None;
            }
            let anchor = text::take(&text::text_of(&c[2]), prompts::ANCHOR_CHARS);
            (!anchor.is_empty()).then_some((host, target, anchor))
        })
        .collect()
}

/// What a page is made from.
struct PageAsk {
    url: String,
    mentions: Vec<Value>,
    profile: Option<make::Profile>,
    host_pages: Vec<HostPage>,
    claims: Vec<Claim>,
    cast: Vec<Person>,
}

/// A page planted during the run.
#[derive(Clone, Debug)]
struct PlantedPage {
    url: String,
    host: String,
    target: String,
    title: String,
    /// Its paragraphs.
    text: Vec<String>,
}

/// What the run has planted.
#[derive(Default)]
struct Planted {
    facts: Vec<String>,
    /// Old and new values from facts that correct one.
    corrections: Vec<(String, String)>,
    pages: Vec<PlantedPage>,
}

/// The world's pages: its seed, its store and what makes new pages.
pub struct Pages {
    seed: Seed,
    maker: Option<Maker>,
    prefetch: usize,
    live_calls: Option<Arc<std::sync::atomic::AtomicUsize>>,
    store: Mutex<Store>,
    /// The run's other pages while prepared pages answer, or the prepared
    /// pages while the run's other pages answer.
    parked: Mutex<Option<Store>>,
    /// Where the canned store was read from.
    canned: Option<std::path::PathBuf>,
    /// Whether the canned store answers.
    canned_active: std::sync::atomic::AtomicBool,
    planted: Mutex<Planted>,
    /// The id of the next search, shared by every way a search arrives.
    queries: std::sync::atomic::AtomicU64,
    locks: Locks,
}

impl Pages {
    /// An in-memory world with the offline generator.
    pub fn new(seed: Seed) -> Self {
        Self::open(seed, Store::memory(), Some(Maker::Stub), 0)
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
            seed,
            maker,
            prefetch,
            live_calls: None,
            store: Mutex::new(store),
            parked: Mutex::new(None),
            canned: None,
            canned_active: Default::default(),
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

    /// A world that serves the store at `root`, made ahead of time for
    /// `seed`, and has the offline generator make what it lacks. What the
    /// run adds stays in memory.
    pub fn canned(seed: Seed, root: &std::path::Path) -> Result<Self, String> {
        let (store, _) = Store::load(root, &seed)?;
        let mut pages = Self::open(seed, store, Some(Maker::Stub), 0);
        pages.parked = Mutex::new(Some(Store::memory()));
        pages.canned = Some(root.to_owned());
        pages.canned_active = true.into();
        Ok(pages)
    }

    /// Prepared pages first, with a bounded model and offline fallback.
    /// All additions stay in memory, including after switching modes.
    pub fn canned_with_model(
        seed: Seed,
        root: &std::path::Path,
        model: Model,
    ) -> Result<Self, String> {
        let mut pages = Self::canned(seed, root)?;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        pages.maker = Some(Maker::Model(model.live(calls.clone())));
        pages.prefetch = 3;
        pages.live_calls = Some(calls);
        Ok(pages)
    }

    /// What answers requests: see [`NewPages`].
    pub fn new_pages(&self) -> NewPages {
        if !self.generation().generate {
            NewPages::Off
        } else if self.canned_active.load(std::sync::atomic::Ordering::SeqCst) {
            NewPages::Canned
        } else {
            NewPages::Stub
        }
    }

    /// The seed with the facts planted so far first.
    fn context(&self) -> std::borrow::Cow<'_, Seed> {
        let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
        if planted.facts.is_empty() {
            return std::borrow::Cow::Borrowed(&self.seed);
        }
        let mut seed = self.seed.clone();
        seed.facts = planted
            .facts
            .iter()
            .chain(&self.seed.facts)
            .cloned()
            .collect();
        std::borrow::Cow::Owned(seed)
    }

    /// Corrects only the claim named by a fact, retaining surrounding history.
    fn corrected_fragment(
        &self,
        text: &str,
        context: &str,
        reached: &mut HashSet<usize>,
    ) -> String {
        let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = text.to_owned();
        static CVE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let cve = CVE.get_or_init(|| regex::Regex::new(r"(?i)CVE-[0-9]{4}-[0-9]+").unwrap());
        for (index, (old, new)) in planted.corrections.iter().enumerate() {
            let fact = planted
                .facts
                .iter()
                .find(|f| correction(f).as_ref() == Some(&(old.clone(), new.clone())));
            let firmware = fact.is_some_and(|f| {
                let f = f.to_lowercase();
                f.contains("firmware") || f.contains("fix") || f.contains("release")
            });
            if firmware {
                let lower = context.to_lowercase();
                if ![
                    "fixed",
                    "fix for",
                    "fixes",
                    "patched",
                    "upgrade to",
                    "update to",
                    "resolved",
                ]
                .iter()
                .any(|w| lower.contains(w))
                {
                    continue;
                }
                if let Some(subject) = fact.and_then(|f| cve.find(f))
                    && cve
                        .find_iter(context)
                        .any(|found| !found.as_str().eq_ignore_ascii_case(subject.as_str()))
                {
                    continue;
                }
                if context.contains(&format!("{new}, not {old}"))
                    || context.contains(&format!("{new} instead of {old}"))
                {
                    continue;
                }
            }
            let changed = replace_content_value(&text, old, new);
            if changed != text {
                reached.insert(index);
            }
            text = changed;
        }
        text
    }

    fn corrected(&self, text: &str, reached: &mut HashSet<usize>) -> String {
        sentences()
            .replace_all(text, |c: &regex::Captures<'_>| {
                self.corrected_fragment(&c[0], &c[0], reached)
            })
            .into_owned()
    }

    /// Keeps inline markup while using the whole surrounding sentence as context.
    fn corrected_node(
        &self,
        node: &kuchiki::NodeRef,
        original: &str,
        reached: &mut HashSet<usize>,
    ) -> String {
        let block = node
            .ancestors()
            .find(|a| {
                a.as_element().is_some_and(|e| {
                    matches!(
                        e.name.local.as_ref(),
                        "p" | "li" | "td" | "th" | "h1" | "h2" | "h3"
                    )
                })
            })
            .unwrap_or_else(|| node.clone());
        if block
            .as_element()
            .is_some_and(|e| e.name.local.as_ref() == "td")
        {
            let column = block
                .preceding_siblings()
                .filter(|n| n.as_element().is_some())
                .count();
            let table = block.ancestors().find(|a| {
                a.as_element()
                    .is_some_and(|e| e.name.local.as_ref() == "table")
            });
            let header = table
                .and_then(|t| t.select("tr").ok()?.next())
                .and_then(|r| {
                    r.as_node()
                        .children()
                        .filter(|n| n.as_element().is_some())
                        .nth(column)
                })
                .map(|n| n.text_contents())
                .unwrap_or_default();
            return self.corrected_fragment(original, &format!("{header}: {original}"), reached);
        }
        if block == *node {
            return self.corrected_fragment(original, original, reached);
        }
        let mut context = String::new();
        let mut offset = 0;
        for child in block.descendants() {
            if child == *node {
                offset = context.len();
            }
            if let Some(text) = child.as_text() {
                context.push_str(&text.borrow());
            }
        }
        let mut corrected = String::new();
        for sentence in sentences().find_iter(&context) {
            let start = sentence.start().max(offset);
            let end = sentence.end().min(offset + original.len());
            if start < end {
                corrected.push_str(&self.corrected_fragment(
                    &context[start..end],
                    sentence.as_str(),
                    reached,
                ));
            }
        }
        corrected
    }

    /// Returns the seed used by this world.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The model that makes new pages, or the kind's name (`stub`,
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
            Some(Maker::Stub) => GeneratorKind::Stub,
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
    fn store(&self) -> MutexGuard<'_, Store> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = store.catch_up();
        store
    }

    fn generating(&self) -> bool {
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
                let canned = match new_pages {
                    NewPages::Canned => true,
                    NewPages::Stub => false,
                    NewPages::Off => self.canned_active.load(std::sync::atomic::Ordering::SeqCst),
                };
                if canned != self.canned_active.load(std::sync::atomic::Ordering::SeqCst) {
                    let mut parked = self.parked.lock().unwrap_or_else(|e| e.into_inner());
                    let Some(other) = parked.as_mut() else {
                        return Err(invalid("This world has no canned pages"));
                    };
                    std::mem::swap(&mut *store, other);
                    store.generation = other.generation;
                    store.made = other.made;
                    self.canned_active
                        .store(canned, std::sync::atomic::Ordering::SeqCst);
                }
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
                let fresh = match &self.canned {
                    Some(root) => Store::load(root, &self.seed).map_err(|e| invalid(&e))?.0,
                    None => Store::memory(),
                };
                let mut parked = self.parked.lock().unwrap_or_else(|e| e.into_inner());
                if store.root().is_some() {
                    return Err(invalid("A world on a store directory cannot restart"));
                }
                let generation = store.generation;
                *store = fresh;
                store.generation = Generation {
                    generate: self.maker.is_some(),
                    ..generation
                };
                if let Some(other) = parked.as_mut() {
                    *other = Store::memory();
                }
                self.canned_active
                    .store(self.canned.is_some(), std::sync::atomic::Ordering::SeqCst);
                *self.planted.lock().unwrap_or_else(|e| e.into_inner()) = Planted::default();
                fcx.emit("adaptive", "restarted", |event| {
                    event
                        .summary(format_args!("run restarted at revision {}", current + 1))
                        .field("revision", current + 1)
                });
            }
        }
        store.generation.revision = current + 1;
        let generation = store.generation;
        let canned = self.canned_active.load(std::sync::atomic::Ordering::SeqCst);
        drop(store);
        if let Some((kind, text, url)) = planted {
            fcx.emit("adaptive", "planted", |event| {
                event
                    .summary(format_args!("planted a {kind}: {text}"))
                    .field("plant", kind)
                    .field("text", text.as_str())
                    .field("url", url.as_str())
                    .field("revision", generation.revision)
            });
        }
        fcx.emit("adaptive", "generation", |event| {
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
                .field("canned", canned)
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

    /// Answers a request. Supply form bytes for form POSTs.
    pub async fn handle(
        self: &Arc<Self>,
        cx: &Cx,
        method: &str,
        host: &str,
        target: &str,
        form: Option<&[u8]>,
    ) -> Response {
        let form = if method == "POST" {
            form.map(|f| &f[..f.len().min(MAX_FORM_BYTES)])
        } else {
            None
        };
        let route = route(host, target, form);
        self.handle_route(cx, method, host, target, route).await
    }

    /// The page a site shows after a form is posted to it: a failed sign
    /// in, a subscription or a message received, in the site's layout.
    pub fn form(&self, host: &str, target: &str) -> Response {
        let host = host.to_lowercase();
        let path = target.split('?').next().unwrap_or(target).to_lowercase();
        let (title, body) = if ["login", "signin", "sign-in", "auth", "account"]
            .iter()
            .any(|word| path.contains(word))
        {
            (
                "Sign in",
                "<h1>Sign in</h1><p class=\"error\" role=\"alert\">The email address or password you entered is incorrect.</p>\
                 <form method=\"post\"><label>Email <input type=\"email\" name=\"email\"></label> \
                 <label>Password <input type=\"password\" name=\"password\"></label> <button>Sign in</button></form>\
                 <p><a href=\"/forgot-password\">Forgot your password?</a></p>",
            )
        } else if ["newsletter", "subscribe", "signup", "sign-up", "register"]
            .iter()
            .any(|word| path.contains(word))
        {
            (
                "Thanks for subscribing",
                "<h1>Thanks for subscribing</h1><p>Check your inbox for an email to confirm your address. \
                 If it has not arrived in a few minutes, look in your spam folder.</p><p><a href=\"/\">Back to the home page</a></p>",
            )
        } else {
            (
                "Thanks for getting in touch",
                "<h1>Thanks for getting in touch</h1><p>We have received your message and aim to reply within two working days.</p>\
                 <p><a href=\"/\">Back to the home page</a></p>",
            )
        };
        let profile = self
            .store()
            .site(&host)
            .cloned()
            .unwrap_or_else(|| make::site_profile(&host));
        let page = make::Page {
            status: 200,
            title: title.into(),
            body: body.into(),
            date: self.seed.date.clone(),
            ..make::Page::default()
        };
        // The receipt is made for this post, as the stub makes a page.
        let shown = Shown {
            cache: Cache::Generated,
            title: title.into(),
            prefetched: false,
            claims: Vec::new(),
            mentions: 0,
            unsupported_snippets: Vec::new(),
            unchecked_snippets: Vec::new(),
            tells: Vec::new(),
            reason: Reason::Direct,
            usage: Some(Usage::stub(0)),
        };
        Response::html(
            render::page_at(&host, target, &profile, &page, &self.seed.date),
            Meta::Page(Box::new(shown)),
            200,
            render::server_of(Some(&profile)),
        )
    }

    /// A planted page at `host` and `target`, in its site's layout.
    fn planted(&self, host: &str, target: &str) -> Option<Response> {
        let page = (self.planted.lock().unwrap_or_else(|e| e.into_inner()).pages)
            .iter()
            .find(|p| p.host == host && p.target == target)
            .cloned()?;
        let profile = self
            .store()
            .site(host)
            .cloned()
            .unwrap_or_else(|| make::site_profile(host));
        let related = self
            .store()
            .known(&self.seed)
            .into_iter()
            .filter(|r| {
                r.url != page.url
                    && (text::split_url(&r.url).0 == host
                        || self
                            .seed
                            .sites
                            .iter()
                            .any(|site| site.host == text::split_url(&r.url).0))
            })
            .take(3)
            .map(|r| (r.title, r.url))
            .collect::<Vec<_>>();
        let article = make::page(
            &self.seed,
            host,
            target,
            &[serde_json::json!({"title":page.title})],
            "news",
            &[],
        );
        use kuchiki::traits::TendrilSink;
        let dom = kuchiki::parse_html().one(article.body);
        let byline = dom
            .select_first(".byline")
            .map(|n| {
                if let Ok(time) = n.as_node().select_first("time") {
                    time.attributes
                        .borrow_mut()
                        .insert("datetime", self.seed.date.clone());
                    for child in time.as_node().children().collect::<Vec<_>>() {
                        child.detach();
                    }
                    time.as_node()
                        .append(kuchiki::NodeRef::new_text(make::result_date(
                            &self.seed.date,
                        )));
                }
                n.as_node().to_string()
            })
            .unwrap_or_default();
        let related = related
            .iter()
            .map(|(title, url)| {
                format!(
                    "<li><a href=\"{}\">{}</a></li>",
                    text::escape(url),
                    text::escape(title)
                )
            })
            .collect::<String>();
        let paragraphs: String = page
            .text
            .iter()
            .map(|p| format!("<p>{}</p>", text::escape(p)))
            .collect();
        let made = make::Page {
            status: 200,
            title: page.title.clone(),
            description: text::take(&page.text.join(" "), 200),
            date: self.seed.date.clone(),
            body: format!(
                "<h1>{}</h1>{byline}{paragraphs}<section class=\"related\"><p class=\"related-title\"><strong>Related</strong></p><ul>{related}</ul></section>",
                text::escape(&page.title)
            ),
            ..make::Page::default()
        };
        Some(Response::html(
            render::page_at(host, target, &profile, &made, &self.seed.date),
            Meta::Planted { title: page.title },
            200,
            render::server_of(Some(&profile)),
        ))
    }

    /// Answers an already routed request; `serve_ms` is measured on the
    /// run's clock.
    pub(crate) async fn handle_route(
        self: &Arc<Self>,
        cx: &Cx,
        method: &str,
        host: &str,
        target: &str,
        route: Route,
    ) -> Response {
        if make::git_path(target) {
            return Response::new(
                404,
                "text/plain; charset=utf-8",
                "Not found",
                vec![],
                Meta::Asset,
            );
        }
        if method == "POST" && route == Route::Page {
            self.making(cx, host, target);
            return self.form(host, target);
        }
        let started = cx.now().since_start();
        let search = matches!(route, Route::Search { .. });
        let mut response = self.answer(cx, &host.to_lowercase(), target, route).await;
        if response.content_type.starts_with("text/html") {
            let body = String::from_utf8_lossy(&response.body);
            let title = match &response.meta {
                Meta::Page(page) => page.title.as_str(),
                _ => "",
            };
            let (title, mut body) = render::counted(title, &body);
            if let Meta::Page(page) = &mut response.meta {
                page.title = title;
            }
            if (!render::cookie_host(host)
                || self.seed.sites.iter().any(|site| {
                    site.host.trim_start_matches("www.") == host.trim_start_matches("www.")
                }))
                && body.contains("cookie-banner")
            {
                use kuchiki::traits::TendrilSink;
                let dom = kuchiki::parse_html().one(body);
                for node in dom.select(".cookie-banner").unwrap().collect::<Vec<_>>() {
                    node.as_node().detach();
                }
                for node in dom.select("script").unwrap().collect::<Vec<_>>() {
                    if node.text_contents().contains("site_cookies") {
                        node.as_node().detach();
                    }
                }
                body = dom.to_string();
            }
            if body.contains("class=\"cookie-banner\"") {
                let (message, accept, reject) = render::cookie_words(host);
                body = body
                    .replace(
                        "We use cookies for site preferences and analytics.",
                        message,
                    )
                    .replace(">Accept</button>", &format!(">{accept}</button>"))
                    .replace(
                        ">Reject non-essential</button>",
                        &format!(">{reject}</button>"),
                    );
            }
            response.body = body.into_bytes();
        }

        let mut reached = HashSet::new();
        // A result list is corrected result by result, so its search box
        // keeps what was typed.
        if !search
            && !matches!(response.meta, Meta::Planted { .. })
            && !self
                .planted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .corrections
                .is_empty()
            && let Ok(body) = std::str::from_utf8(&response.body)
        {
            let corrected = if response.content_type.contains("json") {
                fn correct(pages: &Pages, value: &mut Value, reached: &mut HashSet<usize>) {
                    match value {
                        Value::String(text) => *text = pages.corrected(text, reached),
                        Value::Array(values) => {
                            values.iter_mut().for_each(|v| correct(pages, v, reached))
                        }
                        Value::Object(values) => {
                            values.values_mut().for_each(|v| correct(pages, v, reached))
                        }
                        _ => {}
                    }
                }
                serde_json::from_str::<Value>(body).ok().map(|mut value| {
                    correct(self, &mut value, &mut reached);
                    value.to_string()
                })
            } else if response.content_type.starts_with("text/html") {
                use kuchiki::traits::TendrilSink;
                let dom = kuchiki::parse_html().one(body);
                for node in dom.descendants() {
                    if let Some(text) = node.as_text()
                        && !node.ancestors().any(|ancestor| {
                            ancestor.as_element().is_some_and(|e| {
                                matches!(e.name.local.as_ref(), "script" | "style" | "template")
                            })
                        })
                    {
                        let original = text.borrow().to_string();
                        let corrected = self.corrected_node(&node, &original, &mut reached);
                        *text.borrow_mut() = corrected;
                    }
                }
                for meta in dom.select("meta[name=description], meta[property=\"og:title\"], meta[property=\"og:description\"]").unwrap() {
                    let mut attributes = meta.attributes.borrow_mut();
                    if let Some(content) = attributes.get_mut("content") {
                        *content = self.corrected(content, &mut reached);
                    }
                }
                Some(dom.to_string())
            } else if response.content_type.starts_with("text/plain") {
                Some(self.corrected(body, &mut reached))
            } else {
                None
            };
            if let Some(corrected) = corrected {
                response.body = corrected.into_bytes();
            }
        }
        response.carries += reached.len() as u64;
        response.serve_ms = Some((cx.now().since_start() - started).as_millis() as u64);
        response
    }

    async fn answer(self: &Arc<Self>, cx: &Cx, host: &str, target: &str, route: Route) -> Response {
        let path = target.split('?').next().unwrap_or(target);
        if path == "/favicon.ico" {
            return Response::new(
                200,
                "image/svg+xml",
                render::favicon(host),
                vec![],
                Meta::Asset,
            );
        }
        if matches!(
            (host, path),
            ("www.google.com", "/s2/favicons") | ("www.bing.com", "/th")
        ) {
            let query = target.split_once('?').map_or("", |(_, query)| query);
            let domain = form_urlencoded::parse(query.as_bytes()).find_map(|(key, value)| {
                match (host, key.as_ref()) {
                    ("www.google.com", "domain") => Some(value.into_owned()),
                    ("www.bing.com", "id") => Some(value.into_owned()),
                    _ => None,
                }
            });
            return match domain.filter(|domain| !domain.is_empty()) {
                Some(domain) => Response::new(
                    200,
                    "image/svg+xml",
                    render::favicon(&domain),
                    vec![],
                    Meta::Asset,
                ),
                None => Response::new(404, "text/plain", "Not found", vec![], Meta::Asset),
            };
        }
        if host == "external-content.duckduckgo.com" && path.starts_with("/ip3/") {
            return match path
                .strip_prefix("/ip3/")
                .and_then(|p| p.strip_suffix(".ico"))
            {
                Some(domain) if !domain.is_empty() => Response::new(
                    200,
                    "image/svg+xml",
                    render::favicon(domain),
                    vec![],
                    Meta::Asset,
                ),
                _ => Response::new(404, "text/plain", "Not found", vec![], Meta::Asset),
            };
        }
        if path.starts_with("/_assets/") {
            return match fictionet_extras::sites::asset(host, path) {
                Some((mime, bytes)) => Response::new(200, mime, bytes, vec![], Meta::Asset),
                None => Response::new(404, "text/plain", "Not found", vec![], Meta::Asset),
            };
        }
        match route {
            Route::Redirect { location, status } => {
                let body = format!(
                    "<html><head><title>{status} Moved</title></head><body>\
                    <a href=\"{}\">here</a></body></html>",
                    text::escape(&location)
                );
                let headers = vec![("Location".into(), location.clone())];
                let meta = Meta::Redirect { location };
                Response::new(status, "text/html; charset=utf-8", body, headers, meta)
            }
            Route::SearchHome { engine } => Response::html(
                fictionet_extras::search::home(engine),
                Meta::SearchHome,
                200,
                fictionet_extras::search::engine_server(engine),
            ),
            Route::Search {
                engine,
                query,
                start,
            } => self.search(cx, engine, &query, start).await,
            Route::Page => {
                if make::broken_path(target) {
                    return self.missing(host, target);
                }
                if let Some(planted) = self.planted(host, target) {
                    return planted;
                }
                if let Some(fixed) = self.seed.fixed_for(host, target)
                    && (self.live_calls.is_none()
                        || self.canned_active.load(std::sync::atomic::Ordering::SeqCst))
                {
                    return self.fixed(cx, fixed).await;
                }
                let path = target.split('?').next().unwrap();
                if path.to_ascii_lowercase().ends_with(".css")
                    && !(path == "/search.css" && crate::route::SEARCH_HOSTS.contains(&host))
                {
                    return match self.site_stylesheet(cx, host).await {
                        Ok(profile) => Response::new(
                            200,
                            "text/css",
                            format!("{}\n{}", make::stylesheet(&profile.kind), profile.css),
                            vec![],
                            Meta::Asset,
                        ),
                        Err(stop) => stop.response(Asked::Page),
                    };
                }
                if let Some(asset) = static_asset(path) {
                    return asset;
                }
                self.page(cx, host, target, false).await
            }
        }
    }

    /// Writes a generation's ledger rows, or a stub generation's one row.
    fn log(&self, cx: &Cx, rows: &[Value]) -> Result<(), Stop> {
        let mut store = self.store();
        for row in rows {
            store.log_generation(row).map_err(Stop::store)?;
            if self.live_calls.is_some() && row["record"] == "attempt" {
                cx.emit("adaptive", "model_call", |event| {
                    event.field("call", example_common::events::field(row))
                });
            }
        }
        Ok(())
    }

    /// Starts one generation, or says the budget is spent.
    fn reserve(&self) -> Result<(), Stop> {
        if let Some(calls) = &self.live_calls {
            return calls
                .try_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| (n < GENERATION_BUDGET).then_some(n + 1),
                )
                .map(|_| ())
                .map_err(|_| Stop::Budget);
        }
        let mut store = self.store();
        if store.made >= GENERATION_BUDGET {
            return Err(Stop::Budget);
        }
        store.made += 1;
        Ok(())
    }

    fn maker(&self) -> &Maker {
        self.maker.as_ref().expect("a world that is generating")
    }

    /// Runs one generation with the maker's offline or model path and
    /// writes its rows. `context` names it in `generations.jsonl`.
    async fn generate<T>(
        &self,
        cx: &Cx,
        context: Value,
        stub: impl FnOnce() -> T,
        prompt: impl FnOnce() -> (String, String, u32),
        read: impl Fn(&str) -> Result<T, prompts::Unreadable>,
    ) -> Result<Made<T>, Stop> {
        match self.maker() {
            Maker::Stub => self.offline(cx, context, stub),
            Maker::Model(model) => {
                if self.live_calls.is_some() && self.reserve().is_err() {
                    return self.offline(cx, context, stub);
                }
                let (system, user, max_tokens) = prompt();
                // Refuse text that reveals how pages are made.
                let read = |text: &str| match gives_away(text) {
                    Some(word) => Err(prompts::Unreadable(format!(
                        "the answer contains {word:?}, which no page may contain; write it again without it"
                    ))),
                    None => read(text),
                };
                let (answer, ledger): (_, Ledger) =
                    model.ask(cx, &system, &user, max_tokens, read).await;
                let status = if answer.is_ok() { "ok" } else { "error" };
                let mut rows = ledger.rows(&context, status);
                rows.iter_mut().for_each(|row| model.redact_json(row));
                self.log(cx, &rows)?;
                let usage = ledger.usage();
                match answer {
                    Ok(answer) => Ok(Made {
                        fields: answer.fields,
                        usage,
                    }),
                    Err(_) if self.live_calls.is_some() => self.offline(cx, context, stub),
                    Err(Failure { error }) => Err(Stop::Failed {
                        error: model.redact(&error),
                        usage: Some(Box::new(usage)),
                    }),
                }
            }
        }
    }

    fn offline<T>(
        &self,
        cx: &Cx,
        mut context: Value,
        stub: impl FnOnce() -> T,
    ) -> Result<Made<T>, Stop> {
        let started = cx.now().since_start();
        let fields = stub();
        let usage = Usage::stub((cx.now().since_start() - started).as_millis() as u64);
        context["record"] = json!("stub");
        for (key, value) in serde_json::to_value(&usage).unwrap().as_object().unwrap() {
            context[key] = value.clone();
        }
        context["raw"] = Value::Null;
        self.log(cx, &[context])?;
        Ok(Made { fields, usage })
    }

    /// The people the world names, made the first time a list or page
    /// needs them.
    async fn cast(&self, cx: &Cx) -> Result<Vec<Person>, Stop> {
        let _lock = self
            .locks
            .lock(cx, "cast".into())
            .await
            .map_err(Stop::store)?;
        if let Some(cast) = self.store().cast() {
            return Ok(cast.people.clone());
        }
        if self.live_calls.is_some() {
            let cast = CastRecord {
                people: make::prepared_cast(&self.seed),
                usage: Usage::stub(0),
            };
            self.store().set_cast(cast.clone()).map_err(Stop::store)?;
            return Ok(cast.people);
        }
        self.reserve()?;
        let made = self
            .generate(
                cx,
                json!({"kind": "cast"}),
                || make::prepared_cast(&self.seed),
                || {
                    let (system, user) = prompts::cast(&self.seed);
                    (system, user, CAST_TOKENS)
                },
                prompts::read_cast,
            )
            .await?;
        let record = CastRecord {
            people: made.fields,
            usage: made.usage,
        };
        self.store().set_cast(record.clone()).map_err(Stop::store)?;
        Ok(record.people)
    }

    async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Response {
        let (search, cache, usage, carries) = match self.listing(cx, engine, query, start).await {
            Ok(listing) => listing,
            Err(stop) => return stop.response(Asked::Search),
        };
        let body = search::render(engine, query, &search, start);
        let listing = Listing {
            engine,
            search: query.into(),
            cache,
            carries,
            listed: (search.results.iter())
                .map(|r| {
                    (
                        r.url.clone(),
                        r.title.clone(),
                        self.site_name(&text::target_of(&r.url).0),
                    )
                })
                .collect(),
            usage,
        };
        let meta = Meta::Search(Box::new(listing));
        Response::html(
            body,
            meta,
            200,
            fictionet_extras::search::engine_server(engine),
        )
    }

    /// The result list a search shows: the stored or newly made list, with
    /// the planted pages that share its words first and every planted
    /// correction made. Also how it was supplied and what made it.
    async fn listing(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<(fictionet_extras::search::Search, Cache, Option<Usage>, u64), Stop> {
        let key = if engine == Engine::YouTube {
            format!("youtube {}", query_key(query, start))
        } else {
            query_key(query, start)
        };
        let _lock = self
            .locks
            .lock(cx, format!("search {key}"))
            .await
            .map_err(Stop::store)?;
        if start >= 10 && matches!(self.maker.as_ref(), Some(Maker::Stub)) {
            return Ok((
                fictionet_extras::search::Search::default(),
                Cache::Missing,
                None,
                0,
            ));
        }
        let stored = self.store().search(&key).cloned();
        let (record, cache) = match stored {
            Some(record) => (Some(record), Cache::Cached),
            None if !self.generating() => (None, Cache::Missing),
            None => {
                let record = self.make_search(cx, &key, query, engine).await?;
                self.start_prefetch(cx, &record);
                (Some(record), Cache::Generated)
            }
        };
        let mut search = record
            .as_ref()
            .map(|r| r.search.clone())
            .unwrap_or_default();
        if engine == Engine::YouTube && record.is_some() {
            // Video searches draw from the site's video cards.
            let store = self.store();
            search = make::videos(
                query,
                store
                    .pages()
                    .filter(|p| p.host == "www.youtube.com")
                    .map(|p| (&p.url, String::from_utf8_lossy(&p.body).into_owned())),
            );
        }
        if record.is_some()
            && engine != Engine::Google
            // A prepared list answers every engine as it was written; only
            // lists made on the spot differ by engine.
            && (engine == Engine::YouTube
                || record.as_ref().is_some_and(|r| r.usage.model == "stub"))
        {
            let proposed = if engine == Engine::YouTube {
                search.clone()
            } else {
                make::for_engine(
                    &self.context(),
                    &query_key(query, 0),
                    search.clone(),
                    engine,
                )
            };
            let replayable = proposed.results.iter().all(|r| {
                let (host, target) = text::target_of(&r.url);
                !self.store().mentions(&host, &target).is_empty()
                    || self.seed.fixed.iter().any(|f| f.url == r.url)
            });
            if self.generating() || replayable {
                search = proposed;
                for result in &mut search.results {
                    let (host, target) = text::target_of(&result.url);
                    let mention = if self.generating() {
                        let mention = json!({"via":"search", "query":query, "title":result.title, "snippet":result.snippet, "date":result.date});
                        self.store()
                            .reserve_mention(&self.seed, &host, &target, mention)
                            .map_err(Stop::store)?
                    } else {
                        self.store()
                            .mentions(&host, &target)
                            .first()
                            .cloned()
                            .unwrap_or_else(
                                || json!({"title":result.title,"snippet":result.snippet}),
                            )
                    };
                    result.title = mention["title"].as_str().unwrap_or_default().into();
                    result.snippet = mention["snippet"].as_str().unwrap_or_default().into();
                }
            } else {
                search.results.sort_by_key(|r| {
                    let own = self.seed.fixed.iter().any(|f| f.url == r.url)
                        || self
                            .seed
                            .sites
                            .iter()
                            .any(|s| s.host == text::target_of(&r.url).0);
                    (!own, make::engine_order(engine, query, &r.url))
                });
            }
        }
        if search.ads.is_empty() && record.is_some() {
            let store = self.store();
            for list in store.searches() {
                if make::relevant(
                    &fictionet_extras::search::Result {
                        url: String::new(),
                        title: list.query.clone(),
                        snippet: String::new(),
                        date: String::new(),
                    },
                    query,
                ) {
                    for ad in &list.search.ads {
                        if !search.ads.iter().any(|a| a.url == ad.url) {
                            search.ads.push(ad.clone());
                        }
                    }
                }
            }
        }
        // A list with no results while nothing new is made stays empty.
        if start == 0 && record.is_some() {
            let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
            for page in planted.pages.iter().rev() {
                if make::shares_words(
                    &format!("{} {} {}", page.title, page.url, page.text.join(" ")),
                    query,
                ) {
                    search.results.retain(|r| r.url != page.url);
                    search.results.insert(
                        0,
                        fictionet_extras::search::Result {
                            url: page.url.clone(),
                            title: page.title.clone(),
                            snippet: make::excerpt(&page.text.join(" ")),
                            date: make::result_date(&self.seed.date),
                        },
                    );
                    search.results.truncate(10);
                }
            }
        }
        make::finish_listing(query, &mut search);
        let mut reached = HashSet::new();
        for result in &mut search.results {
            if self
                .planted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pages
                .iter()
                .any(|p| p.url == result.url)
            {
                continue;
            }
            result.title = self.corrected(&result.title, &mut reached);
            result.snippet = self.corrected(&result.snippet, &mut reached);
        }
        Ok((search, cache, record.map(|r| r.usage), reached.len() as u64))
    }

    async fn make_search(
        &self,
        cx: &Cx,
        key: &str,
        query: &str,
        engine: Engine,
    ) -> Result<SearchRecord, Stop> {
        if self.live_calls.is_none() {
            self.reserve()?;
        }
        let cast = self.cast(cx).await?;
        let seed = self.context();
        let (known, claims) = {
            let store = self.store();
            (store.known(&seed), store.recent_claims(40))
        };
        let mut normalized = search::Search {
            results: known,
            ..search::Search::default()
        };
        make::finish_listing(query, &mut normalized);
        let known = normalized.results;
        let made = self
            .generate(
                cx,
                json!({"kind": "search", "query": query}),
                || {
                    if engine == Engine::YouTube {
                        let store = self.store();
                        make::videos(
                            query,
                            store
                                .pages()
                                .filter(|p| p.host == "www.youtube.com")
                                .map(|p| (&p.url, String::from_utf8_lossy(&p.body).into_owned())),
                        )
                    } else {
                        make::search(&self.seed, query, &known, Engine::Google)
                    }
                },
                || {
                    let (system, user) = prompts::search(&seed, &cast, query, &known, &claims);
                    (system, user, SEARCH_TOKENS)
                },
                prompts::read_search,
            )
            .await?;
        let mut search = made.fields;
        make::finish_listing(query, &mut search);
        let mut results: Vec<fictionet_extras::search::Result> = Vec::new();
        for mut r in std::mem::take(&mut search.results) {
            let (host, target) = text::target_of(&r.url);
            let known_match = known.iter().find(|k| k.url == r.url);
            // A page the world already holds stays out of an unrelated list.
            // A model that lists it for this search with a row sharing the
            // search's words has said how it is related.
            let chosen = made.usage.model != "stub"
                && make::shares_words(&format!("{} {} {}", r.title, r.url, r.snippet), query);
            if host.is_empty()
                || results.iter().any(|x| x.url == r.url)
                || known_match.is_some_and(|k| !make::relevant(k, query) && !chosen)
            {
                continue;
            }
            let mention = json!({
                "via": "search",
                "query": query,
                "rank": results.len() + 1,
                "title": r.title,
                "snippet": r.snippet,
                "date": r.date,
            });
            let _page = self
                .locks
                .lock(cx, page_key(&host, &target))
                .await
                .map_err(Stop::store)?;
            let mention = self
                .store()
                .reserve_mention(&self.seed, &host, &target, mention)
                .map_err(Stop::store)?;
            r.title = mention["title"].as_str().unwrap_or_default().into();
            r.snippet = mention["snippet"].as_str().unwrap_or_default().into();
            results.push(r);
        }
        let known_matches = results
            .iter()
            .filter(|r| {
                known
                    .iter()
                    .any(|k| k.url == r.url && make::relevant(k, query))
            })
            .count();
        if made.usage.model == "stub" && known_matches >= 8 {
            results.retain(|r| {
                known
                    .iter()
                    .any(|k| k.url == r.url && make::relevant(k, query))
            });
        }
        search.results = results;
        let record = SearchRecord {
            key: key.into(),
            query: query.into(),
            search,
            usage: made.usage,
        };
        self.store()
            .insert_search(record.clone())
            .map_err(Stop::store)?;
        Ok(record)
    }

    /// Makes the pages behind a new list's first results in the background.
    /// A page that fails here is made again when it is asked for.
    fn start_prefetch(self: &Arc<Self>, cx: &Cx, record: &SearchRecord) {
        if self.live_calls.is_some() && record.usage.model == "stub" {
            return;
        }
        for r in record.search.results.iter().take(self.prefetch) {
            let (host, target) = text::target_of(&r.url);
            let pages = self.clone();
            cx.spawn(move |cx| async move {
                let started = cx.now().since_start();
                let response = pages.page(&cx, &host, &target, true).await;
                cx.emit("adaptive", "prefetch_finished", |e| {
                    e.field("url", format!("https://{host}{target}"))
                        .field("status", response.status as u64)
                });
                if let Meta::Error { error, usage } = &response.meta {
                    let mut row = json!({
                        "kind": "prefetch_error",
                        "record": "diagnostic",
                        "url": format!("https://{host}{target}"),
                        "error": error,
                        "serve_ms": (cx.now().since_start() - started).as_millis() as u64,
                    });
                    if let Some(usage) = usage {
                        row["model"] = json!(usage.model);
                        row["gen_ms"] = json!(usage.gen_ms);
                        row["cost"] = json!(usage.cost);
                    }
                    // A world that cannot write the row says so on the next request.
                    let _ = pages.log(&cx, &[row]);
                }
                Ok(())
            });
        }
    }

    async fn site_stylesheet(&self, cx: &Cx, host: &str) -> Result<make::Profile, Stop> {
        let profile = make::site_profile(host);
        if profile.kind == "qa" {
            return Ok(profile);
        }
        let _site = self
            .locks
            .lock(cx, format!("site {host}"))
            .await
            .map_err(Stop::store)?;
        let stored = self.store().site(host).cloned();
        if let Some(profile) = &stored
            && !profile.css.is_empty()
        {
            return Ok(profile.clone());
        }
        let mut profile = stored.unwrap_or_else(|| make::site_profile(host));
        if !self.generating() {
            profile.css.clear();
            return Ok(profile);
        }
        if matches!(self.maker(), Maker::Model(_)) {
            if self.live_calls.is_none() {
                self.reserve()?;
            }
            let made = self
                .generate(
                    cx,
                    json!({"kind": "stylesheet", "host": host}),
                    String::new,
                    || {
                        let (system, user) = prompts::stylesheet(&self.seed, host, &profile);
                        (system, user, 1000)
                    },
                    |text| {
                        let css = text.trim();
                        if css.is_empty() {
                            Err(prompts::Unreadable("empty stylesheet".into()))
                        } else {
                            Ok(css.to_owned())
                        }
                    },
                )
                .await?;
            profile.css = made.fields;
        } else {
            profile.css = make::site_profile(host).css;
        }
        self.store().site_once(host, profile).map_err(Stop::store)
    }

    async fn fixed(&self, cx: &Cx, fixed: &seed::Fixed) -> Response {
        let (host, target) = (fixed.host.as_str(), fixed.target.as_str());
        let lock = match self.locks.lock(cx, page_key(host, target)).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(Asked::Page),
        };
        if self.generating() && self.store().page(host, target).is_none() {
            self.making(cx, host, target);
        }
        if self.generating()
            && let Err(stop) = self.site_stylesheet(cx, host).await
        {
            return stop.response(Asked::Page);
        }
        let stored = self.store().page(host, target).cloned();
        let (record, made) = match stored {
            Some(record) => (record, false),
            None if !self.generating() => {
                drop(lock);
                return self.missing(host, target);
            }
            None => {
                let record = PageRecord {
                    url: fixed.url.clone(),
                    host: host.into(),
                    target: target.into(),
                    status: 200,
                    content_type: fixed.content_type.clone(),
                    body: fixed.body.clone(),
                    headers: vec![("Server".into(), "nginx".into())],
                    title: fixed.title.clone(),
                    description: fixed.description.clone(),
                    date: String::new(),
                    claims: Vec::new(),
                    mentions: Vec::new(),
                    tells: Vec::new(),
                    unsupported_snippets: Vec::new(),
                    unchecked_snippets: Vec::new(),
                    prefetched: false,
                    fixed: true,
                    usage: None,
                };
                if let Err(error) = self.store().insert_page(record.clone()) {
                    return Stop::store(error).response(Asked::Page);
                }
                (record, true)
            }
        };
        drop(lock);
        if made && record.content_type.starts_with("text/html") {
            self.note_links(&record.url, &String::from_utf8_lossy(&record.body));
        }
        let meta = Meta::Fixed {
            title: record.title,
        };
        Response::new(
            record.status,
            record.content_type,
            record.body,
            record.headers,
            meta,
        )
    }

    /// The 404 for a page the store does not hold while nothing new is made.
    fn missing(&self, host: &str, target: &str) -> Response {
        let store = self.store();
        let profile = store.site(host);
        Response::html(
            render::not_found(host, profile, target, &self.seed.date),
            Meta::Missing,
            404,
            render::server_of(profile),
        )
    }

    fn listed_video(&self, host: &str, target: &str) -> Option<PageRecord> {
        if host != "www.youtube.com" || !target.starts_with("/watch?v=") {
            return None;
        }
        let store = self.store();
        for listing in store.searches() {
            for original in &listing.search.results {
                let (source_host, source_target) = text::target_of(&original.url);
                if source_host != host || !source_target.starts_with("/results?") {
                    continue;
                }
                let mut normalized = search::Search {
                    results: vec![original.clone()],
                    ..search::Search::default()
                };
                make::finish_listing(&listing.query, &mut normalized);
                let video = &normalized.results[0];
                if text::target_of(&video.url).1 != target {
                    continue;
                }
                let mut record = store.page(&source_host, &source_target)?.clone();
                let page = make::Page {
                    title: video.title.clone(),
                    body: format!(
                        "<h1>{}</h1><p class=\"channel\">{}</p>",
                        text::escape(&video.title),
                        text::escape(&video.snippet)
                    ),
                    date: record.date.clone(),
                    ..make::Page::default()
                };
                record.url = video.url.clone();
                record.target = target.into();
                record.title = video.title.clone();
                record.body = render::page_at(
                    host,
                    target,
                    &make::site_profile(host),
                    &page,
                    &self.seed.date,
                )
                .into_bytes();
                return Some(record);
            }
        }
        None
    }

    async fn page(self: &Arc<Self>, cx: &Cx, host: &str, target: &str, prefetch: bool) -> Response {
        if !prefetch && self.store().page(host, target).is_none() {
            self.making(cx, host, target);
        }
        let lock = match self.locks.lock(cx, page_key(host, target)).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(Asked::Page),
        };
        let stored = self.store().page(host, target).cloned();
        let stored = stored.or_else(|| self.listed_video(host, target));
        let (mut record, mut cache) = match stored {
            Some(record) => (record, Cache::Cached),
            None if !self.generating() => {
                drop(lock);
                return self.missing(host, target);
            }
            None => match self.make_page(cx, host, target, prefetch).await {
                Ok(record) => (record, Cache::Generated),
                Err(stop) => return stop.response(Asked::Page),
            },
        };
        if record.content_type.starts_with("text/html")
            && let Some(html) = render::again(
                host,
                target,
                &record.title,
                &String::from_utf8_lossy(&record.body),
                &record.date,
                &self.seed.date,
            )
        {
            record.body = html.into_bytes();
        }
        drop(lock);
        if cache == Cache::Generated && record.content_type.starts_with("text/html") {
            self.note_links(&record.url, &String::from_utf8_lossy(&record.body));
        }
        if !prefetch
            && record.prefetched
            && self.store().unserved.remove(&(host.into(), target.into()))
        {
            cache = Cache::Prefetched;
        }
        // A page asked for before anything mentioned it came direct.
        let reason = record
            .mentions
            .iter()
            .find(|m| m["via"] != "fact")
            .map_or(Reason::Direct, |m| {
                Reason::deserialize(m).unwrap_or_default()
            });
        let visible = String::from_utf8_lossy(&record.body);
        let visible = normalize(&if record.content_type.starts_with("text/html") {
            text::text_of(&visible)
        } else {
            visible.into_owned()
        });
        let carries = record
            .mentions
            .iter()
            .filter(|m| {
                m["via"] == "fact"
                    && m["snippet"]
                        .as_str()
                        .is_some_and(|fact| visible.contains(&normalize(fact)))
            })
            .count() as u64;
        let shown = Shown {
            cache,
            title: record.title,
            prefetched: record.prefetched,
            claims: record.claims,
            mentions: record.mentions.len(),
            unsupported_snippets: record.unsupported_snippets,
            unchecked_snippets: record.unchecked_snippets,
            tells: record.tells,
            reason,
            usage: record.usage,
        };
        let meta = Meta::Page(Box::new(shown));
        let mut response = Response::new(
            record.status,
            record.content_type,
            record.body,
            record.headers,
            meta,
        );
        response.carries = carries;
        response
    }

    /// The site's display name, shared by pages and observers.
    pub fn site_name(&self, host: &str) -> String {
        self.store()
            .site(host)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| make::site_profile(host).name)
    }

    pub(crate) fn making(&self, cx: &Cx, host: &str, target: &str) {
        cx.emit("adaptive", "making", |e| {
            e.field("url", format!("https://{host}{target}"))
                .field("host", host)
                .field("site", self.site_name(host))
        });
    }

    async fn make_page(
        &self,
        cx: &Cx,
        host: &str,
        target: &str,
        prefetch: bool,
    ) -> Result<PageRecord, Stop> {
        cx.emit("adaptive", "making", |e| {
            e.field("url", format!("https://{host}{target}"))
                .field("host", host)
                .field("site", self.site_name(host))
                .field("prefetch", prefetch)
        });
        let site_lock = if self.live_calls.is_none() {
            Some(
                self.locks
                    .lock(cx, format!("site {host}"))
                    .await
                    .map_err(Stop::store)?,
            )
        } else {
            None
        };
        if self.live_calls.is_none() {
            self.reserve()?;
        }
        let cast = self.cast(cx).await?;
        let url = format!("https://{host}{target}");
        let mut ask = {
            let store = self.store();
            PageAsk {
                url: url.clone(),
                mentions: prompts::asked_mentions(store.mentions(host, target)),
                profile: store.site(host).filter(|p| !p.css.is_empty()).cloned(),
                host_pages: store.host_pages(host),
                claims: store.recent_claims(40),
                cast,
            }
        };
        let _site = ask.profile.is_none().then_some(site_lock);
        let expected = prompts::expected_type(&url);
        let mut seed = self.context().into_owned();
        let subject = format!("{url} {}", make::title_from(host, target));
        {
            let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
            seed.facts.retain(|fact| {
                !planted.facts.contains(fact)
                    || correction(fact).is_some()
                    || make::shares_words(fact, &subject)
            });
            for fact in &planted.facts {
                if correction(fact).is_none() && make::shares_words(fact, &subject) {
                    ask.mentions.push(json!({"via":"fact", "snippet":fact}));
                }
            }
        }
        let kind = self
            .store()
            .site(host)
            .map(|p| p.kind.clone())
            .unwrap_or_else(|| make::site_profile(host).kind);
        let mut known = {
            let store = self.store();
            let mut known = store.known(&seed);
            if host == "www.youtube.com" && target == "/" {
                known.extend(
                    make::videos(
                        "",
                        store
                            .pages()
                            .filter(|p| p.host == host)
                            .map(|p| (&p.url, String::from_utf8_lossy(&p.body).into_owned())),
                    )
                    .results,
                );
            }

            for result in store.searches().flat_map(|s| &s.search.results) {
                if !known.iter().any(|r| r.url == result.url) {
                    known.push(result.clone());
                }
            }
            known
        };
        known.extend(
            self.planted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pages
                .iter()
                .map(|p| fictionet_extras::search::Result {
                    url: p.url.clone(),
                    title: p.title.clone(),
                    snippet: p.text.join(" "),
                    date: String::new(),
                }),
        );
        let made = self
            .generate(
                cx,
                json!({"kind": "page", "url": url}),
                || {
                    let mut mentions = ask.mentions.clone();
                    for fact in &self.planted.lock().unwrap_or_else(|e| e.into_inner()).facts {
                        if correction(fact).is_some()
                            && make::shares_words(
                                fact,
                                &format!("{url} {}", make::title_from(host, target)),
                            )
                        {
                            mentions.push(json!({"snippet": fact}));
                        }
                    }
                    make::page_with_known(&seed, host, target, &mentions, &kind, &known, &ask.cast)
                },
                || {
                    let (system, user) = prompts::page(
                        &seed,
                        &ask.cast,
                        &ask.url,
                        &ask.mentions,
                        ask.profile.as_ref(),
                        &ask.host_pages,
                        &ask.claims,
                    );
                    (
                        system,
                        user,
                        PAGE_TOKENS + if ask.profile.is_none() { 1000 } else { 0 },
                    )
                },
                |text| {
                    let page = prompts::read_page(text, expected, !ask.mentions.is_empty())?;
                    if self.live_calls.is_some() {
                        let body = if page.content_type.starts_with("text/html") {
                            let profile = ask
                                .profile
                                .as_ref()
                                .or(page.site.as_ref())
                                .cloned()
                                .unwrap_or_else(|| make::site_profile(host));
                            render::page_at(host, target, &profile, &page, &seed.date)
                        } else {
                            page.body.clone()
                        };
                        text::validate_page(&page.content_type, body.as_bytes())
                            .map_err(prompts::Unreadable)?;
                    }
                    if ask.profile.is_none()
                        && fictionet_extras::sites::lookup(host, target).is_none()
                        && page.site.as_ref().is_none_or(|p| p.css.is_empty())
                    {
                        return Err(prompts::Unreadable("the first page needs SITE_CSS".into()));
                    }
                    Ok(page)
                },
            )
            .await?;
        let mut page = made.fields;
        if let Some(title) = ask
            .mentions
            .iter()
            .filter_map(|m| m["title"].as_str())
            .find(|s| !s.is_empty())
        {
            page.title = title.into();
        }
        let today = &self.seed.date;
        let profile = match ask.profile {
            Some(profile) => profile,
            None => {
                let mut described = page.site.take().unwrap_or_else(|| make::site_profile(host));
                if described.name.is_empty() {
                    described.name = make::site_profile(host).name;
                }
                self.store()
                    .site_once(host, described)
                    .map_err(Stop::store)?
            }
        };
        let html = page.content_type.starts_with("text/html");
        let body = if !html {
            page.body.clone()
        } else if page.status == 404 && ask.mentions.is_empty() {
            render::not_found(host, Some(&profile), target, today)
        } else {
            render::page_at(host, target, &profile, &page, today)
        };
        let tells = text::tells(&if html {
            text::text_of(&page.body)
        } else {
            body.clone()
        });
        let (unsupported, unchecked) =
            text::check_snippets(&body, &page.content_type, &ask.mentions);
        let record = PageRecord {
            url,
            host: host.into(),
            target: target.into(),
            status: page.status,
            content_type: page.content_type,
            body: body.into_bytes(),
            headers: vec![("Server".into(), render::server_of(Some(&profile)).into())],
            title: page.title,
            description: page.description,
            date: page.date,
            claims: page.claims,
            mentions: ask.mentions,
            tells,
            unsupported_snippets: unsupported,
            unchecked_snippets: unchecked,
            prefetched: prefetch,
            fixed: false,
            usage: Some(made.usage),
        };
        let mut store = self.store();
        store.insert_page(record.clone()).map_err(Stop::store)?;
        if prefetch {
            store.unserved.insert((host.into(), target.into()));
        }
        Ok(record)
    }

    /// Records the links of a page just made as mentions of the pages
    /// behind them, unless those pages are stored. A later request has this
    /// context even without a Referer.
    fn note_links(&self, url: &str, markup: &str) {
        let mut store = self.store();
        for (host, target, anchor) in links(url, markup) {
            if store.page(&host, &target).is_none() {
                let mention = json!({"via": "link", "from": url, "anchor": anchor});
                // A mention the store cannot keep loses only context.
                let _ = store.add_mention(&host, &target, mention);
            }
        }
    }
}

/// The most form bytes a search reads from a POST.
pub const MAX_FORM_BYTES: usize = 1 << 20;

/// Planted text with its whitespace joined.
fn normalize(text: &str) -> String {
    text::normalize_space(text)
}

/// The first word in `text` that would tell a reader the web is made up,
/// by the guest content check's rules.
fn gives_away(text: &str) -> Option<String> {
    let audit = example_common::guest_content::Audit::default();
    audit.inspect("planted", text.as_bytes());
    let error = audit.check().err()?;
    Some(error.split('"').nth(1).unwrap_or("that word").to_owned())
}

fn sentences() -> &'static regex::Regex {
    static SENTENCE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SENTENCE.get_or_init(|| regex::Regex::new(r"(?s).*?(?:[.!?](?:\s|$)|$)").unwrap())
}

/// The old and new value a fact corrects: "... is 7.2.5, not 7.2.4." or
/// "... 7.2.5 instead of 7.2.4".
fn correction(fact: &str) -> Option<(String, String)> {
    let fact = fact.trim().trim_end_matches(['.', '!']);
    let (before, after) = fact
        .rsplit_once(", not ")
        .or_else(|| fact.rsplit_once(" instead of "))?;
    let old = after.trim();
    let new = before.split_whitespace().last()?.trim_end_matches(',');
    (!old.is_empty() && !old.contains(' ') && !new.is_empty() && old != new)
        .then(|| (old.to_owned(), new.to_owned()))
}

fn replace_content_value(text: &str, old: &str, new: &str) -> String {
    static URL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let urls = URL.get_or_init(|| {
        regex::Regex::new(r#"(?i)(?:[a-z][a-z0-9+.-]*://|(?:mailto|data):|(?:^|\s)/)[^\s<>"']+"#)
            .unwrap()
    });
    let mut corrected = String::new();
    let mut end = 0;
    for url in urls.find_iter(text) {
        corrected.push_str(&replace_value(&text[end..url.start()], old, new));
        corrected.push_str(url.as_str());
        end = url.end();
    }
    corrected.push_str(&replace_value(&text[end..], old, new));
    corrected
}

/// `text` with each whole `old` replaced by `new`: not inside a longer
/// word or number, so 7.2.4 is not found in 17.2.4 or 7.2.45.
fn replace_value(text: &str, old: &str, new: &str) -> String {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (at, _) in text.match_indices(old) {
        let mut before = text[..at].chars().rev();
        let (b1, b2) = (before.next(), before.next());
        let mut after = text[at + old.len()..].chars();
        let (a1, a2) = (after.next(), after.next());
        if word(b1) || (b1 == Some('.') && digit(b2)) || word(a1) || (a1 == Some('.') && digit(a2))
        {
            continue;
        }
        out.push_str(&text[last..at]);
        out.push_str(new);
        last = at + old.len();
    }
    out.push_str(&text[last..]);
    out
}

/// A planted page from the World menu's URL and text.
fn planted_page(url: &str, body: &str) -> Result<PlantedPage, String> {
    let uri: http::Uri = url
        .trim()
        .parse()
        .map_err(|_| "Enter a full https:// address".to_owned())?;
    let host = uri.host().unwrap_or_default().to_lowercase();
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || crate::admit(&host).is_err()
        || crate::route::SEARCH_HOSTS.contains(&host.as_str())
    {
        return Err("Enter the address of a page on a public site".into());
    }
    let target = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let lines: Vec<String> = body
        .lines()
        .map(text::normalize_space)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() || body.chars().count() > 20_000 {
        return Err("Write the page's text, at most 20,000 characters".into());
    }
    let (title, text) = if lines.len() > 1 {
        (lines[0].clone(), lines[1..].to_vec())
    } else {
        (make::title_from(&host, &target), lines)
    };
    Ok(PlantedPage {
        url: format!("{}://{host}{target}", uri.scheme_str().unwrap_or("https")),
        host,
        target,
        title,
        text,
    })
}

/// Scripts, images and fonts are never made: they get a small
/// fixed answer, so a browser costs no generations. `robots.txt` allows
/// everything.
fn static_asset(path: &str) -> Option<Response> {
    const PIXEL: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\
        \x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";
    let (ctype, body): (&str, &[u8]) = if path == "/robots.txt" {
        ("text/plain; charset=utf-8", b"User-agent: *\nAllow: /\n")
    } else if path == "/search.css" {
        (
            "text/css; charset=utf-8",
            fictionet_extras::search::CSS.as_bytes(),
        )
    } else {
        let (base, ext) = path.rsplit_once('.')?;
        if ext.contains('/') || base.is_empty() {
            return None;
        }
        match ext.to_lowercase().as_str() {
            "js" => ("application/javascript", b"/* site scripts */\n"),
            "gif" | "png" | "jpg" | "jpeg" | "webp" | "svg" | "ico" => ("image/gif", PIXEL),
            "woff" => ("font/woff", b""),
            "woff2" => ("font/woff2", b""),
            _ => return None,
        }
    };
    Some(Response::new(200, ctype, body, vec![], Meta::Asset))
}

#[cfg(test)]
mod tests;

impl fictionet_extras::models::Engine for Pages {
    fn search(
        self: Arc<Self>,
        cx: Cx,
        query: String,
    ) -> fictionet_extras::models::tools::Answer<Vec<fictionet_extras::search::Result>> {
        Box::pin(async move {
            // An agent's own search tool: the world answers it with the list
            // a Google search for the same words shows, and reports it as a
            // search of its own.
            let id = self.next_query_id();
            cx.emit("adaptive", "query", |e| {
                e.summary(format_args!("web search: {query}"))
                    .field("query_id", id)
                    .field("engine", names::name(&Engine::Google))
                    .field("search", query.as_str())
                    .field("start", 0u64)
                    .field("key", query_key(&query, 0))
                    .field("via", "web_search")
            });
            let started = cx.now().since_start();
            let Ok((search, cache, usage, carries)) =
                self.listing(&cx, Engine::Google, &query, 0).await
            else {
                cx.emit("adaptive", "query_failed", |e| {
                    e.field("query_id", id).field("why", "error")
                });
                return Err(fictionet::Error::msg("Search is unavailable"));
            };
            let listing = Listing {
                engine: Engine::Google,
                search: query.clone(),
                cache,
                carries,
                listed: (search.results.iter())
                    .map(|r| {
                        (
                            r.url.clone(),
                            r.title.clone(),
                            self.site_name(&text::target_of(&r.url).0),
                        )
                    })
                    .collect(),
                usage,
            };
            let mut fields = Meta::Search(Box::new(listing)).fields();
            fields.set("query_id", id);
            fields.set("complete", true);
            fields.set(
                "serve_ms",
                (cx.now().since_start() - started).as_millis() as u64,
            );
            cx.emit("adaptive", "search_answer", |e| e.fields(fields));
            Ok(search.results)
        })
    }
    fn fetch(
        self: Arc<Self>,
        cx: Cx,
        url: String,
    ) -> fictionet_extras::models::tools::Answer<fictionet_extras::models::tools::Page> {
        Box::pin(async move {
            let parsed = url::Url::parse(&url)?;
            let (host, target) = text::target_of(&url);
            let response = self.handle(&cx, "GET", &host, &target, None).await;
            let mut fields = response.fields();
            fields.set("kind", "page");
            fields.set("via", "web_fetch");
            fields.set("method", "GET");
            fields.set("scheme", parsed.scheme());
            fields.set("host", host.as_str());
            fields.set("site", self.site_name(&host));
            fields.set("path", parsed.path());
            if let Some(query) = parsed.query() {
                fields.set("query", query);
            }
            fields.set("status", response.status as u64);
            fields.set("complete", true);
            cx.emit("http", "request", |e| e.fields(fields));
            if response.status != 200 {
                return Err(fictionet::Error::msg("Page is unavailable"));
            }
            let title = match response.meta {
                Meta::Page(p) => p.title,
                Meta::Fixed { title } => title,
                _ => url,
            };
            Ok(fictionet_extras::models::tools::Page {
                title,
                media_type: response.content_type.split(';').next().unwrap_or("").into(),
                body: response.body,
            })
        })
    }
    fn serves(&self, host: &str) -> bool {
        crate::admit(host).is_ok()
    }
}

pub(crate) use make::misspelled_host;
