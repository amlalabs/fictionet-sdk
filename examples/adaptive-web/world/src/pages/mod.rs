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
//! - a stylesheet, script, image or font: a small fixed answer.
//!
//! A page takes the title its first mention showed, a result for a URL the
//! world already knows shows what the world said about it, and the search
//! snippets known when a page is made are checked for textual support in
//! it. Choosing a result's title and making the page it names share one
//! lock per URL, so a search and a request for the page publish one title.
//! Worlds sharing a store share these locks too (see [`store`]).
//!
//! [`Generator::Stub`] makes everything offline and deterministically;
//! [`Generator::Model`] asks a model. Without a generator nothing new is
//! made: a URL the store does not hold is a 404, and a query it does not
//! hold has no results. The same holds while generation is turned off.

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
use crate::route::{Engine, Route, query_key, route};
use crate::search::{Cache, GeneratorKind, Reason};
use fictionet::Cx;
use fictionet::events::Fields;
use meta::{Asked, Listing, Shown};
use model::{Failure, Ledger, Model, Usage};
use prompts::{Claim, HostPage, Person};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
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

/// A change to the world's generation setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Make new result lists and pages, or serve only stored ones.
    SetGeneration {
        generate: bool,
        expected_revision: u64,
    },
}

/// The settings revision after an accepted command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    /// Run time when the command was applied, in milliseconds.
    pub at_ms: u64,
}

/// A command that did not change the settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    /// The caller's revision differs from the current settings revision.
    Stale { current: u64 },
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
        if let Some(ms) = self.serve_ms {
            fields.set("serve_ms", ms);
        }
        fields
    }
}

/// What makes new result lists and pages.
pub enum Generator {
    /// The offline generator ([`make`]).
    Stub,
    /// A model ([`model`]).
    Model(Model),
}

impl Generator {
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

/// The world's pages: its seed, its store and what makes new pages.
pub struct Pages {
    seed: Seed,
    generator: Option<Generator>,
    prefetch: usize,
    store: Mutex<Store>,
    locks: Locks,
}

impl Pages {
    /// An in-memory world with the offline generator.
    pub fn new(seed: Seed) -> Self {
        Self::open(seed, Store::memory(), Some(Generator::Stub), 0)
    }

    /// A world on `store` that makes new pages with `generator`, or serves
    /// only the store's with none. Each new result list starts making the
    /// pages behind its first `prefetch` results ahead of time.
    pub fn open(
        seed: Seed,
        mut store: Store,
        generator: Option<Generator>,
        prefetch: usize,
    ) -> Self {
        store.generation.generate = generator.is_some();
        let locks = Locks {
            local: Mutex::default(),
            dir: store.root().map(|root| root.join("locks")),
        };
        Self {
            seed,
            generator,
            prefetch,
            store: Mutex::new(store),
            locks,
        }
    }

    /// Returns the seed used by this world.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The model that makes new pages: `stub`, a model's name, or `replay`
    /// when nothing new is made.
    pub fn model(&self) -> &str {
        match &self.generator {
            Some(Generator::Stub) => "stub",
            Some(Generator::Model(model)) => &model.model,
            None => "replay",
        }
    }

    /// What makes new pages, or `Replay` when nothing new is made.
    pub fn generator_kind(&self) -> GeneratorKind {
        match &self.generator {
            Some(Generator::Stub) => GeneratorKind::Stub,
            Some(Generator::Model(model)) => match model.provider {
                model::Provider::Anthropic => GeneratorKind::Anthropic,
                model::Provider::OpenRouter => GeneratorKind::Openrouter,
            },
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
        self.generator.is_some() && self.store().generation.generate
    }

    /// Applies a command against the current revision, without clearing pages.
    /// Only a changed setting advances the revision and emits an event.
    pub fn apply(&self, fcx: &Cx, command: Command) -> Result<Applied, Rejected> {
        let Command::SetGeneration {
            generate,
            expected_revision,
        } = command;
        let mut store = self.store();
        let generation = &mut store.generation;
        if expected_revision != generation.revision {
            return Err(Rejected::Stale {
                current: generation.revision,
            });
        }
        if generate != generation.generate {
            generation.generate = generate;
            generation.revision += 1;
            fcx.emit("adaptive", "generation", |event| {
                event
                    .summary(format_args!(
                        "generation {} at revision {}",
                        if generate { "enabled" } else { "disabled" },
                        generation.revision
                    ))
                    .field("generate", generate)
                    .field("revision", generation.revision)
            });
        }
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
        self.handle_route(cx, host, target, route).await
    }

    /// Answers an already routed request; `serve_ms` is measured on the
    /// run's clock.
    pub(crate) async fn handle_route(
        self: &Arc<Self>,
        cx: &Cx,
        host: &str,
        target: &str,
        route: Route,
    ) -> Response {
        let started = cx.now().since_start();
        let mut response = self.answer(cx, &host.to_lowercase(), target, route).await;
        response.serve_ms = Some((cx.now().since_start() - started).as_millis() as u64);
        response
    }

    async fn answer(self: &Arc<Self>, cx: &Cx, host: &str, target: &str, route: Route) -> Response {
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
                match engine {
                    Engine::Google => render::google_home(),
                    _ => render::duckduckgo_home(),
                },
                Meta::SearchHome,
                200,
                render::engine_server(engine),
            ),
            Route::Search {
                engine,
                query,
                start,
            } => self.search(cx, engine, &query, start).await,
            Route::Page => {
                if let Some(fixed) = self.seed.fixed_for(host, target) {
                    return self.fixed(cx, fixed).await;
                }
                if let Some(asset) = static_asset(target.split('?').next().unwrap()) {
                    return asset;
                }
                self.page(cx, host, target, false).await
            }
        }
    }

    /// Writes a generation's ledger rows, or a stub generation's one row.
    fn log(&self, rows: &[Value]) -> Result<(), Stop> {
        let mut store = self.store();
        for row in rows {
            store.log_generation(row).map_err(Stop::store)?;
        }
        Ok(())
    }

    /// Starts one generation, or says the budget is spent.
    fn reserve(&self) -> Result<(), Stop> {
        let mut store = self.store();
        if store.made >= GENERATION_BUDGET {
            return Err(Stop::Budget);
        }
        store.made += 1;
        Ok(())
    }

    fn generator(&self) -> &Generator {
        self.generator.as_ref().expect("a world that is generating")
    }

    /// Runs one generation with `generator`'s offline or model path and
    /// writes its rows. `context` names it in `generations.jsonl`.
    async fn generate<T>(
        &self,
        cx: &Cx,
        context: Value,
        stub: impl FnOnce() -> T,
        prompt: impl FnOnce() -> (String, String, u32),
        read: impl Fn(&str) -> Result<T, prompts::Unreadable>,
    ) -> Result<Made<T>, Stop> {
        match self.generator() {
            Generator::Stub => {
                let started = cx.now().since_start();
                let fields = stub();
                let ms = (cx.now().since_start() - started).as_millis() as u64;
                let usage = Usage::stub(ms);
                let mut row = context;
                row["record"] = json!("stub");
                for (key, value) in serde_json::to_value(&usage).unwrap().as_object().unwrap() {
                    row[key] = value.clone();
                }
                row["raw"] = Value::Null;
                self.log(&[row])?;
                Ok(Made { fields, usage })
            }
            Generator::Model(model) => {
                let (system, user, max_tokens) = prompt();
                let (answer, ledger): (_, Ledger) =
                    model.ask(cx, &system, &user, max_tokens, read).await;
                let status = if answer.is_ok() { "ok" } else { "error" };
                let mut rows = ledger.rows(&context, status);
                rows.iter_mut().for_each(|row| model.redact_json(row));
                self.log(&rows)?;
                let usage = ledger.usage();
                match answer {
                    Ok(answer) => Ok(Made {
                        fields: answer.fields,
                        usage,
                    }),
                    Err(Failure { error }) => Err(Stop::Failed {
                        error: model.redact(&error),
                        usage: Some(Box::new(usage)),
                    }),
                }
            }
        }
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
        self.reserve()?;
        let made = self
            .generate(
                cx,
                json!({"kind": "cast"}),
                Vec::new,
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
        let key = query_key(query, start);
        let _lock = match self.locks.lock(cx, format!("search {key}")).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(Asked::Search),
        };
        let stored = self.store().search(&key).cloned();
        let (record, cache) = match stored {
            Some(record) => (Some(record), Cache::Cached),
            None if !self.generating() => (None, Cache::Missing),
            None => match self.make_search(cx, &key, query).await {
                Ok(record) => {
                    self.start_prefetch(cx, &record);
                    (Some(record), Cache::Generated)
                }
                Err(stop) => return stop.response(Asked::Search),
            },
        };
        let empty = make::Search::default();
        let search = record.as_ref().map_or(&empty, |r| &r.search);
        let body = render::search(engine, query, search, start);
        let listing = Listing {
            engine,
            search: query.into(),
            cache,
            listed: (search.results.iter())
                .map(|r| (r.url.clone(), r.title.clone()))
                .collect(),
            usage: record.map(|r| r.usage),
        };
        let meta = Meta::Search(Box::new(listing));
        Response::html(body, meta, 200, render::engine_server(engine))
    }

    async fn make_search(&self, cx: &Cx, key: &str, query: &str) -> Result<SearchRecord, Stop> {
        self.reserve()?;
        let cast = self.cast(cx).await?;
        let (known, claims) = {
            let store = self.store();
            (store.known(&self.seed), store.recent_claims(40))
        };
        let made = self
            .generate(
                cx,
                json!({"kind": "search", "query": query}),
                || make::search(&self.seed, query, &known),
                || {
                    let (system, user) = prompts::search(&self.seed, &cast, query, &known, &claims);
                    (system, user, SEARCH_TOKENS)
                },
                prompts::read_search,
            )
            .await?;
        let mut search = made.fields;
        let mut results: Vec<make::Result> = Vec::new();
        for mut r in std::mem::take(&mut search.results) {
            let (host, target) = text::target_of(&r.url);
            if host.is_empty() || results.iter().any(|x| x.url == r.url) {
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
        for r in record.search.results.iter().take(self.prefetch) {
            let (host, target) = text::target_of(&r.url);
            let pages = self.clone();
            cx.spawn(move |cx| async move {
                let started = cx.now().since_start();
                let response = pages.page(&cx, &host, &target, true).await;
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
                    let _ = pages.log(&[row]);
                }
                Ok(())
            });
        }
    }

    async fn fixed(&self, cx: &Cx, fixed: &seed::Fixed) -> Response {
        let (host, target) = (fixed.host.as_str(), fixed.target.as_str());
        let lock = match self.locks.lock(cx, page_key(host, target)).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(Asked::Page),
        };
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
            render::not_found(host, profile, target, &self.seed.date[..4]),
            Meta::Missing,
            404,
            render::server_of(profile),
        )
    }

    async fn page(self: &Arc<Self>, cx: &Cx, host: &str, target: &str, prefetch: bool) -> Response {
        let lock = match self.locks.lock(cx, page_key(host, target)).await {
            Ok(lock) => lock,
            Err(error) => return Stop::store(error).response(Asked::Page),
        };
        let stored = self.store().page(host, target).cloned();
        let (record, mut cache) = match stored {
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
        let reason = (record.mentions.first()).map_or(Reason::Direct, |m| {
            Reason::deserialize(m).unwrap_or_default()
        });
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
        Response::new(
            record.status,
            record.content_type,
            record.body,
            record.headers,
            meta,
        )
    }

    async fn make_page(
        &self,
        cx: &Cx,
        host: &str,
        target: &str,
        prefetch: bool,
    ) -> Result<PageRecord, Stop> {
        self.reserve()?;
        let cast = self.cast(cx).await?;
        let url = format!("https://{host}{target}");
        let ask = {
            let store = self.store();
            PageAsk {
                url: url.clone(),
                mentions: prompts::asked_mentions(store.mentions(host, target)),
                profile: store.site(host).cloned(),
                host_pages: store.host_pages(host),
                claims: store.recent_claims(40),
                cast,
            }
        };
        let expected = prompts::expected_type(&url);
        let made = self
            .generate(
                cx,
                json!({"kind": "page", "url": url}),
                || {
                    let count = ask.host_pages.len();
                    make::page(&self.seed, host, target, &ask.mentions, count)
                },
                || {
                    let (system, user) = prompts::page(
                        &self.seed,
                        &ask.cast,
                        &ask.url,
                        &ask.mentions,
                        ask.profile.as_ref(),
                        &ask.host_pages,
                        &ask.claims,
                    );
                    (system, user, PAGE_TOKENS)
                },
                |text| prompts::read_page(text, expected, !ask.mentions.is_empty()),
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
        let year = &self.seed.date[..4];
        let profile = match ask.profile {
            Some(profile) => profile,
            None => {
                let described = page.site.take().unwrap_or_else(|| make::site_profile(host));
                self.store()
                    .site_once(host, described)
                    .map_err(Stop::store)?
            }
        };
        let html = page.content_type.starts_with("text/html");
        let body = if !html {
            page.body.clone()
        } else if page.status == 404 && ask.mentions.is_empty() {
            render::not_found(host, Some(&profile), target, year)
        } else {
            render::page(host, &profile, &page, year)
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

/// Stylesheets, scripts, images and fonts are never made: they get a small
/// fixed answer, so a browser costs no generations. `robots.txt` allows
/// everything.
fn static_asset(path: &str) -> Option<Response> {
    const PIXEL: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\
        \x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";
    let (ctype, body): (&str, &[u8]) = if path == "/robots.txt" {
        ("text/plain; charset=utf-8", b"User-agent: *\nAllow: /\n")
    } else {
        let (base, ext) = path.rsplit_once('.')?;
        if ext.contains('/') || base.is_empty() {
            return None;
        }
        match ext.to_lowercase().as_str() {
            "css" => ("text/css", b"/* site styles */\n"),
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
