//! Copied pages, model-written pages and live search share one response path.
//! Each engine renders the active source in its own result format.

mod answers;
mod branding;
mod copied;
mod edits;
mod generate;
mod layout;
mod listing;
mod normalize;
mod page;
mod serve;
mod settings;
mod tools;

use edits::*;
mod live;
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
use fictionet::Cx;
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

/// Output budgets include document markup, site metadata and provider reasoning.
/// Shorter complete answers are requested if a provider reaches its limit.
const SEARCH_TOKENS: u32 = 1800;
const PAGE_TOKENS: u32 = 8000;
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
    /// Forget model-written pages and planted facts, and return to copied pages.
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

/// The source of pages for new requests. Other worlds can pause generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NewPages {
    Copied,
    ModelWritten,
    LiveSearch,
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
    /// Original copied response headers, preserving duplicate and non UTF8 values.
    pub stored_headers: Option<http::HeaderMap>,
    /// What the log records about the answer.
    pub meta: Meta,
    /// How long a routed request took on the run's clock, in milliseconds.
    pub serve_ms: Option<u64>,
    pub carries: u64,
}
impl Response {
    pub(crate) fn new(
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
            stored_headers: None,
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
}

/// What makes new pages, as `--generator` names it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorKind {
    /// Pages and results built from stored records ([`make`]).
    #[default]
    Stored,
    /// Nothing new: the world serves what its store holds.
    Replay,
    /// A model, named by its provider.
    #[serde(untagged)]
    Model(Provider),
}

impl GeneratorKind {
    /// The spelling used by configuration and the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Replay => "replay",
            Self::Model(Provider::Anthropic) => "anthropic",
            Self::Model(Provider::OpenRouter) => "openrouter",
        }
    }

    /// Every kind.
    pub const ALL: [Self; 4] = [
        Self::Stored,
        Self::Model(Provider::OpenRouter),
        Self::Model(Provider::Anthropic),
        Self::Replay,
    ];
}

/// What makes new result lists and pages.
pub enum Maker {
    /// Pages and results built from stored records ([`make`]).
    Stored,
    /// A model ([`model`]).
    Model(Model),
}

impl Maker {
    /// What a store made with this generator records.
    pub fn identity(&self) -> Value {
        match self {
            Self::Stored => json!({"provider": "stored", "model": "stored"}),
            Self::Model(model) => model.identity(),
        }
    }
}

/// A generation's result: what was made and what it cost.
struct Made<T> {
    fields: T,
    usage: Usage,
    recovery: Option<Recovery>,
}

struct Recovery {
    target: crate::observation::WriterTarget,
    reason: String,
    rows: Vec<Value>,
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
    format!("page {}{target}", store::site_key(host))
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
    pub(crate) observation:
        Arc<Mutex<Option<tokio::sync::mpsc::Sender<crate::observation::Observation>>>>,
    seed: Seed,
    maker: Option<Maker>,
    prefetch: usize,
    live_calls: Option<Arc<std::sync::atomic::AtomicUsize>>,
    store: Mutex<Store>,
    copied: Option<copied::Corpus>,
    copied_active: std::sync::atomic::AtomicBool,
    live: Option<Arc<live::Live>>,
    live_active: std::sync::atomic::AtomicBool,
    planted: Mutex<Planted>,
    /// The id of the next search, shared by every way a search arrives.
    queries: std::sync::atomic::AtomicU64,
    locks: Locks,
}

/// The most form bytes a search reads from a POST.
pub const MAX_FORM_BYTES: usize = 1 << 20;

/// Planted text with its whitespace joined.
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

pub(crate) use make::misspelled_host;

#[cfg(test)]
mod tests;
