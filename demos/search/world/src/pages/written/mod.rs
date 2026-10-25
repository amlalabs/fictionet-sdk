//! Written pages: the standalone `web-world`'s web, which the Inspect
//! integration runs. A seed's prose brief says what is true; every result
//! list and page is made the first time it is asked for, by the stored
//! generator ([`make`]) or a model ([`model`]), and kept in a [`store`] that
//! later worlds on the same directory serve again. Replay serves only what
//! a store holds.

mod answers;
mod branding;
mod generate;
mod layout;
mod listing;
mod normalize;
mod original;
mod page;
mod pdf;
mod serve;
mod settings;

pub mod make;
pub mod model;
pub mod prompts;
pub mod provenance;
pub mod render;
pub mod store;

use super::{Listing, Meta, Response, Seed, seed, text};
use crate::files::FileLock;
use crate::route::{Route, query_key};
use fictionet::Cx;
use fictionet_extras::search::{self, Engine};
use model::{Failure, Ledger, Model, Provider, Usage};
use prompts::{PageAsk, Person};
use provenance::Mention;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use store::{CastRecord, PageRecord, SearchRecord, Store};

/// What makes new pages, as the world's configuration names it.
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
    /// The spelling used by configuration.
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

/// The document a generation makes, as `generations.jsonl` names it.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum WriterTarget {
    Cast,
    Stylesheet { host: String },
    Search { query: String },
    Page { url: String },
}

/// A generation's result: what was made and what it cost.
struct Made<T> {
    fields: T,
    usage: Usage,
}

/// Why nothing was made: the generator or the store failed.
#[derive(Debug)]
struct Stop {
    error: String,
}

impl Stop {
    fn store(error: std::io::Error) -> Self {
        Self {
            error: format!("cannot record what the world made: {error}"),
        }
    }
    /// The answer for a stopped search or page: the plain 503 page a busy
    /// server shows. The log keeps why.
    fn response(self) -> Response {
        let meta = Meta::Error { error: self.error };
        let headers = vec![("Server".into(), "nginx".into())];
        Response::new(503, "text/html", super::listing::UNAVAILABLE, headers, meta)
    }
}

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
    fn local(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.into())
            .or_default()
            .clone()
    }

    fn file(&self, key: &str) -> std::io::Result<Option<std::fs::File>> {
        let Some(dir) = &self.dir else {
            return Ok(None);
        };
        std::fs::create_dir_all(dir)?;
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
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(name))
            .map(Some)
    }

    fn try_lock(&self, key: &str) -> std::io::Result<Option<KeyLock>> {
        let Ok(local) = self.local(key).try_lock_owned() else {
            return Ok(None);
        };
        let file = match self.file(key)? {
            Some(file) => match FileLock::try_take(&file)? {
                Some(held) => Some(held),
                None => return Ok(None),
            },
            None => None,
        };
        Ok(Some(KeyLock {
            _local: local,
            _file: file,
        }))
    }

    async fn lock(&self, cx: &Cx, key: String) -> std::io::Result<KeyLock> {
        let local = self.local(&key).lock_owned().await;
        let Some(file) = self.file(&key)? else {
            return Ok(KeyLock {
                _local: local,
                _file: None,
            });
        };
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

/// Returns host, target and anchor of every link on a page, resolved
/// against its URL, in source order: http(s) links with a host that is not
/// a search engine, with anchor text.
pub fn links(url: &str, markup: &str) -> Vec<(String, String, String)> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let link = LINK.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)[^"']*["'][^>]*>(.*?)</a>"#).unwrap()
    });
    link.captures_iter(markup)
        .filter_map(|c| {
            let absolute = text::join(url, &text::unescape(c[1].trim()))?;
            if !absolute.starts_with("http://") && !absolute.starts_with("https://") {
                return None;
            }
            let (host, target) = text::target_of(&absolute);
            if host.is_empty() || crate::route::SEARCH_HOSTS.contains(&host.as_str()) {
                return None;
            }
            let anchor = text::text_of(&c[2]);
            (!anchor.is_empty()).then_some((host, target, anchor))
        })
        .collect()
}

/// The world's written web: its seed, its store and what makes new pages.
pub struct Written {
    seed: Seed,
    maker: Option<Maker>,
    prefetch: usize,
    store: Mutex<Store>,
    originals: original::Originals,
    locks: Locks,
}

/// Scripts, images and fonts are never made: they get a small
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
