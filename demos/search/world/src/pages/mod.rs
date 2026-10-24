//! The world's pages: copied captures, live copies of the real web, and
//! live copies edited for a scenario share one response path. Each search
//! engine renders the active source's results in its own format. The
//! standalone `web-world` serves the [`written`] web instead.

mod copied;
mod edit;
mod listing;
mod live;
pub mod model;
pub mod seed;
mod serve;
mod settings;
pub mod snapshot;
pub(crate) mod text;
mod tools;
pub mod written;

pub use copied::PageBody;
pub use edit::Edit;
pub use seed::Seed;
pub use serve::HeldResource;
pub use settings::{Applied, Command, Rejected};
pub use tools::ToolResults;

use crate::route::Route;
use fictionet::Cx;
use fictionet_extras::search::{self, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// What answers the guest's requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The copied web: captured pages and the offline search index.
    Copied,
    /// The real web, copied from the host when asked for, with real search.
    Live,
    /// The real web as Live serves it, with the scenario's edits.
    Edited,
}

impl Source {
    /// Whether pages come from the real web.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Live | Self::Edited)
    }
}

/// What the log records about an answer.
#[derive(Clone, Debug)]
pub enum Meta {
    /// A search engine's home page.
    SearchHome,
    /// A redirect to `location`.
    Redirect { location: String },
    /// A stylesheet, script, image, font or other file.
    Asset,
    /// A result list.
    Search(Box<Listing>),
    /// A page, with its own title.
    Document { title: String },
    /// No page at this address.
    Missing,
    /// The page could not be copied. The diagnostic says why.
    Error { error: String },
}

/// A result list.
#[derive(Clone, Debug)]
pub struct Listing {
    pub engine: Engine,
    /// The search text.
    pub search: String,
    /// Each result's URL and title, in rank order.
    pub listed: Vec<(String, String)>,
    /// The scenario's edits to the list's titles and snippets.
    pub edits: Vec<Edit>,
}

/// A real page served with the scenario's edits.
#[derive(Clone, Debug)]
pub struct Edited {
    pub edits: Vec<Edit>,
    /// The host's copy of the page, with each change marked.
    pub marked: Arc<str>,
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
    /// The scenario's edits, when the page was edited.
    pub edited: Option<Edited>,
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
            edited: None,
        }
    }

    fn html(body: impl Into<String>, meta: Meta, status: u16, server: &str) -> Self {
        let headers = vec![("Server".into(), server.into())];
        let body = body.into().into_bytes();
        Self::new(status, "text/html; charset=utf-8", body, headers, meta)
    }

    fn not_found() -> Self {
        Self::new(
            404,
            "text/plain; charset=utf-8",
            "Not Found\n",
            vec![],
            Meta::Missing,
        )
    }
}

/// The source in use and its revision, which every accepted command advances.
struct Settings {
    source: Source,
    revision: u64,
}

/// The world's pages: its seed, its copied web, the live web and the editor.
pub struct Pages {
    pub(crate) observation:
        Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<crate::observation::Observation>>>>,
    seed: Seed,
    settings: Mutex<Settings>,
    copied: Option<Arc<copied::Corpus>>,
    live: Option<Arc<live::Live>>,
    editor: Option<Arc<edit::Editor>>,
    /// Single requests from the host: package files the copied web lacks.
    fetcher: live::Fetcher,
    /// The written web, which answers every page and search when present.
    written: Option<Arc<written::Written>>,
}
