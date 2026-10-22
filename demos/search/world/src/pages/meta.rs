//! Typed provenance, generation usage and search results for a page response.

use super::model::Usage;
use crate::search::{Cache, Reason};
use fictionet_extras::search::Engine;
use serde::Serialize;

/// What the log records about an answer.
#[derive(Clone, Debug, Serialize)]
pub enum Meta {
    /// A search engine's home page.
    SearchHome,
    /// A redirect to `location`.
    Redirect { location: String },
    /// A stylesheet, script, image, font or `robots.txt`.
    Asset,
    /// A result list.
    Search(Box<Listing>),
    /// A page from the store, or one made for this request.
    Page(Box<Shown>),
    /// A seed's fixed page.
    Fixed { title: String },
    /// A page planted during the run.
    Planted { title: String },
    /// A page the store does not hold, while nothing new is made.
    Missing,
    /// A list or page the generation budget left unmade.
    Budget(Asked),
    /// The generator or the store failed. `error` is cut at 400 characters.
    Error {
        error: String,
        usage: Option<Box<Usage>>,
    },
}

/// What a stopped answer was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Asked {
    Search,
    Page,
}

/// A result list.
#[derive(Clone, Debug, Serialize)]
pub struct Listing {
    pub engine: Engine,
    /// The search text.
    pub search: String,
    /// Cached, generated, or missing while nothing new is made.
    pub cache: Cache,
    pub carries: u64,
    /// Each result's URL, title and site name, in rank order.
    pub listed: Vec<(String, String, String)>,
    /// What made the list. None when it is missing.
    pub usage: Option<Usage>,
}

/// A page from the store, or one made for this request.
#[derive(Clone, Debug, Serialize)]
pub struct Shown {
    /// Cached, generated or prefetched.
    pub cache: Cache,
    pub title: String,
    /// Made ahead of its first request.
    pub prefetched: bool,
    pub claims: Vec<String>,
    /// How many mentions it was made from.
    pub mentions: usize,
    pub unsupported_snippets: Vec<String>,
    pub unchecked_snippets: Vec<String>,
    pub tells: Vec<String>,
    /// Why the world made it.
    pub reason: Reason,
    /// What made it. None for a seed's fixed page.
    pub usage: Option<Usage>,
}
