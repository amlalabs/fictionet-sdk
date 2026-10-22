//! What the log records about an answer: its kind and what made it. The
//! handler puts [`Meta::fields`] in the request's event; the search
//! projection ([`crate::search`]) reads them back by the same names.

use super::model::Usage;
use crate::search::{Cache, Reason};
use fictionet::events::{Fields, float, opt};
use fictionet::stdlib::protocols::json::Value as J;
use fictionet_extras::events::field;
use fictionet_extras::names::name;
use fictionet_extras::search::Engine;
use serde::Serialize;

/// What the log records about an answer.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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

impl Meta {
    /// The answer as fields of its request's event. `listed` and `reason`
    /// are for the search projection; the log line leaves them out.
    pub fn fields(&self) -> Fields {
        let page = |cache: Cache| {
            Fields::new()
                .with("kind", "page")
                .with("cache", name(&cache))
        };
        match self {
            Self::SearchHome => Fields::new().with("kind", "search_home"),
            Self::Redirect { location } => Fields::new()
                .with("kind", "redirect")
                .with("location", location.as_str()),
            Self::Asset => Fields::new().with("kind", "asset"),
            Self::Search(listing) => listing.fields(),
            Self::Page(shown) => shown.fields(),
            Self::Fixed { title } => page(Cache::Fixed)
                .with("title", title.as_str())
                .with("reason", reason(&Reason::Fixed)),
            Self::Planted { title } => page(Cache::Planted)
                .with("title", title.as_str())
                .with("reason", reason(&Reason::Planted)),
            Self::Missing => page(Cache::Missing),
            Self::Budget(asked) => Fields::new()
                .with("kind", name(asked))
                .with("cache", name(&Cache::Budget)),
            Self::Error { error, usage } => {
                let mut fields = Fields::new()
                    .with("kind", "error")
                    .with("error", error.as_str());
                if let Some(usage) = usage {
                    fields.set("model", usage.model.as_str());
                    fields.set("gen_ms", usage.gen_ms);
                    fields.set("cost", opt(usage.cost.map(float)));
                }
                fields
            }
        }
    }
}

impl Listing {
    fn fields(&self) -> Fields {
        let listed = self
            .listed
            .iter()
            .enumerate()
            .map(|(i, (url, title, site))| {
                field(&serde_json::json!({"rank": i + 1, "url": url, "title": title, "site": site}))
            })
            .collect();
        let mut fields = Fields::new()
            .with("kind", "search")
            .with("carries", self.carries)
            .with("engine", name(&self.engine))
            .with("search", self.search.as_str())
            .with("cache", name(&self.cache))
            .with("model", opt(self.usage.as_ref().map(|u| u.model.as_str())))
            .with("results", self.listed.len() as u64)
            .with("listed", J::Array(listed));
        if self.cache == Cache::Generated
            && let Some(usage) = &self.usage
        {
            fields.set("gen_ms", usage.gen_ms);
            fields.set("cost", opt(usage.cost.map(float)));
        }
        fields
    }
}

impl Shown {
    fn fields(&self) -> Fields {
        let usage = self.usage.as_ref();
        let mut fields = Fields::new()
            .with("kind", "page")
            .with("cache", name(&self.cache))
            .with("title", self.title.as_str())
            .with("model", opt(usage.map(|u| u.model.as_str())))
            .with("prefetched", self.prefetched)
            .with("claims", strings(&self.claims))
            .with("mentions", self.mentions as u64)
            .with("unsupported_snippets", strings(&self.unsupported_snippets))
            .with("unchecked_snippets", strings(&self.unchecked_snippets))
            .with("tells", strings(&self.tells))
            .with("reason", reason(&self.reason));
        if self.cache != Cache::Cached {
            fields.set("gen_ms", opt(usage.map(|u| u.gen_ms)));
            fields.set("cost", opt(usage.and_then(|u| u.cost).map(float)));
        }
        fields
    }
}

fn strings(items: &[String]) -> J {
    J::Array(items.iter().map(|s| s.as_str().into()).collect())
}

fn reason(reason: &Reason) -> J {
    field(&serde_json::to_value(reason).expect("a reason as JSON"))
}
