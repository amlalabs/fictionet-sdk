//! Bounded search and page state for a run observer.

use crate::pages::GeneratorKind;
use example_common::events::js;
use fictionet::events::{Event, Interest, Observation, Observer, Stamp};
use fictionet_extras::search::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Maximum UTF-8 bytes in each retained string.
pub const STRING_BYTES: usize = 256;
/// Most recent search requests retained.
pub const MAX_QUERIES: usize = 128;
/// Most recently shown result lists retained.
pub const MAX_RESULTS: usize = 24;
/// Results retained per list, in display order.
pub const MAX_LISTED: usize = 10;
/// Most recently fetched page URLs retained.
pub const MAX_PAGES: usize = 128;
/// First assigned sites retained.
pub const MAX_SITES: usize = 128;
/// Most recent refused names retained.
pub const MAX_REFUSED: usize = 64;
/// Most recent planted facts and pages retained.
pub const MAX_PLANTED: usize = 16;
/// Maximum compact snapshot JSON size at these limits.
/// Each string byte can need six JSON bytes. Counts use twenty digits;
/// costs use up to twenty-three bytes.
/// Fixed costs include field names, punctuation and the longest enum values.
pub const MAX_SNAPSHOT_BYTES: usize = {
    let string = 6 * STRING_BYTES;
    // Snapshot, seed, generator and omitted counts, with four strings.
    578 + 4 * string
        // Query rows, including failure text and a comma per row.
        + MAX_QUERIES * (504 + 7 * string)
        // Result lists and their entries, including array commas.
        + MAX_RESULTS * (75 + string + MAX_LISTED * (70 + 4 * string))
        // Page rows, including search reasons and a comma per row.
        + MAX_PAGES * (543 + 7 * string)
        // Site and refusal rows, including a comma per row.
        + MAX_SITES * (89 + 3 * string)
        + MAX_REFUSED * (53 + 2 * string)
        // Planted rows with a comma each but the last, the list's name and
        // brackets, the canned flag and the omitted count.
        + MAX_PLANTED * (60 + 3 * string)
        + 178
};

fn bounded(text: &str) -> String {
    let mut end = text.len().min(STRING_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
fn text(e: &Event, key: &str) -> String {
    bounded(e.str(key).unwrap_or_default())
}
fn parse<T: serde::de::DeserializeOwned>(e: &Event, key: &str) -> Option<T> {
    serde_json::from_value(js(Some(e.get(key)?))).ok()
}

/// The seed shown at the start of a run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedCard {
    pub name: String,
    pub date: String,
    pub instructions: String,
}
impl SeedCard {
    fn of(pages: &crate::pages::Pages) -> Self {
        let seed = pages.seed();
        Self {
            name: seed.name.clone(),
            date: seed.date.clone(),
            instructions: seed.instructions.clone(),
        }
    }
}
/// The generator settings for a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generator {
    pub model_calls: u64,
    pub model_cost_known: serde_json::Number,
    pub model_cost_unknown: u64,
    pub kind: GeneratorKind,
    pub model: String,
    /// Maximum result pages to fetch ahead of time per search.
    pub prefetch: u64,
    /// Whether new searches and pages can be made.
    pub generate: bool,
    /// Revision of the generation setting, independent of the snapshot.
    pub generation_revision: u64,
    /// Run time of the last generation change, in milliseconds.
    pub generation_at_ms: u64,
    /// Whether new requests use the copied corpus.
    #[serde(default)]
    pub copied: bool,
    /// Whether host Google searches and downloaded copies answer requests.
    #[serde(default)]
    pub live_search: bool,
    /// Whether the host search credential is configured.
    #[serde(default)]
    pub live_available: bool,
}
impl Default for Generator {
    fn default() -> Self {
        Self {
            model_calls: 0,
            model_cost_known: 0.into(),
            model_cost_unknown: 0,
            kind: GeneratorKind::default(),
            model: String::new(),
            prefetch: 0,
            generate: true,
            generation_revision: 0,
            generation_at_ms: 0,
            copied: false,
            live_search: false,
            live_available: false,
        }
    }
}
/// How the world supplied an answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cache {
    /// Made for this request.
    Generated,
    /// Made ahead of this request.
    Prefetched,
    /// Read from storage.
    Cached,
    /// Supplied as a fixed page.
    Fixed,
    /// A page planted during the run.
    Planted,
    /// Absent from storage during replay.
    Missing,
    /// Blocked by the generation budget.
    Budget,
    /// An absent or unrecognized cache value.
    #[default]
    #[serde(other)]
    Unknown,
}
/// Why a search did not return a result list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    /// The generator or the store failed to make an answer.
    Error,
    /// The generation budget was exhausted.
    Budget,
    /// The handler was dropped before finishing.
    Abandoned,
    /// An absent or unrecognized failure.
    #[default]
    #[serde(other)]
    Unknown,
}
/// The delivery state of a search request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    /// Waiting for an answer.
    Pending,
    /// The answer was fully delivered.
    Served,
    /// The answer was not fully delivered.
    Undelivered,
    /// The request failed before returning a result list.
    Failed { why: Failure, error: Option<String> },
}
/// One search request and its answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Query {
    pub id: u64,
    /// Normalized search key shared across engines.
    pub key: String,
    /// Search text with surrounding whitespace removed.
    pub search: String,
    pub engine: Engine,
    /// Result offset, starting at zero.
    pub start: u64,
    /// Name of the sandbox that asked.
    pub sandbox: Option<String>,
    /// Search source: Claude or Codex web search, a browser, or a command-line client.
    #[serde(default)]
    pub via: Option<String>,
    /// IP address of the client that asked.
    pub peer: Option<String>,
    /// Run time when the request began, in milliseconds.
    pub at_ms: u64,
    /// Sequence number of the query event.
    pub seq: u64,
    pub outcome: Outcome,
    pub cache: Option<Cache>,
    pub carries: Option<u64>,
    /// Result count the answer reported.
    pub results: Option<u64>,
    pub model: String,
    /// Time spent generating the answer, in milliseconds.
    pub gen_ms: Option<u64>,
    pub cost: Option<serde_json::Number>,
    /// Time spent serving the request, in milliseconds.
    pub serve_ms: Option<u64>,
    /// Sequence number of the latest answer or failure event.
    pub answer_seq: Option<u64>,
    /// Run time of that event, in milliseconds.
    pub answer_at_ms: Option<u64>,
}
/// One result in display order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listed {
    /// Position in the result list, starting at one.
    pub rank: u64,
    pub url: String,
    pub host: String,
    pub site: String,
    pub title: String,
}
/// A result list shared by searches with the same key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Results {
    /// Normalized search key shared across engines.
    pub key: String,
    pub listed: Vec<Listed>,
    /// How the first answer supplied this list.
    pub cache: Cache,
    /// First query that showed this list.
    pub query_id: u64,
}
/// Why the world made a page.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub enum Reason {
    /// The page appeared in a search result list.
    Search {
        /// Search text used to make the page.
        query: String,
        /// Position in that result list, starting at one.
        rank: u64,
    },
    /// A stored page linked to this page.
    Link {
        /// URL of the source page.
        from: String,
    },
    /// The page was requested without a prior mention.
    Direct,
    /// The page was supplied by the seed.
    Fixed,
    /// The page was planted during the run.
    Planted,
    /// No known creation reason was supplied.
    #[default]
    #[serde(other)]
    Unknown,
}
impl Reason {
    fn bound(&mut self) {
        match self {
            Self::Search { query, .. } => *query = bounded(query),
            Self::Link { from } => *from = bounded(from),
            _ => {}
        }
    }
}
/// How a page was supplied on one fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Made {
    /// Made by the stored generator.
    FromStore,
    /// Made by a model.
    WrittenLive,
    /// Read from storage.
    Stored,
    /// Supplied as a fixed page.
    Fixed,
    /// A page planted during the run.
    Planted,
    /// Absent from storage during replay.
    Missing,
    /// Blocked by the generation budget.
    NotMade,
    /// The cache value was unrecognized.
    Unknown,
}
impl Made {
    /// Whether a page was served.
    fn supplied(self) -> bool {
        matches!(
            self,
            Self::FromStore | Self::WrittenLive | Self::Stored | Self::Fixed | Self::Planted
        )
    }
}
fn made(cache: Cache, model: &str) -> Made {
    match cache {
        Cache::Generated | Cache::Prefetched if model == "stored" => Made::FromStore,
        Cache::Generated | Cache::Prefetched => Made::WrittenLive,
        Cache::Cached => Made::Stored,
        Cache::Fixed => Made::Fixed,
        Cache::Planted => Made::Planted,
        Cache::Missing => Made::Missing,
        Cache::Budget => Made::NotMade,
        Cache::Unknown => Made::Unknown,
    }
}
/// A fetched page: what its first served fetch said, and its latest delivery
/// state. Until a fetch serves the page (a 404 with generation off, or a
/// refusal over the budget), the first fetch stands in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// Event sequence of the first fetch.
    pub seq: u64,
    /// Serving time of the first fetch, including a missing page.
    pub first_serve_ms: Option<u64>,
    pub url: String,
    pub host: String,
    pub site: String,
    /// Run time of the first fetch, in milliseconds.
    pub at_ms: u64,
    pub fetches: u64,
    /// HTTP status of the latest fetch.
    pub status: Option<u64>,
    pub via: Option<String>,
    pub making: bool,
    /// A request is waiting for this page to be served.
    #[serde(default)]
    pub waiting: bool,
    pub carries: Option<u64>,
    /// Title from the first served fetch.
    pub title: String,
    /// Model from the first served fetch.
    pub model: String,
    /// Cache value from the first served fetch.
    pub cache: Cache,
    /// Serving time of the first served fetch, in milliseconds.
    pub serve_ms: Option<u64>,
    /// Generation time of the first served fetch, in milliseconds.
    pub gen_ms: Option<u64>,
    pub cost: Option<serde_json::Number>,
    /// Serving time of the latest fetch, in milliseconds.
    pub latest_serve_ms: Option<u64>,
    /// Creation reason from the first served fetch.
    pub reason: Reason,
    /// How the first served fetch supplied the page. Later fetches do not
    /// change it.
    pub made: Made,
    /// How the latest fetch supplied the page.
    pub latest: Made,
}
/// Why the world assigned an address to a host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteReason {
    /// A known search engine address.
    SearchEngine,
    /// An address supplied by the seed.
    Seed,
    /// An address restored from storage.
    Recorded,
    /// An address allocated from the world's pool.
    Pool,
    /// An absent or unrecognized assignment reason.
    #[default]
    #[serde(other)]
    Unknown,
}
/// A host and its assigned address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    pub host: String,
    pub site: String,
    pub address: String,
    pub reason: SiteReason,
    /// Run time of the assignment, in milliseconds.
    pub at_ms: u64,
}
/// A name the world refused to serve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub name: String,
    pub reason: String,
    /// Run time of the refusal, in milliseconds.
    pub at_ms: u64,
}
/// A fact or page planted during the run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plant {
    /// `fact` or `page`.
    pub kind: String,
    /// The fact, or the page's title.
    pub text: String,
    /// The page's URL; empty for a fact.
    pub url: String,
    /// Run time of the planting, in milliseconds.
    pub at_ms: u64,
}
/// Counts of rows dropped to keep the snapshot bounded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omitted {
    pub queries: u64,
    pub results: u64,
    /// Results cut from retained lists that exceeded the list limit.
    pub listed: u64,
    pub pages: u64,
    pub sites: u64,
    pub refused: u64,
    #[serde(default)]
    pub planted: u64,
}
/// Bounded state projected from a run's events.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Increases once per event that changes the state.
    pub revision: u64,
    /// Run time of the last change, in milliseconds.
    pub at_ms: u64,
    pub seed: SeedCard,
    pub generator: Generator,
    pub queries: Vec<Query>,
    pub results: Vec<Results>,
    pub pages: Vec<Page>,
    pub sites: Vec<Site>,
    pub refused: Vec<Refused>,
    /// Facts and pages planted during the run, oldest first.
    #[serde(default)]
    pub planted: Vec<Plant>,
    pub omitted: Omitted,
}

/// Projects selected events without retaining event history.
pub struct Searches(Mutex<Snapshot>);
impl Searches {
    /// Starts an empty projection with bounded seed and generator metadata.
    pub fn new(mut seed: SeedCard, mut generator: Generator) -> Self {
        let omitted = Omitted::default();
        seed.name = bounded(&seed.name);
        seed.date = bounded(&seed.date);
        seed.instructions = bounded(&seed.instructions);
        generator.model = bounded(&generator.model);
        Self(Mutex::new(Snapshot {
            seed,
            generator,
            omitted,
            ..Snapshot::default()
        }))
    }
    /// Starts with the card of an in-memory world with the offline
    /// generator ([`Pages::new`](crate::pages::Pages::new)).
    pub fn from_seed(seed: &crate::pages::Seed) -> Self {
        Self::of(&crate::pages::Pages::new(seed.clone()))
    }
    /// Starts with the card of a world's pages: its seed and its generator.
    pub fn of(pages: &crate::pages::Pages) -> Self {
        Self::new(
            SeedCard::of(pages),
            Generator {
                kind: pages.generator_kind(),
                model: pages.model(),
                prefetch: pages.prefetch() as u64,
                generate: pages.generation().generate,
                copied: pages.new_pages() == crate::pages::NewPages::Copied,
                live_search: pages.new_pages() == crate::pages::NewPages::LiveSearch,
                live_available: pages.live_available(),
                ..Generator::default()
            },
        )
    }
    /// Reads the revision without cloning the snapshot.
    pub fn revision(&self) -> u64 {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revision
    }

    /// Clones the current state.
    pub fn snapshot(&self) -> Snapshot {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
impl Observer for Searches {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        let Interest::Event(m, _) = interest else {
            return false;
        };
        matches!(
            (m.source, m.kind),
            (
                "web",
                "site"
                    | "refused"
                    | "query"
                    | "query_failed"
                    | "generation"
                    | "planted"
                    | "restarted"
                    | "search_answer"
                    | "making"
                    | "model_call"
                    | "page_failed"
                    | "prefetch_finished"
            ) | ("http", "request")
        )
    }
    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        if let Observation::Event(event) = observation {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ms = stamp.at.since_start().as_millis().min(u64::MAX as u128) as u64;
            if state.apply(event, stamp.seq, ms) {
                state.revision = state.revision.saturating_add(1);
                state.at_ms = ms;
            }
        }
    }
}
mod events;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_state_still_accepts_events() {
        let searches = Searches::new(
            SeedCard {
                name: "seed".into(),
                ..SeedCard::default()
            },
            Generator::default(),
        );
        let result = std::panic::catch_unwind(|| {
            let _state = searches.0.lock().unwrap();
            panic!("interrupted while holding the state");
        });
        assert!(result.is_err());
        assert!(searches.0.is_poisoned());
        assert_eq!(searches.snapshot().seed.name, "seed");

        let event = Event::new("web", "query")
            .field("query_id", 1u64)
            .field("engine", "google");
        searches.observe(
            Stamp {
                stream: fictionet::events::Stream::Events,
                seq: 1,
                at: fictionet::time::Instant::ZERO,
            },
            Observation::Event(&event),
        );
        let snapshot = searches.snapshot();
        assert_eq!(snapshot.seed.name, "seed");
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.queries[0].id, 1);
        assert_eq!(snapshot.queries[0].outcome, Outcome::Pending);
    }
}
