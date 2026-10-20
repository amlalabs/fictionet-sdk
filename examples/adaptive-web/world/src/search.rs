//! Bounded search and page state for a run observer.

use crate::route::Engine;
use example_common::events::js;
use fictionet::events::{Event, Interest, Observation, Observer, Stamp};
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
/// Facts and site hosts retained in each seed list.
pub const MAX_SEED_ITEMS: usize = 32;
/// Maximum compact snapshot JSON size, in bytes. The worst case at the
/// limits above fits; `tests/search.rs` builds it and measures.
pub const MAX_SNAPSHOT_BYTES: usize = 4 << 20;

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
    pub question: String,
    pub facts: Vec<String>,
    /// Site hosts supplied by the seed.
    pub sites: Vec<String>,
}
impl SeedCard {
    fn of(seed: &crate::pages::Seed) -> Self {
        Self {
            name: seed.name.clone(),
            date: seed.date.clone(),
            question: seed.question.clone(),
            facts: seed.facts.clone(),
            sites: seed.sites.iter().map(|s| s.host.clone()).collect(),
        }
    }
}
/// What makes the world's content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorKind {
    /// Deterministic placeholder content.
    Stub,
    /// Models served by OpenRouter.
    Openrouter,
    /// Models served by Anthropic.
    Anthropic,
    /// Previously stored content.
    Replay,
    /// An absent or unrecognized generator.
    #[default]
    #[serde(other)]
    Unknown,
}
/// The generator settings for a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generator {
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
}
impl Default for Generator {
    fn default() -> Self {
        Self {
            kind: GeneratorKind::default(),
            model: String::new(),
            prefetch: 0,
            generate: true,
            generation_revision: 0,
            generation_at_ms: 0,
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
    /// IP address of the client that asked.
    pub peer: Option<String>,
    /// Run time when the request began, in milliseconds.
    pub at_ms: u64,
    /// Sequence number of the query event.
    pub seq: u64,
    pub outcome: Outcome,
    pub cache: Option<Cache>,
    /// Result count the answer reported.
    pub results: Option<u64>,
    /// Time spent generating the answer, in milliseconds.
    pub gen_ms: Option<u64>,
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
    /// Made by the stub generator.
    Stubbed,
    /// Made by a model.
    WrittenLive,
    /// Read from storage.
    Stored,
    /// Supplied as a fixed page.
    Fixed,
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
            Self::Stubbed | Self::WrittenLive | Self::Stored | Self::Fixed
        )
    }
}
fn made(cache: Cache, model: &str) -> Made {
    match cache {
        Cache::Generated | Cache::Prefetched if model == "stub" => Made::Stubbed,
        Cache::Generated | Cache::Prefetched => Made::WrittenLive,
        Cache::Cached => Made::Stored,
        Cache::Fixed => Made::Fixed,
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
    /// Run time of the first fetch, in milliseconds.
    pub at_ms: u64,
    pub fetches: u64,
    /// HTTP status of the latest fetch.
    pub status: u64,
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
    pub seed_facts: u64,
    pub seed_sites: u64,
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
    pub omitted: Omitted,
}

/// Projects selected events without retaining event history.
pub struct Searches(Mutex<Snapshot>);
impl Searches {
    /// Starts an empty projection with bounded seed and generator metadata.
    pub fn new(mut seed: SeedCard, mut generator: Generator) -> Self {
        let omitted = Omitted {
            seed_facts: seed.facts.len().saturating_sub(MAX_SEED_ITEMS) as u64,
            seed_sites: seed.sites.len().saturating_sub(MAX_SEED_ITEMS) as u64,
            ..Omitted::default()
        };
        seed.name = bounded(&seed.name);
        seed.date = bounded(&seed.date);
        seed.question = bounded(&seed.question);
        seed.facts = seed
            .facts
            .iter()
            .take(MAX_SEED_ITEMS)
            .map(|s| bounded(s))
            .collect();
        seed.sites = seed
            .sites
            .iter()
            .take(MAX_SEED_ITEMS)
            .map(|s| bounded(s))
            .collect();
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
            SeedCard::of(pages.seed()),
            Generator {
                kind: pages.generator_kind(),
                model: pages.model().into(),
                prefetch: pages.prefetch() as u64,
                generate: pages.generation().generate,
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
                "adaptive",
                "site" | "refused" | "query" | "query_failed" | "generation"
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
fn recent<T>(rows: &mut Vec<T>, item: T, limit: usize, omitted: &mut u64) {
    if rows.len() == limit {
        rows.remove(0);
        *omitted = omitted.saturating_add(1);
    }
    rows.push(item);
}
fn host(url: &str) -> String {
    bounded(&crate::pages::text::split_url(url).0)
}
impl Snapshot {
    fn apply(&mut self, e: &Event, seq: u64, ms: u64) -> bool {
        match (e.source, e.kind) {
            ("adaptive", "generation") => {
                let (Some(generate), Some(revision)) = (parse(e, "generate"), e.u64("revision"))
                else {
                    return false;
                };
                if revision <= self.generator.generation_revision {
                    return false;
                }
                self.generator.generate = generate;
                self.generator.generation_revision = revision;
                self.generator.generation_at_ms = ms;
                true
            }
            ("adaptive", "query") => {
                let (Some(id), Some(engine)) = (e.u64("query_id"), parse(e, "engine")) else {
                    return false;
                };
                if self.queries.iter().any(|q| q.id == id) {
                    return false;
                }
                let query = Query {
                    id,
                    key: text(e, "key"),
                    search: text(e, "search"),
                    engine,
                    start: e.u64("start").unwrap_or(0),
                    sandbox: e.conn.sandbox.as_ref().map(|s| bounded(&s.name)),
                    peer: e.conn.peer.map(|p| bounded(&p.ip().to_string())),
                    at_ms: ms,
                    seq,
                    outcome: Outcome::Pending,
                    cache: None,
                    results: None,
                    gen_ms: None,
                    serve_ms: None,
                    answer_seq: None,
                    answer_at_ms: None,
                };
                recent(
                    &mut self.queries,
                    query,
                    MAX_QUERIES,
                    &mut self.omitted.queries,
                );
                true
            }
            ("adaptive", "query_failed") => {
                let Some(q) = self
                    .queries
                    .iter_mut()
                    .find(|q| Some(q.id) == e.u64("query_id"))
                else {
                    return false;
                };
                if q.outcome != Outcome::Pending {
                    return false;
                }
                let why = parse(e, "why").unwrap_or_default();
                q.outcome = Outcome::Failed {
                    why,
                    error: e.str("error").map(bounded),
                };
                q.cache = (why == Failure::Budget).then_some(Cache::Budget);
                q.serve_ms = e.u64("serve_ms");
                q.answer_seq = Some(seq);
                q.answer_at_ms = Some(ms);
                true
            }
            ("http", "request") => {
                let mut changed = false;
                let id = e.u64("query_id");
                if let Some(q) = self.queries.iter_mut().find(|q| Some(q.id) == id)
                    && (q.outcome == Outcome::Pending
                        || (matches!(q.outcome, Outcome::Failed { .. })
                            && (e.str("kind") == Some("error")
                                || e.str("cache") == Some("budget"))))
                {
                    let before = q.clone();
                    let pending = q.outcome == Outcome::Pending;
                    if pending {
                        q.outcome = if e.get("complete").and_then(|v| v.as_bool()) == Some(true) {
                            Outcome::Served
                        } else {
                            Outcome::Undelivered
                        };
                    }
                    q.cache = parse(e, "cache")
                        .or(q.cache)
                        .or(pending.then_some(Cache::Unknown));
                    q.results = e.u64("results");
                    q.gen_ms = e.u64("gen_ms");
                    q.serve_ms = e.u64("serve_ms").or(q.serve_ms);
                    q.answer_seq = Some(seq);
                    q.answer_at_ms = Some(ms);
                    changed = *q != before;
                    if pending
                        && let Some(fictionet::stdlib::protocols::json::Value::Array(items)) =
                            e.get("listed")
                    {
                        // A list made for this answer replaces one shown
                        // while generation was off.
                        let made = matches!(q.cache, Some(Cache::Generated | Cache::Prefetched));
                        let shown = self
                            .results
                            .iter()
                            .position(|r| r.key == q.key)
                            .map(|index| self.results.remove(index));
                        if let Some(list) = shown.filter(|_| !made) {
                            self.results.push(list);
                        } else {
                            let listed = items
                                .iter()
                                .take(MAX_LISTED)
                                .filter_map(|item| {
                                    let value = js(Some(item));
                                    let url = value["url"].as_str()?;
                                    Some(Listed {
                                        rank: value["rank"].as_u64()?,
                                        host: host(url),
                                        url: bounded(url),
                                        title: bounded(value["title"].as_str()?),
                                    })
                                })
                                .collect();
                            self.omitted.listed = self
                                .omitted
                                .listed
                                .saturating_add(items.len().saturating_sub(MAX_LISTED) as u64);
                            recent(
                                &mut self.results,
                                Results {
                                    key: q.key.clone(),
                                    listed,
                                    cache: q.cache.unwrap_or_default(),
                                    query_id: q.id,
                                },
                                MAX_RESULTS,
                                &mut self.omitted.results,
                            );
                        }
                    }
                }
                if e.str("kind") == Some("page") {
                    let Some(host_name) = e.str("host") else {
                        return changed;
                    };
                    let path = e.str("path").unwrap_or("/");
                    let query = e.str("query");
                    let url = bounded(&format!(
                        "{}://{host_name}{path}{}",
                        e.str("scheme").unwrap_or("https"),
                        query.map(|q| format!("?{q}")).unwrap_or_default()
                    ));
                    let cache = parse(e, "cache").unwrap_or_default();
                    let made = made(cache, e.str("model").unwrap_or_default());
                    let mut reason: Reason = parse(e, "reason").unwrap_or_default();
                    reason.bound();
                    let fetched = Page {
                        seq,
                        first_serve_ms: e.u64("serve_ms"),
                        url,
                        host: bounded(host_name),
                        at_ms: ms,
                        fetches: 1,
                        status: e.u64("status").unwrap_or(0),
                        title: text(e, "title"),
                        model: text(e, "model"),
                        cache,
                        serve_ms: e.u64("serve_ms"),
                        gen_ms: e.u64("gen_ms"),
                        latest_serve_ms: e.u64("serve_ms"),
                        reason,
                        made,
                        latest: made,
                    };
                    if let Some(index) = self.pages.iter().position(|p| p.url == fetched.url) {
                        let old = self.pages.remove(index);
                        let mut page = if !old.made.supplied() && made.supplied() {
                            // The fetch that made the page says why and how.
                            Page {
                                seq: old.seq,
                                first_serve_ms: old.first_serve_ms,
                                at_ms: old.at_ms,
                                fetches: old.fetches,
                                ..fetched
                            }
                        } else {
                            Page {
                                status: fetched.status,
                                latest_serve_ms: fetched.latest_serve_ms,
                                latest: made,
                                ..old
                            }
                        };
                        page.fetches = page.fetches.saturating_add(1);
                        self.pages.push(page);
                    } else {
                        recent(&mut self.pages, fetched, MAX_PAGES, &mut self.omitted.pages);
                    }
                    changed = true;
                }
                changed
            }
            ("adaptive", "site") => {
                let host = text(e, "host");
                if self.sites.iter().any(|s| s.host == host) {
                    return false;
                }
                if self.sites.len() == MAX_SITES {
                    self.omitted.sites = self.omitted.sites.saturating_add(1);
                    return true;
                }
                let reason = match e.str("why") {
                    Some("search engine") => SiteReason::SearchEngine,
                    Some("seed") => SiteReason::Seed,
                    Some("recorded") => SiteReason::Recorded,
                    Some("pool") => SiteReason::Pool,
                    _ => SiteReason::Unknown,
                };
                self.sites.push(Site {
                    host,
                    address: text(e, "addr"),
                    reason,
                    at_ms: ms,
                });
                true
            }
            ("adaptive", "refused") => {
                let row = Refused {
                    name: text(e, "host"),
                    reason: text(e, "why"),
                    at_ms: ms,
                };
                if self.refused.last() == Some(&row) {
                    return false;
                }
                if let Some(index) = self.refused.iter().position(|r| r.name == row.name) {
                    self.refused.remove(index);
                }
                recent(
                    &mut self.refused,
                    row,
                    MAX_REFUSED,
                    &mut self.omitted.refused,
                );
                true
            }
            _ => false,
        }
    }
}

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

        let event = Event::new("adaptive", "query")
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
