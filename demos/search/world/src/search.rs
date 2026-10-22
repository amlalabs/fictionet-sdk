//! The provenance of stored search results and pages.

use serde::{Deserialize, Serialize};

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
