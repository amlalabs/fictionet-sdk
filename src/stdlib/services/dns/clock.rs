//! The date a run's clock stands for.

use std::time::SystemTime;

use fictionet::time::Instant;

/// Maps the run's [`Instant`] to a date.
///
/// A run measures time from its start, with no date attached. DNS needs a
/// date only where a standard compares against one, such as the
/// inception and expiration of an RRSIG (RFC 4034 §3.1.5). The world says
/// which date the run starts at, the way
/// [`tls::config_builder`](fictionet::stdlib::services::tls::config_builder)
/// takes a start date for certificates, and engines read dates from this
/// value instead of the host's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WallClock {
    /// The date at [`Instant::ZERO`].
    pub start: SystemTime,
}

impl WallClock {
    /// The date at `now`: `start` plus the time since the run started.
    pub fn at(&self, now: Instant) -> SystemTime {
        self.start + now.since_start()
    }
}
