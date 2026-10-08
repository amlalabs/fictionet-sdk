//! The types for time: [`Instant`], [`Duration`] and the [`ms`] shorthand.
//!
//! Read this page when you work with time in a world. To read the clock,
//! call [`Cx::now`](crate::Cx::now). To wait, call
//! [`Cx::sleep`](crate::Cx::sleep) or [`Cx::sleep_until`](crate::Cx::sleep_until).
//! Fictionet has no global time functions: the clock belongs to the run,
//! and world code reaches it only through its [`Cx`](crate::Cx).
//!
//! Under [`run`](crate::run) the clock measures real elapsed time. Under
//! [`lab`](crate::lab) it starts at zero and jumps to the earliest deadline
//! when every task is waiting. World code is the same either way.
//!
//! ```
//! # use fictionet::{Cx, Result, time::ms};
//! # async fn tick(fcx: Cx) -> Result {
//! let started = fcx.now();
//! fcx.sleep(ms(50)).await?;
//! assert!(fcx.now() >= started + ms(50));
//! # Ok(())
//! # }
//! ```
//!
//! # No dates
//!
//! The clock only counts time since the run started. It has no calendar.
//! What date it is in a world is the world's data, usually from its
//! arguments, such as `--date 2019-03-14`. The world adds the time since
//! start to get the current date for certificates, `Date` headers, or an NTP
//! server it runs. A world's date moves with the run's clock but can start
//! anywhere.

pub use std::time::Duration;

/// A point in time on the run's clock, counted from the start of the run.
///
/// This is not [`std::time::Instant`], because that type always reads the
/// system clock. An `Instant` here is a plain value measured from
/// [`Instant::ZERO`], so a clock other than the system's can produce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    since_start: Duration,
}

impl Instant {
    /// The moment the run started.
    pub const ZERO: Instant = Instant {
        since_start: Duration::ZERO,
    };

    /// Time since the run started.
    pub fn since_start(self) -> Duration {
        self.since_start
    }

    /// Makes an instant from elapsed time since the run started.
    ///
    /// `Duration::MAX` is accepted as a deadline that never arrives.
    #[inline]
    pub fn from_since_start(since_start: Duration) -> Instant {
        Instant { since_start }
    }
}

impl std::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, d: Duration) -> Instant {
        Instant {
            since_start: self.since_start + d,
        }
    }
}

/// Shorthand for a number of milliseconds: `ms(50)` is
/// `Duration::from_millis(50)`.
pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}
