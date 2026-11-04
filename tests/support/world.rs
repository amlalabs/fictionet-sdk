//! Worlds a test runs to their end: a lab world on virtual time, or a
//! world on real time, each within a limit of host time and required to
//! end with [`Done`].

use std::future::Future;
use std::time::Duration;

use fictionet::{Cx, block_on, lab};

use crate::{Done, ended_with_done, within};

/// Runs a closed lab world within the host limit and requires Done.
pub fn world<F, Fut>(limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    seeded_world(fictionet::Seed::from_u64(1), limit, f)
}

/// Runs a seeded lab world within the host limit and requires Done.
pub fn seeded_world<F, Fut>(options: fictionet::Seed, limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let result = within(limit, move || {
        block_on(lab(options, move |fcx| async move {
            f(fcx).await?;
            Err(fictionet::Error::from(Done))
        }))
    });
    ended_with_done(result).unwrap_or_else(|e| panic!("the world failed: {e}"));
}
