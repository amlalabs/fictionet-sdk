use std::future::Future;
use std::time::Duration;

#[cfg(feature = "std")]
use fictionet::run;
use fictionet::{Cx, block_on, lab};

use crate::common::done::Done;
use crate::common::within;

/// Runs a closed lab world within the host limit and requires Done.
pub fn world<F, Fut>(limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    seeded_world(fictionet::Seed::from_u64(1), limit, f)
}

/// Runs a seeded lab world within the host limit and requires Done.
pub fn seeded_world<F, Fut>(seed: fictionet::Seed, limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let result = within(limit, move || {
        block_on(lab(seed, move |fcx| async move {
            f(fcx).await?;
            Err(fictionet::Error::from(Done))
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// Runs a world on real time within the host limit and requires Done.
#[cfg(feature = "std")]
pub fn real_world<F, Fut>(limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    seeded_real_world(fictionet::Seed::random(), limit, f)
}

/// Runs a seeded real-time world within the host limit and requires Done.
#[cfg(feature = "std")]
pub fn seeded_real_world<F, Fut>(seed: fictionet::Seed, limit: Duration, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let result = within(limit, move || {
        block_on(run(seed, move |fcx| async move {
            f(fcx).await?;
            Err(fictionet::Error::from(Done))
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}
