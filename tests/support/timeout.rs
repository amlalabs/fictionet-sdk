use std::future::Future;
use std::time::Duration;

use fictionet::Cx;

/// Waits for a future until the duration expires or the world is cancelled.
pub async fn timeout<T>(fcx: &Cx, d: Duration, fut: impl Future<Output = T>) -> Option<T> {
    fcx.race(Some(fcx.now() + d), fut).await.ok()
}
