use std::time::Duration;

use fictionet::Cx;

/// Waits for a condition and fails if the world stops or the deadline passes.
pub async fn until(fcx: &Cx, limit: Duration, mut ready: impl FnMut() -> bool) {
    fcx.race(Some(fcx.now() + limit), async {
        while !ready() {
            fcx.sleep(Duration::from_millis(10)).await.expect("the world stopped while waiting");
        }
    }).await.expect("condition did not become ready");
}
