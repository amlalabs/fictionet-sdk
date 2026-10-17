use std::time::{Duration, Instant};

/// Polls host state that has no readiness signal, failing with its name at the deadline.
pub fn until(limit: Duration, what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
