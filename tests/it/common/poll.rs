use std::time::{Duration, Instant};

/// Waits for a condition and fails if the deadline passes.
pub fn until(limit: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !ready() {
        assert!(Instant::now() < deadline, "condition did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}
