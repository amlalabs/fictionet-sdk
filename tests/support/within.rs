use std::sync::mpsc;
use std::time::Duration;

/// Runs a function on a thread and fails if it exceeds the limit.
pub fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("timed out")
}
