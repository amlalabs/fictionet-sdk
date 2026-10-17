//! Helpers shared by the test modules, each built with the features of the
//! modules that use it.

#[macro_use]
mod service_fixture;

pub mod alloc;
#[cfg(feature = "std")]
#[allow(dead_code)]
pub mod certs;
#[cfg(feature = "std")]
pub mod done;
pub mod echo_service;
#[cfg(feature = "std")]
pub mod http_observer;
#[cfg(all(feature = "std", feature = "tokio"))]
#[path = "../../../examples/common/hyper.rs"]
pub mod hyper_io;
#[cfg(all(feature = "std", feature = "tokio"))]
pub mod io;
#[cfg(feature = "std")]
pub mod logged;
#[cfg(all(feature = "std", feature = "tokio"))]
pub mod pattern;
#[cfg(feature = "std")]
pub mod poll;
pub mod requirements;
#[cfg(all(feature = "std", feature = "tokio"))]
pub mod rustls_client;
#[cfg(feature = "std")]
pub mod timeout;
#[cfg(feature = "std")]
pub mod wait;
#[cfg(feature = "std")]
pub mod world;

#[cfg(feature = "std")]
use std::sync::mpsc;
#[cfg(feature = "std")]
use std::time::Duration;

/// Runs a function on a thread and fails if it exceeds the limit.
#[cfg(feature = "std")]
pub fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("timed out")
}

/// Runs the test `name` alone in a child process of this binary, and fails
/// if it fails there. Returns true here, where the test then returns, and
/// false in the child, where the test runs. For tests that change or measure
/// the whole process, such as its descriptor limit, memory or threads:
/// `cargo test` runs a binary's tests as threads of one process.
pub fn ran_in_own_process(name: &str) -> bool {
    const CHILD: &str = "FICTIONET_TEST_OWN_PROCESS";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("running 1 test"),
        "{name} in its own process: {}\n{stdout}{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    true
}
