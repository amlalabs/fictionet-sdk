//! Helpers shared by the test modules, each built with the features of the
//! modules that use it.

#[macro_use]
mod service_fixture;

pub mod alloc;
#[cfg(feature = "std")]
#[path = "../../common/certs.rs"]
pub mod certs;
#[cfg(feature = "std")]
pub mod done;
pub mod echo_service;
#[cfg(feature = "std")]
pub mod http_observer;
#[cfg(feature = "std")]
#[path = "../../../examples/common/hyper.rs"]
pub mod hyper_io;
#[cfg(feature = "std")]
pub mod io;
#[cfg(feature = "std")]
pub mod pattern;
#[cfg(feature = "std")]
#[path = "../../common/poll.rs"]
pub mod poll;
#[cfg(feature = "std")]
pub mod rustls_client;
// Only the observer tests call `temp::socket`. The command's tests share
// the file and have no `observe` feature, so it cannot be gated inside.
#[cfg(feature = "std")]
#[cfg_attr(not(feature = "observe"), allow(dead_code))]
#[path = "../../common/temp.rs"]
pub mod temp;
#[cfg(feature = "std")]
pub mod threads;
#[cfg(feature = "std")]
pub mod timeout;
#[cfg(feature = "std")]
pub mod world;

#[cfg(feature = "std")]
#[path = "../../common/within.rs"]
mod within;
#[cfg(feature = "std")]
pub use within::within;

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
