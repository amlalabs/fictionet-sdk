//! Helpers shared by this binary's test modules, each built with the
//! features of the modules that use it. Helpers that other test binaries
//! share are in the fictionet-test-support crate.

#[macro_use]
mod service_fixture;

pub mod alloc;
pub mod echo_service;
pub mod http_observer;
pub mod io;
pub mod rustls_client;
pub mod threads;
pub mod world;

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

/// Runs a lab with the test event log installed.
pub async fn observed_lab<F, Fut>(seed: fictionet::Seed, world: F) -> fictionet::Result
where
    F: FnOnce(fictionet::Cx, std::sync::Arc<fictionet_test_support::EventLog>) -> Fut + Send,
    Fut: std::future::Future<Output = fictionet::Result> + Send + 'static,
{
    let log = std::sync::Arc::new(fictionet_test_support::EventLog::default());
    fictionet::lab(
        fictionet::RunOptions::new(seed).observer(log.clone()),
        move |cx| world(cx, log),
    )
    .await
}

/// Serializes a complete log after a deterministic run.
pub fn log_bytes(log: &fictionet_test_support::EventLog) -> Vec<u8> {
    log.all()
        .iter()
        .map(|event| event.to_line().unwrap() + "\n")
        .collect::<String>()
        .into_bytes()
}
