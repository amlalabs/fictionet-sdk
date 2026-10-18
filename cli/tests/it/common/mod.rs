//! Helpers for the command's tests. Those in the top-level `tests/common`
//! are shared with the SDK's integration tests.

// The command's tests issue certificates; only the SDK's use the bundled roots.
#[allow(dead_code)]
#[path = "../../../../tests/common/certs.rs"]
pub mod certs;
pub mod io;
pub mod logged;
#[path = "../../../../tests/common/poll.rs"]
pub mod poll;
#[path = "../../../../tests/common/temp.rs"]
pub mod temp;
#[path = "../../../../tests/common/within.rs"]
mod within;
pub use within::within;
