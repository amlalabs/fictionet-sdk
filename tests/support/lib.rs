//! Helpers shared by the tests and benchmarks of the SDK and the command,
//! and by the example worlds' tests.

pub mod certs;
mod done;
mod logged;
mod pattern;
pub mod poll;
mod response;
pub mod sandbox;
pub mod temp;
mod timeout;
mod within;

pub use done::{Done, ended_with_done};
pub use logged::logged;
pub use pattern::pattern;
pub use response::response;
pub use timeout::timeout;
pub use within::within;

fictionet::cfg_std! {
    pub mod harness;
}

fictionet::cfg_std! {
    pub mod bench;
}

fictionet::cfg_std! {
    pub mod web_fixture;
}

fictionet::cfg_std! {
    pub use response::{handler, async_handler, reply_handler, EchoSocket};
}
