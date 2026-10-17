//! The stdlib module tree compiled in a consumer crate.
//! Unit tests run in the SDK; integration tests use the copied types here.
#![cfg(not(test))]

#[path = "../../src/stdlib/mod.rs"]
pub mod stdlib;

pub use stdlib::*;

fictionet::cfg_observe! {
    #[path = "../../src/observe/conversation.rs"]
    pub mod observe_conversation;
    #[path = "../../src/observe/http2.rs"]
    pub mod observe_http2;
    #[path = "../../src/observe/protocols.rs"]
    pub mod observe_protocols;
    #[path = "../../src/observe/tls.rs"]
    pub mod observe_tls;
}
