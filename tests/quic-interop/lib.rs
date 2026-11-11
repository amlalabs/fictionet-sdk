//! Independent QUIC peers have their own test binary so BoringSSL cannot
//! change how the SDK's other test binaries link OpenSSL.

#[cfg(all(test, not(target_arch = "wasm32")))]
use fictionet::stdlib::services::quic::*;
#[cfg(all(test, not(target_arch = "wasm32")))]
use fictionet::{Entropy, Seed, SeededEntropy, stdlib, time};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    // Use the same carrier fixtures and their regression tests on both
    // sides of the independent-peer integration.
    include!("../../src/stdlib/services/quic/tests.rs");

    mod http3 {
        include!("http3.rs");
    }

    mod interop {
        include!("interop.rs");
    }

    mod sites {
        include!("sites.rs");
    }
}

#[cfg(test)]
#[path = "../../verification/resources/alloc.rs"]
mod alloc;
#[cfg(test)]
#[path = "../../verification/resources/cost.rs"]
mod cost;
