//! One request through the world, on the host and in a JavaScript engine.
//!
//! In a JavaScript engine, the HTTP/1.1 tests are ignored: hyper's HTTP/1
//! server reads `SystemTime::now` on every poll, which panics on
//! wasm32-unknown-unknown. The README has the details.

use http::Version;
use wasm_world::{Fetched, NAME, SITE, fetch};

fn check(fetched: Fetched, version: Version) {
    assert_eq!(fetched.address, SITE);
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.version, version);
    assert_eq!(fetched.body, format!("hello from {NAME}: GET /from-the-browser\n"));
}

/// HTTP/2 with prior knowledge, with `block_on` driving the world. In a
/// JavaScript engine it fires the timers itself.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn http2_with_block_on() {
    check(fictionet::block_on(fetch(false, Version::HTTP_2)).unwrap(), Version::HTTP_2);
}

/// HTTPS with HTTP/2, with the JavaScript event loop driving the world, as
/// in a page: the timers fire from `setTimeout`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn https_on_the_event_loop() {
    check(fetch(true, Version::HTTP_2).await.unwrap(), Version::HTTP_2);
}

/// HTTPS with HTTP/2, with `block_on` driving the world.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn https_with_block_on() {
    check(fictionet::block_on(fetch(true, Version::HTTP_2)).unwrap(), Version::HTTP_2);
}

/// HTTP/1.1, plain and over TLS.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(target_arch = "wasm32", ignore = "hyper's HTTP/1 server needs SystemTime::now")]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn http1_with_block_on() {
    check(fictionet::block_on(fetch(false, Version::HTTP_11)).unwrap(), Version::HTTP_11);
    check(fictionet::block_on(fetch(true, Version::HTTP_11)).unwrap(), Version::HTTP_11);
}
