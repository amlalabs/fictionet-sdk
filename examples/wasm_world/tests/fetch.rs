//! One request through the world, on the host and in a JavaScript engine.
//!
//! Both targets run four synchronous cases; JavaScript also runs an
//! event-loop case. The README says which requests a world cannot serve in
//! a JavaScript engine.

use http::Version;
use wasm_world::{Fetched, NAME, SITE, fetch};

fn check(fetched: Fetched, version: Version) {
    assert_eq!(fetched.address, SITE);
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.version, version);
    assert_eq!(
        fetched.body,
        format!("hello from {NAME}: GET /from-the-browser\n")
    );
}

/// Plain HTTP and HTTPS with both HTTP versions, driven by `block_on`.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn requests_with_block_on() {
    for (https, version) in [
        (false, Version::HTTP_2),
        (true, Version::HTTP_2),
        (false, Version::HTTP_11),
        (true, Version::HTTP_11),
    ] {
        check(
            fictionet::block_on(fetch(https, version))
                .unwrap_or_else(|e| panic!("https={https}, version={version:?}: {e}")),
            version,
        );
    }
}

/// HTTPS with HTTP/2, with the JavaScript event loop driving the world, as
/// in a page: the timers fire from `setTimeout`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn https_on_the_event_loop() {
    check(fetch(true, Version::HTTP_2).await.unwrap(), Version::HTTP_2);
}
