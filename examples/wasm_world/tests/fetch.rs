//! One request through the world, on the host and in a JavaScript engine.
//!
//! Both targets run four synchronous cases.
//! JavaScript also runs an event-loop case.
//! The README says which requests a world cannot serve in a JavaScript engine.

use fictionet::events::Fields;
use fictionet::stdlib::protocols::json::Value;
use http::Version;
use std::io::Write;
use std::sync::{Arc, Mutex};
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
/// In a JavaScript engine, `block_on` fires the timers itself.
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

/// A real run replays retained events and writes new ones to memory.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_run_writes_events_to_memory() {
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let sink = Sink::default();
    let out = sink.clone();
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(42),
        |fcx| async move {
            assert_eq!(fcx.mode(), fictionet::RunMode::Real);
            fcx.record(fictionet::events::Event::new("test", "before_writer"));
            fcx.events().to_writer(Box::new(out.clone()));
            fcx.record(fictionet::events::Event::new("test", "after_writer"));
            #[cfg(target_arch = "wasm32")]
            assert_eq!(
                out.0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count(),
                2,
                "browser writers deliver synchronously"
            );
            *keep.lock().unwrap() = Some(fcx.events());
            Ok(())
        },
    ))
    .unwrap();
    let log = kept.lock().unwrap().take().unwrap();
    let events = log.all();
    assert_eq!(events.len(), 2);
    let expected: String = events
        .iter()
        .map(|event| format!("{}\n", event.to_line().unwrap()))
        .collect();
    assert_eq!(*sink.0.lock().unwrap(), expected.as_bytes());
    assert_eq!(log.lost(), 0);
}

/// A real run records its wall date on the host and in a JavaScript engine.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_run_records_wall_time() {
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(42),
        |fcx| async move {
            fcx.events().start(&fcx, Fields::new());
            *keep.lock().unwrap() = Some(fcx.events());
            Ok(())
        },
    ))
    .unwrap();
    let log = kept.lock().unwrap().take().unwrap();
    assert!(
        log.of("run", "start")[0]
            .get("wall")
            .and_then(Value::as_f64)
            .is_some_and(|w| w > 1.7e9)
    );
}

/// HTTPS with HTTP/2, with the JavaScript event loop driving the world, as
/// in a page: the timers fire from `setTimeout`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn https_on_the_event_loop() {
    check(fetch(true, Version::HTTP_2).await.unwrap(), Version::HTTP_2);
}
