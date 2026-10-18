//! One request through the world, on the host and in a JavaScript engine.
//!
//! Both targets run four synchronous cases.
//! JavaScript also runs an event-loop case.
//! The README says which requests a world cannot serve in a JavaScript engine.

use fictionet::events::{ConnInfo, Fanout, Memory, Metadata, Observation, Observer, Stamp};
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

/// A real run delivers matching retained events and JSON Lines to memory.
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

    impl Observer for Sink {
        fn enabled(&self, _: Metadata, _: &ConnInfo) -> bool {
            true
        }
        fn observe(&self, _: Stamp, observation: Observation<'_>) {
            if let Observation::Event(event) = observation {
                writeln!(self.clone(), "{}", event.to_line().unwrap()).unwrap();
            }
        }
    }

    let sink = Sink::default();
    let out = sink.clone();
    let evidence = Arc::new(Memory::default());
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(42)).observer(Arc::new(Fanout::new(
            vec![evidence.clone(), Arc::new(sink.clone())],
        ))),
        |fcx| async move {
            assert_eq!(fcx.mode(), fictionet::RunMode::Real);
            fcx.emit("test", "before_writer", |event| event);
            fcx.emit("test", "after_writer", |event| event);
            assert_eq!(
                out.0
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count(),
                3,
                "memory observers deliver synchronously"
            );
            Ok(())
        },
    ))
    .unwrap();
    let events = evidence.checked_all().unwrap();
    assert_eq!(events.len(), 3);
    assert!(events[0].is("run", "start"));
    assert!(events[1].is("test", "before_writer"));
    assert!(events[2].is("test", "after_writer"));
    let expected: String = events
        .iter()
        .map(|event| format!("{}\n", event.to_line().unwrap()))
        .collect();
    assert_eq!(*sink.0.lock().unwrap(), expected.as_bytes());
    assert_eq!(evidence.dropped(), 0);
}

/// A real run records its wall date on the host and in a JavaScript engine.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_run_records_wall_time() {
    let evidence = Arc::new(Memory::default());
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(42)).observer(evidence.clone()),
        |_fcx| async move { Ok(()) },
    ))
    .unwrap();
    let events = evidence.checked_of("run", "start").unwrap();
    assert_eq!(events.len(), 1);
    assert!(
        events[0]
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
