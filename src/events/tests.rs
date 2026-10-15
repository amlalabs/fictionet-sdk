#[cfg(not(target_arch = "wasm32"))]
use super::sink::FILE_QUEUE_BYTES;
use super::*;
use fictionet::sync::Mutex;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

#[test]
fn oversized_event_to_line_returns_error() {
    let event = Event::new("test", "big").summary("x".repeat(1 << 20));
    let error = event.to_line().unwrap_err();
    assert_eq!(error.kind, crate::stdlib::json::ErrorKind::TooLarge);
}

/// An event's JSON says whether its connection was TLS, and its ALPN.
#[test]
fn json_names_tls_and_alpn() {
    let addr = SocketAddr::from(([10, 0, 0, 2], 443));
    let plain = Event::new("http", "request").conn(&ConnInfo::new(1, addr, addr));
    let line = plain.to_line().unwrap();
    assert!(
        line.contains(r#""tls":false,"sni":null,"alpn":null"#),
        "{line}"
    );
    let tls = Event::new("http", "request")
        .conn(&ConnInfo::new(1, addr, addr).over_tls(Some("a.test"), Some(b"h2")));
    let line = tls.to_line().unwrap();
    assert!(
        line.contains(r#""tls":true,"sni":"a.test","alpn":"h2""#),
        "{line}"
    );
}

/// A shared buffer a test writes events into, slowly, or failing after
/// some lines.
#[derive(Clone, Default)]
pub(super) struct Sink {
    pub(super) bytes: Arc<Mutex<Vec<u8>>>,
    fail_after: Option<usize>,
    panic_after: Option<usize>,
    panic_on_flush: bool,
    write_barrier: Option<Arc<std::sync::Barrier>>,
    slow: bool,
}

impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(barrier) = self.write_barrier.take() {
            barrier.wait();
            barrier.wait();
        }
        let mut bytes = self.bytes.lock();
        if self
            .panic_after
            .is_some_and(|n| bytes.iter().filter(|b| **b == b'\n').count() >= n)
        {
            panic!("the sink panicked while writing");
        }
        if self
            .fail_after
            .is_some_and(|n| bytes.iter().filter(|b| **b == b'\n').count() >= n)
        {
            return Err(std::io::Error::other("the disk is full"));
        }
        if self.slow {
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        assert!(!self.panic_on_flush, "the sink panicked while flushing");
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn writer_queue_counts_retained_event_bytes() {
    let sink = Sink::default();
    let out = sink.clone();
    crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
        fcx.events().to_writer(Box::new(out));
        let mut summary = String::with_capacity(FILE_QUEUE_BYTES + 1);
        summary.push('x');
        fcx.record(Event::new("test", "large_capacity").summary(summary));
        assert_eq!(fcx.events().lost(), 1);
        Ok(())
    }))
    .unwrap();
    let bytes = sink.bytes.lock();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("large_capacity"));
    assert!(text.contains("lost"));
}

/// The run's end waits for a file writer to write every line.
#[test]
fn the_run_waits_for_its_file_writer() {
    let sink = Sink {
        slow: true,
        ..Sink::default()
    };
    let out = sink.clone();
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
        fcx.events().to_writer(Box::new(out));
        for i in 0..500u32 {
            fcx.record(Event::new("test", "tick").field("i", i));
        }
        *keep.lock() = Some(fcx.events());
        Ok(())
    }))
    .unwrap();
    let log = kept.lock().take().unwrap();
    let lines = sink.bytes.lock().iter().filter(|b| **b == b'\n').count();
    assert_eq!((lines, log.lost()), (500, 0));
}

/// A write that fails is counted as lost, with every line after it.
#[test]
fn a_failed_write_is_counted_as_lost() {
    let sink = Sink {
        fail_after: Some(100),
        ..Sink::default()
    };
    let out = sink.clone();
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
        fcx.events().to_writer(Box::new(out));
        for i in 0..300u32 {
            fcx.record(Event::new("test", "tick").field("i", i));
        }
        *keep.lock() = Some(fcx.events());
        Ok(())
    }))
    .unwrap();
    let log = kept.lock().take().unwrap();
    let lines = sink.bytes.lock().iter().filter(|b| **b == b'\n').count() as u64;
    // Lines written but not yet flushed when the write failed count as
    // lost too: they may not have reached the file.
    assert_eq!(lines, 100);
    assert!(
        log.lost() >= 200 && lines + log.lost() >= 300,
        "{}",
        log.lost()
    );
}

#[cfg(not(target_arch = "wasm32"))]
fn run_with_panicking_sink(panic_after: usize) -> (Sink, EventLog) {
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let sink = Sink {
        panic_after: Some(panic_after),
        write_barrier: Some(barrier.clone()),
        ..Sink::default()
    };
    let out = sink.clone();
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    crate::block_on(crate::run(
        fictionet::Seed::from_u64(55),
        |fcx| async move {
            fcx.events().to_writer(Box::new(out));
            fcx.record(Event::new("test", "tick").field("i", 0u32));
            // Hold the first write until the rest are queued. The next batch
            // has every remaining event, regardless of thread scheduling.
            barrier.wait();
            for i in 1..300u32 {
                fcx.record(Event::new("test", "tick").field("i", i));
            }
            barrier.wait();
            *keep.lock() = Some(fcx.events());
            Ok(())
        },
    ))
    .unwrap();
    let log = kept.lock().take().unwrap();
    (sink, log)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sink_panics_before_write() {
    let (sink, log) = run_with_panicking_sink(0);
    assert!(sink.bytes.lock().is_empty());
    assert_eq!(log.recorded(), 300);
    assert_eq!(log.lost(), log.recorded());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sink_panics_mid_batch() {
    let (sink, log) = run_with_panicking_sink(100);
    let bytes = sink.bytes.lock();
    let lines = bytes.iter().filter(|b| **b == b'\n').count() as u64;
    assert_eq!(lines, 100);
    assert!(log.lost() >= log.recorded() - lines);
    // Only the first batch's single line was flushed. The 99 written
    // lines in the second batch are lost along with its 200 unwritten ones.
    assert_eq!(log.lost(), 299);
    assert!(
        !std::str::from_utf8(&bytes)
            .unwrap()
            .contains("\"kind\":\"lost\"")
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn join_failure_visible() {
    let store = Store::new(crate::RunMode::Real);
    let log = EventLog::new(store.clone());
    for i in 0..300u32 {
        store.push(Event::new("test", "tick").field("i", i));
    }
    store.close();
    let sink = Sink {
        panic_after: Some(0),
        ..Sink::default()
    };
    log.to_writer(Box::new(sink.clone()));
    assert!(sink.bytes.lock().is_empty());
    assert_eq!(log.lost(), log.all().len() as u64);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sink_panics_while_flushing() {
    for n in [0, 1] {
        let store = Store::new(crate::RunMode::Real);
        let log = EventLog::new(store.clone());
        for _ in 0..n {
            store.push(Event::new("test", "tick"));
        }
        store.close();
        let sink = Sink {
            panic_on_flush: true,
            ..Sink::default()
        };
        log.to_writer(Box::new(sink.clone()));
        assert_eq!(sink.bytes.lock().iter().filter(|b| **b == b'\n').count(), n);
        assert_eq!(log.lost(), 1);
    }
}

/// A panic when the sink is dropped happens after the write guard is gone.
/// Both join paths must latch it, even with no pending lines.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sink_drop_panic_is_latched() {
    struct PanicOnDrop(Sink);

    impl Write for PanicOnDrop {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.write(data)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("the sink panicked when dropped");
        }
    }

    for closed in [false, true] {
        let store = Store::new(crate::RunMode::Real);
        let log = EventLog::new(store.clone());
        if closed {
            store.close();
        }
        log.to_writer(Box::new(PanicOnDrop(Sink::default())));
        store.close();
        assert_eq!(log.lost(), 1);
        log.to_writer(Box::new(Sink::default()));
        assert_eq!(log.lost(), 1, "a later writer cannot clear the failure");
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sink_panic_during_shutdown_preserves_world_panic() {
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    let failure = std::panic::catch_unwind(|| {
        crate::block_on(crate::run(
            fictionet::Seed::from_u64(55),
            |fcx| async move {
                *keep.lock() = Some(fcx.events());
                fcx.events().to_writer(Box::new(Sink {
                    panic_after: Some(0),
                    ..Sink::default()
                }));
                fcx.record(Event::new("test", "tick"));
                panic!("the world panicked");
            },
        ))
    })
    .unwrap_err();
    assert_eq!(failure.downcast_ref::<&str>(), Some(&"the world panicked"));
    assert_eq!(kept.lock().take().unwrap().lost(), 1);
}

/// Events are recorded with no reader at all, numbered and dated on
/// the run's clock, with the task that recorded them.
#[test]
fn every_run_records_its_events() {
    crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
        assert!(!fcx.observed());
        fcx.record(Event::new("world", "hello").field("n", 1u32));
        fcx.sleep(std::time::Duration::from_millis(5)).await?;
        fcx.record(Event::new("world", "hello").field("n", 2u32));
        let events = fcx.events().all();
        assert_eq!(events.len(), 2);
        assert_eq!((events[0].seq, events[1].seq), (1, 2));
        assert!(events[0].at < events[1].at && events[1].at <= fcx.now());
        assert_eq!(
            events[0].origin.as_ref().map(|o| o.task),
            Some(1),
            "the world function is the first task"
        );
        let json = events[1].to_line().unwrap();
        assert!(
            json.contains(r#""source":"world","kind":"hello""#) && json.contains(r#""node":"t1""#),
            "{json}"
        );
        Ok(())
    }))
    .unwrap();
}
