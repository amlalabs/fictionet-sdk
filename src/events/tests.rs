#[cfg(not(target_arch = "wasm32"))]
use super::sink::FILE_QUEUE_BYTES;
use super::*;
use fictionet::sync::Mutex;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

/// An event's JSON says whether its connection was TLS, and its ALPN.
#[test]
fn json_names_tls_and_alpn() {
    let addr = SocketAddr::from(([10, 0, 0, 2], 443));
    let plain = Event::new("http", "request").conn(&ConnInfo::new(1, addr, addr));
    let line = plain.to_line();
    assert!(
        line.contains(r#""tls":false,"sni":null,"alpn":null"#),
        "{line}"
    );
    let tls = Event::new("http", "request")
        .conn(&ConnInfo::new(1, addr, addr).over_tls(Some("a.test"), Some(b"h2")));
    let line = tls.to_line();
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
    slow: bool,
}

impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut bytes = self.bytes.lock();
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
        let json = events[1].to_line();
        assert!(
            json.contains(r#""source":"world","kind":"hello""#) && json.contains(r#""node":"t1""#),
            "{json}"
        );
        Ok(())
    }))
    .unwrap();
}
