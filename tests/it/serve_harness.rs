use crate::common::echo_service;

use std::convert::Infallible;
use std::time::Duration;

use echo_service::{Echo, Ticker};
use fictionet::stdlib::protocols::modbus::{self, Frame};
use fictionet::stdlib::services::serve::{Ended, Flow, Harness, HarnessError};

#[test]
fn the_harness_runs_a_service_with_no_runtime() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Echo, ());
    assert_eq!(h.open().unwrap(), b"hello\n");
    assert_eq!(h.push(b"one\ntw").unwrap(), b"one\n");
    assert_eq!(h.push(b"o\n").unwrap(), b"two\n");
    // A line past the limit is one error item, and the service goes on.
    assert_eq!(h.push(&[b'x'; 100]).unwrap(), b"too long\n");
    assert_eq!(h.push(b"\nthree\n").unwrap(), b"three\n");
    assert_eq!(h.push(b"quit\n").unwrap(), b"bye\n");
    assert!(h.closed());
    assert_eq!(h.end_reason(), Some(Ended::Closed));
    assert!(matches!(h.push(b"more\n"), Err(HarnessError::Closed)));
    assert_eq!(h.output(), b"hello\none\ntwo\ntoo long\nthree\nbye\n");
}

#[test]
fn the_harness_moves_its_clock_and_ticks() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Ticker { ticks: 0 }, ());
    h.open().unwrap();
    assert!(h.deadline().is_some());
    assert_eq!(h.advance(Duration::from_millis(10)).unwrap(), b"");
    assert_eq!(h.advance(Duration::from_millis(25)).unwrap(), b"tick\n");
    assert_eq!(h.advance(Duration::from_millis(30)).unwrap(), b"tick\n");
    assert_eq!(h.advance(Duration::from_millis(30)).unwrap(), b"tick\n");
    assert!(h.closed());
}

#[test]
fn a_half_close_ends_with_the_last_reply() {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Echo, ());
    h.push(b"a\nb").unwrap();
    // The unterminated line is an error item at the end, then on_end.
    assert_eq!(h.end().unwrap(), b"too long\neof\n");
    assert_eq!(h.end_reason(), Some(Ended::Eof));
}

#[test]
fn a_decoder_failure_is_handed_to_the_service_with_what_it_could_not_read() {
    struct Strict {
        unread: Vec<u8>,
    }
    service_fixture! {
        Strict => (fictionet::stdlib::codec::Frames<modbus::Frame>, (), Infallible);
        decoder(self) {
            fictionet::stdlib::codec::Frames::<modbus::Frame>::new()
        }
        on_item(self, _: Frame; _, _) -> Flow {
            Ok(Flow::Continue)
        }
        on_fail(self, _: &fictionet::stdlib::codec::Fail<modbus::Error>; _, driver) -> () {
            self.unread = driver.unread().to_vec();
            driver.reply().extend_from_slice(b"no");
            Ok(())
        }
    }
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Strict { unread: Vec::new() },
        (),
    );
    // Protocol id 7: not Modbus.
    let bad = [0, 1, 0, 7, 0, 6, 1, 3, 0, 0, 0, 1];
    assert!(matches!(h.push(&bad), Err(HarnessError::Decode(_))));
    assert_eq!(h.output(), b"no");
    assert_eq!(h.service().unread, bad);
    assert_eq!(h.end_reason(), Some(Ended::Failed));
}

/// The idle clock counts only while the driver waits for the client.
/// Ordered work suspends it: once the work is done, the client has the
/// whole idle time to speak before the connection closes as idle.
#[test]
fn the_idle_clock_restarts_after_ordered_work() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use fictionet::stdlib::codec::{Ending, LineError, Lines};
    use fictionet::stdlib::services::serve::{Pending, PendingDriver, ServeOptions};

    /// Work that ends once the flag is set.
    struct Gated(Arc<AtomicBool>);
    impl Pending for Gated {
        fn poll_next(
            &mut self,
            _: &mut PendingDriver<'_>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>> {
            if self.0.load(Ordering::SeqCst) {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }
    struct Deferring(Arc<AtomicBool>);
    service_fixture! {
        Deferring => (Lines, (), Infallible);
        decoder(self) { Lines::new(64, Ending::LfOrCrlf) }
        on_item(self, _: Result<Vec<u8>, LineError>; _, driver) -> Flow {
            driver.defer(Gated(self.0.clone()));
            Ok(Flow::Continue)
        }
    }

    let done = Arc::new(AtomicBool::new(false));
    let idle = Duration::from_secs(10);
    let mut h = Harness::with_options(
        fictionet::Seed::from_u64(0),
        Deferring(done.clone()),
        (),
        ServeOptions::default().idle(Some(idle)),
    );
    h.push(b"work\n").unwrap();
    // The work outlasts the idle limit; the driver waits for it, not the client.
    h.advance(idle + idle).unwrap();
    assert!(!h.closed(), "running work is not a silent client");
    done.store(true, Ordering::SeqCst);
    h.poll().unwrap();
    assert!(
        !h.closed(),
        "the client had no time to speak since the work ended"
    );
    h.advance(idle - Duration::from_secs(1)).unwrap();
    assert!(!h.closed());
    h.advance(Duration::from_secs(1)).unwrap();
    assert_eq!(h.end_reason(), Some(Ended::Idle));
}
