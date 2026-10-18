use crate::common::echo_service;

use std::convert::Infallible;
use std::time::Duration;

use echo_service::{Echo, Ticker};
use fictionet::stdlib::protocols::modbus::{self, Frame};
use fictionet::stdlib::services::serve::{Ended, Flow, Harness, HarnessError};

#[test]
fn the_harness_runs_a_service_with_no_runtime() {
    let evidence_h = std::sync::Arc::new(fictionet::events::Memory::default());
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Echo, ()).observer(evidence_h.clone());
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
    let lines: Vec<String> = evidence_h
        .checked_all()
        .unwrap()
        .into_iter()
        .map(|e| e.summary)
        .collect();
    assert_eq!(lines, ["one", "two", "three", "quit"]);
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
