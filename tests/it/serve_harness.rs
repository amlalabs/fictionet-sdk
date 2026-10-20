use crate::common::echo_service;

use std::convert::Infallible;
use std::time::Duration;

use echo_service::{Echo, Ticker};
use fictionet::stdlib::protocols::modbus::{self, Frame};
use fictionet::stdlib::services::serve::{Ended, Flow, Harness, HarnessError};

#[test]
fn the_harness_runs_a_service_with_no_runtime() {
    let log = std::sync::Arc::new(fictionet_observe::Memory::default());
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Echo, ()).observer(log.clone());
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
    let lines: Vec<String> = log
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

#[test]
fn resuming_an_upgrade_keeps_the_observer_and_sequence() {
    use fictionet::events::ConnInfo;
    use fictionet::stdlib::codec::{Ending, LineError, Lines};
    use fictionet::stdlib::services::serve::Upgrade;
    use fictionet_observe::Memory;
    use std::sync::Arc;

    struct Switch;
    service_fixture! {
        Switch => (Lines, (), LineError);
        decoder(self) { Lines::new(64, Ending::LfOrCrlf) }
        on_item(self, item: Result<Vec<u8>, LineError>; _, driver) -> Flow {
            let line = item?;
            driver.emit("test", "line", |event| event.field("bytes", line.len() as u64));
            Ok(if line == b"tls" { Flow::Upgrade(Upgrade::Tls) } else { Flow::Continue })
        }
    }
    let log = Arc::new(Memory::default());
    let mut harness = Harness::new(fictionet::Seed::from_u64(1), Switch, ()).observer(log.clone());
    assert!(matches!(
        harness.push(b"tls\n"),
        Err(HarnessError::Upgraded(Upgrade::Tls))
    ));
    harness
        .resume(ConnInfo {
            tls: true,
            ..ConnInfo::default()
        })
        .unwrap();
    harness.push(b"hello\n").unwrap();
    let events = log.checked_of("test", "line").unwrap();
    assert_eq!(
        events
            .iter()
            .map(|e| (e.seq, e.conn.tls, e.u64("bytes")))
            .collect::<Vec<_>>(),
        [(1, false, Some(3)), (2, true, Some(5))]
    );
}
