//! Services change protocol framing between items through the driver.
use fictionet::Seed;
use fictionet::stdlib::serve::{FaultPlan, Flow, Harness, Plan, ServeOptions};
use fictionet::stdlib::{codec::Wire, imap, postgres, smtp};

#[macro_use]
#[path = "common/service_fixture.rs"]
mod service_fixture;

use fictionet::stdlib::codec::{
    ByteFault, Ending, FaultError, ItemFault, LineError, Lines, Rewrite, RewriteError, Rule,
    Trigger,
};
use fictionet::stdlib::serve::{self, Ended, HarnessError, ServeError};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

#[derive(Default)]
struct FaultLines {
    seen: Vec<Vec<u8>>,
    ended: Vec<Ended>,
}
service_fixture! {
    FaultLines => (Lines, (), LineError);
    decoder(self) {
        Lines::new(64, Ending::LfOrCrlf)
    }
    on_item(self, item: Result<Vec<u8>, LineError>; _, driver) -> Flow {
        let line = item?;
        driver.reply().extend_from_slice(&line);
        driver.reply().push(b'\n');
        self.seen.push(line);
        Ok(Flow::Continue)
    }
    on_end(self, end: Ended; _, _) -> () {
        self.ended.push(end);
        Ok(())
    }
}

fn fault_harness(plan: Plan) -> Harness<FaultLines> {
    Harness::with_options(
        Seed::from_u64(1),
        FaultLines::default(),
        (),
        ServeOptions::default().faults(FaultPlan::new(plan)),
    )
}

struct FaultConnection {
    input: std::io::Cursor<Vec<u8>>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl fictionet::stdlib::Connection for FaultConnection {
    fn poll_read(
        &mut self,
        _: &fictionet::Cx,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, fictionet::stdlib::ConnError>> {
        use std::io::Read;
        Poll::Ready(Ok(self.input.read(buf).unwrap()))
    }

    fn poll_write(
        &mut self,
        _: &fictionet::Cx,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, fictionet::stdlib::ConnError>> {
        self.output.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_shutdown(
        &mut self,
        _: &fictionet::Cx,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), fictionet::stdlib::ConnError>> {
        Poll::Ready(Ok(()))
    }
}

fn assert_fault_error(
    plan: Plan,
    input: &[u8],
    seen: &[Vec<u8>],
    error: FaultError<Infallible>,
    direction: &'static str,
) {
    let mut harness = fault_harness(plan.clone());
    let result = harness.push(input).unwrap_err();
    assert_eq!(
        std::error::Error::source(&result).unwrap().to_string(),
        error.to_string()
    );
    assert!(matches!(result, HarnessError::Faults(e) if e == error));
    assert_eq!(harness.service().seen, seen);
    assert!(harness.output().is_empty());
    assert_eq!(harness.end_reason(), Some(Ended::Closed));
    assert_eq!(harness.service().ended, [Ended::Closed]);
    assert!(matches!(
        harness.push(b"later\n"),
        Err(HarnessError::Closed)
    ));

    let input = input.to_vec();
    let seen = seen.to_vec();
    fictionet::block_on(fictionet::lab(Seed::from_u64(1), |fcx| async move {
        let output = Arc::new(Mutex::new(Vec::new()));
        let conn = FaultConnection {
            input: std::io::Cursor::new(input),
            output: output.clone(),
        };
        let mut service = FaultLines::default();
        let result = serve::connection(
            &fcx,
            conn,
            fictionet::events::ConnInfo::default(),
            &mut service,
            &(),
            &ServeOptions::default().faults(FaultPlan::new(plan)),
        )
        .await;
        let Err(result) = result else {
            panic!("fault failure was not returned")
        };
        assert_eq!(
            std::error::Error::source(&result).unwrap().to_string(),
            error.to_string()
        );
        assert!(matches!(result, ServeError::Faults(e) if e == error));
        assert_eq!(service.seen, seen);
        assert_eq!(service.ended, [Ended::Closed]);
        assert!(output.lock().unwrap().is_empty());
        let events = fcx.events().of("conn", "error");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, fictionet::events::Level::Notice);
        assert_eq!(events[0].str("kind"), Some("faults"));
        assert_eq!(events[0].str("direction"), Some(direction));
        assert_eq!(
            events[0].str("error"),
            Some(fictionet::ErrorChain(&error).to_string().as_str())
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn inbound_byte_fault_error() {
    assert_fault_error(
        Plan {
            inbound: vec![Rule {
                when: Trigger::Always,
                fault: ByteFault::Replace(vec![b'x'; (4 << 20) + 1]),
            }],
            ..Plan::default()
        },
        b"one\n",
        &[],
        FaultError::Rewrite(RewriteError::TooLong { limit: 4 << 20 }),
        "inbound",
    );
}

#[test]
fn outbound_byte_fault_error() {
    assert_fault_error(
        Plan {
            outbound: vec![Rule {
                when: Trigger::Always,
                fault: ByteFault::Replace(vec![b'x'; (4 << 20) + 1]),
            }],
            ..Plan::default()
        },
        b"one\ntwo\n",
        &[b"one".to_vec()],
        FaultError::Rewrite(RewriteError::TooLong { limit: 4 << 20 }),
        "outbound",
    );
}

#[test]
fn item_fault_error() {
    assert_fault_error(
        Plan {
            items: vec![Rule {
                when: Trigger::Always,
                fault: ItemFault::Action {
                    delay: None,
                    rewrite: Rewrite::Raw(vec![0; (4 << 20) + 1]),
                },
            }],
            ..Plan::default()
        },
        b"one\n",
        &[],
        FaultError::Rewrite(RewriteError::TooLong { limit: 4 << 20 }),
        "items",
    );
}

#[test]
fn item_hold_limit_error() {
    assert_fault_error(
        Plan {
            items: vec![Rule {
                when: Trigger::Always,
                fault: ItemFault::Hold { window: u64::MAX },
            }],
            ..Plan::default()
        },
        &b"x\n".repeat(257),
        &[],
        FaultError::HeldLimit { limit: 256 },
        "items",
    );
}

#[test]
fn fault_error_preserves_preceding_output() {
    let mut harness = fault_harness(Plan {
        outbound: vec![Rule {
            when: Trigger::At(2),
            fault: ByteFault::Replace(vec![b'x'; (4 << 20) + 1]),
        }],
        ..Plan::default()
    });
    assert!(matches!(
        harness.push(b"one\ntwo\nthree\n"),
        Err(HarnessError::Faults(FaultError::Rewrite(RewriteError::TooLong { limit })))
            if limit == 4 << 20
    ));
    assert_eq!(harness.output(), b"one\n");
    assert_eq!(harness.service().seen, [b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(harness.end_reason(), Some(Ended::Closed));
}

#[test]
fn outbound_fault_error_cancels_work_with_written_bytes() {
    struct Chunks(u8);
    impl serve::Pending for Chunks {
        fn poll_next(
            &mut self,
            _: &mut serve::PendingDriver<'_>,
            _: &mut Context<'_>,
        ) -> Poll<Option<fictionet::Result<Vec<u8>>>> {
            if self.0 == 3 {
                return Poll::Ready(None);
            }
            self.0 += 1;
            Poll::Ready(Some(Ok(b"one\n".to_vec())))
        }
        fn cancel(&mut self, driver: &mut serve::PendingDriver<'_>) {
            driver.record(
                fictionet::events::Event::new("chunks", "cancel")
                    .field("written", driver.written()),
            );
        }
    }
    struct Replies;
    service_fixture! {
        Replies => (Lines, (), Infallible);
        decoder(self) { Lines::new(64, Ending::LfOrCrlf) }
        on_open(self; _, driver) -> Flow {
            driver.defer(Chunks(0));
            Ok(Flow::Continue)
        }
        on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
            Ok(Flow::Continue)
        }
    }
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Replies,
        (),
        ServeOptions::default().faults(FaultPlan::new(Plan {
            outbound: vec![Rule {
                when: Trigger::After(2),
                fault: ByteFault::Replace(vec![b'x'; (4 << 20) + 1]),
            }],
            ..Plan::default()
        })),
    );
    assert!(matches!(harness.open(), Err(HarnessError::Faults(_))));
    assert_eq!(harness.output(), b"one\n");
    assert_eq!(harness.end_reason(), Some(Ended::Closed));
    let cancelled: Vec<_> = harness
        .events()
        .iter()
        .filter(|e| e.is("chunks", "cancel"))
        .collect();
    assert_eq!(cancelled.len(), 1);
    assert_eq!(
        cancelled[0].get("written").and_then(|v| v.as_u64()),
        Some(4)
    );
}

#[test]
fn outbound_fault_error_during_end_closes_once() {
    #[derive(Default)]
    struct Goodbye {
        ended: Vec<Ended>,
    }
    service_fixture! {
        Goodbye => (Lines, (), Infallible);
        decoder(self) { Lines::new(64, Ending::LfOrCrlf) }
        on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
            Ok(Flow::Continue)
        }
        on_end(self, end: Ended; _, driver) -> () {
            self.ended.push(end);
            driver.reply().extend_from_slice(b"bye\n");
            Ok(())
        }
    }
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Goodbye::default(),
        (),
        ServeOptions::default().faults(FaultPlan::new(Plan {
            outbound: vec![Rule {
                when: Trigger::Always,
                fault: ByteFault::Replace(vec![b'x'; (4 << 20) + 1]),
            }],
            ..Plan::default()
        })),
    );
    assert!(matches!(harness.end(), Err(HarnessError::Faults(_))));
    assert!(harness.output().is_empty());
    assert_eq!(harness.end_reason(), Some(Ended::Closed));
    assert_eq!(harness.service().ended, [Ended::Eof]);
}

#[test]
fn fault_decoder_failure_preserves_partial_bytes() {
    use fictionet::stdlib::codec::{Fail, Frames};
    use fictionet::stdlib::modbus::{self, Frame};
    #[derive(Default)]
    struct PartialFrame {
        unread: Vec<u8>,
    }
    service_fixture! {
        PartialFrame => (Frames<Frame>, (), Infallible);
        decoder(self) { Frames::new() }
        on_item(self, _: Frame; _, _) -> Flow { Ok(Flow::Continue) }
        on_fail(self, _: &Fail<modbus::Error>; _, driver) -> () {
            self.unread = driver.unread().to_vec();
            Ok(())
        }
    }
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        PartialFrame::default(),
        (),
        ServeOptions::default().faults(FaultPlan::new(Plan::default())),
    );
    let bytes = [0, 1, 0, 0, 0, 6, 1];
    harness.push(&bytes).unwrap();
    assert!(matches!(
        harness.end(),
        Err(HarnessError::Decode(Fail::Truncated { unread: 7 }))
    ));
    assert_eq!(harness.service().unread, bytes);
    assert_eq!(harness.end_reason(), Some(Ended::Failed));
}

#[test]
fn fault_operations_do_not_discard_errors() {
    let source = include_str!("../src/stdlib/serve.rs");
    let faults = source
        .split_once("impl<D: Decode> ConnFaults<D>")
        .expect("connection fault implementation")
        .1
        .split_once("// The state machine the driver and the harness share")
        .expect("end of connection fault implementation")
        .0;
    let compact: String = faults.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        !compact.contains("Err(_)=>"),
        "RH-030: discarded fault error"
    );
    assert!(!compact.contains("let_="), "RH-030: unchecked fault result");
}

#[derive(Default)]
struct Mail {
    messages: Vec<Vec<u8>>,
}
service_fixture! {
    Mail => (smtp::Inputs, (), smtp::Error);
    decoder(self) {
        smtp::Inputs::new()
    }
    on_item(self, item: Result<smtp::Input, smtp::Error>; _, driver) -> Flow {
        match item? {
            smtp::Input::Command(command) if command.verb == "DATA" => {
                driver.decoder().start_data().unwrap();
                driver.reply().extend_from_slice(b"354 Send data\r\n");
            }
            smtp::Input::Message(bytes) => {
                self.messages.push(bytes);
                driver.reply().extend_from_slice(b"250 Queued\r\n");
            }
            _ => {}
        }
        Ok(Flow::Continue)
    }
}

#[test]
fn smtp_data_changes_the_active_decoder_and_stops_item_faults() {
    let opts = ServeOptions::default().faults(FaultPlan::new(Plan::default()));
    let mut harness = Harness::with_options(Seed::from_u64(1), Mail::default(), (), opts);
    harness.push(b"DATA\r\n").unwrap();
    harness.push(b"..hello\r\n.\r\n").unwrap();
    assert_eq!(harness.service().messages, [b".hello\r\n".to_vec()]);
    assert_eq!(harness.output(), b"354 Send data\r\n250 Queued\r\n");
    assert_eq!(
        harness
            .events()
            .iter()
            .filter(|event| event.get("stopped").and_then(|v| v.as_str()) == Some("decoder"))
            .count(),
        1
    );
}

#[test]
fn smtp_auth_challenges_cancel_and_handoff_in_one_chunk() {
    use fictionet::stdlib::serve::{HarnessError, Upgrade};

    #[derive(Default)]
    struct Auth {
        responses: Vec<Vec<u8>>,
    }
    service_fixture! {
        Auth => (smtp::Inputs, (), smtp::Error);
        decoder(self) {
            smtp::Inputs::new()
        }
        on_item(self, item: Result<smtp::Input, smtp::Error>; _, driver) -> Flow {
            match item? {
                smtp::Input::Command(command) if command.verb == "AUTH" => {
                    driver.decoder().expect_line().map_err(smtp::Error::Framing)?;
                    driver.reply().extend_from_slice(b"334 \r\n");
                }
                smtp::Input::Line(line) => {
                    if line == b"*" {
                        driver.reply().extend_from_slice(b"501 Cancelled\r\n");
                    } else {
                        driver.decoder().expect_line().map_err(smtp::Error::Framing)?;
                        driver.reply().extend_from_slice(b"334 \r\n");
                    }
                    self.responses.push(line);
                }
                smtp::Input::Command(command) if command.verb == "STARTTLS" => {
                    driver.decoder().handoff().map_err(smtp::Error::Framing)?;
                    driver.reply().extend_from_slice(b"220 Ready\r\n");
                    return Ok(Flow::Upgrade(Upgrade::Handoff));
                }
                smtp::Input::Command(_) => driver.reply().extend_from_slice(b"250 OK\r\n"),
                smtp::Input::Message(_) => panic!("DATA was not selected"),
            }
            Ok(Flow::Continue)
        }
    }
    let mut harness = Harness::new(Seed::from_u64(1), Auth::default(), ());
    assert!(matches!(
        harness
            .push(b"AUTH LOGIN\r\ndGVzdA==\r\ndGVz\r\n*\r\nNOOP\r\nSTARTTLS\r\n\x16\x03\x03\0\x05"),
        Err(HarnessError::Upgraded(Upgrade::Handoff))
    ));
    assert_eq!(
        harness.service().responses,
        [b"dGVzdA==".to_vec(), b"dGVz".to_vec(), b"*".to_vec(),]
    );
    assert_eq!(
        harness.output(),
        b"334 \r\n334 \r\n334 \r\n501 Cancelled\r\n250 OK\r\n220 Ready\r\n"
    );
    assert_eq!(harness.upgraded(), Some(Upgrade::Handoff));
    assert!(!harness.closed());
}

struct Imap {
    commands: Vec<String>,
}
service_fixture! {
    Imap => (imap::Inputs, (), imap::Error);
    decoder(self) {
        imap::Inputs::new()
    }
    on_item(self, item: Result<imap::Input, imap::Error>; _, driver) -> Flow {
        match item? {
            imap::Input::Continue { .. } => {
                assert!(driver.decoder().refuse_literal());
                driver.reply().extend_from_slice(b"a NO refused\r\n");
            }
            imap::Input::Command(command) => self.commands.push(command.name),
            _ => {}
        }
        Ok(Flow::Continue)
    }
}

#[test]
fn imap_refused_literal_leaves_the_next_command_readable() {
    let mut harness = Harness::new(Seed::from_u64(1), Imap { commands: vec![] }, ());
    harness.push(b"a APPEND inbox {3}\r\n").unwrap();
    harness.push(b"b NOOP\r\n").unwrap();
    assert_eq!(harness.service().commands, ["NOOP"]);
    assert_eq!(harness.output(), b"a NO refused\r\n");
}

struct Postgres {
    startups: usize,
}
service_fixture! {
    Postgres => (postgres::FrontendMessages, (), postgres::Error);
    decoder(self) {
        postgres::FrontendMessages::new()
    }
    on_item(self, item: Result<postgres::FrontendMessage, postgres::Error>; _, driver) -> Flow {
        match item? {
            postgres::FrontendMessage::SslRequest => {
                driver.reply().push(b'N');
                driver.decoder().refuse_encryption();
            }
            postgres::FrontendMessage::Startup(_) => self.startups += 1,
            _ => {}
        }
        Ok(Flow::Continue)
    }
}

#[test]
fn postgres_refused_ssl_reads_startup_from_the_same_chunk() {
    let mut harness = Harness::new(Seed::from_u64(1), Postgres { startups: 0 }, ());
    let mut bytes = postgres::FrontendMessage::SslRequest.to_bytes().unwrap();
    postgres::FrontendMessage::Startup(postgres::Startup::new("agent", "world"))
        .write(&mut bytes)
        .unwrap();
    harness.push(&bytes).unwrap();
    assert_eq!(harness.output(), b"N");
    assert_eq!(harness.service().startups, 1);
}

#[test]
fn smtp_mode_change_stops_faults_before_the_next_pipelined_item() {
    use fictionet::stdlib::codec::{ItemFault, Rewrite, Rule, Trigger};
    let opts = ServeOptions::default().faults(FaultPlan::new(Plan {
        items: vec![Rule {
            when: Trigger::At(2),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        }],
        ..Plan::default()
    }));
    let mut harness = Harness::with_options(Seed::from_u64(1), Mail::default(), (), opts);
    harness.push(b"DATA\r\nhello\r\n.\r\n").unwrap();
    assert_eq!(harness.service().messages, [b"hello\r\n".to_vec()]);
}

#[test]
fn decoder_upgrade_stops_faults_before_buffered_items() {
    use fictionet::stdlib::codec::{Ending, ItemFault, LineError, Lines, Rewrite, Rule, Trigger};
    use fictionet::stdlib::serve::Upgrade;
    struct Switch {
        seen: Vec<Vec<u8>>,
    }
    service_fixture! {
        Switch => (Lines, (), LineError);
        decoder(self) {
            Lines::new(64, Ending::LfOrCrlf)
        }
        on_item(self, item: Result<Vec<u8>, LineError>; _, _) -> Flow {
            self.seen.push(item?);
            Ok(if self.seen.len() == 1 {
                Flow::Upgrade(Upgrade::Decoder)
            } else {
                Flow::Continue
            })
        }
    }
    let opts = ServeOptions::default().faults(FaultPlan::new(Plan {
        items: vec![Rule {
            when: Trigger::At(2),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        }],
        ..Plan::default()
    }));
    let mut harness = Harness::with_options(Seed::from_u64(1), Switch { seen: vec![] }, (), opts);
    harness.push(b"one\ntwo\n").unwrap();
    assert_eq!(harness.service().seen, [b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(
        harness
            .events()
            .iter()
            .filter(|event| event.get("stopped").and_then(|v| v.as_str()) == Some("upgrade"))
            .count(),
        1
    );
}

#[test]
fn stuck_item_fault_decoder_passes_the_partial_item_through() {
    use fictionet::stdlib::codec::{Ending, ItemFault, LineError, Lines, Rewrite, Rule, Trigger};

    struct LargeLine {
        seen: Vec<Vec<u8>>,
    }
    service_fixture! {
        LargeLine => (Lines, (), LineError);
        decoder(self) {
            Lines::new(8 << 20, Ending::LfOrCrlf)
        }
        on_item(self, item: Result<Vec<u8>, LineError>; _, _) -> Flow {
            self.seen.push(item?);
            Ok(Flow::Continue)
        }
    }
    let opts = ServeOptions::default().faults(FaultPlan::new(Plan {
        items: vec![Rule {
            when: Trigger::At(1),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        }],
        ..Plan::default()
    }));
    let mut harness =
        Harness::with_options(Seed::from_u64(1), LargeLine { seen: vec![] }, (), opts);
    let bytes = vec![b'x'; (4 << 20) + 1];
    harness.push(&bytes).unwrap();
    assert!(harness.service().seen.is_empty());
    harness.push(b"\n").unwrap();
    assert_eq!(harness.service().seen.len(), 1);
    assert_eq!(harness.service().seen[0], bytes);
    assert_eq!(
        harness
            .events()
            .iter()
            .filter(|event| event.is("conn", "faults")
                && event.get("stopped").and_then(|v| v.as_str()) == Some("stuck"))
            .count(),
        1
    );
}

#[test]
fn datagram_decoder_access_uses_the_current_datagram() {
    use std::{
        collections::VecDeque,
        net::SocketAddr,
        sync::{Arc, Mutex},
    };
    struct Socket {
        input: VecDeque<Vec<u8>>,
        output: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl fictionet::stdlib::DatagramSocket for Socket {
        async fn recv(
            &mut self,
            _: &fictionet::Cx,
        ) -> Result<(Vec<u8>, SocketAddr), fictionet::RecvError> {
            self.input
                .pop_front()
                .map(|bytes| (bytes, "192.0.2.2:1234".parse().unwrap()))
                .ok_or(fictionet::RecvError::Closed)
        }
        fn send_to(&mut self, data: &[u8], _: SocketAddr) {
            self.output.lock().unwrap().push(data.to_vec());
        }
    }
    fictionet::block_on(fictionet::lab(Seed::from_u64(1), |cx| async move {
        let output = Arc::new(Mutex::new(vec![]));
        let socket = Socket {
            input: VecDeque::from([
                b"DATA\r\none\r\n.\r\n".to_vec(),
                b"DATA\r\ntwo\r\n.\r\n".to_vec(),
            ]),
            output: output.clone(),
        };
        let mut service = Mail::default();
        fictionet::stdlib::serve::datagram(
            &cx,
            socket,
            "192.0.2.1:25".parse().unwrap(),
            &mut service,
            &(),
            &ServeOptions::default(),
        )
        .await?;
        assert_eq!(service.messages, [b"one\r\n".to_vec(), b"two\r\n".to_vec()]);
        assert_eq!(
            *output.lock().unwrap(),
            [
                b"354 Send data\r\n250 Queued\r\n".to_vec(),
                b"354 Send data\r\n250 Queued\r\n".to_vec()
            ]
        );
        Ok(())
    }))
    .unwrap();
}
