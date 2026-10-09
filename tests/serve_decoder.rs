//! Services change protocol framing between items through the driver.
use fictionet::Seed;
use fictionet::stdlib::serve::{Driver, FaultPlan, Flow, Harness, Plan, ServeOptions, Service};
use fictionet::stdlib::{codec::Wire, imap, postgres, smtp};

#[derive(Default)]
struct Mail {
    messages: Vec<Vec<u8>>,
}
impl Service for Mail {
    type Decoder = smtp::Inputs;
    type State = ();
    type Error = smtp::Error;
    fn decoder(&self) -> Self::Decoder {
        smtp::Inputs::new()
    }
    fn on_item(
        &mut self,
        item: Result<smtp::Input, smtp::Error>,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
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

struct Imap {
    commands: Vec<String>,
}
impl Service for Imap {
    type Decoder = imap::Inputs;
    type State = ();
    type Error = imap::Error;
    fn decoder(&self) -> Self::Decoder {
        imap::Inputs::new()
    }
    fn on_item(
        &mut self,
        item: Result<imap::Input, imap::Error>,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
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
impl Service for Postgres {
    type Decoder = postgres::FrontendMessages;
    type State = ();
    type Error = postgres::Error;
    fn decoder(&self) -> Self::Decoder {
        postgres::FrontendMessages::new()
    }
    fn on_item(
        &mut self,
        item: Result<postgres::FrontendMessage, postgres::Error>,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
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
    impl Service for Switch {
        type Decoder = Lines;
        type State = ();
        type Error = LineError;
        fn decoder(&self) -> Lines {
            Lines::new(64, Ending::LfOrCrlf)
        }
        fn on_item(
            &mut self,
            item: Result<Vec<u8>, LineError>,
            _: &(),
            _: &mut Driver<'_, Lines>,
        ) -> Result<Flow, LineError> {
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
    impl Service for LargeLine {
        type Decoder = Lines;
        type State = ();
        type Error = LineError;
        fn decoder(&self) -> Lines {
            Lines::new(8 << 20, Ending::LfOrCrlf)
        }
        fn on_item(
            &mut self,
            item: Result<Vec<u8>, LineError>,
            _: &(),
            _: &mut Driver<'_, Lines>,
        ) -> Result<Flow, LineError> {
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
