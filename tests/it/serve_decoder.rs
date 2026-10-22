//! Services change protocol framing between items through the driver.
use fictionet::stdlib::services::serve::{Flow, Harness, ServeOptions};
use fictionet::stdlib::{
    codec::Wire,
    protocols::{imap, postgres, smtp},
};
use fictionet::{RunOptions, Seed};

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
fn smtp_data_changes_the_active_decoder() {
    let mut harness = Harness::new(Seed::from_u64(1), Mail::default(), ());
    harness.push(b"DATA\r\n").unwrap();
    harness.push(b"..hello\r\n.\r\n").unwrap();
    assert_eq!(harness.service().messages, [b".hello\r\n".to_vec()]);
    assert_eq!(harness.output(), b"354 Send data\r\n250 Queued\r\n");
}

#[test]
fn smtp_auth_challenges_cancel_and_handoff_in_one_chunk() {
    use fictionet::stdlib::services::serve::{HarnessError, Upgrade};

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
    impl fictionet::stdlib::network::DatagramSocket for Socket {
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
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(1)),
        |cx| async move {
            let output = Arc::new(Mutex::new(vec![]));
            let socket = Socket {
                input: VecDeque::from([
                    b"DATA\r\none\r\n.\r\n".to_vec(),
                    b"DATA\r\ntwo\r\n.\r\n".to_vec(),
                ]),
                output: output.clone(),
            };
            let mut service = Mail::default();
            fictionet::stdlib::services::serve::datagram(
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
        },
    ))
    .unwrap();
}
