use super::*;
use fictionet::stdlib::layer::{Admit, Budget, Chunk, Harness, StreamCommand, StreamEvent};
use std::io::{ErrorKind, Read, Write};

type Server = Harness<tls::TlsLayer>;

/// A layer whose test picks its config by hand, and that refuses every
/// name when nothing does.
fn refusing() -> tls::TlsLayer {
    tls::TlsLayer::selecting(|_, _| async { None })
}

fn client_output(client: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    bytes
}

fn receive(client: &mut rustls::ClientConnection, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        assert!(client.read_tls(&mut rest).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
}

fn handshake(
    config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    split: usize,
) -> (Server, rustls::ClientConnection) {
    let mut client = rustls::ClientConnection::new(
        client_config,
        rustls::pki_types::ServerName::try_from("example.test").unwrap(),
    )
    .unwrap();
    let mut server = Harness::new(Seed::from_u64(12), tls::TlsLayer::new(config.clone()));
    let hello = client_output(&mut client);
    let split = split.min(hello.len());
    server.push(&hello[..split]).unwrap();
    server.push(&hello[split..]).unwrap();
    assert_eq!(
        server.layer().hello().unwrap().server_name(),
        Some("example.test")
    );
    assert_eq!(
        server.layer().hello().unwrap().alpn(),
        vec![&b"http/1.1"[..]]
    );
    assert!(server.take_output().is_empty());
    let selection = server.work().unwrap();
    assert_eq!(selection.hello().server_name(), Some("example.test"));
    assert_eq!(selection.hello().alpn(), vec![&b"http/1.1"[..]]);
    assert!(server.work().is_none());
    server.complete(Some(config)).unwrap();
    for _ in 0..32 {
        receive(&mut client, &server.take_output());
        server.push(&client_output(&mut client)).unwrap();
        if !client.is_handshaking() && !server.layer().is_handshaking() {
            receive(&mut client, &server.take_output());
            assert_eq!(server.layer().alpn(), Some(&b"http/1.1"[..]));
            return (server, client);
        }
    }
    panic!("handshake did not settle");
}

fn events(server: &mut Server) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    server.driver().send_above(|event| {
        events.push(event);
        Admit::Taken
    });
    events
}

#[test]
fn client_hello_at_every_split_and_records_in_seeded_chunks() {
    block_on(lab(Seed::from_u64(12), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let mut client_config = (*client_config(&fcx, &ca, &[b"http/1.1"])).clone();
        client_config.resumption = rustls::client::Resumption::disabled();
        let client_config = Arc::new(client_config);
        let mut probe = rustls::ClientConnection::new(
            client_config.clone(),
            rustls::pki_types::ServerName::try_from("example.test").unwrap(),
        )?;
        let hello_len = client_output(&mut probe).len();
        let rng = fictionet::SeededEntropy::new(Seed::from_u64(13));
        use fictionet::Entropy;
        for split in 0..=hello_len {
            let (mut server, mut client) = handshake(config.clone(), client_config.clone(), split);
            let message = format!("application bytes after a hello split at {split}");
            client.writer().write_all(message.as_bytes())?;
            let wire = client_output(&mut client);
            let mut at = 0;
            let mut plaintext = Vec::new();
            while at < wire.len() {
                let end = (at + 1 + rng.random_below(31) as usize).min(wire.len());
                server.push(&wire[at..end])?;
                for event in events(&mut server) {
                    if let StreamEvent::Data(chunk) = event {
                        plaintext.extend_from_slice(&chunk);
                    }
                }
                at = end;
            }
            assert_eq!(plaintext, message.as_bytes());
        }
        Ok(())
    }))
    .unwrap();
}

#[test]
fn ciphertext_completion_is_not_admission_and_close_follows_data() {
    block_on(lab(Seed::from_u64(14), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let (mut server, mut client) = handshake(config, client_config, 1);
        server.withhold();
        assert!(matches!(
            server
                .driver()
                .command(StreamCommand::Write(Chunk::new(b"payload".to_vec())))?,
            Admit::Taken
        ));
        server.push(&[])?;
        assert!(events(&mut server).is_empty());
        assert!(server.output().is_empty());
        let mut credited = 0;
        let mut plaintext = Vec::new();
        for _ in 0..256 {
            server.allow(1)?;
            receive(&mut client, &server.take_output());
            let result = client.reader().read_to_end(&mut plaintext);
            assert_eq!(result.unwrap_err().kind(), ErrorKind::WouldBlock);
            for event in events(&mut server) {
                if let StreamEvent::Written(n) = event {
                    credited += n;
                }
            }
            if credited > 0 {
                assert_eq!(credited, 7);
                assert_eq!(plaintext, b"payload");
                break;
            }
            assert!(plaintext.is_empty());
        }
        assert_eq!(credited, 7);
        assert!(matches!(
            server.driver().command(StreamCommand::End)?,
            Admit::Taken
        ));
        server.allow_all()?;
        receive(&mut client, &server.take_output());
        assert!(server.ended());
        assert_eq!(client.reader().read(&mut [0; 1])?, 0);
        assert!(
            events(&mut server)
                .iter()
                .all(|e| !matches!(e, StreamEvent::Written(_)))
        );
        client.send_close_notify();
        server.push(&client_output(&mut client))?;
        assert!(
            events(&mut server)
                .iter()
                .any(|e| matches!(e, StreamEvent::Ended))
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn no_budget_refuses_input_without_consuming_it() {
    let budget = Budget::new(0);
    let mut server = Harness::with_budget(Seed::from_u64(15), refusing(), budget.clone());
    let bytes = vec![22, 3, 3, 0, 4, 1, 0, 0, 0];
    let result = server
        .driver()
        .deliver(StreamEvent::Data(Chunk::new(bytes.clone())))
        .unwrap();
    match result {
        Admit::Blocked(StreamEvent::Data(chunk)) => assert_eq!(&*chunk, bytes),
        other => panic!("expected retained input, got {other:?}"),
    }
    assert_eq!(budget.used(), 0);
    assert!(server.layer().hello().is_none());
}

#[test]
fn transport_eof_waits_for_buffered_plaintext() {
    block_on(lab(Seed::from_u64(16), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let (mut server, mut client) = handshake(config, client_config, 0);
        let message = vec![42; 16 * 1024 + 32];
        client.writer().write_all(&message)?;
        let mut event = StreamEvent::Data(Chunk::new(client_output(&mut client)));
        loop {
            match server.driver().deliver(event)? {
                Admit::Taken => break,
                Admit::Partial(rest) => event = rest,
                other => panic!("ciphertext unexpectedly refused: {other:?}"),
            }
        }
        // End input before letting the layer hand plaintext to the application.
        let mut eof = Some(StreamEvent::Ended);
        let mut plaintext = Vec::new();
        let mut ends = 0;
        for _ in 0..32 {
            if let Some(event) = eof.take() {
                match server.driver().deliver(event)? {
                    Admit::Taken => {}
                    Admit::Blocked(event) => eof = Some(event),
                    other => panic!("EOF unexpectedly refused: {other:?}"),
                }
            }
            server.driver().run()?;
            for event in events(&mut server) {
                match event {
                    StreamEvent::Data(bytes) => plaintext.extend_from_slice(&bytes),
                    StreamEvent::Ended => ends += 1,
                    other => panic!("unexpected event: {other:?}"),
                }
            }
            if ends != 0 {
                break;
            }
        }
        assert_eq!(plaintext, message);
        assert_eq!(ends, 1);
        assert!(eof.is_none());
        assert!(matches!(
            server
                .driver()
                .deliver(StreamEvent::Data(Chunk::new(vec![1])))?,
            Admit::Closed(_)
        ));
        Ok(())
    }))
    .unwrap();
}

#[test]
fn reset_aborts_a_queued_close_and_cancels_hello_work() {
    block_on(lab(Seed::from_u64(17), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let (mut server, _) = handshake(config, client_config.clone(), 0);
        assert!(matches!(
            server.driver().command(StreamCommand::End)?,
            Admit::Taken
        ));
        assert!(matches!(
            server.driver().command(StreamCommand::Reset)?,
            Admit::Taken
        ));
        server.push(&[])?;
        assert!(server.was_reset());
        assert!(server.output().is_empty());
        let mut client = rustls::ClientConnection::new(
            client_config,
            rustls::pki_types::ServerName::try_from("example.test").unwrap(),
        )?;
        let mut server = Harness::new(Seed::from_u64(18), refusing());
        server.push(&client_output(&mut client))?;
        assert!(server.layer().hello().is_some());
        assert!(matches!(
            server.driver().deliver(StreamEvent::Reset)?,
            Admit::Taken
        ));
        assert!(server.work().is_none());
        assert!(server.layer().hello().is_none());
        Ok(())
    }))
    .unwrap();
}

#[test]
fn ciphertext_keeps_its_charge_after_leaving_the_layer() {
    block_on(lab(Seed::from_u64(19), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let (mut server, mut client) = handshake(config, client_config, 0);
        let budget = server.driver().budget().clone();
        assert!(matches!(
            server
                .driver()
                .command(StreamCommand::Write(Chunk::new(b"owned output".to_vec())))?,
            Admit::Taken
        ));
        server.driver().run()?;
        let mut ciphertext = None;
        server.driver().send_below(|command| {
            let StreamCommand::Write(bytes) = command else {
                panic!("expected ciphertext")
            };
            assert!(ciphertext.replace(bytes).is_none());
            Admit::Taken
        });
        let ciphertext = ciphertext.unwrap();
        assert!(
            events(&mut server).is_empty(),
            "admission cannot complete a write"
        );
        drop(server);
        assert_eq!(budget.used(), ciphertext.charged());
        assert!(budget.used() >= ciphertext.len());
        receive(&mut client, &ciphertext);
        let mut message = [0; 12];
        client.reader().read_exact(&mut message)?;
        assert_eq!(&message, b"owned output");
        drop(ciphertext);
        assert_eq!(budget.used(), 0);
        Ok(())
    }))
    .unwrap();
}

#[test]
fn rejection_drains_its_alert_before_reporting_failure() {
    block_on(lab(Seed::from_u64(20), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let mut client = rustls::ClientConnection::new(
            client_config(&fcx, &ca, &[]),
            rustls::pki_types::ServerName::try_from("unknown.test").unwrap(),
        )?;
        let mut server = Harness::new(Seed::from_u64(21), refusing());
        server.withhold();
        server.push(&client_output(&mut client))?;
        assert_eq!(
            server.work().unwrap().hello().server_name(),
            Some("unknown.test")
        );
        server.complete(None)?;
        assert!(server.output().is_empty());
        assert!(matches!(
            server.allow_all(),
            Err(tls::HandshakeError::Rejected)
        ));
        client.read_tls(&mut &server.take_output()[..])?;
        assert!(matches!(
            client.process_new_packets(),
            Err(rustls::Error::AlertReceived(
                AlertDescription::UnrecognisedName
            ))
        ));
        Ok(())
    }))
    .unwrap();
}
