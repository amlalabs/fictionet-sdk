use super::*;
use fictionet::stdlib::layer::{Admit, Budget, Chunk, Harness, StreamCommand, StreamEvent};
use fictionet::stdlib::services::tls::{Handshake, Negotiation};
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
    handshake_charging(config, client_config, split, Budget::unlimited())
}

/// A handshake whose server charges `budget`.
fn handshake_charging(
    config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    split: usize,
    budget: Budget,
) -> (Server, rustls::ClientConnection) {
    let mut client = rustls::ClientConnection::new(
        client_config,
        rustls::pki_types::ServerName::try_from("example.test").unwrap(),
    )
    .unwrap();
    let mut server = Harness::with_budget(
        Seed::from_u64(12),
        tls::TlsLayer::new(config.clone()),
        budget,
    );
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

/// An echo through the layer, a record in and its plaintext written back,
/// allocates at most the one buffer its reply is sealed in and the chunk
/// around it: the record arriving is decrypted in the chunk that brought it
/// and its plaintext goes up as a slice of it, with no allocation at all.
/// Counted over many rounds as an inequality, so fewer passes.
#[test]
fn an_echoed_record_allocates_only_its_sealed_reply() {
    use crate::common::alloc::allocations;
    const ROUNDS: usize = 64;
    /// The sealed reply's bytes and the shared header of the chunk around
    /// them.
    const PER_ROUND: usize = 2;
    block_on(lab(Seed::from_u64(15), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let budget = Budget::new(1 << 20);
        let (mut server, mut client) = handshake_charging(config, client_config, 1, budget.clone());
        let mut made = 0;
        for round in 0..ROUNDS {
            let message = vec![round as u8; 100 + round * 37];
            client.writer().write_all(&message)?;
            let record = Chunk::copy_of(&budget, &client_output(&mut client)).unwrap();
            let mut sent = Vec::new();
            let ((), count) = allocations(|| {
                assert!(matches!(
                    server.driver().deliver(StreamEvent::Data(record)),
                    Ok(Admit::Taken)
                ));
                server.driver().run().unwrap();
                let mut up = None;
                server.driver().send_above(|event| {
                    if let StreamEvent::Data(chunk) = event {
                        up = Some(chunk);
                    }
                    Admit::Taken
                });
                let up = up.expect("the record's plaintext went up");
                assert!(matches!(
                    server.driver().command(StreamCommand::Write(up)),
                    Ok(Admit::Taken)
                ));
                server.driver().run().unwrap();
                let mut written = 0;
                server.driver().send_below(|command| {
                    if let StreamCommand::Write(bytes) = command {
                        written += bytes.len() as u64;
                        crate::common::alloc::unmeasured(|| sent.extend_from_slice(&bytes));
                    }
                    Admit::Taken
                });
                assert!(matches!(
                    server.driver().deliver(StreamEvent::Written(written)),
                    Ok(Admit::Taken)
                ));
                server.driver().run().unwrap();
                server.driver().send_above(|_| Admit::Taken);
            });
            made += count;
            receive(&mut client, &sent);
            let mut echoed = vec![0; message.len()];
            client.reader().read_exact(&mut echoed)?;
            assert_eq!(echoed, message);
        }
        eprintln!("{made} allocations for {ROUNDS} echoed records");
        assert!(
            made <= ROUNDS * PER_ROUND,
            "{made} allocations for {ROUNDS} echoed records"
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn small_ciphertext_does_not_allocate_a_maximum_record() {
    block_on(lab(Seed::from_u64(14), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let (mut server, mut client) = handshake(config, client_config, 1);
        let plaintext = vec![b'p'; 1024];
        let command = StreamCommand::Write(Chunk::unpaid(plaintext.clone()));
        let (_, stats) = crate::common::alloc::measuring(|| {
            assert!(matches!(
                server.driver().command(command).unwrap(),
                Admit::Taken
            ));
            server.driver().run().unwrap();
        });
        assert!(stats.largest_request <= 2 * plaintext.len(), "{stats:?}");
        server.settle()?;
        receive(&mut client, &server.take_output());
        let mut received = vec![0; plaintext.len()];
        client.reader().read_exact(&mut received)?;
        assert_eq!(received, plaintext);
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
                .command(StreamCommand::Write(Chunk::unpaid(b"payload".to_vec())))?,
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
        assert!(client.send_close_notify());
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
        .deliver(StreamEvent::Data(Chunk::unpaid(bytes.clone())))
        .unwrap();
    match result {
        Admit::Blocked(StreamEvent::Data(chunk)) => assert_eq!(&*chunk, bytes),
        other => panic!("expected retained input, got {other:?}"),
    }
    assert_eq!(budget.used(), 0);
    assert!(server.layer().hello().is_none());
}

/// Takes all the room `budget` has left, as other connections on it would.
fn fill(budget: &Budget) -> fictionet::stdlib::layer::Charge {
    budget.charge(budget.limit() - budget.used()).unwrap()
}

/// A whole hello the budget has no room to parse waits, parsed by nothing
/// and holding nothing unpaid, and is taken when memory frees.
#[test]
fn a_hello_without_room_to_parse_waits_for_memory_and_then_goes() {
    block_on(lab(Seed::from_u64(22), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let mut client = rustls::ClientConnection::new(
            client_config,
            rustls::pki_types::ServerName::try_from("example.test").unwrap(),
        )?;
        let budget = Budget::new(256 << 10);
        let mut server = Harness::with_budget(
            Seed::from_u64(22),
            tls::TlsLayer::new(config.clone()),
            budget.clone(),
        );
        let hello = client_output(&mut client);
        let (last, first) = hello.split_last().unwrap();
        server.push(first)?;
        assert!(server.work().is_none());

        // The last byte needs no more buffer, only the room to parse.
        let others = fill(&budget);
        let refusals = server.driver().refusals();
        let ((), held) = crate::common::alloc::left_allocated(|| {
            server.push(&[*last]).unwrap();
        });
        assert!(server.work().is_none(), "a hello was parsed unpaid");
        assert!(server.layer().hello().is_none());
        assert!(server.layer().failure().is_none());
        // What rustls keeps of the waiting message is where it lies in the
        // read buffer, paid for: its spans, at most four of a version, an
        // optional size and a range (48 bytes at most each), and nothing
        // parsed.
        const SPANS: i128 = 4 * 48;
        assert!(
            held <= SPANS,
            "the step kept {held} bytes the budget had no room for"
        );
        assert!(server.driver().budget().refused_since(refusals));

        drop(others);
        server.settle()?;
        assert!(server.work().is_some(), "the hello was not taken");
        server.complete(Some(config))?;
        for _ in 0..32 {
            receive(&mut client, &server.take_output());
            server.push(&client_output(&mut client))?;
            if !client.is_handshaking() && !server.layer().is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.layer().is_handshaking());
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_flight_without_room_waits_for_memory_and_then_goes() {
    block_on(lab(Seed::from_u64(21), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let mut client = rustls::ClientConnection::new(
            client_config,
            rustls::pki_types::ServerName::try_from("example.test").unwrap(),
        )?;
        let budget = Budget::new(256 << 10);
        let mut server = Harness::with_budget(
            Seed::from_u64(21),
            tls::TlsLayer::new(config.clone()),
            budget.clone(),
        );
        server.push(&client_output(&mut client))?;
        assert!(server.work().is_some());

        let others = fill(&budget);
        let refusals = server.driver().refusals();
        let (completed, held) =
            crate::common::alloc::left_allocated(|| server.complete(Some(config)));
        completed?;
        // Nothing of the connection or its flight is kept unpaid: what the
        // step leaves allocated is only the config it keeps to try again.
        assert!(
            held <= 0,
            "the step kept {held} bytes the budget had no room for"
        );
        assert!(server.take_output().is_empty(), "a flight went out unpaid");
        assert!(server.layer().is_handshaking());
        assert!(server.layer().failure().is_none());
        // The refusal is counted, so the runner asks to be woken when
        // memory frees.
        assert!(server.driver().budget().refused_since(refusals));

        drop(others);
        server.settle()?;
        for _ in 0..32 {
            receive(&mut client, &server.take_output());
            server.push(&client_output(&mut client))?;
            if !client.is_handshaking() && !server.layer().is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.layer().is_handshaking());
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_record_without_room_waits_and_its_plaintext_comes_when_memory_frees() {
    block_on(lab(Seed::from_u64(22), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let budget = Budget::new(256 << 10);
        let (mut server, mut client) = handshake_charging(config, client_config, 0, budget.clone());
        let message = vec![b'r'; 10 << 10];
        client.writer().write_all(&message)?;
        let wire = client_output(&mut client);

        let others = fill(&budget);
        server.push(&wire)?;
        assert!(events(&mut server).is_empty(), "plaintext came unpaid");
        assert!(
            server.unread() > 0,
            "the record was read without room for it"
        );
        assert!(server.layer().failure().is_none());

        drop(others);
        server.settle()?;
        let mut plaintext = Vec::new();
        for _ in 0..8 {
            for event in events(&mut server) {
                if let StreamEvent::Data(chunk) = event {
                    plaintext.extend_from_slice(&chunk);
                }
            }
            server.settle()?;
        }
        assert_eq!(server.unread(), 0);
        assert!(plaintext == message, "the record waited intact");
        Ok(())
    }))
    .unwrap();
}

/// A write without room for its record waits, and goes once memory frees.
/// The end after it goes even with the budget full: its close_notify is
/// paid from the room kept since the first byte.
#[test]
fn a_write_without_room_waits_and_an_end_goes_with_the_budget_full() {
    block_on(lab(Seed::from_u64(23), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let budget = Budget::new(256 << 10);
        let (mut server, mut client) = handshake_charging(config, client_config, 0, budget.clone());

        let others = fill(&budget);
        let write = StreamCommand::Write(Chunk::unpaid(b"reply".to_vec()));
        let Admit::Blocked(write) = server.driver().command(write)? else {
            panic!("a write was taken without room for its record");
        };
        server.settle()?;
        assert!(server.take_output().is_empty());

        drop(others);
        assert!(matches!(server.driver().command(write)?, Admit::Taken));
        server.settle()?;
        receive(&mut client, &server.take_output());
        let _others = fill(&budget);
        assert!(matches!(
            server.driver().command(StreamCommand::End)?,
            Admit::Taken
        ));
        server.settle()?;
        receive(&mut client, &server.take_output());
        let mut reply = Vec::new();
        assert_eq!(client.reader().read_to_end(&mut reply)?, 5);
        assert_eq!(reply, b"reply");
        Ok(())
    }))
    .unwrap();
}

#[test]
fn ciphertext_batches_and_completions_survive_key_updates_and_record_splits() {
    // The most one record takes on the wire, in TLS 1.2 (RFC 5246 section
    // 6.2.3): the layer's output holds one, or several smaller ones.
    const RECORD: usize = 5 + (1 << 14) + 2048;
    block_on(lab(Seed::from_u64(43), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        for (fragment, size) in [(None, 128), (None, 16 * 1024), (Some(1024), 4096)] {
            let mut config = (*server_config(&fcx, &ca, "example.test", &[b"http/1.1"])).clone();
            config.max_fragment_size = fragment;
            let (mut server, mut client) = handshake(
                Arc::new(config),
                client_config(&fcx, &ca, &[b"http/1.1"]),
                0,
            );
            events(&mut server);
            client.refresh_traffic_keys()?;
            server.push(&client_output(&mut client))?;
            receive(&mut client, &server.take_output());
            let payload: Vec<_> = (0..size).map(|i| i as u8).collect();
            assert!(matches!(
                server
                    .driver()
                    .command(StreamCommand::Write(Chunk::unpaid(payload.clone())))?,
                Admit::Taken
            ));
            let mut chunks = Vec::new();
            loop {
                server.driver().run()?;
                let Some(command) = server.driver().take_command() else {
                    break;
                };
                let StreamCommand::Write(chunk) = command else {
                    panic!("expected ciphertext")
                };
                assert!(chunk.len() <= RECORD);
                chunks.push(chunk);
            }
            let ciphertext_len: usize = chunks.iter().map(Chunk::len).sum();
            assert_eq!(chunks.len(), ciphertext_len.div_ceil(RECORD));
            assert!(events(&mut server).is_empty());
            for chunk in &chunks {
                receive(&mut client, chunk);
            }
            let mut decrypted = vec![0; size];
            client.reader().read_exact(&mut decrypted)?;
            assert_eq!(decrypted, payload);
            assert!(matches!(
                server
                    .driver()
                    .deliver(StreamEvent::Written(ciphertext_len as u64 - 1))?,
                Admit::Taken
            ));
            assert!(events(&mut server).is_empty());
            assert!(matches!(
                server.driver().deliver(StreamEvent::Written(1))?,
                Admit::Taken
            ));
            assert!(matches!(
                events(&mut server).as_slice(),
                [StreamEvent::Written(n)] if *n == size as u64
            ));
            assert!(matches!(
                server.driver().command(StreamCommand::End)?,
                Admit::Taken
            ));
            server.push(&[])?;
            receive(&mut client, &server.take_output());
            assert_eq!(client.reader().read(&mut [0])?, 0);
            assert!(server.ended());
        }
        Ok(())
    }))
    .unwrap();
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
        // The two records, then the end of input, each delivered as soon as
        // the layer takes it: the layer takes a record only once the one
        // before has gone up, and the end arrives while the last record's
        // plaintext is still buffered, before the application has it.
        let mut input = std::collections::VecDeque::from([
            StreamEvent::Data(Chunk::unpaid(client_output(&mut client))),
            StreamEvent::Ended,
        ]);
        let mut plaintext = Vec::new();
        let mut ends = 0;
        for _ in 0..32 {
            while let Some(event) = input.pop_front() {
                match server.driver().deliver(event)? {
                    Admit::Taken => {}
                    Admit::Partial(rest) => input.push_front(rest),
                    Admit::Blocked(rest) => {
                        input.push_front(rest);
                        break;
                    }
                    other => panic!("input unexpectedly refused: {other:?}"),
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
        assert!(input.is_empty());
        assert!(matches!(
            server
                .driver()
                .deliver(StreamEvent::Data(Chunk::unpaid(vec![1])))?,
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
        assert_eq!(server.layer().handshake(), Handshake::Failed);
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
            server.driver().command(StreamCommand::Write(Chunk::unpaid(
                b"owned output".to_vec()
            )))?,
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
        assert_eq!(server.layer().handshake(), Handshake::Failed);
        assert!(server.layer().failure().is_none());
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

#[test]
fn a_bad_record_after_close_notify_writes_nothing_after_the_end() {
    block_on(lab(Seed::from_u64(22), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let (mut server, mut client) = handshake(config, client_config, 0);
        assert!(matches!(
            server.driver().command(StreamCommand::End)?,
            Admit::Taken
        ));
        server.push(&[])?;
        assert!(server.ended());
        receive(&mut client, &server.take_output());
        // The client may still send after the server's close_notify.
        client.writer().write_all(b"still talking")?;
        let mut record = client_output(&mut client);
        let last = record.len() - 1;
        record[last] ^= 1;
        let mut event = StreamEvent::Data(Chunk::unpaid(record));
        let mut after_end = Vec::new();
        for _ in 0..8 {
            if let Admit::Partial(rest) | Admit::Blocked(rest) = server.driver().deliver(event)? {
                event = rest;
            } else {
                event = StreamEvent::Data(Chunk::unpaid(Vec::new()));
            }
            let _ = server.driver().run();
            server.driver().send_below(|command| {
                after_end.push(format!("{command:?}"));
                Admit::Taken
            });
        }
        assert!(after_end.is_empty(), "commands after End: {after_end:?}");
        Ok(())
    }))
    .unwrap();
}

#[test]
fn hello_work_finished_after_the_client_left_sends_nothing() {
    block_on(lab(Seed::from_u64(23), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        for answer in [Some(config.clone()), None] {
            let mut client = rustls::ClientConnection::new(
                client_config(&fcx, &ca, &[b"http/1.1"]),
                rustls::pki_types::ServerName::try_from("example.test").unwrap(),
            )?;
            let mut server = Harness::new(Seed::from_u64(24), tls::TlsLayer::new(config.clone()));
            server.push(&client_output(&mut client))?;
            assert!(server.work().is_some());
            // The client closes while the world is still choosing a config.
            assert!(matches!(
                server.driver().deliver(StreamEvent::Ended)?,
                Admit::Taken
            ));
            let mut commands = Vec::new();
            let mut drive = |server: &mut Server| {
                for _ in 0..4 {
                    let _ = server.driver().run();
                    server.driver().send_below(|command| {
                        commands.push(format!("{command:?}"));
                        Admit::Taken
                    });
                }
            };
            drive(&mut server);
            server.driver().complete(answer)?;
            drive(&mut server);
            assert_eq!(commands, ["End"], "after the client left");
        }
        Ok(())
    }))
    .unwrap();
}
