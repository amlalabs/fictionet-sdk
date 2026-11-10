//! The layer on rustls's unbuffered API: records decrypted where they
//! arrive and handed up as slices of the chunk they came in, records that
//! arrive in pieces joined first, writes sealed into one buffer each, and
//! the final alert sent with the budget full.

use std::io::{Read, Write};
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use fictionet::stdlib::layer::{Budget, Harness};
use fictionet::stdlib::protocols::x509;
use fictionet::stdlib::services::ca::Ca;
use fictionet::{Seed, SeededEntropy};

/// What the client sends, written out.
fn from_client(client: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    bytes
}

/// Gives the client `bytes` and returns the plaintext it read.
fn to_client(client: &mut rustls::ClientConnection, bytes: &[u8]) -> Vec<u8> {
    let mut plain = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        client.read_tls(&mut rest).unwrap();
        client.process_new_packets().unwrap();
        if let Err(error) = client.reader().read_to_end(&mut plain) {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
    }
    plain
}

/// The plaintext the layer handed up, chunk by chunk.
fn taken_up(h: &mut Harness<TlsLayer>) -> Vec<Chunk> {
    let mut up = Vec::new();
    h.driver().send_above(|event| {
        if let StreamEvent::Data(chunk) = event {
            up.push(chunk);
        }
        Admit::Taken
    });
    up
}

/// Takes the plaintext the layer hands up into `got`, letting the bytes
/// that wait for it in, until it hands up no more.
fn drain(h: &mut Harness<TlsLayer>, got: &mut Vec<u8>) {
    loop {
        let up = taken_up(h);
        if up.is_empty() {
            return;
        }
        for chunk in up {
            got.extend_from_slice(&chunk);
        }
        h.settle().unwrap();
    }
}

/// A layer and a client that finished their handshake, in `version`, on
/// `budget`.
fn connected(
    cx: &Cx,
    version: &'static rustls::SupportedProtocolVersion,
    budget: &Budget,
) -> (rustls::ClientConnection, Harness<TlsLayer>) {
    let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let ca = Ca::new(cx, "Layer CA").unwrap();
    let validity = x509::Validity {
        not_before: x509::Time::from_unix(1_700_000_000).unwrap(),
        not_after: x509::Time::from_unix(2_000_000_000).unwrap(),
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    let config = ca
        .issue(cx, &["layer.example"], validity)
        .unwrap()
        .server_config(cx, start, &Budget::unlimited())
        .unwrap();
    let client_config = Arc::new(
        super::super::client_config_builder(cx, start)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let mut client =
        rustls::ClientConnection::new(client_config, "layer.example".try_into().unwrap()).unwrap();
    let mut h = Harness::with_budget(
        Seed::from_u64(7),
        TlsLayer::new(config.clone()),
        budget.clone(),
    );
    h.push(&from_client(&mut client)).unwrap();
    drop(h.work());
    h.complete(Some(config)).unwrap();
    for _ in 0..8 {
        let out = h.take_output();
        assert!(to_client(&mut client, &out).is_empty());
        h.push(&from_client(&mut client)).unwrap();
        if !client.is_handshaking() && !h.layer().is_handshaking() && !h.layer().output_pending() {
            assert!(taken_up(&mut h).is_empty());
            // What the server sent last, such as TLS 1.3's tickets.
            let out = h.take_output();
            assert!(to_client(&mut client, &out).is_empty());
            let layer = h.layer();
            assert!(
                layer.input.is_none() && !layer.pending,
                "{version:?}: {:?} bytes held after the handshake, {:?} of them joined",
                layer.input.as_ref().map(|input| input.len()),
                layer.tls.as_ref().map(|tls| tls.joined()),
            );
            return (client, h);
        }
    }
    panic!("the handshake did not finish");
}

fn lab_test(seed: u64, test: impl FnOnce(Cx) + Send + 'static) {
    fictionet::block_on(fictionet::lab(Seed::from_u64(seed), |cx| async move {
        test(cx);
        Ok(())
    }))
    .unwrap();
}

/// Records whole in one chunk are decrypted where they lie and go up as
/// one chunk whose bytes lie within the chunk that brought them: nothing
/// is copied out, and nothing is held once they have gone up.
#[test]
fn records_in_one_chunk_go_up_as_one_slice_of_it() {
    lab_test(1, |cx| {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let budget = Budget::new(1 << 20);
            let (mut client, mut h) = connected(&cx, version, &budget);
            let idle = budget.used();
            let messages: [&[u8]; 3] = [b"one", &[5; 4000], b"three"];
            for message in messages {
                client.writer().write_all(message).unwrap();
            }
            let wire = from_client(&mut client);
            let chunk = Chunk::copy_of(&budget, &wire).unwrap();
            let arrived = chunk.as_ptr_range();
            assert!(matches!(
                h.driver().deliver(StreamEvent::Data(chunk)),
                Ok(Admit::Taken)
            ));
            h.driver().run().unwrap();
            let up = taken_up(&mut h);
            assert_eq!(up.len(), 1, "{version:?}: one chunk for the records of one");
            assert!(up[0][..] == messages.concat(), "{version:?}");
            let at = up[0].as_ptr_range();
            assert!(
                arrived.start <= at.start && at.end <= arrived.end,
                "{version:?}: the plaintext was copied out of the chunk it came in"
            );
            drop(up);
            assert_eq!(
                budget.used(),
                idle,
                "{version:?}: input held after it went up"
            );
        }
    });
}

/// However the wire is cut into chunks, inside headers, inside records or
/// between them, the plaintext that goes up is what the client wrote, in
/// order, and once it has gone up the layer holds nothing more than it
/// did idle.
#[test]
fn records_cut_anywhere_are_joined_and_go_up_in_order() {
    lab_test(2, |cx| {
        let entropy = SeededEntropy::new(Seed::from_u64(3));
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let budget = Budget::new(1 << 20);
            let (mut client, mut h) = connected(&cx, version, &budget);
            // The rounds write more than the client buffers by default.
            client.set_buffer_limit(None);
            let idle = budget.used();
            for round in 0..24u8 {
                let mut sent = Vec::new();
                for record in 0..=round % 4 {
                    let len = 1 + (usize::from(round) * 997 + usize::from(record) * 131) % 20_000;
                    let message = vec![round ^ record; len];
                    client.writer().write_all(&message).unwrap();
                    sent.extend_from_slice(&message);
                }
                let wire = from_client(&mut client);
                let mut got = Vec::new();
                let mut rest = &wire[..];
                while !rest.is_empty() {
                    let mut cut = [0u8; 2];
                    fictionet::Entropy::fill_random(&entropy, &mut cut);
                    let most = [1, 3, 5, 6, 64, 1500, 20_000][usize::from(cut[0]) % 7];
                    let take = (1 + usize::from(u16::from_le_bytes(cut)) % most).min(rest.len());
                    h.push(&rest[..take]).unwrap();
                    rest = &rest[take..];
                    drain(&mut h, &mut got);
                }
                let differ = got.iter().zip(&sent).position(|(a, b)| a != b);
                assert!(
                    got == sent,
                    "{version:?}: round {round}: got {} of {} bytes, first difference at {differ:?}",
                    got.len(),
                    sent.len()
                );
                assert_eq!(h.unread(), 0);
                assert_eq!(
                    budget.used(),
                    idle,
                    "{version:?}: round {round} left input held"
                );
            }
        }
    });
}

/// A write goes down sealed in one buffer of exactly its record, which
/// carries its charge, and the client reads back what was written; one
/// larger than a record is taken a record at a time.
#[test]
fn a_write_is_sealed_into_one_buffer_of_its_record() {
    lab_test(3, |cx| {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let budget = Budget::new(1 << 20);
            let (mut client, mut h) = connected(&cx, version, &budget);
            let idle = budget.used();
            let message: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
            let mut write = Some(StreamCommand::Write(
                Chunk::copy_of(&budget, &message).unwrap(),
            ));
            let mut read = Vec::new();
            let mut records = 0;
            while let Some(command) = write.take() {
                match h.driver().command(command).unwrap() {
                    Admit::Taken => {}
                    Admit::Partial(rest) | Admit::Blocked(rest) => write = Some(rest),
                    Admit::Closed(_) => panic!("{version:?}: the write was refused"),
                }
                h.driver().run().unwrap();
                let mut sent = 0;
                h.driver().send_below(|command| {
                    let StreamCommand::Write(bytes) = command else {
                        panic!("{version:?}: expected ciphertext")
                    };
                    assert_eq!(bytes.len(), bytes.capacity(), "{version:?}: spare room");
                    assert!(bytes.charged() >= bytes.capacity(), "{version:?}");
                    records += 1;
                    sent += bytes.len() as u64;
                    read.extend(to_client(&mut client, &bytes));
                    Admit::Taken
                });
                // The carrier below completes what it took.
                if sent != 0 {
                    assert!(matches!(
                        h.driver().deliver(StreamEvent::Written(sent)),
                        Ok(Admit::Taken)
                    ));
                }
                h.settle().unwrap();
                taken_up(&mut h);
            }
            assert!(
                read == message,
                "{version:?}: the client read back otherwise"
            );
            assert!(records >= message.len() / PLAINTEXT, "{version:?}");
            assert_eq!(
                budget.used(),
                idle,
                "{version:?}: a write left a buffer held"
            );
        }
    });
}

/// A `close_notify` goes out with the budget full: the room kept since the
/// first byte pays for its buffer, and the client reads the end.
#[test]
fn a_close_notify_goes_out_with_the_budget_full() {
    lab_test(4, |cx| {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let budget = Budget::new(1 << 20);
            let (mut client, mut h) = connected(&cx, version, &budget);
            let _full = budget.charge(budget.limit() - budget.used()).unwrap();
            assert!(matches!(
                h.driver().command(StreamCommand::End),
                Ok(Admit::Taken)
            ));
            h.settle().unwrap();
            let out = h.take_output();
            assert!(!out.is_empty(), "{version:?}: no close_notify went out");
            assert!(to_client(&mut client, &out).is_empty());
            let mut rest = Vec::new();
            assert_eq!(
                client.reader().read_to_end(&mut rest).unwrap(),
                0,
                "{version:?}"
            );
            assert!(h.ended(), "{version:?}: the stream did not end");
        }
    });
}

/// A name the world refuses is answered with unrecognized_name with the
/// budget full: the room kept since the first byte pays for the alert's
/// buffer, and the layer reports the refusal once the alert is out.
#[test]
fn a_refusal_goes_out_with_the_budget_full() {
    lab_test(5, |cx| {
        let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let ca = Ca::new(&cx, "Refusal CA").unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der()).unwrap();
        let client_config = Arc::new(
            super::super::client_config_builder(&cx, start)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let mut client =
            rustls::ClientConnection::new(client_config, "nobody.example".try_into().unwrap())
                .unwrap();
        let budget = Budget::new(1 << 20);
        let layer = TlsLayer::selecting(|_, _| async { None });
        let mut h = Harness::with_budget(Seed::from_u64(8), layer, budget.clone());
        h.push(&from_client(&mut client)).unwrap();
        assert!(h.work().is_some());
        let _full = budget.charge(budget.limit() - budget.used()).unwrap();
        let failure = h.complete(None).unwrap_err();
        assert!(matches!(failure, HandshakeError::Rejected), "{failure:?}");
        let out = h.take_output();
        assert!(!out.is_empty(), "no alert went out");
        let mut rest = &out[..];
        client.read_tls(&mut rest).unwrap();
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            rustls::Error::AlertReceived(rustls::AlertDescription::UnrecognisedName)
        );
    });
}
