//! A server connection paid from a budget: every buffer charged what it
//! holds, and each refusal changing nothing until the budget has room.

use alloc::vec;
use alloc::vec::Vec;
use std::io::{self, Read, Write};

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::testing::Limit;
use crate::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::client::ClientConnection;
use crate::crypto::ring::default_provider;
use crate::enums::{AlertDescription, SignatureScheme};
use crate::msgs::message::MAX_WIRE_SIZE;
use crate::server::{Acceptor, IntoConnectionError, ServerConnection};
use crate::sync::Arc;
use crate::vecbuf::{FIRST_PLACES, PLACE};
use crate::version::{TLS12, TLS13};
use crate::{
    ClientConfig, CommonState, DigitallySignedStruct, Error, ServerConfig, Side,
    SupportedProtocolVersion,
};

fn server_config() -> Arc<ServerConfig> {
    let chain = vec![
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/end.der")[..]),
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/inter.der")[..]),
    ];
    let key =
        PrivateKeyDer::from_pem_reader(&mut &include_bytes!("../../test-ca/rsa-2048/end.key")[..])
            .unwrap();
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    )
}

/// The client trusts any server: these tests are about the server's
/// buffers, not its certificate.
#[derive(Debug)]
struct TrustAnything;

impl ServerCertVerifier for TrustAnything {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client(version: &'static SupportedProtocolVersion) -> ClientConnection {
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnything))
        .with_no_client_auth();
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("testserver.com").unwrap(),
    )
    .unwrap()
}

/// What `client` has to send.
fn from_client(client: &mut ClientConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    wire
}

/// Gives the server `wire` in pieces of `piece` bytes, processing after
/// each, and checks after each that its buffers are charged what they hold.
/// Returns the most they held after any step.
fn to_server(server: &mut ServerConnection, wire: &[u8], piece: usize) -> usize {
    let mut most = 0;
    for mut rest in wire.chunks(piece) {
        while !rest.is_empty() {
            assert!(server.read_tls(&mut rest).unwrap() > 0);
            assert!(server.buffers_accounted());
            most = most.max(server.buffers_held());
            server.process_new_packets().unwrap();
            assert!(server.buffers_accounted());
            most = most.max(server.buffers_held());
        }
    }
    most
}

/// Gives the client what the server has to send.
fn to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
        assert!(server.buffers_accounted());
    }
    let mut rest = &wire[..];
    while !rest.is_empty() {
        client.read_tls(&mut rest).unwrap();
        client.process_new_packets().unwrap();
    }
}

/// Runs the handshake, returning the most the server's buffers held after
/// any step of it.
fn handshake(server: &mut ServerConnection, client: &mut ClientConnection) -> usize {
    let mut most = 0;
    while client.is_handshaking() || server.is_handshaking() || server.wants_write() {
        let wire = from_client(client);
        most = most.max(to_server(server, &wire, 1000));
        to_client(server, client);
    }
    most
}

/// Everything the client has decrypted.
fn received(client: &mut ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Err(error) = client.reader().read_to_end(&mut bytes) {
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }
    bytes
}

#[test]
fn every_buffer_is_charged_what_it_holds_and_gives_it_back() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let mut client = client(version);
        assert!(
            handshake(&mut server, &mut client) > 0,
            "{version:?}: the handshake charged nothing"
        );

        for round in 0..12u8 {
            let message = vec![round; 3000 + 2000 * usize::from(round)];
            client.writer().write_all(&message).unwrap();
            let wire = from_client(&mut client);
            let mut echoed = Vec::new();
            let mut rest = &wire[..];
            loop {
                if !rest.is_empty() {
                    let mut piece = &rest[..rest.len().min(777)];
                    let read = server.read_tls(&mut piece).unwrap();
                    rest = &rest[read..];
                    assert!(server.buffers_accounted());
                    server.process_new_packets().unwrap();
                    assert!(server.buffers_accounted());
                    assert_eq!(limit.used(), server.buffers_held());
                }
                let before = limit.used();
                let (plaintext, charge) = match server.reader().take_first_chunk() {
                    Ok(paid) => paid.into_parts(),
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        (Vec::new(), None)
                    }
                };
                if plaintext.is_empty() {
                    if rest.is_empty() {
                        break;
                    }
                    continue;
                }
                // The plaintext leaves with its charge: the budget gets back
                // only the queue's places, and then exactly the plaintext's
                // allocation once it is dropped.
                let charge = charge.unwrap();
                assert_eq!(charge.bytes(), plaintext.capacity());
                assert!(limit.used() <= before);
                assert_eq!(limit.used(), server.buffers_held() + plaintext.capacity());
                let written = server.writer().write(&plaintext).unwrap();
                assert_eq!(written, plaintext.len());
                assert!(server.buffers_accounted());
                drop(charge);
                assert_eq!(limit.used(), server.buffers_held());
                echoed.extend_from_slice(&plaintext);
                to_client(&mut server, &mut client);
                assert_eq!(limit.used(), server.buffers_held());
            }
            assert!(echoed == message, "{version:?}: round {round} echoed");
            assert!(
                received(&mut client) == message,
                "{version:?}: round {round} received"
            );
        }

        assert!(server.send_close_notify());
        assert!(server.buffers_accounted());
        drop(server);
        assert_eq!(
            limit.used(),
            0,
            "{version:?}: charges outlived the connection"
        );
    }
}

#[test]
fn a_read_without_room_reads_nothing_until_there_is_room() {
    let limit = Limit::new(0);
    let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
    let mut client = client(&TLS13);
    let hello = from_client(&mut client);
    let mut rest = &hello[..];
    let error = server.read_tls(&mut rest).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(rest.len(), hello.len());
    assert_eq!(limit.used(), 0);

    limit.set_limit(1 << 20);
    to_server(&mut server, rest, 1000);
    assert!(server.wants_write());
    handshake(&mut server, &mut client);
    assert!(!server.is_handshaking());
}

/// A record's plaintext is decrypted where the record was read and stays
/// in that buffer: keeping it takes nothing past the record's own buffer
/// but a place in the plaintext queue. Without room for that place and the
/// answers a record can make, the record waits intact.
#[test]
fn a_records_plaintext_stays_in_the_buffer_it_arrived_in() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let mut client = client(version);
        handshake(&mut server, &mut client);

        let message = vec![7; 1000];
        client.writer().write_all(&message).unwrap();
        let wire = from_client(&mut client);
        let mut rest = &wire[..];
        assert_eq!(server.read_tls(&mut rest).unwrap(), wire.len());
        let read = limit.used();
        assert_eq!(read, wire.len(), "{version:?}: the buffer is the record");

        limit.set_limit(read);
        server.process_new_packets().unwrap();
        assert!(server.wants_budget(), "{version:?}");
        assert_eq!(limit.used(), read);
        assert!(server.buffers_accounted());
        assert_eq!(
            server.reader().into_first_chunk().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        limit.set_limit(1 << 20);
        server.process_new_packets().unwrap();
        assert!(!server.wants_budget(), "{version:?}");
        assert!(server.buffers_accounted());
        assert!(
            limit.used() <= read + FIRST_PLACES * PLACE,
            "{version:?}: keeping the plaintext took {} bytes past its record",
            limit.used() - read
        );
        let (plaintext, charge) = server.reader().take_first_chunk().unwrap().into_parts();
        assert!(
            plaintext == message,
            "{version:?}: the record waited intact"
        );
        // It leaves in the record's buffer, with the record's charge.
        assert_eq!(plaintext.capacity(), read, "{version:?}");
        assert_eq!(charge.unwrap().bytes(), read, "{version:?}");
        assert_eq!(server.buffers_held(), 0, "{version:?}");
    }
}

/// Once the handshake's flights are out, and again once an echo has gone
/// both ways, the connection holds no buffer at all: the receive buffer,
/// the queues and their places are freed, not just emptied.
#[test]
fn an_idle_connection_holds_no_buffer() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let mut client = client(version);
        let most = handshake(&mut server, &mut client);
        std::eprintln!(
            "{version:?}: the handshake's buffers held at most {most} bytes between \
             calls, {} within one",
            limit.most()
        );
        assert_eq!(
            (server.buffers_held(), limit.used()),
            (0, 0),
            "{version:?}: after the handshake"
        );

        let message = vec![3; 5000];
        client.writer().write_all(&message).unwrap();
        let wire = from_client(&mut client);
        to_server(&mut server, &wire, wire.len());
        let mut echoed = Vec::new();
        server.reader().read_to_end(&mut echoed).unwrap_err();
        assert!(echoed == message, "{version:?}");
        server.writer().write_all(&echoed).unwrap();
        to_client(&mut server, &mut client);
        assert!(received(&mut client) == message, "{version:?}");
        assert_eq!(
            (server.buffers_held(), limit.used()),
            (0, 0),
            "{version:?}: after an echo"
        );
    }
}

/// A full-size record from the peer, the most plaintext one record can
/// carry, arrives into one buffer of exactly its size and leaves in it,
/// however it is split on the way: the connection never holds more than
/// that record and its place in the plaintext queue.
#[test]
fn a_full_record_takes_one_buffer_of_its_size() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let mut client = client(version);
        handshake(&mut server, &mut client);

        let message = vec![9; 1 << 14];
        client.writer().write_all(&message).unwrap();
        let wire = from_client(&mut client);
        assert!(wire.len() > message.len() && wire.len() <= MAX_WIRE_SIZE);
        limit.reset_most();
        let most = to_server(&mut server, &wire, 1000);
        std::eprintln!(
            "{version:?}: a {}-byte record held at most {most} bytes of buffers between \
             calls, {} within one",
            wire.len(),
            limit.most()
        );
        assert!(
            most <= wire.len() + FIRST_PLACES * PLACE,
            "{version:?}: {most} bytes held for a {}-byte record",
            wire.len()
        );
        let (plaintext, _charge) = server.reader().take_first_chunk().unwrap().into_parts();
        assert!(plaintext == message, "{version:?}");
        assert_eq!(plaintext.capacity(), wire.len(), "{version:?}");
        assert_eq!(server.buffers_held(), 0, "{version:?}");
    }
}

/// A read takes no more than the record arriving: once a whole record is
/// buffered, the next read takes nothing until it has been processed.
#[test]
fn a_read_stops_at_the_end_of_the_record_arriving() {
    let limit = Limit::new(1 << 20);
    let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
    let mut client = client(&TLS13);
    handshake(&mut server, &mut client);

    client.writer().write_all(&[1; 100]).unwrap();
    let first = from_client(&mut client);
    client.writer().write_all(&[2; 200]).unwrap();
    let second = from_client(&mut client);
    let wire = [first.clone(), second.clone()].concat();
    let mut rest = &wire[..];
    assert_eq!(server.read_tls(&mut rest).unwrap(), first.len());
    assert_eq!(limit.used(), first.len());
    let error = server.read_tls(&mut rest).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(rest.len(), second.len());

    server.process_new_packets().unwrap();
    assert_eq!(server.read_tls(&mut rest).unwrap(), second.len());
    server.process_new_packets().unwrap();
    let mut plaintext = Vec::new();
    server.reader().read_to_end(&mut plaintext).unwrap_err();
    assert!(plaintext == [[1; 100].as_slice(), &[2; 200]].concat());
}

#[test]
fn a_write_takes_what_the_budget_pays_for() {
    let limit = Limit::new(1 << 20);
    let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
    let mut client = client(&TLS13);
    handshake(&mut server, &mut client);

    // Room for one full record and a little more, not two.
    limit.set_limit(limit.used() + (1 << 14) + 600);
    let message = vec![9; 3 << 14];
    let written = server.writer().write(&message).unwrap();
    assert!(written > 0 && written <= 1 << 14, "wrote {written}");
    assert!(server.buffers_accounted());
    assert_eq!(limit.used(), server.buffers_held());
    assert_eq!(server.writer().write(&message[written..]).unwrap(), 0);
    assert_eq!(limit.used(), server.buffers_held());

    // What goes out frees room for the rest.
    to_client(&mut server, &mut client);
    let more = server.writer().write(&message[written..]).unwrap();
    assert!(more > 0);
    to_client(&mut server, &mut client);
    assert!(received(&mut client) == message[..written + more]);
}

#[test]
fn a_flight_without_room_gives_the_hello_back_unchanged() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut acceptor = Acceptor::with_budget(limit.clone());
        let mut client = client(version);
        let hello = from_client(&mut client);
        let mut rest = &hello[..];
        let accepted = loop {
            acceptor.read_tls(&mut rest).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };
        limit.set_limit(limit.used());
        let used = limit.used();
        let accepted = match accepted.into_connection(server_config()) {
            Err(IntoConnectionError::Unpaid(accepted)) => *accepted,
            Ok(_) => panic!("{version:?}: the flight was sent without room"),
            Err(IntoConnectionError::Failed(error, _)) => panic!("{version:?}: {error}"),
        };
        assert_eq!(limit.used(), used, "{version:?}");

        limit.set_limit(1 << 20);
        let mut server = accepted.into_connection(server_config()).unwrap();
        assert!(server.buffers_accounted());
        to_client(&mut server, &mut client);
        handshake(&mut server, &mut client);
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(server.buffers_accounted());
    }
}

#[test]
fn a_close_notify_without_room_is_not_queued_until_there_is_room() {
    let limit = Limit::new(1 << 20);
    let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
    let mut client = client(&TLS13);
    handshake(&mut server, &mut client);
    limit.set_limit(limit.used());
    assert!(!server.send_close_notify());
    assert!(!server.wants_write());
    limit.set_limit(1 << 20);
    assert!(server.send_close_notify());
    assert!(server.wants_write());
    to_client(&mut server, &mut client);
    let mut bytes = Vec::new();
    assert_eq!(client.reader().read_to_end(&mut bytes).unwrap(), 0);
}

#[test]
fn output_with_neither_room_nor_budget_fails_rather_than_overruns() {
    let limit = Limit::new(1 << 10);
    let mut common = CommonState::new(Side::Server);
    common.pay_from(Some(limit.clone()));
    limit.set_limit(0);
    let error = common.send_fatal_alert(AlertDescription::InternalError, Error::DecryptError);
    assert_eq!(error, Error::DecryptError);
    assert_eq!(common.output_paid(), Err(Error::BudgetExhausted));
    assert!(!common.wants_write());
    assert_eq!(limit.used(), 0);

    // With room charged first, the same alert takes nothing more.
    let limit = Limit::new(1 << 10);
    let mut common = CommonState::new(Side::Server);
    common.pay_from(Some(limit.clone()));
    assert!(common.sendable_tls.reserve(64, 1));
    limit.set_limit(limit.used());
    common.send_fatal_alert(AlertDescription::InternalError, Error::DecryptError);
    assert_eq!(common.output_paid(), Ok(()));
    assert!(common.wants_write());
    assert!(common.sendable_tls.accounted());
}
