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
use crate::server::{Acceptor, IntoConnectionError, ServerConnection};
use crate::sync::Arc;
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
fn to_server(server: &mut ServerConnection, wire: &[u8], piece: usize) {
    for mut rest in wire.chunks(piece) {
        while !rest.is_empty() {
            assert!(server.read_tls(&mut rest).unwrap() > 0);
            assert!(server.buffers_accounted());
            server.process_new_packets().unwrap();
            assert!(server.buffers_accounted());
        }
    }
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

fn handshake(server: &mut ServerConnection, client: &mut ClientConnection) {
    while client.is_handshaking() || server.is_handshaking() || server.wants_write() {
        let wire = from_client(client);
        to_server(server, &wire, 1000);
        to_client(server, client);
    }
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
        handshake(&mut server, &mut client);
        assert!(
            limit.used() > 0,
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
                // The plaintext leaves with its charge: the budget's total
                // does not move until it is dropped, and then gives back
                // exactly its allocation.
                let charge = charge.unwrap();
                assert_eq!(charge.bytes(), plaintext.capacity());
                assert_eq!(limit.used(), before);
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

#[test]
fn a_record_without_room_for_its_plaintext_waits_in_the_buffer() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let mut client = client(version);
        handshake(&mut server, &mut client);

        let message = vec![7; 1000];
        client.writer().write_all(&message).unwrap();
        let wire = from_client(&mut client);
        let mut rest = &wire[..];
        while !rest.is_empty() {
            server.read_tls(&mut rest).unwrap();
        }
        // Room for the answers a record can make, not for its plaintext.
        limit.set_limit(limit.used() + 500);
        let used = limit.used();
        server.process_new_packets().unwrap();
        assert!(server.wants_budget(), "{version:?}");
        assert!(limit.used() <= used + 500);
        assert!(server.buffers_accounted());
        assert_eq!(
            server.reader().into_first_chunk().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        limit.set_limit(1 << 20);
        server.process_new_packets().unwrap();
        assert!(!server.wants_budget(), "{version:?}");
        assert!(server.buffers_accounted());
        let mut plaintext = Vec::new();
        server.reader().read_to_end(&mut plaintext).unwrap_err();
        assert!(
            plaintext == message,
            "{version:?}: the record waited intact"
        );
    }
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
