//! A server connection paid from a budget: every buffer charged what it
//! holds, and each refusal changing nothing until the budget has room.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{self, Read, Write};

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::testing::Limit;
use crate::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::client::ClientConnection;
use crate::crypto::ring::default_provider;
use crate::enums::{AlertDescription, ContentType, SignatureScheme};
use crate::msgs::enums::AlertLevel;
use crate::msgs::message::{HEADER_SIZE, MAX_WIRE_SIZE};
use crate::server::danger::{ClientCertVerified, ClientCertVerifier};
use crate::server::{Acceptor, IntoConnectionError, ServerConnection};
use crate::sync::Arc;
use crate::vecbuf::{ALERT_ROOM, FIRST_PLACES, PLACE};
use crate::version::{TLS12, TLS13};
use crate::DistinguishedName;
use crate::{
    ClientConfig, CommonState, DigitallySignedStruct, Error, ServerConfig, Side,
    SupportedProtocolVersion,
};

/// The test CA's RSA server chain and its key.
fn chain_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let chain = vec![
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/end.der")[..]),
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/inter.der")[..]),
    ];
    let key =
        PrivateKeyDer::from_pem_reader(&mut &include_bytes!("../../test-ca/rsa-2048/end.key")[..])
            .unwrap();
    (chain, key)
}

pub(crate) fn server_config() -> Arc<ServerConfig> {
    let (chain, key) = chain_and_key();
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
pub(crate) struct TrustAnything;

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

pub(crate) fn client(version: &'static SupportedProtocolVersion) -> ClientConnection {
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
pub(crate) fn from_client(client: &mut ClientConnection) -> Vec<u8> {
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
                let mut plaintext = Vec::new();
                if let Err(error) = server.reader().read_to_end(&mut plaintext) {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                }
                if plaintext.is_empty() {
                    if rest.is_empty() {
                        break;
                    }
                    continue;
                }
                // Reading gives the plaintext's buffer back.
                assert!(limit.used() <= before);
                assert_eq!(limit.used(), server.buffers_held());
                let written = server.writer().write(&plaintext).unwrap();
                assert_eq!(written, plaintext.len());
                assert!(server.buffers_accounted());
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
        let idle = limit.used();
        assert_eq!(server.read_tls(&mut rest).unwrap(), wire.len());
        let read = limit.used() - idle;
        assert_eq!(read, wire.len(), "{version:?}: the buffer is the record");

        limit.set_limit(idle + read);
        server.process_new_packets().unwrap();
        assert!(server.wants_budget(), "{version:?}");
        assert_eq!(limit.used(), idle + read);
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
            limit.used() <= idle + read + FIRST_PLACES * PLACE,
            "{version:?}: keeping the plaintext took {} bytes past its record",
            limit.used() - idle - read
        );
        let mut plaintext = Vec::new();
        server.reader().read_to_end(&mut plaintext).unwrap_err();
        assert!(
            plaintext == message,
            "{version:?}: the record waited intact"
        );
        assert_eq!(server.buffers_held(), ALERT_ROOM, "{version:?}");
    }
}

/// Once the handshake's flights are out, and again once an echo has gone
/// both ways, the connection holds no buffer: the receive buffer, the
/// queues and their places are freed, not just emptied. It is charged only
/// the room kept for its final alert.
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
            (ALERT_ROOM, ALERT_ROOM),
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
            (ALERT_ROOM, ALERT_ROOM),
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
        let mut plaintext = Vec::new();
        server.reader().read_to_end(&mut plaintext).unwrap_err();
        assert!(plaintext == message, "{version:?}");
        assert_eq!(server.buffers_held(), ALERT_ROOM, "{version:?}");
    }
}

/// A header no record may have (an unknown content type, a version that is
/// not 3.x, a length past the most a record carries) grows the buffer no
/// further than the header itself, however long it says the record is, and
/// the connection fails on it.
#[test]
fn a_junk_header_grows_no_buffer_past_itself() {
    use crate::msgs::message::HEADER_SIZE;
    let junk: [[u8; HEADER_SIZE]; 4] = [
        [0x99, 0x03, 0x03, 0x00, 0xff],
        [0x16, 0x7f, 0x00, 0x00, 0xff],
        [0x17, 0x03, 0x03, 0xff, 0xff],
        [0x16, 0x03, 0x03, 0x00, 0x00],
    ];
    for header in junk {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let wire = [&header[..], &[0x42; 300]].concat();
        let mut rest = &wire[..];
        // The room for the final alert, which the first read pays for:
        // what reading takes past it is the record buffer.
        assert!(server.keep_alert_room());
        let mut failed = false;
        let mut buffered = 0;
        for _ in 0..4 {
            // What reading takes: the record buffer and nothing else.
            let before = limit.used();
            limit.reset_most();
            match server.read_tls(&mut rest) {
                Ok(n) => buffered += n,
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{header:?}");
                    failed = true;
                }
            }
            assert!(
                limit.most() - before <= HEADER_SIZE,
                "{header:?}: the buffer grew by {} bytes",
                limit.most() - before
            );
            assert!(buffered <= HEADER_SIZE, "{header:?}: read {buffered} bytes");
            failed |= server.process_new_packets().is_err();
            assert!(server.buffers_accounted());
        }
        assert!(failed, "{header:?}: the connection went on");
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
    let idle = limit.used();
    assert_eq!(server.read_tls(&mut rest).unwrap(), first.len());
    assert_eq!(limit.used() - idle, first.len());
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

/// A `close_notify` goes out with the budget full: the room kept for the
/// final alert pays for it, and the budget is charged no more for it.
#[test]
fn a_close_notify_goes_out_with_the_budget_full() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let mut server = ServerConnection::with_budget(server_config(), limit.clone()).unwrap();
        let mut client = client(version);
        handshake(&mut server, &mut client);
        let idle = limit.used();
        limit.set_limit(idle);
        assert!(server.send_close_notify(), "{version:?}");
        assert!(server.wants_write(), "{version:?}");
        assert!(limit.used() <= idle, "{version:?}");
        assert!(server.buffers_accounted());
        to_client(&mut server, &mut client);
        let mut bytes = Vec::new();
        assert_eq!(client.reader().read_to_end(&mut bytes).unwrap(), 0);
    }
}

/// A hello that does not parse is answered with decode_error with the
/// budget full: the room kept for the final alert since the first read
/// pays for it, and nothing goes out after it.
#[test]
fn a_fatal_alert_goes_out_with_the_budget_full() {
    let limit = Limit::new(1 << 20);
    let mut acceptor = Acceptor::with_budget(limit.clone());
    // A ClientHello whose body is one byte: a record that frames, and a
    // message that does not parse.
    let hello = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
    let mut rest = &hello[..];
    assert_eq!(acceptor.read_tls(&mut rest).unwrap(), hello.len());
    limit.set_limit(limit.used());
    let Err((_, mut alert)) = acceptor.accept() else {
        panic!("the hello was accepted");
    };
    assert!(!alert.is_empty(), "no alert was queued");

    let mut sent = Vec::new();
    alert.write_all(&mut sent).unwrap();
    // One record, and it is a fatal decode_error alert.
    let (header, payload) = sent.split_at(HEADER_SIZE);
    assert_eq!(ContentType::from(header[0]), ContentType::Alert);
    assert_eq!(
        usize::from(u16::from_be_bytes([header[3], header[4]])),
        payload.len()
    );
    assert_eq!(AlertLevel::from(payload[0]), AlertLevel::Fatal);
    assert_eq!(
        AlertDescription::from(payload[1]),
        AlertDescription::DecodeError
    );
}

/// Offers client authentication without requiring it, naming many CAs, so
/// its certificate request is larger than a record. The client in these
/// tests sends no certificate, so nothing is verified.
#[derive(Debug)]
struct ManyAuthorities(Vec<DistinguishedName>);

impl ClientCertVerifier for ManyAuthorities {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.0
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Err(Error::General("the client sends no certificate".into()))
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("the client sends no certificate".into()))
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("the client sends no certificate".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Runs a handshake with `config` on a budget of `start` bytes that grows
/// by a little each time the server can neither read nor write, as memory
/// another connection frees would. The server may wait for room, but never
/// fails: returns the error if it does.
fn handshake_on_a_growing_budget(
    config: &Arc<ServerConfig>,
    version: &'static SupportedProtocolVersion,
    start: usize,
) -> Result<(), Error> {
    const STEP: usize = 512;
    let limit = Limit::new(start);
    let mut room = start;
    let mut server = ServerConnection::with_budget(config.clone(), limit.clone())?;
    let mut client = client(version);
    let mut wire = Vec::new();
    for _ in 0..10_000 {
        wire.extend(from_client(&mut client));
        if wire.is_empty()
            && !client.is_handshaking()
            && !server.is_handshaking()
            && !server.wants_write()
        {
            return Ok(());
        }
        let mut moved = false;
        if !wire.is_empty() {
            let mut rest = &wire[..];
            match server.read_tls(&mut rest) {
                Ok(read) => {
                    moved |= read > 0;
                    wire.drain(..read);
                }
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::OutOfMemory),
            }
        }
        server.process_new_packets()?;
        assert!(server.buffers_accounted());
        if server.wants_write() {
            to_client(&mut server, &mut client);
            moved = true;
        }
        if !moved {
            room += STEP;
            limit.set_limit(room);
        }
    }
    panic!("{version:?}: the handshake from {start} bytes never finished");
}

/// A server whose config bounds its handshake output (here: a chain, many
/// CA names, many tickets, small records) waits for room for all of it
/// before each handshake message, so however little its budget has when
/// the handshake starts, it never fails for memory: the output a message
/// makes never needs more than was charged for it.
#[test]
fn a_bounded_config_never_fails_its_handshake_for_memory() {
    let plain = server_config();
    let names = (0..200u8)
        .map(|n| DistinguishedName::from(vec![n; 150]))
        .collect();
    let authorities = {
        let (chain, key) = chain_and_key();
        Arc::new(
            ServerConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(Arc::new(ManyAuthorities(names)))
                .with_single_cert(chain, key)
                .unwrap(),
        )
    };
    let tickets = {
        let mut config = (*plain).clone();
        config.send_tls13_tickets = 400;
        Arc::new(config)
    };
    let small_records = {
        let mut config = (*plain).clone();
        config.max_fragment_size = Some(512);
        Arc::new(config)
    };
    let mut failures = Vec::new();
    for (what, config) in [
        ("a chain", &plain),
        ("many CA names", &authorities),
        ("many tickets", &tickets),
        ("small records", &small_records),
    ] {
        let most = config.most_connection().expect("the config is bounded");
        for version in [&TLS12, &TLS13] {
            let failed = (0..2 * most).step_by(most / 16).find_map(|start| {
                handshake_on_a_growing_budget(config, version, start)
                    .err()
                    .map(|error| (start, error))
            });
            if let Some((start, error)) = failed {
                failures.push(format!("{what}, {version:?}, from {start} bytes: {error}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
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
