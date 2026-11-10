//! A server on the unbuffered API: records decrypted where they arrive,
//! records sealed where they are written, and handshake records that stay
//! queued until they are encoded.

use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;
use std::io::{Read, Write};

use crate::budget::testing::Limit;
use crate::budget::tests::{client, from_client, server_config, TrustAnything};
use crate::client::ClientConnection;
use crate::crypto::ring::{cipher_suite, default_provider};
use crate::crypto::CryptoProvider;
use crate::enums::AlertDescription;
use crate::msgs::message::HEADER_SIZE;
use crate::server::{Acceptor, UnbufferedServerConnection};
use crate::sync::Arc;
use crate::unbuffered::{ConnectionState, UnbufferedStatus};
use crate::version::{TLS12, TLS13};
use crate::{ClientConfig, Error, SupportedCipherSuite, SupportedProtocolVersion};

/// A server that accepted the hello in `wire` on the unbuffered API.
fn accept(wire: &[u8]) -> UnbufferedServerConnection {
    accept_with(Acceptor::default(), wire)
}

fn accept_with(mut acceptor: Acceptor, wire: &[u8]) -> UnbufferedServerConnection {
    let mut rest = wire;
    loop {
        acceptor.read_tls(&mut rest).unwrap();
        if let Some(accepted) = acceptor.accept().unwrap() {
            assert!(rest.is_empty(), "bytes after the hello");
            return accepted.into_unbuffered(server_config()).unwrap();
        }
    }
}

/// What the server made of its input: each record's plaintext, with where
/// it lay in the input as first given, and what it sent.
#[derive(Default)]
struct Served {
    records: Vec<(Range<usize>, Vec<u8>)>,
    sent: Vec<u8>,
}

/// Runs the server over `incoming` until it needs more, discarding as it
/// is told. Ranges are counted from the start of `incoming` as given.
fn serve(server: &mut UnbufferedServerConnection, incoming: &mut Vec<u8>) -> Served {
    let mut served = Served::default();
    let mut offset = 0;
    loop {
        let UnbufferedStatus { discard, state } = server.process_tls_records(&mut incoming[..]);
        let mut extra = 0;
        // A failed connection is done once what it queued is out.
        let Ok(state) = state else {
            incoming.drain(..discard);
            return served;
        };
        let more = match state {
            ConnectionState::ReadTraffic(mut traffic) => {
                let record = traffic.next_record().unwrap().unwrap();
                assert!(traffic.next_record().is_none(), "one record a state");
                let plain = traffic.payload(&record).to_vec();
                extra = record.discard;
                let at = offset + record.payload.start..offset + record.payload.end;
                served.records.push((at, plain));
                true
            }
            ConnectionState::EncodeTlsData(mut encode) => {
                let mut out = vec![0; encode.len()];
                let n = encode.encode(&mut out).unwrap();
                assert_eq!(n, out.len());
                served.sent.extend_from_slice(&out);
                true
            }
            ConnectionState::TransmitTlsData(transmit) => {
                transmit.done();
                true
            }
            _ => false,
        };
        incoming.drain(..discard + extra);
        offset += discard + extra;
        if !more {
            return served;
        }
    }
}

/// Gives the client what the server sent and returns what it answers.
fn to_client(client: &mut ClientConnection, bytes: &[u8]) -> Vec<u8> {
    let mut rest = bytes;
    while !rest.is_empty() {
        client.read_tls(&mut rest).unwrap();
        client.process_new_packets().unwrap();
    }
    from_client(client)
}

/// A finished handshake between `client` and an unbuffered server.
fn handshake(client: ClientConnection) -> (ClientConnection, UnbufferedServerConnection) {
    handshake_with(Acceptor::default(), client)
}

fn handshake_with(
    acceptor: Acceptor,
    mut client: ClientConnection,
) -> (ClientConnection, UnbufferedServerConnection) {
    let mut server = accept_with(acceptor, &from_client(&mut client));
    let mut incoming = Vec::new();
    for _ in 0..8 {
        let served = serve(&mut server, &mut incoming);
        let answer = to_client(&mut client, &served.sent);
        incoming.extend_from_slice(&answer);
        if !client.is_handshaking() && !server.is_handshaking() && incoming.is_empty() {
            return (client, server);
        }
    }
    panic!("the handshake did not finish");
}

/// Where each record in `wire` starts and ends.
fn records(wire: &[u8]) -> Vec<Range<usize>> {
    let mut at = 0;
    let mut out = Vec::new();
    while at < wire.len() {
        let len = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
        out.push(at..at + HEADER_SIZE + len);
        at += HEADER_SIZE + len;
    }
    out
}

/// A client whose whole offer is `suite`, so the server picks it.
fn client_with(
    version: &'static SupportedProtocolVersion,
    suite: SupportedCipherSuite,
) -> ClientConnection {
    let provider = CryptoProvider {
        cipher_suites: vec![suite],
        ..default_provider()
    };
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnything))
        .with_no_client_auth();
    ClientConnection::new(Arc::new(config), "testserver.com".try_into().unwrap()).unwrap()
}

/// Several records in one buffer each come back as a range of that buffer,
/// inside the record that carried it, holding exactly what the client
/// wrote: decrypted where they arrived, with nothing copied out.
#[test]
fn records_are_decrypted_where_they_arrive() {
    for version in [&TLS12, &TLS13] {
        let (mut client, mut server) = handshake(client(version));
        let messages: [&[u8]; 3] = [b"first", &[7; 3000], b"third and last"];
        for message in messages {
            client.writer().write_all(message).unwrap();
        }
        let wire = from_client(&mut client);
        let carried = records(&wire);
        assert_eq!(carried.len(), messages.len());

        let mut incoming = wire.clone();
        let served = serve(&mut server, &mut incoming);
        assert!(incoming.is_empty(), "{version:?}: input left over");
        assert_eq!(served.records.len(), messages.len());
        for ((at, plain), (record, message)) in
            served.records.iter().zip(carried.iter().zip(messages))
        {
            assert_eq!(plain, message, "{version:?}");
            assert!(
                record.start + HEADER_SIZE <= at.start && at.end <= record.end,
                "{version:?}: plaintext at {at:?} is outside its record {record:?}"
            );
        }
    }
}

/// A write is sealed into exactly the bytes `encrypted_len` says, for
/// every suite the server may pick, one record or several, and the client
/// reads back what was written.
#[test]
fn a_write_is_sealed_into_the_length_it_said() {
    let suites = [
        (&TLS13, cipher_suite::TLS13_AES_128_GCM_SHA256),
        (&TLS13, cipher_suite::TLS13_AES_256_GCM_SHA384),
        (&TLS13, cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
        (&TLS12, cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        (&TLS12, cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        (
            &TLS12,
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
    ];
    for (version, suite) in suites {
        let (mut client, mut server) = handshake(client_with(version, suite));
        assert_eq!(server.negotiated_cipher_suite(), Some(suite));
        for len in [1, 100, 16384, 16385, 40000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut out = Vec::new();
            let status = server.process_tls_records(&mut []);
            assert_eq!(status.discard, 0);
            let ConnectionState::WriteTraffic(mut write) = status.state.unwrap() else {
                panic!("{suite:?}: not ready to write");
            };
            out.resize(write.encrypted_len(len), 0);
            let n = write.encrypt(&data, &mut out).unwrap();
            assert_eq!(n, out.len(), "{suite:?}: {len} bytes");
            let mut read = Vec::new();
            let mut rest = &out[..];
            while !rest.is_empty() {
                client.read_tls(&mut rest).unwrap();
                client.process_new_packets().unwrap();
                let _ = client.reader().read_to_end(&mut read);
            }
            assert!(read == data, "{suite:?}: {len} bytes read back differently");
        }
    }
}

/// An encode state dropped without encoding leaves its record queued: the
/// next call offers it again, and the handshake still completes.
#[test]
fn an_encode_state_dropped_unencoded_loses_nothing() {
    let mut client = client(&TLS13);
    let mut server = accept(&from_client(&mut client));
    let first = match server.process_tls_records(&mut []).state.unwrap() {
        ConnectionState::EncodeTlsData(encode) => encode.len(),
        state => panic!("expected a record to encode, got {state:?}"),
    };
    assert!(first > 0);
    let again = match server.process_tls_records(&mut []).state.unwrap() {
        ConnectionState::EncodeTlsData(encode) => encode.len(),
        state => panic!("the record was lost: {state:?}"),
    };
    assert_eq!(again, first);

    let mut incoming = Vec::new();
    for _ in 0..8 {
        let served = serve(&mut server, &mut incoming);
        incoming.extend_from_slice(&to_client(&mut client, &served.sent));
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("the handshake did not finish");
}

/// Without room for what a record may make, the record waits where it is,
/// untouched, and nothing is charged: the next call with room processes it.
/// A record the server cannot decrypt is then answered with bad_record_mac,
/// and the connection stays failed, reading nothing more.
#[test]
fn a_record_waits_for_room_and_a_bad_one_is_answered_with_an_alert() {
    for version in [&TLS12, &TLS13] {
        let limit = Limit::new(1 << 20);
        let (mut client, mut server) =
            handshake_with(Acceptor::with_budget(limit.clone()), client(version));
        client.writer().write_all(b"tampered").unwrap();
        let mut incoming = from_client(&mut client);
        *incoming.last_mut().unwrap() ^= 1;
        let arrived = incoming.clone();

        let idle = limit.used();
        limit.set_limit(idle);
        let status = server.process_tls_records(&mut incoming[..]);
        assert_eq!(status.discard, 0, "{version:?}");
        assert!(
            matches!(status.state, Ok(ConnectionState::BlockedBudget)),
            "{version:?}: {:?}",
            status.state
        );
        assert!(incoming == arrived, "{version:?}: the record was touched");
        assert_eq!(limit.used(), idle, "{version:?}");

        limit.set_limit(1 << 20);
        let status = server.process_tls_records(&mut incoming[..]);
        assert_eq!(
            status.state.unwrap_err(),
            Error::DecryptError,
            "{version:?}"
        );
        let served = serve(&mut server, &mut Vec::new());
        assert!(!served.sent.is_empty(), "{version:?}: no alert was sent");
        assert!(
            server.process_tls_records(&mut []).state.is_err(),
            "{version:?}: the connection went on after it failed"
        );

        let mut rest = &served.sent[..];
        client.read_tls(&mut rest).unwrap();
        assert!(
            rest.is_empty(),
            "{version:?}: more than one record went out"
        );
        assert_eq!(
            client.process_new_packets().unwrap_err(),
            Error::AlertReceived(AlertDescription::BadRecordMac),
            "{version:?}"
        );
    }
}
