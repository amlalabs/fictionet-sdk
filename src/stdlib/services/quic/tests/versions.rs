//! QUIC version 2 and version negotiation through two layers on the
//! simulated datagram carrier
//!
//! Each test checks the version both layers settle on, the versions of the
//! long headers each peer put on the carrier, and that a stream carries
//! bytes both ways, which needs both sides to derive one version's keys.

use super::*;

/// The packet type bits of a long header's first byte that mean Retry in
/// `version` (RFC 9000 section 17.2, RFC 9369 section 3.2)
fn is_retry(first: u8, version: u32) -> bool {
    let bits = (first >> 4) & 0b11;
    match version {
        QUIC_V2 => bits == 0b00,
        _ => bits == 0b11,
    }
}

fn versions(peer: &Peer) -> Vec<u32> {
    peer.long_headers
        .iter()
        .map(|&(_, version)| version)
        .collect()
}

fn settled(pair: &Pair) -> (Option<u32>, Option<u32>) {
    (
        pair.client.driver.layer().version(),
        pair.server.driver.layer().version(),
    )
}

/// Open a stream, send a request one way and a response the other
fn exchange(pair: &mut Pair) {
    pair.client
        .command(MuxCommand::control(ControlCommand::Open(Dir::Bi)));
    pair.drive();
    let (client, _) = pair.client.opened();
    pair.client.command(client.grant(64));
    pair.client.command(client.send(StreamCommand::Write(
        Chunk::copy_of(pair.client.driver.budget(), b"request").unwrap(),
    )));
    pair.client.command(client.send(StreamCommand::End));
    pair.drive();
    let (server, _) = pair.server.opened();
    pair.server.command(server.grant(64));
    pair.drive();
    assert!(pair.server.events.iter().any(|event| matches!(
        event,
        MuxEvent::Child(id, StreamEvent::Data(data)) if *id == server.id() && data.as_ref() == b"request"
    )));
    pair.server.command(server.send(StreamCommand::Write(
        Chunk::copy_of(pair.server.driver.budget(), b"response").unwrap(),
    )));
    pair.server.command(server.send(StreamCommand::End));
    pair.drive();
    assert!(pair.client.events.iter().any(|event| matches!(
        event,
        MuxEvent::Child(id, StreamEvent::Data(data)) if *id == client.id() && data.as_ref() == b"response"
    )));
}

#[test]
fn a_version_2_first_flight_completes_in_version_2() {
    let mut pair = Pair::versions(
        QUIC_V2,
        &[QUIC_V2],
        &[QUIC_V1, QUIC_V2],
        AddressValidation::Accept,
    );
    pair.handshake();
    exchange(&mut pair);
    assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
    for peer in [&pair.client, &pair.server] {
        let sent = versions(peer);
        assert!(!sent.is_empty());
        assert!(sent.iter().all(|&version| version == QUIC_V2), "{sent:x?}");
    }
}

#[test]
fn a_server_preferring_version_2_upgrades_a_version_1_first_flight() {
    let mut pair = Pair::versions(
        QUIC_V1,
        &[QUIC_V2, QUIC_V1],
        &[QUIC_V2, QUIC_V1],
        AddressValidation::Accept,
    );
    pair.handshake();
    exchange(&mut pair);
    assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
    let client = versions(&pair.client);
    let server = versions(&pair.server);
    assert_eq!(client[0], QUIC_V1, "the first flight is in version 1");
    assert!(
        server.iter().all(|&version| version == QUIC_V2),
        "{server:x?}"
    );
    let switched = client
        .iter()
        .position(|&version| version == QUIC_V2)
        .unwrap();
    assert!(client[switched..].iter().all(|&version| version == QUIC_V2));
}

#[test]
fn a_client_that_offers_only_version_1_keeps_it() {
    let mut pair = Pair::versions(
        QUIC_V1,
        &[QUIC_V1],
        &[QUIC_V2, QUIC_V1],
        AddressValidation::Accept,
    );
    pair.handshake();
    exchange(&mut pair);
    assert_eq!(settled(&pair), (Some(QUIC_V1), Some(QUIC_V1)));
    for peer in [&pair.client, &pair.server] {
        assert!(versions(peer).iter().all(|&version| version == QUIC_V1));
    }
}

#[test]
fn a_version_2_retry_is_answered_in_version_2() {
    let mut pair = Pair::versions(
        QUIC_V2,
        &[QUIC_V2],
        &[QUIC_V1, QUIC_V2],
        AddressValidation::Retry,
    );
    pair.handshake();
    exchange(&mut pair);
    assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
    let (first, version) = pair.server.long_headers[0];
    assert_eq!(version, QUIC_V2);
    assert!(is_retry(first, version), "{first:#x}");
    assert!(!is_retry(first, QUIC_V1));
    assert!(
        versions(&pair.client)
            .iter()
            .all(|&version| version == QUIC_V2)
    );
}

#[test]
fn a_retry_keeps_the_original_version_before_an_upgrade() {
    let mut pair = Pair::versions(
        QUIC_V1,
        &[QUIC_V2, QUIC_V1],
        &[QUIC_V2, QUIC_V1],
        AddressValidation::Retry,
    );
    pair.handshake();
    exchange(&mut pair);
    assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
    let (first, version) = pair.server.long_headers[0];
    assert_eq!(version, QUIC_V1);
    assert!(is_retry(first, version), "{first:#x}");
    // The Initial carrying the token stays in version 1; the server's
    // answer to it upgrades.
    assert_eq!(&versions(&pair.client)[..2], &[QUIC_V1, QUIC_V1]);
    let server = versions(&pair.server);
    assert!(
        server[1..].iter().all(|&version| version == QUIC_V2),
        "{server:x?}"
    );
}

#[test]
fn version_negotiation_moves_the_client_to_version_2() {
    let mut pair = Pair::versions(
        QUIC_V1,
        &[QUIC_V1, QUIC_V2],
        &[QUIC_V2],
        AddressValidation::Accept,
    );
    pair.handshake();
    exchange(&mut pair);
    assert_eq!(settled(&pair), (Some(QUIC_V2), Some(QUIC_V2)));
    let client = versions(&pair.client);
    let server = versions(&pair.server);
    assert_eq!(client[0], QUIC_V1);
    assert_eq!(server[0], 0, "a Version Negotiation packet");
    assert!(
        client[1..].iter().all(|&version| version == QUIC_V2),
        "{client:x?}"
    );
    assert!(
        server[1..].iter().all(|&version| version == QUIC_V2),
        "{server:x?}"
    );
}
