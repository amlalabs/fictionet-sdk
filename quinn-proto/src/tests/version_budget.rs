//! Version negotiation under a budget that cannot pay for it
//!
//! Each new key derivation, a client's trial of an offered version, a
//! server's retained original keys, a restart after Version Negotiation and
//! the Retry check is charged before it allocates. A refusal costs the
//! packet that needed it and nothing else: the attempt goes on, and
//! completes once the budget has room.

use fictionet_buf::{Budget, Charge};

use super::*;
use crate::version::{VersionList, QUIC_V1, QUIC_V2};

/// What one derivation of Initial keys is charged
fn key_charge() -> usize {
    server_config().crypto.initial_keys_charge()
}

/// A budget of `limit` bytes, with all but `room` of it held by the
/// returned charge
fn budget_with_room(room: usize) -> (Budget, Charge) {
    let limit = 1 << 20;
    let budget = Budget::new(limit);
    let hog = budget.charge(limit - room).unwrap();
    (budget, hog)
}

fn pair_with_server_versions(server_versions: &[u32]) -> Pair {
    let mut server_endpoint = EndpointConfig::default();
    server_endpoint.supported_versions(server_versions.to_vec());
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
    let server = Endpoint::new(
        Arc::new(server_endpoint),
        Some(Arc::new(server_config())),
        true,
        None,
    );
    Pair::new_from_endpoint(client, server)
}

fn client_in(version: u32, preferred: &[u32]) -> ClientConfig {
    let mut config = client_config();
    config
        .version(version)
        .preferred_versions(VersionList::new(preferred).unwrap());
    config
}

/// Steps the pair a few times, enough for the server to answer the first flight
fn exchange_first_flights(pair: &mut Pair) {
    for _ in 0..3 {
        pair.step();
    }
}

fn versions_sent_by(pair: &Pair, sender: Side) -> Vec<u32> {
    pair.long_versions
        .iter()
        .filter(|(side, _)| *side == sender)
        .map(|&(_, version)| version)
        .collect()
}

#[test]
fn a_server_without_room_for_the_retained_keys_keeps_the_clients_version() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2, QUIC_V1]);
    // One byte short of what deriving the retained keys can hold.
    let (budget, hog) = budget_with_room(key_charge() - 1);
    pair.server.endpoint.set_reassembly_budget(&budget);
    let client_ch = pair.begin_connect(client_in(QUIC_V1, &[QUIC_V2, QUIC_V1]));
    exchange_first_flights(&mut pair);
    drop(hog);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
    assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V1);
    assert_eq!(pair.server_conn_mut(server_ch).version(), QUIC_V1);
    assert!(versions_sent_by(&pair, Side::Server)
        .iter()
        .all(|&version| version == QUIC_V1));
}

#[test]
fn a_client_without_room_to_try_an_offered_version_waits_for_it() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2, QUIC_V1]);
    let (budget, hog) = budget_with_room(key_charge() - 1);
    pair.client.endpoint.set_reassembly_budget(&budget);
    let client_ch = pair.begin_connect(client_in(QUIC_V1, &[QUIC_V2, QUIC_V1]));
    exchange_first_flights(&mut pair);
    // The server answered in version 2; the client could not try its keys,
    // so it holds nothing more and has not switched.
    assert!(versions_sent_by(&pair, Side::Server).contains(&QUIC_V2));
    assert_eq!(budget.used(), budget.limit() - (key_charge() - 1));
    assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V1);
    assert!(versions_sent_by(&pair, Side::Client)
        .iter()
        .all(|&version| version == QUIC_V1));

    drop(hog);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
    assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V2);
    assert_eq!(pair.server_conn_mut(server_ch).version(), QUIC_V2);
}

#[test]
fn a_client_without_room_to_start_again_ignores_version_negotiation_until_it_has() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2]);
    let (budget, hog) = budget_with_room(key_charge() - 1);
    pair.client.endpoint.set_reassembly_budget(&budget);
    let client_ch = pair.begin_connect(client_in(QUIC_V1, &[QUIC_V1, QUIC_V2]));
    exchange_first_flights(&mut pair);
    assert_eq!(
        versions_sent_by(&pair, Side::Server)[0],
        0,
        "a Version Negotiation packet"
    );
    assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V1);
    assert_eq!(budget.used(), budget.limit() - (key_charge() - 1));

    drop(hog);
    pair.drive();
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
    assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V2);
    assert_eq!(pair.server_conn_mut(server_ch).version(), QUIC_V2);
}

#[test]
fn a_client_without_room_to_check_a_retry_discards_it_until_it_has() {
    let _guard = subscribe();
    for room in [0, key_charge() - 1] {
        let mut pair = Pair::default();
        pair.server.handle_incoming = Box::new(validate_incoming);
        let (budget, hog) = budget_with_room(room);
        pair.client.endpoint.set_reassembly_budget(&budget);
        let client_ch = pair.begin_connect(client_in(QUIC_V2, &[QUIC_V2]));
        exchange_first_flights(&mut pair);
        // A Retry arrived; the client could not check or follow it, so the
        // server never saw its token.
        assert!(!versions_sent_by(&pair, Side::Server).is_empty());
        assert_eq!(pair.server.endpoint.open_connections(), 0);
        assert_eq!(budget.used(), budget.limit() - room);

        drop(hog);
        pair.drive();
        let server_ch = pair.server.assert_accept();
        pair.finish_connect(client_ch, server_ch);
        assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V2);
    }
}

#[test]
fn a_server_retry_allocates_nothing_beyond_its_buffer() {
    use crate::cost::{Charged, Costs, Linear};
    let _guard = subscribe();
    let mut costs = Costs::new("QUIC Retry");
    for version in [QUIC_V1, QUIC_V2] {
        let mut pair = Pair::default();
        pair.begin_connect(client_in(version, &[version]));
        pair.client.drive(pair.time, pair.server.addr);
        let (_, datagram) = pair.client.outbound.pop_front().unwrap();
        let mut buf = Vec::with_capacity(MIN_INITIAL_SIZE.into());
        let Some(DatagramEvent::NewConnection(incoming)) = pair.server.endpoint.handle(
            pair.time,
            pair.client.addr,
            None,
            None,
            datagram.as_ref().into(),
            &mut buf,
        ) else {
            panic!("the first flight is a new connection");
        };
        buf.clear();
        // The token, the tag and the Pseudo-Packet live in `buf`.
        let input = buf.capacity();
        let nothing = Linear {
            num: 0,
            den: 1,
            fixed: 0,
        };
        let size = costs.step(input, 0, nothing, || {
            Charged::new(
                pair.server.endpoint.retry(incoming, &mut buf).unwrap().size,
                0,
            )
        });
        assert!(size > 0 && size <= buf.capacity());
    }
    eprintln!("cost: QUIC Retry: {}", costs.summary());
}
