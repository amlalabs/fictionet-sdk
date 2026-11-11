//! An endpoint whose routing storage is paid for up front
//!
//! `Endpoint::reserve` charges its budget for the tables of a fixed number
//! of connections and makes them at that size. The endpoint then refuses
//! what would grow them: a connection past the reservation, and a local
//! connection ID past a connection's share.

use fictionet_buf::Budget;

use super::*;
use crate::cost::{Charged, Costs, Linear};

const CID_LIFETIME: Duration = Duration::from_secs(2);

fn reserved_server(connections: usize, budget: &Budget) -> Endpoint {
    // IDs that expire make the server issue new ones and the client
    // retire old ones for as long as the connections last.
    let rotating: fn(&mut dyn Rng) -> Box<dyn ConnectionIdGenerator> =
        |_| Box::new(*RandomConnectionIdGenerator::new(8).set_lifetime(CID_LIFETIME));
    let mut server = Endpoint::new(
        Arc::new(EndpointConfig {
            connection_id_generator_factory: Arc::new(rotating),
            ..EndpointConfig::default()
        }),
        Some(Arc::new(server_config())),
        true,
        None,
    );
    assert!(server.reserve(connections, budget));
    server
}

/// Runs the pair for `span` of its time, waking whichever side is due
fn run_for(pair: &mut Pair, span: Duration) {
    let stop = pair.time + span;
    while pair.time < stop {
        if !pair.step() {
            match min_opt(pair.client.next_wakeup(), pair.server.next_wakeup()) {
                Some(time) => pair.time = time,
                None => break,
            }
        }
    }
}

#[test]
fn reserving_routing_storage_stays_within_its_charge() {
    let mut costs = Costs::new("endpoint reservation");
    for connections in [1, 3, 64, 1000] {
        let budget = Budget::unlimited();
        let mut endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(server_config())),
            true,
            None,
        );
        // The reservation is all the step allocates: every table it makes
        // fits in what it charged.
        costs.step(
            0,
            0,
            Linear {
                num: 0,
                den: 1,
                fixed: 0,
            },
            || {
                assert!(endpoint.reserve(connections, &budget));
                Charged::new((), budget.used())
            },
        );
        assert_eq!(budget.used(), Endpoint::reserved_bytes(connections));
        drop(endpoint);
        assert_eq!(budget.used(), 0);
    }
    eprintln!("cost: QUIC endpoint reservation: {}", costs.summary());
}

#[test]
fn a_refused_reservation_allocates_nothing() {
    let mut endpoint = Endpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(server_config())),
        true,
        None,
    );
    let budget = Budget::new(Endpoint::reserved_bytes(4) - 1);
    let mut costs = Costs::new("refused endpoint reservation");
    let refused = costs.step(
        0,
        0,
        Linear {
            num: 0,
            den: 1,
            fixed: 0,
        },
        || Charged::new(endpoint.reserve(4, &budget), budget.used()),
    );
    assert!(!refused);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_reserved_endpoint_keeps_its_tables_through_connection_id_rotation() {
    let _guard = subscribe();
    let budget = Budget::unlimited();
    let server = reserved_server(2, &budget);
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
    let mut pair = Pair::new_from_endpoint(client, server);
    let (first, _) = pair.connect();
    let (second, _) = pair.connect();
    let before = pair.server.endpoint.table_capacities();
    let reserved = budget.used();

    // Five lifetimes: each connection's server IDs are replaced five times.
    run_for(&mut pair, 5 * CID_LIFETIME);
    for client_ch in [first, second] {
        assert!(!pair.client_conn_mut(client_ch).is_closed());
        assert!(pair.client_conn_mut(client_ch).active_rem_cid_seq() >= 5);
    }
    assert_eq!(pair.server.endpoint.table_capacities(), before);
    assert_eq!(budget.used(), reserved);
}

#[test]
fn a_full_reserved_endpoint_refuses_a_connection_and_admits_one_after_a_drain() {
    let _guard = subscribe();
    let budget = Budget::unlimited();
    let server = reserved_server(2, &budget);
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
    let mut pair = Pair::new_from_endpoint(client, server);
    let (first, _) = pair.connect();
    let (second, _) = pair.connect();
    let before = pair.server.endpoint.table_capacities();

    let third = pair.begin_connect(client_config());
    pair.drive();
    assert_matches!(
        pair.server.assert_accept_error(),
        ConnectionError::CidsExhausted
    );
    assert_matches!(
        pair.client_conn_mut(third).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::ConnectionClosed(ref close)
        }) if close.error_code == TransportErrorCode::CONNECTION_REFUSED
    );
    // The two admitted connections never noticed.
    for client_ch in [first, second] {
        assert!(!pair.client_conn_mut(client_ch).is_closed());
    }

    // Closing one and letting it drain frees its place.
    let now = pair.time;
    pair.client_conn_mut(first)
        .close(now, VarInt(0), Bytes::new());
    run_for(&mut pair, Duration::from_secs(10));
    pair.connect();
    assert!(!pair.client_conn_mut(second).is_closed());
    assert_eq!(pair.server.endpoint.table_capacities(), before);
}
