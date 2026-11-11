// The QUIC Interop Runner's test cases over QUIC version 2, between the
// SDK and ngtcp2, in both roles.
//
// Each case follows the runner's definition in `testcases_quic.py`: the
// same files, network scenario and checks, with the negotiated version
// required to be 2 where the runner requires 1. Unless a case says
// otherwise, the client's first flight is in version 1 and offers 2 and 1,
// and the server prefers 2, so every connection reaches version 2 by
// compatible version negotiation (RFC 9368, RFC 9369).

use std::collections::BTreeMap;
use std::time::Duration;

use fictionet::stdlib::services::quic::{AddressValidation, QUIC_V1, QUIC_V2};

use crate::network::{Endpoint, Kind, Network, Scenario, Side};
use crate::ngtcp2::{App, Clients, Closed, Ngtcp2};
use crate::sdk::{SdkH3, SdkHq, Versions};

const KB: usize = 1 << 10;
const MB: usize = 1 << 20;
const OFFER: &[u32] = &[QUIC_V2, QUIC_V1];

/// Which implementation is the client
#[derive(Clone, Copy, Debug)]
enum Roles {
    SdkClient,
    SdkServer,
}

#[derive(Clone, Copy)]
struct Case {
    sizes: &'static [usize],
    scenario: fn(u64) -> Scenario,
    /// The client's first flight
    first: u32,
    client: &'static [u32],
    server: &'static [u32],
    retry: bool,
    app: App,
}

impl Case {
    fn new(sizes: &'static [usize]) -> Self {
        Self {
            sizes,
            scenario: Scenario::simple,
            first: QUIC_V1,
            client: OFFER,
            server: OFFER,
            retry: false,
            app: App::Hq,
        }
    }
}

fn files(sizes: &[usize], seed: u64) -> BTreeMap<String, Vec<u8>> {
    let mut state = seed;
    sizes
        .iter()
        .enumerate()
        .map(|(i, &size)| {
            let bytes = (0..size)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (state >> 56) as u8
                })
                .collect();
            (format!("/{i}-{size}"), bytes)
        })
        .collect()
}

/// One connection's outcome
struct Run {
    net: Network,
    client: Option<u32>,
    server: Option<u32>,
    /// The close the server received, when the scenario delivered it
    close: Option<Closed>,
}

/// Run one connection, check the files, and close it as the runner's
/// clients do: with no error once every file has arrived
fn connect(case: Case, roles: Roles, seed: u64) -> Run {
    let files = files(case.sizes, seed);
    let paths: Vec<String> = files.keys().cloned().collect();
    let mut net = Network::new((case.scenario)(seed));
    let tail = Duration::from_secs(1);
    match roles {
        Roles::SdkClient => {
            assert_eq!(case.app, App::Hq, "the SDK has no HTTP/3 client");
            let mut client = SdkHq::client(
                Versions {
                    first: case.first,
                    preferred: case.client,
                },
                &paths,
                seed,
            );
            let mut server = Ngtcp2::server(case.server, case.retry, seed);
            for (path, bytes) in &files {
                server.serve(path, bytes);
            }
            net.run(&mut client, &mut server, |client, _, _| {
                if client.app.responses().is_some() {
                    client.close();
                }
                client.app.ended
            });
            let responses = client.app.responses().unwrap_or_else(|| {
                panic!(
                    "SDK client ended without its files: {:?}, server {:?}, link {:?}",
                    client.app.lost,
                    server.failure(),
                    net.impaired()
                )
            });
            assert!(
                responses
                    .iter()
                    .zip(files.values())
                    .all(|(got, want)| got == want),
                "every file arrives intact"
            );
            assert!(client.app.lost.is_none(), "{:?}", client.app.lost);
            Run {
                client: client.version(),
                server: server.version(),
                close: server.peer_close(),
                net,
            }
        }
        Roles::SdkServer => {
            let mut client = Ngtcp2::client(case.first, case.client, case.app, seed, net.now);
            for path in &paths {
                client.request(path);
            }
            let versions = Versions {
                first: case.first,
                preferred: case.server,
            };
            let validation = if case.retry {
                AddressValidation::Retry
            } else {
                AddressValidation::Accept
            };
            let mut closed = None;
            let finish = |client: &mut Ngtcp2, now: Duration, closed: &mut Option<Duration>| {
                if closed.is_none() && client.responses().is_some() {
                    client.close(now);
                    *closed = Some(now);
                }
                // The close leaves on the next step; the server may then
                // take it within the tail.
                closed.is_some_and(|at| now >= at + tail)
            };
            let (versions_seen, close);
            if case.app == App::H3 {
                let mut server = SdkH3::server(versions, &files, seed);
                net.run(&mut client, &mut server, |client, _, now| {
                    finish(client, now, &mut closed)
                });
                versions_seen = (client.version(), server.version());
                close = None;
            } else {
                let mut server = SdkHq::server(versions, validation, &files, seed);
                net.run(&mut client, &mut server, |client, server, now| {
                    finish(client, now, &mut closed)
                        || server.app.lost.is_some() && closed.is_some()
                });
                versions_seen = (client.version(), server.version());
                close = server.app.lost.as_ref().and_then(|error| match error {
                    quinn_proto::ConnectionError::ConnectionClosed(close) => {
                        Some(Closed::Transport(u64::from(close.error_code)))
                    }
                    quinn_proto::ConnectionError::ApplicationClosed(close) => {
                        Some(Closed::Application(close.error_code.into_inner()))
                    }
                    // The client's close was lost; the server timed out.
                    quinn_proto::ConnectionError::TimedOut => None,
                    other => panic!("the server lost the connection: {other}"),
                });
            }
            assert_eq!(client.failure(), None);
            let responses = client.responses().unwrap();
            for (response, want) in responses.iter().zip(files.values()) {
                assert_eq!(response.body.len(), want.len());
                assert!(&response.body == want, "every file arrives intact");
                assert_eq!(response.status, (case.app == App::H3).then_some(200));
            }
            Run {
                client: versions_seen.0,
                server: versions_seen.1,
                close,
                net,
            }
        }
    }
}

/// The runner's `_check_version_and_files`, requiring `version`
fn negotiated(run: &Run, version: u32) -> Result<(), String> {
    if run.client != Some(version) || run.server != Some(version) {
        return Err(format!(
            "negotiated {:x?} and {:x?}, expected {version:#x}",
            run.client, run.server
        ));
    }
    Ok(())
}

fn retried(run: &Run) -> bool {
    run.net
        .packets()
        .iter()
        .any(|packet| packet.kind == Kind::Retry)
}

/// The runner's `TestCaseV2.check`
fn version_2(run: &Run) -> Result<(), String> {
    let client_initial = run.net.versions(Side::Client, Kind::Initial);
    if !client_initial.contains(&QUIC_V1) {
        return Err(format!("client Initial versions {client_initial:x?}"));
    }
    let server_initial = run.net.versions(Side::Server, Kind::Initial);
    if !server_initial.contains(&QUIC_V2) {
        return Err(format!("server Initial versions {server_initial:x?}"));
    }
    for side in [Side::Client, Side::Server] {
        let mut handshake = run.net.versions(side, Kind::Handshake);
        handshake.dedup();
        if handshake != [QUIC_V2] {
            return Err(format!("{side:?} Handshake versions {handshake:x?}"));
        }
    }
    Ok(())
}

/// The runner's `TestCaseRetry._check_trace`, by token: some client
/// Initial carries a token a Retry carried
fn retry_trace(run: &Run) -> Result<(), String> {
    let packets = run.net.packets();
    let tokens: Vec<&Vec<u8>> = packets
        .iter()
        .filter(|p| p.from == Side::Server && p.kind == Kind::Retry)
        .map(|p| &p.token)
        .collect();
    if tokens.is_empty() || tokens.iter().any(|token| token.is_empty()) {
        return Err("no Retry with a token".into());
    }
    if !packets
        .iter()
        .any(|p| p.from == Side::Client && p.kind == Kind::Initial && tokens.contains(&&p.token))
    {
        return Err("no Initial used a Retry token".into());
    }
    Ok(())
}

/// Every check a case makes on one connection, in version 2
fn check(case: Case, run: &Run) -> Result<(), String> {
    negotiated(run, QUIC_V2)?;
    if case.first == QUIC_V1 && case.server[0] == QUIC_V2 {
        version_2(run)?;
    }
    for side in [Side::Client, Side::Server] {
        let mut handshake = run.net.versions(side, Kind::Handshake);
        handshake.dedup();
        if handshake != [QUIC_V2] {
            return Err(format!("{side:?} Handshake versions {handshake:x?}"));
        }
    }
    if case.retry {
        retry_trace(run)?;
        let retry = run.net.versions(Side::Server, Kind::Retry);
        // RFC 9369 section 4.1: a Retry is in the client's version.
        if retry.iter().any(|&version| version != case.first) {
            return Err(format!("Retry versions {retry:x?}"));
        }
    } else if retried(run) {
        return Err("a Retry was sent".into());
    }
    Ok(())
}

/// Run `connections` connections of `case`, as the runner's multiconnect
/// does, and check each one
fn interop(case: Case, roles: Roles, connections: u64) -> Vec<Run> {
    (0..connections)
        .map(|i| {
            eprintln!("{roles:?}, connection {i}");
            let run = connect(case, roles, 0x5eed_0000 + i);
            if let Err(why) = check(case, &run) {
                panic!("{roles:?}, connection {i}: {why}");
            }
            run
        })
        .collect()
}

/// A connection that saw no impairment closes with no error
fn closed_cleanly(runs: &[Run]) {
    for run in runs {
        assert!(
            matches!(
                run.close,
                None | Some(Closed::Transport(0) | Closed::Application(0))
            ),
            "{:?}",
            run.close
        );
    }
}

fn both(case: Case, connections: u64) -> [Vec<Run>; 2] {
    [
        interop(case, Roles::SdkClient, connections),
        interop(case, Roles::SdkServer, connections),
    ]
}

#[test]
fn v2() {
    for runs in both(Case::new(&[KB]), 1) {
        version_2(&runs[0]).unwrap();
        assert!(runs[0].close.is_some(), "the close arrived");
        closed_cleanly(&runs);
    }
}

#[test]
fn handshake() {
    for runs in both(Case::new(&[KB]), 1) {
        assert!(runs[0].close.is_some(), "the close arrived");
        closed_cleanly(&runs);
    }
}

#[test]
fn handshake_starting_in_version_2() {
    let case = Case {
        first: QUIC_V2,
        client: &[QUIC_V2],
        ..Case::new(&[KB])
    };
    for runs in both(case, 1) {
        // Every long header packet is in version 2.
        for packet in runs[0].net.packets() {
            assert!(matches!(packet.version, None | Some(QUIC_V2)), "{packet:?}");
        }
    }
}

#[test]
fn transfer() {
    for runs in both(Case::new(&[2 * MB, 3 * MB, 5 * MB]), 1) {
        assert!(runs[0].close.is_some(), "the close arrived");
        closed_cleanly(&runs);
    }
}

#[test]
fn retry() {
    let case = Case {
        retry: true,
        ..Case::new(&[10 * KB])
    };
    // `check` requires a Retry in the client's version 1, an Initial that
    // carries its token, and every later Handshake packet in version 2.
    both(case, 1);
}

#[test]
fn retry_in_version_2() {
    let case = Case {
        retry: true,
        first: QUIC_V2,
        client: &[QUIC_V2],
        ..Case::new(&[10 * KB])
    };
    // `check` requires every Retry in version 2, the client's version.
    both(case, 1);
}

#[test]
fn http3() {
    let case = Case {
        app: App::H3,
        ..Case::new(&[5 * KB, 10 * KB, 500 * KB])
    };
    interop(case, Roles::SdkServer, 1);
}

/// Loss and corruption cases also check that the link impaired packets
fn impaired(runs: &[Run], corrupt: bool) {
    let (dropped, corrupted, _) = runs.iter().fold((0, 0, 0), |sum, run| {
        let (d, c, q) = run.net.impaired();
        (sum.0 + d, sum.1 + c, sum.2 + q)
    });
    if corrupt {
        assert!(corrupted > 0 && dropped == 0);
    } else {
        assert!(dropped > 0 && corrupted == 0);
    }
}

#[test]
fn handshakeloss() {
    let case = Case {
        scenario: |seed| Scenario::drop_rate(30, seed),
        ..Case::new(&[KB])
    };
    for runs in both(case, 50) {
        impaired(&runs, false);
    }
}

#[test]
fn transferloss() {
    let case = Case {
        scenario: |seed| Scenario::drop_rate(2, seed),
        ..Case::new(&[2 * MB])
    };
    for runs in both(case, 1) {
        impaired(&runs, false);
    }
}

#[test]
fn handshakecorruption() {
    let case = Case {
        scenario: |seed| Scenario::corrupt_rate(30, seed),
        ..Case::new(&[KB])
    };
    for runs in both(case, 50) {
        impaired(&runs, true);
    }
}

#[test]
fn transfercorruption() {
    let case = Case {
        scenario: |seed| Scenario::corrupt_rate(2, seed),
        ..Case::new(&[2 * MB])
    };
    for runs in both(case, 1) {
        impaired(&runs, true);
    }
}

#[test]
fn versionnegotiation_into_version_2() {
    // The runner's versionnegotiation case, with a server that accepts only
    // version 2: the SDK client's version 1 first flight draws a Version
    // Negotiation packet, and the client starts again in version 2.
    let case = Case {
        server: &[QUIC_V2],
        ..Case::new(&[KB])
    };
    let run = connect(case, Roles::SdkClient, 7);
    negotiated(&run, QUIC_V2).unwrap();
    let packets = run.net.packets();
    assert!(
        packets
            .iter()
            .any(|p| p.from == Side::Server && p.kind == Kind::VersionNegotiation)
    );
    assert_eq!(run.net.versions(Side::Client, Kind::Initial)[0], QUIC_V1);
}

#[test]
fn the_version_2_checks_reject_a_connection_that_stays_in_version_1() {
    // A control for the checks above: a server that prefers version 1
    // keeps the client's version, and the same checks then fail.
    let case = Case {
        server: &[QUIC_V1, QUIC_V2],
        ..Case::new(&[KB])
    };
    for roles in [Roles::SdkClient, Roles::SdkServer] {
        let run = connect(case, roles, 11);
        negotiated(&run, QUIC_V1).unwrap();
        assert!(version_2(&run).is_err());
        assert!(check(Case::new(&[KB]), &run).is_err());
    }
}

/// Every file arrived intact over HTTP/3, in version 2
fn served(client: &Ngtcp2, files: &BTreeMap<String, Vec<u8>>) {
    assert_eq!(client.failure(), None);
    let responses = client.responses().expect("every response");
    assert_eq!(responses.len(), files.len());
    for (response, want) in responses.iter().zip(files.values()) {
        assert_eq!(response.status, Some(200));
        assert!(&response.body == want, "every file arrives intact");
    }
    assert_eq!(client.version(), Some(QUIC_V2));
}

#[test]
fn http3_clients_at_once_share_one_listener() {
    // Eight ngtcp2 clients at one address, each on its own connection at
    // the same time, through one SDK HTTP/3 listener on the runner's link.
    let case = Case {
        app: App::H3,
        ..Case::new(&[5 * KB, 100 * KB])
    };
    let seed = 0x5eed_1000;
    let files = files(case.sizes, seed);
    let mut net = Network::new((case.scenario)(seed));
    let mut clients = Clients(
        (0..8)
            .map(|i| {
                let mut client =
                    Ngtcp2::client(case.first, case.client, App::H3, seed + i, net.now);
                for path in files.keys() {
                    client.request(path);
                }
                client
            })
            .collect(),
    );
    let versions = Versions {
        first: case.first,
        preferred: case.server,
    };
    let mut server = SdkH3::server(versions, &files, seed);
    net.run(&mut clients, &mut server, |clients, _, _| {
        clients.0.iter().all(|client| client.responses().is_some())
    });
    for client in &clients.0 {
        served(client, &files);
    }
    assert_eq!(server.version(), Some(QUIC_V2));
}

#[test]
fn http3_multiconnect_through_one_listener() {
    // The runner's multiconnect case: fifty connections in turn through
    // 30% loss each way, here over HTTP/3 and all to one SDK listener,
    // which holds the earlier ones while they drain.
    let case = Case {
        app: App::H3,
        scenario: |seed| Scenario::drop_rate(30, seed),
        ..Case::new(&[KB])
    };
    let seed = 0x5eed_2000;
    let files = files(case.sizes, seed);
    let mut net = Network::new((case.scenario)(seed));
    let versions = Versions {
        first: case.first,
        preferred: case.server,
    };
    let mut server = SdkH3::server(versions, &files, seed);
    for i in 0..50 {
        let mut client = Ngtcp2::client(case.first, case.client, App::H3, seed + i, net.now);
        for path in files.keys() {
            client.request(path);
        }
        let mut closed = None;
        net.run(&mut client, &mut server, |client, _, now| {
            if closed.is_none() && client.responses().is_some() {
                client.close(now);
                closed = Some(now);
            }
            closed.is_some_and(|at| now >= at + Duration::from_secs(1))
        });
        served(&client, &files);
    }
    assert_eq!(server.version(), Some(QUIC_V2));
    assert!(net.impaired().0 > 0, "the link dropped packets");
}
