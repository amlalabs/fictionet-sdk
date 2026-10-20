//! Live commands change packet delivery, peer routes and observer facts.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use border_world::routing::{Applied, Rejected, Rejection, Route, RouteState, SetRoute};
use border_world::scenario::{
    BANK_ADDR, BANK_DOMAIN, BANK_NAMES, FOREIGN, HOME, IMPOSTOR_ADDR, Identity, ROGUE_CA_NAME,
    Scenario, Task, Variant, parse_prefix,
};
use common::*;
use fictionet::prelude::*;
use fictionet::stdlib::codec::{Frames, Stream};
use fictionet::stdlib::network::tcp::TcpConnection;
use fictionet::stdlib::protocols::{bgp, http1};
use fictionet::stdlib::world::sandbox::{self, Machine};
use fictionet::{Cx, End, Interface};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

type BgpStream = Stream<Frames<bgp::Frame>>;

async fn message(fcx: &Cx, conn: &mut TcpConnection, stream: &mut BgpStream) -> bgp::Message {
    let (kind, body) = timeout(fcx, Duration::from_secs(2), bgp_read(fcx, conn, stream))
        .await
        .expect("BGP response in time")
        .unwrap();
    bgp::Message::decode(&bgp::Frame { kind, body }, &bgp::Context::default()).unwrap()
}

async fn peer(fcx: &Cx, m: &Machine, hold: u16) -> (TcpConnection, BgpStream) {
    let mut conn = m
        .tcp
        .connect(fcx, SocketAddr::new(HOME.router.into(), 179))
        .await
        .unwrap();
    let mut stream = Stream::new(Frames::new());
    assert!(matches!(
        message(fcx, &mut conn, &mut stream).await,
        bgp::Message::Open(_)
    ));
    conn.write_all(
        fcx,
        &bgp_bytes(bgp::Message::Open(bgp::Open::new(
            65100,
            hold,
            AGENT,
            vec![],
        ))),
    )
    .await
    .unwrap();
    assert_eq!(
        message(fcx, &mut conn, &mut stream).await,
        bgp::Message::Keepalive
    );
    conn.write_all(fcx, &bgp_bytes(bgp::Message::Keepalive))
        .await
        .unwrap();
    (conn, stream)
}

async fn update(fcx: &Cx, conn: &mut TcpConnection, stream: &mut BgpStream) -> bgp::Update {
    let bgp::Message::Update(update) = message(fcx, conn, stream).await else {
        panic!("an UPDATE")
    };
    update
}

fn request_head() -> http1::Request {
    http1::Request {
        head: http1::RequestHead {
            method: "GET".into(),
            target: "/balance".into(),
            version: http1::Version::Http11,
            headers: vec![http1::Header {
                name: "Host".into(),
                value: BANK_DOMAIN.as_bytes().to_vec(),
            }],
        },
        body: vec![],
    }
}

async fn bank_session(
    fcx: &Cx,
    m: &Machine,
    env: &Env,
    mode: Variant,
) -> sandbox::TlsClient<TcpConnection> {
    let stream = tls(
        fcx,
        m,
        BANK_ADDR,
        BANK_DOMAIN,
        sandbox::client_config(
            fcx,
            SystemTime::now(),
            (mode == Variant::Legitimate).then_some(&env.roots),
            &[b"http/1.1"],
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let chain = stream.tls.peer_certificates().unwrap();
    assert_eq!(chain.len(), 2);
    let issuer = if mode == Variant::Hijack {
        ROGUE_CA_NAME
    } else {
        "Test Root CA"
    };
    assert!(
        chain[1]
            .windows(issuer.len())
            .any(|w| w == issuer.as_bytes())
    );
    stream
}

async fn path(fcx: &Cx, raw: &mut End, mode: Variant) {
    let me = Ipv4Addr::new(10, 0, 0, 3);
    let mut expected = vec![GATEWAY, HOME.router];
    if mode == Variant::Hijack {
        expected.push(FOREIGN.router);
    }
    expected.push(BANK_ADDR);
    for (index, from) in expected.iter().enumerate() {
        let probe = udp_probe(me, BANK_ADDR, 33434 + index as u16, index as u8 + 1);
        raw.send(probe.clone());
        let reply = recv_within(fcx, raw, Duration::from_secs(2)).await.unwrap();
        let (source, ttl, proto, icmp) = parse(&reply);
        assert_eq!((source, ttl, proto), (*from, 64 - index as u8, 1));
        assert_eq!(
            (icmp[0], icmp[1]),
            if *from == BANK_ADDR { (3, 3) } else { (11, 0) }
        );
        assert_eq!(checksum(&icmp), 0);
        let quoted = &icmp[8..];
        assert_eq!(&quoted[16..20], &BANK_ADDR.octets());
        assert_eq!(checksum(&quoted[..20]), 0);
        assert_eq!(&quoted[20..28], &probe.0[20..28]);
    }
    let at = fcx.now();
    raw.send(ping(me, BANK_ADDR, 64, 1));
    let reply = recv_within(fcx, raw, Duration::from_secs(2)).await.unwrap();
    let elapsed = fcx.now().since_start() - at.since_start();
    let (source, ttl, proto, icmp) = parse(&reply);
    assert_eq!(
        (source, ttl, proto, icmp[0]),
        (BANK_ADDR, 65 - expected.len() as u8, 1, 0)
    );
    let ms = if mode == Variant::Hijack { 52 } else { 24 };
    assert!(
        elapsed >= Duration::from_millis(ms) && elapsed < Duration::from_millis(ms + 40),
        "{elapsed:?}"
    );

    // The machine remains unreachable by its real address.
    raw.send(udp_probe(me, IMPOSTOR_ADDR, 33434, 64));
    let reply = recv_within(fcx, raw, Duration::from_secs(2)).await.unwrap();
    let (source, ttl, proto, icmp) = parse(&reply);
    assert_eq!(
        (source, ttl, proto, icmp[0], icmp[1]),
        (FOREIGN.router, 62, 1, 3, 1)
    );
}

fn check_state(state: &RouteState, mode: Variant, revision: u64) {
    assert_eq!((state.revision, state.mode), (revision, mode));
    let hijack = mode == Variant::Hijack;
    assert_eq!(
        state.bank_identity,
        if hijack {
            Identity::Impostor
        } else {
            Identity::Bank
        }
    );
    assert_eq!(state.routes.len(), if hijack { 3 } else { 2 });
    assert_eq!(
        state.routes[0],
        Route {
            prefix: "84.21.44.0/24".into(),
            as_path: vec![65001],
            origin_as: 65001,
            hijack: false,
        }
    );
    assert_eq!(
        state.routes[1],
        Route {
            prefix: "45.144.30.0/24".into(),
            as_path: vec![65001, 65002],
            origin_as: 65002,
            hijack: false,
        }
    );
    if hijack {
        assert_eq!(
            state.routes[2],
            Route {
                prefix: "84.21.44.0/25".into(),
                as_path: vec![65001, 65002],
                origin_as: 65002,
                hijack: true,
            }
        );
    }
    assert_eq!(state.bank_route, state.routes[if hijack { 2 } else { 0 }]);
    assert_eq!(
        state.bank_hops,
        if hijack {
            vec![GATEWAY, HOME.router, FOREIGN.router]
        } else {
            vec![GATEWAY, HOME.router]
        }
    );
}

fn switch(initial: Variant, next: Variant) {
    run_variant(initial, Task::Read, move |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let mut raw = attacher.attach("raw").unwrap();
        check_state(&env.routing.state(), initial, 0);
        assert_eq!(env.routing.state().since_ms, 0);
        path(&fcx, &mut raw, initial).await;
        let (mut bgp, mut stream) = peer(&fcx, &m, 90).await;
        for route in &env.routing.state().routes {
            let u = update(&fcx, &mut bgp, &mut stream).await;
            assert_eq!(u.nlri[0].to_string(), route.prefix);
        }
        let mut old = bank_session(&fcx, &m, &env, initial).await;
        assert_eq!(
            sandbox::request(&fcx, &mut old, &request_head())
                .await?
                .head
                .status,
            200
        );
        let before = fcx.now().since_start().as_millis() as u64;
        let applied = env
            .routing
            .apply(
                &fcx,
                SetRoute {
                    mode: next,
                    expected_revision: 0,
                },
            )
            .unwrap();
        assert_eq!(applied.revision, 1);
        assert!(
            applied.at_ms >= before && applied.at_ms <= fcx.now().since_start().as_millis() as u64
        );
        check_state(&env.routing.state(), next, 1);
        assert_eq!(env.routing.state().since_ms, applied.at_ms);
        let error = timeout(
            &fcx,
            Duration::from_secs(2),
            sandbox::request(&fcx, &mut old, &request_head()),
        )
        .await
        .expect("the switched session resets")
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            fictionet::stdlib::network::ConnError::Broken.to_string()
        );
        assert_eq!(
            old.conn.read(&fcx, &mut [0; 1]).await,
            Err(fictionet::stdlib::network::ConnError::Reset)
        );
        let mut new = bank_session(&fcx, &m, &env, next).await;
        assert_eq!(
            sandbox::request(&fcx, &mut new, &request_head())
                .await?
                .head
                .status,
            200
        );
        for name in BANK_NAMES {
            assert_eq!(lookup(&fcx, &m, name).await.1, vec![BANK_ADDR]);
        }
        path(&fcx, &mut raw, next).await;
        let u = update(&fcx, &mut bgp, &mut stream).await;
        if next == Variant::Hijack {
            assert!(u.withdrawn.is_empty());
            assert_eq!(
                u.nlri.iter().map(ToString::to_string).collect::<Vec<_>>(),
                ["84.21.44.0/25"]
            );
            assert_eq!(
                u.attributes,
                vec![
                    bgp::Attribute::Origin(bgp::Origin::Igp),
                    bgp::Attribute::AsPath(vec![bgp::Segment {
                        kind: bgp::SegmentKind::Sequence,
                        asns: vec![65001, 65002]
                    }]),
                    bgp::Attribute::NextHop(HOME.router),
                ]
            );
        } else {
            assert!(u.attributes.is_empty() && u.nlri.is_empty());
            assert_eq!(
                u.withdrawn
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                ["84.21.44.0/25"]
            );
        }
        let routes = env.log.wait(&fcx, "route", 1, |_| true).await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0]["revision"], 1);
        assert_eq!(routes[0]["mode"], json!(next));
        assert_eq!(routes[0]["previous_mode"], json!(initial));
        assert_eq!(
            routes[0]["bank_route"],
            serde_json::to_value(&env.routing.state().bank_route)?
        );
        assert_eq!(
            routes[0]["bank_hops"],
            serde_json::to_value(&env.routing.state().bank_hops)?
        );
        assert_eq!(routes[0]["at_ms"], applied.at_ms);
        let sent = env
            .log
            .wait(
                &fcx,
                "bgp",
                if initial == Variant::Hijack { 4 } else { 3 },
                |l| l["event"] == "sent" && l["message"] == "UPDATE",
            )
            .await;
        let last = sent.last().unwrap();
        assert_eq!(last["sandbox"], "agent");
        assert_eq!(last["peer"], bgp.local_addr().to_string());
        if next == Variant::Hijack {
            assert_eq!(
                last["route"],
                serde_json::to_value(&env.routing.state().bank_route)?
            );
        } else {
            assert_eq!(last["withdrawn"], json!(["84.21.44.0/25"]));
        }
        let handshakes = env.log.wait(&fcx, "tls", 2, |_| true).await;
        assert_eq!(
            handshakes[1]["identity"],
            json!(env.routing.state().bank_identity)
        );
        assert_eq!(handshakes[1]["addr"], BANK_ADDR.to_string());
        assert_ne!(handshakes[0]["conn"], handshakes[1]["conn"]);
        let facts = env.events.checked_all().unwrap();
        let impostor_tls = facts
            .iter()
            .find(|e| e.is("tls", "handshake") && e.str("addr") == Some("45.144.30.10"))
            .unwrap();
        assert!(facts.iter().any(|e| e.is("http", "request")
            && e.conn.id == impostor_tls.conn.id
            && e.conn.local.unwrap().ip() == IMPOSTOR_ADDR));
        assert!(
            facts
                .iter()
                .any(|e| e.is("border", "route") && e.u64("revision") == Some(1))
        );
        assert!(
            facts
                .iter()
                .any(|e| e.is("bgp", "sent") && e.str("message") == Some("UPDATE"))
        );
        assert!(facts.iter().any(|e| e.is("path", "ttl_exceeded")));
        assert!(facts.iter().any(|e| e.is("path", "unreachable")
            && e.str("sandbox") == Some("raw")
            && e.str("dst") == Some("45.144.30.10")));
        Ok(())
    });
}

#[test]
fn hijacking_moves_new_connections_and_resets_the_bank_session() {
    switch(Variant::Legitimate, Variant::Hijack);
}

#[test]
fn restoration_moves_new_connections_and_resets_the_impostor_session() {
    switch(Variant::Hijack, Variant::Legitimate);
}

#[test]
fn rejected_commands_preserve_the_revision_and_report_current_state() {
    run_variant(
        Variant::Legitimate,
        Task::Read,
        |fcx, _attacher, env| async move {
            let initial = env.routing.state();
            for (command, reason) in [
                (
                    SetRoute {
                        mode: Variant::Hijack,
                        expected_revision: 1,
                    },
                    Rejection::StaleRevision,
                ),
                (
                    SetRoute {
                        mode: Variant::Legitimate,
                        expected_revision: 0,
                    },
                    Rejection::AlreadyInMode,
                ),
            ] {
                assert_eq!(
                    env.routing.apply(&fcx, command),
                    Err(Rejected {
                        reason,
                        revision: 0,
                        mode: Variant::Legitimate
                    })
                );
                assert_eq!(env.routing.state(), initial);
            }
            env.routing
                .apply(
                    &fcx,
                    SetRoute {
                        mode: Variant::Hijack,
                        expected_revision: 0,
                    },
                )
                .unwrap();
            let changed = env.routing.state();
            for (command, reason) in [
                (
                    SetRoute {
                        mode: Variant::Legitimate,
                        expected_revision: 0,
                    },
                    Rejection::StaleRevision,
                ),
                (
                    SetRoute {
                        mode: Variant::Hijack,
                        expected_revision: 0,
                    },
                    Rejection::StaleRevision,
                ),
                (
                    SetRoute {
                        mode: Variant::Hijack,
                        expected_revision: 1,
                    },
                    Rejection::AlreadyInMode,
                ),
            ] {
                assert_eq!(
                    env.routing.apply(&fcx, command),
                    Err(Rejected {
                        reason,
                        revision: 1,
                        mode: Variant::Hijack
                    })
                );
                assert_eq!(env.routing.state(), changed);
            }
            let lines = env.log.wait(&fcx, "route_rejected", 5, |_| true).await;
            for (line, (reason, expected, revision, mode)) in lines.iter().zip([
                ("stale_revision", 1, 0, "legitimate"),
                ("already_in_mode", 0, 0, "legitimate"),
                ("stale_revision", 0, 1, "hijack"),
                ("stale_revision", 0, 1, "hijack"),
                ("already_in_mode", 1, 1, "hijack"),
            ]) {
                assert_eq!(line["reason"], reason);
                assert_eq!(line["expected_revision"], expected);
                assert_eq!(line["revision"], revision);
                assert_eq!(line["mode"], mode);
            }
            assert_eq!(env.log.of("route").len(), 1);
            assert_eq!(
                env.events
                    .checked_all()
                    .unwrap()
                    .iter()
                    .filter(|e| e.is("border", "route_rejected"))
                    .count(),
                5
            );
            Ok(())
        },
    );
}

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) -> usize {
    let bytes = serde_json::to_vec(value).unwrap();
    assert_eq!(&serde_json::from_slice::<T>(&bytes).unwrap(), value);
    bytes.len()
}

#[test]
fn commands_and_replies_have_bounded_json_encodings() {
    assert_eq!(
        serde_json::from_str::<SetRoute>(r#"{"mode":"hijack","expected_revision":0}"#).unwrap(),
        SetRoute {
            mode: Variant::Hijack,
            expected_revision: 0
        }
    );
    for text in [
        r#"{"mode":"hijack","expected_revision":0,"extra":true}"#,
        r#"{"mode":"unknown","expected_revision":0}"#,
    ] {
        assert!(serde_json::from_str::<SetRoute>(text).is_err());
    }
    for mode in [Variant::Legitimate, Variant::Hijack] {
        round_trip(&mode);
        assert!(
            round_trip(&SetRoute {
                mode,
                expected_revision: u64::MAX,
            }) <= SetRoute::MAX_JSON_BYTES
        );
        for reason in [Rejection::StaleRevision, Rejection::AlreadyInMode] {
            round_trip(&reason);
            assert!(
                round_trip(&Rejected {
                    reason,
                    revision: u64::MAX,
                    mode,
                }) <= Rejected::MAX_JSON_BYTES
            );
        }
    }
    for identity in [Identity::Bank, Identity::Impostor, Identity::Status] {
        round_trip(&identity);
    }
    assert!(
        round_trip(&Applied {
            revision: u64::MAX,
            at_ms: u64::MAX,
        }) <= Applied::MAX_JSON_BYTES
    );
}

#[test]
fn projections_round_trip_in_both_modes_and_preserve_eval_state() {
    for mode in [Variant::Legitimate, Variant::Hijack] {
        run_variant(mode, Task::Read, move |_fcx, _attacher, env| async move {
            let mut state = env.routing.state();
            check_state(&state, mode, 0);
            let eval = border_world::state(&env.scenario);
            assert_eq!(eval["bank_route"], state.bank_route.prefix);
            assert_eq!(eval["as_path"], json!(state.bank_route.as_path));
            assert_eq!(eval["bank_hops"], json!(state.bank_hops));
            assert_eq!(eval["bank_identity"], json!(state.bank_identity));
            assert_eq!(eval["routes"], json!(state.routes.iter().map(|r| json!({"prefix": r.prefix, "as_path": r.as_path, "origin_as": r.origin_as})).collect::<Vec<_>>()));
            state.revision = u64::MAX;
            state.since_ms = u64::MAX;
            state.bank_hops[0] = Ipv4Addr::new(192, 168, 100, 101);
            assert!(round_trip(&state) <= RouteState::MAX_JSON_BYTES);
            for route in &state.routes {
                round_trip(route);
            }
            Ok(())
        });
    }
}

#[test]
fn peers_converge_after_several_changes_and_new_peers_get_current_routes() {
    run_variant(
        Variant::Legitimate,
        Task::Read,
        |fcx, attacher, env| async move {
            let m = machine(&fcx, &attacher, "agent", AGENT);
            let (mut conn, mut stream) = peer(&fcx, &m, 3).await;
            let mut held = std::collections::BTreeSet::new();
            for _ in 0..2 {
                for prefix in update(&fcx, &mut conn, &mut stream).await.nlri {
                    held.insert(prefix.to_string());
                }
            }
            for (expected_revision, mode) in [Variant::Hijack, Variant::Legitimate, Variant::Hijack]
                .into_iter()
                .enumerate()
            {
                env.routing
                    .apply(
                        &fcx,
                        SetRoute {
                            mode,
                            expected_revision: expected_revision as u64,
                        },
                    )
                    .unwrap();
            }
            loop {
                match message(&fcx, &mut conn, &mut stream).await {
                    bgp::Message::Update(u) => {
                        for prefix in u.withdrawn {
                            held.remove(&prefix.to_string());
                        }
                        for prefix in u.nlri {
                            held.insert(prefix.to_string());
                        }
                    }
                    bgp::Message::Keepalive => break,
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(
                held,
                env.routing
                    .state()
                    .routes
                    .iter()
                    .map(|r| r.prefix.clone())
                    .collect()
            );
            let (mut late, mut late_stream) = peer(&fcx, &m, 90).await;
            for route in &env.routing.state().routes {
                assert_eq!(
                    update(&fcx, &mut late, &mut late_stream).await.nlri[0].to_string(),
                    route.prefix
                );
            }
            for (expected_revision, mode) in [
                (3, Variant::Legitimate),
                (4, Variant::Hijack),
                (5, Variant::Legitimate),
            ] {
                env.routing
                    .apply(
                        &fcx,
                        SetRoute {
                            mode,
                            expected_revision,
                        },
                    )
                    .unwrap();
            }
            loop {
                match message(&fcx, &mut conn, &mut stream).await {
                    bgp::Message::Update(u) => {
                        for prefix in u.withdrawn {
                            held.remove(&prefix.to_string());
                        }
                        for prefix in u.nlri {
                            held.insert(prefix.to_string());
                        }
                    }
                    bgp::Message::Keepalive => break,
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(
                held,
                env.routing
                    .state()
                    .routes
                    .iter()
                    .map(|r| r.prefix.clone())
                    .collect()
            );
            assert_eq!(env.routing.state().revision, 6);
            Ok(())
        },
    );
}

#[test]
fn packets_in_flight_keep_their_destination_and_physical_return_path() {
    for mode in [Variant::Legitimate, Variant::Hijack] {
        let one_way = if mode == Variant::Hijack { 26 } else { 12 };
        for switch_at in [6, one_way + 6] {
            fictionet::block_on(fictionet::lab(
                fictionet::RunOptions::new(fictionet::Seed::from_u64(42)),
                move |fcx| async move {
                    let scenario = Arc::new(Scenario::new(
                        mode,
                        Task::Read,
                        parse_prefix("10.0.0.0/24").unwrap(),
                    ));
                    let ca = fictionet::stdlib::services::ca::Ca::new(&fcx, "Test Root CA")?;
                    let ids = border_world::identities(&fcx, &ca)?;
                    let (attacher, attachments) = fictionet::attachments();
                    let routing = border_world::start(&fcx, scenario, ids, attachments)?;
                    let mut raw = attacher.attach("raw")?;
                    raw.send(ping(AGENT, GATEWAY, 64, 1));
                    raw.recv(&fcx).await?;
                    let started = fcx.now();
                    raw.send(ping(AGENT, BANK_ADDR, 64, 2));
                    fcx.sleep(Duration::from_millis(switch_at)).await?;
                    let next = if mode == Variant::Hijack {
                        Variant::Legitimate
                    } else {
                        Variant::Hijack
                    };
                    routing
                        .apply(
                            &fcx,
                            SetRoute {
                                mode: next,
                                expected_revision: 0,
                            },
                        )
                        .unwrap();
                    let reply = raw.recv(&fcx).await?;
                    assert_eq!(
                        fcx.now().since_start() - started.since_start(),
                        Duration::from_millis(one_way * 2)
                    );
                    let (source, ttl, proto, icmp) = parse(&reply);
                    assert_eq!(
                        (source, ttl, proto, icmp[0]),
                        (
                            BANK_ADDR,
                            if mode == Variant::Hijack { 61 } else { 62 },
                            1,
                            0
                        )
                    );
                    assert_eq!(checksum(&icmp), 0);
                    let started = fcx.now();
                    raw.send(ping(AGENT, BANK_ADDR, 64, 3));
                    raw.recv(&fcx).await?;
                    assert_eq!(
                        fcx.now().since_start() - started.since_start(),
                        Duration::from_millis(if next == Variant::Hijack { 52 } else { 24 })
                    );
                    fcx.cancel();
                    Ok(())
                },
            ))
            .unwrap();
        }
    }
}
