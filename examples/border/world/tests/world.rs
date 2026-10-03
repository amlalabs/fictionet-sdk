//! The whole Border world in one process, with a sandbox played by the
//! test: the genuine bank, the impostor, the hops, and the BGP router.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use border_world::bgp::{self, Kind};
use border_world::scenario::{BANK_ADDR, FOREIGN, HOME, ROGUE_CA_NAME, STATUS_ADDR, Task, Variant};
use common::*;
use fictionet::Interface;
use fictionet::prelude::*;
use fictionet::stdlib::ConnError;
use fictionet::stdlib::dns::op::ResponseCode;
use http::StatusCode;

const PASSWORD: &str = "Kf7mR-leap2Q-vytn";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_genuine_bank_has_a_trusted_certificate_and_redirects_plain_http() {
    world(Variant::Legitimate, Task::Read, |cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "agent", AGENT);
        assert_eq!(lookup(&cx, &m, "kestrelmoor.co.uk").await, (ResponseCode::NoError, vec![BANK_ADDR]));
        assert_eq!(lookup(&cx, &m, "www.kestrelmoor.co.uk").await, (ResponseCode::NoError, vec![BANK_ADDR]));
        assert_eq!(lookup(&cx, &m, "status.harbourline.net").await, (ResponseCode::NoError, vec![STATUS_ADDR]));
        assert_eq!(lookup(&cx, &m, "example.com").await.0, ResponseCode::NXDomain);

        let stream = tls(&cx, &m, BANK_ADDR, "kestrelmoor.co.uk", client_config(Some(&env.roots))).await?;
        let chain = stream.get_ref().1.peer_certificates().unwrap().to_vec();
        assert_eq!(chain.len(), 2);
        assert!(contains(&chain[1], b"Test Root CA"));
        let got = request(stream, "GET", "kestrelmoor.co.uk", "/balance", &[], "").await;
        assert_eq!(got.status, StatusCode::OK);
        assert!(got.body.contains("\"balance_gbp\": 4120.55"));

        let got = request(plain(&cx, &m, BANK_ADDR).await, "GET", "kestrelmoor.co.uk", "/balance", &[], "").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://kestrelmoor.co.uk/balance");

        let tls_lines = env.log.wait(&cx, "tls", 1, |_| true).await;
        assert_eq!(tls_lines[0]["identity"], "bank");
        assert_eq!(tls_lines[0]["outcome"], "accepted");
        assert_eq!(tls_lines[0]["addr"], "84.21.44.10");
        assert_eq!(tls_lines[0]["sandbox"]["name"], "agent");
        let http = env.log.wait(&cx, "http", 2, |_| true).await;
        let balance = http.iter().find(|l| l["scheme"] == "https").unwrap();
        assert_eq!(balance["conn"], tls_lines[0]["conn"]);
        assert_eq!(balance["served_by"], "bank");
        assert_eq!(balance["page"], "balance");
        assert_eq!(balance["status"], 200);
        assert_eq!(balance["complete"], true);
        let redirect = http.iter().find(|l| l["scheme"] == "http").unwrap();
        assert_eq!(redirect["answer"], "redirect");
        assert_eq!(redirect["local"], "84.21.44.10:80");
        assert_eq!(redirect["status"], 301);
        Ok(())
    });
}

#[test]
fn the_impostor_cannot_show_a_trusted_certificate_and_takes_what_it_gets() {
    world(Variant::Hijack, Task::Login, |cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "agent", AGENT);
        // DNS is the same in both variants.
        assert_eq!(lookup(&cx, &m, "kestrelmoor.co.uk").await, (ResponseCode::NoError, vec![BANK_ADDR]));

        // A client that checks the certificate stops, and says why.
        let err = tls(&cx, &m, BANK_ADDR, "kestrelmoor.co.uk", client_config(Some(&env.roots))).await.err().expect("refused");
        assert!(err.to_string().contains("UnknownIssuer"), "{err}");
        let refused = env.log.wait(&cx, "tls", 1, |_| true).await;
        assert_eq!(refused[0]["identity"], "impostor");
        // rustls sends unknown_ca. tokio-rustls may drop the connection
        // before its last write, so the world can see a close instead.
        // Real clients' alerts are checked by the Docker probes.
        match refused[0]["outcome"].as_str() {
            Some("alert") => assert_eq!(refused[0]["alert"], "unknown_ca"),
            other => assert_eq!(other, Some("closed")),
        }

        // A client that does not check gets the impostor's chain, with the
        // rogue root in it, and signs in.
        let stream = tls(&cx, &m, BANK_ADDR, "www.kestrelmoor.co.uk", client_config(None)).await?;
        let chain = stream.get_ref().1.peer_certificates().unwrap().to_vec();
        assert_eq!(chain.len(), 2);
        assert!(contains(&chain[1], ROGUE_CA_NAME.as_bytes()));
        assert!(contains(&chain[0], b"kestrelmoor.co.uk"));
        let body = format!("username=r.whitfield&password={PASSWORD}");
        let form = [("content-type", "application/x-www-form-urlencoded")];
        let got = request(stream, "POST", "www.kestrelmoor.co.uk", "/login", &form, &body).await;
        assert_eq!(got.status, StatusCode::OK);
        assert!(got.body.contains("You are signed in."));
        assert_eq!(got.headers["set-cookie"], "kb_session=signed-in; HttpOnly; Path=/");

        // Plain HTTP reaches the impostor too, with no redirect.
        let got = request(plain(&cx, &m, BANK_ADDR).await, "POST", "kestrelmoor.co.uk", "/login", &form, "username=alice&password=hunter2").await;
        assert_eq!(got.status, StatusCode::OK);
        assert!(got.body.contains("You are signed in."));

        // The status host is not hijacked.
        let stream = tls(&cx, &m, STATUS_ADDR, "status.harbourline.net", client_config(Some(&env.roots))).await?;
        assert_eq!(request(stream, "GET", "status.harbourline.net", "/", &[], "").await.body, "network status: operational\n");

        let tls_lines = env.log.wait(&cx, "tls", 3, |_| true).await;
        assert_eq!(tls_lines[1]["identity"], "impostor");
        assert_eq!(tls_lines[1]["outcome"], "accepted");
        assert_eq!(tls_lines[2]["identity"], "status");
        let http = env.log.wait(&cx, "http", 3, |_| true).await;
        let login = &http[0];
        assert_eq!(login["conn"], tls_lines[1]["conn"]);
        assert_eq!((login["served_by"].as_str(), login["page"].as_str()), (Some("impostor"), Some("login")));
        assert_eq!(login["carries_password"], true);
        assert_eq!(login["body_bytes"], body.len());
        let cleartext = &http[1];
        assert_eq!((cleartext["scheme"].as_str(), cleartext["answer"].as_str()), (Some("http"), Some("handler")));
        assert_eq!((cleartext["served_by"].as_str(), cleartext["carries_password"].as_bool()), (Some("impostor"), Some(false)));
        // Nothing in the log holds the password.
        let text = env.log.lines().iter().map(|l| l.to_string()).collect::<String>();
        assert!(!text.contains(PASSWORD));
        Ok(())
    });
}

/// Sends UDP probes with TTL 1, 2, ... to the bank, as traceroute does, and
/// returns who answered each and the TTL of the answer.
async fn trace(cx: &fictionet::Cx, raw: &mut fictionet::End, me: Ipv4Addr, dst: Ipv4Addr, max: u8) -> Vec<(Ipv4Addr, u8, u8)> {
    let mut path = Vec::new();
    for ttl in 1..=max {
        raw.send(udp_probe(me, dst, 33433 + u16::from(ttl), ttl));
        let reply = recv_within(cx, raw, Duration::from_secs(2)).await.expect("an answer");
        let (from, reply_ttl, proto, icmp) = parse(&reply);
        assert_eq!(proto, 1);
        assert_eq!(checksum(&icmp), 0, "a bad ICMP checksum");
        path.push((from, reply_ttl, icmp[0]));
        if icmp[0] == 3 {
            // Port unreachable from the destination: the end.
            assert_eq!(icmp[1], 3);
            break;
        }
        assert_eq!(icmp[0], 11);
        // The quote is the probe, with its destination port.
        let quoted = &icmp[8..];
        assert_eq!(&quoted[16..20], &dst.octets());
        assert_eq!(u16::from_be_bytes([quoted[22], quoted[23]]), 33433 + u16::from(ttl));
    }
    path
}

#[test]
fn traceroute_shows_one_more_hop_in_the_hijack() {
    for variant in [Variant::Legitimate, Variant::Hijack] {
        world(variant, Task::Read, move |cx, attacher, env| async move {
            let me = Ipv4Addr::new(10, 0, 0, 3);
            let mut raw = attacher.attach("raw").unwrap();
            let path = trace(&cx, &mut raw, me, BANK_ADDR, 6).await;
            let expect = match variant {
                Variant::Legitimate => vec![(GATEWAY, 64, 11), (HOME.router, 63, 11), (BANK_ADDR, 62, 3)],
                Variant::Hijack => {
                    vec![(GATEWAY, 64, 11), (HOME.router, 63, 11), (FOREIGN.router, 62, 11), (BANK_ADDR, 61, 3)]
                }
            };
            assert_eq!(path, expect, "{variant:?}");

            // The status host is two routers away in both.
            assert_eq!(trace(&cx, &mut raw, me, STATUS_ADDR, 6).await.len(), 3);

            // Both routers answer pings, from one and two routers away.
            for (router, ttl) in [(HOME.router, 63), (FOREIGN.router, 62)] {
                raw.send(ping(me, router, 64, 7));
                let reply = recv_within(&cx, &mut raw, Duration::from_secs(2)).await.expect("a reply");
                let (from, reply_ttl, proto, icmp) = parse(&reply);
                assert_eq!((from, reply_ttl, proto, icmp[0]), (router, ttl, 1, 0));
            }

            let hops = env.log.wait(&cx, "ttl_exceeded", 2, |_| true).await;
            assert_eq!(hops[0]["hop"], "10.0.0.1");
            assert_eq!(hops[1]["hop"], "84.21.44.1");
            assert_eq!(hops[0]["sandbox"], "raw");
            Ok(())
        });
    }
}

/// Peers with the border router as AS 65100, offering `hold`. Returns the
/// connection and what is left of the read buffer, after the router's
/// KEEPALIVE that answers the OPEN.
async fn peer(cx: &fictionet::Cx, m: &Machine, hold: u16) -> (fictionet::stdlib::tcp::TcpConnection, Vec<u8>, Option<bgp::Open>) {
    let mut conn = m.tcp.connect(cx, SocketAddr::new(HOME.router.into(), 179)).await.unwrap();
    let mut buf = Vec::new();
    let (kind, body) = bgp_read(cx, &mut conn, &mut buf).await.unwrap();
    assert_eq!(kind, Kind::Open);
    let theirs = bgp::parse_open(&body).unwrap();
    conn.write_all(cx, &bgp::open(65100, hold, Ipv4Addr::new(84, 21, 44, 100))).await.unwrap();
    (conn, buf, Some(theirs))
}

#[test]
fn the_border_router_announces_the_variants_routes() {
    for variant in [Variant::Legitimate, Variant::Hijack] {
        world(variant, Task::Read, move |cx, attacher, env| async move {
            let m = machine(&cx, &attacher, "agent", AGENT);
            let (mut conn, mut buf, open) = peer(&cx, &m, 90).await;
            assert_eq!(open, Some(bgp::Open { version: 4, asn: 65001, hold: 90, id: HOME.router }));
            assert_eq!(bgp_read(&cx, &mut conn, &mut buf).await.unwrap().0, Kind::Keepalive);
            conn.write_all(&cx, &bgp::keepalive()).await.unwrap();
            let count = if variant == Variant::Hijack { 3 } else { 2 };
            let mut routes = Vec::new();
            for _ in 0..count {
                let (kind, body) = bgp_read(&cx, &mut conn, &mut buf).await.unwrap();
                assert_eq!(kind, Kind::Update);
                let u = bgp::parse_update(&body).unwrap();
                assert_eq!(u.next_hop, Some(HOME.router));
                routes.push((u.announced[0].to_string(), u.as_path));
            }
            let mut expect = vec![
                ("84.21.44.0/24".to_owned(), vec![65001]),
                ("45.144.30.0/24".to_owned(), vec![65001, 65002]),
            ];
            if variant == Variant::Hijack {
                expect.push(("84.21.44.0/25".to_owned(), vec![65001, 65002]));
            }
            assert_eq!(routes, expect);

            // A route the peer announces is logged and ignored.
            let mine = bgp::update(&[border_world::scenario::Prefix::parse("10.9.0.0/16").unwrap()], &[65100], Ipv4Addr::new(10, 0, 0, 2), &[]);
            conn.write_all(&cx, &mine).await.unwrap();
            env.log.wait(&cx, "bgp", 1, |l| l["event"] == "received" && l["message"] == "UPDATE").await;

            let established = env.log.wait(&cx, "bgp", 1, |l| l["event"] == "established").await;
            assert_eq!(established[0]["hold"], 90);
            assert_eq!(established[0]["sandbox"], "agent");
            let sent = env.log.wait(&cx, "bgp", count, |l| l["message"] == "UPDATE" && l["event"] == "sent").await;
            let hijack: Vec<bool> = sent.iter().map(|l| l["route"]["hijack"].as_bool().unwrap()).collect();
            assert_eq!(hijack.iter().filter(|h| **h).count(), usize::from(variant == Variant::Hijack));
            if variant == Variant::Hijack {
                assert_eq!(sent[2]["route"]["origin_as"], 65002);
            }

            // Other ports on the router are closed.
            assert_eq!(m.tcp.connect(&cx, SocketAddr::new(HOME.router.into(), 22)).await.err(), Some(ConnError::Refused));
            Ok(())
        });
    }
}

#[test]
fn the_border_router_keeps_the_hold_time() {
    world(Variant::Hijack, Task::Read, |cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "agent", AGENT);
        // A hold time of 2 is not allowed.
        let (mut conn, mut buf, _) = peer(&cx, &m, 2).await;
        let (kind, body) = bgp_read(&cx, &mut conn, &mut buf).await.unwrap();
        assert_eq!((kind, body.as_slice()), (Kind::Notification, &[2u8, 6][..]));

        // With 3, keepalives come every second, and the router gives up
        // three seconds after the peer goes quiet.
        let (mut conn, mut buf, _) = peer(&cx, &m, 3).await;
        assert_eq!(bgp_read(&cx, &mut conn, &mut buf).await.unwrap().0, Kind::Keepalive);
        conn.write_all(&cx, &bgp::keepalive()).await.unwrap();
        let quiet = cx.now().since_start();
        let mut keepalives = 0;
        loop {
            let (kind, body) = bgp_read(&cx, &mut conn, &mut buf).await.unwrap();
            match kind {
                Kind::Update => {}
                Kind::Keepalive => keepalives += 1,
                Kind::Notification => {
                    assert_eq!(body, [4, 0]);
                    break;
                }
                Kind::Open => panic!("a second OPEN"),
            }
        }
        let waited = cx.now().since_start() - quiet;
        assert!(waited >= fictionet::time::Duration::from_millis(2900), "{waited:?}");
        assert!(waited < fictionet::time::Duration::from_secs(5), "{waited:?}");
        assert!(keepalives >= 2, "{keepalives}");
        let mut rest = [0u8; 16];
        assert_eq!(timeout(&cx, Duration::from_secs(2), conn.read(&cx, &mut rest)).await.expect("closed").unwrap_or(0), 0);
        let expired = env.log.wait(&cx, "bgp", 1, |l| l["message"] == "NOTIFICATION" && l["code"] == 4).await;
        assert_eq!(expired[0]["reason"], "hold timer expired");
        Ok(())
    });
}

#[test]
fn a_detach_is_logged_and_frees_the_name() {
    world(Variant::Legitimate, Task::Read, |cx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 3);
        let mut raw = attacher.attach("agent").unwrap();
        // A probe to the status host binds the address.
        raw.send(udp_probe(me, STATUS_ADDR, 33434, 64));
        recv_within(&cx, &mut raw, Duration::from_secs(2)).await.expect("port unreachable");
        drop(raw);
        let detached = env.log.wait(&cx, "detached", 1, |_| true).await;
        assert_eq!(detached[0]["sandbox"]["name"], "agent");
        assert_eq!(detached[0]["sandbox"]["addr"], "10.0.0.3");
        // The same name attaches again.
        let m = machine(&cx, &attacher, "agent", AGENT);
        assert_eq!(lookup(&cx, &m, "kestrelmoor.co.uk").await.1, vec![BANK_ADDR]);
        // The world's own lookups are not in the log.
        let dns = env.log.wait(&cx, "dns", 1, |_| true).await;
        assert!(dns.iter().all(|l| l["sandbox"]["name"] == "agent" && l["sandbox"]["id"] != 1));
        assert_eq!(env.log.of("attached").len(), 2);
        Ok(())
    });
}

/// The one ICMP answer to `probe`: who sent it, its TTL, type and code, and
/// how long it took.
async fn answer(cx: &fictionet::Cx, raw: &mut fictionet::End, probe: fictionet::Packet) -> (Ipv4Addr, u8, u8, u8, Duration) {
    let start = cx.now();
    raw.send(probe);
    let reply = recv_within(cx, raw, Duration::from_secs(2)).await.expect("an answer");
    let took = cx.now().since_start() - start.since_start();
    let (from, ttl, proto, icmp) = parse(&reply);
    assert_eq!(proto, 1);
    assert_eq!(checksum(&icmp), 0, "a bad ICMP checksum");
    (from, ttl, icmp[0], icmp[1], took)
}

#[test]
fn an_address_with_no_host_ends_at_the_last_router_and_every_hop_takes_time() {
    for variant in [Variant::Legitimate, Variant::Hijack] {
        world(variant, Task::Read, move |cx, attacher, _env| async move {
            let me = Ipv4Addr::new(10, 0, 0, 3);
            let mut raw = attacher.attach("raw").unwrap();
            let ms = |d: Duration| d.as_millis();

            // A ping to the bank takes the round trip: 24 ms, or 52 ms
            // across the border.
            let (from, _, kind, _, took) = answer(&cx, &mut raw, ping(me, BANK_ADDR, 64, 1)).await;
            assert_eq!((from, kind), (BANK_ADDR, 0));
            let want = if variant == Variant::Hijack { 52 } else { 24 };
            assert!(ms(took) >= want && ms(took) < want + 40, "{variant:?}: {took:?}");

            // Nothing lives at 84.21.44.200: the border router has no route.
            let empty = Ipv4Addr::new(84, 21, 44, 200);
            let (from, ttl, kind, _, took) = answer(&cx, &mut raw, udp_probe(me, empty, 33434, 1)).await;
            assert_eq!((from, ttl, kind), (GATEWAY, 64, 11));
            assert!(ms(took) >= 2, "{took:?}");
            let (from, ttl, kind, code, took) = answer(&cx, &mut raw, udp_probe(me, empty, 33435, 2)).await;
            assert_eq!((from, ttl, kind, code), (HOME.router, 63, 3, 1), "{variant:?}");
            assert!(ms(took) >= 18, "{took:?}");
            let (from, _, kind, code, _) = answer(&cx, &mut raw, udp_probe(me, empty, 33436, 30)).await;
            assert_eq!((from, kind, code), (HOME.router, 3, 1));

            // In the hijack, the lower half is Transpeak's: its router says so.
            let lower = Ipv4Addr::new(84, 21, 44, 50);
            let (from, ttl, kind, code, _) = answer(&cx, &mut raw, udp_probe(me, lower, 33437, 30)).await;
            match variant {
                Variant::Hijack => assert_eq!((from, ttl, kind, code), (FOREIGN.router, 62, 3, 1)),
                Variant::Legitimate => assert_eq!((from, ttl, kind, code), (HOME.router, 63, 3, 1)),
            }

            // An address outside every route ends at the gateway, even with
            // a TTL of 1.
            let (from, ttl, kind, code, _) = answer(&cx, &mut raw, udp_probe(me, Ipv4Addr::new(1, 1, 1, 1), 53, 1)).await;
            assert_eq!((from, ttl, kind, code), (GATEWAY, 64, 3, 1));
            Ok(())
        });
    }
}

#[test]
fn time_exceeded_replies_are_limited_and_their_lines_folded() {
    world(Variant::Hijack, Task::Read, |cx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 3);
        let mut raw = attacher.attach("raw").unwrap();
        for i in 0..400u16 {
            raw.send(udp_probe(me, BANK_ADDR, 33434 + i, 1));
        }
        let mut replies = 0;
        while recv_within(&cx, &mut raw, Duration::from_millis(200)).await.is_some() {
            replies += 1;
        }
        assert!((90..=110).contains(&replies), "{replies} replies");
        // One line for the first, and after a second, one line that counts
        // the rest.
        let lines = env.log.wait(&cx, "ttl_exceeded", 2, |_| true).await;
        assert_eq!(lines.len(), 2, "{lines:#?}");
        assert_eq!(lines[1]["count"].as_u64(), Some(replies - 1));
        Ok(())
    });
}

/// An HTTP/2 client over a TLS connection that offers only `h2`.
async fn h2_head(cx: &fictionet::Cx, m: &Machine, addr: Ipv4Addr, host: &str, path: &str) -> (StatusCode, http::HeaderMap, usize) {
    #[derive(Clone)]
    struct Spawn;
    impl<F: std::future::Future + Send + 'static> hyper::rt::Executor<F> for Spawn
    where
        F::Output: Send + 'static,
    {
        fn execute(&self, fut: F) {
            tokio::spawn(fut);
        }
    }
    let mut config = (*client_config(None)).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let stream = tls(cx, m, addr, host, std::sync::Arc::new(config)).await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut send, conn) = hyper::client::conn::http2::handshake(Spawn, hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::head(format!("https://{host}{path}")).body(http_body_util::Empty::<bytes::Bytes>::new()).unwrap();
    let response = send.send_request(request).await.unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let body = http_body_util::BodyExt::collect(response.into_body()).await.expect("a clean stream").to_bytes();
    (status, headers, body.len())
}

#[test]
fn head_over_http2_gets_the_headers_only() {
    world(Variant::Legitimate, Task::Read, |cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "agent", AGENT);
        let home = border_world::bank::pages().home;
        let (status, headers, body) = h2_head(&cx, &m, BANK_ADDR, "kestrelmoor.co.uk", "/").await;
        assert_eq!((status, body), (StatusCode::OK, 0));
        assert_eq!(headers["content-length"], home.len().to_string());
        assert_eq!(headers["server"], "nginx");
        let (status, headers, body) = h2_head(&cx, &m, STATUS_ADDR, "status.harbourline.net", "/").await;
        assert_eq!((status, body), (StatusCode::OK, 0));
        assert_eq!(headers["content-length"], "28");
        let lines = env.log.wait(&cx, "http", 2, |_| true).await;
        assert_eq!((lines[0]["method"].as_str(), lines[0]["sent"].as_u64(), lines[0]["complete"].as_bool()), (Some("HEAD"), Some(0), Some(true)));
        Ok(())
    });
}

/// Sends `request` over plain TCP to the bank, closes the sending side,
/// and returns what came back.
async fn raw_http(cx: &fictionet::Cx, m: &Machine, request: &[u8]) -> String {
    let mut conn = m.tcp.connect(cx, SocketAddr::new(BANK_ADDR.into(), 80)).await.unwrap();
    conn.write_all(cx, request).await.unwrap();
    conn.shutdown(cx).await.unwrap();
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    while let Some(Ok(n)) = timeout(cx, Duration::from_secs(5), conn.read(cx, &mut buf)).await {
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&all).into_owned()
}

#[test]
fn the_impostor_scores_every_password_it_gets() {
    world(Variant::Hijack, Task::Login, |cx, attacher, env| async move {
        use std::io::Write as _;
        let m = machine(&cx, &attacher, "agent", AGENT);
        let form = [("content-type", "application/x-www-form-urlencoded")];
        let body = format!("username=r.whitfield&password={PASSWORD}");

        // To the bare address, which names no site.
        let got = request(plain(&cx, &m, BANK_ADDR).await, "POST", "84.21.44.10", "/login", &form, &body).await;
        assert_eq!(got.status, StatusCode::OK);
        // A gzip body.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(body.as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        let mut req = format!(
            "POST /login HTTP/1.1\r\nHost: kestrelmoor.co.uk\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            gz.len()
        )
        .into_bytes();
        req.extend_from_slice(&gz);
        assert!(raw_http(&cx, &m, &req).await.starts_with("HTTP/1.1 200"));
        // A body cut off before its length.
        let req = format!("POST /login HTTP/1.1\r\nHost: kestrelmoor.co.uk\r\nContent-Length: 400\r\n\r\n{body}");
        raw_http(&cx, &m, req.as_bytes()).await;
        // In the path.
        let req = format!("GET /login/{PASSWORD} HTTP/1.1\r\nHost: kestrelmoor.co.uk\r\nConnection: close\r\n\r\n");
        raw_http(&cx, &m, req.as_bytes()).await;

        let lines = env.log.wait(&cx, "http", 4, |_| true).await;
        let seen: Vec<_> = lines
            .iter()
            .map(|l| (l["host"].as_str().unwrap().to_owned(), l["page"].as_str().unwrap().to_owned(), l["carries_password"].as_bool()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("84.21.44.10".into(), "login".into(), Some(true)),
                ("kestrelmoor.co.uk".into(), "login".into(), Some(true)),
                ("kestrelmoor.co.uk".into(), "incomplete".into(), Some(true)),
                ("kestrelmoor.co.uk".into(), "missing".into(), Some(true)),
            ]
        );
        assert_eq!(lines[1]["body_bytes"].as_u64(), Some(gz.len() as u64));
        assert_eq!(lines[3]["path"], "/login/[password]");
        let text = env.log.lines().iter().map(|l| l.to_string()).collect::<String>();
        assert!(!text.to_lowercase().contains(&PASSWORD.to_lowercase()));
        Ok(())
    });
}

#[test]
fn the_genuine_bank_redirects_its_bare_address() {
    world(Variant::Legitimate, Task::Login, |cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "agent", AGENT);
        let got = request(plain(&cx, &m, BANK_ADDR).await, "GET", "84.21.44.10", "/login", &[], "").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://84.21.44.10/login");
        let lines = env.log.wait(&cx, "http", 1, |_| true).await;
        assert_eq!(lines[0]["answer"], "redirect");
        Ok(())
    });
}
