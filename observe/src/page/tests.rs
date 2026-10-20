use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server() -> Server {
    Page::new(
        "Test page",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .bind_loopback(0)
    .await
    .unwrap()
}

fn address(server: &Server) -> &str {
    server
        .url()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
}

fn bearer(server: &Server) -> String {
    format!(
        "Authorization: Bearer {}\r\n",
        server.url().split("#token=").nth(1).unwrap()
    )
}

async fn raw(server: &Server, wire: &[u8]) -> String {
    let mut conn = TcpStream::connect(address(server)).await.unwrap();
    conn.write_all(wire).await.unwrap();
    let mut bytes = Vec::new();
    conn.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

async fn request(server: &Server, method: &str, path: &str, extra: &str, body: &str) -> String {
    raw(
        server,
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            address(server),
            body.len()
        )
        .as_bytes(),
    )
    .await
}

fn status(response: &str, code: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {code} ")),
        "{response}"
    );
    for header in [
        "Content-Security-Policy:",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: no-referrer",
        "Cache-Control: no-store",
        "Cross-Origin-Opener-Policy: same-origin",
        "Cross-Origin-Resource-Policy: same-origin",
    ] {
        assert!(response.contains(header), "missing {header}: {response}");
    }
}

#[tokio::test]
async fn the_page_is_public_and_only_bearers_authenticate() {
    let server = server().await;
    status(&request(&server, "GET", "/", "", "").await, 200);
    status(&request(&server, "GET", "/page.mjs", "", "").await, 200);
    for path in [
        "/api/page",
        "/api/world",
        "/api/watch",
        "/api/keylog",
        "/api/pcap?link=e1",
        "/api/missing",
    ] {
        status(&request(&server, "GET", path, "", "").await, 401);
    }
    let token = server.url().split("#token=").nth(1).unwrap();
    status(
        &request(&server, "GET", &format!("/api/page?token={token}"), "", "").await,
        401,
    );
    status(
        &request(
            &server,
            "GET",
            "/api/page",
            &format!("Cookie: token={token}\r\n"),
            "",
        )
        .await,
        401,
    );
    status(
        &request(&server, "GET", "/api/page", &bearer(&server), "").await,
        200,
    );
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    status(
        &request(&server, "POST", "/api/bootstrap?token=x", &headers, "").await,
        409,
    );
    status(
        &request(&server, "POST", "/api/bootstrap", &headers, "").await,
        204,
    );
    for _ in 0..2 {
        status(
            &request(&server, "POST", "/api/bootstrap", &headers, "").await,
            204,
        );
    }
    for authorization in ["", "Authorization: Bearer wrong\r\n"] {
        status(
            &request(
                &server,
                "POST",
                "/api/bootstrap",
                &format!("{authorization}Origin: http://{}\r\n", address(&server)),
                "",
            )
            .await,
            401,
        );
    }
}

#[tokio::test]
async fn the_import_map_nonce_is_fresh_and_only_the_page_relaxes_style_elements() {
    let server = server().await;
    let first = request(&server, "GET", "/", "", "").await;
    let second = request(&server, "GET", "/", "", "").await;
    let nonce = |response: &str| {
        response
            .split_once("nonce=\"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_ne!(nonce(&first), nonce(&second));
    for response in [&first, &second] {
        status(response, 200);
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let value = nonce(response);
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(head.contains(&format!("script-src 'self' 'nonce-{value}';")));
        assert!(head.contains("style-src 'self'; style-src-elem 'self' 'unsafe-inline';"));
        assert!(!head.contains("sha256-"));
        assert!(!body.contains("PAGE_NONCE"));
        assert!(body.contains("type=\"importmap\""));
    }
    for path in ["/page.mjs", "/page.css", "/vendor/licenses", "/missing"] {
        let response = request(&server, "GET", path, "", "").await;
        let head = response.split_once("\r\n\r\n").unwrap().0;
        assert!(head.contains(http::SECURITY));
        assert!(!head.contains("nonce-"));
        assert!(!head.contains("unsafe-inline"));
    }
    for path in ["/shell.mjs", "/shell.css"] {
        status(&request(&server, "GET", path, "", "").await, 404);
    }
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    let response = request(&server, "POST", "/api/bootstrap", &headers, "").await;
    status(&response, 204);
    assert_eq!(response.split_once("\r\n\r\n").unwrap().1, "");
}

#[tokio::test]
async fn every_request_checks_the_exact_host_and_origin() {
    let server = server().await;
    let port = address(&server).split(':').nth(1).unwrap();
    for host in [
        "evil.example".into(),
        "127.0.0.1".into(),
        "localhost".into(),
        "127.0.0.1:1".into(),
        format!("127.0.0.2:{port}"),
        format!("[::1]:{port}"),
        format!("LOCALHOST:{port}"),
    ] {
        status(
            &raw(
                &server,
                format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
            )
            .await,
            403,
        );
    }
    for host in [format!("localhost:{port}"), address(&server).into()] {
        for origin in [
            format!("http://localhost:{port}"),
            format!("http://{}", address(&server)),
        ] {
            status(
                &raw(
                    &server,
                    format!("GET / HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\n\r\n")
                        .as_bytes(),
                )
                .await,
                200,
            );
        }
    }
    for headers in [
        "Origin: https://evil.example\r\n",
        "Origin: http://127.0.0.1:1\r\n",
        "Sec-Fetch-Site: cross-site\r\n",
        "Sec-Fetch-Site: same-site\r\n",
    ] {
        status(&request(&server, "GET", "/", headers, "").await, 403);
    }
    for method in ["POST", "DELETE"] {
        status(
            &request(&server, method, "/api/bootstrap", &bearer(&server), "").await,
            403,
        );
    }
    status(
        &request(
            &server,
            "GET",
            "/ws/screen/host",
            "Upgrade: websocket\r\n",
            "",
        )
        .await,
        403,
    );
}

#[tokio::test]
async fn duplicate_security_headers_and_oversized_requests_are_rejected() {
    let server = server().await;
    for name in [
        "Host",
        "Origin",
        "Authorization",
        "Cookie",
        "Sec-Fetch-Site",
        "Content-Length",
        "Upgrade",
    ] {
        let wire = format!(
            "GET / HTTP/1.1\r\n{name}: 0\r\n{}: 0\r\n\r\n",
            name.to_ascii_lowercase()
        );
        status(&raw(&server, wire.as_bytes()).await, 400);
    }
    for fields in [
        "Transfer-Encoding: chunked",
        "Transfer-Encoding: identity",
        "Content-Length: 65537",
        "Content-Length: -1",
        "Content-Length: 0, 0",
        "Host : value",
        "X: one\r\n two",
        "X: \x00",
    ] {
        status(
            &raw(
                &server,
                format!("GET / HTTP/1.1\r\n{fields}\r\n\r\n").as_bytes(),
            )
            .await,
            400,
        );
    }
    let wire = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nX: {}\r\n\r\n",
        address(&server),
        "x".repeat(http::MAX_HEAD)
    );
    // The parser also checks a complete oversized head without socket buffering.
    assert!(http::parse_request(wire.as_bytes()).is_none());
    status(&raw(&server, &wire.as_bytes()[..http::MAX_HEAD]).await, 400);
    status(
        &request(&server, "GET", "/", "", &"x".repeat(http::MAX_BODY)).await,
        200,
    );
}

#[test]
fn request_parsing_uses_only_the_first_head() {
    let first = b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n";
    let suffix =
        b"GET /api/page HTTP/1.1\r\nHost: localhost:1\r\nAuthorization: Bearer secret\r\n\r\n";
    let req = http::parse_request(&[first.as_slice(), suffix].concat()).unwrap();
    assert_eq!(req.host.as_deref(), Some("evil.example"));
    assert!(req.authorization.is_none());
    for line in [
        "GET /",
        "GET / HTTP/2.0",
        "GET / HTTP/1.1 extra",
        "GET  / HTTP/1.1",
        "GET\t/ HTTP/1.1",
        "G(ET / HTTP/1.1",
        "GET /#fragment HTTP/1.1",
        "GET http://localhost/ HTTP/1.1",
    ] {
        assert!(
            http::parse_request(format!("{line}\r\n\r\n").as_bytes()).is_none(),
            "{line}"
        );
    }
    for size in [http::MAX_HEAD - 1, http::MAX_HEAD, http::MAX_HEAD + 1] {
        let mut head = String::from("GET / HTTP/1.1\r\nX: ");
        head.push_str(&"x".repeat(size - head.len() - 4));
        head.push_str("\r\n\r\n");
        assert_eq!(
            http::parse_request(head.as_bytes()).is_some(),
            size <= http::MAX_HEAD
        );
    }
}

#[tokio::test]
async fn observation_routes_preserve_session_replies() {
    let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(5)).observer(dashboard.observer()),
        |cx| async move {
            cx.emit("fixture", "ready", |e| e.field("name", "guest"));
            Ok(())
        },
    ))
    .unwrap();
    let server = Page::new("Observation", dashboard.handle())
        .bind_loopback(0)
        .await
        .unwrap();
    for op in [
        "world", "graph", "counters", "events", "keylog", "link", "packet", "pcap",
    ] {
        let response = request(&server, "GET", &format!("/api/{op}"), &bearer(&server), "").await;
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let expected = dashboard.handle().session().request(
            1,
            &format!(r#"{{"op":"{op}"}}"#),
            std::time::Instant::now(),
            None,
        );
        assert_eq!(body.as_bytes(), expected[0].bytes, "{op}");
    }
    let watch = request(&server, "GET", "/api/watch?after=0", &bearer(&server), "").await;
    status(&watch, 200);
    assert!(watch.contains("event: snapshot\n"));
    assert!(watch.contains("event: event\n"));
    assert!(watch.contains("event: end\n"));
    let merged = request(
        &server,
        "GET",
        "/api/packets?link=e3,e7",
        &bearer(&server),
        "",
    )
    .await;
    status(&merged, 200);
    assert!(merged.contains("event: link_error\ndata: {\"link\":\"e3\","));
    assert!(merged.contains("event: link_error\ndata: {\"link\":\"e7\","));
    assert!(merged.contains("event: end\n"));
    let pcap = request(&server, "GET", "/api/pcap?link=e3,e7", &bearer(&server), "").await;
    status(&pcap, 404);
    assert!(pcap.contains("no capture for e3, e7"));
}

async fn first_event(server: &Server, path: &str) -> String {
    let mut conn = TcpStream::connect(address(server)).await.unwrap();
    conn.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            address(server),
            bearer(server)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut wire = Vec::new();
    loop {
        let mut chunk = [0; 1024];
        let n = conn.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0);
        wire.extend_from_slice(&chunk[..n]);
        if wire.windows(2).any(|w| w == b"\n\n") {
            return String::from_utf8(wire).unwrap();
        }
    }
}

#[tokio::test]
async fn state_routes_serve_snapshots_deltas_and_persistent_status() {
    let topic = StateTopic::new(StateLimits {
        max_bytes: 32,
        deltas: 2,
    });
    let at = fictionet::time::Instant::from_since_start(std::time::Duration::from_secs(2));
    topic.publish(at, &vec![1]).unwrap();
    topic.publish_with_delta(at, &vec![1, 2], &2).unwrap();
    let server = Page::new(
        "State",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .table("Numbers", topic.clone(), vec![Column::new("Number", "")])
    .bind_loopback(0)
    .await
    .unwrap();
    let response = request(&server, "GET", "/api/state/numbers", &bearer(&server), "").await;
    status(&response, 200);
    let snapshot: Snapshot<Vec<u32>> =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(snapshot.value, Some(vec![1, 2]));
    assert_eq!(snapshot.revision, 2);
    assert_eq!(snapshot.at, 2.0);
    let delta = first_event(&server, "/api/states/stream?topics=numbers&after=numbers:1").await;
    assert!(delta.contains("event: delta\n"));
    assert!(delta.contains("data: {\"topic\":\"numbers\",\"revision\":2,"));
    topic.publish_with_delta(at, &vec![1, 2, 3], &3).unwrap();
    topic.publish_with_delta(at, &vec![1, 2, 3, 4], &4).unwrap();
    assert!(
        first_event(&server, "/api/states/stream?topics=numbers&after=numbers:1")
            .await
            .contains("event: snapshot\n")
    );
    assert!(topic.publish(at, &vec![99; 50]).is_err());
    let response = request(&server, "GET", "/api/state/numbers", &bearer(&server), "").await;
    assert!(response.contains("\"too_large\":true"));
    assert!(response.contains("\"revision\":4"));
    assert!(response.contains("\"value\":[1,2,3,4]"));
}

/// Reads whole SSE events from a stream, skipping the response head and
/// heartbeat comments, until `count` more events have arrived.
async fn next_events(conn: &mut TcpStream, wire: &mut Vec<u8>, count: usize) -> Vec<String> {
    let mut events = Vec::new();
    loop {
        let text = String::from_utf8(wire.clone()).unwrap();
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        let blocks: Vec<&str> = body.split("\n\n").collect();
        // The last block is incomplete until its blank line arrives.
        let complete: Vec<String> = blocks[..blocks.len() - 1]
            .iter()
            .filter(|block| block.starts_with("event: "))
            .map(|block| block.to_string())
            .collect();
        if complete.len() >= events.len() + count {
            let consumed = body.rfind("\n\n").unwrap() + 2;
            let head = text.len() - body.len();
            wire.drain(head..head + consumed);
            events.extend(complete);
            return events;
        }
        let mut chunk = [0; 1024];
        let n = conn.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0, "the stream closed");
        wire.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn one_state_stream_carries_several_topics_and_rejects_bad_lists() {
    let first = StateTopic::new(StateLimits::default());
    let second = StateTopic::new(StateLimits::default());
    let at = fictionet::time::Instant::from_since_start(std::time::Duration::from_secs(2));
    first.publish(at, &vec![1]).unwrap();
    second.publish(at, &vec![2]).unwrap();
    second.publish(at, &vec![2, 3]).unwrap();
    let server = Page::new(
        "State",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .table("First", first.clone(), vec![Column::new("Number", "")])
    .table("Second", second.clone(), vec![Column::new("Number", "")])
    .bind_loopback(0)
    .await
    .unwrap();
    let mut conn = TcpStream::connect(address(&server)).await.unwrap();
    conn.write_all(
        format!(
            concat!(
                "GET /api/states/stream?topics=first,second&after=second:2 HTTP/1.1\r\n",
                "Host: {}\r\n{}\r\n",
            ),
            address(&server),
            bearer(&server)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut wire = Vec::new();
    // The second topic's cursor is current, so only the first gets a snapshot.
    let opening = next_events(&mut conn, &mut wire, 1).await;
    assert_eq!(opening.len(), 1);
    assert!(
        opening[0].starts_with("event: snapshot\n"),
        "{}",
        opening[0]
    );
    assert!(opening[0].contains("data: {\"topic\":\"first\",\"revision\":1,"));
    second.publish_with_delta(at, &vec![2, 3, 4], &4).unwrap();
    let delta = next_events(&mut conn, &mut wire, 1).await;
    assert_eq!(delta.len(), 1);
    assert!(delta[0].starts_with("event: delta\n"), "{}", delta[0]);
    assert!(delta[0].contains("{\"topic\":\"second\",\"revision\":3,"));
    assert!(delta[0].contains("\"delta\":4"));
    first.publish(at, &vec![5]).unwrap();
    let snapshot = next_events(&mut conn, &mut wire, 1).await;
    assert!(snapshot[0].contains("{\"topic\":\"first\",\"revision\":2,"));
    assert!(snapshot[0].contains("\"value\":[5]"));
    drop(conn);

    let many = vec!["first"; 65].join(",");
    for (query, code) in [
        ("", 400),
        ("topics=", 400),
        ("topics=first,,second", 400),
        ("topics=first,first", 400),
        ("topics=missing", 404),
        ("topics=first&topics=second", 400),
        ("topics=first&after=second:1", 400),
        ("topics=first&after=first:x", 400),
        ("topics=first&after=first", 400),
        ("topics=first&after=first:1,first:2", 400),
        ("topics=first&other=1", 400),
        (&format!("topics={many}"), 400),
    ] {
        let response = request(
            &server,
            "GET",
            &format!("/api/states/stream?{query}"),
            &bearer(&server),
            "",
        )
        .await;
        status(&response, code);
    }
    // There is one way to stream state.
    status(
        &request(
            &server,
            "GET",
            "/api/state/first/stream",
            &bearer(&server),
            "",
        )
        .await,
        404,
    );
}

#[derive(Deserialize)]
struct SetRoute {
    mode: String,
    expected_revision: u64,
}

#[tokio::test]
async fn commands_decode_bound_deduplicate_timeout_and_record_world_inputs() {
    let port = CommandPort::<SetRoute, serde_json::Value>::new(CommandLimits {
        queued: 1,
        requests: 2,
        timeout: std::time::Duration::ZERO,
    });
    let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
    let server = Page::new("Controls", dashboard.handle())
        .control(
            "Routing",
            port.clone(),
            vec![Action {
                label: "Direct".into(),
                command: serde_json::json!({"mode":"direct", "expected_revision":0}),
            }],
        )
        .bind_loopback(0)
        .await
        .unwrap();
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    let first = r#"{"request_id":"first","command":{"mode":"direct","expected_revision":0}}"#;
    let timeout = request(&server, "POST", "/api/command/routing", &headers, first).await;
    status(&timeout, 504);
    assert!(timeout.contains("the command may still apply; read the state before retrying"));
    status(
        &request(&server, "POST", "/api/command/routing", &headers, first).await,
        202,
    );
    let second = first.replace("first", "second");
    status(
        &request(&server, "POST", "/api/command/routing", &headers, &second).await,
        503,
    );
    let invalid =
        r#"{"request_id":"invalid","command":{"mode":"direct","expected_revision":"zero"}}"#;
    let error = request(&server, "POST", "/api/command/routing", &headers, invalid).await;
    status(&error, 400);
    assert!(error.contains("expected_revision"));
    // The world applies the command after the HTTP timeout, at its own time.
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(9)).observer(dashboard.observer()),
        |cx| async move {
            let input = port.recv().await.unwrap();
            assert_eq!(input.command.mode, "direct");
            assert_eq!(input.command.expected_revision, 0);
            input.reply(
                &cx,
                serde_json::json!({"revision":1,"at":cx.now().since_start().as_secs_f64()}),
            );
            assert!(port.try_recv().is_none());
            Ok(())
        },
    ))
    .unwrap();
    let completed = request(&server, "POST", "/api/command/routing", &headers, first).await;
    status(&completed, 200);
    let changed = first.replace("direct", "indirect");
    assert_eq!(
        request(&server, "POST", "/api/command/routing", &headers, &changed).await,
        completed
    );
    let events = request(&server, "GET", "/api/events", &bearer(&server), "").await;
    assert!(events.contains("\"source\":\"page\""), "{events}");
    assert!(events.contains("\"kind\":\"command\""));
    assert!(events.contains("\"request_id\":\"first\""));
    assert!(events.contains("\"mode\":\"direct\""));
}

#[tokio::test]
async fn the_command_cache_retains_pending_ids_and_evicts_completed_ids() {
    let port = CommandPort::<u32, u32>::new(CommandLimits {
        queued: 2,
        requests: 1,
        timeout: std::time::Duration::ZERO,
    });
    let server = Page::new(
        "Cache",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .control("Count", port.clone(), vec![])
    .bind_loopback(0)
    .await
    .unwrap();
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    let first = r#"{"request_id":"first","command":1}"#;
    let second = r#"{"request_id":"second","command":2}"#;
    status(
        &request(&server, "POST", "/api/command/count", &headers, first).await,
        504,
    );
    let command = port.try_recv().unwrap();
    // An input already received by the world still occupies the ID cache.
    status(
        &request(&server, "POST", "/api/command/count", &headers, second).await,
        503,
    );
    drop(command);
    let unavailable = request(&server, "POST", "/api/command/count", &headers, first).await;
    status(&unavailable, 409);
    assert!(unavailable.contains("unavailable"));
    status(
        &request(&server, "POST", "/api/command/count", &headers, second).await,
        504,
    );
    drop(port.try_recv().unwrap());
    // Completed IDs are evicted in insertion order at the configured bound.
    status(
        &request(&server, "POST", "/api/command/count", &headers, first).await,
        504,
    );
    assert_eq!(port.try_recv().unwrap().command, 1);
}

#[tokio::test]
async fn a_world_reply_reaches_the_waiting_http_caller() {
    let port = CommandPort::<u32, u32>::new(CommandLimits::default());
    let server = Page::new(
        "Reply",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .control("Count", port.clone(), vec![])
    .bind_loopback(0)
    .await
    .unwrap();
    let worker = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(3)),
            |cx| async move {
                let command = port.recv().await.unwrap();
                assert_eq!(command.command, 42);
                command.reject(&cx, Rejected::StaleRevision { current: 7 });
                Ok(())
            },
        ))
        .unwrap();
    });
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    let response = request(
        &server,
        "POST",
        "/api/command/count",
        &headers,
        r#"{"request_id":"count","command":42}"#,
    )
    .await;
    status(&response, 409);
    assert!(response.contains("\"reason\":\"stale_revision\",\"current\":7"));
    worker.join().unwrap();
}

#[tokio::test]
async fn invalid_declarations_fail_before_binding() {
    let page = || {
        Page::new(
            "Validation",
            crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
        )
    };
    let topic = || StateTopic::<Vec<u32>>::new(StateLimits::default());
    let duplicate =
        page()
            .table("Same Title", topic(), vec![])
            .table("Same title", topic(), vec![]);
    assert!(
        duplicate
            .bind_loopback(0)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("Same title")
    );
    for pointer in ["field", "/bad~", "/bad~2"] {
        let invalid = page().table("Rows", topic(), vec![Column::new("Value", pointer)]);
        assert!(
            invalid
                .bind_loopback(0)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains(pointer)
        );
    }
    let invalid = page().control(
        "Count",
        CommandPort::<u32, u32>::new(CommandLimits {
            queued: 0,
            ..CommandLimits::default()
        }),
        vec![],
    );
    assert!(
        invalid
            .bind_loopback(0)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("CommandPort::new")
    );
    let invalid = page().control(
        "Count",
        CommandPort::<u32, u32>::new(CommandLimits::default()),
        vec![Action {
            label: "Increment".into(),
            command: "bad".into(),
        }],
    );
    assert!(
        invalid
            .bind_loopback(0)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("Increment")
    );
    assert!(
        page()
            .control_state(topic())
            .bind_loopback(0)
            .await
            .is_err()
    );
    let invalid = page()
        .control(
            "Count",
            CommandPort::<u32, u32>::new(CommandLimits::default()),
            vec![],
        )
        .control_state(topic())
        .control_state(topic());
    assert!(
        invalid
            .bind_loopback(0)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("twice")
    );
}

#[tokio::test]
async fn split_heads_preserve_bodies_and_the_deadline_is_bounded() {
    struct Segments<'a>(std::collections::VecDeque<&'a [u8]>);
    impl tokio::io::AsyncRead for Segments<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            out: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            while let Some(bytes) = self.0.pop_front() {
                if bytes.is_empty() {
                    continue;
                }
                let n = bytes.len().min(out.remaining());
                out.put_slice(&bytes[..n]);
                self.0.push_front(&bytes[n..]);
                break;
            }
            std::task::Poll::Ready(Ok(()))
        }
    }
    let head = b"POST /api/bootstrap HTTP/1.1\r\nHost: localhost:1\r\nContent-Length: 5\r\n\r\nhelloAuthorization: Bearer suffix\r\n\r\n";
    for split in 0..=head.len() {
        let mut input = Segments([&head[..split], &head[split..]].into());
        let req = http::read_request(&mut input, http::IO_TIMEOUT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(req.body, b"hello");
        assert!(req.authorization.is_none());
    }
    let (_writer, mut stalled) = tokio::io::duplex(16);
    assert!(
        http::read_request(&mut stalled, std::time::Duration::ZERO)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn packet_streams_merge_links_and_downloads_join_sections() {
    use fictionet::{Interface, InterfaceExt};
    let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(5)).observer(dashboard.observer()),
        |cx| async move {
            let (attacher, mut attachments) = fictionet::attachments();
            for name in ["one", "two"] {
                let mut sandbox = attacher.attach(name).unwrap();
                let mut attached = attachments.next(&cx).await?;
                sandbox.send(fictionet::Packet(vec![
                    0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0, 0, 0,
                    0x12, 0x34, 0, 1,
                ]));
                let packet = attached.recv(&cx).await?;
                attached.send(packet);
                for _ in 0..16 {
                    let mut packet = vec![0; 8192];
                    packet[..28].copy_from_slice(&[
                        0x45, 0, 0x20, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0,
                        0, 0, 0x12, 0x34, 0, 1,
                    ]);
                    sandbox.send(fictionet::Packet(packet));
                    attached.recv(&cx).await?;
                }
            }
            Ok(())
        },
    ))
    .unwrap();
    let server = Page::new("Packets", dashboard.handle())
        .host(Host::new("one"))
        .host(Host::new("two"))
        .bind_loopback(0)
        .await
        .unwrap();
    let response = request(
        &server,
        "GET",
        "/api/packets?link=e1,e2",
        &bearer(&server),
        "",
    )
    .await;
    status(&response, 200);
    for link in ["e1", "e2"] {
        assert!(
            response.contains(&format!(
                "event: packet\ndata: {{\"link\":\"{link}\",\"seq\":1,"
            )),
            "{response}"
        );
        assert!(response.contains(&format!("event: link_end\ndata: {{\"link\":\"{link}\",")));
        let detail = request(
            &server,
            "GET",
            &format!("/api/packet?link={link}&seq=1"),
            &bearer(&server),
            "",
        )
        .await;
        status(&detail, 200);
        assert!(detail.contains("Internet Protocol Version 4"));
    }
    let mut expected = Vec::new();
    let mut session = dashboard.handle().session();
    for link in ["e1", "e2"] {
        let mut values = session.request(
            1,
            &format!(r#"{{"op":"pcap","link":"{link}"}}"#),
            std::time::Instant::now(),
            None,
        );
        loop {
            let done = values.last().unwrap().end;
            for value in values {
                assert!(value.binary);
                expected.extend(value.bytes);
            }
            if done {
                break;
            }
            values = session.poll(std::time::Instant::now(), None);
        }
    }
    let mut conn = TcpStream::connect(address(&server)).await.unwrap();
    conn.write_all(
        format!(
            "GET /api/pcap?link=e1,e2 HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            address(&server),
            bearer(&server)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    conn.read_to_end(&mut response).await.unwrap();
    let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    status(std::str::from_utf8(&response[..end]).unwrap(), 200);
    assert!(
        expected.len() > 128 << 10,
        "both captures require multiple chunks"
    );
    assert!(
        !std::str::from_utf8(&response[..end])
            .unwrap()
            .contains("Content-Length:")
    );
    assert_eq!(response[end..], expected);
    let mut conn = TcpStream::connect(address(&server)).await.unwrap();
    conn.write_all(
        format!(
            "GET /api/export/packets HTTP/1.1\r\nHost: {}\r\n{}\r\n",
            address(&server),
            bearer(&server)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut exported = Vec::new();
    conn.read_to_end(&mut exported).await.unwrap();
    let end = exported.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    status(std::str::from_utf8(&exported[..end]).unwrap(), 200);
    assert_eq!(
        exported[end..],
        expected,
        "scope keeps captures after guest links close"
    );
}

#[tokio::test]
async fn linked_controls_insert_a_revision_for_action_validation() {
    let port = CommandPort::<SetRoute, ()>::new(CommandLimits {
        timeout: std::time::Duration::ZERO,
        ..CommandLimits::default()
    });
    let server = Page::new(
        "Routing",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .control(
        "Route",
        port.clone(),
        vec![Action {
            label: "Bank".into(),
            command: serde_json::json!({"mode":"bank"}),
        }],
    )
    .control_state(StateTopic::<u32>::new(StateLimits::default()))
    .bind_loopback(0)
    .await
    .unwrap();
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    status(
        &request(
            &server,
            "POST",
            "/api/command/route",
            &headers,
            r#"{"request_id":"route","command":{"mode":"bank","expected_revision":7}}"#,
        )
        .await,
        504,
    );
    let command = port.try_recv().unwrap();
    assert_eq!(command.command.mode, "bank");
    assert_eq!(command.command.expected_revision, 7);
    let invalid = Page::new(
        "Routing",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .control(
        "Route",
        port,
        vec![Action {
            label: "Bad action".into(),
            command: serde_json::json!(1),
        }],
    )
    .control_state(StateTopic::<u32>::new(StateLimits::default()))
    .bind_loopback(0)
    .await
    .err()
    .unwrap();
    assert!(invalid.to_string().contains("Bad action"));
}

#[test]
fn rfb_messages_survive_every_split_and_enforce_input_ownership() {
    use super::rfb::{Decision, Gateway};
    let mut encoding = vec![2, 0, 0, 1];
    encoding.extend_from_slice(&(-316i32).to_be_bytes());
    let mut clipboard = vec![6, 0, 0, 0];
    clipboard.extend_from_slice(&(-3i32).to_be_bytes());
    clipboard.extend_from_slice(b"abc");
    let messages = vec![
        (vec![0; 20], false),
        (encoding, false),
        (vec![3, 0, 0, 0, 0, 0, 0, 1, 0, 1], false),
        (vec![4, 1, 0, 0, 0, 0, 0, 65], true),
        (vec![5, 0, 0, 1, 0, 1], true),
        (vec![5, 128, 0, 1, 0, 1, 2], true),
        (clipboard, true),
        (vec![150, 1, 0, 0, 0, 0, 0, 1, 0, 1], false),
        (vec![248, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2], false),
        (vec![250, 0, 1, 1], true),
        ([vec![251, 0, 0, 1, 0, 1, 1, 0], vec![0; 16]].concat(), true),
        (vec![255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65], true),
    ];
    for version in [b"RFB 003.007\n", b"RFB 003.008\n"] {
        let mut wire = version.to_vec();
        wire.extend_from_slice(&[1, 0]);
        for (message, _) in &messages {
            wire.extend_from_slice(message);
        }
        for held in [false, true] {
            let mut expected = vec![
                Decision::Pass(version.to_vec()),
                Decision::Pass(vec![1]),
                Decision::Pass(vec![1]),
            ];
            expected.extend(messages.iter().map(|(bytes, input)| {
                if *input && !held {
                    Decision::Drop
                } else {
                    Decision::Pass(bytes.clone())
                }
            }));
            for split in 0..=wire.len() {
                let mut gateway = Gateway::default();
                let mut actual = gateway.feed(&wire[..split], || held);
                actual.extend(gateway.feed(&wire[split..], || held));
                assert_eq!(actual, expected, "split {split}");
            }
            let mut gateway = Gateway::default();
            let actual: Vec<_> = wire
                .iter()
                .flat_map(|b| gateway.feed(&[*b], || held))
                .collect();
            assert_eq!(actual, expected);
        }
    }
    for bad in [
        vec![1],
        vec![255, 1],
        vec![2, 0, 0, 65],
        vec![6, 0, 0, 0, 128, 0, 0, 0],
        vec![248, 0, 0, 0, 0, 0, 0, 0, 65],
    ] {
        let mut gateway = Gateway::default();
        gateway.feed(b"RFB 003.008\n\x01\x00", || false);
        assert!(matches!(
            gateway.feed(&bad, || true).last(),
            Some(Decision::Close(_))
        ));
        assert!(gateway.feed(&[3; 10], || true).is_empty());
    }
    assert!(matches!(
        Gateway::default().feed(b"RFB 003.003\n", || true).last(),
        Some(Decision::Close(_))
    ));
    let mut gateway = Gateway::default();
    gateway.feed(b"RFB 003.008\n", || false);
    assert!(matches!(
        gateway.feed(&[2], || false).last(),
        Some(Decision::Close(_))
    ));
}

#[derive(Clone, Default)]
struct FakeConsole {
    opens: Arc<std::sync::atomic::AtomicUsize>,
    peers: Arc<std::sync::Mutex<Vec<tokio::io::DuplexStream>>>,
    terminals: Arc<std::sync::atomic::AtomicUsize>,
    reads: Arc<std::sync::atomic::AtomicUsize>,
    closes: Arc<std::sync::atomic::AtomicUsize>,
    resizes: Arc<std::sync::Mutex<Vec<(u16, u16)>>>,
}
impl Console for FakeConsole {
    fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
        let fake = self.clone();
        Some(Box::pin(async move {
            fake.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (a, b) = tokio::io::duplex(2 << 20);
            fake.peers.lock().unwrap().push(b);
            Ok(Box::new(a) as Box<dyn Duplex>)
        }))
    }
    fn terminal(&self, _: u16, _: u16) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
        let fake = self.clone();
        Some(Box::pin(async move {
            fake.terminals
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (a, b) = tokio::io::duplex(2 << 20);
            fake.peers.lock().unwrap().push(b);
            let (read, write) = tokio::io::split(a);
            Ok(Box::new(FakePty {
                read,
                write: tokio::sync::Mutex::new(write),
                fake,
            }) as Box<dyn Pty>)
        }))
    }
}
struct FakePty {
    read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    write: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
    fake: FakeConsole,
}
impl Pty for FakePty {
    fn read(&mut self) -> BoxFuture<'_, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 64 << 10];
            let n = self.read.read(&mut bytes).await?;
            bytes.truncate(n);
            self.fake
                .reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((n > 0).then_some(bytes))
        })
    }
    fn write<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.write.lock().await.write_all(bytes).await })
    }
    fn resize(&self, cols: u16, rows: u16) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.fake.resizes.lock().unwrap().push((cols, rows));
            Ok(())
        })
    }
    fn close(&self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.fake
                .closes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

fn json_body(response: &str) -> serde_json::Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn origin(server: &Server) -> String {
    format!("{}Origin: http://{}\r\n", bearer(server), address(server))
}
async fn mint(server: &Server, host: &str, capability: &str) -> serde_json::Value {
    let response = request(
        server,
        "POST",
        "/api/ticket",
        &origin(server),
        &serde_json::json!({"host":host,"capability":capability}).to_string(),
    )
    .await;
    status(&response, 200);
    let body = json_body(&response);
    assert_eq!(body["expires_in"], 30);
    body
}

struct Ws {
    conn: TcpStream,
    messages: fictionet::stdlib::codec::Stream<fictionet::stdlib::protocols::websocket::Messages>,
}
use fictionet::stdlib::protocols::websocket::Message;
impl Ws {
    async fn connect(
        server: &Server,
        host: &str,
        capability: &str,
        ticket: &serde_json::Value,
        expected: u16,
    ) -> Self {
        let mut conn = TcpStream::connect(address(server)).await.unwrap();
        let fields =
            fictionet::stdlib::protocols::websocket::request_headers(address(server), [1; 16], &[])
                .unwrap();
        let mut head = format!(
            "GET /ws/{capability}/{host}?ticket={} HTTP/1.1\r\nOrigin: http://{}\r\n",
            ticket["ticket"].as_str().unwrap(),
            address(server)
        );
        for (name, value) in fields {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        conn.write_all(head.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        while !reply.ends_with(b"\r\n\r\n") {
            reply.push(conn.read_u8().await.unwrap());
        }
        status(std::str::from_utf8(&reply).unwrap(), expected);
        Self {
            conn,
            messages: fictionet::stdlib::codec::Stream::new(
                fictionet::stdlib::protocols::websocket::Messages::for_receiver(
                    fictionet::stdlib::codec::Side::Client,
                )
                .with_limit(2 << 20),
            ),
        }
    }
    async fn send(&mut self, message: Message) {
        use fictionet::stdlib::codec::Wire;
        let wire = message
            .to_frame(Some([1, 2, 3, 4]))
            .unwrap()
            .to_bytes()
            .unwrap();
        self.conn.write_all(&wire).await.unwrap();
    }
    async fn recv(&mut self) -> Message {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(message) = self.messages.next() {
                    return message.unwrap();
                }
                let n = self.conn.read(self.messages.spare()).await.unwrap();
                assert_ne!(n, 0);
                self.messages.commit(n);
            }
        })
        .await
        .unwrap()
    }
    async fn barrier(&mut self) {
        self.send(Message::Ping(vec![7])).await;
        assert_eq!(self.recv().await, Message::Pong(vec![7]));
    }
    async fn close(mut self) {
        self.send(Message::Close(None)).await;
        assert!(matches!(self.recv().await, Message::Close(_)));
        let mut bytes = Vec::new();
        self.conn.read_to_end(&mut bytes).await.unwrap();
    }
}

#[tokio::test]
async fn tickets_are_bound_single_use_expiring_and_bounded_before_console_open() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let a = FakeConsole::default();
    let b = FakeConsole::default();
    let server = Page::new(
        "Hosts",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .host(Host::new("alpha").console(a.clone()))
    .host(Host::new("beta").console(b.clone()))
    .clock(move || std::time::Duration::from_secs(now.load(Ordering::SeqCst)))
    .standard_panels()
    .bind_loopback(0)
    .await
    .unwrap();
    let ticket = mint(&server, "alpha", "screen").await;
    Ws::connect(&server, "beta", "screen", &ticket, 401).await;
    assert_eq!(a.opens.load(Ordering::SeqCst), 0);
    assert_eq!(b.opens.load(Ordering::SeqCst), 0);
    let ticket = mint(&server, "alpha", "screen").await;
    Ws::connect(&server, "alpha", "terminal", &ticket, 401).await;
    assert_eq!(a.terminals.load(Ordering::SeqCst), 0);
    let ticket = mint(&server, "alpha", "screen").await;
    clock.store(30, Ordering::SeqCst);
    Ws::connect(&server, "alpha", "screen", &ticket, 401).await;
    assert_eq!(a.opens.load(Ordering::SeqCst), 0);
    let ticket = mint(&server, "alpha", "screen").await;
    let mut ws = Ws::connect(&server, "alpha", "screen", &ticket, 101).await;
    ws.barrier().await;
    assert_eq!(a.opens.load(Ordering::SeqCst), 1);
    Ws::connect(&server, "alpha", "screen", &ticket, 401).await;
    ws.close().await;
    for _ in 0..64 {
        mint(&server, "beta", "screen").await;
    }
    status(
        &request(
            &server,
            "POST",
            "/api/ticket",
            &origin(&server),
            r#"{"host":"beta","capability":"screen"}"#,
        )
        .await,
        503,
    );
    clock.store(60, Ordering::SeqCst);
    mint(&server, "beta", "screen").await;
    assert_eq!(b.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn screen_input_follows_the_live_lease_and_disconnect_releases_it() {
    let fake = FakeConsole::default();
    let server = Page::new(
        "Screen",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .host(Host::new("host").console(fake.clone()))
    .bind_loopback(0)
    .await
    .unwrap();
    let a = mint(&server, "host", "screen").await;
    let b = mint(&server, "host", "screen").await;
    let mut first = Ws::connect(&server, "host", "screen", &a, 101).await;
    first.barrier().await;
    let mut peer = fake.peers.lock().unwrap().pop().unwrap();
    let mut second = Ws::connect(&server, "host", "screen", &b, 101).await;
    second.barrier().await;
    first
        .send(Message::Binary(b"RFB 003.008\n\x01\x00".to_vec()))
        .await;
    let mut handshake = [0; 14];
    peer.read_exact(&mut handshake).await.unwrap();
    assert_eq!(&handshake, b"RFB 003.008\n\x01\x01");
    let key = vec![4, 1, 0, 0, 0, 0, 0, 65];
    let flow = vec![3, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    first
        .send(Message::Binary([key.clone(), flow.clone()].concat()))
        .await;
    let mut bytes = vec![0; 10];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, flow);
    let claim = |session: &serde_json::Value, take: bool| {
        serde_json::json!({"host":"host","session":session["session"],"take":take}).to_string()
    };
    status(
        &request(
            &server,
            "POST",
            "/api/lease",
            &origin(&server),
            &claim(&a, false),
        )
        .await,
        200,
    );
    first.send(Message::Binary(key.clone())).await;
    let mut input = [0; 8];
    peer.read_exact(&mut input).await.unwrap();
    assert_eq!(input.as_slice(), key);
    status(
        &request(
            &server,
            "POST",
            "/api/lease",
            &origin(&server),
            &claim(&b, false),
        )
        .await,
        409,
    );
    status(
        &request(
            &server,
            "POST",
            "/api/lease",
            &origin(&server),
            &claim(&b, true),
        )
        .await,
        200,
    );
    let state = request(&server, "GET", "/api/state/leases", &bearer(&server), "").await;
    assert_eq!(json_body(&state)["value"]["host"]["holder"], b["session"]);
    assert!(
        first_event(&server, "/api/states/stream?topics=leases")
            .await
            .contains(b["session"].as_str().unwrap())
    );
    first
        .send(Message::Binary([key, flow.clone()].concat()))
        .await;
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, flow);
    peer.write_all(b"server bytes").await.unwrap();
    assert_eq!(
        first.recv().await,
        Message::Binary(b"server bytes".to_vec())
    );
    first.send(Message::Text("bad".into())).await;
    assert!(
        matches!(first.recv().await,Message::Close(Some(close)) if close.reason.contains("binary"))
    );
    second.close().await;
    let state = request(&server, "GET", "/api/state/leases", &bearer(&server), "").await;
    assert!(json_body(&state)["value"]["host"]["holder"].is_null());
    // A terminal's session names no screen, so it cannot hold the input lease.
    let shell = mint(&server, "host", "terminal").await;
    let mut terminal = Ws::connect(&server, "host", "terminal", &shell, 101).await;
    terminal.barrier().await;
    status(
        &request(
            &server,
            "POST",
            "/api/lease",
            &origin(&server),
            &claim(&shell, true),
        )
        .await,
        400,
    );
    terminal.close().await;
}

#[tokio::test]
async fn terminals_resize_echo_backpressure_and_close_with_session_bounds() {
    use std::sync::atomic::Ordering;
    let fake = FakeConsole::default();
    let server = Page::new(
        "Terminal",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .host(Host::new("host").console(fake.clone()))
    .bind_loopback(0)
    .await
    .unwrap();
    let mut sockets = Vec::new();
    for _ in 0..4 {
        let ticket = mint(&server, "host", "terminal").await;
        let mut ws = Ws::connect(&server, "host", "terminal", &ticket, 101).await;
        ws.barrier().await;
        sockets.push(ws);
    }
    let ticket = mint(&server, "host", "terminal").await;
    Ws::connect(&server, "host", "terminal", &ticket, 503).await;
    assert_eq!(fake.terminals.load(Ordering::SeqCst), 4);
    let mut ws = sockets.pop().unwrap();
    let mut peer = fake.peers.lock().unwrap().pop().unwrap();
    ws.send(Message::Binary(b"hello".to_vec())).await;
    let mut input = [0; 5];
    peer.read_exact(&mut input).await.unwrap();
    assert_eq!(&input, b"hello");
    ws.send(Message::Text(
        r#"{"type":"resize","cols":100,"rows":40}"#.into(),
    ))
    .await;
    ws.barrier().await;
    assert_eq!(*fake.resizes.lock().unwrap(), [(100, 40)]);
    peer.write_all(&vec![7; 256 << 10]).await.unwrap();
    for _ in 0..3 {
        assert_eq!(ws.recv().await, Message::Binary(vec![7; 64 << 10]));
    }
    ws.barrier().await;
    assert_eq!(fake.reads.load(Ordering::SeqCst), 3);
    ws.send(Message::Text(format!(
        r#"{{"type":"ack","bytes":{}}}"#,
        160 << 10
    )))
    .await;
    ws.barrier().await;
    assert_eq!(fake.reads.load(Ordering::SeqCst), 3);
    ws.send(Message::Text(r#"{"type":"ack","bytes":1}"#.into()))
        .await;
    assert_eq!(ws.recv().await, Message::Binary(vec![7; 64 << 10]));
    ws.close().await;
    assert_eq!(fake.closes.load(Ordering::SeqCst), 1);
    for ws in sockets {
        ws.close().await;
    }
    assert_eq!(fake.closes.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn two_hosts_publish_status_scope_links_and_filter_dashboard_events() {
    use fictionet::{Interface, InterfaceExt};
    let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
    let observer = dashboard.observer();
    let (ready, started) = tokio::sync::oneshot::channel();
    let world = std::thread::spawn(move || {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(2)).observer(observer),
            |cx| async move {
                let (attacher, mut attachments) = fictionet::attachments();
                let mut sandboxes = Vec::new();
                let mut links = Vec::new();
                for name in ["east", "west"] {
                    let mut sandbox = attacher.attach(name).unwrap();
                    let mut link = attachments.next(&cx).await?;
                    sandbox.send(fictionet::Packet(vec![0x45; 28]));
                    let packet = link.recv(&cx).await?;
                    link.send(packet);
                    sandboxes.push(sandbox);
                    links.push(link);
                }
                cx.emit("fixture", "request", |e| e.field("route", "bank"));
                cx.emit("fixture", "request", |e| e.field("route", "other"));
                cx.emit("fixture", "ready", |e| e.field("route", "bank"));
                assert!(ready.send((sandboxes, links)).is_ok());
                Ok(())
            },
        ))
        .unwrap()
    });
    let endpoints = started.await.unwrap();
    let a = FakeConsole::default();
    let b = FakeConsole::default();
    let status_topic = StateTopic::new(StateLimits::default());
    status_topic
        .publish(
            fictionet::time::Instant::from_since_start(std::time::Duration::ZERO),
            &HostStatus {
                state: HostState::DesktopUp,
                addresses: vec!["10.0.0.2".into()],
                screen: true,
                terminal: true,
            },
        )
        .unwrap();
    let server = Page::new("Two hosts", dashboard.handle())
        .host(
            Host::new("alpha")
                .sandbox("east")
                .console(a.clone())
                .status(status_topic),
        )
        .host(Host::new("beta").sandbox("west").console(b.clone()))
        .standard_panels()
        .event_table(
            "Requests",
            EventFilter {
                source: Some("fixture".into()),
                kind: Some("request".into()),
                field: Some(("route".into(), "bank".into())),
                host: None,
                kinds: vec![],
            },
            vec![Column::new("Route", "/fields/route")],
        )
        .moment(
            "Bank requested",
            EventFilter {
                source: Some("fixture".into()),
                kind: Some("request".into()),
                field: Some(("route".into(), "bank".into())),
                host: None,
                kinds: vec![],
            },
        )
        .custom(
            "Plant",
            "export function mount() { return () => {}; }",
            StateTopic::<u32>::new(StateLimits::default()),
        )
        .asset("plant/data.json", "application/json", b"{}".to_vec())
        .workspace("Plant")
        .bind_loopback(0)
        .await
        .unwrap();
    let page = request(&server, "GET", "/api/page", &bearer(&server), "").await;
    let description: PageDescription = serde_json::from_value(json_body(&page)).unwrap();
    assert_eq!(description.hosts.len(), 2);
    assert_eq!(description.hosts[0].sandbox, "east");
    assert_eq!(description.hosts[0].screen.as_deref(), Some("alpha-screen"));
    assert_eq!(
        description.hosts[1].terminal.as_deref(),
        Some("beta-terminal")
    );
    assert_eq!(
        description
            .panels
            .iter()
            .filter(|p| p.area == Area::Workspace)
            .map(|p| p.id.as_str())
            .collect::<Vec<_>>(),
        ["plant"]
    );
    let state = json_body(
        &request(
            &server,
            "GET",
            &description.hosts[0].status,
            &bearer(&server),
            "",
        )
        .await,
    );
    assert_eq!(state["value"]["state"], "desktop_up");
    assert_eq!(state["value"]["addresses"], serde_json::json!(["10.0.0.2"]));
    let east = json_body(
        &request(
            &server,
            "GET",
            "/api/host/alpha/links",
            &bearer(&server),
            "",
        )
        .await,
    );
    let west =
        json_body(&request(&server, "GET", "/api/host/beta/links", &bearer(&server), "").await);
    assert_eq!(east["links"], serde_json::json!(["e1"]));
    assert_eq!(west["links"], serde_json::json!(["e2"]));
    for (name, fake) in [("alpha", &a), ("beta", &b)] {
        for capability in ["screen", "terminal"] {
            let ticket = mint(&server, name, capability).await;
            let mut ws = Ws::connect(&server, name, capability, &ticket, 101).await;
            ws.barrier().await;
            ws.close().await;
        }
        assert_eq!(fake.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(fake.terminals.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    let rows = json_body(
        &request(
            &server,
            "GET",
            "/api/event-table/requests",
            &bearer(&server),
            "",
        )
        .await,
    );
    assert_eq!(rows["rows"].as_array().unwrap().len(), 1);
    assert_eq!(rows["rows"][0]["fields"]["route"], "bank");
    assert_eq!(description.moments.len(), 1);
    assert_eq!(description.moments[0].id, "bank-requested");
    assert_eq!(description.moments[0].title, "Bank requested");
    let moment_rows = json_body(
        &request(
            &server,
            "GET",
            &description.moments[0].events,
            &bearer(&server),
            "",
        )
        .await,
    );
    assert_eq!(moment_rows, rows);
    let next = rows["next"].as_u64().unwrap();
    assert!(next > rows["rows"][0]["seq"].as_u64().unwrap());
    let rows = json_body(
        &request(
            &server,
            "GET",
            &format!("/api/event-table/requests?after={next}"),
            &bearer(&server),
            "",
        )
        .await,
    );
    assert_eq!(rows["rows"], serde_json::json!([]));
    let module = request(&server, "GET", "/panels/plant.mjs", "", "").await;
    status(&module, 200);
    assert!(module.ends_with("export function mount() { return () => {}; }"));
    status(
        &request(&server, "GET", "/assets/plant/data.json", "", "").await,
        200,
    );
    drop(endpoints);
    world.join().unwrap();
}

#[tokio::test]
async fn all_panel_kinds_and_assets_are_validated_at_bind() {
    let page = || {
        Page::new(
            "Builder",
            crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
        )
    };
    let topic = || StateTopic::<Vec<u32>>::new(StateLimits::default());
    for invalid in [
        page().table("Packets", topic(), vec![]).standard_panels(),
        page().custom("Events", "", topic()).standard_panels(),
        page()
            .event_table("Map", EventFilter::default(), vec![])
            .standard_panels(),
        page()
            .host(Host::new("alpha").console(FakeConsole::default()))
            .table("Alpha Screen", topic(), vec![])
            .standard_panels(),
    ] {
        let error = invalid.bind_loopback(0).await.err().unwrap().to_string();
        assert!(error.contains("standard_panels"), "{error}");
        assert!(
            error.contains("table(") || error.contains("custom("),
            "{error}"
        );
    }
    for invalid in [
        page().host(Host::new("bad/name")),
        page().host(Host::new("")),
        page().host(Host::new("a")).host(Host::new("a")),
        page().table("Rows", topic(), vec![]).workspace("Rows"),
        page().workspace("missing"),
        page().asset("../file", "text/plain", vec![]),
        page().asset("a//b", "text/plain", vec![]),
        page().asset("a", "text/plain\r\nX: value", vec![]),
        page().asset("a", "invalid", vec![]),
        page().asset("a", "text/plain;bad", vec![]),
        page()
            .asset("a", "text/plain", vec![])
            .asset("a", "text/plain", vec![]),
        page().event_table(
            "Rows",
            EventFilter {
                host: Some("missing".into()),
                ..EventFilter::default()
            },
            vec![],
        ),
        page().table("Leases", topic(), vec![]),
    ] {
        assert!(invalid.bind_loopback(0).await.is_err());
    }
}

#[tokio::test]
async fn console_open_errors_and_oversized_messages_close_the_socket() {
    struct Unready;
    impl Console for Unready {
        fn screen(&self) -> Option<BoxFuture<'static, io::Result<Box<dyn Duplex>>>> {
            Some(Box::pin(async {
                Err(io::Error::other("desktop is booting"))
            }))
        }
        fn terminal(&self, _: u16, _: u16) -> Option<BoxFuture<'static, io::Result<Box<dyn Pty>>>> {
            None
        }
    }
    let fake = FakeConsole::default();
    let server = Page::new(
        "Limits",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .host(Host::new("booting").console(Unready))
    .host(Host::new("ready").console(fake.clone()))
    .bind_loopback(0)
    .await
    .unwrap();
    let ticket = mint(&server, "booting", "screen").await;
    let mut ws = Ws::connect(&server, "booting", "screen", &ticket, 101).await;
    assert!(
        matches!(ws.recv().await,Message::Close(Some(close)) if close.reason == "desktop is booting")
    );
    let mut screens = Vec::new();
    for _ in 0..4 {
        let ticket = mint(&server, "ready", "screen").await;
        let mut ws = Ws::connect(&server, "ready", "screen", &ticket, 101).await;
        ws.barrier().await;
        screens.push(ws);
    }
    let ticket = mint(&server, "ready", "screen").await;
    Ws::connect(&server, "ready", "screen", &ticket, 503).await;
    assert_eq!(fake.opens.load(std::sync::atomic::Ordering::SeqCst), 4);
    for ws in screens {
        ws.close().await;
    }
    for (capability, length) in [("screen", (1u64 << 20) + 9), ("terminal", (64 << 10) + 1)] {
        let ticket = mint(&server, "ready", capability).await;
        let mut ws = Ws::connect(&server, "ready", capability, &ticket, 101).await;
        // The declared length is rejected without allocating or reading its payload.
        let mut head = vec![0x82, 0xff];
        head.extend_from_slice(&length.to_be_bytes());
        head.extend_from_slice(&[1, 2, 3, 4]);
        ws.conn.write_all(&head).await.unwrap();
        assert!(matches!(ws.recv().await, Message::Close(Some(_))));
    }
}

#[tokio::test]
async fn moments_validate_titles_ids_and_host_filters_before_binding() {
    let page = || {
        Page::new(
            "Moments",
            crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
        )
    };
    for invalid in [
        page().moment("", EventFilter::default()),
        page().moment("---", EventFilter::default()),
        page().moment("a".repeat(129), EventFilter::default()),
        page()
            .moment("Ready", EventFilter::default())
            .moment("ready", EventFilter::default()),
        page()
            .moment("Map", EventFilter::default())
            .standard_panels(),
        page().moment("Rows", EventFilter::default()).table(
            "Rows",
            StateTopic::<Vec<u32>>::new(StateLimits::default()),
            vec![],
        ),
        page().moment(
            "Ready",
            EventFilter {
                host: Some("missing".into()),
                ..EventFilter::default()
            },
        ),
    ] {
        assert_eq!(
            invalid.bind_loopback(0).await.err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[tokio::test]
async fn left_the_box_is_declared_and_requires_a_bearer() {
    for standard in [false, true] {
        let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
        let page = Page::new("Destinations", dashboard.handle());
        let server = if standard {
            page.standard_panels()
        } else {
            page.left_the_box()
        }
        .bind_loopback(0)
        .await
        .unwrap();
        let description =
            json_body(&request(&server, "GET", "/api/page", &bearer(&server), "").await);
        assert!(
            description["panels"]
                .as_array()
                .unwrap()
                .iter()
                .any(|panel| panel["kind"] == "left_the_box")
        );
        status(&request(&server, "GET", "/api/egress", "", "").await, 401);
        let response = request(&server, "GET", "/api/egress", &bearer(&server), "").await;
        status(&response, 200);
        let snapshot = json_body(&response);
        assert_eq!(snapshot["destinations"], serde_json::json!([]));
        assert_eq!(snapshot["dropped"], 0);
        assert_eq!(snapshot["lost"], 0);
        status(
            &request(
                &server,
                "GET",
                "/api/egress?token=wrong",
                &bearer(&server),
                "",
            )
            .await,
            400,
        );
        status(
            &request(&server, "GET", "/components/left-the-box.mjs", "", "").await,
            200,
        );
    }
}

#[tokio::test]
async fn labels_are_world_commands_and_event_exports_keep_scope_labels_and_loss() {
    let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
    let labels = Labels::default();
    let worker_labels = labels.clone();
    let observer = dashboard.observer();
    let server = Page::new("Export", dashboard.handle())
        .host(Host::new("alpha"))
        .host(Host::new("beta"))
        .labels(labels)
        .standard_panels()
        .bind_loopback(0)
        .await
        .unwrap();
    for path in ["/api/export/events", "/api/export/packets"] {
        status(&request(&server, "GET", path, "", "").await, 401);
    }
    let worker = std::thread::spawn(move || {
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(3)).observer(observer.clone()),
            |cx| async move {
                let command = worker_labels.commands.recv().await.unwrap();
                worker_labels.apply(&cx, command);
                for n in 0..300 {
                    let guest = if n % 2 == 0 { "alpha" } else { "beta" };
                    let conn = fictionet::events::ConnInfo::new(
                        2,
                        "192.0.2.1:80".parse().unwrap(),
                        "10.0.2.15:40000".parse().unwrap(),
                    )
                    .from_sandbox(Some(fictionet::events::Sandbox {
                        id: 1,
                        name: guest.into(),
                        addr: None,
                        addr_v6: None,
                    }));
                    cx.emitter(&conn).emit("fixture", "request", |event| {
                        event.field("number", n as u32)
                    });
                }
                observer.lost(fictionet::events::Loss {
                    stream: fictionet::events::Stream::Events,
                    reason: fictionet::events::LossReason::Overflow,
                    count: 7,
                    bytes: None,
                    seqs: None,
                });
                Ok(())
            },
        ))
        .unwrap();
    });
    let headers = format!("{}Origin: http://{}\r\n", bearer(&server), address(&server));
    let response = request(&server, "POST", "/api/command/labels", &headers,
        r#"{"request_id":"label","command":{"action":"add","target":{"kind":"connection","id":2,"local":"192.0.2.1:80","peer":"10.0.2.15:40000"},"text":"download"}}"#).await;
    status(&response, 200);
    assert_eq!(json_body(&response)["status"], "applied");
    worker.join().unwrap();
    let all = request(&server, "GET", "/api/export/events", &bearer(&server), "").await;
    status(&all, 200);
    assert!(all.contains("application/x-ndjson"));
    let lines: Vec<serde_json::Value> = all
        .split_once("\r\n\r\n")
        .unwrap()
        .1
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["source"] == "fixture")
            .count(),
        300
    );
    assert_eq!(
        lines.iter().find(|line| line["type"] == "loss").unwrap()["count"],
        7
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["source"] == "page" && line["kind"] == "label")
            .count(),
        1
    );
    assert!(
        lines
            .iter()
            .filter(|line| line["source"] == "fixture")
            .all(|line| line["labels"][0]["text"] == "download")
    );
    let scoped = request(
        &server,
        "GET",
        "/api/export/events?host=alpha",
        &bearer(&server),
        "",
    )
    .await;
    status(&scoped, 200);
    let lines: Vec<serde_json::Value> = scoped
        .split_once("\r\n\r\n")
        .unwrap()
        .1
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["source"] == "fixture")
            .count(),
        150
    );
    assert!(
        lines
            .iter()
            .filter(|line| line["source"] == "fixture")
            .all(|line| line["sandbox"]["name"] == "alpha")
    );
    assert!(lines.iter().any(|line| line["type"] == "loss"));
    status(
        &request(
            &server,
            "GET",
            "/api/export/events?host=unknown",
            &bearer(&server),
            "",
        )
        .await,
        404,
    );
    let description = json_body(&request(&server, "GET", "/api/page", &bearer(&server), "").await);
    let kinds: Vec<_> = description["panels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|panel| panel["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "packets",
            "events",
            "map",
            "left_the_box",
            "containment",
            "labels"
        ]
    );
}

#[tokio::test]
async fn state_can_be_registered_without_a_panel_and_controls_select_world_fields() {
    let topic = StateTopic::new(StateLimits::default());
    topic
        .publish(
            fictionet::time::Instant::from_since_start(std::time::Duration::ZERO),
            &serde_json::json!({"enabled":true,"revision":0}),
        )
        .unwrap();
    let page = Page::new(
        "Settings",
        crate::DashboardObserver::new(crate::DashboardOptions::demo()).handle(),
    )
    .state("settings", topic.clone())
    .control(
        "Switch",
        CommandPort::<serde_json::Value, u32>::new(CommandLimits::default()),
        vec![
            Action {
                label: "On".into(),
                command: serde_json::json!({"enabled":true}),
            },
            Action {
                label: "Off".into(),
                command: serde_json::json!({"enabled":false}),
            },
        ],
    )
    .control_state(topic)
    .control_revision("/value/revision");
    let server = page.bind_loopback(0).await.unwrap();
    let state =
        json_body(&request(&server, "GET", "/api/state/settings", &bearer(&server), "").await);
    assert_eq!(state["revision"], 1);
    assert_eq!(state["value"]["revision"], 0);
    let description = json_body(&request(&server, "GET", "/api/page", &bearer(&server), "").await);
    let panels = description["panels"].as_array().unwrap();
    assert_eq!(panels.len(), 1);
    assert_eq!(panels[0]["revision"], "/value/revision");
}

#[tokio::test]
async fn event_tables_select_several_kinds_without_other_events() {
    let dashboard = crate::DashboardObserver::new(crate::DashboardOptions::demo());
    fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(dashboard.observer()),
        |cx| async move {
            for kind in ["query", "site", "query_failed"] {
                cx.emit("sample", kind, |event| event.field("search", "office"));
            }
            cx.emit("other", "query", |event| event);
            cx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
    let server = Page::new("Queries", dashboard.handle())
        .event_table(
            "Queries",
            EventFilter {
                source: Some("sample".into()),
                kinds: vec!["query".into(), "query_failed".into()],
                ..EventFilter::default()
            },
            vec![Column::new("Event", "/kind")],
        )
        .bind_loopback(0)
        .await
        .unwrap();
    let response = request(
        &server,
        "GET",
        "/api/event-table/queries",
        &bearer(&server),
        "",
    )
    .await;
    let rows = json_body(&response);
    let kinds: Vec<_> = rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["query", "query_failed"]);
}
