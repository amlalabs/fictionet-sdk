use super::events::{http_seen, local, raw_http, wait_for, world_events};
use super::*;

// Checks the Date response for both HTTP versions.
async fn assert_date_responses(fcx: &Cx, m: &Machine, addr: Ipv4Addr, date: Option<SystemTime>) {
    for h2 in [false, true] {
        let mut client = plain_client(fcx, m, addr, h2).await;
        let got = client.get("http", "dated.test", "/").await;
        assert_eq!(got.body, "hello");
        assert_eq!(
            got.version,
            if h2 {
                Version::HTTP_2
            } else {
                Version::HTTP_11
            }
        );
        let header = got
            .headers
            .get("date")
            .map(|v| v.to_str().unwrap().to_owned());
        match date {
            Some(_) => {
                let header = header.expect("a Date header");
                assert!(
                    header.starts_with("Sat, 01 Jun 2019 00:0"),
                    "h2 {h2}: {header}"
                );
            }
            None => assert_eq!(header, None, "h2 {h2}: no world date, so no Date"),
        }
        // A Date the handler sets is kept.
        let got = client.get("http", "dated.test", "/own").await;
        assert_eq!(
            got.headers.get_all("date").iter().collect::<Vec<_>>(),
            ["Mon, 01 Jan 2001 00:00:00 GMT"]
        );
    }
}

// ---------------------------------------------------------------------------
// Tests: HTTPS, HTTP/2 and HTTP/1.1

#[test]
fn https_with_http2_and_http11() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;

        // A client that offers h2 gets HTTP/2.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"h2", b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Client::new(&fcx, conn, true).await;
        let got = client.get("https", "secure.test", "/a/b?c=d").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.version, Version::HTTP_2);
        assert_eq!(got.body, "secure https secure.test 443 HTTP/2.0 #1");

        // Many streams at once on the one connection.
        let Client::H2(send) = &client else {
            unreachable!()
        };
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let mut c = Client::H2(send.clone());
            tasks.push(fcx.spawn(move |_| async move {
                let got = c.get("https", "secure.test", "/x").await;
                assert_eq!(got.status, StatusCode::OK);
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&fcx).await?;
        }
        assert_eq!(env.served.load(Ordering::SeqCst), 21);

        // A client that offers only http/1.1 gets it.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("https", "secure.test", "/").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.version, Version::HTTP_11);
        assert_eq!(got.body, "secure https secure.test 443 HTTP/1.1 #22");
        // Keep-alive: a second request on the same connection.
        let got = client.get("https", "secure.test:443", "/").await;
        assert_eq!(got.body, "secure https secure.test 443 HTTP/1.1 #23");

        // A client that offers no ALPN at all gets HTTP/1.1.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[])
            .await
            .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), None);
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );
        Ok(())
    });
}

/// `Date` headers come from the world's date, over HTTP/1.1 and HTTP/2,
/// and never from the host's clock: without a world date there is none.
#[test]
fn dates_come_from_the_world() {
    // 2019-06-01T00:00:00Z.
    let june_2019 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_559_347_200);
    for date in [Some(june_2019), None] {
        let result = within(Duration::from_secs(60), move || {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (attacher, attachments) = fictionet::attachments();
                let site = axum::Router::new()
                    .route(
                        "/own",
                        axum::routing::get(|| async {
                            ([("date", "Mon, 01 Jan 2001 00:00:00 GMT")], "own")
                        }),
                    )
                    .fallback(|| async { "hello" });
                let mut sites = web::Sites::new(move |name: &str| {
                    (name == "dated.test").then(|| web::Site::new(site.clone()))
                });
                if let Some(date) = date {
                    sites = sites.date(date);
                }
                sites.start(&fcx, attachments)?;
                let m = default_machine(&fcx, &attacher);
                let addr = lookup(&fcx, &m, "dated.test").await;
                assert_date_responses(&fcx, &m, addr, date).await;
                Err(fictionet::Error::from(Done))
            }))
        });
        assert!(result.is_err_and(|e| e.downcast_ref::<Done>().is_some()));
    }
}

#[test]
fn port_80_redirects_tls_sites_and_serves_the_others() {
    world(|fcx, attacher, _env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        assert_eq!(lookup(&fcx, &m, "shared.test").await, addr);
        let plain = lookup(&fcx, &m, "plain.test").await;

        // A site with TLS: 301 to https, with the path and query.
        let mut client = plain_client(&fcx, &m, addr, false).await;
        let got = client.get("http", "secure.test", "/a/b?c=d").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://secure.test/a/b?c=d");
        // The site without TLS at the same address, on the same connection.
        let got = client.get("http", "shared.test", "/p").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.body, "shared http shared.test 80 HTTP/1.1 /p");

        // A site with its own address, over HTTP/1.1 and HTTP/2 with prior
        // knowledge.
        let mut client = plain_client(&fcx, &m, plain, false).await;
        assert_eq!(
            client.get("http", "plain.test", "/q").await.body,
            "plain http plain.test 80 HTTP/1.1 /q"
        );
        let mut client = plain_client(&fcx, &m, plain, true).await;
        let got = client.get("http", "plain.test", "/r").await;
        assert_eq!(got.version, Version::HTTP_2);
        assert_eq!(got.body, "plain http plain.test 80 HTTP/2.0 /r");

        // Port 443 is closed on a machine with no TLS site.
        assert_eq!(
            m.tcp
                .connect(&fcx, SocketAddr::new(plain.into(), 443))
                .await
                .err(),
            Some(ConnError::Refused)
        );
        Ok(())
    });
}

#[test]
fn a_tls_site_with_plain_http_answers_port_80_itself() {
    world_events(|fcx, attacher, env, log| async move {
        let m = default_machine(&fcx, &attacher);
        assert_eq!(lookup(&fcx, &m, "both.test").await, BOTH_ADDR);

        // Port 80: the handler answers, with an http Target, over HTTP/1.1
        // and HTTP/2 with prior knowledge. No redirect.
        for h2 in [false, true] {
            let mut client = plain_client(&fcx, &m, BOTH_ADDR, h2).await;
            let got = client.get("http", "both.test", "/a?b=c").await;
            assert_eq!(got.status, StatusCode::OK);
            assert!(got.headers.get("location").is_none());
            let version = if h2 { "HTTP/2.0" } else { "HTTP/1.1" };
            assert!(
                got.body
                    .starts_with(&format!("secure http both.test 80 {version} #")),
                "{}",
                got.body
            );
        }

        // Port 443 still serves it over TLS.
        let conn = tls_connect(&fcx, &m, &env, BOTH_ADDR, "both.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("https", "both.test", "/").await;
        assert_eq!(got.status, StatusCode::OK);
        assert!(
            got.body
                .starts_with("secure https both.test 443 HTTP/1.1 #"),
            "{}",
            got.body
        );

        // Each plain request is a Handler event on port 80, with no SNI.
        let seen = wait_for(&fcx, &log, 3, http_seen).await;
        let plain: Vec<_> = seen.iter().filter(|h| local(h).port() == 80).collect();
        assert_eq!(plain.len(), 2);
        for h in plain {
            assert_eq!(
                (h.str("answer"), h.str("scheme"), h.str("sni")),
                (Some("handler"), Some("http"), None)
            );
            assert_eq!((h.u64("status"), h.str("path")), (Some(200), Some("/a")));
        }

        // A TLS site without it still redirects, at the same time.
        let secure = lookup(&fcx, &m, "secure.test").await;
        let mut client = plain_client(&fcx, &m, secure, false).await;
        assert_eq!(
            client.get("http", "secure.test", "/").await.status,
            StatusCode::MOVED_PERMANENTLY
        );
        Ok(())
    });
}

#[test]
fn a_host_that_is_not_this_site_gets_421() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        lookup(&fcx, &m, "shared.test").await;
        let plain = lookup(&fcx, &m, "plain.test").await;

        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            // A name with no site at all.
            assert_eq!(
                client.get("https", "nope.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            // A site at another address.
            assert_eq!(
                client.get("https", "plain.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            // A site at this address, but without TLS.
            assert_eq!(
                client.get("https", "shared.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            // The connection still works.
            assert_eq!(
                client.get("https", "secure.test", "/").await.status,
                StatusCode::OK
            );
        }

        // Plain HTTP too.
        let mut client = plain_client(&fcx, &m, plain, false).await;
        assert_eq!(
            client.get("http", "secure.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            client.get("http", "198.18.0.1", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        Ok(())
    });
}

#[test]
fn a_failing_handler_gets_500() {
    world(|fcx, attacher, _env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "broken.test").await;
        let mut client = plain_client(&fcx, &m, addr, false).await;
        assert_eq!(
            client.get("http", "broken.test", "/").await.status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        Ok(())
    });
}

#[test]
fn an_unknown_tls_name_is_rejected_with_unrecognized_name() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        lookup(&fcx, &m, "shared.test").await;
        let calls = env.calls.load(Ordering::SeqCst);
        // A name with no site; a site here without TLS; a site elsewhere.
        for sni in ["nope.test", "shared.test", "plain.test"] {
            match tls_connect(&fcx, &m, &env, addr, sni, &[b"h2"]).await {
                Err(TlsError::Tls(rustls::Error::AlertReceived(
                    rustls::AlertDescription::UnrecognisedName,
                ))) => {}
                Err(e) => panic!("{sni}: expected unrecognized_name, got {e:?}"),
                Ok(_) => panic!("{sni}: the handshake should fail"),
            }
        }
        // Names seen in a handshake do not run the callback.
        assert_eq!(env.calls.load(Ordering::SeqCst), calls);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The proxy (feature tokio)

#[cfg(feature = "web-proxy")]
#[tokio::test]
async fn the_proxy_uses_its_target_and_removes_connection_headers() {
    use fictionet::stdlib::httpd::{self, Handler, VHost, VirtualHosts};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0; 4096];
        while !received.ends_with(b"\r\n\r\nhello") {
            let n = conn.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            received.extend_from_slice(&buf[..n]);
        }
        conn.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close, x-private\r\nConnection: x-other\r\nX-Private: secret\r\nX-Other: secret\r\nUpgrade: websocket\r\nX-Public: kept\r\n\r\nworld").await.unwrap();
        String::from_utf8(received).unwrap()
    });
    run(fictionet::Seed::from_u64(1), move |fcx| async move {
        let vhosts = VirtualHosts::new();
        vhosts.insert("127.0.0.1", VHost::new(httpd::tower(web::proxy(&fcx)?)));
        let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
        let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
        let mut ex = httpd::Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
        let reply = vhosts.call(
            Request::builder()
                .method("POST")
                .uri("https://127.0.0.1:443/path?q=1")
                .version(http::Version::HTTP_2)
                .header("host", "different.test")
                .header("connection", "x-private")
                .header("connection", "x-other, upgrade")
                .header("x-private", "secret")
                .header("x-other", "secret")
                .header("upgrade", "websocket")
                .header("proxy-authorization", "Basic secret")
                .header("x-public", "kept")
                .body(web::Body::from("hello"))
                .unwrap(),
            &mut ex,
        );
        let httpd::Reply::Later(work) = reply else {
            panic!("the proxy dispatches upstream");
        };
        let response = work(fcx.clone()).await?;
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers()["x-public"], "kept");
        for name in ["connection", "x-private", "x-other", "upgrade"] {
            assert!(!response.headers().contains_key(name));
        }
        assert_eq!(response.into_body().collect().await?.to_bytes(), "world");
        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("post /path?q=1 http/1.1\r\n"));
        assert!(request.contains(&format!("host: {address}\r\n")));
        assert!(request.contains("x-public: kept\r\n"));
        for name in ["x-private", "x-other", "upgrade", "proxy-authorization"] {
            assert!(!request.contains(name));
        }
        Ok(())
    })
    .await
    .unwrap();
}

#[cfg(feature = "web-proxy")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxy_answers_502_when_the_real_site_cannot_be_reached() {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run(fictionet::Seed::random(), |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let upstream = web::proxy(&fcx)?;
            web::Sites::new(move |h| {
                (h == "nowhere.invalid").then(|| web::Site::new(upstream.clone()))
            })
            .start(&fcx, attachments)?;
            let m = default_machine(&fcx, &attacher);
            let addr = lookup(&fcx, &m, "nowhere.invalid").await;
            let mut client = plain_client(&fcx, &m, addr, false).await;
            let got = client.get("http", "nowhere.invalid", "/").await;
            assert_eq!(got.status, StatusCode::BAD_GATEWAY, "{}", got.body);
            assert!(got.body.contains("nowhere.invalid"), "{}", got.body);
            Err(fictionet::Error::from(Done))
        }),
    )
    .await
    .expect("timed out");
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// An axum handler that echoes WebSocket text messages.
#[cfg(feature = "tokio")]
fn echo_socket() -> axum::Router {
    use axum::extract::ws::{Message as Ws, WebSocketUpgrade};
    axum::Router::new().route(
        "/echo",
        axum::routing::get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut socket| async move {
                while let Some(Ok(message)) = socket.recv().await {
                    if let Ws::Text(t) = message {
                        let _ = socket
                            .send(Ws::Text(format!("echo: {}", t.as_str()).into()))
                            .await;
                    }
                }
            })
        }),
    )
}

/// Makes a client's WebSocket handshake on `conn` for `host`, then sends
/// `text` and returns the first message back.
#[cfg(feature = "tokio")]
async fn websocket_echo<C: Connection>(
    fcx: &Cx,
    conn: &mut C,
    host: &str,
    text: &str,
) -> fictionet::stdlib::websocket::Message {
    use fictionet::stdlib::codec::{Stream, Wire};
    use fictionet::stdlib::websocket::{Message as Ws, Messages};
    let request = format!(
        "GET /echo HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    conn.write_all(fcx, request.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = conn.read(fcx, &mut buf).await.unwrap();
        assert!(
            n > 0,
            "the server closed during the handshake: {:?}",
            String::from_utf8_lossy(&got)
        );
        got.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8_lossy(&got[..head_end]).to_lowercase();
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(
        head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
        "{head}"
    );
    let frame = Ws::Text(text.to_owned())
        .to_frame(Some([1, 2, 3, 4]))
        .unwrap();
    conn.write_all(fcx, &frame.to_bytes().unwrap())
        .await
        .unwrap();
    let mut stream = Stream::new(Messages::for_receiver(
        fictionet::stdlib::codec::Side::Client,
    ));
    assert_eq!(stream.push(&got[head_end..]), got.len() - head_end);
    loop {
        if let Some(m) = stream.next() {
            return m.unwrap();
        }
        let n = conn.read(fcx, &mut buf).await.unwrap();
        assert!(n > 0, "the server closed the WebSocket");
        assert_eq!(stream.push(&buf[..n]), n);
    }
}

/// An axum `WebSocketUpgrade` handler on `web::Sites`: the handshake, then
/// messages both ways.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websockets_work_through_sites() {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run(fictionet::Seed::random(), |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|h| (h == "ws.test").then(|| web::Site::new(echo_socket())))
                .start(&fcx, attachments)?;
            let m = default_machine(&fcx, &attacher);
            let addr = lookup(&fcx, &m, "ws.test").await;
            let mut conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 80))
                .await
                .unwrap();
            let reply = websocket_echo(&fcx, &mut conn, "ws.test", "hello").await;
            assert_eq!(
                reply,
                fictionet::stdlib::websocket::Message::Text("echo: hello".into())
            );
            Err(fictionet::Error::from(Done))
        }),
    )
    .await
    .expect("timed out");
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

// ---------------------------------------------------------------------------
// Tests: fix round 1

/// Requires EOF within five seconds; transport errors stay errors.
pub(super) async fn read_all<C: Connection>(fcx: &Cx, conn: &mut C) -> Result<Vec<u8>, ConnError> {
    io::read_to_end(fcx, conn, fcx.now() + Duration::from_secs(5))
        .await
        .expect("the response ends")
}

/// A body whose length the handler knows goes out with `content-length`;
/// one that streams goes out chunked on HTTP/1.1.
#[test]
fn a_known_length_is_sent_as_content_length() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let plain = lookup(&fcx, &m, "plain.test").await;
        let events = lookup(&fcx, &m, "events.test").await;
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        conn.write_all(
            &fcx,
            b"GET /len HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let got = String::from_utf8(read_all(&fcx, &mut conn).await.unwrap())
            .unwrap()
            .to_lowercase();
        let body = "plain http plain.test 80 HTTP/1.1 /len";
        assert!(
            got.contains(&format!("content-length: {}\r\n", body.len())),
            "{got:?}"
        );
        assert!(!got.contains("transfer-encoding"), "{got:?}");
        // axum's 4 MiB Vec has a known length too, over TLS.
        let conn = tls_connect(&fcx, &m, &env, events, "events.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("https", "events.test", "/big").await;
        assert_eq!(got.headers["content-length"], BIG.to_string());
        assert_eq!(got.body.len(), BIG);
        Ok(())
    });
}

/// A `HEAD` request gets the headers a `GET` would, `content-length`
/// included, and no body, over HTTP/2 as well as HTTP/1.1. hyper sends a
/// handler's body on HTTP/2 even for `HEAD`, which breaks the stream.
#[test]
fn head_gets_the_headers_and_no_body_on_both_versions() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let secure = lookup(&fcx, &m, "secure.test").await;
        let events = lookup(&fcx, &m, "events.test").await;
        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&fcx, &m, &env, secure, "secure.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            let get = client.get("https", "secure.test", "/x").await;
            let head = client
                .send(http::Method::HEAD, "https", "secure.test", "/x")
                .await;
            assert_eq!(
                (head.status, head.body.as_str()),
                (StatusCode::OK, ""),
                "h2 {h2}"
            );
            // The page ends with a request count, #1 then #2: same length.
            assert_eq!(
                head.headers["content-length"],
                get.body.len().to_string(),
                "h2 {h2}"
            );
            // A whole 4 MiB body is left out too, and so is Sites' own 421.
            let conn = tls_connect(&fcx, &m, &env, events, "events.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            let big = client
                .send(http::Method::HEAD, "https", "events.test", "/big")
                .await;
            assert_eq!((big.status, big.body.len()), (StatusCode::OK, 0), "h2 {h2}");
            assert_eq!(big.headers["content-length"], BIG.to_string(), "h2 {h2}");
            let other = client
                .send(http::Method::HEAD, "https", "secure.test", "/")
                .await;
            assert_eq!(
                (other.status, other.body.len()),
                (StatusCode::MISDIRECTED_REQUEST, 0),
                "h2 {h2}"
            );
            // The connection still works after them.
            assert_eq!(
                client.get("https", "events.test", "/page").await.status,
                StatusCode::OK,
                "h2 {h2}"
            );
        }
        Ok(())
    });
}

/// A request whose host names no site at the address goes to the
/// address's `default_host`, if it has one: an address typed as the host,
/// or any other name. A site that has its own name there keeps it.
#[test]
fn the_default_host_answers_hosts_with_no_site_of_their_own() {
    world(|fcx, attacher, _env| async move {
        let m = default_machine(&fcx, &attacher);
        assert_eq!(lookup(&fcx, &m, "default.test").await, DEFAULT_ADDR);
        assert_eq!(lookup(&fcx, &m, "other.test").await, DEFAULT_ADDR);
        let ask =
            |host: &str| format!("GET /p HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        for (host, want) in [
            ("203.0.113.40", "default http 203.0.113.40 80 HTTP/1.1 /p"),
            ("unknown.test", "default http unknown.test 80 HTTP/1.1 /p"),
            ("default.test", "default http default.test 80 HTTP/1.1 /p"),
            ("other.test", "other http other.test 80 HTTP/1.1 /p"),
        ] {
            let got = String::from_utf8(
                raw_http(&fcx, &m, DEFAULT_ADDR, ask(host).as_bytes())
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(
                got.starts_with("HTTP/1.1 200 OK") && got.ends_with(want),
                "{host}: {got:?}"
            );
        }
        // A TLS site that is the default redirects plain HTTP to https, at
        // the host the client named.
        assert_eq!(lookup(&fcx, &m, "tls-default.test").await, TLS_DEFAULT_ADDR);
        let got = String::from_utf8(
            raw_http(&fcx, &m, TLS_DEFAULT_ADDR, ask("203.0.113.41").as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(got.starts_with("HTTP/1.1 301"), "{got:?}");
        assert!(
            got.to_lowercase()
                .contains("location: https://203.0.113.41/p\r\n"),
            "{got:?}"
        );
        // Without a default, the same request gets 421.
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let got = String::from_utf8(
            raw_http(&fcx, &m, SECURE_ADDR, ask("203.0.113.10").as_bytes())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(got.starts_with("HTTP/1.1 421"), "{got:?}");
        Ok(())
    });
}

/// A client that sends its request and then shuts down its side (as
/// `nc -N` and HTTP/1.0 scripts do) still gets the response, over plain
/// HTTP and over TLS.
#[test]
fn a_client_that_half_closes_after_its_request_gets_the_response() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let plain = lookup(&fcx, &m, "plain.test").await;
        let secure = lookup(&fcx, &m, "secure.test").await;
        let requests: [(&[u8], http1::Version, &str); 2] = [
            (
                b"GET /h HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
                http1::Version::Http11,
                "plain http plain.test 80 HTTP/1.1 /h",
            ),
            (
                b"GET /h HTTP/1.0\r\nHost: plain.test\r\n\r\n",
                http1::Version::Http10,
                "plain http plain.test 80 HTTP/1.0 /h",
            ),
        ];
        for (request, version, body) in requests {
            let mut conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(plain.into(), 80))
                .await
                .unwrap();
            conn.write_all(&fcx, request).await.unwrap();
            conn.shutdown(&fcx).await.unwrap();
            let got = read_all(&fcx, &mut conn).await.unwrap();
            assert_half_close_response(&got, version, body);
        }
        let mut conn = tls_connect(&fcx, &m, &env, secure, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        conn.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        conn.shutdown(&fcx).await.unwrap();
        let got = read_all(&fcx, &mut conn).await.unwrap();
        assert_half_close_response(
            &got,
            http1::Version::Http11,
            "secure https secure.test 443 HTTP/1.1 #1",
        );
        Ok(())
    });
}

/// Requires a complete, length-delimited 200 with exactly `body`.
fn assert_half_close_response(got: &[u8], version: http1::Version, body: &str) {
    let response = http1::Response::parse_for(got, "GET").expect("complete half-close response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.head.version, version);
    assert!(
        response
            .head
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-length")),
        "half-close response must declare its length"
    );
    assert_eq!(response.body, body.as_bytes());
}

#[test]
fn half_close_truncated_body_rejected() {
    // Signal after the reader consumes the prefix, so a reset cannot discard
    // the scripted bytes before they reach read_all's buffer.
    struct Receipt {
        conn: tcp::TcpConnection,
        remaining: usize,
        sent: Option<tokio::sync::oneshot::Sender<()>>,
    }
    impl Connection for Receipt {
        fn poll_read(
            &mut self,
            fcx: &Cx,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize, ConnError>> {
            let result = self.conn.poll_read(fcx, cx, buf);
            if let Poll::Ready(Ok(n)) = result {
                self.remaining -= n;
                if self.remaining == 0
                    && let Some(sent) = self.sent.take()
                {
                    sent.send(()).expect("peer waits for receipt");
                }
            }
            result
        }
        fn poll_write(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<Result<usize, ConnError>> {
            panic!("client already half-closed")
        }
        fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
            panic!("client already half-closed")
        }
    }

    run_world::world(Duration::from_secs(10), |fcx| async move {
        for reset in [false, true] {
            for (version, body, prefix) in [
                (
                    "HTTP/1.1",
                    "plain http plain.test 80 HTTP/1.1 /h",
                    "plain http plain.test 80",
                ),
                (
                    "HTTP/1.0",
                    "plain http plain.test 80 HTTP/1.0 /h",
                    "plain http plain.test 80",
                ),
                // Replay the TLS case's body framing over plain TCP to test the reader and parser.
                ("HTTP/1.1", "secure https secure.test 443 HTTP/1.1 #1", ""),
            ] {
                let (a, b) = fictionet::pair();
                let server = machine(&fcx, a, Ipv4Addr::new(10, 0, 0, 1));
                let client = machine(&fcx, b, Ipv4Addr::new(10, 0, 0, 2));
                let mut listener = server.tcp.listen(80)?;
                let partial = format!(
                    "{version} 200 OK\r\nContent-Length: {}\r\n\r\n{prefix}",
                    body.len()
                );
                let length = partial.len();
                let (sent, received) = tokio::sync::oneshot::channel();
                let bytes = partial.clone();
                fcx.spawn(move |fcx| async move {
                    let mut peer = listener.accept(&fcx).await?;
                    assert_eq!(
                        read_all(&fcx, &mut peer).await?,
                        b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"
                    );
                    peer.write_all(&fcx, bytes.as_bytes()).await?;
                    received.await?;
                    if reset {
                        peer.reset();
                    } else {
                        peer.shutdown(&fcx).await?;
                    }
                    Ok(())
                });
                let mut conn = client
                    .tcp
                    .connect(&fcx, SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 80))
                    .await?;
                conn.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
                    .await?;
                conn.shutdown(&fcx).await?;
                let mut conn = Receipt {
                    conn,
                    remaining: length,
                    sent: Some(sent),
                };
                let got = read_all(&fcx, &mut conn).await;
                assert_eq!(conn.remaining, 0, "the reader consumed the prefix");
                if reset {
                    assert_eq!(got, Err(ConnError::Reset));
                } else {
                    let got = got.unwrap();
                    assert_eq!(got, partial.as_bytes());
                    assert_eq!(
                        http1::Response::parse_for(&got, "GET"),
                        Err(http1::Error::Incomplete)
                    );
                }
            }
        }
        Ok(())
    });
}

#[test]
fn eager_sites_send_the_world_date_without_a_lookup() {
    // 2019-06-01T00:00:00Z.
    let june_2019 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_559_347_200);
    for date in [Some(june_2019), None] {
        let result = within(Duration::from_secs(60), move || {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (attacher, attachments) = fictionet::attachments();
                let site = axum::Router::new()
                    .route(
                        "/own",
                        axum::routing::get(|| async {
                            ([("date", "Mon, 01 Jan 2001 00:00:00 GMT")], "own")
                        }),
                    )
                    .fallback(|| async { "hello" });
                let mut site = web::Site::new(site);
                if let Some(date) = date {
                    site = site.date(date);
                }
                let addr = Ipv4Addr::new(203, 0, 113, 10);
                web::Sites::new(|_| None)
                    .into_net()
                    .add_host(site.at(addr).into_host("dated.test"))
                    .start(&fcx, attachments)?;
                let m = default_machine(&fcx, &attacher);
                assert_date_responses(&fcx, &m, addr, date).await;
                Err(fictionet::Error::from(Done))
            }))
        });
        assert!(result.is_err_and(|e| e.downcast_ref::<Done>().is_some()));
    }
}
