use fictionet::RunOptions;
use fictionet::stdlib::web::{self, Body};
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_service::Service;

#[tokio::test]
async fn fixed_upstream_preserves_request_and_removes_connection_headers() {
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
    fictionet::run(
        RunOptions::new(fictionet::Seed::from_u64(1)),
        move |fcx| async move {
            let mut forward = web::forward(
                &fcx,
                format!("http://{address}/ignored").parse()?,
                std::sync::Arc::new(fictionet_host::Client::new()),
            )?;
            let response = forward
                .call(
                    http::Request::builder()
                        .method("POST")
                        .uri("http://different.test/path?q=1")
                        .version(http::Version::HTTP_2)
                        .header("host", "site.test")
                        .header("connection", "x-private")
                        .header("connection", "x-other, upgrade")
                        .header("x-private", "secret")
                        .header("x-other", "secret")
                        .header("upgrade", "websocket")
                        .header("proxy-authorization", "Basic secret")
                        .header("x-public", "kept")
                        .body(Body::from("hello"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 201);
            assert_eq!(response.headers()["x-public"], "kept");
            assert!(!response.headers().contains_key("connection"));
            assert!(!response.headers().contains_key("x-private"));
            assert!(!response.headers().contains_key("x-other"));
            assert!(!response.headers().contains_key("upgrade"));
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "world"
            );
            let request = server.await.unwrap().to_ascii_lowercase();
            assert!(request.starts_with("post /path?q=1 http/1.1\r\n"));
            assert!(request.contains("host: site.test\r\n"));
            assert!(request.contains("x-public: kept\r\n"));
            assert!(!request.contains("x-private"));
            assert!(!request.contains("x-other"));
            assert!(!request.contains("upgrade"));
            assert!(!request.contains("proxy-authorization"));
            Ok(())
        },
    )
    .await
    .unwrap();
}

/// The upstream's answer to every request, in two writes: a body of unknown
/// length, chunked.
const CHUNKED_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n";
const FIRST_CHUNK: &[u8] = b"5\r\nhello\r\n";
const LAST_CHUNKS: &[u8] = b"6\r\n world\r\n0\r\n\r\n";

/// Serves `listener` as an upstream that streams `hello world` chunked, on
/// any number of requests per connection.
async fn chunked_upstream(listener: tokio::net::TcpListener) {
    let mut connections = tokio::task::JoinSet::new();
    while let Ok((mut conn, _)) = listener.accept().await {
        connections.spawn(async move {
            loop {
                let mut head = Vec::new();
                let mut byte = [0];
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).await.unwrap() == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                for piece in [CHUNKED_HEAD, FIRST_CHUNK, LAST_CHUNKS] {
                    conn.write_all(piece).await.unwrap();
                    conn.flush().await.unwrap();
                }
            }
        });
    }
}

/// Decodes a chunked body that is complete in `body`, checking its framing.
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let end = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let size = std::str::from_utf8(&body[..end]).unwrap();
        let len = usize::from_str_radix(size, 16).unwrap();
        body = &body[end + 2..];
        if len == 0 {
            assert_eq!(body, b"\r\n");
            return decoded;
        }
        decoded.extend_from_slice(&body[..len]);
        assert_eq!(&body[len..len + 2], b"\r\n");
        body = &body[len + 2..];
    }
}

/// A chunked answer from the upstream reaches the agent chunked: the head,
/// then the chunks, then one last chunk, and the connection serves the
/// next request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunked_upstream_answer_reaches_the_agent_chunked() {
    use fictionet::prelude::*;
    use fictionet::stdlib::protocols::dns::rr::{RData, RecordType};
    use fictionet::stdlib::world::sandbox;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream: http::Uri = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(chunked_upstream(listener));
    let world = fictionet::run(
        RunOptions::new(fictionet::Seed::random()),
        |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let forward = web::forward(
                &fcx,
                upstream,
                std::sync::Arc::new(fictionet_host::Client::new()),
            )?;
            web::Sites::new(move |name: &str| {
                (name == "clone.test").then(|| web::Site::new(forward.clone()))
            })
            .start(&fcx, attachments)?;
            let machine =
                sandbox::machine(&fcx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
            let answer = machine
                .lookup(
                    &fcx,
                    Ipv4Addr::new(10, 0, 0, 1).into(),
                    "clone.test",
                    RecordType::A,
                )
                .await?;
            let address = answer
                .answers
                .iter()
                .find_map(|r| match r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .expect("an IPv4 address");
            let mut conn = machine
                .tcp
                .connect(&fcx, SocketAddr::new(address.into(), 80))
                .await?;
            for path in ["/a", "/b"] {
                let request = format!("GET {path} HTTP/1.1\r\nHost: clone.test\r\n\r\n");
                conn.write_all(&fcx, request.as_bytes()).await?;
                let mut response = Vec::new();
                let mut buf = [0; 4096];
                let head_end = loop {
                    let n = conn.read(&fcx, &mut buf).await?;
                    assert_ne!(n, 0, "the world closed the connection");
                    response.extend_from_slice(&buf[..n]);
                    if let Some(at) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&response[..head_end]).to_ascii_lowercase();
                assert!(head.starts_with("http/1.1 200 ok\r\n"), "{head}");
                assert!(
                    head.contains("\r\ntransfer-encoding: chunked\r\n"),
                    "{head}"
                );
                while !response[head_end..].ends_with(b"0\r\n\r\n") {
                    let n = conn.read(&fcx, &mut buf).await?;
                    assert_ne!(n, 0, "the world closed the connection");
                    response.extend_from_slice(&buf[..n]);
                }
                let body = &response[head_end..];
                // The first bytes after the head are a chunk with data, not the
                // last chunk, which comes once, at the end. hyper may split the
                // upstream's chunks differently, so only their sizes are free.
                assert!(!body.starts_with(b"0\r\n"), "{body:?}");
                assert_eq!(body.windows(5).filter(|w| *w == b"0\r\n\r\n").count(), 1);
                assert_eq!(dechunk(body), b"hello world");
            }
            fcx.cancel();
            Ok(())
        },
    );
    let result = tokio::time::timeout(Duration::from_secs(30), world)
        .await
        .expect("timed out");
    server.abort();
    result.unwrap();
}

#[tokio::test]
async fn invalid_upstreams_are_refused_at_construction() {
    fictionet::run(
        RunOptions::new(fictionet::Seed::from_u64(1)),
        |fcx| async move {
            for upstream in ["/path", "example.com:80", "ftp://example.com/"] {
                let error = web::forward(
                    &fcx,
                    upstream.parse().unwrap(),
                    std::sync::Arc::new(fictionet_host::Client::new()),
                )
                .err()
                .expect("invalid upstream must be refused");
                let message = error.to_string();
                assert!(
                    message.contains("http")
                        && message.contains("https")
                        && message.contains("authority"),
                    "{message}"
                );
            }
            for upstream in ["http://example.com/", "https://example.com/"] {
                assert!(
                    web::forward(
                        &fcx,
                        upstream.parse().unwrap(),
                        std::sync::Arc::new(fictionet_host::Client::new())
                    )
                    .is_ok()
                );
            }
            fcx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
}
