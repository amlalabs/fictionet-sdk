#![cfg(feature = "tokio")]

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
        conn.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: close, x-private\r\nX-Private: secret\r\nX-Public: kept\r\n\r\nworld").await.unwrap();
        String::from_utf8(received).unwrap()
    });
    let mut forward = web::forward(format!("http://{address}/ignored").parse().unwrap());
    let response = forward
        .call(
            http::Request::builder()
                .method("POST")
                .uri("/path?q=1")
                .header("host", "site.test")
                .header("connection", "x-private")
                .header("x-private", "secret")
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
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "world"
    );
    let request = server.await.unwrap().to_ascii_lowercase();
    assert!(request.starts_with("post /path?q=1 http/1.1\r\n"));
    assert!(request.contains("host: site.test\r\n"));
    assert!(request.contains("x-public: kept\r\n"));
    assert!(!request.contains("x-private"));
}
