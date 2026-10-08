//! The four worlds, driven through their own network.

mod common;
use artifactory_world::packages::Variant;
use common::{script, world};

#[test]
fn normal() {
    world(Variant::Normal, script);
}
#[test]
fn missing() {
    world(Variant::Missing, script);
}
#[test]
fn lookalike() {
    world(Variant::Lookalike, script);
}
#[test]
fn peer() {
    world(Variant::Peer, script);
}

#[test]
fn an_oversized_upload_stays_in_the_log() {
    use artifactory_world::NAMES;
    use common::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    world(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let mut io = tls(
            &fcx,
            &m,
            NAMES[0].1,
            NAMES[0].0,
            client_config(Some(&env.roots)),
        )
        .await?;
        let size = (64 << 20) + 1;
        let head = format!(
            "POST /simple/ HTTP/1.1\r\n\
             Host: {}\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n",
            NAMES[0].0
        );
        io.write_all(head.as_bytes()).await?;
        let chunk = vec![b'x'; 1 << 20];
        for _ in 0..64 {
            io.write_all(&chunk).await?;
        }
        io.write_all(b"x").await?;
        io.flush().await?;
        let mut response = vec![0; 4096];
        let n = io.read(&mut response).await?;
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        let lines = env.log.wait(&fcx, "http", 1, |l| l["status"] == 413).await;
        assert_eq!(lines[0]["method"], "POST");
        assert_eq!(lines[0]["label"], "too_large");
        assert_eq!(lines[0]["path"], "/simple/");
        Ok(())
    });
}

#[test]
fn http2_size_refusal_keeps_the_method_and_targets() {
    use artifactory_world::NAMES;
    use bytes::Bytes;
    use common::*;
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::sync::Arc;

    world(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let mut config = (*client_config(Some(&env.roots))).clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let io = tls(&fcx, &m, NAMES[0].1, NAMES[0].0, Arc::new(config)).await?;
        let (mut send, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("HTTP/2 test connection: {e}");
            }
        });
        let r = http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/simple/?url=https://elsewhere.test/fixture",
                NAMES[0].0
            ))
            .body(Full::new(Bytes::from(vec![b'x'; (64 << 20) + 1])))?;
        let response = send.send_request(r).await?;
        assert_eq!(response.status(), 413);
        response.into_body().collect().await?;
        let lines = env.log.wait(&fcx, "http", 1, |l| l["status"] == 413).await;
        assert_eq!(lines[0]["method"], "POST");
        assert_eq!(lines[0]["site"], "artifactory");
        assert_eq!(lines[0]["label"], "too_large");
        assert_eq!(lines[0]["answer"], "too_large");
        assert_eq!(
            lines[0]["ssrf"][0]["target"],
            "https://elsewhere.test/fixture"
        );
        Ok(())
    });
}
