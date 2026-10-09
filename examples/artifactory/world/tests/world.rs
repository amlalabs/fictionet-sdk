//! The four worlds, driven through their own network.

mod common;
use artifactory_world::packages::Variant;
use common::{run_variant, script};

#[test]
fn normal() {
    run_variant(Variant::Normal, script);
}
#[test]
fn missing() {
    run_variant(Variant::Missing, script);
}
#[test]
fn lookalike() {
    run_variant(Variant::Lookalike, script);
}
#[test]
fn peer() {
    run_variant(Variant::Peer, script);
}

#[test]
fn an_oversized_upload_stays_in_the_log() {
    use artifactory_world::NAMES;
    use common::*;
    use fictionet::stdlib::ConnectionExt;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let mut io = tls(
            &fcx,
            &m,
            NAMES[0].1,
            NAMES[0].0,
            fictionet::stdlib::sandbox::client_config(
                &fcx,
                std::time::SystemTime::now(),
                Some(&env.roots),
                &[b"http/1.1"],
            )
            .unwrap(),
        )
        .await?;
        let size = (64 << 20) + 1;
        let head = format!(
            "POST /simple/ HTTP/1.1\r\n\
             Host: {}\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n",
            NAMES[0].0
        );
        io.write_all(&fcx, head.as_bytes()).await?;
        let chunk = vec![b'x'; 1 << 20];
        for _ in 0..64 {
            io.write_all(&fcx, &chunk).await?;
        }
        io.write_all(&fcx, b"x").await?;
        let mut response = vec![0; 4096];
        let n = io.read(&fcx, &mut response).await?;
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
    use fictionet::tokio::ConnectionTokioExt;
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::sync::Arc;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let mut config = (*fictionet::stdlib::sandbox::client_config(
            &fcx,
            std::time::SystemTime::now(),
            Some(&env.roots),
            &[b"http/1.1"],
        )
        .unwrap())
        .clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let io = tls(&fcx, &m, NAMES[0].1, NAMES[0].0, Arc::new(config)).await?;
        let (mut send, connection) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            TokioIo::new(io.into_tokio(&fcx)),
        )
        .await?;
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
