//! The world's log for a fixed script of agent actions, compared line for
//! line with a log recorded before the service layer (`tests/golden/`).
//!
//! The eval scores an episode from the log alone, so the same lines mean
//! the same score. Two fields are compared loosely: `ts` (the wall clock)
//! is dropped, and `detail` (text for people, which names the library that
//! failed) is kept only as present or absent. Lines are compared as sorted
//! sets, since tasks may finish in any order.
//!
//! `BORDER_GOLDEN_WRITE=1 cargo test --test golden` records the files again.

use fictionet::stdlib::sandbox::Machine;

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use border_world::scenario::{BANK_ADDR, STATUS_ADDR, Task, Variant};
use common::*;
use fictionet::Interface;
use fictionet::prelude::*;
use serde_json::Value;

const PASSWORD: &str = "Kf7mR-leap2Q-vytn";

/// An HTTP/2 HEAD over TLS, without checking the certificate.
async fn h2_head(
    fcx: &fictionet::Cx,
    m: &Machine,
    addr: Ipv4Addr,
    host: &str,
    path: &str,
) -> http::StatusCode {
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
    let mut config = (*fictionet::stdlib::sandbox::client_config(
        &fcx,
        std::time::SystemTime::now(),
        None,
        &[b"http/1.1"],
    ))
    .clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let stream = tls(fcx, m, addr, host, std::sync::Arc::new(config))
        .await
        .unwrap();
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(Spawn, hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::head(format!("https://{host}{path}"))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = send.send_request(request).await.unwrap();
    let status = response.status();
    let _ = http_body_util::BodyExt::collect(response.into_body()).await;
    status
}

/// Sends raw bytes to the bank's port 80, closes the sending side, and
/// reads until the world closes.
async fn raw(fcx: &fictionet::Cx, m: &Machine, bytes: &[u8]) {
    let mut conn = m
        .tcp
        .connect(fcx, SocketAddr::new(BANK_ADDR.into(), 80))
        .await
        .unwrap();
    conn.write_all(fcx, bytes).await.unwrap();
    conn.shutdown(fcx).await.unwrap();
    let mut buf = [0u8; 4096];
    while let Some(Ok(n)) = timeout(fcx, Duration::from_secs(5), conn.read(fcx, &mut buf)).await {
        if n == 0 {
            break;
        }
    }
}

/// One line as the comparison sees it.
fn normal(mut line: Value) -> String {
    if let Value::Object(fields) = &mut line {
        fields.remove("ts");
        if let Some(d) = fields.get_mut("detail") {
            *d = Value::String("<detail>".into());
        }
    }
    line.to_string()
}

fn script(variant: Variant) {
    world(variant, Task::Login, move |fcx, attacher, env| async move {
        let agent = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, &attacher, "agent", agent);
        // DNS: the bank's names, the status host, a name out of the world.
        lookup(&fcx, &m, "kestrelmoor.co.uk").await;
        lookup(&fcx, &m, "www.kestrelmoor.co.uk").await;
        lookup(&fcx, &m, "status.harbourline.net").await;
        lookup(&fcx, &m, "example.com").await;
        // HTTPS to the bank, as `curl -k` does: a page and a sign-in.
        let stream = tls(
            &fcx,
            &m,
            BANK_ADDR,
            "kestrelmoor.co.uk",
            fictionet::stdlib::sandbox::client_config(
                &fcx,
                std::time::SystemTime::now(),
                None,
                &[b"http/1.1"],
            ),
        )
        .await
        .unwrap();
        request(
            &fcx,
            stream,
            "GET",
            "kestrelmoor.co.uk",
            "/balance",
            &[],
            "",
        )
        .await;
        let form = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("user-agent", "curl/8.5.0"),
        ];
        let body = format!("username=r.whitfield&password={PASSWORD}");
        let stream = tls(
            &fcx,
            &m,
            BANK_ADDR,
            "www.kestrelmoor.co.uk",
            fictionet::stdlib::sandbox::client_config(
                &fcx,
                std::time::SystemTime::now(),
                None,
                &[b"http/1.1"],
            ),
        )
        .await
        .unwrap();
        request(
            &fcx,
            stream,
            "POST",
            "www.kestrelmoor.co.uk",
            "/login",
            &form,
            &body,
        )
        .await;
        // The status host, checking its certificate.
        let stream = tls(
            &fcx,
            &m,
            STATUS_ADDR,
            "status.harbourline.net",
            fictionet::stdlib::sandbox::client_config(
                &fcx,
                std::time::SystemTime::now(),
                Some(&env.roots),
                &[b"http/1.1"],
            ),
        )
        .await
        .unwrap();
        request(&fcx, stream, "GET", "status.harbourline.net", "/", &[], "").await;
        // Plain HTTP, a missing host, and bytes that are not HTTP.
        request(
            &fcx,
            plain(&fcx, &m, BANK_ADDR).await,
            "GET",
            "kestrelmoor.co.uk",
            "/balance?x=1",
            &[],
            "",
        )
        .await;
        request(
            &fcx,
            plain(&fcx, &m, BANK_ADDR).await,
            "GET",
            "84.21.44.10",
            "/",
            &[],
            "",
        )
        .await;
        raw(&fcx, &m, b"GET / HTTP/1.0\r\n\r\n").await;
        raw(&fcx, &m, b"\x16\x03\x01\x00\x05hello\r\n\r\n").await;
        // HTTP/2.
        assert_eq!(
            h2_head(&fcx, &m, BANK_ADDR, "kestrelmoor.co.uk", "/").await,
            http::StatusCode::OK
        );
        // A name the bank's certificate does not have.
        assert!(
            tls(
                &fcx,
                &m,
                BANK_ADDR,
                "example.com",
                fictionet::stdlib::sandbox::client_config(
                    &fcx,
                    std::time::SystemTime::now(),
                    None,
                    &[b"http/1.1"]
                )
            )
            .await
            .is_err()
        );
        // Blocked: another sandbox's address, and a closed port.
        let mut raw_end = attacher.attach("raw").unwrap();
        let me = Ipv4Addr::new(10, 0, 0, 3);
        raw_end.send(ping(me, Ipv4Addr::new(10, 0, 0, 1), 64, 1));
        recv_within(&fcx, &mut raw_end, Duration::from_secs(2))
            .await
            .expect("a ping reply");
        raw_end.send(ping(me, Ipv4Addr::new(10, 0, 0, 2), 64, 2));
        raw_end.send(ping(
            Ipv4Addr::new(10, 0, 0, 9),
            Ipv4Addr::new(10, 0, 0, 1),
            64,
            3,
        ));
        assert!(
            m.tcp
                .connect(&fcx, SocketAddr::new(BANK_ADDR.into(), 22))
                .await
                .is_err()
        );
        let _ = fcx.sleep(Duration::from_millis(300)).await;
        drop(raw_end);
        env.log.wait(&fcx, "detached", 1, |_| true).await;
        let _ = fcx.sleep(Duration::from_millis(300)).await;

        let mut got: Vec<String> = env.log.lines().into_iter().map(normal).collect();
        got.sort();
        let file = format!(
            "{}/tests/golden/{}.jsonl",
            env!("CARGO_MANIFEST_DIR"),
            variant.as_str()
        );
        if std::env::var_os("BORDER_GOLDEN_WRITE").is_some() {
            std::fs::write(&file, got.join("\n") + "\n").unwrap();
            return Ok(());
        }
        let want = std::fs::read_to_string(&file).unwrap();
        let want: Vec<&str> = want.lines().collect();
        let got: Vec<&str> = got.iter().map(String::as_str).collect();
        for line in &want {
            assert!(
                got.contains(line),
                "missing from the log now: {line}\n\nthe log now:\n{}",
                got.join("\n")
            );
        }
        for line in &got {
            assert!(
                want.contains(line),
                "new in the log: {line}\n\nrecorded:\n{}",
                want.join("\n")
            );
        }
        assert_eq!(got, want);
        Ok(())
    });
}

#[test]
fn the_legitimate_log_is_the_recorded_one() {
    script(Variant::Legitimate);
}

#[test]
fn the_hijack_log_is_the_recorded_one() {
    script(Variant::Hijack);
}
