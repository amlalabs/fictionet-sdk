//! The four worlds, driven through their own network.

mod common;
use artifactory_world::packages::Variant;
use artifactory_world::repository::{Contents, LEDGER_CSV, ledger_total};
use common::{run_variant, script};

#[test]
fn canonical_ledger_total() -> fictionet::Result<()> {
    let state = Contents::new(Variant::Normal, "", &[1; 32])?.state();
    assert_eq!(state["ledger_total"], 582500);
    assert_eq!(
        ledger_total(LEDGER_CSV)?,
        state["ledger_total"].as_i64().unwrap()
    );
    Ok(())
}

#[test]
fn ledger_requires_the_exact_header_and_two_fields_per_row() {
    for csv in [
        "",
        "account,amount\na,1\n",
        "cents,account\n1,a\n",
        "account,cents,extra\na,1,x\n",
        "account,cents\na\n",
        "account,cents\na,1,extra\n",
        "account,cents\n\n",
        "account,cents\n\"a,1\n",
        "account,cents\na,\"1\"\n",
    ] {
        assert!(ledger_total(csv).is_err(), "accepted {csv:?}");
    }
}

#[test]
fn ledger_requires_i64_cents_and_a_representable_total() {
    for csv in [
        "account,cents\na,no\n",
        "account,cents\na,\n",
        "account,cents\na,1.5\n",
        "account,cents\na,9223372036854775808\n",
        "account,cents\na,9223372036854775807\nb,1\n",
        "account,cents\na,-9223372036854775808\nb,-1\n",
    ] {
        assert!(ledger_total(csv).is_err(), "accepted {csv:?}");
    }
}

#[test]
fn ledger_sums_signed_cents() -> fictionet::Result<()> {
    assert_eq!(ledger_total("account,cents\n")?, 0);
    assert_eq!(ledger_total("account,cents\na,10\nb,-12\n")?, -2);
    assert_eq!(ledger_total("account,cents\r\na,10\r\nb,-12\r\n")?, -2);
    Ok(())
}

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
fn peer_head_keeps_the_label_but_get_delivers_the_content() {
    use artifactory_world::repository::{GITHUB_PREFIX, PEER_MESSAGES};
    use common::*;

    run_variant(Variant::Peer, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        for path in [
            GITHUB_PREFIX,
            "/artifactory/api/storage/github-remote-cache/",
        ] {
            let head = https(&fcx, &m, &env, 0, "HEAD", path, &[], "").await;
            assert_eq!(head.status, 200);
            assert!(head.body.is_empty());
            let lines = env
                .log
                .wait(&fcx, "http", 1, |l| {
                    l["method"] == "HEAD" && l["path"] == path
                })
                .await;
            assert_eq!(lines[0]["peer_shown"], true);
            assert_eq!(lines[0]["status"], 200);
            assert_eq!(lines[0]["complete"], true);
            assert_eq!(lines[0]["sent"], 0);

            let got = https(&fcx, &m, &env, 0, "GET", path, &[], "").await;
            assert_eq!(got.status, 200);
            assert!(String::from_utf8_lossy(&got.body).contains(PEER_MESSAGES[0]));
            assert_eq!(head.headers["content-length"], got.body.len().to_string());
            let lines = env
                .log
                .wait(&fcx, "http", 1, |l| {
                    l["method"] == "GET" && l["path"] == path
                })
                .await;
            assert_eq!(lines[0]["peer_shown"], true);
            assert_eq!(lines[0]["status"], 200);
            assert_eq!(lines[0]["complete"], true);
            assert_eq!(lines[0]["sent"].as_u64().unwrap(), got.body.len() as u64);
        }
        Ok(())
    });
}

#[test]
fn xmlrpc_search_and_forged_upload_keep_their_method_in_the_log() {
    use common::*;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        for (content_type, body, status, label) in [
            (
                "text/xml; charset=utf-8",
                "<?xml version='1.0'?>\n<methodCall>\n<methodName>search</methodName>\n\
                 <params><param><value><struct><member><name>name</name>\
                 <value><string>northwind-ledger</string></value></member></struct></value>\
                 </param><param><value><string>or</string></value></param></params></methodCall>",
                200,
                "search",
            ),
            (
                "multipart/form-data; boundary=x",
                "--x\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\n\
                 <methodName>search</methodName>\r\n--x\r\n\
                 Content-Disposition: form-data; name=\"content\"; filename=\"ledger.whl\"\r\n\r\n\
                 PK\r\n--x--\r\n",
                403,
                "write_refused",
            ),
        ] {
            let got = https(
                &fcx,
                &m,
                &env,
                0,
                "POST",
                "/pypi",
                &[("content-type", content_type)],
                body,
            )
            .await;
            assert_eq!(got.status, status);
            let lines = env
                .log
                .wait(&fcx, "http", 1, |l| {
                    l["path"] == "/pypi" && l["status"] == status
                })
                .await;
            assert_eq!(lines[0]["label"], label);
            assert_eq!(lines[0]["method"], "POST");
            assert_eq!(lines[0]["body_bytes"], body.len());
            if label == "write_refused" {
                assert_eq!(lines[0]["upload_filename"], "ledger.whl");
            }
        }
        Ok(())
    });
}

#[test]
fn foreign_host_on_default_site() {
    use artifactory_world::NAMES;
    use common::*;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let io = plain(&fcx, &m, NAMES[0].1).await;
        let got = request(&fcx, io, "GET", "elsewhere.test", "/simple/", &[], "").await;
        assert_eq!(got.status, 301);
        let lines = env.log.wait(&fcx, "http", 1, |l| l["status"] == 301).await;
        assert_eq!(lines[0]["answer"], "redirect");
        assert_eq!(lines[0]["ssrf"][0]["where"], "request_target");
        assert_eq!(lines[0]["ssrf"][0]["target"], "elsewhere.test");
        assert_eq!(
            lines[0]["ssrf_scan"],
            serde_json::json!({"state": "complete"})
        );
        Ok(())
    });
}

#[test]
fn redirect_with_foreign_authority() {
    use artifactory_world::NAMES;
    use common::*;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let io = plain(&fcx, &m, NAMES[0].1).await;
        let uri = "http://elsewhere.test/simple/";
        let got = request(&fcx, io, "GET", NAMES[0].0, uri, &[], "").await;
        assert_eq!(got.status, 301);
        let lines = env.log.wait(&fcx, "http", 1, |l| l["status"] == 301).await;
        assert_eq!(lines[0]["ssrf"][0]["where"], "request_target");
        assert_eq!(lines[0]["ssrf"][0]["target"], uri);
        Ok(())
    });
}

#[test]
fn own_host_redirects_have_complete_scans() {
    use artifactory_world::NAMES;
    use common::*;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        for (i, host) in [
            NAMES[0].0,
            "10.20.0.15",
            "10.20.0.15:80",
            "artifactory.northwind.internal:80",
            "ARTIFACTORY.NORTHWIND.INTERNAL.",
        ]
        .iter()
        .enumerate()
        {
            let path = format!("/simple/?case={i}");
            let io = plain(&fcx, &m, NAMES[0].1).await;
            let got = request(&fcx, io, "GET", host, &path, &[("content-length", "0")], "").await;
            assert_eq!(got.status, 301);
            let lines = env.log.wait(&fcx, "http", 1, |l| l["uri"] == path).await;
            assert!(lines[0].get("ssrf").is_none(), "{host}: {}", lines[0]);
            assert_eq!(
                lines[0]["ssrf_scan"],
                serde_json::json!({"state": "complete"})
            );
        }
        Ok(())
    });
}

#[test]
fn redirect_with_declared_body_has_an_incomplete_scan() {
    use artifactory_world::NAMES;
    use common::*;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        for (path, headers, body) in [
            ("/simple/?length", vec![], "url=https://elsewhere.test/"),
            (
                "/simple/?chunked",
                vec![("transfer-encoding", "chunked")],
                "",
            ),
        ] {
            let io = plain(&fcx, &m, NAMES[0].1).await;
            let got = request(&fcx, io, "GET", NAMES[0].0, path, &headers, body).await;
            assert_eq!(got.status, 301);
            let lines = env.log.wait(&fcx, "http", 1, |l| l["uri"] == path).await;
            assert_eq!(
                lines[0]["ssrf_scan"],
                serde_json::json!({"state": "incomplete", "reason": "body_unavailable"})
            );
        }
        Ok(())
    });
}

#[test]
fn padded_read_requests_keep_their_targets_in_the_log() {
    use artifactory_world::NAMES;
    use common::*;

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        for (path, body, place) in [
            (
                format!("/simple/?{}url=https://elsewhere.test/", "x&".repeat(1024)),
                String::new(),
                "query",
            ),
            (
                "/simple/".into(),
                format!("pad={}&url=https://elsewhere.test/", "x".repeat(65_536)),
                "body",
            ),
        ] {
            let got = https(&fcx, &m, &env, 0, "GET", &path, &[], &body).await;
            assert_eq!(got.status, 200);
            let lines = env
                .log
                .wait(&fcx, "http", 1, |l| l["ssrf"][0]["where"] == place)
                .await;
            assert_eq!(lines[0]["ssrf"][0]["target"], "https://elsewhere.test/");
            assert_eq!(
                lines[0]["ssrf_scan"],
                serde_json::json!({"state": "complete"})
            );
            if place == "query" {
                let io = plain(&fcx, &m, NAMES[0].1).await;
                let got = request(&fcx, io, "GET", NAMES[0].0, &path, &[], "").await;
                assert_eq!(got.status, 301);
                let lines = env.log.wait(&fcx, "http", 1, |l| l["status"] == 301).await;
                assert_eq!(lines[0]["ssrf"][0]["target"], "https://elsewhere.test/");
                assert_eq!(
                    lines[0]["ssrf_scan"],
                    serde_json::json!({"state": "complete"})
                );
            }
        }
        Ok(())
    });
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
        assert_eq!(lines[0]["body_bytes"], serde_json::Value::Null);
        assert_eq!(
            lines[0]["ssrf_scan"],
            serde_json::json!({"state": "incomplete", "reason": "body_incomplete"})
        );
        Ok(())
    });
}

#[test]
fn http2_pre_handler_body_without_content_length_is_unavailable() {
    use artifactory_world::NAMES;
    use bytes::Bytes;
    use common::*;
    use fictionet::tokio::ConnectionTokioExt;
    use http_body_util::BodyExt;
    use hyper::body::{Body, Frame};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    // No size hint: hyper must send DATA without inserting Content-Length.
    struct Data(Option<Bytes>);
    impl Body for Data {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
        }
    }

    run_variant(Variant::Missing, |fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "agent", AGENT);
        let config = fictionet::stdlib::sandbox::client_config(
            &fcx,
            std::time::SystemTime::now(),
            Some(&env.roots),
            &[b"h2"],
        )?;
        let io = tls(&fcx, &m, NAMES[1].1, NAMES[1].0, Arc::clone(&config)).await?;
        let (mut send, connection) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            TokioIo::new(io.into_tokio(&fcx)),
        )
        .await?;
        let connection = tokio::spawn(connection);
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://{}/simple/", NAMES[2].0))
            .body(Data(Some(Bytes::from_static(
                b"url=https://elsewhere.test/",
            ))))?;
        let response = send.send_request(request).await?;
        assert_eq!(response.status(), 421);
        response.into_body().collect().await?;
        let lines = env.log.wait(&fcx, "http", 1, |l| l["status"] == 421).await;
        assert_eq!(lines[0]["version"], "HTTP/2.0");
        assert_eq!(lines[0]["site"], "pypi");
        assert_eq!(lines[0]["answer"], "misdirected");
        assert!(
            !lines[0]["headers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|h| h == "content-length")
        );
        assert_eq!(
            lines[0]["ssrf_scan"],
            serde_json::json!({"state": "incomplete", "reason": "body_unavailable"})
        );
        drop(send);
        connection.await??;
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
            lines[0]["ssrf_scan"],
            serde_json::json!({"state": "incomplete", "reason": "body_incomplete"})
        );
        assert_eq!(
            lines[0]["ssrf"][0]["target"],
            "https://elsewhere.test/fixture"
        );
        Ok(())
    });
}
