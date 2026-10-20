use super::*;
use fictionet::events::ConnInfo;
use fictionet::stdlib::web::httpd::{self, Exchange, Handler, Reply, VHost, VirtualHosts};
use fictionet::{RunOptions, Seed};
use std::collections::VecDeque;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const PACKAGE: &str = "/ubuntu/pool/main/p/package/package_1_amd64.deb";
const INDEX: &str = "/ubuntu/dists/noble/InRelease";

struct Upstream {
    uri: http::Uri,
    requests: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<VecDeque<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl Upstream {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let seen = requests.clone();
        let responses = replies.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                let responses = responses.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(socket.read_u8().await.unwrap());
                        assert!(head.len() < MAX_HEAD);
                    }
                    seen.lock().unwrap().push(String::from_utf8(head).unwrap());
                    let response = responses
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| reply("200 OK", "", b"package"));
                    socket.write_all(&response).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
        });
        Self {
            uri,
            requests,
            replies,
            task,
        }
    }

    fn push(&self, response: Vec<u8>) {
        self.replies.lock().unwrap().push_back(response);
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn cache(&self, fcx: &Cx, root: &Path) -> Cache<web::Forward> {
        Cache::new(
            web::forward(fcx, self.uri.clone()).unwrap(),
            root.to_owned(),
        )
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn reply(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn request(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("host", "mirror.test")
        .body(Body::empty())
        .unwrap()
}

// Exercise the real routing boundary that supplies the cache's origin key.
async fn send<S>(fcx: &Cx, cache: &Cache<S>, request: Request<Body>) -> Answer
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    send_on(fcx, cache, request, false).await
}

async fn send_on<S>(fcx: &Cx, cache: &Cache<S>, request: Request<Body>, tls: bool) -> Answer
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    let hosts = VirtualHosts::new();
    let mut host = VHost::new(httpd::tower(cache.clone()));
    host.https = tls;
    hosts.insert("mirror.test", host.clone());
    hosts.insert("releases.openai.com", host.clone());
    hosts.insert("other.test", host);
    let conn = ConnInfo {
        local: Some(
            format!("127.0.0.1:{}", if tls { 443 } else { 80 })
                .parse()
                .unwrap(),
        ),
        tls,
        ..ConnInfo::default()
    };
    match hosts.call(request, &mut Exchange::new(fcx.now(), fcx, &conn)) {
        Reply::Now(r) => Ok(r),
        Reply::Later(f) => f(fcx.clone()).await,
        Reply::Handoff(_) => panic!("unexpected upgrade"),
    }
}

async fn bytes(response: Response<Body>) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

async fn run<F: Future<Output = ()> + Send + 'static>(f: impl FnOnce(Cx) -> F + Send + 'static) {
    tokio::time::timeout(
        Duration::from_secs(20),
        fictionet::run(RunOptions::new(Seed::from_u64(1)), |fcx| async move {
            f(fcx).await;
            Ok(())
        }),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn miss_then_hit_survives_a_new_run() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        let response = send(&fcx, &cache, request(PACKAGE)).await.unwrap();
        assert_eq!(
            response
                .extensions()
                .get::<fictionet::events::Fields>()
                .unwrap()
                .get("forwarded")
                .and_then(|v| v.as_str()),
            Some(upstream.uri.to_string().trim_end_matches('/'))
        );
        assert_eq!(bytes(response).await, "package");
        let response = send(&fcx, &cache, request(PACKAGE)).await.unwrap();
        let fields = response
            .extensions()
            .get::<fictionet::events::Fields>()
            .unwrap();
        assert_eq!(
            fields.get("served_by").and_then(|v| v.as_str()),
            Some("host package cache")
        );
        assert!(fields.get("forwarded").is_none());
        assert_eq!(bytes(response).await, "package");
        assert_eq!(upstream.count(), 1);
        assert_eq!(cache.state.stats.saved.load(Ordering::Relaxed), 7);
        cache.close().await;
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 1);
    })
    .await;
}

#[tokio::test]
async fn mutable_indexes_keep_origin_validators_and_changes() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for path in [INDEX, "/ubuntu/dists/noble/main/binary-amd64/Packages.xz"] {
            for body in [b"first".as_slice(), b"second"] {
                upstream.push(reply("200 OK", "ETag: \"current\"\r\n", body));
                assert_eq!(
                    bytes(send(&fcx, &cache, request(path)).await.unwrap()).await,
                    body
                );
            }
            for (name, value) in [
                (header::IF_NONE_MATCH, "\"current\""),
                (header::IF_MODIFIED_SINCE, "Wed, 01 Jul 2026 12:00:00 GMT"),
            ] {
                upstream.push(reply(
                    "304 Not Modified",
                    "ETag: \"updated\"\r\nCache-Control: no-cache\r\n",
                    b"",
                ));
                let mut req = request(path);
                req.headers_mut()
                    .insert(name.clone(), value.parse().unwrap());
                let response = send(&fcx, &cache, req).await.unwrap();
                assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(response.headers()[header::ETAG], "\"updated\"");
                assert!(bytes(response).await.is_empty());
                assert!(
                    upstream
                        .requests
                        .lock()
                        .unwrap()
                        .last()
                        .unwrap()
                        .contains(&format!("{name}: {value}"))
                );
            }
        }
        assert_eq!(upstream.count(), 8);
        assert!(!dir.path().join("mirror.test").exists());
    })
    .await;
}

#[tokio::test]
async fn offline_indexes_report_failure_instead_of_stale_success() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let mut upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        upstream.push(reply("503 Service Unavailable", "", b"offline"));
        let response = send(&fcx, &cache, request(INDEX)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(bytes(response).await, "offline");
        upstream.task.abort();
        let _ = (&mut upstream.task).await;
        assert!(send(&fcx, &cache, request(INDEX)).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn partial_body_is_never_published() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        upstream.push(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        );
        let cache = upstream.cache(&fcx, dir.path());
        assert!(
            send(&fcx, &cache, request(PACKAGE))
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .is_err()
        );
        let path = dir.path().join("mirror.test/http-80").join(&PACKAGE[1..]);
        assert!(!path.exists());
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            0
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 2);
    })
    .await;
}

#[tokio::test]
async fn concurrent_misses_share_one_fetch() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for path in [PACKAGE] {
            let mut pending = Vec::new();
            for _ in 0..8 {
                pending.push(Box::pin(send(&fcx, &cache, request(path))));
            }
            // Poll every request before permitting the server to run.
            std::future::poll_fn(|cx| {
                for future in &mut pending {
                    assert!(future.as_mut().poll(cx).is_pending());
                }
                Poll::Ready(())
            })
            .await;
            for future in pending {
                assert_eq!(bytes(future.await.unwrap()).await, "package");
            }
        }
        assert_eq!(upstream.count(), 1);
    })
    .await;
}

#[tokio::test]
async fn ranges_use_complete_entries_and_other_ranges_pass_through() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        upstream.push(reply(
            "206 Partial Content",
            "Content-Range: bytes 2-6/7\r\n",
            b"ckage",
        ));
        let cache = upstream.cache(&fcx, dir.path());
        let mut req = request(PACKAGE);
        req.headers_mut()
            .insert(header::RANGE, "bytes=2-".parse().unwrap());
        assert_eq!(
            send(&fcx, &cache, req).await.unwrap().status(),
            StatusCode::PARTIAL_CONTENT
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        for (range, expected, content_range) in [
            ("bytes=2-", "ckage", "bytes 2-6/7"),
            ("bytes=1-3", "ack", "bytes 1-3/7"),
            ("bytes=-3", "age", "bytes 4-6/7"),
        ] {
            let mut req = request(PACKAGE);
            req.headers_mut()
                .insert(header::RANGE, range.parse().unwrap());
            let response = send(&fcx, &cache, req).await.unwrap();
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(response.headers()[header::CONTENT_RANGE], content_range);
            assert_eq!(bytes(response).await, expected);
        }
        assert_eq!(upstream.count(), 2);
        for range in ["bytes=999-", "bytes=0-1,3-4", "bytes=-0"] {
            let mut req = request(PACKAGE);
            req.headers_mut()
                .insert(header::RANGE, range.parse().unwrap());
            bytes(send(&fcx, &cache, req).await.unwrap()).await;
        }
        assert_eq!(upstream.count(), 5);
    })
    .await;
}

#[tokio::test]
async fn errors_and_unknown_paths_are_not_cached() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for status in ["404 Not Found", "503 Service Unavailable", "302 Found"] {
            upstream.push(reply(status, "", b"error"));
            assert_ne!(
                send(&fcx, &cache, request(PACKAGE)).await.unwrap().status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 4);
        for path in [
            "/key.asc",
            "/robots.txt",
            "/ubuntu/pool/a.deb?query=1",
            "/ubuntu/pool/../a.deb",
        ] {
            for _ in 0..2 {
                bytes(send(&fcx, &cache, request(path)).await.unwrap()).await;
            }
        }
        assert_eq!(upstream.count(), 12);
    })
    .await;
}

#[tokio::test]
async fn tls_origin_and_hosts_have_separate_entries() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for tls in [false, true] {
            for host in ["mirror.test", "other.test"] {
                for _ in 0..2 {
                    let mut req = request(PACKAGE);
                    req.headers_mut()
                        .insert(header::HOST, host.parse().unwrap());
                    assert_eq!(
                        bytes(send_on(&fcx, &cache, req, tls).await.unwrap()).await,
                        "package"
                    );
                }
            }
        }
        assert_eq!(upstream.count(), 4);
    })
    .await;
}

#[test]
fn repository_policy_and_path_limits() {
    assert!(immutable(PACKAGE));
    assert!(immutable("/apt/pool/firefox_1%3a2.deb"));
    assert!(immutable(&format!(
        "/ubuntu/dists/noble/main/by-hash/SHA256/{}",
        "a".repeat(64)
    )));
    assert!(immutable(&format!(
        "/ubuntu/dists/noble/main/by-hash/SHA512/{}",
        "A".repeat(128)
    )));
    for path in [
        INDEX,
        "/ubuntu/dists/noble/Packages.xz",
        "/key.asc",
        "/pool/a.txt",
        "/pool/../escape.deb",
        "/pool//a.deb",
        "/pool/./a.deb",
        "/pool/a\\b.deb",
        "/pool/%2e%2e/a.deb",
        "/pool/a%2fb.deb",
        "/pool/a%5Cb.deb",
        "/pool/a%00.deb",
        "/pool/a%253a.deb",
        "/pool/é.deb",
        "/pool/..\0.deb",
        "/pool/a%0d%0a.deb",
        "/ubuntu/dists/noble/by-hash/SHA256/not-a-hash",
        "/by-hash/anything",
        "/ubuntu/dists/pool/index.deb",
    ] {
        assert!(!immutable(path), "{path}");
    }
    assert!(!immutable(&format!("/pool/{}.deb", "a".repeat(250))));
    assert!(!immutable(&format!("/pool/{}a.deb", "a/".repeat(33))));
    assert!(!immutable(&format!("/pool/{}a.deb", "a".repeat(2048))));
}

#[test]
fn release_files_are_immutable_inside_version_directories() {
    const CLAUDE: &str = "downloads.claude.ai";
    const OPENAI: &str = "releases.openai.com";
    for (host, path) in [
        (CLAUDE, "/claude-code-releases/2.1.292/linux-x64/claude.zst"),
        (CLAUDE, "/claude-code-releases/2.1.292/manifest.json"),
        (OPENAI, "/codex/releases/0.163.0/codex-package_SHA256SUMS"),
        (OPENAI, "/codex/releases/0.164.0-alpha.3/codex.tar.zst"),
    ] {
        assert!(release(host, path), "{host}{path}");
    }
    for (host, path) in [
        // Channels move to new releases.
        (CLAUDE, "/claude-code-releases/stable"),
        (CLAUDE, "/claude-code-releases/latest"),
        (OPENAI, "/codex/channels/latest"),
        (OPENAI, "/codex/install.sh"),
        // A version directory itself, and names that are not versions.
        (CLAUDE, "/claude-code-releases/2.1.292"),
        (CLAUDE, "/claude-code-releases/2.1/manifest.json"),
        (CLAUDE, "/claude-code-releases/2.1.x/manifest.json"),
        (OPENAI, "/codex/releases/latest/release.json"),
        // The layout belongs to its own host.
        ("mirror.test", "/claude-code-releases/2.1.292/manifest.json"),
        (CLAUDE, "/codex/releases/0.163.0/release.json"),
        // Ambiguous or encoded names.
        (CLAUDE, "/claude-code-releases/2.1.292/../stable"),
        (CLAUDE, "/claude-code-releases/2.1.292/%2e%2e/a"),
        (CLAUDE, "/claude-code-releases/2.1.292//claude"),
    ] {
        assert!(!release(host, path), "{host}{path}");
    }
}

#[tokio::test]
async fn a_client_that_stops_at_content_length_still_leaves_the_file() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        let mut body = send(&fcx, &cache, request(PACKAGE))
            .await
            .unwrap()
            .into_body();
        let mut got = Vec::new();
        while got.len() < "package".len() {
            let frame = body.frame().await.unwrap().unwrap();
            got.extend_from_slice(&frame.into_data().unwrap());
        }
        // Leave before the end of the stream, as curl does.
        drop(body);
        assert_eq!(got, b"package");
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 1);
    })
    .await;
}

#[tokio::test]
async fn release_files_are_passed_on_and_stored_without_cookies() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        let release = |path: &str| {
            Request::builder()
                .uri(path)
                .header("host", "releases.openai.com")
                .body(Body::empty())
                .unwrap()
        };
        let file = "/codex/releases/0.163.0/codex.tar.zst";
        upstream.push(reply("200 OK", "Set-Cookie: __cf_bm=one\r\n", b"package"));
        for _ in 0..2 {
            let response = send(&fcx, &cache, release(file)).await.unwrap();
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert_eq!(bytes(response).await, "package");
        }
        assert_eq!(upstream.count(), 1);
        // A channel moves, so it passes through, cookies and all.
        upstream.push(reply("200 OK", "Set-Cookie: __cf_bm=two\r\n", b"0.163.0"));
        let channel = send(&fcx, &cache, release("/codex/channels/latest"))
            .await
            .unwrap();
        assert!(channel.headers().contains_key(header::SET_COOKIE));
        assert_eq!(bytes(channel).await, "0.163.0");
        assert_eq!(upstream.count(), 2);
    })
    .await;
}

#[tokio::test]
async fn by_hash_is_immutable_and_damaged_entries_are_refetched() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let path = &format!("/ubuntu/dists/noble/main/by-hash/SHA256/{}", "a".repeat(64));
        let cache = upstream.cache(&fcx, dir.path());
        bytes(send(&fcx, &cache, request(path)).await.unwrap()).await;
        cache.close().await;
        let cache = upstream.cache(&fcx, dir.path());
        bytes(send(&fcx, &cache, request(path)).await.unwrap()).await;
        assert_eq!(upstream.count(), 1);
        let disk_path = dir.path().join("mirror.test/http-80").join(&path[1..]);
        let file = File::options().write(true).open(disk_path).await.unwrap();
        file.set_len(5).await.unwrap();
        assert_eq!(
            bytes(send(&fcx, &cache, request(path)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 2);
    })
    .await;
}

#[tokio::test]
async fn uncacheable_representations_and_requests_pass_through() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for extra in [
            "Vary: Accept-Language\r\n",
            "Cache-Control: no-store\r\n",
            "Content-Encoding: gzip\r\n",
            "Set-Cookie: session=value\r\n",
        ] {
            upstream.push(reply("200 OK", extra, b"uncached"));
            assert_eq!(
                bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
                "uncached"
            );
        }
        upstream.push(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno length".to_vec());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "no length"
        );
        for name in [
            header::AUTHORIZATION,
            header::COOKIE,
            header::IF_NONE_MATCH,
            header::IF_MODIFIED_SINCE,
        ] {
            let mut req = request(PACKAGE);
            req.headers_mut().insert(name, "value".parse().unwrap());
            bytes(send(&fcx, &cache, req).await.unwrap()).await;
        }
        assert_eq!(upstream.count(), 9);
        assert_eq!(
            *cache.state.stats.bypassed.lock().unwrap(),
            BTreeMap::from([
                ("response variant", 3),
                ("response directive", 1),
                ("response framing", 1),
                ("credentials", 2),
                ("conditional or range", 2),
            ])
        );
        assert!(!dir.path().join("mirror.test").exists());
        bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await;
        bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await;
        assert_eq!(upstream.count(), 10);
        assert!(upstream.requests.lock().unwrap()[9].contains("accept-encoding: identity"));
    })
    .await;
}

#[tokio::test]
async fn changed_if_range_is_forwarded() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        upstream.push(reply("200 OK", "ETag: \"current\"\r\n", b"package"));
        bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await;
        for validator in ["\"current\"", "\"old\"", "W/\"current\""] {
            let mut req = request(PACKAGE);
            req.headers_mut()
                .insert(header::RANGE, "bytes=2-".parse().unwrap());
            req.headers_mut()
                .insert(header::IF_RANGE, validator.parse().unwrap());
            let response = send(&fcx, &cache, req).await.unwrap();
            if validator == "\"current\"" {
                assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
                assert_eq!(bytes(response).await, "ckage");
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(bytes(response).await, "package");
            }
        }
        assert_eq!(upstream.count(), 3);
    })
    .await;
}

#[tokio::test]
async fn interrupted_mutable_index_is_not_hidden_by_cached_bytes() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        upstream.push(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        );
        assert!(
            send(&fcx, &cache, request(INDEX))
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .is_err()
        );
        assert_eq!(upstream.count(), 2);
        assert!(!dir.path().join("mirror.test").exists());
    })
    .await;
}

#[tokio::test]
async fn immutable_conditions_obey_precedence_and_weak_comparison() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        upstream.push(reply(
            "200 OK",
            "ETag: \"current\"\r\nLast-Modified: Wed, 01 Jul 2026 12:00:00 GMT\r\n",
            b"package",
        ));
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        for (tag, status) in [
            ("W/\"current\"", StatusCode::NOT_MODIFIED),
            ("\"old\"", StatusCode::OK),
            ("*", StatusCode::NOT_MODIFIED),
        ] {
            let mut req = request(PACKAGE);
            req.headers_mut()
                .insert(header::IF_NONE_MATCH, tag.parse().unwrap());
            req.headers_mut().insert(
                header::IF_MODIFIED_SINCE,
                "Wed, 01 Jul 2026 12:00:00 GMT".parse().unwrap(),
            );
            let response = send(&fcx, &cache, req).await.unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(
                bytes(response).await.len(),
                if status == StatusCode::OK { 7 } else { 0 }
            );
        }
        assert_eq!(upstream.count(), 1);
    })
    .await;
}

#[derive(Clone)]
struct Scripted {
    replies: Arc<Mutex<VecDeque<Response<Body>>>>,
    requests: Arc<Mutex<Vec<Request<Body>>>>,
}
impl Scripted {
    fn new(replies: Vec<Response<Body>>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into())),
            requests: Arc::default(),
        }
    }
}
impl Service<Request<Body>> for Scripted {
    type Response = Response<Body>;
    type Error = Error;
    type Future = std::future::Ready<Answer>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: Request<Body>) -> Self::Future {
        self.requests.lock().unwrap().push(request);
        std::future::ready(Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected upstream request")))
    }
}

struct ControlledBody(mpsc::Receiver<Result<Frame<Bytes>, Error>>);
impl http_body::Body for ControlledBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        self.0.poll_recv(cx)
    }
}

fn complete(body: &'static str) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn cold_response_streams_before_completion_and_waiters_retry_failure() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let (tx, rx) = mpsc::channel(1);
        let source = Scripted::new(vec![
            Response::builder()
                .header(header::CONTENT_LENGTH, 7)
                .body(Body::new(ControlledBody(rx)))
                .unwrap(),
            complete("package"),
        ]);
        let cache = Cache::new(source.clone(), dir.path().to_owned());
        let path = dir.path().join("mirror.test/http-80").join(&PACKAGE[1..]);
        let mut first = send(&fcx, &cache, request(PACKAGE))
            .await
            .unwrap()
            .into_body();
        tx.send(Ok(Frame::data(Bytes::from_static(b"pac"))))
            .await
            .unwrap();
        assert_eq!(
            first.frame().await.unwrap().unwrap().into_data().unwrap(),
            "pac"
        );
        assert!(!path.exists());
        let mut waiter = Box::pin(send(&fcx, &cache, request(PACKAGE)));
        std::future::poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tx.send(Err(Error::msg("upstream interrupted")))
            .await
            .unwrap();
        assert!(first.collect().await.is_err());
        assert_eq!(bytes(waiter.await.unwrap()).await, "package");
        assert_eq!(source.requests.lock().unwrap().len(), 2);
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(source.requests.lock().unwrap().len(), 2);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn cancelled_download_releases_its_key_and_never_publishes() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let (tx, rx) = mpsc::channel(1);
        let source = Scripted::new(vec![
            Response::builder()
                .header(header::CONTENT_LENGTH, 7)
                .body(Body::new(ControlledBody(rx)))
                .unwrap(),
            complete("package"),
        ]);
        let cache = Cache::new(source, dir.path().to_owned());
        let mut body = send(&fcx, &cache, request(PACKAGE))
            .await
            .unwrap()
            .into_body();
        tx.send(Ok(Frame::data(Bytes::from_static(b"pac"))))
            .await
            .unwrap();
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "pac"
        );
        drop(body);
        tx.closed().await;
        let path = dir.path().join("mirror.test/http-80").join(&PACKAGE[1..]);
        assert!(!path.exists());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn all_traffic_and_key_waiters_share_bounded_admission() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let source = Scripted::new(vec![complete("package")]);
        let mut cache = Cache::new(source.clone(), dir.path().to_owned());
        // Unpolled futures consume admission too, so they cannot accumulate
        // unbounded key locks or upstream requests.
        let pending: Vec<_> = (0..SLOTS).map(|_| cache.call(request(PACKAGE))).collect();
        for path in [PACKAGE, INDEX, "/arbitrary?query=1"] {
            let response = cache.call(request(path)).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(bytes(response).await, "apt mirror busy\n");
        }
        assert!(source.requests.lock().unwrap().is_empty());
        assert_eq!(cache.state.stats.bypassed.lock().unwrap()["admission"], 3);
        drop(pending);
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(source.requests.lock().unwrap().len(), 1);
    })
    .await;
}

#[tokio::test]
async fn hostile_fill_headers_cannot_select_or_frame_the_stored_object() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        let mut req = request(PACKAGE);
        for (name, value) in [
            ("accept-language", "evil"),
            ("x-rewrite-url", "/private"),
            ("x-forwarded-host", "evil.test"),
            ("connection", "accept-encoding"),
            ("accept-encoding", "gzip"),
            ("content-length", "999"),
            ("transfer-encoding", "chunked"),
            ("expect", "100-continue"),
        ] {
            req.headers_mut().insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        assert_eq!(
            bytes(send(&fcx, &cache, req).await.unwrap()).await,
            "package"
        );
        let wire = upstream.requests.lock().unwrap()[0].clone();
        assert!(wire.contains("accept-encoding: identity\r\n"));
        for text in [
            "evil",
            "private",
            "gzip",
            "999",
            "chunked",
            "100-continue",
            "connection:",
        ] {
            assert!(!wire.contains(text), "{wire}");
        }
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 1);
    })
    .await;
}

#[tokio::test]
async fn head_queries_and_storage_directives_do_not_populate_or_poison() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        let mut req = request(PACKAGE);
        *req.method_mut() = Method::HEAD;
        let response = send(&fcx, &cache, req).await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "7");
        assert!(bytes(response).await.is_empty());
        for path in [format!("{PACKAGE}?variant=1"), PACKAGE.to_owned()] {
            let mut req = request(&path);
            if path == PACKAGE {
                *req.method_mut() = Method::POST;
            }
            assert_eq!(
                bytes(send(&fcx, &cache, req).await.unwrap()).await,
                "package"
            );
        }
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        for (name, value) in [
            (header::CACHE_CONTROL, "no-store"),
            (header::CACHE_CONTROL, "no-cache, no-store"),
            (header::PRAGMA, "unknown"),
        ] {
            upstream.push(reply("200 OK", "", b"fresh"));
            let mut req = request(PACKAGE);
            req.headers_mut().insert(name, value.parse().unwrap());
            assert_eq!(bytes(send(&fcx, &cache, req).await.unwrap()).await, "fresh");
        }
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 7);
        assert_eq!(
            *cache.state.stats.bypassed.lock().unwrap(),
            BTreeMap::from([("query or method", 3), ("request directive", 3)])
        );
    })
    .await;
}

#[tokio::test]
async fn no_cache_private_variants_and_chunked_responses_are_never_retained() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for extra in [
            "Cache-Control: no-cache\r\n",
            "Cache-Control: private=\"ETag\"\r\n",
            "Vary: *\r\n",
            "Vary: Accept-Encoding, Cookie\r\n",
            "Content-Encoding: identity\r\nContent-Encoding: gzip\r\n",
        ] {
            upstream.push(reply("200 OK", extra, b"variant"));
            assert_eq!(
                bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
                "variant"
            );
        }
        upstream.push(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                .to_vec(),
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "abc"
        );
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(upstream.count(), 6);
    })
    .await;
}

#[tokio::test]
async fn cache_age_survives_restart_and_origin_expiry_is_respected() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let date = httpdate::fmt_http_date(SystemTime::now() - Duration::from_secs(300));
        upstream.push(reply(
            "200 OK",
            &format!("Date: {date}\r\nAge: 500\r\nCache-Control: max-age=1000\r\n"),
            b"package",
        ));
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        cache.close().await;
        let path = dir.path().join("mirror.test/http-80").join(&PACKAGE[1..]);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(100))
            .unwrap();
        let cache = upstream.cache(&fcx, dir.path());
        let response = send(&fcx, &cache, request(PACKAGE)).await.unwrap();
        assert_eq!(response.headers()[header::DATE], date);
        assert!(header_age(response.headers()) >= 600);
        assert_eq!(bytes(response).await, "package");
        assert_eq!(upstream.count(), 1);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(1001))
            .unwrap();
        upstream.push(reply("200 OK", "Cache-Control: max-age=0\r\n", b"changed"));
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "changed"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 3);
    })
    .await;
}

#[tokio::test]
async fn symlinks_and_hardlinks_disable_cache_without_touching_the_target() {
    run(|fcx| async move {
        for location in ["root", "host", "file", "hardlink"] {
            let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
            let outside = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
            let sentinel = outside.path().join("sentinel");
            std::fs::write(&sentinel, "do not touch").unwrap();
            let root = dir.path().join("cache");
            if location == "root" {
                std::os::unix::fs::symlink(outside.path(), &root).unwrap();
            } else {
                std::fs::create_dir(&root).unwrap();
                if location == "host" {
                    std::os::unix::fs::symlink(outside.path(), root.join("mirror.test")).unwrap();
                } else {
                    let path = root.join("mirror.test/http-80").join(&PACKAGE[1..]);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    if location == "file" {
                        std::os::unix::fs::symlink(&sentinel, path).unwrap();
                    } else {
                        std::fs::hard_link(&sentinel, path).unwrap();
                    }
                }
            }
            let source = Scripted::new(vec![complete("package"), complete("fresh")]);
            let cache = Cache::new(source, root);
            assert_eq!(
                bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
                "package"
            );
            assert_eq!(
                bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
                "fresh"
            );
            assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "do not touch");
            assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
        }
    })
    .await;
}

#[tokio::test]
async fn disk_budget_includes_old_files_and_limits_new_admission() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let file = std::fs::File::create(dir.path().join("old")).unwrap();
        file.set_len(MAX_TOTAL - 8192).unwrap();
        let source = Scripted::new(vec![complete("package"), complete("fresh")]);
        let cache = Cache::new(source, dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "fresh"
        );
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(cache.state.stats.bypassed.lock().unwrap()["full cache"], 2);
    })
    .await;
}

#[tokio::test]
async fn reservations_bound_concurrent_files_and_release_failed_downloads() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    let disk = Arc::new(Disk::open(dir.path().to_owned()).unwrap());
    let mut pending = Vec::new();
    for i in 0..7 {
        pending.push(
            disk.reserve(Path::new(&format!("pool/{i}.deb")), MAX_FILE)
                .unwrap()
                .unwrap(),
        );
    }
    assert!(
        disk.reserve(Path::new("pool/full.deb"), MAX_FILE)
            .unwrap()
            .is_none()
    );
    drop(pending);
    assert!(
        disk.reserve(Path::new("pool/available.deb"), MAX_FILE)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn second_owner_bypasses_and_restart_removes_crash_debris() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let source = Scripted::new(vec![complete("package"), complete("other process")]);
        let owner = Cache::new(source.clone(), dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &owner, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        let second = Cache::new(source.clone(), dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &second, request(PACKAGE)).await.unwrap()).await,
            "other process"
        );
        assert_eq!(second.state.stats.bypassed.lock().unwrap()["disabled"], 1);
        second.close().await;
        owner.close().await;
        let debris = dir.path().join(".download-interrupted");
        std::fs::write(&debris, b"partial").unwrap();
        let restarted = Cache::new(source.clone(), dir.path().to_owned());
        assert!(!debris.exists());
        assert_eq!(
            bytes(send(&fcx, &restarted, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(source.requests.lock().unwrap().len(), 2);
    })
    .await;
}

#[tokio::test]
async fn temp_collision_never_removes_another_download() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    let path = dir.path().join(".download-collision");
    std::fs::write(&path, "existing download").unwrap();
    assert!(Temporary::create(path.clone()).is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "existing download");
}

#[tokio::test]
async fn slow_body_deadline_releases_resources_even_without_a_reader() {
    let slots = Arc::new(Semaphore::new(1));
    let (tx, rx) = mpsc::channel(1);
    let body = stream(
        Source::Upstream(Body::new(ControlledBody(rx))),
        slots.clone().try_acquire_owned().unwrap(),
        tokio::time::Instant::now(),
        None,
        Arc::default(),
        tokio_util::task::TaskTracker::new(),
    );
    tx.closed().await;
    assert!(slots.try_acquire().is_ok());
    assert!(body.collect().await.is_err());
}

#[tokio::test]
async fn filesystem_entry_limit_bounds_tiny_files_and_directories() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        for i in 1..MAX_NODES {
            std::fs::File::create(dir.path().join(format!("old-{i}"))).unwrap();
        }
        let source = Scripted::new(vec![complete("package"), complete("fresh")]);
        let cache = Cache::new(source, dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "fresh"
        );
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count() as u64,
            MAX_NODES
        );
    })
    .await;
}

#[tokio::test]
async fn oversized_files_and_header_blocks_stream_without_storage() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let mut large = complete("large");
        large
            .headers_mut()
            .insert(header::CONTENT_LENGTH, (MAX_FILE + 1).into());
        let mut headers = complete("headers");
        headers
            .headers_mut()
            .insert("x-large", "a".repeat(MAX_HEAD).parse().unwrap());
        let source = Scripted::new(vec![large, headers, complete("package")]);
        let cache = Cache::new(source, dir.path().to_owned());
        let response = send(&fcx, &cache, request(PACKAGE)).await.unwrap();
        assert_eq!(length(response.headers()), Some(MAX_FILE + 1));
        // The synthetic source ends early; admission must not start a disk write.
        assert_eq!(bytes(response).await, "large");
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "headers"
        );
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
    })
    .await;
}

#[tokio::test]
async fn failed_replacement_preserves_complete_bytes_and_does_not_serve_them_stale() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let mut old = complete("old package");
        old.headers_mut()
            .insert(header::CACHE_CONTROL, "max-age=0".parse().unwrap());
        let mut short = complete("short");
        short
            .headers_mut()
            .insert(header::CONTENT_LENGTH, 100.into());
        let source = Scripted::new(vec![old, short, complete("new package")]);
        let cache = Cache::new(source, dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "old package"
        );
        let path = dir.path().join("mirror.test/http-80").join(&PACKAGE[1..]);
        let original = std::fs::read(&path).unwrap();
        assert!(
            send(&fcx, &cache, request(PACKAGE))
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "new package"
        );
    })
    .await;
}

#[tokio::test]
async fn disk_write_failure_does_not_replace_a_valid_upstream_response() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let path = dir.path().join("mirror.test/http-80").join(&PACKAGE[1..]);
        std::fs::create_dir_all(&path).unwrap();
        let source = Scripted::new(vec![complete("package"), complete("fresh")]);
        let cache = Cache::new(source, dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "fresh"
        );
        assert_eq!(cache.state.stats.bypassed.lock().unwrap()["storage"], 2);
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
    })
    .await;
}

#[tokio::test]
async fn admission_covers_response_bodies_after_headers_are_returned() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    let mut senders = Vec::new();
    let mut responses = Vec::new();
    for _ in 0..SLOTS {
        let (tx, rx) = mpsc::channel(1);
        senders.push(tx);
        responses.push(Response::new(Body::new(ControlledBody(rx))));
    }
    responses.push(complete("available"));
    let source = Scripted::new(responses);
    let mut cache = Cache::new(source.clone(), dir.path().to_owned());
    let mut held = Vec::new();
    for _ in 0..SLOTS {
        held.push(cache.call(request("/bypass")).await.unwrap());
    }
    assert_eq!(
        cache.call(request("/bypass")).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(source.requests.lock().unwrap().len(), SLOTS);
    drop(held.pop());
    senders.last().unwrap().closed().await;
    assert_eq!(
        bytes(cache.call(request("/bypass")).await.unwrap()).await,
        "available"
    );
    assert_eq!(source.requests.lock().unwrap().len(), SLOTS + 1);
}

#[tokio::test]
async fn ambiguous_upstream_framing_is_rejected_without_a_cache_entry() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for headers in [
            "Content-Length: 3\r\nContent-Length: 4\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n",
        ] {
            upstream.push(
                format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\nabc").into_bytes(),
            );
            assert!(send(&fcx, &cache, request(PACKAGE)).await.is_err());
        }
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
    })
    .await;
}

#[tokio::test]
async fn request_bodies_are_forwarded_without_populating_the_cache() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let source = Scripted::new(vec![complete("body response"), complete("package")]);
        let cache = Cache::new(source.clone(), dir.path().to_owned());
        let mut req = request(PACKAGE);
        *req.body_mut() = Body::from("guest body");
        assert_eq!(
            bytes(send(&fcx, &cache, req).await.unwrap()).await,
            "body response"
        );
        assert!(!dir.path().join("mirror.test").exists());
        assert_eq!(
            source.requests.lock().unwrap()[0].body().bytes().unwrap(),
            "guest body"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(source.requests.lock().unwrap().len(), 2);
    })
    .await;
}

#[tokio::test]
async fn cached_readers_keep_directory_ownership_until_their_files_close() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let payload = Bytes::from(vec![b'p'; 8 * CHUNK]);
        let source = Scripted::new(vec![
            Response::builder()
                .header(header::CONTENT_LENGTH, payload.len())
                .body(Body::from(payload.clone()))
                .unwrap(),
            complete("other owner"),
        ]);
        let cache = Cache::new(source.clone(), dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            payload
        );
        let held = send(&fcx, &cache, request(PACKAGE)).await.unwrap();
        let closing = cache.close();
        let contender = Cache::new(source.clone(), dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &contender, request(PACKAGE)).await.unwrap()).await,
            "other owner"
        );
        assert_eq!(bytes(held).await, payload);
        contender.close().await;
        closing.await;
        let cache = Cache::new(source.clone(), dir.path().to_owned());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            payload
        );
        assert_eq!(source.requests.lock().unwrap().len(), 2);
    })
    .await;
}

#[tokio::test]
async fn stalled_storage_holds_the_guest_back_only_briefly() {
    run(|_| async move {
        let payload = Bytes::from(vec![b'p'; CHUNK * 4]);
        let expected = payload.clone();
        let (write, mut disk) = mpsc::channel(1);
        let writer = CacheWriter::new(write, tokio::spawn(std::future::pending()));
        let (tx, rx) = mpsc::channel(1);
        let started = std::time::Instant::now();
        let task = tokio::spawn(async move {
            tee(
                Source::Upstream(Body::from(payload.clone())),
                &tx,
                Some(writer),
                Some(payload.len() as u64),
                Arc::default(),
            )
            .await
        });
        assert_eq!(
            ControlledBody(rx).collect().await.unwrap().to_bytes(),
            expected
        );
        task.await.unwrap().unwrap();
        // The disk never reads: the guest waits out the stall budget once.
        assert!(started.elapsed() >= STALL);
        assert!(started.elapsed() < STALL * 3);
        assert_eq!(disk.try_recv().unwrap(), expected.slice(..CHUNK));
        assert!(matches!(
            disk.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    })
    .await;
}

#[tokio::test]
async fn a_disk_that_lags_briefly_still_gets_every_chunk() {
    run(|_| async move {
        let payload = Bytes::from(vec![b'p'; CHUNK * 4]);
        let len = payload.len() as u64;
        let (write, mut disk) = mpsc::channel(1);
        let writer = CacheWriter::new(write, tokio::spawn(async { Ok(()) }));
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let body = Source::Upstream(Body::from(payload));
            tee(body, &tx, Some(writer), Some(len), Arc::default()).await
        });
        let slow = tokio::spawn(async move {
            let mut stored = 0;
            while let Some(chunk) = disk.recv().await {
                tokio::time::sleep(Duration::from_millis(20)).await;
                stored += chunk.len();
            }
            stored
        });
        let body = ControlledBody(rx).collect().await.unwrap().to_bytes();
        assert_eq!(body.len(), CHUNK * 4);
        task.await.unwrap().unwrap();
        // Every chunk reached the disk, and the commit closed the queue.
        assert_eq!(slow.await.unwrap(), CHUNK * 4);
    })
    .await;
}

#[tokio::test]
async fn immutable_request_freshness_preferences_allow_fills_and_hits() {
    run(|fcx| async move {
        let hash = format!("/ubuntu/dists/noble/main/by-hash/SHA256/{}", "a".repeat(64));
        for path in [PACKAGE, hash.as_str()] {
            for directives in [
                vec![(header::CACHE_CONTROL, "max-age=0")],
                vec![(header::CACHE_CONTROL, "max-age=86400")],
                vec![(header::CACHE_CONTROL, "no-cache")],
                vec![(header::PRAGMA, "no-cache")],
                vec![
                    (header::CACHE_CONTROL, "no-cache"),
                    (header::PRAGMA, "no-cache"),
                ],
                vec![
                    (header::CACHE_CONTROL, "max-age=0"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
            ] {
                let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
                let source = Scripted::new(vec![complete("package")]);
                let cache = Cache::new(source.clone(), dir.path().to_owned());
                for _ in 0..2 {
                    let mut req = request(path);
                    req.headers_mut()
                        .insert(header::ACCEPT, "text/*".parse().unwrap());
                    req.headers_mut()
                        .insert(header::USER_AGENT, "Debian APT-HTTP/1.3".parse().unwrap());
                    for (name, value) in &directives {
                        req.headers_mut().append(name, value.parse().unwrap());
                    }
                    assert_eq!(
                        bytes(send(&fcx, &cache, req).await.unwrap()).await,
                        "package"
                    );
                }
                assert_eq!(cache.state.stats.hits.load(Ordering::Relaxed), 1);
                assert_eq!(cache.state.stats.misses.load(Ordering::Relaxed), 1);
                assert!(cache.state.stats.bypassed.lock().unwrap().is_empty());
                let requests = source.requests.lock().unwrap();
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].headers().len(), 2);
                assert_eq!(requests[0].headers()[header::ACCEPT_ENCODING], "identity");
            }
        }
    })
    .await;
}

#[tokio::test]
async fn mutable_request_directives_are_forwarded_and_counted() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let source = Scripted::new(vec![
            complete("first"),
            complete("second"),
            complete("third"),
        ]);
        let cache = Cache::new(source.clone(), dir.path().to_owned());
        for (name, value, expected) in [
            (header::CACHE_CONTROL, "max-age=0", "first"),
            (header::CACHE_CONTROL, "no-cache", "second"),
            (header::PRAGMA, "no-cache", "third"),
        ] {
            let mut req = request(INDEX);
            req.headers_mut().insert(&name, value.parse().unwrap());
            assert_eq!(
                bytes(send(&fcx, &cache, req).await.unwrap()).await,
                expected
            );
            assert_eq!(
                source.requests.lock().unwrap().last().unwrap().headers()[name],
                value
            );
        }
        assert_eq!(
            *cache.state.stats.bypassed.lock().unwrap(),
            BTreeMap::from([("not immutable", 3)])
        );
        assert!(!dir.path().join("mirror.test").exists());
    })
    .await;
}

#[derive(Clone)]
struct Counting(Arc<std::sync::atomic::AtomicUsize>);

impl Service<Request<Body>> for Counting {
    type Response = Response<Body>;
    type Error = Error;
    type Future = std::future::Ready<Answer>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<Body>) -> Self::Future {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(web::httpd::text(StatusCode::OK, "package")))
    }
}

#[tokio::test]
async fn closing_stops_forwarding_on_clones_made_before_closing() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut mirror = Closable::new(Counting(calls.clone()), closed.clone());
    let mut earlier = mirror.clone();
    let status = |response: Response<Body>| response.status();
    assert_eq!(
        status(mirror.call(Request::new(Body::empty())).await.unwrap()),
        StatusCode::OK
    );
    closed.store(true, Ordering::SeqCst);
    for service in [&mut mirror, &mut earlier] {
        assert_eq!(
            status(service.call(Request::new(Body::empty())).await.unwrap()),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn setup_completion_closes_cached_and_uncached_requests() {
    run(|fcx| async move {
        let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
        let upstream = Upstream::new().await;
        let mut cache = upstream.cache(&fcx, dir.path());
        let setup = Arc::new(Setup::new(["station".into(), "server".into()]));
        cache.setup = Some(setup.clone());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        setup.done("station");
        setup.done("station");
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 2);
        setup.done("server");
        for path in [PACKAGE, INDEX, "/upload?data=secret"] {
            for method in ["GET", "POST"] {
                let mut req = request(path);
                *req.method_mut() = method.parse().unwrap();
                assert_eq!(
                    send(&fcx, &cache, req).await.unwrap().status(),
                    StatusCode::FORBIDDEN
                );
            }
        }
        assert_eq!(upstream.count(), 2);
    })
    .await;
}

#[test]
fn closed_cache_releases_ownership_with_an_inherited_descriptor() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "cache").unwrap();
    let disk = Disk::open(dir.path().to_owned()).unwrap();
    let inherited = disk.lock.try_clone().unwrap();
    drop(disk);
    let next = Disk::open(dir.path().to_owned()).unwrap();
    assert!(inherited.metadata().unwrap().is_file());
    drop(next);
}
