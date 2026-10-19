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
async fn send(fcx: &Cx, cache: &Cache<web::Forward>, request: Request<Body>) -> Answer {
    send_on(fcx, cache, request, false).await
}

async fn send_on(
    fcx: &Cx,
    cache: &Cache<web::Forward>,
    request: Request<Body>,
    tls: bool,
) -> Answer {
    let hosts = VirtualHosts::new();
    let mut host = VHost::new(httpd::tower(cache.clone()));
    host.https = tls;
    hosts.insert("mirror.test", host.clone());
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
        let dir = crate::RunDir::new().unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(PACKAGE)).await.unwrap()).await,
            "package"
        );
        assert_eq!(upstream.count(), 1);
        assert_eq!(cache.state.stats.saved.load(Ordering::Relaxed), 7);
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
async fn index_revalidates_once_per_run_and_replaces_on_change() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
        let upstream = Upstream::new().await;
        upstream.push(reply("200 OK", "ETag: \"first\"\r\n", b"first"));
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "first"
        );
        upstream.push(reply("304 Not Modified", "", b""));
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "first"
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "first"
        );
        assert_eq!(upstream.count(), 2);
        assert!(upstream.requests.lock().unwrap()[1].contains("if-none-match: \"first\""));
        upstream.push(reply(
            "200 OK",
            "Last-Modified: Wed, 01 Jul 2026 12:00:00 GMT\r\n",
            b"second",
        ));
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "second"
        );
        upstream.push(reply("304 Not Modified", "", b""));
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "second"
        );
        assert!(
            upstream.requests.lock().unwrap()[3]
                .contains("if-modified-since: Wed, 01 Jul 2026 12:00:00 GMT")
        );
    })
    .await;
}

#[tokio::test]
async fn offline_index_fallback() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
        let mut upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        let cache = upstream.cache(&fcx, dir.path());
        upstream.task.abort();
        // Joining the stopped listener makes connection refusal deterministic.
        let _ = (&mut upstream.task).await;
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        assert_eq!(cache.state.stats.offline.load(Ordering::Relaxed), 1);
    })
    .await;
}

#[tokio::test]
async fn partial_body_is_never_published() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
        let upstream = Upstream::new().await;
        upstream.push(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        );
        let cache = upstream.cache(&fcx, dir.path());
        assert!(send(&fcx, &cache, request(PACKAGE)).await.is_err());
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
        let dir = crate::RunDir::new().unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        for path in [PACKAGE, INDEX] {
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
        assert_eq!(upstream.count(), 2);
    })
    .await;
}

#[tokio::test]
async fn ranges_use_complete_entries_and_other_ranges_pass_through() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
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
        let dir = crate::RunDir::new().unwrap();
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
        let dir = crate::RunDir::new().unwrap();
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
    assert_eq!(policy(PACKAGE), Some(Policy::Immutable));
    assert_eq!(
        policy("/apt/pool/firefox_1%3a2.deb"),
        Some(Policy::Immutable)
    );
    assert_eq!(
        policy("/ubuntu/dists/noble/main/by-hash/SHA256/abc"),
        Some(Policy::Immutable)
    );
    for name in [
        "InRelease",
        "Release",
        "Release.gpg",
        "main/binary-amd64/Packages.xz",
        "main/i18n/Translation-en.gz",
        "Contents-amd64.gz",
    ] {
        assert_eq!(
            policy(&format!("/ubuntu/dists/noble/{name}")),
            Some(Policy::Index)
        );
    }
    for path in [
        "/key.asc",
        "/pool/a.txt",
        "/pool/../escape.deb",
        "/pool//a.deb",
        "/pool/./a.deb",
        "/pool/a\\b.deb",
    ] {
        assert_eq!(policy(path), None);
    }
    assert_eq!(policy(&format!("/pool/{}.deb", "a".repeat(250))), None);
}

#[tokio::test]
async fn by_hash_is_immutable_and_damaged_entries_are_refetched() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
        let upstream = Upstream::new().await;
        let path = "/ubuntu/dists/noble/main/by-hash/SHA256/abcdef";
        let cache = upstream.cache(&fcx, dir.path());
        bytes(send(&fcx, &cache, request(path)).await.unwrap()).await;
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
        let dir = crate::RunDir::new().unwrap();
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
        let dir = crate::RunDir::new().unwrap();
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
async fn interrupted_index_replacement_preserves_the_complete_entry() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
        let upstream = Upstream::new().await;
        let cache = upstream.cache(&fcx, dir.path());
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        let cache = upstream.cache(&fcx, dir.path());
        upstream.push(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "package"
        );
        let path = dir.path().join("mirror.test/http-80").join(&INDEX[1..]);
        let entry = Entry::open(&path).await.unwrap();
        assert_eq!(
            bytes(
                entry
                    .response(&HeaderMap::new(), None)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .await,
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
async fn guest_conditions_do_not_prevent_index_population_or_offline_use() {
    run(|fcx| async move {
        let dir = crate::RunDir::new().unwrap();
        let mut upstream = Upstream::new().await;
        upstream.push(reply(
            "200 OK",
            "ETag: \"current\"\r\nLast-Modified: Wed, 01 Jul 2026 12:00:00 GMT\r\n",
            b"index",
        ));
        let cache = upstream.cache(&fcx, dir.path());
        let mut req = request(INDEX);
        req.headers_mut().insert(
            header::IF_MODIFIED_SINCE,
            "Wed, 01 Jul 2026 12:00:00 GMT".parse().unwrap(),
        );
        assert_eq!(
            send(&fcx, &cache, req).await.unwrap().status(),
            StatusCode::NOT_MODIFIED
        );
        assert_eq!(
            bytes(send(&fcx, &cache, request(INDEX)).await.unwrap()).await,
            "index"
        );
        assert_eq!(upstream.count(), 1);
        assert!(!upstream.requests.lock().unwrap()[0].contains("if-modified-since"));
        for (tag, status) in [
            ("W/\"current\"", StatusCode::NOT_MODIFIED),
            ("\"old\"", StatusCode::OK),
            ("*", StatusCode::NOT_MODIFIED),
        ] {
            let mut req = request(INDEX);
            req.headers_mut()
                .insert(header::IF_NONE_MATCH, tag.parse().unwrap());
            assert_eq!(send(&fcx, &cache, req).await.unwrap().status(), status);
        }
        let cache = upstream.cache(&fcx, dir.path());
        upstream.task.abort();
        let _ = (&mut upstream.task).await;
        let mut req = request(INDEX);
        req.headers_mut()
            .insert(header::IF_NONE_MATCH, "\"older\"".parse().unwrap());
        assert_eq!(bytes(send(&fcx, &cache, req).await.unwrap()).await, "index");
    })
    .await;
}
