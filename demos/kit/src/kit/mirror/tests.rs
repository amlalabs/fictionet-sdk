use super::*;
use std::sync::{Mutex, atomic::AtomicUsize};

const PACKAGE: &str = "/ubuntu/pool/main/p/package/package_1_amd64.deb";

#[derive(Clone)]
struct Upstream {
    calls: Arc<AtomicUsize>,
    replies: Arc<Mutex<std::collections::VecDeque<Response<Body>>>>,
}
impl Upstream {
    fn new() -> Self {
        Self {
            calls: Arc::default(),
            replies: Arc::default(),
        }
    }
}
impl Service<Request<Body>> for Upstream {
    type Response = Response<Body>;
    type Error = Error;
    type Future = std::future::Ready<Answer>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<Body>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::future::ready(Ok(self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Response::new(Body::from("package")))))
    }
}
fn request(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).unwrap()
}
async fn send(mirror: &Mirror<Upstream>, request: Request<Body>) -> Answer {
    use fictionet::stdlib::web::httpd::{self, Handler};
    let hosts = httpd::VirtualHosts::new();
    hosts.insert(
        "mirror.test",
        httpd::VHost::new(httpd::tower(mirror.clone())),
    );
    let output = Arc::new(Mutex::new(None));
    let result = output.clone();
    fictionet::run(fictionet::Seed::from_u64(1), |cx| async move {
        let mut request = request;
        request
            .headers_mut()
            .insert(header::HOST, http::HeaderValue::from_static("mirror.test"));
        let reply = hosts.call(
            request,
            &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()),
        );
        let response = match reply {
            httpd::Reply::Now(response) => Ok(response),
            httpd::Reply::Later(work) => work(cx.clone()).await,
        };
        *result.lock().unwrap() = Some(response);
        Ok(())
    })
    .await?;
    output.lock().unwrap().take().unwrap()
}
async fn bytes(response: Response<Body>) -> Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn immutable_files_are_published_at_host_and_path_and_survive_reopening() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "mirror").unwrap();
    let upstream = Upstream::new();
    let mirror = Mirror::new(upstream.clone(), dir.path().into());
    assert_eq!(
        bytes(send(&mirror, request(PACKAGE)).await.unwrap()).await,
        "package"
    );
    assert_eq!(
        std::fs::read(dir.path().join("mirror.test").join(&PACKAGE[1..])).unwrap(),
        b"package"
    );
    let reopened = Mirror::new(upstream.clone(), dir.path().into());
    assert_eq!(
        bytes(send(&reopened, request(PACKAGE)).await.unwrap()).await,
        "package"
    );
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn mutable_indexes_and_conditional_requests_go_upstream() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "mirror").unwrap();
    let upstream = Upstream::new();
    let mirror = Mirror::new(upstream.clone(), dir.path().into());
    for _ in 0..2 {
        bytes(
            send(&mirror, request("/ubuntu/dists/noble/InRelease"))
                .await
                .unwrap(),
        )
        .await;
    }
    bytes(send(&mirror, request(PACKAGE)).await.unwrap()).await;
    for header in [
        header::RANGE,
        header::IF_NONE_MATCH,
        header::AUTHORIZATION,
        header::COOKIE,
    ] {
        let mut request = request(PACKAGE);
        request
            .headers_mut()
            .insert(header, http::HeaderValue::from_static("value"));
        bytes(send(&mirror, request).await.unwrap()).await;
    }
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 7);
}

#[tokio::test]
async fn failed_and_incomplete_downloads_never_publish_files() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "mirror").unwrap();
    let upstream = Upstream::new();
    upstream.replies.lock().unwrap().extend([
        Response::builder()
            .status(503)
            .body(Body::from("busy"))
            .unwrap(),
        Response::builder()
            .header(header::CONTENT_LENGTH, 100)
            .body(Body::from("short"))
            .unwrap(),
    ]);
    let mirror = Mirror::new(upstream.clone(), dir.path().into());
    assert_eq!(send(&mirror, request(PACKAGE)).await.unwrap().status(), 503);
    assert!(send(&mirror, request(PACKAGE)).await.is_err());
    let path = dir.path().join("mirror.test").join(&PACKAGE[1..]);
    assert!(!path.exists());
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        0
    );
    assert_eq!(
        bytes(send(&mirror, request(PACKAGE)).await.unwrap()).await,
        "package"
    );
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn closing_the_mirror_refuses_cached_and_upstream_files() {
    let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "mirror").unwrap();
    let upstream = Upstream::new();
    let mirror = Mirror::new(upstream.clone(), dir.path().into());
    bytes(send(&mirror, request(PACKAGE)).await.unwrap()).await;
    mirror.closed.store(true, Ordering::Release);
    for path in [PACKAGE, "/ubuntu/dists/noble/InRelease"] {
        let response = send(&mirror, request(path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(bytes(response).await, "Forbidden\n");
    }
    assert_eq!(upstream.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn file_keys_reject_traversal_and_mutable_releases() {
    for path in [
        "/../pool/a.deb",
        "/pool/%2e%2e/a.deb",
        "/pool/a%2fb.deb",
        "/pool/a.deb?token=x",
        "/ubuntu/dists/noble/InRelease",
    ] {
        assert!(!immutable(path), "{path}");
    }
    assert!(immutable(PACKAGE));
}
