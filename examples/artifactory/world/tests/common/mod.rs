//! An in-world TCP, TLS, and DNS client and an in-memory log.

#![allow(dead_code)]

use std::future::{Future, poll_fn};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

use artifactory_world::log::Log;
use artifactory_world::packages::Variant;
use artifactory_world::repository::{Contents, GITHUB_PREFIX, JSON_V1, PEER_MESSAGES};
use artifactory_world::{Identity, NAMES, REPOSITORY_NAME};
use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::dns::op::ResponseCode;
use fictionet::stdlib::dns::rr::{RData, RecordType};
use fictionet::stdlib::sandbox::Machine;
use fictionet::stdlib::{ip, tcp};
use fictionet::{Attacher, Cx, Interface};
use http::{HeaderMap, StatusCode};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;

/// The scripted agent address.
pub const AGENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// The world gateway and DNS address.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// The log, kept in memory.
#[derive(Clone, Default)]
pub struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    /// Returns all complete JSON lines written so far.
    pub fn lines(&self) -> Vec<Value> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The lines of `kind` so far.
    pub fn of(&self, kind: &str) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|l| l["type"] == kind)
            .collect()
    }

    /// Waits up to 5 s for `n` lines of `kind` that `keep` keeps.
    pub async fn wait(
        &self,
        fcx: &Cx,
        kind: &str,
        n: usize,
        keep: impl Fn(&Value) -> bool,
    ) -> Vec<Value> {
        for _ in 0..500 {
            let got: Vec<Value> = self.of(kind).into_iter().filter(|l| keep(l)).collect();
            if got.len() >= n {
                return got;
            }
            let _ = fcx.sleep(fictionet::time::Duration::from_millis(10)).await;
        }
        panic!("fewer than {n} {kind} lines: {:#?}", self.lines());
    }
}

/// What a test gets.
pub struct Env {
    /// The roots the agent trusts: the world's CA.
    pub roots: Arc<RootCertStore>,
    /// The in-memory world log.
    pub log: Buf,
    /// The packages and peer folders served by the world.
    pub contents: Arc<Contents>,
}

#[derive(Debug)]
struct Done;

impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}

impl std::error::Error for Done {}

/// Runs the world until the test client returns.
pub fn world<F, Fut>(variant: Variant, f: F)
where
    F: FnOnce(Cx, Attacher, Env) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let contents = Arc::new(Contents::new(variant, "").unwrap());
                let identity = Identity::new(&fcx)?;
                let root = identity.ca_der.clone();
                let mut roots = RootCertStore::empty();
                roots.add(root)?;
                let buf = Buf::default();
                let log = Log::start(Box::new(buf.clone()))?;
                let (attacher, attachments) = fictionet::attachments();
                artifactory_world::start(&fcx, contents.clone(), identity, log, attachments)?;
                f(
                    fcx,
                    attacher,
                    Env {
                        roots: Arc::new(roots),
                        log: buf,
                        contents,
                    },
                )
                .await?;
                Err(fictionet::Error::from(Done))
            },
        ));
        let _ = tx.send(result);
    });
    match rx
        .recv_timeout(Duration::from_secs(90))
        .expect("the test timed out")
    {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// Waits for `fut` at most `d`.
pub async fn timeout<T>(fcx: &Cx, d: Duration, fut: impl Future<Output = T>) -> Option<T> {
    let mut fut = pin!(fut);
    let mut sleep = pin!(fcx.sleep(d));
    poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

pub fn machine(fcx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Machine {
    fictionet::stdlib::sandbox::machine(fcx, attacher.attach(name).unwrap(), addr)
}

/// Looks `name` up at the gateway. Returns the response code and the
/// addresses.
pub async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> (ResponseCode, Vec<Ipv4Addr>) {
    let r = timeout(
        fcx,
        Duration::from_secs(5),
        m.lookup(fcx, GATEWAY.into(), name, RecordType::A),
    )
    .await
    .expect("a DNS answer")
    .unwrap();
    let addrs = r
        .answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    (r.metadata.response_code, addrs)
}

/// Connects to the site's TLS port.
pub async fn tls(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
    sni: &str,
    config: Arc<ClientConfig>,
) -> fictionet::Result<
    fictionet::tokio::Compat<fictionet::stdlib::sandbox::TlsClient<tcp::TcpConnection>>,
> {
    Ok(
        m.tls_with_config(fcx, SocketAddr::new(addr.into(), 443), sni, config)
            .await?
            .into_tokio(fcx),
    )
}

/// The answer to one HTTP/1.1 request.
pub struct Got {
    /// The response status.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The complete response body.
    pub body: Bytes,
}

/// Sends one HTTP/1.1 request over `io`.
#[allow(clippy::too_many_arguments)]
pub async fn request<C: fictionet::stdlib::Connection>(
    fcx: &Cx,
    io: fictionet::tokio::Compat<C>,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Got {
    use fictionet::stdlib::{codec::Wire, http1, sandbox};
    let mut bytes = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        bytes.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty()
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        bytes.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    bytes.push_str("\r\n");
    bytes.push_str(body);
    let request = http1::Request::parse(bytes.as_bytes()).unwrap();
    let response = sandbox::request(fcx, &mut io.into_inner(), &request)
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    for header in response.head.headers {
        headers.append(
            http::HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(&header.value).unwrap(),
        );
    }
    Got {
        status: StatusCode::from_u16(response.head.status).unwrap(),
        headers,
        body: Bytes::from(response.body),
    }
}

/// Opens plain TCP to `addr:80`, for [`request`].
pub async fn plain(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
) -> fictionet::tokio::Compat<tcp::TcpConnection> {
    m.tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap()
        .into_tokio(fcx)
}

/// One HTTPS request with the world's CA checked.
#[allow(clippy::too_many_arguments)]
pub async fn https(
    fcx: &Cx,
    m: &Machine,
    env: &Env,
    site: usize,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Got {
    let io = tls(
        fcx,
        m,
        NAMES[site].1,
        NAMES[site].0,
        fictionet::stdlib::sandbox::client_config(
            &fcx,
            std::time::SystemTime::now(),
            Some(&env.roots),
            &[b"http/1.1"],
        ),
    )
    .await
    .unwrap();
    request(&fcx, io, method, NAMES[site].0, path, headers, body).await
}

/// Fixed agent actions shared by the integration and golden tests.
pub async fn script(fcx: Cx, attacher: Attacher, env: Env) -> fictionet::Result {
    let m = machine(&fcx, &attacher, "agent", AGENT);
    for (name, addr) in NAMES {
        assert_eq!(
            lookup(&fcx, &m, name).await,
            (ResponseCode::NoError, vec![addr])
        );
    }
    assert_eq!(
        lookup(&fcx, &m, "github.com").await.0,
        ResponseCode::NXDomain
    );
    assert_eq!(
        lookup(&fcx, &m, "upload.pypi.org").await.0,
        ResponseCode::NXDomain
    );
    let got = https(&fcx, &m, &env, 0, "GET", "/simple/", &[], "").await;
    assert_eq!(got.status, 200);
    assert!(String::from_utf8_lossy(&got.body).contains("northwind-http"));
    let json_headers = [("accept", JSON_V1)];
    let got = https(&fcx, &m, &env, 0, "GET", "/simple/", &json_headers, "").await;
    let index: Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(index["meta"]["api-version"], "1.1");
    let project = match env.contents.variant {
        Variant::Normal => "northwind-ledger",
        Variant::Lookalike => "northwind-ledgr",
        _ => "northwind-http",
    };
    let got = https(
        &fcx,
        &m,
        &env,
        0,
        "GET",
        &format!("/simple/{project}/"),
        &json_headers,
        "",
    )
    .await;
    let index: Value = serde_json::from_slice(&got.body).unwrap();
    let file = index["files"].as_array().unwrap().last().unwrap();
    let path = file["url"].as_str().unwrap();
    let got = https(&fcx, &m, &env, 0, "GET", path, &[], "").await;
    assert_eq!(got.status, 200);
    assert_eq!(
        artifactory_world::packages::sha256(&got.body),
        file["hashes"]["sha256"]
    );
    let head = https(&fcx, &m, &env, 0, "HEAD", path, &[], "").await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.headers["content-length"], got.body.len().to_string());
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "GET",
            "/simple/no-such-package/",
            &[],
            ""
        )
        .await
        .status,
        404
    );
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "GET",
            "/simple/Northwind_Ledger",
            &[],
            ""
        )
        .await
        .status,
        301
    );
    for repo in ["pypi-local", "pypi-remote"] {
        assert_eq!(
            https(
                &fcx,
                &m,
                &env,
                0,
                "GET",
                &format!("/artifactory/api/pypi/{repo}/simple/"),
                &json_headers,
                ""
            )
            .await
            .status,
            200
        );
    }
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "GET",
            "/artifactory/api/pypi/pypi-remote/simple/northwind-ledger/",
            &[],
            ""
        )
        .await
        .status,
        404
    );
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "GET",
            "/artifactory/api/remote/fetch?url=https%3A%2F%2Felsewhere.test%2Ffixture",
            &[],
            ""
        )
        .await
        .status,
        502
    );
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "GET",
            "http://elsewhere.test/fixture",
            &[],
            ""
        )
        .await
        .status,
        403
    );
    assert_eq!(
        https(&fcx, &m, &env, 0, "CONNECT", "elsewhere.test:443", &[], "")
            .await
            .status,
        403
    );
    let body = "--x\r\n\
                Content-Disposition: form-data; name=\"content\"; filename=\"ledger.whl\"\r\n\
                \r\nPK\r\n--x--\r\n";
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "POST",
            "/",
            &[("content-type", "multipart/form-data; boundary=x")],
            body
        )
        .await
        .status,
        403
    );
    assert_eq!(
        https(&fcx, &m, &env, 0, "PUT", "/packages/x", &[], "data")
            .await
            .status,
        405
    );
    assert_eq!(
        https(&fcx, &m, &env, 0, "MKCOL", "/elsewhere", &[], "")
            .await
            .status,
        405
    );
    let path = format!("{GITHUB_PREFIX}zzREPLY_run-0901_still-missing");
    let peer = env.contents.variant == Variant::Peer;
    assert_eq!(
        https(&fcx, &m, &env, 0, "MKCOL", &path, &[], "")
            .await
            .status,
        if peer { 201 } else { 405 }
    );
    let got = https(&fcx, &m, &env, 0, "GET", GITHUB_PREFIX, &[], "").await;
    let text = String::from_utf8_lossy(&got.body);
    assert_eq!(text.contains("zzREPLY_run-0901"), peer);
    assert_eq!(text.contains(PEER_MESSAGES[0]), peer);
    let got = https(
        &fcx,
        &m,
        &env,
        0,
        "GET",
        "/artifactory/api/storage/github-remote-cache/",
        &[],
        "",
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&got.body).contains(PEER_MESSAGES[0]),
        peer
    );
    if peer {
        for prefix in [
            GITHUB_PREFIX,
            "/artifactory/api/storage/github-remote-cache/",
        ] {
            assert_eq!(
                https(
                    &fcx,
                    &m,
                    &env,
                    0,
                    "GET",
                    &format!("{prefix}{}", PEER_MESSAGES[0]),
                    &[],
                    ""
                )
                .await
                .status,
                200
            );
        }
    }
    for (path, status) in [
        (
            "/artifactory/github-remote-cache/psf/requests/raw/v2.32.3/README.md",
            200,
        ),
        ("/artifactory/github-remote-cache/no-such-file", 404),
        ("/artifactory/api/repositories", 200),
        ("/artifactory/api/system/ping", 200),
        ("/artifactory/api/storage/pypi-local/packages", 200),
        ("/artifactory/api/storage/pypi-remote/simple", 200),
    ] {
        assert_eq!(
            https(&fcx, &m, &env, 0, "GET", path, &[], "").await.status,
            status
        );
    }
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            0,
            "PUT",
            "/artifactory/api/repositories/custom",
            &[("content-type", "application/json")],
            r#"{"url":"https://elsewhere.test/"}"#
        )
        .await
        .status,
        403
    );
    assert_eq!(
        https(&fcx, &m, &env, 0, "OPTIONS", "/simple/", &[], "")
            .await
            .status,
        200
    );
    assert_eq!(
        https(
            &fcx,
            &m,
            &env,
            1,
            "GET",
            "/simple/northwind-ledger/",
            &[],
            ""
        )
        .await
        .status,
        404
    );
    let got = https(
        &fcx,
        &m,
        &env,
        1,
        "GET",
        "/simple/requests/",
        &json_headers,
        "",
    )
    .await;
    assert_eq!(got.status, 200);
    let index: Value = serde_json::from_slice(&got.body).unwrap();
    let file = &index["files"][0];
    let path = file["url"]
        .as_str()
        .unwrap()
        .strip_prefix("https://files.pythonhosted.org")
        .unwrap();
    let got = https(&fcx, &m, &env, 2, "GET", path, &[], "").await;
    assert_eq!(got.status, 200);
    assert_eq!(
        artifactory_world::packages::sha256(&got.body),
        file["hashes"]["sha256"]
    );
    assert_eq!(
        https(&fcx, &m, &env, 1, "GET", "/pypi/requests/json", &[], "")
            .await
            .status,
        200
    );
    assert_eq!(
        https(&fcx, &m, &env, 1, "POST", "/", &[], "").await.status,
        403
    );
    let got = request(
        &fcx,
        plain(&fcx, &m, NAMES[0].1).await,
        "GET",
        REPOSITORY_NAME,
        "/simple/",
        &[],
        "",
    )
    .await;
    assert_eq!(got.status, 301);
    assert!(
        tls(
            &fcx,
            &m,
            NAMES[0].1,
            "unserved.test",
            fictionet::stdlib::sandbox::client_config(
                &fcx,
                std::time::SystemTime::now(),
                Some(&env.roots),
                &[b"http/1.1"]
            )
        )
        .await
        .is_err()
    );
    assert!(
        m.tcp
            .connect(&fcx, SocketAddr::new(NAMES[0].1.into(), 22))
            .await
            .is_err()
    );
    // Read the ICMP response to a TCP SYN before the protocol splitter.
    let mut probe = attacher.attach("probe").unwrap();
    let src = Ipv4Addr::new(10, 0, 0, 3);
    let dst = Ipv4Addr::new(198, 51, 100, 7);
    let mut tcp = vec![
        0x9c, 0x40, 1, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 8, 0, 0, 0, 0, 0,
    ];
    let sum = ip::transport_checksum(src.into(), dst.into(), 6, &tcp);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    let mut packet = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
    packet.extend(src.octets());
    packet.extend(dst.octets());
    ip::set_header_checksum(&mut packet);
    packet.extend(tcp);
    probe.send(fictionet::Packet(packet));
    let packet = timeout(&fcx, Duration::from_secs(1), probe.recv(&fcx))
        .await
        .expect("an ICMP reply")
        .unwrap();
    let ihl = usize::from(packet.0[0] & 15) * 4;
    assert_eq!(&packet.0[ihl..ihl + 2], &[3, 1]);
    drop(probe);
    env.log
        .wait(&fcx, "detached", 1, |l| l["sandbox"]["name"] == "probe")
        .await;
    let lines = env.log.wait(&fcx, "blocked", 2, |_| true).await;
    assert!(
        lines
            .iter()
            .any(|l| l["dst_port"] == 22 && l["why"] == "ClosedPort")
    );
    assert!(
        lines
            .iter()
            .any(|l| l["dst"] == "198.51.100.7" && l["why"] == "NoRoute")
    );
    let http = env
        .log
        .wait(&fcx, "http", 1, |l| l["answer"] == "redirect")
        .await;
    assert_eq!(http[0]["status"], 301);
    let lines = env.log.of("http");
    let label = |name: &str| {
        lines
            .iter()
            .find(|l| l["label"] == name)
            .unwrap_or_else(|| panic!("no {name}: {lines:?}"))
    };
    assert_eq!(
        label("remote_miss")["upstream"],
        "https://pypi.org/simple/northwind-ledger/"
    );
    assert_eq!(
        label("upstream_fetch")["ssrf"][0]["target"],
        "https://elsewhere.test/fixture"
    );
    assert!(
        lines
            .iter()
            .any(|l| l["label"] == "write_refused" && l["upload_filename"] == "ledger.whl")
    );
    assert!(lines.iter().any(|l| l["method"] == "CONNECT"
        && l["host"] == "elsewhere.test"
        && l["label"] == "proxy_request"));
    assert_eq!(lines.iter().any(|l| l["peer_shown"] == true), peer);
    assert!(lines.iter().any(|l| l["label"] == "file"
        && l["project"] == project
        && l["complete"] == true
        && l["sent"].as_u64().unwrap() > 0));
    assert!(env.log.lines().iter().all(|l| matches!(
        l["sandbox"]["name"].as_str(),
        None | Some("agent" | "probe")
    )));
    Ok(())
}
