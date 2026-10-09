//! Clients and log capture for example world tests.

#![allow(dead_code)]

use std::future::Future;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use fictionet::stdlib::dns::op::ResponseCode;
use fictionet::stdlib::dns::rr::{RData, RecordType};
use fictionet::stdlib::sandbox::Machine;
use fictionet::stdlib::{http1, sandbox, tcp};
use fictionet::{Attacher, Cx};
use http::{HeaderMap, StatusCode};
use rustls::ClientConfig;
use serde_json::Value;

#[path = "../../tests/common/timeout.rs"]
mod timing;
pub use timing::timeout;

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

#[derive(Debug)]
struct Done;
impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}
impl std::error::Error for Done {}

/// Runs a test script on a runtime and ends the world when it returns.
pub fn run<F, Fut>(seed: fictionet::Seed, f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(fictionet::run(seed, move |fcx| async move {
            f(fcx).await?;
            Err(fictionet::Error::from(Done))
        }));
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
) -> fictionet::Result<sandbox::TlsClient<tcp::TcpConnection>> {
    m.tls_with_config(fcx, SocketAddr::new(addr.into(), 443), sni, config)
        .await
}

/// The answer to one HTTP/1.1 request.
pub struct Got {
    /// The response status.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The complete response body.
    pub body: Vec<u8>,
}

/// Sends one HTTP/1.1 request over `io`.
#[allow(clippy::too_many_arguments)]
pub async fn request<C: fictionet::stdlib::Connection>(
    fcx: &Cx,
    mut io: C,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Got {
    let mut fields = vec![http1::Header {
        name: "Host".into(),
        value: host.as_bytes().to_vec(),
    }];
    fields.extend(headers.iter().map(|(name, value)| http1::Header {
        name: (*name).into(),
        value: value.as_bytes().to_vec(),
    }));
    if !body.is_empty()
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        fields.push(http1::Header {
            name: "Content-Length".into(),
            value: body.len().to_string().into_bytes(),
        });
    }
    let request = http1::Request {
        head: http1::RequestHead {
            method: method.into(),
            target: path.into(),
            version: http1::Version::Http11,
            headers: fields,
        },
        body: body.as_bytes().to_vec(),
    };
    let response = sandbox::request(fcx, &mut io, &request).await.unwrap();
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
        body: response.body,
    }
}

/// Opens plain TCP to `addr:80`, for [`request`].
pub async fn plain(fcx: &Cx, m: &Machine, addr: Ipv4Addr) -> tcp::TcpConnection {
    m.tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap()
}
