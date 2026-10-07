//! A small Fictionet world that runs in a browser.
//!
//! [`fetch`] builds a world with one website, `hello.test`, and plays one
//! sandbox inside the same process: it asks the world's DNS server for
//! the name over UDP, opens a TCP connection to the address it got, and
//! sends one HTTP request with hyper's client, over TLS (rustls with ring)
//! or without. Every packet goes through smoltcp, in the world and in the
//! sandbox's own stack. Nothing touches a real network, so the same code
//! runs natively and on wasm32-unknown-unknown.

mod tls_client;

use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use fictionet::stdlib::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::{Connection, ip, tcp, tls, udp, web};
use fictionet::{Cx, Result, run};
use http::{Request, Response, Version};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::tls_client::TlsClient;

/// The site's one name.
pub const NAME: &str = "hello.test";
/// The site's address in the world.
pub const SITE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
/// The world's gateway and DNS server.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// The sandbox's address.
const SANDBOX: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// What [`fetch`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The address DNS gave for [`NAME`].
    pub address: Ipv4Addr,
    /// The response's status code.
    pub status: u16,
    /// The HTTP version of the response.
    pub version: Version,
    /// The response body, as text.
    pub body: String,
}

/// Runs the world, makes one request in it with HTTP `version` (1.1, or
/// 2), and returns what came back.
///
/// With `https`, the site serves TLS with a certificate from a CA made for
/// this run, and the request goes to port 443, with ALPN choosing the
/// version. Without, it goes to port 80, and HTTP/2 uses prior knowledge.
///
/// The future runs on any executor: [`fictionet::block_on`], tokio, or a
/// page's event loop through `wasm_bindgen_futures`.
pub async fn fetch(https: bool, version: Version) -> Result<Fetched> {
    let fetched = Arc::new(Mutex::new(None));
    let out = fetched.clone();
    let ended = run(move |cx| async move {
        let certs = certs()?;
        // The world's date: certificates are checked against it.
        let date = std::time::Duration::from_secs(1_767_225_600); // 2026-01-01
        let server = Arc::new(
            tls::config_builder(&cx, std::time::UNIX_EPOCH + date, rustls::crypto::ring::default_provider())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(certs.chain, certs.key)?,
        );
        let (attacher, attachments) = fictionet::attachments();
        let sites = web::Sites::new(move |host| match host {
            // TLS on port 443, and the same site without it on port 80
            // (rather than a redirect to https).
            NAME => Some(
                web::Site::new(Hello)
                    .at(SITE)
                    .tls({
                        let server = server.clone();
                        move |_| server.clone()
                    })
                    .plain_http(),
            ),
            _ => None,
        });
        sites.serve(&cx, attachments)?;

        // The sandbox: an IP stack of its own on the attachment's cable.
        let cable = attacher.attach("agent")?;
        let (tcp_packets, udp_packets, _icmp, _other) = ip::split_protocols(&cx, cable);
        let tcp = tcp::endpoint(&cx, tcp_packets, SANDBOX.into());
        let udp = udp::endpoint(&cx, udp_packets, SANDBOX.into());

        let address = lookup(&cx, &udp, NAME).await?;
        let response = if https {
            let conn = tcp.connect(&cx, SocketAddr::new(address.into(), 443)).await?;
            let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(certs.roots)
                .with_no_client_auth();
            client.alpn_protocols = vec![if version == Version::HTTP_2 { b"h2".to_vec() } else { b"http/1.1".to_vec() }];
            let mut conn = TlsClient::new(conn, Arc::new(client), NAME)?;
            conn.handshake(&cx).await?;
            get(&cx, conn, "https", version, "/from-the-browser").await?
        } else {
            let conn = tcp.connect(&cx, SocketAddr::new(address.into(), 80)).await?;
            get(&cx, conn, "http", version, "/from-the-browser").await?
        };
        let status = response.status().as_u16();
        let version = response.version();
        let body = response.into_body().collect().await?.to_bytes();
        let body = String::from_utf8(body.to_vec())?;
        *out.lock().unwrap() = Some(Fetched { address, status, version, body });
        // Ending with an error cancels the sites, which would serve forever.
        Err(fictionet::Error::from(Done))
    })
    .await;
    match ended {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => return Err(e),
        Ok(()) => return Err(fictionet::Error::msg("the world ended before the request")),
    }
    let fetched = fetched.lock().unwrap().take();
    fetched.ok_or_else(|| "no response".into())
}

/// The page's entry point: [`fetch`] as a JavaScript promise of the
/// response body, such as `await fetchText(true, true)` for HTTPS with
/// HTTP/2. The world runs on the page's event loop.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = fetchText)]
pub async fn fetch_text(https: bool, http2: bool) -> std::result::Result<String, String> {
    let version = if http2 { Version::HTTP_2 } else { Version::HTTP_11 };
    let fetched = fetch(https, version).await.map_err(|e| e.to_string())?;
    Ok(format!("{} {:?} from {}\n{}", fetched.status, fetched.version, fetched.address, fetched.body))
}

/// The site's handler: answers every request with its method and path.
#[derive(Clone)]
struct Hello;

impl tower_service::Service<Request<web::Body>> for Hello {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<std::result::Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<std::result::Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<web::Body>) -> Self::Future {
        let body = format!("hello from {NAME}: {} {}\n", request.method(), request.uri().path());
        std::future::ready(Ok(Response::new(Full::new(Bytes::from(body)))))
    }
}

/// Why the world ended once the sandbox was done.
#[derive(Debug)]
struct Done;

impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}

impl std::error::Error for Done {}

/// Asks the world's DNS server for the A record of `name`.
async fn lookup(cx: &Cx, udp: &udp::Endpoint, name: &str) -> Result<Ipv4Addr> {
    let mut socket = udp.bind(40000 + (cx.random_u64() % 20000) as u16)?;
    let mut query = Message::query();
    query.metadata.id = cx.random_u64() as u16;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    socket.send_to(&query.to_vec()?, SocketAddr::new(GATEWAY.into(), 53));
    // The world's links lose nothing, so one query is enough.
    let (bytes, _from) = socket.recv(cx).await?;
    let answer = Message::from_vec(&bytes)?;
    if answer.metadata.response_code != ResponseCode::NoError {
        return Err(fictionet::Error::msg(format!("DNS answered {} for {name}", answer.metadata.response_code)));
    }
    answer
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .ok_or_else(|| format!("no A record for {name}").into())
}

/// The run's CA, and a certificate for [`NAME`] that it signed.
struct Certs {
    roots: RootCertStore,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn certs() -> Result<Certs> {
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca = ca.self_signed(&ca_key)?;
    let mut leaf = CertificateParams::new(vec![NAME.to_owned()])?;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key)?;
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    Ok(Certs { roots, chain: vec![leaf.der().clone()], key })
}

/// Sends one GET for `path` to [`NAME`] over `conn` with hyper's client.
async fn get<C: Connection + Unpin>(
    cx: &Cx,
    conn: C,
    scheme: &str,
    version: Version,
    path: &str,
) -> Result<Response<Incoming>> {
    let io = Io { cx: cx.clone(), conn };
    let empty = Empty::<Bytes>::new;
    if version == Version::HTTP_2 {
        let (mut send, conn) = hyper::client::conn::http2::handshake(Exec(cx.clone()), io).await?;
        cx.spawn(move |_| async move {
            let _ = conn.await;
            Ok(())
        });
        let request = Request::builder().uri(format!("{scheme}://{NAME}{path}")).body(empty())?;
        Ok(send.send_request(request).await?)
    } else {
        let (mut send, conn) = hyper::client::conn::http1::handshake(io).await?;
        cx.spawn(move |_| async move {
            let _ = conn.await;
            Ok(())
        });
        let request = Request::builder().uri(path).header("host", NAME).body(empty())?;
        Ok(send.send_request(request).await?)
    }
}

/// A stdlib connection as hyper's I/O.
struct Io<C> {
    cx: Cx,
    conn: C,
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut chunk = vec![0u8; buf.remaining().min(16 * 1024)];
        match this.conn.poll_read(&this.cx, task, &mut chunk) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&chunk[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn.poll_write(&this.cx, task, data).map_err(std::io::Error::other)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.poll_shutdown(&this.cx, task).map_err(std::io::Error::other)
    }
}

/// hyper's executor for HTTP/2: each future becomes a task of the run.
#[derive(Clone)]
struct Exec(Cx);

impl<F: Future<Output = ()> + Send + 'static> hyper::rt::Executor<F> for Exec {
    fn execute(&self, fut: F) {
        self.0.spawn(move |_| async move {
            fut.await;
            Ok(())
        });
    }
}
