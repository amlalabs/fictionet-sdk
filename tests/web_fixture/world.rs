//! The quick-start world with bulk transfers and a real upstream for tests.
//!
//! `web_fixture <socket> <ca path>` serves the world. `--upstream <port>`
//! instead runs a real HTTP server on the host's network for the proxy.

use std::io::{Read, Write};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use fictionet::Result;
use fictionet::stdlib::web;
use rustls::pki_types::PrivateKeyDer;

#[allow(dead_code)]
#[path = "../../examples/web_world.rs"]
mod web_world;

fn main() -> Result {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--upstream") {
        let port = args.get(2).map(|p| p.parse()).transpose()?.unwrap_or(80);
        return upstream(port);
    }
    web_world::run(world)
}

fn world(
    fcx: &fictionet::Cx,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    attachments: fictionet::Attachments,
) -> Result {
    let app = web_world::app()
        .route("/big", get(|| async { vec![b'x'; 16 << 20] }))
        .route("/upload", post(upload).layer(DefaultBodyLimit::disable()));
    let plain = web_world::plain()
        .route("/mb", get(|| async { vec![b'x'; 1 << 20] }))
        .route("/big", get(|| async { vec![b'x'; 16 << 20] }))
        .route("/upload", post(upload).layer(DefaultBodyLimit::disable()));
    let sites = web_world::sites(fcx, chain, key, app, plain)?;
    web::Sites::new(move |host: &str| {
        if host == "upstream" {
            println!("lookup {host}");
            Some(web::Site::new(web::proxy()))
        } else {
            sites(host)
        }
    })
    .serve(fcx, attachments)
}

/// Reads a request body to its end and answers with its length, for
/// measuring uploads.
async fn upload(body: axum::body::Body) -> String {
    use http_body_util::BodyExt;
    let mut body = body;
    let mut n = 0usize;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => n += f.data_ref().map_or(0, |d| d.len()),
            Err(e) => return format!("error after {n} bytes: {e}\n"),
        }
    }
    format!("{n}\n")
}

/// A real HTTP server on the host's network, for the proxy to reach.
fn upstream(port: u16) -> Result {
    let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
    println!("upstream listening on port {port}");
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        std::thread::spawn(move || {
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let first = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned();
            println!("upstream got: {first}");
            let body = format!("hello from the real upstream: {first}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes());
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! What a client sees of the world, compared with a report recorded
    //! before the world moved onto the service layer
    //! (`tests/web_fixture/golden.txt`): DNS answers, and the status, the
    //! headers that matter and the body of each request.
    //!
    //! `WEB_FIXTURE_GOLDEN_WRITE=1 cargo test --features tokio --example web_fixture` records it
    //! again.

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, mpsc};

    use bytes::Bytes;
    use fictionet::prelude::*;
    use fictionet::stdlib::dns::op::{Message, Query};
    use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
    use fictionet::stdlib::{ip, tcp, udp};
    use fictionet::{Cx, End};
    use http_body_util::{BodyExt, Full};
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    struct Machine {
        tcp: tcp::Endpoint,
        udp: udp::Endpoint,
        _icmp: End,
    }

    async fn dns(fcx: &Cx, m: &Machine, name: &str, kind: RecordType) -> String {
        let mut socket = m
            .udp
            .bind(40000 + (fcx.random_u64() % 20000) as u16)
            .unwrap();
        let mut q = Message::query();
        q.metadata.id = 7;
        q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        socket.send_to(
            &q.to_vec().unwrap(),
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 53),
        );
        let (bytes, _) = socket.recv(fcx).await.unwrap();
        let r = Message::from_vec(&bytes).unwrap();
        let addrs: Vec<String> = r
            .answers
            .iter()
            .filter_map(|a| match &a.data {
                RData::A(a) => Some(a.0.to_string()),
                RData::AAAA(a) => Some(a.0.to_string()),
                _ => None,
            })
            .collect();
        format!(
            "dns {name} {kind:?} {:?} {addrs:?}",
            r.metadata.response_code
        )
    }

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

    /// One request; a line with what came back.
    async fn ask<IO>(io: IO, h2: bool, method: &str, uri: &str, host: &str, body: Vec<u8>) -> String
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(io);
        let request = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host)
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        let response = if h2 {
            let (mut send, conn) = hyper::client::conn::http2::handshake(Spawn, io)
                .await
                .unwrap();
            tokio::spawn(conn);
            let (mut parts, body) = request.into_parts();
            parts.headers.remove("host");
            send.send_request(http::Request::from_parts(parts, body))
                .await
                .unwrap()
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(conn);
            send.send_request(request).await.unwrap()
        };
        let status = response.status().as_u16();
        let version = response.version();
        let headers: Vec<String> = [
            "location",
            "content-length",
            "content-type",
            "transfer-encoding",
        ]
        .iter()
        .filter_map(|h| {
            response
                .headers()
                .get(*h)
                .map(|v| format!("{h}={}", v.to_str().unwrap()))
        })
        .collect();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let shown = if body.len() > 200 {
            format!("<{} bytes>", body.len())
        } else {
            format!("{:?}", String::from_utf8_lossy(&body))
        };
        format!("{method} {host}{uri} {version:?} {status} {headers:?} {shown}")
    }

    async fn report(
        fcx: &Cx,
        attacher: &fictionet::Attacher,
        roots: Arc<rustls::RootCertStore>,
    ) -> Vec<String> {
        let end = attacher.attach("agent").unwrap();
        let (t, u, i, _o) = ip::split_protocols(fcx, end);
        let m = Machine {
            tcp: tcp::endpoint(fcx, t, ME.into()),
            udp: udp::endpoint(fcx, u, ME.into()),
            _icmp: i,
        };
        let mut lines = Vec::new();
        for name in [
            "example.test",
            "www.example.test",
            "shared.test",
            "plain.test",
            "v4only.test",
            "v6only.test",
            "nope.test",
        ] {
            lines.push(dns(fcx, &m, name, RecordType::A).await);
            lines.push(dns(fcx, &m, name, RecordType::AAAA).await);
        }
        let tls = |addr: IpAddr, sni: &'static str, alpn: &'static [u8]| {
            let roots = roots.clone();
            let m = &m;
            async move {
                let conn = m
                    .tcp
                    .connect(fcx, SocketAddr::new(addr, 443))
                    .await
                    .unwrap();
                let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                config.alpn_protocols = vec![alpn.to_vec()];
                tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(ServerName::try_from(sni).unwrap(), conn.into_tokio(fcx))
                    .await
                    .unwrap()
            }
        };
        let shared: IpAddr = super::web_world::SHARED.into();
        lines.push(
            ask(
                tls(shared, "example.test", b"http/1.1").await,
                false,
                "GET",
                "/",
                "example.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                tls(shared, "example.test", b"h2").await,
                true,
                "GET",
                "https://example.test/",
                "example.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                tls(shared, "example.test", b"http/1.1").await,
                false,
                "GET",
                "/count",
                "example.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                tls(shared, "www.example.test", b"h2").await,
                true,
                "GET",
                "https://www.example.test/count",
                "www.example.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                tls(shared, "example.test", b"http/1.1").await,
                false,
                "POST",
                "/upload",
                "example.test",
                vec![b'u'; 100_000],
            )
            .await,
        );
        lines.push(
            ask(
                tls(shared, "example.test", b"http/1.1").await,
                false,
                "HEAD",
                "/big",
                "example.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                tls(shared, "example.test", b"http/1.1").await,
                false,
                "GET",
                "/nowhere",
                "example.test",
                vec![],
            )
            .await,
        );
        let plain = |addr: IpAddr| {
            let m = &m;
            async move {
                m.tcp
                    .connect(fcx, SocketAddr::new(addr, 80))
                    .await
                    .unwrap()
                    .into_tokio(fcx)
            }
        };
        lines.push(
            ask(
                plain(shared).await,
                false,
                "GET",
                "/a?b=c",
                "example.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                plain(shared).await,
                false,
                "GET",
                "/x",
                "shared.test",
                vec![],
            )
            .await,
        );
        lines.push(ask(plain(shared).await, false, "GET", "/x", "nope.test", vec![]).await);
        let auto: IpAddr = Ipv4Addr::new(198, 18, 0, 1).into();
        lines.push(ask(plain(auto).await, false, "GET", "/mb", "plain.test", vec![]).await);
        lines.push(
            ask(
                plain(auto).await,
                true,
                "GET",
                "http://plain.test/y",
                "plain.test",
                vec![],
            )
            .await,
        );
        lines.push(
            ask(
                plain(auto).await,
                false,
                "POST",
                "/upload",
                "plain.test",
                vec![b'v'; 3000],
            )
            .await,
        );
        let v4: IpAddr = Ipv4Addr::new(198, 18, 0, 2).into();
        lines.push(
            ask(
                tls(v4, "v4only.test", b"http/1.1").await,
                false,
                "GET",
                "/",
                "v4only.test",
                vec![],
            )
            .await,
        );
        lines
    }

    #[test]
    fn the_client_report_is_the_recorded_one() {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca.self_signed(&ca_key).unwrap();
        let names = [
            "example.test",
            "www.example.test",
            "v4only.test",
            "v6only.test",
        ];
        let mut leaf = CertificateParams::new(names.map(str::to_owned).to_vec()).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let roots = Arc::new(roots);
        let chain = vec![leaf.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let _ = rt.block_on(fictionet::run(
                fictionet::Seed::random(),
                move |fcx| async move {
                    let (attacher, attachments) = fictionet::attachments();
                    super::world(&fcx, chain, key, attachments)?;
                    let lines = report(&fcx, &attacher, roots).await;
                    let _ = tx.send(lines);
                    fcx.cancel();
                    Ok(())
                },
            ));
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("the client finished");
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/web_fixture/golden.txt");
        let got = got.join("\n") + "\n";
        if std::env::var_os("WEB_FIXTURE_GOLDEN_WRITE").is_some() {
            std::fs::write(file, &got).unwrap();
            return;
        }
        assert_eq!(got, std::fs::read_to_string(file).unwrap());
    }
}
