use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fictionet::Cx;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::network::{ConnError, Connection, ConnectionExt, tcp};
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, Query};
use fictionet::stdlib::protocols::dns::rr::rdata::A;
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::http1;
use fictionet::stdlib::services::dns::Client;
use fictionet::stdlib::services::stack::{Boxed, Tunnel};
use fictionet::stdlib::services::tls;
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply};
use fictionet::stdlib::world::net::dns::encrypted::Fronts;
use fictionet::stdlib::world::net::{Host, Net};
use fictionet_extras::hyper_io::{Exec, Io};
use fictionet_test_support::sandbox::{Machine, TlsClient, client_config, machine};
use fictionet_test_support::{certs, world::world};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};

const SITE: Ipv4Addr = Ipv4Addr::new(45, 33, 4, 80);
const DNS: Ipv4Addr = Ipv4Addr::new(45, 33, 9, 9);
const ADDRESS: Ipv4Addr = Ipv4Addr::new(45, 33, 4, 90);

fn date() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_750_000_000)
}

fn copied() -> tls::Factory {
    tls::Factory::new(|opening| {
        fictionet_copied_tls::TlsLayer::selecting(move |cx, hello| {
            let selected = (opening.select)(cx, hello.server_name().map(str::to_owned));
            let cx = opening.cx.clone();
            async move {
                let selected = selected.await?;
                Some(Arc::new(
                    selected.rustls_config(&cx, SystemTime::UNIX_EPOCH).ok()?,
                ))
            }
        })
        .handshake_by(opening.deadline)
    })
}

struct Page;
impl Handler for Page {
    fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
        Reply::Now(Response::new(Body::from(vec![b'x'; 16_000])))
    }
}

/// Records the actual encrypted stream delivered by the network. Parsing
/// happens after delivery, independently of server buffers and TCP chunks.
struct Recorded {
    conn: tcp::TcpConnection,
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl Connection for Recorded {
    fn poll_read(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        let read = self.conn.poll_read(cx, task, buf);
        if let Poll::Ready(Ok(n)) = read {
            self.bytes.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        read
    }
    fn poll_write(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        self.conn.poll_write(cx, task, buf)
    }
    fn poll_flush(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.conn.poll_flush(cx, task)
    }
    fn poll_shutdown(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.conn.poll_shutdown(cx, task)
    }
    fn poll_gone(&self, task: &mut Context<'_>) -> Poll<()> {
        self.conn.poll_gone(task)
    }
}

type Transcript = Arc<Mutex<Vec<u8>>>;
async fn connect(
    cx: &Cx,
    machine: &Machine,
    roots: &Arc<rustls::RootCertStore>,
    at: Ipv4Addr,
    port: u16,
    name: &str,
    protocol: &[u8],
) -> (TlsClient<Recorded>, Transcript) {
    let config = client_config(cx, date(), Some(roots), &[protocol]).unwrap();
    let session =
        rustls::ClientConnection::new(config, name.to_owned().try_into().unwrap()).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let conn = machine
        .tcp
        .connect(cx, SocketAddr::from((at, port)))
        .await
        .unwrap();
    let mut client = TlsClient::with(
        Recorded {
            conn,
            bytes: bytes.clone(),
        },
        session,
    );
    client.handshake(cx).await.unwrap();
    assert_eq!(client.tls.alpn_protocol(), Some(protocol));
    (client, bytes)
}

fn record_lengths(bytes: &Transcript) -> Vec<usize> {
    let bytes = bytes.lock().unwrap();
    let mut remaining = bytes.as_slice();
    let mut lengths = Vec::new();
    while remaining.len() >= 5 {
        let n = usize::from(u16::from_be_bytes([remaining[3], remaining[4]]));
        if remaining.len() < n + 5 {
            break;
        }
        lengths.push(n);
        remaining = &remaining[n + 5..];
    }
    assert!(!lengths.is_empty());
    lengths
}

fn small_records(bytes: &Transcript) {
    // A TLS 1.3 encrypted record adds an inner content type and an AEAD tag.
    assert!(record_lengths(bytes).into_iter().all(|n| n <= 512 + 1 + 16));
}

async fn request(
    cx: &Cx,
    client: TlsClient<Recorded>,
    h2: bool,
    request: Request<Full<Bytes>>,
) -> (StatusCode, Bytes) {
    let io = Io {
        fcx: cx.clone(),
        conn: client,
    };
    let response = if h2 {
        let (mut send, conn) = hyper::client::conn::http2::handshake(Exec(cx.clone()), io)
            .await
            .unwrap();
        cx.spawn(move |_| async move {
            let _ = conn.await;
            Ok(())
        });
        send.send_request(request).await.unwrap()
    } else {
        let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        cx.spawn(move |_| async move {
            let _ = conn.await;
            Ok(())
        });
        send.send_request(request).await.unwrap()
    };
    assert_eq!(
        response.version(),
        if h2 {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        }
    );
    let status = response.status();
    (
        status,
        response.into_body().collect().await.unwrap().to_bytes(),
    )
}

fn get(h2: bool, name: &str) -> Request<Full<Bytes>> {
    Request::get(if h2 {
        format!("https://{name}/")
    } else {
        "/".to_owned()
    })
    .header("host", name)
    .body(Full::new(Bytes::new()))
    .unwrap()
}

async fn answer(_: Cx, client: Client, bytes: Vec<u8>) -> Option<Vec<u8>> {
    assert_eq!(client.peer.ip(), Ipv4Addr::new(10, 0, 0, 2));
    let mut message = Message::from_vec(&bytes).unwrap();
    message.metadata.message_type = MessageType::Response;
    message.add_answer(Record::from_rdata(
        message.queries[0].name().clone(),
        300,
        RData::A(A(ADDRESS)),
    ));
    Some(message.to_vec().unwrap())
}

fn query() -> Message {
    let mut message = Message::query();
    message.metadata.id = 91;
    message.add_query(Query::query(
        Name::from_ascii("site.example.").unwrap(),
        RecordType::A,
    ));
    message
}

fn check_answer(bytes: &[u8]) {
    let message = Message::from_vec(bytes).unwrap();
    assert_eq!(message.metadata.id, query().metadata.id);
    assert_eq!(message.metadata.message_type, MessageType::Response);
    assert_eq!(&message.answers[0].data, &RData::A(A(ADDRESS)));
}

#[test]
fn owned_tls_serves_both_http_versions_and_encrypted_dns() {
    world(Duration::from_secs(60), |cx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (ca, leaf) = certs::issue(
            &cx,
            "Example CA",
            &["site.example", "neighbor.example", "dns.example"],
        )?;
        let config = leaf.certified_key();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der())?;
        let roots = Arc::new(roots);
        let site_config = config.clone();
        let site = fictionet::stdlib::web::Site::from_server(
            httpd::Server::new(Page)
                .tls_with(move |_| site_config.clone())
                .tls_layer(copied()),
        )
        .at(SITE)
        .into_host("site.example");
        // This site's default TLS factory does not replace the existing listener.
        let neighbor_config = config.clone();
        let neighbor = httpd::Server::new(Page)
            .tls_with(move |_| neighbor_config.clone())
            .served_by(Host::new("neighbor").at(SITE).dns_name("neighbor.example"));
        let fronts = Fronts::new(answer, move |_| config.clone())
            .tls_layer(copied())
            .names([Name::from_ascii("dns.example.")?]);
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts([
                site,
                neighbor,
                fronts.doh(fronts.dot(Host::new("dns").at(DNS))),
            ])
            .start(&cx, attachments)?;
        let machine = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
        for h2 in [false, true] {
            let protocol = if h2 { b"h2".as_slice() } else { b"http/1.1" };
            let (client, transcript) =
                connect(&cx, &machine, &roots, SITE, 443, "site.example", protocol).await;
            let (status, body) = request(&cx, client, h2, get(h2, "site.example")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), vec![b'x'; 16_000]);
            small_records(&transcript);
            assert!(record_lengths(&transcript).len() > 16_000 / 512);
        }
        let (client, transcript) =
            connect(&cx, &machine, &roots, SITE, 443, "neighbor.example", b"h2").await;
        let req = Request::get("https://neighbor.example/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, body) = request(&cx, client, true, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), vec![b'x'; 16_000]);
        small_records(&transcript);
        let (mut client, transcript) =
            connect(&cx, &machine, &roots, DNS, 853, "dns.example", b"dot").await;
        let message = query().to_vec().unwrap();
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&message);
        client.write_all(&cx, &framed).await.unwrap();
        let mut response = Vec::new();
        loop {
            if response.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([response[0], response[1]]));
                if response.len() == len + 2 {
                    break;
                }
            }
            let mut buffer = [0; 4096];
            let n = client.read(&cx, &mut buffer).await.unwrap();
            assert!(n > 0);
            response.extend_from_slice(&buffer[..n]);
        }
        check_answer(&response[2..]);
        small_records(&transcript);
        for h2 in [false, true] {
            let protocol = if h2 { b"h2".as_slice() } else { b"http/1.1" };
            let (client, transcript) =
                connect(&cx, &machine, &roots, DNS, 443, "dns.example", protocol).await;
            let req = Request::post(if h2 {
                "https://dns.example/dns-query"
            } else {
                "/dns-query"
            })
            .header("host", "dns.example")
            .header("content-type", "application/dns-message")
            .body(Full::new(Bytes::from(message.clone())))
            .unwrap();
            let (status, bytes) = request(&cx, client, h2, req).await;
            assert_eq!(status, StatusCode::OK);
            check_answer(&bytes);
            small_records(&transcript);
        }
        Ok(())
    });
}

/// A deliberately small HTTP/1 application: one whole request, answered
/// with JSON, then close. It owns HTTP serving while reusing wire framing.
fn alternate_http1() -> Boxed {
    Boxed::new(Tunnel::new(|cx, mut conn| async move {
        let mut requests = Stream::new(http1::Requests::new());
        let mut buf = [0; 4096];
        loop {
            let Ok(n) = conn.read(&cx, &mut buf).await else {
                return;
            };
            if n == 0 || requests.push(&buf[..n]) != n {
                return;
            }
            if let Some(request) = requests.next() {
                let Ok(request) = request else {
                    return;
                };
                let mut response =
                    http1::Response::json(b"{\"implementation\":\"owned\"}").unwrap();
                response.head.headers.push(http1::Header {
                    name: "Connection".into(),
                    value: b"close".to_vec(),
                });
                let mut bytes = Vec::new();
                response
                    .write_for(request.head.method(), &mut bytes)
                    .unwrap();
                if conn.write_all(&cx, &bytes).await.is_ok() {
                    let _ = conn.shutdown(&cx).await;
                }
                return;
            }
        }
    }))
}

#[test]
fn owned_http1_keeps_standard_tls_and_http2() {
    world(Duration::from_secs(60), |cx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (ca, leaf) = certs::issue(&cx, "Example CA", &["site.example", "alternate.example"])?;
        let config = leaf.certified_key();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der())?;
        let roots = Arc::new(roots);
        let first_config = config.clone();
        let first = httpd::Server::new(Page)
            .tls_with(move |_| first_config.clone())
            .served_by(Host::new("first").at(SITE).dns_name("site.example"));
        let site = httpd::Server::new(Page)
            .tls_with(move |_| config.clone())
            .applications(
                vec![
                    b"h2".to_vec(),
                    b"http/1.1".to_vec(),
                    b"echo.example".to_vec(),
                ],
                |cx, opening, handler, options| {
                    if opening.info.alpn.as_deref() == Some(b"h2") {
                        Boxed::new(httpd::http_for(handler, options, &opening.info, cx.now()))
                    } else if opening.info.alpn.as_deref() == Some(b"echo.example") {
                        Boxed::new(Tunnel::new(|cx, mut conn| async move {
                            let mut buf = [0; 128];
                            while let Ok(n) = conn.read(&cx, &mut buf).await {
                                if n == 0 || conn.write_all(&cx, &buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }))
                    } else {
                        alternate_http1()
                    }
                },
            )
            .served_by(
                Host::new("alternate")
                    .at(SITE)
                    .dns_name("alternate.example"),
            );
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts([first, site])
            .start(&cx, attachments)?;
        let machine = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
        let (client, _) = connect(
            &cx,
            &machine,
            &roots,
            SITE,
            443,
            "site.example",
            b"http/1.1",
        )
        .await;
        let (status, body) = request(&cx, client, false, get(false, "site.example")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), vec![b'x'; 16_000]);
        for h2 in [false, true] {
            let protocol = if h2 { b"h2".as_slice() } else { b"http/1.1" };
            let (client, transcript) = connect(
                &cx,
                &machine,
                &roots,
                SITE,
                443,
                "alternate.example",
                protocol,
            )
            .await;
            let (status, body) = request(&cx, client, h2, get(h2, "alternate.example")).await;
            assert_eq!(status, StatusCode::OK);
            if h2 {
                assert_eq!(body.as_ref(), vec![b'x'; 16_000]);
                assert!(record_lengths(&transcript).into_iter().any(|n| n > 529));
            } else {
                assert_eq!(body.as_ref(), b"{\"implementation\":\"owned\"}");
            }
        }
        let (mut client, _) = connect(
            &cx,
            &machine,
            &roots,
            SITE,
            443,
            "alternate.example",
            b"echo.example",
        )
        .await;
        let sent = b"an application selected by its own ALPN";
        client.write_all(&cx, sent).await.unwrap();
        let mut received = vec![0; sent.len()];
        let mut count = 0;
        while count < received.len() {
            let n = client.read(&cx, &mut received[count..]).await.unwrap();
            assert!(n > 0);
            count += n;
        }
        assert_eq!(received, sent);
        Ok(())
    });
}
