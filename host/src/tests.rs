use super::*;
use fictionet::stdlib::{protocols::x509, services::ca::Ca, web::httpd};
use fictionet::{Cx, Seed};
use http_body_util::BodyExt;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use tower_service::Service;

trait Socket: Read + Write {}
impl<T: Read + Write> Socket for T {}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const OK_CLOSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// A server configuration with a certificate for `name` from a new CA, and
/// a client configuration that trusts that CA.
fn certificates(fcx: &Cx, name: &str) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let ca = Ca::new(fcx, "Upstream test CA").unwrap();
    let leaf = ca
        .issue(
            fcx,
            &[name],
            x509::Validity {
                not_before: x509::Time::from_unix(946684800).unwrap(),
                not_after: x509::Time::from_unix(4102444800).unwrap(),
            },
        )
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    (Arc::new(client), Arc::new(server))
}

fn forward(
    fcx: &Cx,
    client: Arc<Client>,
    tls: bool,
    authority: impl std::fmt::Display,
) -> fictionet::stdlib::web::Forward {
    let scheme = if tls { "https" } else { "http" };
    fictionet::stdlib::web::forward(
        fcx,
        format!("{scheme}://{authority}").parse().unwrap(),
        client,
    )
    .unwrap()
}

/// Accepts one connection. Each server read and write has five seconds, so
/// a broken client fails the test instead of hanging it. Each write goes out
/// at once: under Nagle an answer could wait for an ACK, and a server that
/// then closes on unread bytes resets the connection and drops it unsent.
fn accept(listener: &TcpListener) -> TcpStream {
    let (tcp, _) = listener.accept().unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_nodelay(true).unwrap();
    tcp
}

fn serve_tls(
    config: Arc<rustls::ServerConfig>,
    mut tcp: TcpStream,
) -> rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    let mut conn = rustls::ServerConnection::new(config).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).unwrap();
    }
    rustls::StreamOwned::new(conn, tcp)
}

/// An upstream on 127.0.0.1 that serves one connection.
fn upstream(
    fcx: &Cx,
    tls: bool,
    serve: impl FnOnce(&mut dyn Socket) + Send + 'static,
) -> (
    fictionet::stdlib::web::Forward,
    thread::JoinHandle<()>,
    String,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = Client::new();
    let server = tls.then(|| {
        let (trust, server) = certificates(fcx, "127.0.0.1");
        client.tls = trust;
        server
    });
    let worker = thread::spawn(move || {
        let mut tcp = accept(&listener);
        if let Some(server) = server {
            let mut stream = serve_tls(server, tcp);
            assert_eq!(stream.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
            serve(&mut stream);
            stream.conn.send_close_notify();
            let _ = stream.flush();
        } else {
            serve(&mut tcp);
        }
    });
    (
        forward(fcx, Arc::new(client), tls, address),
        worker,
        format!("{}://{address}", if tls { "https" } else { "http" }),
    )
}

/// A listener whose accept queue is full, so that connecting to it hangs:
/// Linux drops a SYN that would overflow the queue.
fn unanswered() -> (TcpListener, TcpStream, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // SAFETY: listen takes no pointers; this only shortens the queue.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let address = listener.local_addr().unwrap();
    let queued = TcpStream::connect(address).unwrap();
    (listener, queued, address)
}

fn read_head(socket: &mut dyn Socket) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

fn request() -> Request<Body> {
    Request::builder()
        .uri("/path?q=1")
        .header("host", "original.test")
        .body(Body::empty())
        .unwrap()
}

fn upload(size: usize) -> Request<Body> {
    let mut request = request();
    *request.method_mut() = Method::POST;
    *request.body_mut() = Body::from(vec![b'x'; size]);
    request
}

fn run<F>(test: impl FnOnce(Cx, Arc<fictionet_test_support::EventLog>) -> F + Send)
where
    F: std::future::Future<Output = Result<(), Error>> + Send + 'static,
{
    let log = Arc::new(fictionet_test_support::EventLog::default());
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(Seed::from_u64(1)).observer(log.clone()),
        move |fcx| test(fcx, log),
    ))
    .unwrap();
}

async fn poll_once<F: Future + ?Sized>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

#[test]
fn content_length_and_chunked_responses_reuse_connections() {
    for tls in [false, true] {
        run(async move |fcx, _log| {
            let (mut forward, server, _origin) = upstream(&fcx, tls, |socket| {
                for response in [
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
                    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nworld\r\n0\r\n\r\n",
                ] {
                    let head = read_head(socket).to_ascii_lowercase();
                    assert!(head.starts_with("get /path?q=1 http/1.1\r\n"));
                    assert!(head.contains("host: original.test\r\n"));
                    socket.write_all(response).unwrap();
                    socket.flush().unwrap();
                }
            });
            for (expected, length) in [("hello", Some(5)), ("world", None)] {
                let response = forward.call(request()).await?;
                assert_eq!(response.status(), 200);
                assert_eq!(response.body().size_hint().exact(), length);
                assert_eq!(response.into_body().collect().await?.to_bytes(), expected);
            }
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn empty_requests_declare_a_length_only_when_their_method_expects_content() {
    run(async |fcx, _log| {
        let methods = ["GET", "HEAD", "DELETE", "OPTIONS", "POST", "PUT", "PATCH"];
        let (mut forward, server, _origin) = upstream(&fcx, false, move |socket| {
            for method in methods {
                let head = read_head(socket).to_ascii_lowercase();
                let expects = matches!(method, "POST" | "PUT" | "PATCH");
                assert_eq!(head.contains("content-length: 0\r\n"), expects, "{head}");
                assert!(!head.contains("transfer-encoding"), "{head}");
                socket
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .unwrap();
                socket.flush().unwrap();
            }
        });
        for method in methods {
            let mut request = request();
            *request.method_mut() = method.parse()?;
            let response = forward.call(request).await?;
            assert_eq!(response.status(), 204);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
        }
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn large_responses_stream_beyond_the_owned_codec_limit() {
    for tls in [false, true] {
        run(async move |fcx, _log| {
            let size = 12 << 20;
            let (mut forward, server, _origin) = upstream(&fcx, tls, move |socket| {
                read_head(socket);
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").unwrap();
                for _ in 0..size / 8192 {
                    socket.write_all(&[b'x'; 8192]).unwrap();
                }
                socket.flush().unwrap();
            });
            let mut body = forward.call(request()).await?.into_body();
            let mut received = 0;
            while let Some(frame) = body.frame().await {
                let data = frame?.into_data().unwrap();
                assert!(data.len() <= 8192);
                assert!(data.iter().all(|b| *b == b'x'));
                received += data.len();
            }
            assert_eq!(received, size);
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn close_delimited_responses_and_redirects_are_passed_through() {
    for tls in [false, true] {
        run(async move |fcx, _log| {
            let (mut forward, server, _origin) = upstream(&fcx, tls, |socket| {
                read_head(socket);
                socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: /elsewhere?q=2\r\nConnection: close\r\n\r\nredirect body").unwrap();
                socket.flush().unwrap();
            });
            let response = forward.call(request()).await?;
            assert_eq!(response.status(), 302);
            assert_eq!(response.headers()["location"], "/elsewhere?q=2");
            assert!(!response.headers().contains_key("connection"));
            assert_eq!(
                response.into_body().collect().await?.to_bytes(),
                "redirect body"
            );
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn close_delimited_events_arrive_before_the_server_closes() {
    for tls in [false, true] {
        run(async move |fcx, _log| {
            let (received, receipt) = mpsc::channel();
            let (mut forward, server, _origin) = upstream(&fcx, tls, move |socket| {
                read_head(socket);
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: first\n\n").unwrap();
                socket.flush().unwrap();
                receipt
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the client buffered the first event until the server closed");
                socket.write_all(b"data: second\n\n").unwrap();
                socket.flush().unwrap();
            });
            let response = forward.call(request()).await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], "text/event-stream");
            let mut body = response.into_body();
            let mut first = Vec::new();
            while first.len() < b"data: first\n\n".len() {
                let frame = body.frame().await.expect("the first event is missing")?;
                first.extend_from_slice(&frame.into_data().unwrap());
            }
            assert_eq!(first, b"data: first\n\n");
            received.send(()).unwrap();
            let mut second = Vec::new();
            while let Some(frame) = body.frame().await {
                second.extend_from_slice(&frame?.into_data().unwrap());
            }
            assert_eq!(second, b"data: second\n\n");
            assert!(body.is_end_stream());
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn tls_without_close_notify_uses_the_response_framing() {
    run(async move |fcx, _log| {
        for (response, complete) in [
            (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello".as_slice(), true),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", true),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello", false),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", true),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let (trust, config) = certificates(&fcx, "127.0.0.1");
            let server = thread::spawn(move || {
                let mut socket = serve_tls(config, accept(&listener));
                read_head(&mut socket);
                socket.write_all(response).unwrap();
                socket.flush().unwrap();
            });
            let mut client = Client::new();
            client.tls = trust;
            let mut forward = forward(&fcx, Arc::new(client), true, address);
            let body = forward.call(request()).await?.into_body().collect().await;
            if complete {
                assert_eq!(body?.to_bytes(), "hello");
            } else {
                assert!(body.is_err(), "a truncated body was accepted");
            }
            server.join().unwrap();
        }
        Ok(())
    });
}

#[test]
fn head_204_304_and_interim_responses_have_no_body() {
    for tls in [false, true] {
        run(async move |fcx, _log| {
            let (mut forward, server, _origin) = upstream(&fcx, tls, |socket| {
                for (method, response) in [
                    ("head", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".as_slice()),
                    ("get", b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"),
                    ("get", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\nETag: \"x\"\r\n\r\n"),
                    ("get", b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"),
                ] {
                    let head = read_head(socket).to_ascii_lowercase();
                    assert!(head.starts_with(&format!("{method} ")), "{head}");
                    socket.write_all(response).unwrap();
                    socket.flush().unwrap();
                }
            });
            // All four share one connection, so each bodiless answer ended
            // exactly at its head.
            for (method, status, body) in [
                ("HEAD", 200, ""),
                ("GET", 204, ""),
                ("GET", 304, ""),
                ("GET", 200, "done"),
            ] {
                let mut request = request();
                *request.method_mut() = method.parse()?;
                let response = forward.call(request).await?;
                assert_eq!(response.status(), status);
                assert_eq!(response.body().size_hint().exact(), Some(body.len() as u64));
                assert_eq!(response.into_body().collect().await?.to_bytes(), body);
            }
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn chunk_extensions_and_trailers_are_skipped() {
    run(async |fcx, _log| {
        let (mut forward, server, _origin) = upstream(&fcx, false, |socket| {
            for _ in 0..2 {
                read_head(socket);
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n5;name=value\r\nhello\r\n0;last\r\nX-Sum: 5\r\n\r\n")
                    .unwrap();
                socket.flush().unwrap();
            }
        });
        // The second request reuses the connection, so the trailer was read
        // to its end.
        for _ in 0..2 {
            let response = forward.call(request()).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "hello");
        }
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn connection_close_responses_are_not_reused() {
    run(async |fcx, _log| {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let mut tcp = accept(&listener);
                read_head(&mut tcp);
                tcp.write_all(OK_CLOSE).unwrap();
                // The client closes its side instead of sending more here.
                assert_eq!(tcp.read(&mut [0]).unwrap(), 0);
            }
        });
        let mut forward = forward(&fcx, Arc::new(Client::new()), false, address);
        for _ in 0..2 {
            let response = forward.call(request()).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        }
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn a_pooled_connection_the_server_closed_is_replaced_for_idempotent_requests() {
    for tls in [false, true] {
        run(async move |fcx, _log| {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let address = listener.local_addr()?;
            let mut client = Client::new();
            let config = tls.then(|| {
                let (trust, server) = certificates(&fcx, "127.0.0.1");
                client.tls = trust;
                server
            });
            let (closed, idle_closed) = mpsc::channel();
            let server = thread::spawn(move || {
                let open = || -> Box<dyn Socket> {
                    let tcp = accept(&listener);
                    match &config {
                        Some(config) => Box::new(serve_tls(config.clone(), tcp)),
                        None => Box::new(tcp),
                    }
                };
                // Closed while idle.
                let mut first = open();
                read_head(&mut *first);
                first.write_all(OK).unwrap();
                first.flush().unwrap();
                drop(first);
                closed.send(()).unwrap();
                // Closed when the next request arrives, which it leaves
                // unanswered.
                let mut second = open();
                read_head(&mut *second);
                second.write_all(OK).unwrap();
                second.flush().unwrap();
                read_head(&mut *second);
                drop(second);
                // That request is idempotent, so it comes again, body and all.
                let mut third = open();
                let head = read_head(&mut *third).to_ascii_lowercase();
                assert!(head.starts_with("put "), "{head}");
                let mut body = [0; 5];
                third.read_exact(&mut body).unwrap();
                assert_eq!(&body, b"again");
                third.write_all(OK).unwrap();
                third.flush().unwrap();
                // A POST left unanswered may have been acted on, so it does
                // not come again: the next connection carries the GET after it.
                let head = read_head(&mut *third).to_ascii_lowercase();
                assert!(head.starts_with("post "), "{head}");
                drop(third);
                let mut fourth = open();
                let head = read_head(&mut *fourth).to_ascii_lowercase();
                assert!(head.starts_with("get "), "{head}");
                fourth.write_all(OK).unwrap();
                fourth.flush().unwrap();
            });
            let mut forward = forward(&fcx, Arc::new(client), tls, address);
            let response = forward.call(request()).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            idle_closed.recv()?;
            for request in [request(), {
                let mut again = request();
                *again.method_mut() = Method::PUT;
                *again.body_mut() = Body::from("again");
                again
            }] {
                let response = forward.call(request).await?;
                assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            }
            let mut once = request();
            *once.method_mut() = Method::POST;
            *once.body_mut() = Body::from("once");
            assert!(forward.call(once).await.is_err());
            let response = forward.call(request()).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn tls_sends_and_checks_the_dns_name() {
    run(async |fcx, _log| {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let (trust, config) = certificates(&fcx, "localhost");
        let server = thread::spawn(move || {
            let mut stream = serve_tls(config, accept(&listener));
            assert_eq!(stream.conn.server_name(), Some("localhost"));
            read_head(&mut stream);
            stream.write_all(OK).unwrap();
            stream.flush().unwrap();
        });
        let mut client = Client::new();
        client.tls = trust;
        // localhost may also resolve to ::1, where nothing listens, so this
        // also moves on from a refused address.
        let mut forward = forward(&fcx, Arc::new(client), true, format!("localhost:{port}"));
        let response = forward.call(request()).await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn tls_refuses_a_certificate_for_another_name_or_from_an_unknown_ca() {
    run(async |fcx, _log| {
        let (trust, wrong_name) = certificates(&fcx, "elsewhere.test");
        let (_, unknown_ca) = certificates(&fcx, "localhost");
        for config in [wrong_name, unknown_ca] {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            let server = thread::spawn(move || {
                let mut tcp = accept(&listener);
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut tcp).is_err() {
                        return;
                    }
                }
                panic!("the client finished a handshake it should refuse");
            });
            let mut client = Client::new();
            client.tls = trust.clone();
            let mut forward = forward(&fcx, Arc::new(client), true, format!("localhost:{port}"));
            let error = forward.call(request()).await.unwrap_err();
            assert!(
                error.to_string().contains("invalid peer certificate"),
                "{error}"
            );
            server.join().unwrap();
        }
        Ok(())
    });
}

#[test]
fn a_large_upload_streams_while_the_server_echoes_it() {
    run(async |fcx, _log| {
        let size = 64 << 20;
        let (mut forward, server, _origin) = upstream(&fcx, false, move |socket| {
            read_head(socket);
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").unwrap();
            let mut buf = vec![0; 64 << 10];
            let mut left = size;
            while left > 0 {
                let n = socket.read(&mut buf[..left.min(64 << 10)]).unwrap();
                assert_ne!(n, 0);
                socket.write_all(&buf[..n]).unwrap();
                left -= n;
            }
            socket.flush().unwrap();
        });
        let mut body = forward.call(upload(size)).await?.into_body();
        let mut received = 0;
        while let Some(frame) = body.frame().await {
            let data = frame?.into_data().unwrap();
            assert!(data.iter().all(|b| *b == b'x'));
            received += data.len();
        }
        assert_eq!(received, size);
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn an_early_answer_during_an_upload_reaches_the_world() {
    for tls in [false, true] {
        for linger in [false, true] {
            run(async move |fcx, _log| {
                let size = 64 << 20;
                let (mut forward, server, _origin) = upstream(&fcx, tls, move |socket| {
                    read_head(socket);
                    socket
                        .write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo much")
                        .unwrap();
                    socket.flush().unwrap();
                    if linger {
                        // RFC 9112 section 9.6: read on until the client
                        // closes, which it does once it has the answer.
                        let mut read = 0;
                        let mut buf = vec![0; 64 << 10];
                        while let Ok(n @ 1..) = socket.read(&mut buf) {
                            read += n;
                        }
                        assert!(read < size, "the client sent the whole body");
                    }
                    // Otherwise the server closes on unread bytes, and the
                    // client's writes fail while the answer waits to be read.
                });
                let response = forward.call(upload(size)).await?;
                assert_eq!(response.status(), 413);
                assert_eq!(response.into_body().collect().await?.to_bytes(), "too much");
                server.join().unwrap();
                Ok(())
            });
        }
    }
}

struct Downstream {
    input: Bytes,
    output: Arc<Mutex<Vec<u8>>>,
    reset: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl fictionet::stdlib::network::Connection for Downstream {
    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        match &mut *self.reset.lock() {
            Some(reset) => Pin::new(reset).poll(cx).map(|_| ()),
            None => Poll::Pending,
        }
    }

    fn poll_read(
        &mut self,
        _: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, fictionet::stdlib::network::ConnError>> {
        if self.input.is_empty() {
            if let Some(reset) = &mut *self.reset.lock()
                && Pin::new(reset).poll(cx).is_ready()
            {
                return Poll::Ready(Err(fictionet::stdlib::network::ConnError::Reset));
            }
            return Poll::Pending;
        }
        let n = buf.len().min(self.input.len());
        buf[..n].copy_from_slice(&self.input.split_to(n));
        Poll::Ready(Ok(n))
    }
    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, fictionet::stdlib::network::ConnError>> {
        self.output.lock().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_shutdown(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), fictionet::stdlib::network::ConnError>> {
        Poll::Ready(Ok(()))
    }
}

/// Serves one request through `forward` the way a site does and returns
/// the answer.
async fn serve_one(fcx: &Cx, forward: fictionet::stdlib::web::Forward) -> String {
    let output = Arc::new(Mutex::new(Vec::new()));
    let conn = Downstream {
        input: Bytes::from_static(
            b"GET / HTTP/1.1\r\nHost: original.test\r\nConnection: close\r\n\r\n",
        ),
        output: output.clone(),
        reset: Mutex::new(None),
    };
    fcx.race(
        Some(fcx.now() + Duration::from_secs(5)),
        httpd::serve_connection(
            fcx,
            conn,
            fictionet::events::ConnInfo::default(),
            Arc::new(forward),
            &httpd::HttpOptions::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    String::from_utf8(output.lock().clone()).unwrap()
}

/// Serves one request through `forward`, checks that it answered 502 and
/// recorded the error and the origin it tried, and returns the answer.
async fn bad_gateway(
    fcx: &Cx,
    log: &fictionet_test_support::EventLog,
    forward: fictionet::stdlib::web::Forward,
    origin: &str,
) -> String {
    let output = serve_one(fcx, forward).await;
    assert!(
        output.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{output}"
    );
    let events = log.of("http", "request");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].str("answer"), Some("error"));
    assert_eq!(events[0].u64("status"), Some(502));
    assert_eq!(events[0].str("forwarded"), Some(origin));
    output
}

#[test]
fn a_forwarded_request_names_the_origin_in_its_event() {
    for tls in [false, true] {
        run(async move |fcx, log| {
            let (forward, server, _origin) = upstream(&fcx, tls, |socket| {
                read_head(socket);
                socket.write_all(OK_CLOSE).unwrap();
                socket.flush().unwrap();
            });

            let output = serve_one(&fcx, forward).await;
            assert!(output.starts_with("HTTP/1.1 200 OK\r\n"), "{output}");
            let events = log.of("http", "request");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].str("answer"), Some("handler"));
            assert_eq!(events[0].u64("status"), Some(200));
            assert_eq!(events[0].str("forwarded"), Some(_origin.as_str()));
            assert!(_origin.starts_with(if tls {
                "https://127.0.0.1:"
            } else {
                "http://127.0.0.1:"
            }));
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn malformed_heads_record_bad_gateway_responses() {
    for tls in [false, true] {
        run(async move |fcx, log| {
            let (forward, server, _origin) = upstream(&fcx, tls, |socket| {
                read_head(socket);
                socket.write_all(b"HTTP/1.1 not-a-status\r\n\r\n").unwrap();
                socket.flush().unwrap();
            });
            let output = bad_gateway(&fcx, &log, forward, &_origin).await;
            assert!(
                output.contains("the upstream response is malformed: invalid HTTP start line"),
                "{output}"
            );
            server.join().unwrap();
            Ok(())
        });
    }
}

#[test]
fn stalled_connections_time_out_with_bad_gateway_responses() {
    let quick = || {
        let mut client = Client::new();
        client.connect_timeout = Duration::from_millis(100);
        Arc::new(client)
    };
    run(async move |fcx, log| {
        let (_listener, _queued, address) = unanswered();
        let output = bad_gateway(
            &fcx,
            &log,
            forward(&fcx, quick(), false, address),
            &format!("http://{address}"),
        )
        .await;
        assert!(output.contains("connecting timed out"), "{output}");
        Ok(())
    });
    run(async move |fcx, log| {
        // A server that takes the connection but never answers the TLS hello.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            let mut tcp = accept(&listener);
            let mut hello = Vec::new();
            let _ = tcp.read_to_end(&mut hello);
        });
        let output = bad_gateway(
            &fcx,
            &log,
            forward(&fcx, quick(), true, address),
            &format!("https://{address}"),
        )
        .await;
        assert!(output.contains("connecting timed out"), "{output}");
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn dropping_a_streaming_response_interrupts_the_upstream_read() {
    run(async |fcx, _log| {
        let (mut forward, server, _origin) = upstream(&fcx, false, |socket| {
            read_head(socket);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                .unwrap();
            socket.flush().unwrap();
            assert_eq!(socket.read(&mut [0]).unwrap(), 0);
        });
        drop(forward.call(request()).await?);
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn dropping_a_request_while_it_connects_frees_its_slot() {
    run(async |fcx, _log| {
        let (_listener, _queued, hanging) = unanswered();
        let (_ok, server, _origin) = upstream(&fcx, false, |socket| {
            read_head(socket);
            socket.write_all(OK).unwrap();
            socket.flush().unwrap();
        });
        let mut client = Client::new();
        client.exchanges = 1;
        let client = Arc::new(client);
        let mut stuck = forward(&fcx, client.clone(), false, hanging);
        let mut ok = forward(
            &fcx,
            client.clone(),
            false,
            _origin.parse::<http::Uri>()?.authority().unwrap(),
        );
        let mut connecting = stuck.call(request());
        assert!(poll_once(connecting.as_mut()).await.is_pending());
        let mut waiting = ok.call(request());
        assert!(poll_once(waiting.as_mut()).await.is_pending());
        assert_eq!(client.slots.lock().busy, 1);
        drop(connecting);
        let response = waiting.await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn exchanges_past_the_cap_wait_for_a_slot() {
    run(async |fcx, _log| {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let (arrived, both_arrived) = mpsc::channel();
        let (answer, answered) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut open: Vec<_> = (0..2)
                .map(|_| {
                    let mut tcp = accept(&listener);
                    read_head(&mut tcp);
                    tcp
                })
                .collect();
            arrived.send(()).unwrap();
            answered.recv().unwrap();
            for tcp in &mut open {
                tcp.write_all(OK_CLOSE).unwrap();
            }
            let mut third = accept(&listener);
            read_head(&mut third);
            third.write_all(OK_CLOSE).unwrap();
        });
        let mut client = Client::new();
        client.exchanges = 2;
        let client = Arc::new(client);
        let mut forward = forward(&fcx, client.clone(), false, address);
        let mut calls: Vec<_> = (0..3).map(|_| forward.call(request())).collect();
        for call in &mut calls {
            assert!(poll_once(call.as_mut()).await.is_pending());
        }
        both_arrived.recv()?;
        assert_eq!(client.slots.lock().busy, 2);
        assert!(poll_once(calls[2].as_mut()).await.is_pending());
        answer.send(())?;
        for call in calls {
            let response = call.await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        }
        server.join().unwrap();
        Ok(())
    });
}

#[test]
fn a_client_reset_before_the_upstream_answers_keeps_the_origin() {
    run(async move |fcx, events| {
        let (reset, receive) = tokio::sync::oneshot::channel();
        let (finish, finished) = mpsc::channel();
        let (forward, server, _origin) = upstream(&fcx, false, move |socket| {
            read_head(socket);
            reset.send(()).unwrap();
            finished.recv_timeout(Duration::from_secs(5)).unwrap();
        });

        let conn = Downstream {
            input: Bytes::from_static(b"GET / HTTP/1.1\r\nHost: original.test\r\n\r\n"),
            output: Arc::default(),
            reset: Mutex::new(Some(receive)),
        };
        httpd::serve_connection(
            &fcx,
            conn,
            fictionet::events::ConnInfo::default(),
            Arc::new(forward),
            &httpd::HttpOptions::default(),
        )
        .await?;
        let requests = events.of("http", "request");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].str("answer"), Some("cancelled"));
        assert_eq!(requests[0].u64("status"), None);
        assert_eq!(requests[0].str("forwarded"), Some(_origin.as_str()));
        finish.send(()).unwrap();
        server.join().unwrap();
        Ok(())
    });
}
