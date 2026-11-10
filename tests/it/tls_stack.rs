//! TCP, TLS and HTTP/1 composed with `Chain`: the same stack in the pure
//! harness, at every cut and under backpressure, and live over TCP in a
//! world, including a CONNECT inside TLS that hands the stream on.

use super::*;
use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use fictionet::stdlib::layer::{Budget, Chain, Harness, Switch};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::network::{ip, tcp};
use fictionet::stdlib::services::stack::{self, Polling, StreamEnd, StreamLimits};
use fictionet::stdlib::web::httpd::{self, Http1};
use fictionet::{Entropy, SeededEntropy};

/// TLS with HTTP/1 on top, the HTTP/1 able to hand its stream on.
type Https = Chain<tls::TlsLayer, Switch<Http1, httpd::Upgraded>>;

fn https(config: Arc<ServerConfig>, handler: impl httpd::Handler) -> Https {
    Chain::new(tls::TlsLayer::new(config), Http1::new(handler).upgradable())
}

/// Answers `GET /` with a body long enough to take several records, and
/// CONNECT with 200 and an echo of the tunnel.
fn handler() -> impl httpd::Handler {
    fictionet_test_support::reply_handler(|_, request| {
        if request.method() == http::Method::CONNECT {
            let mut response = http::Response::new(httpd::Body::empty());
            response.extensions_mut().insert(httpd::UpgradeHandler::new(
                |fcx, mut conn| async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = conn.read(&fcx, &mut buf).await {
                        if n == 0 || conn.write_all(&fcx, &buf[..n]).await.is_err() {
                            break;
                        }
                    }
                },
            ));
            return httpd::Reply::Now(response);
        }
        httpd::Reply::Now(http::Response::new(httpd::Body::from(page())))
    })
}

fn page() -> Vec<u8> {
    (0..40_000u32).map(|n| b'a' + (n % 26) as u8).collect()
}

fn client(config: Arc<ClientConfig>) -> rustls::ClientConnection {
    rustls::ClientConnection::new(
        config,
        rustls::pki_types::ServerName::try_from("example.test").unwrap(),
    )
    .unwrap()
}

/// The client's ciphertext waiting to go out.
fn ciphertext(client: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut bytes).unwrap();
    }
    bytes
}

/// Gives the client the server's ciphertext and returns the plaintext it
/// decrypts.
fn decrypt(client: &mut rustls::ClientConnection, mut bytes: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::new();
    while !bytes.is_empty() {
        assert!(client.read_tls(&mut bytes).unwrap() > 0);
        client.process_new_packets().unwrap();
        if let Err(e) = client.reader().read_to_end(&mut plaintext) {
            assert_eq!(e.kind(), ErrorKind::WouldBlock);
        }
    }
    plaintext
}

/// Feeds `bytes` to the server in pieces of 1 to 64 bytes drawn from
/// `cuts`, so record and message boundaries fall anywhere.
fn push_cut<L>(server: &mut Harness<L>, bytes: &[u8], cuts: &SeededEntropy)
where
    L: fictionet::stdlib::layer::Layer<Lower = fictionet::stdlib::layer::ByteStream>,
    L::Error: std::fmt::Debug,
{
    let mut at = 0;
    while at < bytes.len() {
        let end = (at + 1 + cuts.random_below(64) as usize).min(bytes.len());
        server.push(&bytes[at..end]).unwrap();
        at = end;
    }
}

/// Shakes hands through the stack in `server`, the client's bytes cut by
/// `cuts`.
fn handshake(
    server: &mut Harness<Https>,
    client: &mut rustls::ClientConnection,
    cuts: &SeededEntropy,
) {
    for _ in 0..32 {
        push_cut(server, &ciphertext(client), cuts);
        decrypt(client, &server.take_output());
        if !client.is_handshaking() && !server.layer().lower().is_handshaking() {
            return;
        }
    }
    panic!("the handshake did not settle");
}

/// The status line, headers and body of one response.
fn split_response(response: &[u8]) -> (&[u8], &[u8]) {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a whole head");
    (&response[..end], &response[end + 4..])
}

#[test]
fn https_in_one_chain_means_the_same_however_its_input_is_cut() {
    block_on(lab(Seed::from_u64(31), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let mut answers = Vec::new();
        for seed in 0..8 {
            let cuts = SeededEntropy::new(Seed::from_u64(seed));
            let mut server = Harness::new(Seed::from_u64(32), https(config.clone(), handler()))
                .with_worker(Polling::new());
            let mut client = client(client_config.clone());
            handshake(&mut server, &mut client, &cuts);
            client
                .writer()
                .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")?;
            push_cut(&mut server, &ciphertext(&mut client), &cuts);
            let response = decrypt(&mut client, &server.take_output());
            let (head, body) = split_response(&response);
            assert!(head.starts_with(b"HTTP/1.1 200"), "the request is answered");
            assert_eq!(body, page(), "the whole body comes through TLS");
            answers.push(response);
        }
        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "every cut gets the same answer"
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_reset_after_tls_establishes_terminates_the_application_session() {
    use fictionet::stdlib::layer::{Admit, Layer, StreamEvent};
    use fictionet::stdlib::services::tls::{Handshake, Negotiation, Secure};

    block_on(lab(Seed::from_u64(40), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let secure = Secure::new(tls::TlsLayer::new(config), |_| {
            Some(stack::Session::new(
                Http1::new(handler()),
                StreamLimits::default(),
                fcx.now(),
            ))
        });
        let mut server = Harness::new(Seed::from_u64(41), secure).with_worker(Polling::new());
        let mut client = client(client_config(&fcx, &ca, &[b"http/1.1"]));
        for _ in 0..32 {
            server.push(&ciphertext(&mut client))?;
            decrypt(&mut client, &server.take_output());
            if !client.is_handshaking() && server.layer().upper().is_some() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(matches!(
            server.layer().tls().handshake(),
            Handshake::Established { .. }
        ));
        assert!(!server.layer().upper().unwrap().is_terminal());

        assert!(matches!(
            server.driver().deliver(StreamEvent::Reset)?,
            Admit::Taken
        ));
        server.settle()?;

        assert_eq!(server.layer().tls().handshake(), Handshake::Failed);
        assert!(
            server.layer().upper().unwrap().is_terminal(),
            "the application session must receive the peer reset through TLS"
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn https_in_one_chain_loses_nothing_when_its_writes_are_held_back() {
    block_on(lab(Seed::from_u64(33), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let cuts = SeededEntropy::new(Seed::from_u64(34));
        let mut server = Harness::new(Seed::from_u64(35), https(config, handler()))
            .with_worker(Polling::new());
        let mut client = client(client_config);
        handshake(&mut server, &mut client, &cuts);
        // Two pipelined requests while the transport takes nothing.
        server.withhold();
        client.writer().write_all(
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\nGET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        )?;
        server.push(&ciphertext(&mut client))?;
        assert!(server.output().is_empty(), "nothing goes out while held back");
        // A few bytes at a time, then everything.
        let mut wire = Vec::new();
        for _ in 0..64 {
            server.allow(1 + cuts.random_below(700) as usize)?;
            wire.extend(server.take_output());
        }
        server.allow_all()?;
        wire.extend(server.take_output());
        let plaintext = decrypt(&mut client, &wire);
        let (head, rest) = split_response(&plaintext);
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let (first, second) = rest.split_at(page().len());
        assert_eq!(first, page(), "the first answer is whole and first");
        let (head, body) = split_response(second);
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert_eq!(body, page(), "the second answer follows it whole");
        Ok(())
    }))
    .unwrap();
}

/// A CONNECT inside TLS replaces HTTP, not TLS: the client's first tunnel
/// bytes come in the same record as its request, the server writes
/// nothing out until long after, and every byte still comes back once, in
/// order, after the answer.
#[test]
fn a_connect_inside_tls_hands_its_bytes_on_under_backpressure() {
    block_on(lab(Seed::from_u64(36), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let cuts = SeededEntropy::new(Seed::from_u64(37));
        let mut server = Harness::new(Seed::from_u64(38), https(config, handler()))
            .with_worker(Polling::in_world(fcx.clone()));
        let mut client = client(client_config);
        handshake(&mut server, &mut client, &cuts);
        server.withhold();
        let payload: Vec<u8> = (0..(200u32 << 10)).map(|n| (n % 251) as u8).collect();
        let mut sent = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n".to_vec();
        sent.extend_from_slice(&payload[..1000]);
        client.writer().write_all(&sent)?;
        let first = ciphertext(&mut client);
        server.push(&first)?;
        for piece in payload[1000..].chunks(16 << 10) {
            client.writer().write_all(piece)?;
            server.push(&ciphertext(&mut client))?;
        }
        assert!(
            server.output().is_empty(),
            "nothing goes out while held back"
        );
        assert!(
            server.unread() > 0,
            "the stack stops taking input it has no room for"
        );
        let mut wire = Vec::new();
        for _ in 0..256 {
            server.allow(1 + cuts.random_below(5000) as usize)?;
            wire.extend(server.take_output());
        }
        server.allow_all()?;
        wire.extend(server.take_output());
        let plaintext = decrypt(&mut client, &wire);
        let answer = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(&plaintext[..answer.len()], answer, "the answer comes first");
        assert!(
            plaintext[answer.len()..] == payload[..],
            "every tunnel byte comes back once, in order"
        );
        Ok(())
    }))
    .unwrap();
}

// ---------------------------------------------------------------------------
// Live, over TCP in a world.

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 2, 1);

fn two_machines(fcx: &Cx) -> (tcp::Endpoint, tcp::Endpoint) {
    let (a, b) = fictionet::pair();
    let (at, _au, _ai, _ao) = ip::split_protocols(fcx, a);
    let (bt, _bu, _bi, _bo) = ip::split_protocols(fcx, b);
    let client: IpAddr = Ipv4Addr::new(10, 9, 2, 2).into();
    (
        tcp::endpoint(fcx, at, SERVER.into()),
        tcp::endpoint(fcx, bt, client),
    )
}

/// Serves the composed stack on port 443 of `server`, each connection on
/// the stream runner, and reports how each run ended.
fn serve_https(
    fcx: &Cx,
    server: &tcp::Endpoint,
    config: Arc<ServerConfig>,
) -> mpsc::Receiver<Result<StreamEnd, String>> {
    let mut listener = server.listen(443).unwrap();
    let (ended, ends) = mpsc::channel();
    fcx.spawn(move |fcx| async move {
        loop {
            let conn = listener.accept(&fcx).await?;
            let info = ConnInfo::new(1, conn.local_addr(), conn.peer_addr());
            let (config, ended) = (config.clone(), ended.clone());
            fcx.spawn(move |fcx| async move {
                let limits = StreamLimits {
                    idle: None,
                    write_timeout: None,
                };
                let stack = https(config, handler());
                let end = stack::stream(
                    &fcx,
                    conn,
                    &info,
                    stack,
                    Budget::unlimited(),
                    limits,
                    |_| {},
                )
                .await
                .map_err(|e| format!("{e:?}"));
                let _ = ended.send(end);
                Ok(())
            });
        }
    });
    ends
}

/// Shakes hands as the client over `conn`.
async fn connect_tls(
    fcx: &Cx,
    conn: &mut tcp::TcpConnection,
    tls: &mut rustls::ClientConnection,
) -> fictionet::Result {
    let mut buf = vec![0u8; 16 << 10];
    while tls.is_handshaking() {
        conn.write_all(fcx, &ciphertext(tls)).await?;
        if !tls.is_handshaking() {
            break;
        }
        let n = conn.read(fcx, &mut buf).await?;
        assert!(n > 0, "the server closed during the handshake");
        decrypt(tls, &buf[..n]);
    }
    conn.write_all(fcx, &ciphertext(tls)).await?;
    Ok(())
}

#[test]
fn https_in_one_chain_answers_live_and_finishes_with_the_client() {
    fictionet_test_support::world::world(Duration::from_secs(30), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let (server, client_machine) = two_machines(&fcx);
        let ends = serve_https(&fcx, &server, config);
        let mut conn = client_machine
            .connect(&fcx, SocketAddr::new(SERVER.into(), 443))
            .await?;
        let mut tls = client(client_config(&fcx, &ca, &[b"http/1.1"]));
        connect_tls(&fcx, &mut conn, &mut tls).await?;
        tls.writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")?;
        conn.write_all(&fcx, &ciphertext(&mut tls)).await?;
        let mut plaintext = Vec::new();
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let n = conn.read(&fcx, &mut buf).await?;
            if n == 0 {
                break;
            }
            plaintext.extend(decrypt(&mut tls, &buf[..n]));
        }
        let (head, body) = split_response(&plaintext);
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert_eq!(body, page());
        let end = ends.recv().unwrap();
        assert_eq!(
            end,
            Ok(StreamEnd::Finished),
            "HTTP closed, then TLS, then TCP"
        );
        Ok(())
    });
}

/// Sends `data` through `tls` over `conn` while reading what comes back,
/// until `want` plaintext bytes came and everything went out. Reads
/// nothing for `quiet` first, so every buffer on the way can fill.
async fn exchange<C: Connection>(
    fcx: &Cx,
    conn: &mut C,
    tls: &mut rustls::ClientConnection,
    data: &[u8],
    want: usize,
    quiet: Duration,
) -> Result<Vec<u8>, ConnError> {
    let mut quiet = Some(Box::pin(fcx.sleep(quiet)));
    let mut unsent = data;
    let mut out: Vec<u8> = Vec::new();
    let mut written = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 16 << 10];
    std::future::poll_fn(|cx| {
        loop {
            if out.len() - written < (64 << 10) && !unsent.is_empty() {
                let n = tls
                    .writer()
                    .write(&unsent[..unsent.len().min(16 << 10)])
                    .unwrap();
                unsent = &unsent[n..];
                out.extend(ciphertext(tls));
                continue;
            }
            if written < out.len() {
                match conn.poll_write(fcx, cx, &out[written..]) {
                    Poll::Ready(Ok(n)) => {
                        written += n;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
            break;
        }
        if let Some(waiting) = &mut quiet {
            if waiting.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            quiet = None;
        }
        while got.len() < want {
            match conn.poll_read(fcx, cx, &mut buf) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ConnError::Closed)),
                Poll::Ready(Ok(n)) => got.extend(decrypt(tls, &buf[..n])),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if unsent.is_empty() && written == out.len() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok(got)
}

#[test]
fn a_connect_inside_tls_keeps_every_byte_live_while_its_client_reads_nothing() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let (server, client_machine) = two_machines(&fcx);
        let _ends = serve_https(&fcx, &server, config);
        let mut conn = client_machine
            .connect(&fcx, SocketAddr::new(SERVER.into(), 443))
            .await?;
        let mut tls = client(client_config(&fcx, &ca, &[b"http/1.1"]));
        connect_tls(&fcx, &mut conn, &mut tls).await?;
        let payload: Vec<u8> = (0..(512u32 << 10)).map(|n| (n % 251) as u8).collect();
        let mut sent = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n".to_vec();
        sent.extend_from_slice(&payload);
        let answer = b"HTTP/1.1 200 OK\r\n\r\n";
        let want = answer.len() + payload.len();
        let quiet = Duration::from_secs(2);
        let got = exchange(&fcx, &mut conn, &mut tls, &sent, want, quiet).await?;
        assert_eq!(&got[..answer.len()], answer, "the answer comes first");
        assert!(
            got[answer.len()..] == payload[..],
            "every tunnel byte comes back once, in order"
        );
        Ok(())
    });
}

/// A TLS connection whose user only writes, while its client sends far
/// more than the connection holds for a reader, still finishes its writes:
/// their completions do not wait behind the bytes nobody reads yet, and
/// those bytes are all there when it reads.
#[test]
fn a_tls_connection_that_only_writes_finishes_while_its_client_sends() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(39), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA")?;
            let config = server_config(&fcx, &ca, "example.test", &[]);
            let client_config = client_config(&fcx, &ca, &[]);
            let (server_side, mut client_side) = mem_pair();
            let from_server: Vec<u8> = (0..(256u32 << 10)).map(|n| (n % 241) as u8).collect();
            let from_client: Vec<u8> = (0..(256u32 << 10)).map(|n| (n % 239) as u8).collect();
            let (sent, expected) = (from_server.clone(), from_client.clone());
            let server = fcx.spawn(move |fcx| async move {
                let hello = tls::server(&fcx, server_side).await?;
                let mut conn = hello.finish(&fcx, config).await?;
                conn.write_all(&fcx, &sent).await?;
                let mut got = vec![0u8; expected.len()];
                let mut at = 0;
                while at < got.len() {
                    let n = conn.read(&fcx, &mut got[at..]).await?;
                    assert!(n > 0, "the client's bytes end early");
                    at += n;
                }
                assert!(
                    got == expected,
                    "every byte the client sent is read once, in order"
                );
                Ok(())
            });
            let mut tls = client(client_config);
            let mut buf = vec![0u8; 16 << 10];
            while tls.is_handshaking() {
                client_side.write_all(&fcx, &ciphertext(&mut tls)).await?;
                if !tls.is_handshaking() {
                    break;
                }
                let n = client_side.read(&fcx, &mut buf).await?;
                decrypt(&mut tls, &buf[..n]);
            }
            let got = exchange(
                &fcx,
                &mut client_side,
                &mut tls,
                &from_client,
                from_server.len(),
                Duration::ZERO,
            )
            .await?;
            assert!(got == from_server, "every byte the server wrote arrives");
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

#[test]
fn ip_tcp_tls_and_http_run_in_the_pure_packet_harness() {
    use fictionet::stdlib::layer::{
        Admit, ByteStream, Chunk, Env, Layer, StreamCommand, StreamEvent, Top,
    };
    use fictionet::stdlib::services::stack::Boxed;
    use std::convert::Infallible;
    use std::sync::Mutex;

    struct Client {
        tls: rustls::ClientConnection,
        response: Arc<Mutex<Vec<u8>>>,
    }
    impl Layer for Client {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = std::io::Error;
        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Self::Error> {
            if let StreamEvent::Data(bytes) = event {
                self.response
                    .lock()
                    .unwrap()
                    .extend(decrypt(&mut self.tls, &bytes));
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Self::Error> {
            match command {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            let bytes = ciphertext(&mut self.tls);
            (!bytes.is_empty()).then(|| StreamCommand::Write(Chunk::unpaid(bytes)))
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    block_on(lab(Seed::from_u64(31), |fcx| async move {
        let ca = Ca::new(&fcx, "Test CA")?;
        let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
        let client_config = client_config(&fcx, &ca, &[b"http/1.1"]);
        let received = Arc::new(Mutex::new(Vec::new()));
        let response = received.clone();
        crate::packet_composition::exchange(
            move || Boxed::new(https(config.clone(), handler())),
            move || {
                let mut tls = client(client_config.clone());
                tls.writer()
                    .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
                    .unwrap();
                Boxed::new(Client {
                    tls,
                    response: response.clone(),
                })
            },
            || received.lock().unwrap().ends_with(&page()),
        );
        let response = received.lock().unwrap();
        let (head, body) = split_response(&response);
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert_eq!(body, page());
        Ok(())
    }))
    .unwrap();
}
