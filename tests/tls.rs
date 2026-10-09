//! TLS: the world as a TLS server, with a rustls client over an in-memory
//! connection, all under the lab, with a real-time throughput test.

mod common;

use common::within;

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::prelude::*;
use fictionet::stdlib::ca::Ca;
use fictionet::stdlib::tls::{self, ServerConfig};
use fictionet::stdlib::{ConnError, Connection};
use fictionet::{Cx, Seed, block_on, lab};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{AlertDescription, ClientConfig, ClientConnection, RootCertStore};

// ---------------------------------------------------------------------------
// An in-memory connection pair.

const PIPE_CAPACITY: usize = 64 * 1024;

#[derive(Default)]
struct Pipe {
    buf: VecDeque<u8>,
    /// The writer shut down or was dropped.
    write_closed: bool,
    /// The reader was dropped.
    read_closed: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// One end of an in-memory byte stream, with a bounded buffer each way.
struct MemConn {
    rx: Arc<Mutex<Pipe>>,
    tx: Arc<Mutex<Pipe>>,
}

fn mem_pair() -> (MemConn, MemConn) {
    let a = Arc::new(Mutex::new(Pipe::default()));
    let b = Arc::new(Mutex::new(Pipe::default()));
    (
        MemConn {
            rx: a.clone(),
            tx: b.clone(),
        },
        MemConn { rx: b, tx: a },
    )
}

impl Connection for MemConn {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        let mut p = self.rx.lock().unwrap();
        if p.buf.is_empty() {
            if p.write_closed {
                return Poll::Ready(Ok(0));
            }
            p.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(p.buf.len());
        for (i, b) in p.buf.drain(..n).enumerate() {
            buf[i] = b;
        }
        if let Some(w) = p.writer.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        let mut p = self.tx.lock().unwrap();
        if p.read_closed {
            return Poll::Ready(Err(ConnError::Reset));
        }
        if p.write_closed {
            return Poll::Ready(Err(ConnError::Closed));
        }
        let room = PIPE_CAPACITY - p.buf.len();
        if room == 0 {
            p.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        p.buf.extend(&data[..n]);
        if let Some(w) = p.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_shutdown(&mut self, _fcx: &Cx, _cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        let mut p = self.tx.lock().unwrap();
        p.write_closed = true;
        if let Some(w) = p.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MemConn {
    fn drop(&mut self) {
        let mut p = self.tx.lock().unwrap();
        p.write_closed = true;
        if let Some(w) = p.reader.take() {
            w.wake();
        }
        drop(p);
        let mut p = self.rx.lock().unwrap();
        p.read_closed = true;
        if let Some(w) = p.writer.take() {
            w.wake();
        }
    }
}

// ---------------------------------------------------------------------------
// A rustls client over a connection.

struct Client {
    conn: MemConn,
    tls: ClientConnection,
}

#[derive(Debug)]
#[allow(dead_code)] // The fields show in failure messages.
enum ClientError {
    Conn(ConnError),
    Tls(rustls::Error),
    /// The connection ended without close_notify.
    Truncated,
}

impl From<ConnError> for ClientError {
    fn from(e: ConnError) -> Self {
        ClientError::Conn(e)
    }
}

impl Client {
    async fn connect(
        fcx: &Cx,
        conn: MemConn,
        config: Arc<ClientConfig>,
        name: &str,
    ) -> Result<Client, ClientError> {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let tls = tls::with_context(fcx, || ClientConnection::new(config, name)).unwrap();
        let mut c = Client { conn, tls };
        while c.tls.is_handshaking() {
            c.flush(fcx).await?;
            if !c.tls.is_handshaking() {
                break;
            }
            c.read_more(fcx).await?;
        }
        c.flush(fcx).await?;
        Ok(c)
    }

    async fn flush(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        while self.tls.wants_write() {
            let mut out = Vec::new();
            self.tls.write_tls(&mut out).unwrap();
            self.conn.write_all(fcx, &out).await?;
        }
        Ok(())
    }

    /// Reads one chunk from the connection and processes it.
    async fn read_more(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        let mut buf = vec![0; 16 * 1024];
        let n = self.conn.read(fcx, &mut buf).await?;
        if n == 0 && self.tls.is_handshaking() {
            return Err(ClientError::Truncated);
        }
        let mut data = &buf[..n];
        loop {
            self.tls.read_tls(&mut data).unwrap();
            let r = tls::with_context(fcx, || self.tls.process_new_packets());
            // Send any alert or reply before reporting.
            let _ = self.flush(fcx).await;
            r.map_err(ClientError::Tls)?;
            if data.is_empty() {
                return Ok(());
            }
        }
    }

    /// Reads application data. `Ok(0)` is the server's close_notify.
    async fn read(&mut self, fcx: &Cx, buf: &mut [u8]) -> Result<usize, ClientError> {
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => self.read_more(fcx).await?,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    return Err(ClientError::Truncated);
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    async fn write_all(&mut self, fcx: &Cx, mut data: &[u8]) -> Result<(), ClientError> {
        while !data.is_empty() {
            let n = self
                .tls
                .writer()
                .write(&data[..data.len().min(16 * 1024)])
                .unwrap();
            data = &data[n..];
            self.flush(fcx).await?;
        }
        Ok(())
    }

    async fn close(&mut self, fcx: &Cx) -> Result<(), ClientError> {
        self.tls.send_close_notify();
        self.flush(fcx).await?;
        self.conn.shutdown(fcx).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Certificates.

fn date(y: i32, m: u8, d: u8) -> SystemTime {
    let secs = fictionet::stdlib::x509::Time::Generalized(format!("{y:04}{m:02}{d:02}000000Z"))
        .unix()
        .unwrap();
    UNIX_EPOCH + Duration::from_secs(secs as u64)
}

fn roots(ca: &Ca) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    roots
}

fn issue(
    fcx: &Cx,
    ca: &Ca,
    names: &[&str],
    from: i32,
    to: i32,
    client: bool,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    use fictionet::stdlib::{
        codec::Wire,
        x509::{self, ExtensionValue},
    };
    let time = |year| {
        x509::Time::from_unix(
            date(year, 1, 1)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
        .unwrap()
    };
    let mut leaf = ca
        .issue(
            fcx,
            names,
            x509::Validity {
                not_before: time(from),
                not_after: time(to),
            },
        )
        .unwrap();
    if client {
        let mut tbs = x509::Certificate::parse(&leaf.chain[0]).unwrap().tbs;
        tbs.extensions
            .retain(|e| e.oid.as_bytes() != x509::oid::EXTENDED_KEY_USAGE);
        let oid = fictionet::stdlib::asn1::Oid::from_contents(x509::oid::CLIENT_AUTH).unwrap();
        tbs.extensions.push(
            x509::ExtendedKeyUsage(vec![oid])
                .to_extension(false)
                .unwrap(),
        );
        leaf.chain[0] = ca.sign(tbs).unwrap().to_bytes().unwrap().into();
    }
    (leaf.chain, leaf.key)
}

fn provider() -> rustls::crypto::CryptoProvider {
    tls::crypto_provider()
}

/// A server config for `name`, issued by `ca`, offering `alpn`.
fn server_config(fcx: &Cx, ca: &Ca, name: &str, alpn: &[&[u8]]) -> Arc<ServerConfig> {
    let (chain, key) = issue(fcx, ca, &[name], 2000, 2100, false);
    let mut config = tls::config_builder(fcx, date(2030, 1, 1))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A clock for the client, fixed at one moment.
#[derive(Debug)]
struct FixedTime(SystemTime);

impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            self.0.duration_since(UNIX_EPOCH).unwrap(),
        ))
    }
}

fn client_config(fcx: &Cx, ca: &Ca, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    fictionet::stdlib::sandbox::client_config(
        fcx,
        date(2030, 1, 1),
        Some(&Arc::new(roots(ca))),
        alpn,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests.

#[test]
fn handshake_with_sni_and_alpn() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let config = server_config(&fcx, &ca, "example.test", &[b"h2", b"http/1.1"]);
            let client_config = client_config(&fcx, &ca, &[b"h2", b"http/1.1"]);
            let (server_side, client_side) = mem_pair();

            let server = fcx.spawn(move |fcx| async move {
                let hello = tls::server(&fcx, server_side).await?;
                assert_eq!(hello.server_name(), Some("example.test"));
                assert_eq!(hello.alpn(), vec![&b"h2"[..], &b"http/1.1"[..]]);
                let mut conn = hello.finish(&fcx, config).await?;
                assert_eq!(conn.alpn(), Some(&b"h2"[..]));
                let mut buf = [0; 4];
                let mut got = 0;
                while got < 4 {
                    got += conn.read(&fcx, &mut buf[got..]).await?;
                }
                assert_eq!(&buf, b"ping");
                conn.write_all(&fcx, b"pong").await?;
                conn.shutdown(&fcx).await?;
                Ok(())
            });

            let mut client = Client::connect(&fcx, client_side, client_config, "example.test")
                .await
                .unwrap();
            assert_eq!(client.tls.alpn_protocol(), Some(&b"h2"[..]));
            client.write_all(&fcx, b"ping").await.unwrap();
            let mut buf = [0; 4];
            let mut got = 0;
            while got < 4 {
                got += client.read(&fcx, &mut buf[got..]).await.unwrap();
            }
            assert_eq!(&buf, b"pong");
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

#[test]
fn the_world_picks_a_config_per_handshake() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let a = server_config(&fcx, &ca, "a.test", &[]);
            let b = server_config(&fcx, &ca, "b.test", &[]);
            let client_config = client_config(&fcx, &ca, &[]);

            for name in ["a.test", "b.test", "a.test"] {
                let (server_side, client_side) = mem_pair();
                let (a, b) = (a.clone(), b.clone());
                let server = fcx.spawn(move |fcx| async move {
                    let hello = tls::server(&fcx, server_side).await?;
                    let config = if hello.server_name() == Some("a.test") {
                        a
                    } else {
                        b
                    };
                    let mut conn = hello.finish(&fcx, config).await?;
                    conn.write_all(&fcx, b"hi").await?;
                    conn.shutdown(&fcx).await?;
                    Ok(())
                });
                // The client checks the certificate matches the name, so the
                // handshake succeeds only if the server picked the right one.
                let mut client = Client::connect(&fcx, client_side, client_config.clone(), name)
                    .await
                    .unwrap();
                let mut buf = [0; 2];
                let mut got = 0;
                while got < 2 {
                    got += client.read(&fcx, &mut buf[got..]).await.unwrap();
                }
                assert_eq!(&buf, b"hi");
                server.join(&fcx).await?;
            }

            // The wrong config fails the handshake on the client's side.
            let (server_side, client_side) = mem_pair();
            let a2 = a.clone();
            let server = fcx.spawn(move |fcx| async move {
                let hello = tls::server(&fcx, server_side).await?;
                assert_eq!(hello.server_name(), Some("b.test"));
                assert_eq!(hello.finish(&fcx, a2).await.err(), Some(ConnError::Broken));
                Ok(())
            });
            let err = Client::connect(&fcx, client_side, client_config, "b.test")
                .await
                .err()
                .unwrap();
            assert!(
                matches!(err, ClientError::Tls(rustls::Error::InvalidCertificate(_))),
                "{err:?}"
            );
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

#[test]
fn reject_sends_unrecognized_name() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let client_config = client_config(&fcx, &ca, &[]);
            let (server_side, client_side) = mem_pair();
            let server = fcx.spawn(move |fcx| async move {
                let hello = tls::server(&fcx, server_side).await?;
                assert_eq!(hello.server_name(), Some("unknown.test"));
                hello.reject(&fcx).await?;
                Ok(())
            });
            let err = Client::connect(&fcx, client_side, client_config, "unknown.test")
                .await
                .err()
                .unwrap();
            assert!(
                matches!(
                    err,
                    ClientError::Tls(rustls::Error::AlertReceived(
                        AlertDescription::UnrecognisedName
                    ))
                ),
                "{err:?}"
            );
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

#[test]
fn a_dropped_hello_closes_with_no_alert() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let client_config = client_config(&fcx, &ca, &[]);
            let (server_side, client_side) = mem_pair();
            let server = fcx.spawn(move |fcx| async move {
                drop(tls::server(&fcx, server_side).await?);
                Ok(())
            });
            let err = Client::connect(&fcx, client_side, client_config, "x.test")
                .await
                .err()
                .unwrap();
            // The client reads the end of the stream, not an alert.
            assert!(matches!(err, ClientError::Truncated), "{err:?}");
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

#[test]
fn a_first_message_that_is_not_a_hello_is_broken() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (server_side, mut client_side) = mem_pair();
            let server = fcx.spawn(move |fcx| async move {
                assert_eq!(
                    tls::server(&fcx, server_side).await.err(),
                    Some(ConnError::Broken)
                );
                Ok(())
            });
            client_side
                .write_all(&fcx, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await?;
            server.join(&fcx).await?;
            // Nothing was sent back.
            let mut buf = [0; 16];
            assert_eq!(client_side.read(&fcx, &mut buf).await?, 0);

            // A client that closes before its hello is complete.
            let (server_side, mut client_side) = mem_pair();
            let server = fcx.spawn(move |fcx| async move {
                assert_eq!(
                    tls::server(&fcx, server_side).await.err(),
                    Some(ConnError::Broken)
                );
                Ok(())
            });
            client_side.write_all(&fcx, &[22, 3, 1, 0, 200, 1]).await?;
            client_side.shutdown(&fcx).await?;
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

/// The server checks the client's certificate against its config's clock:
/// `start` plus the time since the run started.
fn client_auth_at(start: SystemTime) -> (Result<(), ConnError>, Result<(), String>) {
    within(Duration::from_secs(20), move || {
        let result = Arc::new(Mutex::new(None));
        let r = result.clone();
        let outcome = Arc::new(Mutex::new(None));
        let o = outcome.clone();
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            // Valid only in 2019.
            let (client_chain, client_key) = issue(&fcx, &ca, &["client.test"], 2019, 2020, true);
            let (chain, key) = issue(&fcx, &ca, &["example.test"], 2000, 2100, false);
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(&ca)),
                Arc::new(provider()),
            )
            .build()
            .unwrap();
            let config = Arc::new(
                tls::config_builder(&fcx, start)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_client_cert_verifier(verifier)
                    .with_single_cert(chain, key)
                    .unwrap(),
            );
            // The client's clock says mid-2019, so it accepts the server.
            let client_config = Arc::new(
                ClientConfig::builder_with_details(
                    Arc::new(provider()),
                    Arc::new(FixedTime(date(2019, 6, 1))),
                )
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots(&ca))
                .with_client_auth_cert(client_chain, client_key)
                .unwrap(),
            );

            let (server_side, client_side) = mem_pair();
            let server = fcx.spawn(move |fcx| async move {
                let hello = tls::server(&fcx, server_side).await?;
                let finished = hello.finish(&fcx, config).await;
                let ok = finished.is_ok();
                if let Ok(mut conn) = finished {
                    conn.write_all(&fcx, b"ok").await?;
                }
                *r.lock().unwrap() = Some(ok);
                Ok(())
            });
            let client = async {
                let mut c = Client::connect(&fcx, client_side, client_config, "example.test")
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                // In TLS 1.3 the client finishes first; the server's verdict
                // arrives with the first read.
                let mut buf = [0; 2];
                let mut got = 0;
                while got < 2 {
                    got += c
                        .read(&fcx, &mut buf[got..])
                        .await
                        .map_err(|e| format!("{e:?}"))?;
                }
                Ok::<_, String>(())
            };
            let client_result = client.await;
            server.join(&fcx).await?;
            let server_ok = result.lock().unwrap().unwrap();
            *o.lock().unwrap() = Some((
                if server_ok {
                    Ok(())
                } else {
                    Err(ConnError::Broken)
                },
                client_result,
            ));
            Ok(())
        }))
        .unwrap();
        outcome.lock().unwrap().take().unwrap()
    })
}

#[test]
fn certificates_are_checked_against_the_worlds_date() {
    let (server, client) = client_auth_at(date(2019, 6, 1));
    assert_eq!(server, Ok(()));
    assert_eq!(client, Ok(()));

    let (server, client) = client_auth_at(date(2030, 6, 1));
    assert_eq!(server, Err(ConnError::Broken));
    let client = client.unwrap_err();
    assert!(client.contains("CertificateExpired"), "{client}");
}

#[test]
fn close_notify_both_ways() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let config = server_config(&fcx, &ca, "example.test", &[]);
            let client_config = client_config(&fcx, &ca, &[]);
            let (server_side, client_side) = mem_pair();

            let server = fcx.spawn(move |fcx| async move {
                let mut conn = tls::server(&fcx, server_side)
                    .await?
                    .finish(&fcx, config)
                    .await?;
                conn.write_all(&fcx, b"bye").await?;
                conn.shutdown(&fcx).await?;
                // Writing after shutdown fails.
                assert!(conn.write(&fcx, b"more").await.is_err());
                // Reading still works, until the client's close_notify.
                let mut got = Vec::new();
                let mut buf = [0; 64];
                loop {
                    let n = conn.read(&fcx, &mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                assert_eq!(got, b"last words");
                Ok(())
            });

            let mut client = Client::connect(&fcx, client_side, client_config, "example.test")
                .await
                .unwrap();
            let mut got = Vec::new();
            let mut buf = [0; 64];
            loop {
                // Ok(0) from rustls means a real close_notify; a bare end of
                // stream would be `Truncated`.
                let n = client.read(&fcx, &mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, b"bye");
            client.write_all(&fcx, b"last words").await.unwrap();
            client.close(&fcx).await.unwrap();
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

fn pattern(i: usize) -> u8 {
    (i * 31 + i / 997) as u8
}

#[test]
fn five_megabytes_each_way() {
    const SIZE: usize = 5 * 1024 * 1024;
    within(Duration::from_secs(120), || {
        block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let ca = Ca::new(&fcx, "Test CA").unwrap();
                let config = server_config(&fcx, &ca, "example.test", &[]);
                let client_config = client_config(&fcx, &ca, &[]);
                let (server_side, client_side) = mem_pair();
                let data: Arc<Vec<u8>> = Arc::new((0..SIZE).map(pattern).collect());

                let d = data.clone();
                let server = fcx.spawn(move |fcx| async move {
                    let mut conn = tls::server(&fcx, server_side)
                        .await?
                        .finish(&fcx, config)
                        .await?;
                    // Odd-sized writes, so records do not line up with them.
                    for chunk in d.chunks(70_001) {
                        conn.write_all(&fcx, chunk).await?;
                    }
                    let mut received = 0usize;
                    let mut buf = vec![0; 50_000];
                    loop {
                        let n = conn.read(&fcx, &mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        for (i, b) in buf[..n].iter().enumerate() {
                            assert_eq!(*b, pattern(received + i));
                        }
                        received += n;
                    }
                    assert_eq!(received, SIZE);
                    conn.shutdown(&fcx).await?;
                    Ok(())
                });

                let mut client = Client::connect(&fcx, client_side, client_config, "example.test")
                    .await
                    .unwrap();
                let mut received = Vec::with_capacity(SIZE);
                let mut buf = vec![0; 40_000];
                while received.len() < SIZE {
                    let n = client.read(&fcx, &mut buf).await.unwrap();
                    assert!(n > 0);
                    received.extend_from_slice(&buf[..n]);
                }
                assert!(received == *data);
                client.write_all(&fcx, &data).await.unwrap();
                client.close(&fcx).await.unwrap();
                let n = client.read(&fcx, &mut buf).await.unwrap();
                assert_eq!(n, 0);
                Ok(server.join(&fcx).await?)
            },
        ))
    })
    .unwrap();
}

#[test]
fn tls12_clients_work_too() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let config = server_config(&fcx, &ca, "example.test", &[b"http/1.1"]);
            // The config draws random values through Fictionet, not ring.
            assert_eq!(
                format!("{:?}", config.crypto_provider().secure_random),
                "CxRandom"
            );
            let mut client_config = ClientConfig::builder_with_details(
                Arc::new(provider()),
                Arc::new(FixedTime(date(2030, 1, 1))),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots(&ca))
            .with_no_client_auth();
            client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let (server_side, client_side) = mem_pair();
            let server = fcx.spawn(move |fcx| async move {
                let mut conn = tls::server(&fcx, server_side)
                    .await?
                    .finish(&fcx, config)
                    .await?;
                assert_eq!(conn.alpn(), Some(&b"http/1.1"[..]));
                conn.write_all(&fcx, b"twelve").await?;
                conn.shutdown(&fcx).await?;
                Ok(())
            });
            let mut client =
                Client::connect(&fcx, client_side, Arc::new(client_config), "example.test")
                    .await
                    .unwrap();
            assert_eq!(
                client.tls.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2)
            );
            let mut got = Vec::new();
            let mut buf = [0; 64];
            loop {
                let n = client.read(&fcx, &mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, b"twelve");
            Ok(server.join(&fcx).await?)
        }))
    })
    .unwrap();
}

/// A cancel comes before plaintext the TLS connection already decrypted,
/// and a handshake cut by a cancel says `Cancelled`, not a broken
/// connection.
#[test]
fn a_cancel_comes_first_and_is_never_a_broken_handshake() {
    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let ca = Ca::new(&fcx, "Test CA").unwrap();
            let config = server_config(&fcx, &ca, "example.test", &[]);
            let client_config = client_config(&fcx, &ca, &[]);
            let (server_side, client_side) = mem_pair();
            let (tx, rx) = mpsc::channel();
            let server = fcx.spawn(move |fcx| async move {
                let _ = fcx
                    .region(|region_fcx| async move {
                        let mut conn = tls::server(&region_fcx, server_side)
                            .await?
                            .finish(&region_fcx, config)
                            .await?;
                        // One byte now: rustls holds the rest, decrypted.
                        let mut one = [0; 1];
                        assert_eq!(conn.read(&region_fcx, &mut one).await?, 1);
                        region_fcx.cancel();
                        let _ = tx.send(conn.read(&region_fcx, &mut one).await);
                        Ok(())
                    })
                    .await;
                Ok(())
            });
            let mut client = Client::connect(&fcx, client_side, client_config, "example.test")
                .await
                .unwrap();
            client.write_all(&fcx, b"hello").await.unwrap();
            server.join(&fcx).await?;
            assert_eq!(rx.recv().unwrap(), Err(ConnError::Cancelled));
            Ok(())
        }))
    })
    .unwrap();

    within(Duration::from_secs(20), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (server_side, _client_side) = mem_pair();
            fcx.region(|region_fcx| async move {
                let stopper = region_fcx.clone();
                region_fcx.spawn(move |fcx| async move {
                    fcx.sleep(Duration::from_millis(20)).await?;
                    stopper.cancel();
                    Ok(())
                });
                // The client never says hello.
                let res = tls::server_detailed(&region_fcx, server_side).await;
                assert!(
                    matches!(res, Err(tls::HandshakeError::Cancelled)),
                    "{:?}",
                    res.err()
                );
                Ok(())
            })
            .await
        }))
    })
    .unwrap();
}

#[test]
fn sandbox_client_returns_invalid_server_name() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_, conn) = mem_pair();
        let roots = Arc::new(RootCertStore::empty());
        let result = fictionet::stdlib::sandbox::TlsClient::new(
            &fcx,
            conn,
            &roots,
            "invalid name",
            &[],
            date(2030, 1, 1),
        );
        assert!(result.is_err());
        Ok(())
    }))
    .unwrap();
}
