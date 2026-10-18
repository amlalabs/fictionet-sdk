//! Dropped TLS writes never credit old bytes to a later write.

use fictionet_test_support::certs;

use std::future::{Future, poll_fn};
use std::io::{ErrorKind, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::SystemTime;

use fictionet::stdlib::network::{Connection, ConnectionExt, tcp};
use fictionet::stdlib::services::tls::{self, ServerConfig};
use fictionet::time::ms;
use fictionet::{Cx, Interface, InterfaceExt, Result, RunOptions};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

fn configs(fcx: &Cx) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let (ca, leaf) = certs::issue(fcx, "Test CA", &["secret.test"]).unwrap();
    let server = tls::config_builder(fcx, SystemTime::now())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// A TLS client that finishes the handshake, then reads nothing until
/// `drain` receives a message, then reads and discards everything.
async fn client<C: Connection>(
    fcx: &Cx,
    mut conn: C,
    config: Arc<ClientConfig>,
    mut drain: fictionet::End,
    received: Arc<AtomicBool>,
) -> Result {
    let mut tls = ClientConnection::new(config, ServerName::try_from("secret.test").unwrap())?;
    let mut buf = vec![0u8; 16 << 10];
    loop {
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)?;
            conn.write_all(fcx, &out).await?;
        }
        if !tls.is_handshaking() {
            break;
        }
        let n = conn.read(fcx, &mut buf).await?;
        tls.read_tls(&mut &buf[..n])?;
        tls.process_new_packets()?;
    }
    drain.recv(fcx).await?;
    let mut sink = Vec::new();
    loop {
        let n = conn.read(fcx, &mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            tls.read_tls(&mut rest)?;
            tls.process_new_packets()?;
            let _ = tls
                .reader()
                .read_to_end(&mut sink)
                .map_err(|e| assert_eq!(e.kind(), ErrorKind::WouldBlock));
            if sink.ends_with(b"hi") {
                assert!(sink[..sink.len() - 2].iter().all(|b| *b == b'A'));
                received.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }
    }
}

fn scenario(use_write_all: bool) {
    scenario_mode(if use_write_all { 1 } else { 0 })
}

fn scenario_mode(mode: u8) {
    let r = fictionet::block_on(fictionet::lab(
        RunOptions::new(fictionet::Seed::from_u64(3)),
        move |fcx| async move {
            let (server_cfg, client_cfg) = configs(&fcx);
            let (a, b) = fictionet::pair();
            let c_ep = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
            let s_ep = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
            let mut listener = s_ep.listen(443)?;
            let (mut drain, d) = fictionet::pair();
            let received = Arc::new(AtomicBool::new(false));
            let got = received.clone();
            let peer = fcx.spawn(move |fcx| async move {
                let conn = c_ep.connect(&fcx, "10.0.0.1:443".parse()?).await?;
                client(&fcx, conn, client_cfg, d, got).await
            });
            let conn = listener.accept(&fcx).await?;
            let mut conn = tls::server(&fcx, conn)
                .await?
                .finish(&fcx, server_cfg)
                .await?;
            // Write until a write is pending, then drop that write's future,
            // as a timeout or select! would.
            let chunk = vec![b'A'; 16 << 10];
            if mode == 2 {
                // Control: retry the same bytes, never drop a pending write.
                let big = vec![b'A'; 600 << 10];
                let w = conn.write_all(&fcx, &big);
                let mut d2 = drain;
                fcx.spawn(move |fcx| async move {
                    fcx.sleep(ms(200)).await?;
                    d2.send(fictionet::Packet(Vec::new()));
                    Ok(())
                });
                w.await?;
                conn.write_all(&fcx, b"hi").await?;
                fcx.race(Some(fcx.now() + ms(500)), peer.join(&fcx))
                    .await??;
                eprintln!("control: wrote 600 KiB + 2 without dropping a write");
                assert!(received.load(Ordering::SeqCst));
                fcx.cancel();
                return Ok(());
            }
            let mut total = 0usize;
            loop {
                let mut fut = Box::pin(conn.write(&fcx, &chunk));
                let polled = poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx))).await;
                match polled {
                    Poll::Ready(r) => total += r?,
                    Poll::Pending => break, // dropped here
                }
                fcx.idle().await?;
            }
            eprintln!(
                "wrote {total} bytes, then dropped a pending write of {}",
                chunk.len()
            );
            drain.send(fictionet::Packet(Vec::new()));
            if mode == 1 {
                conn.write_all(&fcx, b"hi").await?;
                eprintln!("write_all of 2 bytes returned");
            } else {
                let n = conn.write(&fcx, b"hi").await?;
                eprintln!("write(b\"hi\") (2 bytes) returned Ok({n})");
                assert_eq!(n, 2);
            }
            fcx.race(Some(fcx.now() + ms(500)), peer.join(&fcx))
                .await??;
            assert!(
                received.load(Ordering::SeqCst),
                "the peer received the new bytes"
            );
            fcx.cancel();
            Ok(())
        },
    ));
    r.unwrap();
}

#[test]
fn a_new_write_reports_only_its_own_bytes() {
    scenario(false);
}

#[test]
fn write_all_accepts_new_bytes_after_a_dropped_write() {
    scenario(true);
}

#[test]
fn control_no_dropped_write() {
    scenario_mode(2);
}

mod contract {
    use super::*;
    use fictionet::stdlib::{network::ConnError, world::sandbox::TlsClient};
    use std::io::Write;
    use std::sync::Mutex;
    use std::task::{Context, Waker};
    use std::time::{Duration, UNIX_EPOCH};

    struct Peer {
        tls: rustls::Connection,
        budget: usize,
        terminal: Option<Result<usize, ConnError>>,
        received: Vec<u8>,
        corrupt: bool,
    }

    struct Transport(Arc<Mutex<Peer>>);

    impl Connection for Transport {
        fn poll_read(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize, ConnError>> {
            let mut peer = self.0.lock().unwrap();
            if !peer.tls.wants_write() {
                return Poll::Pending;
            }
            let n = peer.tls.write_tls(&mut &mut *buf).unwrap();
            if peer.corrupt {
                buf[n - 1] ^= 1;
            }
            Poll::Ready(Ok(n))
        }

        fn poll_write(
            &mut self,
            fcx: &Cx,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<Result<usize, ConnError>> {
            let mut peer = self.0.lock().unwrap();
            if let Some(result) = peer.terminal.take() {
                return Poll::Ready(result);
            }
            if peer.budget == 0 {
                return Poll::Pending;
            }
            let limit = data.len().min(peer.budget);
            let n = peer.tls.read_tls(&mut &data[..limit]).unwrap();
            peer.budget -= n;
            tls::with_context(fcx, || peer.tls.process_new_packets()).unwrap();
            let Peer { tls, received, .. } = &mut *peer;
            let result = tls.reader().read_to_end(received);
            assert_eq!(result.unwrap_err().kind(), ErrorKind::WouldBlock);
            Poll::Ready(Ok(n))
        }

        fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn connected(fcx: &Cx, server: bool) -> (Box<dyn Connection>, Arc<Mutex<Peer>>) {
        let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let (ca, leaf) = certs::issue(fcx, "Test CA", &["secret.test"]).unwrap();
        let config = leaf.server_config(fcx, start).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der()).unwrap();
        let client_config = fictionet::stdlib::world::sandbox::client_config(
            fcx,
            start,
            Some(&Arc::new(roots)),
            &[],
        )
        .unwrap();
        let session = if server {
            let client = tls::with_context(fcx, || {
                ClientConnection::new(
                    client_config.clone(),
                    ServerName::try_from("secret.test").unwrap(),
                )
            })
            .unwrap();
            rustls::Connection::Client(client)
        } else {
            rustls::Connection::Server(
                tls::with_context(fcx, || rustls::ServerConnection::new(config.clone())).unwrap(),
            )
        };
        let peer = Arc::new(Mutex::new(Peer {
            tls: session,
            budget: usize::MAX,
            terminal: None,
            received: Vec::new(),
            corrupt: false,
        }));
        let transport = Transport(peer.clone());
        let conn: Box<dyn Connection> = if server {
            let conn = tls::server(fcx, transport)
                .await
                .unwrap()
                .finish(fcx, config)
                .await
                .unwrap();
            assert!(!conn.inner().0.lock().unwrap().tls.is_handshaking());
            Box::new(conn)
        } else {
            let session = tls::with_context(fcx, || {
                ClientConnection::new(client_config, ServerName::try_from("secret.test").unwrap())
            })
            .unwrap();
            let mut conn = TlsClient::with(transport, session);
            conn.handshake(fcx).await.unwrap();
            assert!(!conn.tls.is_handshaking());
            assert!(!conn.conn.0.lock().unwrap().tls.is_handshaking());
            Box::new(conn)
        };
        (conn, peer)
    }

    fn write_waits_for_complete_ciphertext(server: bool) {
        fictionet::block_on(fictionet::lab(
            RunOptions::new(fictionet::Seed::from_u64(4)),
            move |fcx| async move {
                let (mut client, peer) = connected(&fcx, server).await;
                let data = b"hello";
                {
                    let mut cx = Context::from_waker(Waker::noop());
                    peer.lock().unwrap().budget = 0;
                    assert!(client.poll_write(&fcx, &mut cx, data).is_pending());
                    let mut complete = false;
                    for _ in 0..128 {
                        assert!(peer.lock().unwrap().received.is_empty());
                        peer.lock().unwrap().budget = 1;
                        match client.poll_write(&fcx, &mut cx, data) {
                            Poll::Pending => {
                                assert!(client.poll_write(&fcx, &mut cx, data).is_pending());
                            }
                            Poll::Ready(result) => {
                                assert_eq!(result, Ok(data.len()));
                                assert_eq!(peer.lock().unwrap().received, data);
                                complete = true;
                                break;
                            }
                        }
                    }
                    assert!(complete, "ciphertext did not drain");
                }
                peer.lock().unwrap().budget = usize::MAX;
                client.write_all(&fcx, b"!").await?;
                assert_eq!(peer.lock().unwrap().received, b"hello!");
                Ok(())
            },
        ))
        .unwrap();
    }

    fn dropped_write_credits_only_matching_retries(server: bool) {
        fictionet::block_on(fictionet::lab(
            RunOptions::new(fictionet::Seed::from_u64(5)),
            move |fcx| async move {
                let original = b"original";
                let retries: &[&[u8]] = &[original, b"original plus", b"orig", b"other", b""];
                for flush_by_read in [false, true] {
                    for &retry in retries {
                        let (mut client, peer) = connected(&fcx, server).await;
                        {
                            let mut cx = Context::from_waker(Waker::noop());
                            peer.lock().unwrap().budget = 1;
                            {
                                let mut write = std::pin::pin!(client.write_all(&fcx, original));
                                assert!(write.as_mut().poll(&mut cx).is_pending());
                            }
                            assert!(peer.lock().unwrap().received.is_empty());
                            assert!(client.poll_write(&fcx, &mut cx, retry).is_pending());
                            peer.lock().unwrap().budget = usize::MAX;
                            if flush_by_read {
                                assert!(client.poll_read(&fcx, &mut cx, &mut [0]).is_pending());
                                assert_eq!(peer.lock().unwrap().received, original);
                            }
                        }
                        let n = client.write(&fcx, retry).await?;
                        let same = retry.starts_with(original);
                        assert_eq!(n, if same { original.len() } else { retry.len() });
                        client.write_all(&fcx, &retry[n..]).await?;
                        client.write_all(&fcx, b"!").await?;
                        let mut expected = original.to_vec();
                        expected.extend_from_slice(if same {
                            &retry[original.len()..]
                        } else {
                            retry
                        });
                        expected.push(b'!');
                        assert_eq!(peer.lock().unwrap().received, expected);
                    }
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    fn write_propagates_downstream_failures(server: bool) {
        fictionet::block_on(fictionet::lab(
            RunOptions::new(fictionet::Seed::from_u64(6)),
            move |fcx| async move {
                for partial in [false, true] {
                    for (result, error) in [
                        (Ok(0), ConnError::Closed),
                        (Err(ConnError::Reset), ConnError::Reset),
                        (Err(ConnError::Broken), ConnError::Broken),
                    ] {
                        let (mut client, peer) = connected(&fcx, server).await;
                        let mut cx = Context::from_waker(Waker::noop());
                        if partial {
                            peer.lock().unwrap().budget = 1;
                            assert!(client.poll_write(&fcx, &mut cx, b"hello").is_pending());
                        }
                        peer.lock().unwrap().terminal = Some(result);
                        assert_eq!(
                            client.poll_write(&fcx, &mut cx, b"hello"),
                            Poll::Ready(Err(error))
                        );
                        assert!(peer.lock().unwrap().received.is_empty());
                    }
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    fn read_propagates_output_failure(
        server: bool,
        incoming: bool,
        result: Result<usize, ConnError>,
        error: ConnError,
    ) {
        fictionet::block_on(fictionet::lab(
            RunOptions::new(fictionet::Seed::from_u64(7)),
            move |fcx| async move {
                let (mut conn, peer) = connected(&fcx, server).await;
                let mut cx = Context::from_waker(Waker::noop());
                // Leave ciphertext queued, as when a write future is dropped.
                peer.lock().unwrap().budget = 0;
                assert!(conn.poll_write(&fcx, &mut cx, b"queued").is_pending());
                if incoming {
                    let mut peer = peer.lock().unwrap();
                    tls::with_context(&fcx, || peer.tls.refresh_traffic_keys()).unwrap();
                    peer.tls.writer().write_all(b"hello").unwrap();
                }
                peer.lock().unwrap().terminal = Some(result);
                let mut buf = [0; 16];
                assert_eq!(
                    conn.poll_read(&fcx, &mut cx, &mut buf),
                    Poll::Ready(Err(error))
                );
                assert!(peer.lock().unwrap().received.is_empty());
                if incoming && server {
                    assert!(!peer.lock().unwrap().tls.wants_write());
                }
                // The output error must not consume decrypted application bytes.
                peer.lock().unwrap().budget = usize::MAX;
                if incoming {
                    assert_eq!(conn.poll_read(&fcx, &mut cx, &mut buf), Poll::Ready(Ok(5)));
                    assert_eq!(&buf[..5], b"hello");
                } else {
                    assert!(conn.poll_read(&fcx, &mut cx, &mut buf).is_pending());
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn server_tls_error_wins_over_output_failure() {
        fictionet::block_on(fictionet::lab(
            RunOptions::new(fictionet::Seed::from_u64(8)),
            |fcx| async move {
                let (mut conn, peer) = connected(&fcx, true).await;
                {
                    let mut peer = peer.lock().unwrap();
                    peer.tls.writer().write_all(b"hello").unwrap();
                    peer.corrupt = true;
                    peer.terminal = Some(Err(ConnError::Reset));
                }
                let mut cx = Context::from_waker(Waker::noop());
                assert_eq!(
                    conn.poll_read(&fcx, &mut cx, &mut [0; 16]),
                    Poll::Ready(Err(ConnError::Broken))
                );
                assert!(peer.lock().unwrap().terminal.is_none());
                Ok(())
            },
        ))
        .unwrap();
    }

    macro_rules! contracts {
        ($name:ident, $server:expr) => {
            mod $name {
                use super::*;

                #[test]
                fn write_waits_for_complete_ciphertext() {
                    super::write_waits_for_complete_ciphertext($server);
                }
                #[test]
                fn dropped_write_credits_only_matching_retries() {
                    super::dropped_write_credits_only_matching_retries($server);
                }
                #[test]
                fn write_propagates_downstream_failures() {
                    super::write_propagates_downstream_failures($server);
                }
                #[test]
                fn read_with_input_reports_closed_output() {
                    read_propagates_output_failure($server, true, Ok(0), ConnError::Closed);
                }
                #[test]
                fn read_with_input_reports_reset_output() {
                    read_propagates_output_failure(
                        $server,
                        true,
                        Err(ConnError::Reset),
                        ConnError::Reset,
                    );
                }
                #[test]
                fn read_with_input_reports_broken_output() {
                    read_propagates_output_failure(
                        $server,
                        true,
                        Err(ConnError::Broken),
                        ConnError::Broken,
                    );
                }
                #[test]
                fn read_without_input_reports_closed_output() {
                    read_propagates_output_failure($server, false, Ok(0), ConnError::Closed);
                }
                #[test]
                fn read_without_input_reports_reset_output() {
                    read_propagates_output_failure(
                        $server,
                        false,
                        Err(ConnError::Reset),
                        ConnError::Reset,
                    );
                }
                #[test]
                fn read_without_input_reports_broken_output() {
                    read_propagates_output_failure(
                        $server,
                        false,
                        Err(ConnError::Broken),
                        ConnError::Broken,
                    );
                }
            }
        };
    }

    contracts!(server, true);
    contracts!(sandbox_client, false);
}
