//! Dropped TLS writes never credit old bytes to a later write.
use std::future::{Future, poll_fn};
use std::io::{ErrorKind, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::SystemTime;

use fictionet::stdlib::tls::{self, ServerConfig};
use fictionet::stdlib::{Connection, ConnectionExt, tcp};
use fictionet::time::ms;
use fictionet::{Cx, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

fn configs(fcx: &Cx) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let ca = fictionet::stdlib::ca::Ca::new(fcx, "Test CA").unwrap();
    let leaf = ca
        .issue(
            fcx,
            &["secret.test"],
            fictionet::stdlib::x509::Validity {
                not_before: fictionet::stdlib::x509::Time::from_unix(946684800).unwrap(),
                not_after: fictionet::stdlib::x509::Time::from_unix(4102444800).unwrap(),
            },
        )
        .unwrap();
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
/// `drain` is set, then reads and discards everything.
async fn client<C: Connection>(
    fcx: &Cx,
    mut conn: C,
    config: Arc<ClientConfig>,
    drain: Arc<AtomicBool>,
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
    while !drain.load(Ordering::SeqCst) {
        fcx.sleep(ms(10)).await?;
    }
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
        fictionet::Seed::from_u64(3),
        move |fcx| async move {
            let (server_cfg, client_cfg) = configs(&fcx);
            let (a, b) = fictionet::pair();
            let c_ep = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
            let s_ep = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
            let mut listener = s_ep.listen(443)?;
            let drain = Arc::new(AtomicBool::new(false));
            let received = Arc::new(AtomicBool::new(false));
            let got = received.clone();
            let d = drain.clone();
            fcx.spawn(move |fcx| async move {
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
                let d2 = drain.clone();
                fcx.spawn(move |fcx| async move {
                    fcx.sleep(ms(200)).await?;
                    d2.store(true, Ordering::SeqCst);
                    Ok(())
                });
                w.await?;
                conn.write_all(&fcx, b"hi").await?;
                fcx.sleep(ms(500)).await?;
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
                fcx.sleep(ms(1)).await?;
            }
            eprintln!(
                "wrote {total} bytes, then dropped a pending write of {}",
                chunk.len()
            );
            drain.store(true, Ordering::SeqCst);
            if mode == 1 {
                conn.write_all(&fcx, b"hi").await?;
                eprintln!("write_all of 2 bytes returned");
            } else {
                let n = conn.write(&fcx, b"hi").await?;
                eprintln!("write(b\"hi\") (2 bytes) returned Ok({n})");
                assert_eq!(n, 2);
            }
            fcx.sleep(ms(500)).await?;
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
