//! TLS key collection leaves application events unchanged.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::{Connection, ConnectionExt, tcp};
use fictionet::stdlib::services::tls::{self, ServerConfig};
use fictionet::time::ms;
use fictionet::{Cx, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// A CA, and a server and client config for `secret.test`.
fn configs(fcx: &Cx) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let ca = fictionet::stdlib::services::ca::Ca::new(fcx, "Test CA").unwrap();
    let leaf = ca
        .issue(
            fcx,
            &["secret.test"],
            fictionet::stdlib::protocols::x509::Validity {
                not_before: fictionet::stdlib::protocols::x509::Time::from_unix(946684800).unwrap(),
                not_after: fictionet::stdlib::protocols::x509::Time::from_unix(4102444800).unwrap(),
            },
        )
        .unwrap();
    let provider = rustls::crypto::ring::default_provider();
    let server = tls::config_builder(fcx, SystemTime::now())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain, leaf.key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// Speaks TLS as a client over `conn`: finishes the handshake, changes
/// its keys with a KeyUpdate (which asks the server to change its own),
/// sends one request and returns the response.
async fn fetch<C: Connection>(
    fcx: &Cx,
    mut conn: C,
    config: Arc<ClientConfig>,
    request: &[u8],
) -> Result<Vec<u8>> {
    let mut tls = ClientConnection::new(config, ServerName::try_from("secret.test").unwrap())?;
    let mut sent = false;
    let mut response = Vec::new();
    let mut buf = vec![0u8; 16 << 10];
    loop {
        if !sent && !tls.is_handshaking() {
            tls.refresh_traffic_keys()?;
            tls.writer().write_all(request)?;
            sent = true;
        }
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)?;
            conn.write_all(fcx, &out).await?;
        }
        match tls.reader().read_to_end(&mut response) {
            Ok(_) => return Ok(response),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(response),
            Err(e) => return Err(e.into()),
        }
        if response.ends_with(b"hello") {
            return Ok(response);
        }
        let n = conn.read(fcx, &mut buf).await?;
        if n == 0 {
            return Ok(response);
        }
        tls.read_tls(&mut &buf[..n])?;
        tls.process_new_packets()?;
    }
}

fn one_run(observe: bool) -> Vec<Vec<u8>> {
    let out = Arc::new(fictionet::sync::Mutex::new(None));
    let o = out.clone();
    let evidence = Arc::new(fictionet::events::Memory::default());
    let collector = Arc::new(fictionet_observe::Collector::new(
        fictionet_observe::Options {
            keys: if observe {
                fictionet_observe::Options::default().keys
            } else {
                None
            },
            ..fictionet_observe::Options::default()
        },
    ));
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(Arc::new(
            fictionet::events::Fanout::new(vec![evidence.clone(), collector.clone()]),
        )),
        move |fcx| async move {
            let (server_cfg, client_cfg) = configs(&fcx);
            let (a, b) = fictionet::pair();
            let client = tcp::endpoint(&fcx, a, "10.0.0.2".parse()?);
            let server = tcp::endpoint(&fcx, b, "10.0.0.1".parse()?);
            let mut listener = server.listen(443)?;
            fcx.spawn(move |fcx| async move {
                let conn = listener.accept(&fcx).await?;
                let mut conn = tls::server(&fcx, conn)
                    .await?
                    .finish(&fcx, server_cfg)
                    .await?;
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = conn.read(&fcx, &mut buf).await?;
                    request.extend_from_slice(&buf[..n]);
                }
                conn.write_all(&fcx, b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
                    .await?;
                conn.shutdown(&fcx).await?;
                Ok(())
            });
            fcx.emit("test", "before_tls", |event| event);
            let conn = client.connect(&fcx, "10.0.0.1:443".parse()?).await?;
            let _ = fetch(
                &fcx,
                conn,
                client_cfg,
                b"GET / HTTP/1.1\r\nhost: secret.test\r\n\r\n",
            )
            .await?;
            fcx.sleep(ms(200)).await?;
            fcx.emit("test", "after_tls", |event| event);
            assert_eq!(!collector.keys().is_empty(), observe);
            let events = evidence.checked_all().unwrap();
            assert_eq!(events.len(), 3);
            assert!(events[0].is("run", "start"));
            assert!(events[1].is("test", "before_tls"));
            assert!(events[2].is("test", "after_tls"));
            *o.lock() = Some(
                events
                    .iter()
                    .map(|e| e.to_json().to_bytes().unwrap())
                    .collect(),
            );
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    out.lock().take().expect("world finished")
}

#[test]
fn observing_tls_does_not_change_the_event_log() {
    assert_eq!(one_run(false), one_run(true));
}
