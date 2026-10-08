//! An observer decrypts TLS on a watched link: a world with a stdlib TLS
//! server and a rustls client, joined by two TCP endpoints and one pair.
//! The observer watches the pair, and sees the HTTP inside the TLS.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use fictionet::relay::observer::{Client, Value};
use fictionet::stdlib::tls::{self, ServerConfig};
use fictionet::stdlib::{Connection, ConnectionExt, tcp};
use fictionet::time::ms;
use fictionet::{Cx, Result};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

fn temp_socket() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fn-obstls-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("world.sock").to_str().unwrap().to_owned()
}

/// A CA, and a server and client config for `secret.test`.
fn configs(fcx: &Cx) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let mut leaf = CertificateParams::new(vec!["secret.test".to_owned()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = leaf.signed_by(&key, &ca, &ca_key).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let provider = rustls::crypto::ring::default_provider();
    let server = tls::config_builder(fcx, SystemTime::now(), provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
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

fn text(v: &Value) -> String {
    String::from_utf8_lossy(&v.bytes).into_owned()
}

#[test]
fn an_observer_sees_http_inside_tls() {
    let path = temp_socket();
    let (attacher, mut attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )
    .unwrap();
    let go = Arc::new(AtomicBool::new(false));
    let fetched = Arc::new(std::sync::Mutex::new(None));
    let (g, f) = (go.clone(), fetched.clone());
    std::thread::spawn(move || {
        let _ = fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            move |fcx| async move {
                // Taking attachments is what lets the world socket find this run.
                fcx.spawn(move |fcx| async move {
                    let _ = attachments.next(&fcx).await;
                    Ok(())
                });
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
                while !g.load(Ordering::SeqCst) {
                    fcx.sleep(ms(10)).await?;
                }
                let conn = client.connect(&fcx, "10.0.0.1:443".parse()?).await?;
                let response = fetch(
                    &fcx,
                    conn,
                    client_cfg,
                    b"GET /secret HTTP/1.1\r\nhost: secret.test\r\n\r\n",
                )
                .await?;
                *f.lock().unwrap() = Some(response);
                fcx.sleep(std::time::Duration::from_secs(60)).await?;
                Ok(())
            },
        ));
    });

    let mut observer = Client::connect(&path, "test").unwrap();
    observer.set_timeout(Some(Duration::from_secs(10))).unwrap();
    // Follow the graph until the pair between the two endpoints shows.
    observer.request(r#"{"op":"watch"}"#).unwrap();
    let start = Instant::now();
    let mut edge = None;
    while edge.is_none() && start.elapsed() < Duration::from_secs(10) {
        let v = text(&observer.next_value().unwrap().unwrap());
        // The pair is the only edge; both of its ends are tcp::endpoint.
        if let Some(at) = v.find(r#"{"id":"e"#) {
            let digits: String = v[at + 8..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            edge = Some(digits);
        }
    }
    let edge = edge.expect("the pair between the endpoints");
    let packets = observer
        .request(&format!(r#"{{"op":"packets","link":"e{edge}"}}"#))
        .unwrap();
    go.store(true, Ordering::SeqCst);

    let (mut request, mut response) = (false, false);
    while !(request && response) && start.elapsed() < Duration::from_secs(20) {
        let v = observer.next_value().unwrap().unwrap();
        if v.id != packets {
            continue;
        }
        let t = text(&v);
        // The packet is shown as what TLS carries.
        request |= t.contains(r#""proto":"HTTP","info":"GET /secret HTTP/1.1""#)
            && t.contains("decrypted");
        response |=
            t.contains(r#""proto":"HTTP","info":"HTTP/1.1 200 OK""#) && t.contains("decrypted");
    }
    assert!(request && response, "the HTTP inside the TLS was not shown");
    assert!(
        fetched
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|r| r.ends_with(b"hello"))
    );

    // The keys, and the capture with the keys in it.
    observer.request(r#"{"op":"keylog"}"#).unwrap();
    let keylog = loop {
        let v = observer.next_value().unwrap().unwrap();
        if v.id != packets {
            break v;
        }
    };
    assert!(
        keylog.binary && text(&keylog).contains("CLIENT_TRAFFIC_SECRET_0 "),
        "{}",
        text(&keylog)
    );
    observer
        .request(&format!(r#"{{"op":"pcap","link":"e{edge}"}}"#))
        .unwrap();
    let pcap = loop {
        let v = observer.next_value().unwrap().unwrap();
        if v.id != packets {
            break v;
        }
    };
    // The third block is the Decryption Secrets Block.
    let b = &pcap.bytes;
    let first = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let second = u32::from_le_bytes(b[first + 4..first + 8].try_into().unwrap()) as usize;
    assert_eq!(
        u32::from_le_bytes(b[first + second..first + second + 4].try_into().unwrap()),
        0x0a
    );
}
