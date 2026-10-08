//! TLS as the stdlib serves it (`tls::server`, then `finish`): the
//! ClientHello that `web::Sites` routes on by SNI, the rest of the
//! handshake, and reads after it, from any bytes in pieces of any size.
#![no_main]

use std::sync::{Arc, OnceLock};
use std::time::{Duration, UNIX_EPOCH};

use fictionet::stdlib::{ConnectionExt, tls};
use fictionet_fuzz::{MemConn, world};
use libfuzzer_sys::fuzz_target;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The first byte: bit 0 finishes the handshake whatever the name, not
/// only for `site.test`. The second: the size of each read, 0 for as much
/// as fits. The rest: the bytes from the client.
struct Input {
    any_name: bool,
    piece: usize,
    bytes: Vec<u8>,
}

impl Input {
    fn read(data: &[u8]) -> Option<Input> {
        let [flags, piece, rest @ ..] = data else {
            return None;
        };
        Some(Input {
            any_name: flags & 1 != 0,
            piece: *piece as usize,
            bytes: rest.to_vec(),
        })
    }
}

fn cert() -> &'static (Vec<u8>, Vec<u8>) {
    static CERT: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CERT.get_or_init(|| {
        let c = rcgen::generate_simple_self_signed(vec!["site.test".to_owned()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    })
}

fuzz_target!(|data: &[u8]| {
    let Some(input) = Input::read(data) else {
        return;
    };
    let (der, key) = cert();
    world(move |fcx| async move {
        let config = tls::config_builder(
            &fcx,
            UNIX_EPOCH + Duration::from_secs(1_900_000_000))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())),
        )
        .unwrap();
        let mut config = config;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let pieces = if input.piece == 0 {
            Vec::new()
        } else {
            vec![input.piece; input.bytes.len() / input.piece + 1]
        };
        let conn = MemConn::new(input.bytes, pieces);
        let Ok(hello) = tls::server(&fcx, conn).await else {
            return;
        };
        let _ = hello.alpn();
        if !input.any_name && hello.server_name() != Some("site.test") {
            let _ = hello.reject(&fcx).await;
            return;
        }
        let Ok(mut conn) = hello.finish(&fcx, config).await else {
            return;
        };
        let mut buf = [0u8; 4096];
        // The input is finite and never waits, so reading ends.
        for _ in 0..1000 {
            match conn.read(&fcx, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = conn.write_all(&fcx, b"HTTP/1.1 200 OK\r\n\r\n").await;
        let _ = conn.shutdown(&fcx).await;
    });
});
