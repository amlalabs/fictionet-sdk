#![cfg(feature = "ring")]
#![allow(clippy::disallowed_types)]

use rustls::pki_types::pem::PemObject;
use std::sync::Arc;

use bencher::{benchmark_group, benchmark_main, Bencher};
use rustls::crypto::ring as provider;
use rustls::ServerConnection;
use std::io::{self, Read};

struct TestNonBlockIo;

impl Read for TestNonBlockIo {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

fn bench_ewouldblock(c: &mut Bencher) {
    let certs = vec![rustls::pki_types::CertificateDer::from_slice(
        include_bytes!("../test-ca/rsa-2048/end.der"),
    )];
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(include_bytes!(
        "../test-ca/rsa-2048/end.key"
    ))
    .unwrap();
    let server_config =
        rustls::ServerConfig::builder_with_provider(provider::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    c.iter(|| server.read_tls(&mut TestNonBlockIo));
}

benchmark_group!(benches, bench_ewouldblock);
benchmark_main!(benches);
