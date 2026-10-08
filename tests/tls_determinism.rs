//! Record-level replay and interoperability of the public TLS provider.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use fictionet::stdlib::tls;
use fictionet::{Cx, Seed, block_on};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, Connection, HandshakeKind, NamedGroup, RootCertStore,
    ServerConnection, SupportedProtocolVersion,
};

struct Fixture {
    cert: &'static [u8],
    key: &'static [u8],
}
macro_rules! fixture {
    ($name:literal) => {
        Fixture {
            cert: include_bytes!(concat!("fixtures/tls/", $name, ".cert.der")),
            key: include_bytes!(concat!("fixtures/tls/", $name, ".key.der")),
        }
    };
}
const P256: Fixture = fixture!("p256");
const P384: Fixture = fixture!("p384");
const ED25519: Fixture = fixture!("ed25519");
const RSA: Fixture = fixture!("rsa");
// The fixtures are valid in 2030; wall time never enters replay verification.
const DATE: u64 = 1_893_456_000;

struct Clock(Cx);
impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            Duration::from_secs(DATE) + self.0.now().since_start(),
        ))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Records {
    client: Vec<u8>,
    server: Vec<u8>,
}

fn transfer(from: &mut Connection, to: &mut Connection, log: &mut Vec<u8>) -> bool {
    if !from.wants_write() {
        return false;
    }
    let mut bytes = Vec::new();
    from.write_tls(&mut bytes).unwrap();
    assert!(!bytes.is_empty());
    log.extend_from_slice(&bytes);
    let mut input = bytes.as_slice();
    while !input.is_empty() {
        assert!(to.read_tls(&mut input).unwrap() > 0);
        to.process_new_packets().unwrap();
    }
    true
}

fn pump(client: &mut Connection, server: &mut Connection, records: &mut Records) {
    for _ in 0..32 {
        let a = transfer(client, server, &mut records.client);
        let b = transfer(server, client, &mut records.server);
        if !a && !b {
            assert!(!client.is_handshaking());
            assert!(!server.is_handshaking());
            return;
        }
    }
    panic!("TLS did not quiesce");
}

fn configs(
    cx: &Cx,
    fixture: &Fixture,
    version: &'static SupportedProtocolVersion,
    group: NamedGroup,
    stock_client: bool,
    stock_server: bool,
) -> (Arc<ClientConfig>, Arc<rustls::ServerConfig>) {
    let provider = |stock| {
        let mut p = if stock {
            rustls::crypto::ring::default_provider()
        } else {
            tls::crypto_provider()
        };
        p.kx_groups.retain(|g| g.name() == group);
        assert_eq!(p.kx_groups.len(), 1);
        Arc::new(p)
    };
    let cert = CertificateDer::from(fixture.cert.to_vec());
    let key = PrivateKeyDer::try_from(fixture.key.to_vec()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let clock = Arc::new(Clock(cx.clone()));
    let client = ClientConfig::builder_with_details(provider(stock_client), clock.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder_with_details(provider(stock_server), clock)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn exchange(
    client_config: Arc<ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
    group: NamedGroup,
    version: &'static SupportedProtocolVersion,
    resumed: bool,
) -> Records {
    let mut client = Connection::Client(
        ClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap(),
    );
    let mut server = Connection::Server(ServerConnection::new(server_config).unwrap());
    let mut records = Records::default();
    pump(&mut client, &mut server, &mut records);
    let expected = if resumed {
        HandshakeKind::Resumed
    } else {
        HandshakeKind::Full
    };
    assert_eq!(client.handshake_kind(), Some(expected));
    assert_eq!(server.handshake_kind(), Some(expected));
    assert_eq!(client.protocol_version(), Some(version.version));
    assert_eq!(server.protocol_version(), Some(version.version));
    // TLS 1.2 abbreviated handshakes reuse the session's secret without ECDHE.
    if !resumed || version.version == rustls::ProtocolVersion::TLSv1_3 {
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            group
        );
        assert_eq!(
            server.negotiated_key_exchange_group().unwrap().name(),
            group
        );
    }
    client
        .writer()
        .write_all(b"client application data")
        .unwrap();
    server
        .writer()
        .write_all(b"server application data")
        .unwrap();
    pump(&mut client, &mut server, &mut records);
    let mut received = [0; 23];
    client.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"server application data");
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, b"client application data");
    if version.version == rustls::ProtocolVersion::TLSv1_3 {
        client.refresh_traffic_keys().unwrap();
        server.refresh_traffic_keys().unwrap();
        pump(&mut client, &mut server, &mut records);
        client.writer().write_all(b"updated").unwrap();
        server.writer().write_all(b"updated").unwrap();
        pump(&mut client, &mut server, &mut records);
        let mut updated = [0; 7];
        client.reader().read_exact(&mut updated).unwrap();
        assert_eq!(&updated, b"updated");
        server.reader().read_exact(&mut updated).unwrap();
        assert_eq!(&updated, b"updated");
    }
    client.send_close_notify();
    server.send_close_notify();
    pump(&mut client, &mut server, &mut records);
    assert_eq!(client.reader().read(&mut received).unwrap(), 0);
    assert_eq!(server.reader().read(&mut received).unwrap(), 0);
    records
}

fn replay(
    seed: u64,
    fixture: &'static Fixture,
    version: &'static SupportedProtocolVersion,
    group: NamedGroup,
) -> Vec<Records> {
    let output = Arc::new(Mutex::new(Vec::new()));
    let result = output.clone();
    block_on(fictionet::lab(Seed::from_u64(seed), move |cx| async move {
        let (client, server) =
            tls::with_context(&cx, || configs(&cx, fixture, version, group, false, false));
        for resumed in [false, true, true] {
            let records = tls::with_context(&cx, || {
                exchange(client.clone(), server.clone(), group, version, resumed)
            });
            result.lock().unwrap().push(records);
            cx.sleep(Duration::from_secs(1)).await?;
        }
        Ok(())
    }))
    .unwrap();
    Arc::try_unwrap(output).unwrap().into_inner().unwrap()
}

fn deterministic(
    fixture: &'static Fixture,
    version: &'static SupportedProtocolVersion,
    group: NamedGroup,
) {
    let first = replay(41, fixture, version, group);
    assert_eq!(first, replay(41, fixture, version, group));
    let different = replay(42, fixture, version, group);
    for (a, b) in first.iter().zip(&different) {
        assert_ne!(a.client, b.client);
        assert_ne!(a.server, b.server);
    }
}

macro_rules! matrix {
    ($module:ident, $fixture:ident) => {
        mod $module {
            use super::*;
            #[test]
            fn tls12_x25519() {
                deterministic(&$fixture, &rustls::version::TLS12, NamedGroup::X25519);
            }
            #[test]
            fn tls12_p256() {
                deterministic(&$fixture, &rustls::version::TLS12, NamedGroup::secp256r1);
            }
            #[test]
            fn tls12_p384() {
                deterministic(&$fixture, &rustls::version::TLS12, NamedGroup::secp384r1);
            }
            #[test]
            fn tls13_x25519() {
                deterministic(&$fixture, &rustls::version::TLS13, NamedGroup::X25519);
            }
            #[test]
            fn tls13_p256() {
                deterministic(&$fixture, &rustls::version::TLS13, NamedGroup::secp256r1);
            }
            #[test]
            fn tls13_p384() {
                deterministic(&$fixture, &rustls::version::TLS13, NamedGroup::secp384r1);
            }
        }
    };
}
matrix!(ecdsa_p256, P256);
matrix!(ecdsa_p384, P384);
matrix!(ed25519, ED25519);
matrix!(rsa_cert, RSA);

#[test]
fn real_time_stock_ring_interop() {
    block_on(fictionet::run(Seed::from_u64(87), |cx| async move {
        for fixture in [&P256, &P384, &ED25519, &RSA] {
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                for group in [
                    NamedGroup::X25519,
                    NamedGroup::secp256r1,
                    NamedGroup::secp384r1,
                ] {
                    for stock_client in [false, true] {
                        tls::with_context(&cx, || {
                            let (client, server) =
                                configs(&cx, fixture, version, group, stock_client, !stock_client);
                            exchange(client.clone(), server.clone(), group, version, false);
                            exchange(client, server, group, version, true);
                        });
                    }
                }
            }
        }
        Ok(())
    }))
    .unwrap();
}

#[test]
fn provider_preserves_ring_preferences_and_requires_context() {
    let ours = tls::crypto_provider();
    let ring = rustls::crypto::ring::default_provider();
    assert_eq!(ours.cipher_suites, ring.cipher_suites);
    assert_eq!(
        ours.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
        ring.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>()
    );
    assert_eq!(
        ours.signature_verification_algorithms.supported_schemes(),
        ring.signature_verification_algorithms.supported_schemes()
    );
    assert!(ours.secure_random.fill(&mut [0; 1]).is_err());
    for group in &ours.kx_groups {
        assert!(group.start().is_err());
    }
    let key = ours
        .key_provider
        .load_private_key(PrivateKeyDer::try_from(RSA.key.to_vec()).unwrap())
        .unwrap();
    for scheme in [
        rustls::SignatureScheme::RSA_PSS_SHA256,
        rustls::SignatureScheme::RSA_PKCS1_SHA256,
    ] {
        assert!(
            key.choose_scheme(&[scheme])
                .unwrap()
                .sign(b"absent context")
                .is_err()
        );
    }
}

#[test]
fn invalid_key_shares() {
    block_on(fictionet::lab(Seed::from_u64(42), |cx| async move {
        tls::with_context(&cx, || {
            for group in tls::crypto_provider().kx_groups {
                let len = match group.name() {
                    NamedGroup::X25519 => 32,
                    NamedGroup::secp256r1 => 65,
                    NamedGroup::secp384r1 => 97,
                    _ => unreachable!(),
                };
                for invalid in [vec![], vec![0; len - 1], vec![0; len], vec![0; len + 1]] {
                    assert!(group.start().unwrap().complete(&invalid).is_err());
                }
                if group.name() == NamedGroup::X25519 {
                    let mut low_order = [0; 32];
                    low_order[0] = 1;
                    assert!(group.start().unwrap().complete(&low_order).is_err());
                } else {
                    let mut off_curve = vec![0; len];
                    off_curve[0] = 4;
                    assert!(group.start().unwrap().complete(&off_curve).is_err());
                    let public = group.start().unwrap().pub_key().to_vec();
                    let mut compressed = public[..=(len - 1) / 2].to_vec();
                    compressed[0] = 2;
                    assert!(group.start().unwrap().complete(&compressed).is_err());
                }
            }
        });
        Ok(())
    }))
    .unwrap();
}

#[test]
fn config_builder_uses_run_clock() {
    block_on(fictionet::lab(Seed::from_u64(11), |cx| async move {
        let config = tls::config_builder(&cx, UNIX_EPOCH + Duration::from_secs(DATE))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![P256.cert.to_vec().into()],
                PrivateKeyDer::try_from(P256.key.to_vec()).unwrap(),
            )
            .unwrap();
        assert_eq!(config.time_provider.current_time().unwrap().as_secs(), DATE);
        cx.sleep(Duration::from_secs(9)).await?;
        assert_eq!(
            config.time_provider.current_time().unwrap().as_secs(),
            DATE + 9
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn nested_context_restores_on_return_and_unwind() {
    use fictionet::{Entropy, SeededEntropy};
    fn check(oracle: &SeededEntropy) {
        let mut got = [0; 17];
        let mut expected = [0; 17];
        tls::crypto_provider().secure_random.fill(&mut got).unwrap();
        oracle.fill_random(&mut expected);
        assert_eq!(got, expected);
    }
    block_on(fictionet::lab(Seed::from_u64(71), |outer| async move {
        let outer_rng = Arc::new(SeededEntropy::new(Seed::from_u64(71)));
        tls::with_context(&outer, || {
            check(&outer_rng);
            let nested_rng = outer_rng.clone();
            block_on(fictionet::lab(Seed::from_u64(72), |inner| async move {
                let inner_rng = SeededEntropy::new(Seed::from_u64(72));
                tls::with_context(&inner, || check(&inner_rng));
                check(&nested_rng);
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    tls::with_context(&inner, || {
                        check(&inner_rng);
                        panic!("unwind context");
                    });
                }));
                assert!(panic.is_err());
                check(&nested_rng);
                Ok(())
            }))
            .unwrap();
            check(&outer_rng);
        });
        assert!(
            tls::crypto_provider()
                .secure_random
                .fill(&mut [0; 1])
                .is_err()
        );
        Ok(())
    }))
    .unwrap();
}

#[test]
fn rsa_signature_schemes_and_key_encodings() {
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
    use rsa::pkcs8::DecodePrivateKey;
    use rustls::SignatureScheme::*;
    let private = rsa::RsaPrivateKey::from_pkcs8_der(RSA.key).unwrap();
    let public = private.to_public_key().to_pkcs1_der().unwrap();
    let pkcs1 = private.to_pkcs1_der().unwrap();
    let schemes = [
        (RSA_PSS_SHA512, &ring::signature::RSA_PSS_2048_8192_SHA512),
        (RSA_PSS_SHA384, &ring::signature::RSA_PSS_2048_8192_SHA384),
        (RSA_PSS_SHA256, &ring::signature::RSA_PSS_2048_8192_SHA256),
        (
            RSA_PKCS1_SHA512,
            &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        ),
        (
            RSA_PKCS1_SHA384,
            &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        ),
        (
            RSA_PKCS1_SHA256,
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        ),
    ];
    let sign = |seed, der: PrivateKeyDer<'static>| {
        let public = public.clone();
        let result = Arc::new(Mutex::new(Vec::new()));
        let output = result.clone();
        block_on(fictionet::lab(Seed::from_u64(seed), |cx| async move {
            tls::with_context(&cx, || {
                let key = tls::crypto_provider()
                    .key_provider
                    .load_private_key(der)
                    .unwrap();
                let offered = schemes.iter().rev().map(|(s, _)| *s).collect::<Vec<_>>();
                assert_eq!(
                    key.choose_scheme(&offered).unwrap().scheme(),
                    RSA_PSS_SHA512
                );
                for (scheme, verifier) in schemes {
                    let signer = key.choose_scheme(&[scheme]).unwrap();
                    assert_eq!(signer.scheme(), scheme);
                    let signature = signer.sign(b"signature test").unwrap();
                    ring::signature::UnparsedPublicKey::new(verifier, public.as_bytes())
                        .verify(b"signature test", &signature)
                        .unwrap();
                    output.lock().unwrap().push(signature);
                }
            });
            Ok(())
        }))
        .unwrap();
        Arc::try_unwrap(result).unwrap().into_inner().unwrap()
    };
    let first = sign(17, PrivateKeyDer::try_from(RSA.key.to_vec()).unwrap());
    assert_eq!(
        first,
        sign(17, PrivateKeyDer::Pkcs1(pkcs1.as_bytes().to_vec().into()))
    );
    let other = sign(18, PrivateKeyDer::try_from(RSA.key.to_vec()).unwrap());
    for i in 0..3 {
        assert_ne!(first[i], other[i]);
    }
    for i in 3..6 {
        assert_eq!(first[i], other[i]);
    }
}

#[test]
fn ecdsa_sec1_keys_match_pkcs8_and_sign_without_entropy() {
    use rsa::pkcs8::DecodePrivateKey;
    let p256 = p256::SecretKey::from_pkcs8_der(P256.key)
        .unwrap()
        .to_sec1_der()
        .unwrap();
    let p384 = p384::SecretKey::from_pkcs8_der(P384.key)
        .unwrap()
        .to_sec1_der()
        .unwrap();
    for (fixture, sec1, scheme) in [
        (
            &P256,
            p256.as_slice(),
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ),
        (
            &P384,
            p384.as_slice(),
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        ),
    ] {
        let provider = tls::crypto_provider();
        let key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::try_from(fixture.key.to_vec()).unwrap())
            .unwrap();
        let converted = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Sec1(sec1.to_vec().into()))
            .unwrap();
        assert_eq!(key.public_key(), converted.public_key());
        let signature = key
            .choose_scheme(&[scheme])
            .unwrap()
            .sign(b"RFC 6979")
            .unwrap();
        assert_eq!(
            signature,
            converted
                .choose_scheme(&[scheme])
                .unwrap()
                .sign(b"RFC 6979")
                .unwrap()
        );
        assert!(
            key.choose_scheme(&[rustls::SignatureScheme::ED25519])
                .is_none()
        );
    }
}
