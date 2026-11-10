//! The TLS crypto provider (`src/stdlib/services/tls/provider.rs`) draws
//! every random byte from the `Entropy` it was built with, and from
//! nothing else. Compiled into `tests/it` as a child of `tls.rs`.
//!
//! The provider's randomness reaches rustls in three places: the
//! `SecureRandom` (hello randoms, session IDs, tickets, padding), each key
//! exchange group (the ephemeral secret), and the signing key (RSA blinding
//! and PSS salts; ECDSA here is deterministic, RFC 6979). If any of them
//! drew from the operating system, a thread-local or any state shared
//! between providers, then:
//!
//! - two runs with the same seeds would not send the same bytes;
//! - two connections stepped in turn on one thread would not send what
//!   each sends alone;
//! - a provider would draw nothing from its own entropy for that part.
//!
//! The tests check all three for each key type (the CA's ECDSA key and an
//! RSA-2048 key), each group (X25519, P-256, P-384) and both versions.

use super::*;
use fictionet::{Entropy, SeededEntropy};
use rustls::{ClientConnection, ConnectionCommon, NamedGroup, ServerConnection};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// A seeded source that counts the bytes drawn from it.
struct Counted {
    inner: SeededEntropy,
    drawn: AtomicU64,
}

impl Counted {
    fn new(seed: u64) -> Arc<Counted> {
        Arc::new(Counted {
            inner: SeededEntropy::new(Seed::from_u64(seed)),
            drawn: AtomicU64::new(0),
        })
    }

    fn drawn(&self) -> u64 {
        self.drawn.load(Ordering::Relaxed)
    }
}

impl Entropy for Counted {
    fn fill_random(&self, out: &mut [u8]) {
        self.drawn.fetch_add(out.len() as u64, Ordering::Relaxed);
        self.inner.fill_random(out);
    }
}

struct Key {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    roots: RootCertStore,
    name: &'static str,
}

fn ecdsa(fcx: &Cx) -> Key {
    let ca = Ca::new(fcx, "Test CA").unwrap();
    let (chain, key) = issue(fcx, &ca, &["example.test"], 2000, 2100, false);
    Key {
        chain,
        key,
        roots: roots(&ca),
        name: "example.test",
    }
}

fn rsa() -> Key {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/rustls/test-ca/rsa-2048/");
    let read = |name: &str| std::fs::read(format!("{dir}{name}")).unwrap();
    let der = fictionet::stdlib::protocols::x509::pem_decode(&read("end.key"))
        .unwrap()
        .remove(0)
        .data;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(read("ca.der"))).unwrap();
    Key {
        chain: vec![
            CertificateDer::from(read("end.der")),
            CertificateDer::from(read("inter.der")),
        ],
        key: PrivateKeyDer::Pkcs8(der.into()),
        roots,
        name: "testserver.com",
    }
}

fn server(key: &Key, entropy: Arc<dyn Entropy>) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_details(
            Arc::new(tls::crypto_provider(entropy)),
            Arc::new(FixedTime(date(2030, 1, 1))),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(key.chain.clone(), key.key.clone_key())
        .unwrap(),
    )
}

fn client(
    key: &Key,
    entropy: Arc<dyn Entropy>,
    group: NamedGroup,
    version: &'static rustls::SupportedProtocolVersion,
) -> Arc<ClientConfig> {
    let mut provider = tls::crypto_provider(entropy);
    provider.kx_groups.retain(|g| g.name() == group);
    assert_eq!(provider.kx_groups.len(), 1);
    Arc::new(
        ClientConfig::builder_with_details(
            Arc::new(provider),
            Arc::new(FixedTime(date(2030, 1, 1))),
        )
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(key.roots.clone())
        .with_no_client_auth(),
    )
}

fn drain<D>(conn: &mut ConnectionCommon<D>) -> Vec<u8> {
    let mut bytes = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut bytes).unwrap();
    }
    bytes
}

fn feed<D>(conn: &mut ConnectionCommon<D>, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        conn.read_tls(&mut rest).unwrap();
        conn.process_new_packets().unwrap();
    }
}

/// One connection: the handshake, a request, a reply, and close_notify
/// both ways. `up` and `down` are every byte each side sent.
struct Pair {
    client: ClientConnection,
    server: ServerConnection,
    up: Vec<u8>,
    down: Vec<u8>,
    stage: u8,
}

impl Pair {
    fn new(key: &Key, server: Arc<ServerConfig>, client: Arc<ClientConfig>) -> Pair {
        let name = rustls::pki_types::ServerName::try_from(key.name).unwrap();
        Pair {
            client: ClientConnection::new(client, name).unwrap(),
            server: ServerConnection::new(server).unwrap(),
            up: Vec::new(),
            down: Vec::new(),
            stage: 0,
        }
    }

    /// One flight each way; true once both sides have closed.
    fn step(&mut self) -> bool {
        let up = drain(&mut self.client);
        feed(&mut self.server, &up);
        self.up.extend_from_slice(&up);
        let down = drain(&mut self.server);
        feed(&mut self.client, &down);
        self.down.extend_from_slice(&down);
        if self.client.is_handshaking() || self.server.is_handshaking() {
            return false;
        }
        match self.stage {
            0 => {
                self.client.writer().write_all(b"request").unwrap();
                self.server.writer().write_all(b"reply").unwrap();
            }
            1 => {
                assert!(self.client.send_close_notify());
                assert!(self.server.send_close_notify());
            }
            _ => return up.is_empty() && down.is_empty(),
        }
        self.stage += 1;
        false
    }

    fn finish(mut self) -> (Vec<u8>, Vec<u8>) {
        for _ in 0..32 {
            if self.step() {
                return (self.up, self.down);
            }
        }
        panic!("the connection did not finish");
    }
}

/// The bytes each side sends, with the server's and the client's
/// providers seeded `s` and `c`, and how many bytes each provider drew.
fn run(
    key: &Key,
    group: NamedGroup,
    version: &'static rustls::SupportedProtocolVersion,
    s: u64,
    c: u64,
) -> ((Vec<u8>, Vec<u8>), u64, u64) {
    let (se, ce) = (Counted::new(s), Counted::new(c));
    let pair = Pair::new(
        key,
        server(key, se.clone()),
        client(key, ce.clone(), group, version),
    );
    let transcript = pair.finish();
    (transcript, se.drawn(), ce.drawn())
}

const GROUPS: [NamedGroup; 3] = [
    NamedGroup::X25519,
    NamedGroup::secp256r1,
    NamedGroup::secp384r1,
];

fn versions() -> [&'static rustls::SupportedProtocolVersion; 2] {
    [&rustls::version::TLS12, &rustls::version::TLS13]
}

#[test]
fn the_provider_draws_only_from_its_own_entropy() {
    block_on(lab(Seed::from_u64(30), |fcx| async move {
        for key in [ecdsa(&fcx), rsa()] {
            for group in GROUPS {
                for version in versions() {
                    let what = format!("{} {group:?} {:?}", key.name, version.version);
                    let (first, s1, c1) = run(&key, group, version, 1, 2);
                    let (again, s2, c2) = run(&key, group, version, 1, 2);
                    assert!(
                        first == again,
                        "{what}: the same seeds sent different bytes"
                    );
                    assert_eq!((s1, c1), (s2, c2), "{what}");
                    assert!(s1 > 0 && c1 > 0, "{what}: a provider drew nothing");
                    // The server's bytes follow its own entropy and nothing else.
                    let (other, _, _) = run(&key, group, version, 3, 2);
                    assert!(other.1 != first.1, "{what}: the server ignored its entropy");
                    let (other, _, _) = run(&key, group, version, 1, 4);
                    assert!(other.0 != first.0, "{what}: the client ignored its entropy");
                }
            }
        }
        Ok(())
    }))
    .unwrap();
}

/// Each part of the provider draws from it: a provider whose key
/// exchange group, `SecureRandom` or signing key is the same apart from
/// the entropy behind that one part sends different bytes.
#[test]
fn each_part_of_the_provider_draws_from_its_entropy() {
    block_on(lab(Seed::from_u64(31), |fcx| async move {
        for key in [ecdsa(&fcx), rsa()] {
            let version = &rustls::version::TLS13;
            let group = NamedGroup::X25519;
            let reference = run(&key, group, version, 1, 2).0;
            let splice = |part: usize| {
                let base = tls::crypto_provider(Counted::new(1));
                let other = tls::crypto_provider(Counted::new(9));
                let provider = match part {
                    0 => rustls::crypto::CryptoProvider {
                        secure_random: other.secure_random,
                        ..base
                    },
                    1 => rustls::crypto::CryptoProvider {
                        kx_groups: other.kx_groups,
                        ..base
                    },
                    _ => rustls::crypto::CryptoProvider {
                        key_provider: other.key_provider,
                        ..base
                    },
                };
                let config = Arc::new(
                    ServerConfig::builder_with_details(
                        Arc::new(provider),
                        Arc::new(FixedTime(date(2030, 1, 1))),
                    )
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(key.chain.clone(), key.key.clone_key())
                    .unwrap(),
                );
                Pair::new(&key, config, client(&key, Counted::new(2), group, version)).finish()
            };
            assert!(splice(0).1 != reference.1, "{}: SecureRandom", key.name);
            assert!(splice(1).1 != reference.1, "{}: key exchange", key.name);
            // ECDSA signatures are deterministic; RSA-PSS draws its salt.
            let signed = splice(2).1 != reference.1;
            assert_eq!(
                signed,
                key.name == "testserver.com",
                "{}: signing",
                key.name
            );
        }
        Ok(())
    }))
    .unwrap();
}

#[test]
fn connections_stepped_in_turn_send_what_each_sends_alone() {
    block_on(lab(Seed::from_u64(32), |fcx| async move {
        for key in [ecdsa(&fcx), rsa()] {
            let version = &rustls::version::TLS13;
            let alone_a = run(&key, NamedGroup::X25519, version, 1, 2).0;
            let alone_b = run(&key, NamedGroup::secp256r1, version, 5, 6).0;
            let mut a = Pair::new(
                &key,
                server(&key, Counted::new(1)),
                client(&key, Counted::new(2), NamedGroup::X25519, version),
            );
            let mut b = Pair::new(
                &key,
                server(&key, Counted::new(5)),
                client(&key, Counted::new(6), NamedGroup::secp256r1, version),
            );
            let (mut done_a, mut done_b) = (false, false);
            for _ in 0..32 {
                done_a = done_a || a.step();
                done_b = done_b || b.step();
            }
            assert!(done_a && done_b);
            assert!((a.up, a.down) == alone_a, "{}: connection a", key.name);
            assert!((b.up, b.down) == alone_b, "{}: connection b", key.name);
        }
        Ok(())
    }))
    .unwrap();
}
