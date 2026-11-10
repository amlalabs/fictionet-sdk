//! Real handshakes between the crate's client and its server, each logged
//! as the server saw it, for the trace check of
//! `verification/tls-rfc/tla/HandshakeTrace.tla` against the RFC spec
//! `Handshake.tla`.
//!
//! Every record that crosses between the two is kept. Once a run is over,
//! each record is opened with the secrets both sides logged through
//! [`KeyLog`]: a record that decrypts under a key was protected under that
//! key's epoch, so the epoch in the log is observed, not assumed. TLS 1.3
//! records are tried under the early, handshake and application secrets
//! (and the secrets each KeyUpdate derives from them); TLS 1.2 records
//! after a ChangeCipherSpec under the keys the master secret gives. Each
//! handshake message, alert, ChangeCipherSpec and application data record
//! is one log entry: who sent it (`recv` for the server's input), what it
//! is, the epoch, and for a ClientHello what it offers. Whether a Finished
//! or CertificateVerify is valid is known only by how a run was built: it
//! is "ok" unless the run altered the client's hello.
//!
//! With `FICTIONET_TLS_TRACE_DIR` set, each run writes `HsLog_<name>.tla`
//! and `.cfg` there, to be checked by TLC (`cargo xtask tls-verify
//! handshake-trace`). Runs that show a known departure from the RFC write
//! `HsDeparture_<name>`: those logs must not be behaviors of the spec.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;
use std::io::{self, Read, Write};
use std::sync::Mutex;

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::budget::testing::Limit;
use crate::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::client::{ClientConfig, ClientConnection, Resumption};
use crate::conn::ConnectionRandoms;
use crate::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::crypto::ring::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
};
use crate::crypto::ring::kx_group::{SECP256R1, X25519};
use crate::crypto::ring::{default_provider, Ticketer};
use crate::crypto::tls13::OkmBlock;
use crate::crypto::{CryptoProvider, SupportedKxGroup};
use crate::enums::{ContentType, HandshakeType, ProtocolVersion, SignatureScheme};
use crate::msgs::codec::Codec;
use crate::msgs::enums::NamedGroup;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{MessagePayload, OutboundPlainMessage};
use crate::server::danger::{ClientCertVerified, ClientCertVerifier};
use crate::server::{Acceptor, IntoConnectionError, ServerConfig, ServerConnection};
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::tls12::ConnectionSecrets;
use crate::tls13::key_schedule::{
    derive_next_traffic_secret, derive_traffic_iv, derive_traffic_key,
};
use crate::tls13::Tls13CipherSuite;
use crate::version::{TLS12, TLS13};
use crate::{
    DigitallySignedStruct, DistinguishedName, Error, KeyLog, Side, SupportedProtocolVersion,
};

// ---------------------------------------------------------------------------
// Configs

/// Every secret either side logs, with the client random it belongs to.
#[derive(Debug, Default)]
struct Keys(Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>);

impl KeyLog for Keys {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.to_string(), client_random.to_vec(), secret.to_vec()));
    }
}

impl Keys {
    fn get(&self, label: &str, random: &[u8]) -> Option<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(l, r, _)| l == label && r == random)
            .map(|(_, _, s)| s.clone())
    }
}

fn chain() -> Vec<CertificateDer<'static>> {
    vec![
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/end.der")[..]),
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/inter.der")[..]),
    ]
}

fn key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_reader(&mut &include_bytes!("../../test-ca/rsa-2048/end.key")[..])
        .unwrap()
}

/// One TLS 1.3 and one TLS 1.2 suite, so every record of a run is under
/// the same AEAD, and the key exchange groups given.
fn provider(groups: &[&'static dyn SupportedKxGroup]) -> Arc<CryptoProvider> {
    let mut provider = default_provider();
    provider.cipher_suites = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = groups
        .iter()
        .map(|group| -> Arc<dyn SupportedKxGroup> {
            if group.name() == NamedGroup::X25519 {
                Arc::new(*X25519)
            } else {
                Arc::new(*SECP256R1)
            }
        })
        .collect();
    Arc::new(provider)
}

/// Accepts any client certificate: these runs are about the messages.
#[derive(Debug)]
struct AnyClient {
    mandatory: bool,
}

impl ClientCertVerifier for AnyClient {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The client trusts any server.
#[derive(Debug)]
struct AnyServer;

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// How a run's server is set up.
#[derive(Clone)]
struct ServerSetup {
    groups: Vec<&'static dyn SupportedKxGroup>,
    auth: Option<bool>,
    early: u32,
    half_rtt: bool,
    ticketer: bool,
}

impl Default for ServerSetup {
    fn default() -> Self {
        Self {
            groups: vec![X25519, SECP256R1],
            auth: None,
            early: 0,
            half_rtt: false,
            ticketer: false,
        }
    }
}

fn server_config(
    setup: &ServerSetup,
    storage: &Arc<dyn crate::server::StoresServerSessions>,
    keys: &Arc<Keys>,
) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder_with_provider(provider(&setup.groups))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .unwrap();
    let builder = match setup.auth {
        Some(mandatory) => builder.with_client_cert_verifier(Arc::new(AnyClient { mandatory })),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_single_cert(chain(), key()).unwrap();
    config.key_log = keys.clone();
    config.session_storage = storage.clone();
    config.max_early_data_size = setup.early;
    config.send_half_rtt_data = setup.half_rtt;
    config.send_tls13_tickets = 1;
    if setup.ticketer {
        config.ticketer = Ticketer::new().unwrap();
    }
    Arc::new(config)
}

/// How a run's client is set up.
#[derive(Clone)]
struct ClientSetup {
    version: &'static SupportedProtocolVersion,
    groups: Vec<&'static dyn SupportedKxGroup>,
    cert: bool,
    early: bool,
}

impl ClientSetup {
    fn new(version: &'static SupportedProtocolVersion) -> Self {
        Self {
            version,
            groups: vec![X25519, SECP256R1],
            cert: false,
            early: false,
        }
    }
}

fn client_config(
    setup: &ClientSetup,
    resumption: &Resumption,
    keys: &Arc<Keys>,
) -> Arc<ClientConfig> {
    // A client resumes only with the same verifier and certificate
    // resolver (Arc::ptr_eq), so every run shares one of each.
    static VERIFIER: std::sync::OnceLock<Arc<AnyServer>> = std::sync::OnceLock::new();
    static NO_CERT: std::sync::OnceLock<Arc<dyn crate::client::ResolvesClientCert>> =
        std::sync::OnceLock::new();
    static CERT: std::sync::OnceLock<Arc<dyn crate::client::ResolvesClientCert>> =
        std::sync::OnceLock::new();
    let builder = ClientConfig::builder_with_provider(provider(&setup.groups))
        .with_protocol_versions(&[setup.version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(VERIFIER.get_or_init(|| Arc::new(AnyServer)).clone());
    let fresh = || {
        ClientConfig::builder_with_provider(provider(&setup.groups))
            .with_protocol_versions(&[setup.version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyServer))
    };
    let resolver = match setup.cert {
        true => CERT.get_or_init(|| {
            fresh()
                .with_client_auth_cert(chain(), key())
                .unwrap()
                .client_auth_cert_resolver
        }),
        false => NO_CERT.get_or_init(|| fresh().with_no_client_auth().client_auth_cert_resolver),
    };
    let mut config = builder.with_client_cert_resolver(resolver.clone());
    config.key_log = keys.clone();
    config.resumption = resumption.clone();
    config.enable_early_data = setup.early;
    Arc::new(config)
}

fn client(config: Arc<ClientConfig>) -> ClientConnection {
    ClientConnection::new(config, ServerName::try_from("testserver.com").unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// The wire

#[derive(Clone, Copy, PartialEq, Debug)]
enum Dir {
    /// From the client: the server's input.
    In,
    /// From the server.
    Out,
}

/// A whole record as it crossed.
#[derive(Clone)]
struct Wire {
    dir: Dir,
    typ: u8,
    body: Vec<u8>,
}

fn split(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let len = usize::from(u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]));
        records.push((bytes[at], bytes[at + 5..at + 5 + len].to_vec()));
        at += 5 + len;
    }
    assert_eq!(at, bytes.len(), "the wire holds whole records");
    records
}

fn record(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![typ, 3, 3];
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn drain_client(client: &mut ClientConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    wire
}

fn drain_server(server: &mut ServerConnection) -> Vec<u8> {
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    wire
}

/// Reads stop at the end of each record: process between reads.
fn feed_server(server: &mut ServerConnection, mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        match server.read_tls(&mut bytes) {
            Ok(_) => {}
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::Other),
        }
        server.process_new_packets()?;
    }
    Ok(())
}

fn feed_client(client: &mut ClientConnection, mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        match client.read_tls(&mut bytes) {
            Ok(_) => {}
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::Other),
        }
        client.process_new_packets()?;
    }
    Ok(())
}

/// One connection as the server saw it.
struct Run {
    name: String,
    wire: Vec<Wire>,
    keys: Arc<Keys>,
    /// The groups the server supports, in its order, to tell whether a
    /// hello has a share for the group it picks.
    server_groups: Vec<NamedGroup>,
    /// TLS 1.2: the session the hello resumes: "none", "ems" or "noems".
    session: &'static str,
    /// Whether the client's Finished matches the server's transcript.
    finished_ok: bool,
}

impl Run {
    fn new(name: &str, keys: &Arc<Keys>, server: &ServerSetup) -> Self {
        Self {
            name: name.to_string(),
            wire: Vec::new(),
            keys: keys.clone(),
            server_groups: server.groups.iter().map(|g| g.name()).collect(),
            session: "none",
            finished_ok: true,
        }
    }

    fn note(&mut self, dir: Dir, bytes: &[u8]) {
        for (typ, body) in split(bytes) {
            self.wire.push(Wire { dir, typ, body });
        }
    }

    fn to_server(
        &mut self,
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Result<(), Error> {
        let bytes = drain_client(client);
        self.note(Dir::In, &bytes);
        feed_server(server, &bytes)
    }

    fn to_client(
        &mut self,
        server: &mut ServerConnection,
        client: &mut ClientConnection,
    ) -> Result<(), Error> {
        let bytes = drain_server(server);
        self.note(Dir::Out, &bytes);
        feed_client(client, &bytes)
    }

    /// What the server has queued, noted and dropped: it goes nowhere.
    fn server_output(&mut self, server: &mut ServerConnection) {
        let bytes = drain_server(server);
        self.note(Dir::Out, &bytes);
    }

    fn handshake(&mut self, client: &mut ClientConnection, server: &mut ServerConnection) {
        loop {
            self.to_server(client, server).unwrap();
            self.to_client(server, client).unwrap();
            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                break;
            }
        }
    }

    /// The client sends `data`, the server reads it and sends it back.
    fn echo(&mut self, client: &mut ClientConnection, server: &mut ServerConnection, data: &[u8]) {
        client.writer().write_all(data).unwrap();
        self.to_server(client, server).unwrap();
        let mut got = Vec::new();
        let _ = server.reader().read_to_end(&mut got);
        assert!(
            got == data,
            "{}: the server read what the client sent",
            self.name
        );
        server.writer().write_all(&got).unwrap();
        self.to_client(server, client).unwrap();
        let mut back = Vec::new();
        let _ = client.reader().read_to_end(&mut back);
        assert!(back == data, "{}: the client read the echo", self.name);
    }
}

// ---------------------------------------------------------------------------
// Opening the records

/// What a ClientHello offers, in the spec's terms.
#[derive(Clone, PartialEq, Debug)]
struct Offer {
    v: &'static str,
    sh: bool,
    ed: bool,
    pk: bool,
    em: bool,
    ss: &'static str,
}

/// One log entry.
#[derive(Clone, PartialEq, Debug)]
struct Entry {
    d: &'static str,
    m: &'static str,
    e: String,
    x: &'static str,
    co: bool,
    ch: Option<Offer>,
}

/// A key a direction's records may be under.
struct Candidate {
    epoch: String,
    decrypter: Box<dyn MessageDecrypter>,
    seq: u64,
}

fn tls13_keys(
    suite: &'static Tls13CipherSuite,
    secret: &[u8],
) -> (
    crate::crypto::cipher::AeadKey,
    crate::crypto::cipher::Iv,
    OkmBlock,
) {
    let expander = suite.hkdf_provider.expander_for_okm(&OkmBlock::new(secret));
    (
        derive_traffic_key(expander.as_ref(), suite.aead_alg),
        derive_traffic_iv(expander.as_ref()),
        derive_next_traffic_secret(expander.as_ref()),
    )
}

fn tls13_decrypter(suite: &'static Tls13CipherSuite, secret: &[u8]) -> Box<dyn MessageDecrypter> {
    let (key, iv, _) = tls13_keys(suite, secret);
    suite.aead_alg.decrypter(key, iv)
}

fn tls13_encrypter(suite: &'static Tls13CipherSuite, secret: &[u8]) -> Box<dyn MessageEncrypter> {
    let (key, iv, _) = tls13_keys(suite, secret);
    suite.aead_alg.encrypter(key, iv)
}

/// The keys of one direction: TLS 1.3 epochs, or TLS 1.2 keys that the
/// direction's ChangeCipherSpec turns on.
struct Direction {
    candidates: Vec<Candidate>,
    tls12: Option<Box<dyn MessageDecrypter>>,
    tls12_on: bool,
    tls12_seq: u64,
    /// Bytes of a handshake message still arriving.
    pending: Vec<u8>,
}

impl Direction {
    fn tls13(suite: &'static Tls13CipherSuite, keys: &Keys, random: &[u8], dir: Dir) -> Self {
        let (early, hs, app) = match dir {
            Dir::In => (
                Some("CLIENT_EARLY_TRAFFIC_SECRET"),
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
            ),
            Dir::Out => (
                None,
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_TRAFFIC_SECRET_0",
            ),
        };
        let mut candidates = Vec::new();
        let mut add = |epoch: &str, secret: &[u8]| {
            candidates.push(Candidate {
                epoch: epoch.to_string(),
                decrypter: tls13_decrypter(suite, secret),
                seq: 0,
            })
        };
        if let Some(secret) = early.and_then(|label| keys.get(label, random)) {
            add("early", &secret);
        }
        if let Some(secret) = keys.get(hs, random) {
            add("hs", &secret);
        }
        if let Some(mut secret) = keys.get(app, random) {
            for n in 0..4 {
                add(&format!("app{n}"), &secret);
                let (_, _, next) = tls13_keys(suite, &secret);
                secret = next.as_ref().to_vec();
            }
        }
        Self {
            candidates,
            tls12: None,
            tls12_on: false,
            tls12_seq: 0,
            pending: Vec::new(),
        }
    }

    fn tls12(decrypter: Option<Box<dyn MessageDecrypter>>) -> Self {
        Self {
            candidates: Vec::new(),
            tls12: decrypter,
            tls12_on: false,
            tls12_seq: 0,
            pending: Vec::new(),
        }
    }

    /// The record's epoch, its inner type and its plaintext.
    fn open(&mut self, typ: u8, body: &[u8]) -> (String, u8, Vec<u8>) {
        if typ == 20 {
            self.tls12_on = self.tls12.is_some();
            return ("none".into(), typ, body.to_vec());
        }
        if self.tls12_on {
            let mut buf = body.to_vec();
            let message = InboundOpaqueMessage::new(
                ContentType::from(typ),
                ProtocolVersion::TLSv1_2,
                &mut buf,
            );
            let plain = self
                .tls12
                .as_mut()
                .unwrap()
                .decrypt(message, self.tls12_seq)
                .expect("a TLS 1.2 record after ChangeCipherSpec decrypts");
            self.tls12_seq += 1;
            return ("ccs".into(), typ, plain.payload.to_vec());
        }
        if typ != 23 || self.candidates.is_empty() {
            return ("none".into(), typ, body.to_vec());
        }
        for candidate in &mut self.candidates {
            let mut buf = body.to_vec();
            let message = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut buf,
            );
            if let Ok(plain) = candidate.decrypter.decrypt(message, candidate.seq) {
                candidate.seq += 1;
                return (
                    candidate.epoch.clone(),
                    u8::from(plain.typ),
                    plain.payload.to_vec(),
                );
            }
        }
        // Under none of the keys either side logged.
        ("none".into(), typ, body.to_vec())
    }
}

fn handshake_name(dir: Dir, typ: HandshakeType, body_with_header: &[u8]) -> &'static str {
    match (dir, typ) {
        (_, HandshakeType::ClientHello) => "CH",
        (_, HandshakeType::ServerHello) => {
            match MessagePayload::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_3,
                body_with_header,
            ) {
                Ok(MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(_)),
                    ..
                }) => "HRR",
                _ => "SH",
            }
        }
        (_, HandshakeType::NewSessionTicket) => "NST",
        (_, HandshakeType::EndOfEarlyData) => "EOED",
        (_, HandshakeType::EncryptedExtensions) => "EE",
        (_, HandshakeType::Certificate) => "Cert",
        (_, HandshakeType::ServerKeyExchange) => "SKE",
        (_, HandshakeType::CertificateRequest) => "CR",
        (_, HandshakeType::ServerHelloDone) => "SHD",
        (_, HandshakeType::CertificateVerify) => "CV",
        (_, HandshakeType::ClientKeyExchange) => "CKE",
        (_, HandshakeType::Finished) => "Fin",
        (_, HandshakeType::KeyUpdate) => "KU",
        _ => "Other",
    }
}

impl Run {
    fn offer(&self, message: &[u8]) -> Offer {
        let Ok(MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(hello)),
            ..
        }) = MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_2, message)
        else {
            panic!("{}: a ClientHello that does not parse", self.name);
        };
        let tls13 = hello
            .supported_versions
            .as_ref()
            .is_some_and(|versions| versions.tls13);
        // The group the server picks: the client's first that it supports.
        let picked = hello
            .named_groups
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|group| self.server_groups.contains(group));
        let share = hello
            .key_shares
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|share| Some(&share.group) == picked);
        match tls13 {
            true => Offer {
                v: "13",
                sh: share,
                ed: hello.early_data_request.is_some(),
                pk: hello.preshared_key_offer.is_some(),
                em: false,
                ss: "none",
            },
            false => Offer {
                v: "12",
                sh: false,
                ed: false,
                pk: false,
                em: hello.extended_master_secret_request.is_some(),
                ss: self.session,
            },
        }
    }

    /// The run's log.
    fn entries(&self) -> Vec<Entry> {
        let hello = |w: &&Wire, typ: u8| w.typ == 22 && w.body.first() == Some(&typ);
        let client_hello = self
            .wire
            .iter()
            .find(|w| w.dir == Dir::In && hello(w, 1))
            .expect("a run starts with a ClientHello");
        let client_random = client_hello.body[6..38].to_vec();
        // The ServerHello (not a HelloRetryRequest): suite, random, version.
        let server_hello = self.wire.iter().find_map(|w| {
            if w.dir != Dir::Out || !hello(&w, 2) {
                return None;
            }
            match MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_3, &w.body) {
                Ok(MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::ServerHello(sh)),
                    ..
                }) => Some((
                    sh.cipher_suite,
                    sh.random.0,
                    sh.extensions.selected_version.is_some(),
                )),
                _ => None,
            }
        });
        let (mut inward, mut outward) = match server_hello {
            Some((negotiated, _, true)) => {
                let SupportedCipherSuite::Tls13(suite) = TLS13_AES_128_GCM_SHA256 else {
                    unreachable!()
                };
                assert_eq!(negotiated, suite.common.suite);
                (
                    Direction::tls13(suite, &self.keys, &client_random, Dir::In),
                    Direction::tls13(suite, &self.keys, &client_random, Dir::Out),
                )
            }
            Some((suite, server_random, false)) => {
                let SupportedCipherSuite::Tls12(suite12) = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                else {
                    unreachable!()
                };
                assert_eq!(suite, suite12.common.suite);
                match self.keys.get("CLIENT_RANDOM", &client_random) {
                    Some(master) => {
                        let mut client = [0u8; 32];
                        client.copy_from_slice(&client_random);
                        let randoms = ConnectionRandoms {
                            client,
                            server: server_random,
                        };
                        let secrets = ConnectionSecrets::new_resume(randoms, suite12, &master);
                        (
                            Direction::tls12(Some(secrets.make_cipher_pair(Side::Server).0)),
                            Direction::tls12(Some(secrets.make_cipher_pair(Side::Client).0)),
                        )
                    }
                    None => (Direction::tls12(None), Direction::tls12(None)),
                }
            }
            None => (Direction::tls12(None), Direction::tls12(None)),
        };

        let mut entries = Vec::new();
        for w in &self.wire {
            let direction = match w.dir {
                Dir::In => &mut inward,
                Dir::Out => &mut outward,
            };
            let d = match w.dir {
                Dir::In => "recv",
                Dir::Out => "send",
            };
            let (epoch, typ, plain) = direction.open(w.typ, &w.body);
            let entry = |m, x, co, ch| Entry {
                d,
                m,
                e: epoch.clone(),
                x,
                co,
                ch,
            };
            match typ {
                20 => entries.push(entry("CCS", "", false, None)),
                21 => {
                    let x = match (plain[0], plain[1]) {
                        (2, _) => "fatal",
                        (_, 0) => "close",
                        (_, 100) => "noreneg",
                        _ => "warn",
                    };
                    entries.push(entry("Alert", x, false, None));
                }
                23 => entries.push(entry("AD", "", false, None)),
                22 => {
                    direction.pending.extend_from_slice(&plain);
                    let mut messages = Vec::new();
                    loop {
                        let pending = &direction.pending;
                        if pending.len() < 4 {
                            break;
                        }
                        let len = usize::from(pending[1]) << 16
                            | usize::from(pending[2]) << 8
                            | usize::from(pending[3]);
                        if pending.len() < 4 + len {
                            break;
                        }
                        messages.push(direction.pending.drain(..4 + len).collect::<Vec<u8>>());
                    }
                    let count = messages.len();
                    for (i, message) in messages.iter().enumerate() {
                        let co = i + 1 < count || !direction.pending.is_empty();
                        let typ = HandshakeType::from(message[0]);
                        let m = handshake_name(w.dir, typ, message);
                        let body = &message[4..];
                        let x = match (w.dir, m) {
                            (Dir::In, "Cert") => {
                                // TLS 1.3 starts with the request context.
                                let at = match epoch.as_str() {
                                    "hs" => 1 + usize::from(body[0]),
                                    _ => 0,
                                };
                                match body[at..at + 3] == [0, 0, 0] {
                                    true => "empty",
                                    false => "full",
                                }
                            }
                            (Dir::In, "CV") => "ok",
                            (Dir::In, "Fin") => match self.finished_ok {
                                true => "ok",
                                false => "bad",
                            },
                            (_, "KU") => match body[0] {
                                1 => "req",
                                _ => "noreq",
                            },
                            _ => "",
                        };
                        let ch = (m == "CH" && w.dir == Dir::In).then(|| self.offer(message));
                        entries.push(entry(m, x, co, ch));
                    }
                }
                _ => panic!("{}: a record of type {typ}", self.name),
            }
        }
        entries
    }

    /// Writes the log as a TLA+ module and config, if asked to.
    fn write(&self, departure: bool) -> Vec<Entry> {
        let entries = self.entries();
        assert!(
            entries.iter().all(|e| e.m != "Other"),
            "{}: a message the spec has no name for",
            self.name
        );
        let Some(dir) = std::env::var_os("FICTIONET_TLS_TRACE_DIR") else {
            return entries;
        };
        let module = format!(
            "{}_{}",
            if departure { "HsDeparture" } else { "HsLog" },
            self.name
        );
        let mut tla = format!(
            "---- MODULE {module} ----\n(* The handshake `{}` as the server saw it, written by \
             rustls/src/server/hs_trace.rs. *)\nEXTENDS HandshakeTrace\n\nTraceLog == <<\n",
            self.name
        );
        for (i, e) in entries.iter().enumerate() {
            let ch = e.ch.clone().unwrap_or(Offer {
                v: "",
                sh: false,
                ed: false,
                pk: false,
                em: false,
                ss: "none",
            });
            write!(
                tla,
                "  [d |-> \"{}\", m |-> \"{}\", e |-> \"{}\", x |-> \"{}\", co |-> {}, \
                 ch |-> [v |-> \"{}\", sh |-> {}, ed |-> {}, pk |-> {}, em |-> {}, ss |-> \"{}\"]]{}\n",
                e.d,
                e.m,
                e.e,
                e.x,
                tla_bool(e.co),
                ch.v,
                tla_bool(ch.sh),
                tla_bool(ch.ed),
                tla_bool(ch.pk),
                tla_bool(ch.em),
                ch.ss,
                if i + 1 < entries.len() { "," } else { "" }
            )
            .unwrap();
        }
        tla.push_str(">>\n====\n");
        let received = entries.iter().filter(|e| e.d == "recv").count();
        let alone = entries
            .iter()
            .filter(|e| e.d == "send" && (e.m == "AD" || e.m == "NST"))
            .count();
        let cfg = format!(
            "INIT TraceInit\nNEXT TraceNext\nCHECK_DEADLOCK FALSE\nCONSTANTS\n  Log <- TraceLog\n  \
             Versions = {{\"13\", \"12\"}}\n  MaxEarly = 8\n  Skip = 8\n  MaxRecv = {received}\n  \
             MaxSend = {alone}\n  MaxKU = 3\n  CoMsgs = {{\"CH\", \"EOED\", \"Fin\", \"KU\"}}\n\
             INVARIANT LogUnfinished\n"
        );
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{module}.tla")), tla).unwrap();
        std::fs::write(dir.join(format!("{module}.cfg")), cfg).unwrap();
        entries
    }
}

fn tla_bool(b: bool) -> &'static str {
    match b {
        true => "TRUE",
        false => "FALSE",
    }
}

// ---------------------------------------------------------------------------
// The runs

fn memory_storage() -> Arc<dyn crate::server::StoresServerSessions> {
    crate::server::ServerSessionMemoryCache::new(32)
}

/// A whole handshake and an echo each way.
fn plain_run(
    name: &str,
    server: &ServerSetup,
    client_setup: &ClientSetup,
    storage: &Arc<dyn crate::server::StoresServerSessions>,
    resumption: &Resumption,
) -> Run {
    let keys = Arc::new(Keys::default());
    let mut run = Run::new(name, &keys, server);
    let mut s = ServerConnection::new(server_config(server, storage, &keys)).unwrap();
    let mut c = client(client_config(client_setup, resumption, &keys));
    run.handshake(&mut c, &mut s);
    run.echo(&mut c, &mut s, b"hello");
    run
}

#[test]
fn tls13_full_hrr_and_resumption() {
    let storage = memory_storage();
    let resumption = Resumption::in_memory_sessions(8);
    let server = ServerSetup::default();
    let first = plain_run(
        "tls13_full",
        &server,
        &ClientSetup::new(&TLS13),
        &storage,
        &resumption,
    );
    first.write(false);
    let again = plain_run(
        "tls13_resumed",
        &server,
        &ClientSetup::new(&TLS13),
        &storage,
        &resumption,
    );
    let entries = again.write(false);
    assert!(
        entries
            .iter()
            .any(|e| e.ch.as_ref().is_some_and(|ch| ch.pk)),
        "the second hello offers the ticket"
    );

    // A key share for a group the server does not pick.
    let server = ServerSetup {
        groups: vec![X25519],
        ..ServerSetup::default()
    };
    let client_setup = ClientSetup {
        groups: vec![SECP256R1, X25519],
        ..ClientSetup::new(&TLS13)
    };
    let hrr = plain_run(
        "tls13_hrr",
        &server,
        &client_setup,
        &memory_storage(),
        &Resumption::in_memory_sessions(8),
    );
    let entries = hrr.write(false);
    assert!(entries.iter().any(|e| e.m == "HRR"));
}

#[test]
fn tls13_client_auth_and_half_rtt() {
    for (name, mandatory, cert) in [
        ("tls13_client_auth", true, true),
        ("tls13_client_auth_empty", false, false),
    ] {
        let server = ServerSetup {
            auth: Some(mandatory),
            ..ServerSetup::default()
        };
        let client_setup = ClientSetup {
            cert,
            ..ClientSetup::new(&TLS13)
        };
        let run = plain_run(
            name,
            &server,
            &client_setup,
            &memory_storage(),
            &Resumption::in_memory_sessions(8),
        );
        run.write(false);
    }

    // 0.5-RTT: the server writes once it has answered the hello.
    let keys = Arc::new(Keys::default());
    let server = ServerSetup {
        half_rtt: true,
        ..ServerSetup::default()
    };
    let mut run = Run::new("tls13_half_rtt", &keys, &server);
    let mut s = ServerConnection::new(server_config(&server, &memory_storage(), &keys)).unwrap();
    let mut c = client(client_config(
        &ClientSetup::new(&TLS13),
        &Resumption::in_memory_sessions(8),
        &keys,
    ));
    run.to_server(&mut c, &mut s).unwrap();
    assert!(s.is_handshaking());
    assert_eq!(s.writer().write(b"early answer").unwrap(), 12);
    run.handshake(&mut c, &mut s);
    let mut got = Vec::new();
    let _ = c.reader().read_to_end(&mut got);
    assert!(got == b"early answer");
    run.write(false);
}

#[test]
fn tls13_key_updates_both_ways() {
    let keys = Arc::new(Keys::default());
    let server = ServerSetup::default();
    let mut run = Run::new("tls13_key_update", &keys, &server);
    let mut s = ServerConnection::new(server_config(&server, &memory_storage(), &keys)).unwrap();
    let mut c = client(client_config(
        &ClientSetup::new(&TLS13),
        &Resumption::in_memory_sessions(8),
        &keys,
    ));
    run.handshake(&mut c, &mut s);
    // The client asks for an update; the server answers before its data.
    c.refresh_traffic_keys().unwrap();
    run.echo(&mut c, &mut s, b"after the client's update");
    // The server asks; the client answers before its data.
    s.refresh_traffic_keys().unwrap();
    run.to_client(&mut s, &mut c).unwrap();
    run.echo(&mut c, &mut s, b"after the server's update");
    let entries = run.write(false);
    assert_eq!(entries.iter().filter(|e| e.m == "KU").count(), 4);
}

/// A first connection that leaves the client a ticket good for early data.
fn early_ticket(storage: &Arc<dyn crate::server::StoresServerSessions>, resumption: &Resumption) {
    let server = ServerSetup {
        early: 1024,
        ..ServerSetup::default()
    };
    let client_setup = ClientSetup {
        early: true,
        ..ClientSetup::new(&TLS13)
    };
    plain_run(
        "tls13_early_ticket",
        &server,
        &client_setup,
        storage,
        resumption,
    );
}

/// A connection that sends early data to a server set up as `server`.
/// With `coalesce`, the client's EndOfEarlyData and Finished are put into
/// one record under the early keys.
fn early_run(
    name: &str,
    server: &ServerSetup,
    groups: Vec<&'static dyn SupportedKxGroup>,
    coalesce: bool,
) -> (Run, bool) {
    let storage = memory_storage();
    let resumption = Resumption::in_memory_sessions(8);
    early_ticket(&storage, &resumption);
    let keys = Arc::new(Keys::default());
    let mut run = Run::new(name, &keys, server);
    let mut s = ServerConnection::new(server_config(server, &storage, &keys)).unwrap();
    let client_setup = ClientSetup {
        early: true,
        groups,
        ..ClientSetup::new(&TLS13)
    };
    let mut c = client(client_config(&client_setup, &resumption, &keys));
    let written = c
        .early_data()
        .expect("the ticket allows early data")
        .write(b"early")
        .unwrap();
    assert_eq!(written, 5);
    run.to_server(&mut c, &mut s).unwrap();
    run.to_client(&mut s, &mut c).unwrap();
    if coalesce {
        let bytes = drain_client(&mut c);
        let bytes = coalesce_eoed(&keys, &run, &bytes);
        run.note(Dir::In, &bytes);
        if feed_server(&mut s, &bytes).is_err() {
            run.server_output(&mut s);
            return (run, false);
        }
        run.to_client(&mut s, &mut c).unwrap();
    }
    run.handshake(&mut c, &mut s);
    run.echo(&mut c, &mut s, b"after");
    let accepted = c.is_early_data_accepted();
    (run, accepted)
}

/// The client's second flight with its EndOfEarlyData record and its
/// Finished record joined into one record under the early keys.
fn coalesce_eoed(keys: &Keys, run: &Run, bytes: &[u8]) -> Vec<u8> {
    let SupportedCipherSuite::Tls13(suite) = TLS13_AES_128_GCM_SHA256 else {
        unreachable!()
    };
    let hello = run
        .wire
        .iter()
        .find(|w| w.dir == Dir::In && w.typ == 22)
        .unwrap();
    let random = &hello.body[6..38];
    let early = keys.get("CLIENT_EARLY_TRAFFIC_SECRET", random).unwrap();
    let hs = keys.get("CLIENT_HANDSHAKE_TRAFFIC_SECRET", random).unwrap();
    let early_records = run
        .wire
        .iter()
        .filter(|w| w.dir == Dir::In && w.typ == 23)
        .count() as u64;
    let records = split(bytes);
    let protected: Vec<usize> = (0..records.len()).filter(|&i| records[i].0 == 23).collect();
    let open = |secret: &[u8], seq: u64, body: &[u8]| {
        let mut buf = body.to_vec();
        let message = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut buf,
        );
        let plain = tls13_decrypter(suite, secret)
            .decrypt(message, seq)
            .unwrap();
        assert_eq!(plain.typ, ContentType::Handshake);
        plain.payload.to_vec()
    };
    let mut joined = open(&early, early_records, &records[protected[0]].1);
    joined.extend(open(&hs, 0, &records[protected[1]].1));
    let sealed = tls13_encrypter(suite, &early)
        .encrypt(
            OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: joined.as_slice().into(),
            },
            early_records,
        )
        .unwrap()
        .encode();
    let mut out = Vec::new();
    for (i, (typ, body)) in records.iter().enumerate() {
        if i == protected[0] {
            out.extend_from_slice(&sealed);
        } else if i != protected[1] {
            out.extend(record(*typ, body));
        }
    }
    out
}

#[test]
fn tls13_early_data_accepted_rejected_and_after_hrr() {
    let accepting = ServerSetup {
        early: 1024,
        ..ServerSetup::default()
    };
    let (run, accepted) = early_run(
        "tls13_early_accepted",
        &accepting,
        vec![X25519, SECP256R1],
        false,
    );
    assert!(accepted, "the server took the early data");
    run.write(false);

    // The same ticket, a server that takes no early data: trial decryption.
    let rejecting = ServerSetup::default();
    let (run, accepted) = early_run(
        "tls13_early_rejected",
        &rejecting,
        vec![X25519, SECP256R1],
        false,
    );
    assert!(!accepted);
    run.write(false);

    // Early data offered, a HelloRetryRequest: skipped as application data.
    let other_group = ServerSetup {
        groups: vec![SECP256R1],
        early: 1024,
        ..ServerSetup::default()
    };
    let (run, accepted) = early_run(
        "tls13_early_hrr",
        &other_group,
        vec![X25519, SECP256R1],
        false,
    );
    assert!(!accepted);
    let entries = run.write(false);
    assert!(entries.iter().any(|e| e.m == "HRR"));
}

/// RFC 8446 5.1: EndOfEarlyData must end its record, as the read key
/// changes after it. A Finished sharing its record, under the early keys,
/// is refused with a fatal alert. (rustls took it before the fix; the log
/// was then a departure, not a behavior of the spec.)
#[test]
fn tls13_end_of_early_data_sharing_a_record() {
    let accepting = ServerSetup {
        early: 1024,
        ..ServerSetup::default()
    };
    let (run, _) = early_run(
        "tls13_eoed_coalesced",
        &accepting,
        vec![X25519, SECP256R1],
        true,
    );
    let entries = run.write(false);
    assert!(entries.iter().any(|e| e.m == "EOED" && e.co));
    assert!(entries
        .last()
        .is_some_and(|e| e.m == "Alert" && e.x == "fatal"));
}

#[test]
fn tls12_full_auth_and_resumption() {
    let storage = memory_storage();
    let resumption = Resumption::in_memory_sessions(8);
    let server = ServerSetup::default();
    plain_run(
        "tls12_full",
        &server,
        &ClientSetup::new(&TLS12),
        &storage,
        &resumption,
    )
    .write(false);
    let mut again = plain_run(
        "tls12_resumed",
        &server,
        &ClientSetup::new(&TLS12),
        &storage,
        &resumption,
    );
    again.session = "ems";
    let entries = again.write(false);
    assert!(entries.iter().any(|e| e.d == "send" && e.m == "CCS"));

    let server = ServerSetup {
        auth: Some(true),
        ..ServerSetup::default()
    };
    let client_setup = ClientSetup {
        cert: true,
        ..ClientSetup::new(&TLS12)
    };
    plain_run(
        "tls12_client_auth",
        &server,
        &client_setup,
        &memory_storage(),
        &Resumption::in_memory_sessions(8),
    )
    .write(false);

    // Tickets instead of session ids.
    let storage = memory_storage();
    let resumption = Resumption::in_memory_sessions(8);
    let server = ServerSetup {
        ticketer: true,
        ..ServerSetup::default()
    };
    plain_run(
        "tls12_ticket_full",
        &server,
        &ClientSetup::new(&TLS12),
        &storage,
        &resumption,
    )
    .write(false);
    let mut again = plain_run(
        "tls12_ticket_resumed",
        &server,
        &ClientSetup::new(&TLS12),
        &storage,
        &resumption,
    );
    again.session = "ems";
    again.write(false);
}

/// The client's hello without its extended_master_secret extension.
fn without_ems(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (typ, body) in split(bytes) {
        if typ == 22 && body[0] == 1 {
            let Ok(MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(mut hello)),
                ..
            }) = MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_2, &body)
            else {
                panic!("a ClientHello that does not parse");
            };
            assert!(hello.extended_master_secret_request.is_some());
            hello.extensions.extended_master_secret_request = None;
            let encoded =
                HandshakeMessagePayload(HandshakePayload::ClientHello(hello)).get_encoding();
            out.extend(record(22, &encoded));
        } else {
            out.extend(record(typ, &body));
        }
    }
    out
}

/// RFC 7627 5.3 with the hello stripped of extended master secret on the
/// way: a session that used it is not resumed; a full handshake goes on,
/// and the client's Finished then fails against the server's transcript.
#[test]
fn tls12_extended_master_secret_mismatch() {
    let storage = memory_storage();
    let resumption = Resumption::in_memory_sessions(8);
    let server = ServerSetup::default();
    plain_run(
        "tls12_ems_session",
        &server,
        &ClientSetup::new(&TLS12),
        &storage,
        &resumption,
    );

    let keys = Arc::new(Keys::default());
    let mut run = Run::new("tls12_ems_mismatch", &keys, &server);
    run.session = "ems";
    let mut s = ServerConnection::new(server_config(&server, &storage, &keys)).unwrap();
    let mut c = client(client_config(&ClientSetup::new(&TLS12), &resumption, &keys));
    let bytes = without_ems(&drain_client(&mut c));
    run.note(Dir::In, &bytes);
    assert!(
        feed_server(&mut s, &bytes).is_err(),
        "the server refuses to resume"
    );
    run.server_output(&mut s);
    let entries = run.write(false);
    assert!(entries
        .last()
        .is_some_and(|e| e.m == "Alert" && e.x == "fatal"));

    // No session: a full handshake without EMS; the transcripts differ.
    let keys = Arc::new(Keys::default());
    let mut run = Run::new("tls12_bad_finished", &keys, &server);
    run.finished_ok = false;
    let mut s = ServerConnection::new(server_config(&server, &memory_storage(), &keys)).unwrap();
    let mut c = client(client_config(
        &ClientSetup::new(&TLS12),
        &Resumption::disabled(),
        &keys,
    ));
    let bytes = without_ems(&drain_client(&mut c));
    run.note(Dir::In, &bytes);
    feed_server(&mut s, &bytes).unwrap();
    run.to_client(&mut s, &mut c).unwrap();
    let bytes = drain_client(&mut c);
    run.note(Dir::In, &bytes);
    assert!(
        feed_server(&mut s, &bytes).is_err(),
        "the server refuses the Finished"
    );
    run.server_output(&mut s);
    let entries = run.write(false);
    assert!(entries
        .last()
        .is_some_and(|e| e.m == "Alert" && e.x == "fatal"));
}

/// A flight the budget has no room for, given back by into_connection and
/// converted again: the log is a behavior, and the same as a run that was
/// never refused.
#[test]
fn a_refused_flight_retried_does_what_the_first_would_have() {
    for (name, version) in [("budget_retry13", &TLS13), ("budget_retry12", &TLS12)] {
        let server = ServerSetup::default();
        let storage = memory_storage();
        let mut logs = Vec::new();
        for refuse in [true, false] {
            let keys = Arc::new(Keys::default());
            let mut run = Run::new(name, &keys, &server);
            let config = server_config(&server, &storage, &keys);
            let limit = Limit::new(1 << 20);
            let mut acceptor = Acceptor::with_budget(limit.clone());
            let mut c = client(client_config(
                &ClientSetup::new(version),
                &Resumption::disabled(),
                &keys,
            ));
            let bytes = drain_client(&mut c);
            run.note(Dir::In, &bytes);
            let mut rest = &bytes[..];
            let mut accepted = loop {
                acceptor.read_tls(&mut rest).unwrap();
                if let Some(accepted) = acceptor.accept().unwrap() {
                    break accepted;
                }
            };
            if refuse {
                limit.set_limit(limit.used());
                for _ in 0..2 {
                    accepted = match accepted.into_connection(config.clone()) {
                        Err(IntoConnectionError::Unpaid(accepted)) => *accepted,
                        _ => panic!("{name}: the flight went without room"),
                    };
                }
                limit.set_limit(1 << 20);
            }
            let mut s = accepted.into_connection(config).unwrap();
            run.handshake(&mut c, &mut s);
            run.echo(&mut c, &mut s, b"paid");
            logs.push(if refuse {
                run.write(false)
            } else {
                run.entries()
            });
        }
        assert!(
            logs[0] == logs[1],
            "{name}: the retried run is the run never refused"
        );
    }
}

/// A ServerConnection answering its first hello in process_new_packets has
/// no Accepted to give back: a flight without room fails the connection,
/// with nothing sent (hs.rs ExpectClientHello::handle).
#[test]
fn a_refused_flight_inside_the_connection_fails_it_silently() {
    let server = ServerSetup::default();
    let mut found = false;
    for room in (0..40_000).step_by(256) {
        let keys = Arc::new(Keys::default());
        let mut run = Run::new("budget_refused_in_connection", &keys, &server);
        let limit = Limit::new(1 << 20);
        let mut s = ServerConnection::with_budget(
            server_config(&server, &memory_storage(), &keys),
            limit.clone(),
        )
        .unwrap();
        let mut c = client(client_config(
            &ClientSetup::new(&TLS13),
            &Resumption::disabled(),
            &keys,
        ));
        let bytes = drain_client(&mut c);
        let mut rest = &bytes[..];
        s.read_tls(&mut rest).unwrap();
        assert!(rest.is_empty());
        limit.set_limit(limit.used() + room);
        match s.process_new_packets() {
            Err(Error::BudgetExhausted) => {
                run.note(Dir::In, &bytes);
                assert!(!s.wants_write(), "nothing is sent");
                run.server_output(&mut s);
                run.write(false);
                found = true;
                break;
            }
            Ok(_) if s.wants_write() => break,
            _ => {}
        }
    }
    assert!(found, "some room reads the hello and refuses the flight");
}
