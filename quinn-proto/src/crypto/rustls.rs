use std::{any::Any, io, str, sync::Arc};

use bytes::BytesMut;
#[cfg(feature = "ring")]
use ring::aead;
pub use rustls::Error;
#[cfg(feature = "__rustls-post-quantum-test")]
use rustls::NamedGroup;
use rustls::{
    self,
    client::danger::ServerCertVerifier,
    crypto::tls13::OkmBlock,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    quic::{Connection, HeaderProtectionKey, KeyChange, PacketKey, Secrets, Suite, Version},
    CipherSuite,
};

use crate::{
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
    version::{QUIC_V1, QUIC_V2},
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
};

impl From<Side> for rustls::Side {
    fn from(s: Side) -> Self {
        match s {
            Side::Client => Self::Client,
            Side::Server => Self::Server,
        }
    }
}

/// A rustls TLS session
pub struct TlsSession {
    /// The version of the session's first flight
    original_version: u32,
    /// The negotiated version, used for handshake and 1-RTT keys
    wire_version: u32,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    inner: Connection,
    suite: InitialSuite,
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, UnsupportedVersion> {
        Ok(initial_keys(
            interpret_version(version)?,
            *dst_cid,
            side,
            &self.suite.suite,
        ))
    }

    fn initial_keys_charge(&self) -> usize {
        self.suite.charge
    }

    fn set_negotiated_version(&mut self, version: u32) -> Result<(), UnsupportedVersion> {
        let negotiated = interpret_version(version)?;
        match &mut self.inner {
            Connection::Client(conn) => conn.set_negotiated_version(negotiated),
            Connection::Server(conn) => conn.set_negotiated_version(negotiated),
        }
        .map_err(|_| UnsupportedVersion)?;
        self.wire_version = version;
        Ok(())
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.inner.alpn_protocol().map(|x| x.into()),
            server_name: match self.inner {
                Connection::Client(_) => None,
                Connection::Server(ref session) => session.server_name().map(|x| x.into()),
            },
            #[cfg(feature = "__rustls-post-quantum-test")]
            negotiated_key_exchange_group: self
                .inner
                .negotiated_key_exchange_group()
                .expect("key exchange group is negotiated")
                .name(),
        }))
    }

    /// For the rustls `TlsSession`, the `Any` type is `Vec<rustls::pki_types::CertificateDer>`
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_certificates().map(|v| -> Box<dyn Any> {
            Box::new(
                v.iter()
                    .map(|v| v.clone().into_owned())
                    .collect::<Vec<CertificateDer<'static>>>(),
            )
        })
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: e.to_string(),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {e}"))
            }
        })?;
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.server_name().is_some(),
            };
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            // A client's Chosen Version is the version of its first flight
            // (RFC 9368 section 4); a server's is the negotiated version.
            Some(buf) => match TransportParameters::read_for_version(
                self.side(),
                match self.side() {
                    Side::Server => self.original_version,
                    Side::Client => self.wire_version,
                },
                &mut io::Cursor::new(buf),
            ) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

        Some(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn is_valid_retry(&self, version: u32, pseudo_packet: &mut [u8]) -> bool {
        is_valid_retry(version, pseudo_packet)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner
            .export_keying_material(output, label, Some(context))
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

const RETRY_INTEGRITY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

// RFC 9369 section 3.3.3
const RETRY_INTEGRITY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const RETRY_INTEGRITY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

/// The Retry Integrity Tag nonce and key of a version (RFC 9001 section 5.8,
/// RFC 9369 section 3.3.3)
fn retry_integrity(version: Version) -> Option<([u8; 12], [u8; 16])> {
    match version {
        Version::V1Draft => Some((RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT)),
        Version::V1 => Some((RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1)),
        Version::V2 => Some((RETRY_INTEGRITY_NONCE_V2, RETRY_INTEGRITY_KEY_V2)),
        _ => None,
    }
}

impl crypto::HeaderKey for Box<dyn HeaderProtectionKey> {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }

    fn heap_size(&self) -> usize {
        // The rustls key behind this box; ring keys hold no further heap.
        size_of_val(&**self)
    }
}

/// Authentication data for (rustls) TLS session
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,
    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
    /// The key exchange group negotiated with the peer
    #[cfg(feature = "__rustls-post-quantum-test")]
    pub negotiated_key_exchange_group: NamedGroup,
}

/// A QUIC-compatible TLS client configuration
///
/// Quinn implicitly constructs a `QuicClientConfig` with reasonable defaults within
/// [`ClientConfig::with_root_certificates()`][root_certs].
/// Alternatively, `QuicClientConfig`'s [`TryFrom`] implementation can be used to wrap around a
/// custom [`rustls::ClientConfig`], in which case care should be taken around certain points:
///
/// - If `enable_early_data` is not set to true, then sending 0-RTT data will not be possible on
///   outgoing connections.
/// - The [`rustls::ClientConfig`] must have TLS 1.3 support enabled for conversion to succeed.
///
/// The object in the `resumption` field of the inner [`rustls::ClientConfig`] determines whether
/// calling `into_0rtt` on outgoing connections returns `Ok` or `Err`. It typically allows
/// `into_0rtt` to proceed if it recognizes the server name, and defaults to an in-memory cache of
/// 256 server names.
///
/// [root_certs]: crate::config::ClientConfig::with_root_certificates()
pub struct QuicClientConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
    initial: InitialSuite,
}

impl QuicClientConfig {
    /// Initialize a sane QUIC-compatible TLS client configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled. Advanced users can use any [`rustls::ClientConfig`] that
    /// satisfies this requirement.
    pub(crate) fn new(verifier: Arc<dyn ServerCertVerifier>) -> Self {
        let inner = Self::inner(verifier);
        Self {
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.crypto_provider())
                .map(InitialSuite::new)
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        }
    }

    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub fn with_initial(
        inner: Arc<rustls::ClientConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self {
                inner,
                initial: InitialSuite::new(initial),
            }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    pub(crate) fn inner(verifier: Arc<dyn ServerCertVerifier>) -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap() // The default providers support TLS 1.3
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        config.enable_early_data = true;
        config
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let wire_version = version;
        let version = interpret_version(version)?;
        Ok(Box::new(TlsSession {
            original_version: wire_version,
            wire_version,
            got_handshake_data: false,
            next_secrets: None,
            inner: rustls::quic::Connection::Client(
                rustls::quic::ClientConnection::new(
                    self.inner.clone(),
                    version,
                    ServerName::try_from(server_name)
                        .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?
                        .to_owned(),
                    to_vec(params),
                )
                .unwrap(),
            ),
            suite: self.initial,
        }))
    }
}

impl TryFrom<rustls::ClientConfig> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ClientConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ClientConfig>> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ClientConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .map(InitialSuite::new)
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

/// The initial cipher suite (AES-128-GCM-SHA256) is not available
///
/// When the cipher suite is supplied `with_initial()`, it must be
/// [`CipherSuite::TLS13_AES_128_GCM_SHA256`]. When the cipher suite is derived from a config's
/// [`CryptoProvider`][provider], that provider must reference a cipher suite with the same ID.
///
/// [provider]: rustls::crypto::CryptoProvider
#[derive(Clone, Debug)]
pub struct NoInitialCipherSuite {
    /// Whether the initial cipher suite was supplied by the caller
    specific: bool,
}

impl std::fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self.specific {
            true => "invalid cipher suite specified",
            false => "no initial cipher suite found",
        })
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// A QUIC-compatible TLS server configuration
///
/// Quinn implicitly constructs a `QuicServerConfig` with reasonable defaults within
/// [`ServerConfig::with_single_cert()`][single]. Alternatively, `QuicServerConfig`'s [`TryFrom`]
/// implementation or `with_initial` method can be used to wrap around a custom
/// [`rustls::ServerConfig`], in which case care should be taken around certain points:
///
/// - If `max_early_data_size` is not set to `u32::MAX`, the server will not be able to accept
///   incoming 0-RTT data. QUIC prohibits `max_early_data_size` values other than 0 or `u32::MAX`.
/// - The `rustls::ServerConfig` must have TLS 1.3 support enabled for conversion to succeed.
///
/// [single]: crate::config::ServerConfig::with_single_cert()
pub struct QuicServerConfig {
    inner: Arc<rustls::ServerConfig>,
    initial: InitialSuite,
}

impl QuicServerConfig {
    pub(crate) fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        let inner = Self::inner(cert_chain, key)?;
        Ok(Self {
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.crypto_provider())
                .map(InitialSuite::new)
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub fn with_initial(
        inner: Arc<rustls::ServerConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self {
                inner,
                initial: InitialSuite::new(initial),
            }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    /// Initialize a sane QUIC-compatible TLS server configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled, and that the maximum early data size is either 0 or
    /// `u32::MAX`. Advanced users can use any [`rustls::ServerConfig`] that satisfies these
    /// requirements.
    pub(crate) fn inner(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<rustls::ServerConfig, rustls::Error> {
        let mut inner = rustls::ServerConfig::builder_with_provider(configured_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap() // The *ring* default provider supports TLS 1.3
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        inner.max_early_data_size = u32::MAX;
        Ok(inner)
    }
}

impl TryFrom<rustls::ServerConfig> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rustls::ServerConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rustls::ServerConfig>> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: Arc<rustls::ServerConfig>) -> Result<Self, Self::Error> {
        Ok(Self {
            initial: initial_suite_from_provider(inner.crypto_provider())
                .map(InitialSuite::new)
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        let wire_version = version;
        let version = interpret_version(version).unwrap();
        Box::new(TlsSession {
            original_version: wire_version,
            wire_version,
            got_handshake_data: false,
            next_secrets: None,
            inner: rustls::quic::Connection::Server(
                rustls::quic::ServerConnection::new(self.inner.clone(), version, to_vec(params))
                    .unwrap(),
            ),
            suite: self.initial,
        })
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(
            version,
            *dst_cid,
            Side::Server,
            &self.initial.suite,
        ))
    }

    fn initial_keys_charge(&self) -> usize {
        self.initial.charge
    }

    fn retry_tag(&self, version: u32, pseudo_packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        retry_tag(version, pseudo_packet).unwrap()
    }
}

/// The Retry Integrity Tag of a Retry of `version` whose Retry Pseudo-Packet
/// is `pseudo_packet`
pub(crate) fn retry_tag(version: u32, pseudo_packet: &[u8]) -> Option<[u8; 16]> {
    let (nonce, key) = interpret_version(version).ok().and_then(retry_integrity)?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

    let tag = key
        .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
        .unwrap();
    let mut result = [0; 16];
    result.copy_from_slice(tag.as_ref());
    Some(result)
}

/// Whether `pseudo_packet`, a Retry Pseudo-Packet followed by the Retry's
/// tag, carries a valid tag for `version`
pub(crate) fn is_valid_retry(version: u32, pseudo_packet: &mut [u8]) -> bool {
    let Some((nonce, key)) = interpret_version(version).ok().and_then(retry_integrity) else {
        return false;
    };
    let Some(tag_start) = pseudo_packet.len().checked_sub(16) else {
        return false;
    };
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

    let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
    key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
}

/// The initial cipher suite with what a derivation of its Initial keys
/// holds at most
#[derive(Clone, Copy)]
struct InitialSuite {
    suite: Suite,
    /// The most heap bytes live at once while [`initial_keys`] derives a set
    charge: usize,
}

impl InitialSuite {
    /// Measures `suite` once, when a configuration is made. Sizes do not
    /// depend on the version or the connection ID.
    fn new(suite: Suite) -> Self {
        // rustls' `Keys::initial` holds the expander of the Initial secret
        // while each direction's `KeyBuilder` holds the expander of that
        // direction's secret, so at most two expanders live beside the keys.
        let keys = initial_keys(Version::V1, ConnectionId::new(&[]), Side::Client, &suite);
        let hkdf = suite.suite.hkdf_provider;
        let extracted = hkdf.extract_from_secret(None, &[]);
        let expanded = hkdf.expander_for_okm(&OkmBlock::new(&[0; 32]));
        let expander = size_of_val(&*extracted).max(size_of_val(&*expanded));
        Self {
            suite,
            charge: keys.heap_size() + 2 * expander,
        }
    }
}

pub(crate) fn initial_suite_from_provider(
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
}

pub(crate) fn configured_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "rustls-ring")]
    let provider = rustls::crypto::ring::default_provider();
    Arc::new(provider)
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

pub(crate) fn initial_keys(
    version: Version,
    dst_cid: ConnectionId,
    side: Side,
    suite: &Suite,
) -> Keys {
    let keys = suite.keys(&dst_cid, side.into(), version);
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}

impl crypto::PacketKey for Box<dyn PacketKey> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self.encrypt_in_place(packet, &*header, payload).unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .decrypt_in_place(packet, header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        (**self).confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        (**self).integrity_limit()
    }

    fn heap_size(&self) -> usize {
        // The rustls key behind this box; ring keys hold no further heap.
        size_of_val(&**self)
    }
}

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        QUIC_V1 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        QUIC_V2 => Ok(Version::V2),
        _ => Err(UnsupportedVersion),
    }
}

#[cfg(kani)]
#[path = "../../../verification/quic/kani/version_keys.rs"]
mod version_keys;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{Charged, Costs, Linear};

    /// Each derivation of Initial keys, in every version, for either side
    /// and any connection ID length, holds at most what it is charged
    /// before it starts, the keys included
    #[test]
    fn initial_key_derivations_stay_within_their_charge() {
        let provider = configured_provider();
        let suite = InitialSuite::new(initial_suite_from_provider(&provider).unwrap());
        let expander = size_of_val(
            &*suite
                .suite
                .suite
                .hkdf_provider
                .extract_from_secret(None, &[]),
        );
        let mut all = Costs::new("QUIC Initial keys");
        for version in [Version::V1Draft, Version::V1, Version::V2] {
            for side in [Side::Client, Side::Server] {
                for cid in [&[][..], &[7; 8][..], &[9; 20][..]] {
                    // A derivation copies nothing of its input. It asks for
                    // the keys and three expanders: one for the Initial
                    // secret and one for each direction's, two of them live
                    // at once.
                    let linear = Linear {
                        num: 0,
                        den: 1,
                        fixed: suite.charge + expander,
                    };
                    let mut costs = Costs::new("QUIC Initial keys");
                    let keys = costs.step(cid.len(), suite.charge, linear, || {
                        Charged::new(
                            initial_keys(version, ConnectionId::new(cid), side, &suite.suite),
                            0,
                        )
                    });
                    assert!(keys.heap_size() <= suite.charge);
                    all.absorb(&costs);
                }
            }
        }
        eprintln!("cost: QUIC Initial keys: {}", all.summary());
    }
}
