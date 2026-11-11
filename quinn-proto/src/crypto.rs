//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic in Quinn is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer as well as a single implementation of these traits that uses
//! *ring* and rustls to implement the TLS protocol support.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::{any::Any, str, sync::Arc};

use bytes::BytesMut;

use crate::{
    shared::ConnectionId, transport_parameters::TransportParameters, ConnectError, Side,
    TransportError,
};

/// Cryptography interface based on *ring*
#[cfg(feature = "ring")]
pub(crate) mod ring_like;
/// TLS interface based on rustls
#[cfg(feature = "rustls-ring")]
pub mod rustls;

/// A cryptographic session (commonly TLS)
pub trait Session: Send + Sync + 'static {
    /// Create the Initial keys of `version` given the client's initial destination ConnectionId
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, UnsupportedVersion>;

    /// The most heap bytes live at once while [`initial_keys`](Self::initial_keys)
    /// derives a set, the keys it returns included: what a budget is charged
    /// before a derivation
    fn initial_keys_charge(&self) -> usize;

    /// Switch to a compatible version (RFC 9368 section 2.3) before handshake keys exist
    ///
    /// Handshake and 1-RTT keys then use `version`, and so does the check of
    /// a server's Chosen Version. A server still expects the client's Chosen
    /// Version to be the version the session started with. 0-RTT keys keep
    /// that version too.
    fn set_negotiated_version(&mut self, version: u32) -> Result<(), UnsupportedVersion>;

    /// Get data negotiated during the handshake, if available
    ///
    /// Returns `None` until the connection emits `HandshakeDataReady`.
    fn handshake_data(&self) -> Option<Box<dyn Any>>;

    /// Get the peer's identity, if available
    fn peer_identity(&self) -> Option<Box<dyn Any>>;

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer. This method will only return `true` the first time that
    /// handshake data is available. Future calls will always return false.
    ///
    /// On success, returns `true` iff `self.handshake_data()` has been populated.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError>;

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Writes handshake bytes into the given buffer and optionally returns the negotiated keys
    ///
    /// When the handshake proceeds to the next phase, this method will return a new set of
    /// keys to encrypt data with.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>>;

    /// Whether `pseudo_packet`, the Retry Pseudo-Packet of a Retry of wire
    /// `version` followed by the Retry's integrity tag (RFC 9001 section
    /// 5.8), carries a valid tag
    fn is_valid_retry(&self, version: u32, pseudo_packet: &mut [u8]) -> bool;

    /// Fill `output` with `output.len()` bytes of keying material derived
    /// from the [Session]'s secrets, using `label` and `context` for domain
    /// separation.
    ///
    /// This function will fail, returning [ExportKeyingMaterialError],
    /// if the requested output length is too large.
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError>;
}

/// A pair of keys for bidirectional communication
pub struct KeyPair<T> {
    /// Key for encrypting data
    pub local: T,
    /// Key for decrypting data
    pub remote: T,
}

/// A complete set of keys for a certain packet space
pub struct Keys {
    /// Header protection keys
    pub header: KeyPair<Box<dyn HeaderKey>>,
    /// Packet protection keys
    pub packet: KeyPair<Box<dyn PacketKey>>,
}

impl Keys {
    /// Heap bytes of the four keys, including their boxes
    pub fn heap_size(&self) -> usize {
        size_of_val(&*self.header.local)
            + self.header.local.heap_size()
            + size_of_val(&*self.header.remote)
            + self.header.remote.heap_size()
            + size_of_val(&*self.packet.local)
            + self.packet.local.heap_size()
            + size_of_val(&*self.packet.remote)
            + self.packet.remote.heap_size()
    }
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig: Send + Sync {
    /// Start a client session with this configuration
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion>;

    /// The most heap bytes live at once while [`initial_keys`](Self::initial_keys)
    /// derives a set, the keys it returns included
    fn initial_keys_charge(&self) -> usize;

    /// The integrity tag of a Retry whose Retry Pseudo-Packet (RFC 9001
    /// section 5.8) is `pseudo_packet`
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn retry_tag(&self, version: u32, pseudo_packet: &[u8]) -> [u8; 16];

    /// Start a server session with this configuration
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session>;
}

/// Keys used to protect packet payloads
pub trait PacketKey: Send + Sync {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    /// Decrypt the packet payload with the given packet number
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError>;
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
    /// Maximum number of packets that may be sent using a single key
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned
    fn integrity_limit(&self) -> u64;
    /// Heap bytes this key occupies, so storage for another key can be charged first
    fn heap_size(&self) -> usize;
}

/// Keys used to protect packet headers
pub trait HeaderKey: Send + Sync {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
    /// Heap bytes this key occupies, so storage for another key can be charged first
    fn heap_size(&self) -> usize;
}

/// A key for signing with HMAC-based algorithms
pub trait HmacKey: Send + Sync {
    /// Method for signing a message
    fn sign(&self, data: &[u8], signature_out: &mut [u8]);
    /// Length of `sign`'s output
    fn signature_len(&self) -> usize;
    /// Method for verifying a message
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// Error returned by [Session::export_keying_material].
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportKeyingMaterialError;

/// The length of a token's AEAD tag
pub const TOKEN_TAG_LEN: usize = 16;

/// A pseudo random key for HKDF, from which each token's AEAD key is derived
///
/// Both operations work in place, so a token is sealed in the buffer it is
/// sent from and opened in the caller's storage.
pub trait HandshakeTokenKey: Send + Sync {
    /// Seal `data` in place under the key derived from `random_bytes`,
    /// returning the tag
    fn seal(
        &self,
        random_bytes: &[u8],
        data: &mut [u8],
        additional_data: &[u8],
    ) -> Result<[u8; TOKEN_TAG_LEN], CryptoError>;
    /// Open `data`, a sealed message followed by its tag, in place under
    /// the key derived from `random_bytes`, returning the message
    fn open<'a>(
        &self,
        random_bytes: &[u8],
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError>;
}

/// Generic crypto errors
#[derive(Debug)]
pub struct CryptoError;

/// Error indicating that the specified QUIC version is not supported
#[derive(Debug)]
pub struct UnsupportedVersion;

impl From<UnsupportedVersion> for ConnectError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}
