//! A server-side SSH transport with no I/O and caller-seeded randomness.
//!
//! Call [`Transport::seed`] before [`Transport::start`] or
//! [`Transport::start_identification`]. Feed bytes through
//! [`Decode`] and immediately pass each event to [`Transport::handle`] before
//! decoding the next packet, so NEWKEYS takes effect at its packet boundary.
//! Application messages use [`Transport::write_packet`]. Key exchange supports
//! Curve25519, NIST P-256 and P-384; host signatures support Ed25519 and RSA SHA-2.
//! Packets use OpenSSH ChaCha20-Poly1305 or AES-GCM with no compression.
//!
//! A transport error is fatal. The caller must close the connection. Each key
//! is limited to one GiB or one billion packets; call [`Transport::rekey`]
//! before reaching that limit. A new exchange preserves the first session ID.

use std::sync::Arc;

use p256::elliptic_curve::{sec1::ToSec1Point, zeroize::Zeroizing};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{Rng, SeedableRng},
};
use ring::{
    aead, digest,
    signature::{self, KeyPair},
};
use rsa::traits::PublicKeyParts;

use super::{
    Error, Identification, KexInit, Line, Lines, MAX_NAME, MAX_PACKET, MAX_PAYLOAD,
    MAX_VERSION_LINE, Message, Mpint, Packet, Reader, put_string,
};
use fictionet::stdlib::codec::{Decode, Heap, HeapBound, Step, Wire};

const CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];
const KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
];
const STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
const KEY_BYTES: u64 = 1 << 30;
const KEY_PACKETS: u64 = 1 << 30;
/// The one extension EXT_INFO names, and its value.
const SERVER_SIG_ALGS: (&[u8], &[u8]) =
    (b"server-sig-algs", b"ssh-ed25519,rsa-sha2-512,rsa-sha2-256");
/// An EXT_INFO payload: its number, the count of extensions, and the one
/// extension's name and value.
const EXT_INFO_LEN: usize = 1 + 4 + 4 + SERVER_SIG_ALGS.0.len() + 4 + SERVER_SIG_ALGS.1.len();

/// The sizes a key exchange method works with: the server's share, the
/// raw shared secret, and the hash.
struct Group {
    share: usize,
    secret: usize,
    hash: &'static digest::Algorithm,
}

impl Group {
    /// The method's sizes, or `None` for one this transport does not run.
    fn of(kex: &str) -> Option<Group> {
        let (share, secret, hash) = match kex {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => (32, 32, &digest::SHA256),
            "ecdh-sha2-nistp256" => (65, 32, &digest::SHA256),
            "ecdh-sha2-nistp384" => (97, 48, &digest::SHA384),
            _ => return None,
        };
        Some(Group {
            share,
            secret,
            hash,
        })
    }

    /// The shared secret as an mpint: its length, a sign byte, the bytes.
    fn encoded_secret(&self) -> usize {
        4 + 1 + self.secret
    }
}

/// A fatal framing, cryptographic, negotiation or state failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Invalid SSH framing or payload.
    Codec(Error),
    /// The peer sent a message outside the current exchange state.
    State,
    /// No supported algorithm was common to both peers.
    Algorithm,
    /// Invalid host key, peer key share, signature or authentication tag.
    Crypto,
    /// The caller has not provided a fresh connection seed.
    Unseeded,
    /// A key's byte, packet or nonce limit was reached.
    KeyExhausted,
}

fictionet::error_display!(TransportError, f, {
    TransportError::Codec(e) => std::fmt::Display::fmt(e, f),
    TransportError::State => f.write_str("unexpected SSH transport message"),
    TransportError::Algorithm => f.write_str("unsupported SSH algorithm negotiation"),
    TransportError::Crypto => f.write_str("SSH cryptographic verification failed"),
    TransportError::Unseeded => f.write_str("SSH transport requires a connection seed"),
    TransportError::KeyExhausted => f.write_str("SSH transport key limit reached"),
});

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        Self::Codec(e)
    }
}

/// A private host signing key. Debug output never contains key material.
pub struct HostKey {
    key: HostSecret,
    public: Vec<u8>,
}

enum HostSecret {
    Ed25519(signature::Ed25519KeyPair),
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostKey")
            .field("algorithms", &self.algorithms())
            .finish()
    }
}

impl HostKey {
    /// Builds an Ed25519 host key from a private seed supplied by the world.
    pub fn ed25519_from_seed(seed: [u8; 32]) -> Result<Self, TransportError> {
        let seed = Zeroizing::new(seed);
        let key = signature::Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| TransportError::Crypto)?;
        let mut public = Vec::new();
        put_string(&mut public, b"ssh-ed25519");
        put_string(&mut public, key.public_key().as_ref());
        Ok(Self {
            key: HostSecret::Ed25519(key),
            public,
        })
    }

    /// Imports a PKCS#1 DER RSA private key, with a 2048 to 8192 bit modulus.
    pub fn rsa_from_pkcs1(der: &[u8]) -> Result<Self, TransportError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        signature::RsaKeyPair::from_der(der).map_err(|_| TransportError::Crypto)?;
        Self::rsa(rsa::RsaPrivateKey::from_pkcs1_der(der).map_err(|_| TransportError::Crypto)?)
    }

    /// Imports a PKCS#8 DER RSA private key, with a 2048 to 8192 bit modulus.
    pub fn rsa_from_pkcs8(der: &[u8]) -> Result<Self, TransportError> {
        use rsa::pkcs8::DecodePrivateKey;
        signature::RsaKeyPair::from_pkcs8(der).map_err(|_| TransportError::Crypto)?;
        Self::rsa(rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(|_| TransportError::Crypto)?)
    }

    fn rsa(key: rsa::RsaPrivateKey) -> Result<Self, TransportError> {
        key.validate().map_err(|_| TransportError::Crypto)?;
        if !(2048..=8192).contains(&key.n().bits()) {
            return Err(TransportError::Crypto);
        }
        let mut public = Vec::new();
        put_string(&mut public, b"ssh-rsa");
        Mpint::from_unsigned_bytes(&key.e().to_bytes_be())?.write(&mut public)?;
        Mpint::from_unsigned_bytes(&key.n().to_bytes_be())?.write(&mut public)?;
        Ok(Self {
            key: HostSecret::Rsa(Box::new(key)),
            public,
        })
    }

    /// SSH public key blob, suitable for a known-host entry after base64 encoding.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Signature algorithms this key supports, in server preference order.
    pub fn algorithms(&self) -> &'static [&'static str] {
        match self.key {
            HostSecret::Ed25519(_) => &["ssh-ed25519"],
            HostSecret::Rsa(_) => &["rsa-sha2-512", "rsa-sha2-256"],
        }
    }

    /// The length of a raw signature: Ed25519's 64 bytes, or as many as
    /// the RSA modulus has.
    fn raw_signature_len(&self) -> usize {
        match &self.key {
            HostSecret::Ed25519(_) => 64,
            HostSecret::Rsa(key) => key.size(),
        }
    }

    /// The length of a signature blob for `algorithm`: the algorithm's
    /// name and the raw signature, each as a string.
    fn signature_len(&self, algorithm: &str) -> usize {
        4 + algorithm.len() + 4 + self.raw_signature_len()
    }

    /// Signs `message` as a blob of [`signature_len`](Self::signature_len)
    /// bytes, allocated for exactly those. The raw signature is a second
    /// allocation, freed before this returns; an RSA signer's working
    /// memory is the `rsa` crate's.
    fn sign(
        &self,
        algorithm: &str,
        message: &[u8],
        rng: &mut ChaCha20Rng,
    ) -> Result<Vec<u8>, TransportError> {
        let signature = match &self.key {
            HostSecret::Ed25519(key) if algorithm == "ssh-ed25519" => {
                key.sign(message).as_ref().to_vec()
            }
            HostSecret::Rsa(key) => {
                let mut rng = RsaRandom(rng);
                match algorithm {
                    "rsa-sha2-256" => key.sign_with_rng(
                        &mut rng,
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                        digest::digest(&digest::SHA256, message).as_ref(),
                    ),
                    "rsa-sha2-512" => key.sign_with_rng(
                        &mut rng,
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha512>(),
                        digest::digest(&digest::SHA512, message).as_ref(),
                    ),
                    _ => return Err(TransportError::Algorithm),
                }
                .map_err(|_| TransportError::Crypto)?
            }
            _ => return Err(TransportError::Algorithm),
        };
        let mut out = Vec::with_capacity(4 + algorithm.len() + 4 + signature.len());
        put_string(&mut out, algorithm.as_bytes());
        put_string(&mut out, &signature);
        Ok(out)
    }
}

struct RsaRandom<'a>(&'a mut ChaCha20Rng);
impl rsa::rand_core::CryptoRng for RsaRandom<'_> {}
impl rsa::rand_core::RngCore for RsaRandom<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// One complete identification or authenticated packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEvent {
    /// The client identification, without its line ending.
    Version(Identification),
    /// A packet whose padding and authentication have been checked.
    Packet {
        /// Sequence number before any strict NEWKEYS reset.
        sequence: u32,
        /// The message number and its fields.
        payload: Vec<u8>,
    },
}

/// Algorithms selected by the latest completed key exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// Key exchange algorithm.
    pub kex: String,
    /// Host signature algorithm.
    pub host: String,
    /// Client to server authenticated cipher.
    pub incoming: String,
    /// Server to client authenticated cipher.
    pub outgoing: String,
}

enum Exchange {
    Idle,
    Proposal(Vec<u8>),
    Share {
        server: Vec<u8>,
        client: Vec<u8>,
        algorithms: Negotiated,
        skip_guess: bool,
    },
    NewKeys(Box<Direction>),
}

/// A bounded SSH server transport. It performs no host I/O or clock reads.
pub struct Transport {
    host_key: Arc<HostKey>,
    identification: Identification,
    peer: Option<Identification>,
    lines: Lines,
    rng: Option<ChaCha20Rng>,
    proposal: KexInit,
    /// Whether the client's first proposal asked for EXT_INFO.
    ext_info: bool,
    exchange: Exchange,
    negotiated: Option<Negotiated>,
    incoming: Direction,
    outgoing: Direction,
    session_id: Vec<u8>,
    strict: bool,
    started: bool,
    established: bool,
}

impl Transport {
    /// Creates a server with modern authenticated ciphers and strict KEX support.
    pub fn new(host_key: Arc<HostKey>, identification: Identification) -> Self {
        let names = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        let mut kex_algorithms: Vec<String> = names(KEX);
        kex_algorithms.push(STRICT_SERVER.to_owned());
        let proposal = KexInit {
            kex_algorithms,
            server_host_key_algorithms: names(host_key.algorithms()),
            encryption_client_to_server: names(CIPHERS),
            encryption_server_to_client: names(CIPHERS),
            mac_client_to_server: names(&["hmac-sha2-256"]),
            mac_server_to_client: names(&["hmac-sha2-256"]),
            compression_client_to_server: names(&["none"]),
            compression_server_to_client: names(&["none"]),
            ..KexInit::default()
        };
        Self {
            host_key,
            identification,
            peer: None,
            lines: Lines::new(),
            rng: None,
            proposal,
            ext_info: false,
            exchange: Exchange::Idle,
            negotiated: None,
            incoming: Direction::plain(),
            outgoing: Direction::plain(),
            session_id: Vec::new(),
            strict: false,
            started: false,
            established: false,
        }
    }

    /// Seeds this connection once, before it starts. Use a fresh unpredictable
    /// seed per real connection, or the world's entropy stream for a simulation.
    pub fn seed(&mut self, seed: [u8; 32]) -> Result<(), TransportError> {
        let seed = Zeroizing::new(seed);
        if self.started || self.rng.is_some() {
            return Err(TransportError::State);
        }
        self.rng = Some(ChaCha20Rng::from_seed(*seed));
        Ok(())
    }

    /// The configured proposal. Its cookie is replaced for every exchange.
    pub fn proposal(&self) -> &KexInit {
        &self.proposal
    }

    /// Reorders or filters supported algorithms before the transport starts.
    /// Unknown algorithms, optimistic guesses and compression are rejected.
    pub fn set_proposal(&mut self, proposal: KexInit) -> Result<(), TransportError> {
        if self.started {
            return Err(TransportError::State);
        }
        let subset = |v: &[String], allowed: &[String]| {
            !v.is_empty() && v.iter().all(|s| allowed.contains(s))
        };
        if proposal.first_kex_packet_follows
            || proposal.reserved != 0
            || !subset(&proposal.kex_algorithms, &self.proposal.kex_algorithms)
            || !proposal
                .kex_algorithms
                .iter()
                .any(|s| KEX.contains(&s.as_str()))
            || !subset(
                &proposal.server_host_key_algorithms,
                &self.proposal.server_host_key_algorithms,
            )
            || !subset(
                &proposal.encryption_client_to_server,
                &self.proposal.encryption_client_to_server,
            )
            || !subset(
                &proposal.encryption_server_to_client,
                &self.proposal.encryption_server_to_client,
            )
            || !subset(
                &proposal.mac_client_to_server,
                &self.proposal.mac_client_to_server,
            )
            || !subset(
                &proposal.mac_server_to_client,
                &self.proposal.mac_server_to_client,
            )
            || proposal.compression_client_to_server != ["none"]
            || proposal.compression_server_to_client != ["none"]
        {
            return Err(TransportError::Algorithm);
        }
        Message::KexInit(proposal.clone()).to_bytes()?;
        self.proposal = proposal;
        Ok(())
    }

    /// Algorithms installed by the latest exchange. Available once the server
    /// has sent NEWKEYS; use `is_established` and `is_rekeying` to check completion.
    pub fn negotiated(&self) -> Option<&Negotiated> {
        self.negotiated.as_ref()
    }
    /// The first exchange hash, retained across rekeys for user authentication.
    pub fn session_id(&self) -> Option<&[u8]> {
        (!self.session_id.is_empty()).then_some(&self.session_id)
    }
    /// Whether both directions have completed the initial NEWKEYS exchange.
    pub fn is_established(&self) -> bool {
        self.established
    }
    /// Whether an exchange currently prevents sending application messages.
    pub fn is_rekeying(&self) -> bool {
        !matches!(self.exchange, Exchange::Idle)
    }
    /// The most [`held`](Decode::held) can reach from now on: what does not
    /// change once started (the identification and proposal of ours), and
    /// the most the peer can make the transport hold: its identification,
    /// the names an exchange settles on, the session identifier, the keys
    /// of both directions, and the largest exchange state, both proposals
    /// with their names. A caller charges this once, after starting.
    pub fn most_held(&self) -> usize {
        let ours = self.proposal.encoded_len().unwrap_or(MAX_PAYLOAD);
        let names = 4 * MAX_NAME;
        let key = std::mem::size_of::<aead::LessSafeKey>();
        self.identification.heap()
            + MAX_VERSION_LINE
            + self.proposal.heap()
            + names
            + digest::MAX_OUTPUT_LEN
            + 2 * key
            + (ours + MAX_PAYLOAD + names).max(std::mem::size_of::<Direction>() + key)
    }

    /// The most [`handle`](Self::handle) allocates for `payload` and frees
    /// before it returns, beyond the payload itself and what
    /// [`most_held`](Self::most_held) bounds: a KEXINIT's parsed lists,
    /// boxed for an observer or not ([`KexInit`]'s [`HeapBound`]), an
    /// ECDH_INIT's exchange ([`exchange_scratch`](Self::exchange_scratch)),
    /// or the strings of a transport message ([`Message`]'s bound). Other
    /// packets are handed up whole, allocating nothing. Charge it before
    /// handling.
    pub fn scratch(&self, payload: &[u8]) -> usize {
        match payload.first() {
            Some(&super::msg::KEXINIT) => Box::<KexInit>::most_heap(payload.len()),
            Some(30) => self.exchange_scratch(payload),
            Some(1..=4) => Message::most_heap_of(payload),
            _ => 0,
        }
    }

    /// What answering the ECDH_INIT `payload` allocates, all of it at
    /// once at most, from the sizes the exchange works with: the two
    /// version texts; the server's share, the raw secret and the encoded
    /// one; the transcript; the raw signature and its blob; the two keys
    /// derived at a time; the reply; and EXT_INFO. Each is allocated for
    /// exactly its size. Outside an exchange, or for a method this
    /// transport does not run, the payload is refused before anything is
    /// allocated. An RSA signer's own working memory is the `rsa` crate's,
    /// not counted here.
    fn exchange_scratch(&self, payload: &[u8]) -> usize {
        let Exchange::Share {
            server,
            client,
            algorithms,
            ..
        } = &self.exchange
        else {
            return 0;
        };
        let (Some(group), Some(peer)) = (Group::of(&algorithms.kex), &self.peer) else {
            return 0;
        };
        let texts = peer.len() + self.identification.len();
        let host = self.host_key.public_key().len();
        // Seven strings, the client's share among them within the
        // payload, and the encoded secret.
        let transcript = 7 * 4
            + texts
            + client.len()
            + server.len()
            + host
            + payload.len()
            + group.share
            + group.encoded_secret();
        let signature = self.host_key.signature_len(&algorithms.host);
        let keys = derived_len(group.hash, 64) + derived_len(group.hash, 12);
        let reply = 1 + 3 * 4 + host + group.share + signature;
        texts
            + group.share
            + group.secret
            + group.encoded_secret()
            + transcript
            + self.host_key.raw_signature_len()
            + signature
            + keys
            + reply
            + EXT_INFO_LEN
    }

    /// Whether a direction is close enough to its key limit to initiate rekey.
    pub fn needs_rekey(&self) -> bool {
        [&self.incoming, &self.outgoing]
            .iter()
            .any(|d| d.bytes >= KEY_BYTES / 2 || d.packets >= KEY_PACKETS / 2)
    }

    /// Appends the server identification and first KEXINIT.
    pub fn start(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.start_identification(out)?;
        self.send_proposal(out)
    }

    /// Appends only the server identification. The first KEXINIT follows the
    /// peer's identification in [`Self::handle`], matching OpenSSH's ordering.
    pub fn start_identification(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError> {
        if self.started {
            return Err(TransportError::State);
        }
        if self.rng.is_none() {
            return Err(TransportError::Unseeded);
        }
        if self.identification.proto() != "2.0" {
            return Err(Error::BadVersion.into());
        }
        self.identification.write(out)?;
        self.started = true;
        Ok(())
    }

    fn send_proposal(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.rng
            .as_mut()
            .ok_or(TransportError::Unseeded)?
            .fill_bytes(&mut self.proposal.cookie);
        // The proposal is lent to the message, not copied: the encoded
        // payload is all this allocates.
        let message = Message::KexInit(std::mem::take(&mut self.proposal));
        let payload = message.to_bytes();
        let Message::KexInit(proposal) = message else {
            unreachable!("the message was built as a KEXINIT")
        };
        self.proposal = proposal;
        let payload = payload?;
        self.send(&payload, out)?;
        self.exchange = Exchange::Proposal(payload);
        Ok(())
    }

    /// Starts a server-initiated rekey. Simultaneous peer rekeys are supported.
    pub fn rekey(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError> {
        if !self.established || self.is_rekeying() {
            return Err(TransportError::State);
        }
        self.send_proposal(out)
    }

    /// Handles an event immediately after decoding. Handshake messages append
    /// replies and return `None`; application messages return their payload.
    pub fn handle(
        &mut self,
        event: TransportEvent,
        out: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        if !self.started {
            return Err(TransportError::State);
        }
        let TransportEvent::Packet { sequence, payload } = event else {
            if let TransportEvent::Version(id) = event {
                if self.peer.is_some() || !matches!(id.proto(), "2.0" | "1.99") {
                    return Err(Error::BadVersion.into());
                }
                self.peer = Some(id);
                if matches!(self.exchange, Exchange::Idle) {
                    self.send_proposal(out)?;
                }
            }
            return Ok(None);
        };
        if self.peer.is_none() {
            return Err(TransportError::State);
        }
        let number = *payload.first().ok_or(Error::Empty)?;
        if let Exchange::Share { skip_guess, .. } = &mut self.exchange
            && *skip_guess
        {
            *skip_guess = false;
            return Ok(None);
        }
        if number == 20 {
            self.negotiate(sequence, &payload, out)?;
            return Ok(None);
        }
        if number == 30 {
            self.exchange_share(&payload, out)?;
            return Ok(None);
        }
        if number == 21 {
            if payload.len() != 1 {
                return Err(Error::Trailing.into());
            }
            let Exchange::NewKeys(mut incoming) =
                std::mem::replace(&mut self.exchange, Exchange::Idle)
            else {
                return Err(TransportError::State);
            };
            incoming.sequence = if self.strict {
                0
            } else {
                self.incoming.sequence
            };
            self.incoming = *incoming;
            self.established = true;
            return Ok(None);
        }
        if number == 1 {
            Message::parse(&payload)?;
            return Ok(Some(payload));
        }
        if self.strict && !self.established {
            return Err(TransportError::State);
        }
        if matches!(number, 2..=4) {
            Message::parse(&payload)?;
            return Ok(None);
        }
        if !self.established
            || matches!(self.exchange, Exchange::Share { .. } | Exchange::NewKeys(_))
        {
            return Err(TransportError::State);
        }
        Ok(Some(payload))
    }

    fn negotiate(
        &mut self,
        sequence: u32,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        let Message::KexInit(client) = Message::parse(payload)? else {
            return Err(TransportError::State);
        };
        if matches!(self.exchange, Exchange::Idle) {
            if !self.established {
                return Err(TransportError::State);
            }
            self.send_proposal(out)?;
        }
        let Exchange::Proposal(server) = std::mem::replace(&mut self.exchange, Exchange::Idle)
        else {
            return Err(TransportError::State);
        };
        let choose = |c: &[String], s: &[String]| {
            KexInit::choose(c, s)
                .map(str::to_owned)
                .ok_or(TransportError::Algorithm)
        };
        let kex = choose(&client.kex_algorithms, &self.proposal.kex_algorithms)?;
        if !KEX.contains(&kex.as_str()) {
            return Err(TransportError::Algorithm);
        }
        let host = choose(
            &client.server_host_key_algorithms,
            &self.proposal.server_host_key_algorithms,
        )?;
        let incoming = choose(
            &client.encryption_client_to_server,
            &self.proposal.encryption_client_to_server,
        )?;
        let outgoing = choose(
            &client.encryption_server_to_client,
            &self.proposal.encryption_server_to_client,
        )?;
        choose(
            &client.compression_client_to_server,
            &self.proposal.compression_client_to_server,
        )?;
        choose(
            &client.compression_server_to_client,
            &self.proposal.compression_server_to_client,
        )?;
        if !self.established {
            self.strict = client.kex_algorithms.iter().any(|s| s == STRICT_CLIENT)
                && self
                    .proposal
                    .kex_algorithms
                    .iter()
                    .any(|s| s == STRICT_SERVER);
            if self.strict && sequence != 0 {
                return Err(TransportError::State);
            }
            self.ext_info = client.kex_algorithms.iter().any(|s| s == "ext-info-c");
        }
        let skip_guess = client.first_kex_packet_follows
            && (client.kex_algorithms.first() != Some(&kex)
                || client.server_host_key_algorithms.first() != Some(&host));
        self.exchange = Exchange::Share {
            server,
            client: payload.to_vec(),
            algorithms: Negotiated {
                kex,
                host,
                incoming,
                outgoing,
            },
            skip_guess,
        };
        Ok(())
    }

    fn exchange_share(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TransportError> {
        let Exchange::Share {
            server,
            client,
            algorithms,
            ..
        } = std::mem::replace(&mut self.exchange, Exchange::Idle)
        else {
            return Err(TransportError::State);
        };
        let mut reader = Reader::new(&payload[1..]);
        let client_public = reader.string()?;
        reader.finish()?;
        let rng = self.rng.as_mut().ok_or(TransportError::Unseeded)?;
        let (server_public, secret, hash) = shared_secret(&algorithms.kex, client_public, rng)?;
        let peer = version_text(self.peer.as_ref().ok_or(TransportError::State)?)?;
        let ours = version_text(&self.identification)?;
        let mut transcript = Zeroizing::new(Vec::with_capacity(
            7 * 4
                + peer.len()
                + ours.len()
                + client.len()
                + server.len()
                + self.host_key.public_key().len()
                + client_public.len()
                + server_public.len()
                + secret.len(),
        ));
        put_string(&mut transcript, &peer);
        put_string(&mut transcript, &ours);
        put_string(&mut transcript, &client);
        put_string(&mut transcript, &server);
        put_string(&mut transcript, self.host_key.public_key());
        put_string(&mut transcript, client_public);
        put_string(&mut transcript, &server_public);
        transcript.extend_from_slice(&secret);
        let exchange_hash = digest::digest(hash, &transcript);
        if self.session_id.is_empty() {
            self.session_id = exchange_hash.as_ref().to_vec();
        }
        let signature = self
            .host_key
            .sign(&algorithms.host, exchange_hash.as_ref(), rng)?;
        let derive = |letter, length| {
            derive_key(
                hash,
                &secret,
                exchange_hash.as_ref(),
                &self.session_id,
                letter,
                length,
            )
        };
        let incoming =
            Direction::encrypted(&algorithms.incoming, &derive(b'C', 64), &derive(b'A', 12))?;
        let outgoing =
            Direction::encrypted(&algorithms.outgoing, &derive(b'D', 64), &derive(b'B', 12))?;
        let mut reply = Vec::with_capacity(
            1 + 3 * 4 + self.host_key.public_key().len() + server_public.len() + signature.len(),
        );
        reply.push(31);
        put_string(&mut reply, self.host_key.public_key());
        put_string(&mut reply, &server_public);
        put_string(&mut reply, &signature);
        self.send(&reply, out)?;
        self.send(&[21], out)?;
        let sequence = if self.strict {
            0
        } else {
            self.outgoing.sequence
        };
        self.outgoing = outgoing;
        self.outgoing.sequence = sequence;
        if !self.established && self.ext_info {
            let mut extension = Vec::with_capacity(EXT_INFO_LEN);
            extension.push(7);
            extension.extend_from_slice(&1u32.to_be_bytes());
            put_string(&mut extension, SERVER_SIG_ALGS.0);
            put_string(&mut extension, SERVER_SIG_ALGS.1);
            self.send(&extension, out)?;
        }
        self.negotiated = Some(algorithms);
        self.exchange = Exchange::NewKeys(Box::new(incoming));
        Ok(())
    }

    /// Encrypts an application payload. Refuses application output during KEX.
    pub fn write_packet(
        &mut self,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        if !self.established || self.is_rekeying() {
            return Err(TransportError::State);
        }
        self.send(payload, out)
    }

    /// Sends a final disconnect with the current outgoing keys, including
    /// during key exchange. The caller closes the connection after flushing it.
    pub fn disconnect(
        &mut self,
        reason: super::DisconnectReason,
        description: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        if !self.started {
            return Err(TransportError::State);
        }
        let payload = Message::Disconnect {
            reason,
            description: description.to_owned(),
            language: String::new(),
        }
        .to_bytes()?;
        self.send(&payload, out)
    }

    fn send(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.outgoing.write(
            payload,
            self.rng.as_mut().ok_or(TransportError::Unseeded)?,
            out,
        )
    }
}

impl Decode for Transport {
    type Item = TransportEvent;
    type Error = TransportError;
    const NAME: &'static str = "SSH transport";
    fn capacity(&self) -> usize {
        MAX_PACKET + 16
    }
    fn held(&self) -> usize {
        let direction = |d: &Direction| match d.cipher {
            Cipher::Gcm { .. } => std::mem::size_of::<aead::LessSafeKey>(),
            _ => 0,
        };
        self.identification.heap()
            + self.peer.heap()
            + self.proposal.heap()
            + self.negotiated.as_ref().map_or(0, |algorithms| {
                algorithms.kex.capacity()
                    + algorithms.host.capacity()
                    + algorithms.incoming.capacity()
                    + algorithms.outgoing.capacity()
            })
            + self.session_id.capacity()
            + direction(&self.incoming)
            + direction(&self.outgoing)
            + match &self.exchange {
                Exchange::Idle => 0,
                Exchange::Proposal(bytes) => bytes.capacity(),
                Exchange::Share {
                    server,
                    client,
                    algorithms,
                    ..
                } => {
                    server.capacity()
                        + client.capacity()
                        + algorithms.kex.capacity()
                        + algorithms.host.capacity()
                        + algorithms.incoming.capacity()
                        + algorithms.outgoing.capacity()
                }
                Exchange::NewKeys(incoming) => {
                    std::mem::size_of::<Direction>() + direction(incoming)
                }
            }
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        if self.peer.is_none() {
            return match self.lines.decode(input, eof)? {
                Step::Item(Line::Version(id), used) => {
                    Ok(Step::Item(TransportEvent::Version(id), used))
                }
                Step::Item(Line::Banner(_), _) => Err(Error::BadVersion.into()),
                _ => Ok(Step::Need),
            };
        }
        self.incoming.read(input)
    }
}

fn version_text(id: &Identification) -> Result<Vec<u8>, Error> {
    let mut bytes = id.to_bytes()?;
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(bytes)
}

type SharedSecret = (Vec<u8>, Zeroizing<Vec<u8>>, &'static digest::Algorithm);

fn shared_secret(
    algorithm: &str,
    peer: &[u8],
    rng: &mut ChaCha20Rng,
) -> Result<SharedSecret, TransportError> {
    let (public, shared, hash) = match algorithm {
        "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
            let peer: [u8; 32] = peer.try_into().map_err(|_| TransportError::Crypto)?;
            let mut bytes = Zeroizing::new([0; 32]);
            rng.fill_bytes(bytes.as_mut());
            let secret = x25519_dalek::StaticSecret::from(*bytes);
            let public = x25519_dalek::PublicKey::from(&secret);
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
            if !shared.was_contributory() {
                return Err(TransportError::Crypto);
            }
            (
                public.as_bytes().to_vec(),
                Zeroizing::new(shared.as_bytes().to_vec()),
                &digest::SHA256,
            )
        }
        "ecdh-sha2-nistp256" => {
            if peer.len() != 65 || peer[0] != 4 {
                return Err(TransportError::Crypto);
            }
            let peer =
                p256::PublicKey::from_sec1_bytes(peer).map_err(|_| TransportError::Crypto)?;
            let secret = loop {
                let mut bytes = Zeroizing::new([0; 32]);
                rng.fill_bytes(bytes.as_mut());
                if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_ref()) {
                    break secret;
                }
            };
            let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
            let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            (
                public,
                Zeroizing::new(shared.raw_secret_bytes().to_vec()),
                &digest::SHA256,
            )
        }
        "ecdh-sha2-nistp384" => {
            if peer.len() != 97 || peer[0] != 4 {
                return Err(TransportError::Crypto);
            }
            let peer =
                p384::PublicKey::from_sec1_bytes(peer).map_err(|_| TransportError::Crypto)?;
            let secret = loop {
                let mut bytes = Zeroizing::new([0; 48]);
                rng.fill_bytes(bytes.as_mut());
                if let Ok(secret) = p384::SecretKey::from_slice(bytes.as_ref()) {
                    break secret;
                }
            };
            let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
            let shared = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
            (
                public,
                Zeroizing::new(shared.raw_secret_bytes().to_vec()),
                &digest::SHA384,
            )
        }
        _ => return Err(TransportError::Algorithm),
    };
    // SSH interprets the X25519 result as a network-order unsigned integer too.
    let first = shared
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(shared.len());
    let significant = &shared[first..];
    let sign = usize::from(significant.first().is_some_and(|&byte| byte >= 128));
    let mut encoded = Zeroizing::new(Vec::with_capacity(4 + sign + significant.len()));
    encoded.extend_from_slice(&((significant.len() + sign) as u32).to_be_bytes());
    if sign != 0 {
        encoded.push(0);
    }
    encoded.extend_from_slice(significant);
    Ok((public, encoded, hash))
}

/// The allocation a key of `length` bytes derived with `hash` takes: the
/// whole hash outputs that reach `length`, at least one.
fn derived_len(hash: &'static digest::Algorithm, length: usize) -> usize {
    length.div_ceil(hash.output_len()).max(1) * hash.output_len()
}

/// A key of `length` bytes (RFC 4253 section 7.2), in an allocation of
/// [`derived_len`] bytes.
fn derive_key(
    hash: &'static digest::Algorithm,
    secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    letter: u8,
    length: usize,
) -> Zeroizing<Vec<u8>> {
    let mut base = digest::Context::new(hash);
    base.update(secret);
    base.update(exchange_hash);
    let mut first = base.clone();
    first.update(&[letter]);
    first.update(session_id);
    let mut key = Zeroizing::new(Vec::with_capacity(derived_len(hash, length)));
    key.extend_from_slice(first.finish().as_ref());
    while key.len() < length {
        let mut next = base.clone();
        next.update(&key);
        key.extend_from_slice(next.finish().as_ref());
    }
    key.truncate(length);
    key
}

enum Cipher {
    Plain,
    Chacha {
        open: aead::chacha20_poly1305_openssh::OpeningKey,
        seal: aead::chacha20_poly1305_openssh::SealingKey,
    },
    Gcm {
        key: Box<aead::LessSafeKey>,
        nonce: [u8; 12],
    },
}

struct Direction {
    cipher: Cipher,
    sequence: u32,
    packets: u64,
    bytes: u64,
}

impl Direction {
    fn plain() -> Self {
        Self {
            cipher: Cipher::Plain,
            sequence: 0,
            packets: 0,
            bytes: 0,
        }
    }
    fn encrypted(name: &str, material: &[u8], iv: &[u8]) -> Result<Self, TransportError> {
        let cipher = match name {
            "chacha20-poly1305@openssh.com" => {
                let key = material.try_into().map_err(|_| TransportError::Crypto)?;
                Cipher::Chacha {
                    open: aead::chacha20_poly1305_openssh::OpeningKey::new(key),
                    seal: aead::chacha20_poly1305_openssh::SealingKey::new(key),
                }
            }
            "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com" => {
                let algorithm = if name.starts_with("aes128") {
                    &aead::AES_128_GCM
                } else {
                    &aead::AES_256_GCM
                };
                Cipher::Gcm {
                    key: Box::new(aead::LessSafeKey::new(
                        aead::UnboundKey::new(algorithm, &material[..algorithm.key_len()])
                            .map_err(|_| TransportError::Crypto)?,
                    )),
                    nonce: iv.try_into().map_err(|_| TransportError::Crypto)?,
                }
            }
            _ => return Err(TransportError::Algorithm),
        };
        Ok(Self {
            cipher,
            sequence: 0,
            packets: 0,
            bytes: 0,
        })
    }
    fn block(&self) -> usize {
        if matches!(self.cipher, Cipher::Gcm { .. }) {
            16
        } else {
            8
        }
    }
    fn check_limit(&self, bytes: usize) -> Result<(), TransportError> {
        if self.packets >= KEY_PACKETS || self.bytes.saturating_add(bytes as u64) > KEY_BYTES {
            return Err(TransportError::KeyExhausted);
        }
        if let Cipher::Gcm { nonce, .. } = &self.cipher
            && nonce[4..] == [255; 8]
        {
            return Err(TransportError::KeyExhausted);
        }
        Ok(())
    }
    fn advance(&mut self, bytes: usize) {
        self.sequence = self.sequence.wrapping_add(1);
        self.packets += 1;
        self.bytes += bytes as u64;
        if let Cipher::Gcm { nonce, .. } = &mut self.cipher {
            let counter = u64::from_be_bytes(nonce[4..].try_into().expect("fixed nonce length"));
            nonce[4..].copy_from_slice(&(counter + 1).to_be_bytes());
        }
    }
    fn write(
        &mut self,
        payload: &[u8],
        rng: &mut ChaCha20Rng,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        if payload.is_empty() {
            return Err(Error::Empty.into());
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLong(payload.len().min(u32::MAX as usize) as u32).into());
        }
        let encrypted = !matches!(self.cipher, Cipher::Plain);
        let offset = if encrypted { 1 } else { 5 };
        let block = self.block();
        let padding = 4 + (block - (offset + payload.len() + 4) % block) % block;
        let length = 1 + payload.len() + padding;
        self.check_limit(length + 4)?;
        let tag = if encrypted { 16 } else { 0 };
        out.try_reserve(4 + length + tag)
            .map_err(|_| Error::Unwritable)?;
        // The packet is built and sealed where it goes, in `out`: nothing
        // else is allocated for it.
        let start = out.len();
        out.extend_from_slice(&(length as u32).to_be_bytes());
        out.push(padding as u8);
        out.extend_from_slice(payload);
        out.resize(start + 4 + length, 0);
        rng.fill_bytes(&mut out[start + 5 + payload.len()..]);
        let packet = &mut out[start..];
        let sealed = match &self.cipher {
            Cipher::Plain => Ok(None),
            Cipher::Chacha { seal, .. } => {
                let mut tag = [0; 16];
                seal.seal_in_place(self.sequence, packet, &mut tag);
                Ok(Some(tag))
            }
            Cipher::Gcm { key, nonce } => {
                let (head, body) = packet.split_at_mut(4);
                key.seal_in_place_separate_tag(
                    aead::Nonce::assume_unique_for_key(*nonce),
                    aead::Aad::from(head),
                    body,
                )
                .map(|tag| Some(tag.as_ref().try_into().expect("16-byte GCM tag")))
            }
        };
        match sealed {
            Ok(Some(tag)) => out.extend_from_slice(&tag),
            Ok(None) => {}
            Err(_) => {
                out.truncate(start);
                return Err(TransportError::Crypto);
            }
        }
        self.advance(length + 4);
        Ok(())
    }
    fn read(&mut self, input: &[u8]) -> Result<Step<TransportEvent>, TransportError> {
        let Some(head) = input.get(..4) else {
            return Ok(Step::Need);
        };
        let head: [u8; 4] = head.try_into().expect("four-byte packet length");
        let head = match &self.cipher {
            Cipher::Chacha { open, .. } => open.decrypt_packet_length(self.sequence, head),
            _ => head,
        };
        let length = u32::from_be_bytes(head) as usize;
        let encrypted = !matches!(self.cipher, Cipher::Plain);
        if length > MAX_PACKET - 4 || length < if encrypted { 8 } else { 12 } {
            return Err(Error::PacketLength(length as u32).into());
        }
        let aligned = if encrypted { length } else { length + 4 };
        if !aligned.is_multiple_of(self.block()) {
            return Err(Error::PacketLength(length as u32).into());
        }
        self.check_limit(length + 4)?;
        let total = length + 4 + if encrypted { 16 } else { 0 };
        let Some(input) = input.get(..total) else {
            return Ok(Step::Need);
        };
        // An encrypted packet is opened in the one vector that then holds
        // its payload: nothing else is allocated for it.
        let payload = match &self.cipher {
            Cipher::Plain => Packet::parse(input)?.payload,
            Cipher::Chacha { open, .. } => {
                let mut packet = input[..length + 4].to_vec();
                let tag = input[length + 4..]
                    .try_into()
                    .map_err(|_| TransportError::Crypto)?;
                open.open_in_place(self.sequence, &mut packet, tag)
                    .map_err(|_| TransportError::Crypto)?;
                unpad(packet, 4)?
            }
            Cipher::Gcm { key, nonce } => {
                let mut packet = input[4..].to_vec();
                let body = key
                    .open_in_place(
                        aead::Nonce::assume_unique_for_key(*nonce),
                        aead::Aad::from(head),
                        &mut packet,
                    )
                    .map_err(|_| TransportError::Crypto)?
                    .len();
                packet.truncate(body);
                unpad(packet, 0)?
            }
        };
        if payload.is_empty() {
            return Err(Error::Empty.into());
        }
        let sequence = self.sequence;
        self.advance(length + 4);
        Ok(Step::Item(
            TransportEvent::Packet { sequence, payload },
            total,
        ))
    }
}

/// The payload of an opened packet whose body (padding length, payload,
/// padding) starts at `at`, in place in the packet's own vector.
fn unpad(mut packet: Vec<u8>, at: usize) -> Result<Vec<u8>, TransportError> {
    let body = &packet[at..];
    let padding = *body.first().ok_or(Error::Empty)?;
    if padding < 4 || usize::from(padding) + 1 >= body.len() {
        return Err(Error::Padding(padding).into());
    }
    let payload = body.len() - 1 - usize::from(padding);
    if payload > MAX_PAYLOAD {
        return Err(Error::PayloadTooLong(payload as u32).into());
    }
    packet.truncate(at + 1 + payload);
    packet.drain(..at + 1);
    Ok(packet)
}

#[cfg(test)]
mod replay;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identification_start_waits_for_complete_peer_identification() {
        let identification = Identification::new("2.0", "server", None).unwrap();
        let key = Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap());
        let mut transport = Transport::new(key, identification.clone());
        transport.seed([19; 32]).unwrap();
        let mut output = Vec::new();
        transport.start_identification(&mut output).unwrap();
        assert_eq!(output, identification.to_bytes().unwrap());
        assert!(!transport.is_rekeying());
        output.clear();

        let peer = Identification::new("2.0", "client", None).unwrap();
        let bytes = peer.to_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(matches!(
                transport.decode(&bytes[..end], false).unwrap(),
                Step::Need
            ));
            assert!(output.is_empty());
        }
        let Step::Item(event, used) = transport.decode(&bytes, false).unwrap() else {
            panic!("complete identification did not decode");
        };
        assert_eq!(used, bytes.len());
        assert!(matches!(&event, TransportEvent::Version(id) if id == &peer));
        assert!(transport.handle(event, &mut output).unwrap().is_none());
        let packet = Packet::parse(&output).unwrap();
        assert_eq!(
            Message::parse(&packet.payload).unwrap(),
            Message::KexInit(transport.proposal().clone())
        );
        assert!(transport.is_rekeying());
    }

    #[test]
    fn randomized_encrypted_packets_roundtrip_incrementally() {
        let mut rng = ChaCha20Rng::from_seed([19; 32]);
        for cipher in CIPHERS {
            for _ in 0..64 {
                let mut material = [0; 64];
                let mut iv = [0; 12];
                rng.fill_bytes(&mut material);
                rng.fill_bytes(&mut iv);
                let mut sender = Direction::encrypted(cipher, &material, &iv).unwrap();
                let mut receiver = Direction::encrypted(cipher, &material, &iv).unwrap();
                sender.sequence = rng.next_u32();
                receiver.sequence = sender.sequence;
                for size in [
                    1,
                    2,
                    7,
                    16,
                    100,
                    (rng.next_u32() as usize % 4096) + 1,
                    MAX_PAYLOAD,
                ] {
                    let mut payload = vec![0; size];
                    rng.fill_bytes(&mut payload);
                    let mut bytes = Vec::new();
                    let sequence = sender.sequence;
                    sender.write(&payload, &mut rng, &mut bytes).unwrap();
                    let mut decoded = None;
                    let mut end = 0;
                    while end < bytes.len() {
                        end = (end + (rng.next_u32() as usize % 512) + 1).min(bytes.len());
                        match receiver.read(&bytes[..end]).unwrap() {
                            Step::Need => {}
                            Step::Item(event, used) => {
                                assert_eq!(used, bytes.len());
                                decoded = Some(event);
                            }
                            _ => panic!("unexpected decoder step"),
                        }
                    }
                    assert_eq!(decoded, Some(TransportEvent::Packet { sequence, payload }));
                }
            }
        }
    }
}
