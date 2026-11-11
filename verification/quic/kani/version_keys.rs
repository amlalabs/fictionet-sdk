//! Version two's packet protection in the rustls adapter
//!
//! Compiled into `crypto/rustls.rs` under `cfg(kani)`. The harnesses call
//! the production `interpret_version`, `retry_integrity` and
//! `initial_keys`, which runs the fork's `Suite::keys`, `Keys::initial`,
//! `KeyBuilder` and HKDF-Expand-Label. Only the hash and the ciphers are
//! replaced, by a symbolic suite whose outputs record how they were made:
//! which salt the extraction used and which labels each expansion used.
//! A key therefore names its own derivation, and the harness reads that
//! name back through the engine's `PacketKey` and `HeaderKey`.
//!
//! The expected salts, labels, keys and nonces below are copied from the
//! RFCs, not from the code: RFC 9001 sections 5.2 and 5.8, RFC 9369
//! sections 3.3.1 to 3.3.3, and draft-ietf-quic-tls-29 for the drafts.

use super::*;
use crate::version::{is_known, TypeBits, QUIC_V1, QUIC_V2};
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey as RustlsPacketKey, Tag};

/// RFC 9001 section 5.2
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// RFC 9369 section 3.3.1
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// draft-ietf-quic-tls-29 section 5.2, used by drafts 29 to 32
const SALT_DRAFT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

/// RFC 9001 section 5.8
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
/// RFC 9369 section 3.3.3
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

const CID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// What a symbolic secret or key records about its derivation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Salt {
    V1 = 1,
    V2,
    Draft,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Label {
    ClientIn = 1,
    ServerIn,
    Key,
    Iv,
    Hp,
    KeyV2,
    IvV2,
    HpV2,
    Other,
}

const LABELS: [(&[u8], Label); 8] = [
    (b"client in", Label::ClientIn),
    (b"server in", Label::ServerIn),
    (b"quic key", Label::Key),
    (b"quic iv", Label::Iv),
    (b"quic hp", Label::Hp),
    (b"quicv2 key", Label::KeyV2),
    (b"quicv2 iv", Label::IvV2),
    (b"quicv2 hp", Label::HpV2),
];

fn salt_code(salt: Option<&[u8]>) -> u8 {
    match salt {
        Some(s) if s == SALT_V1 => Salt::V1 as u8,
        Some(s) if s == SALT_V2 => Salt::V2 as u8,
        Some(s) if s == SALT_DRAFT => Salt::Draft as u8,
        _ => Salt::Other as u8,
    }
}

/// The label of an HKDF-Expand-Label info (RFC 8446 section 7.1): length,
/// label length, "tls13 ", label, context length, context
fn label_code(info: &[&[u8]]) -> u8 {
    if info.len() != 6 || info[2] != b"tls13 " || info[5] != b"" {
        return Label::Other as u8;
    }
    LABELS
        .iter()
        .find(|(text, _)| *text == info[3])
        .map_or(Label::Other as u8, |(_, label)| *label as u8)
}

fn salt_of(code: u8) -> Salt {
    [Salt::V1, Salt::V2, Salt::Draft]
        .into_iter()
        .find(|salt| *salt as u8 == code)
        .unwrap_or(Salt::Other)
}

fn label_of(code: u8) -> Label {
    LABELS
        .iter()
        .map(|(_, label)| *label)
        .find(|label| *label as u8 == code)
        .unwrap_or(Label::Other)
}

/// A secret: the salt it was extracted with, whether the input was the
/// client's Destination Connection ID, and the labels expanded since
struct Expander {
    trail: [u8; 3],
}

impl HkdfExpander for Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        output.fill(0);
        output[..3].copy_from_slice(&self.trail);
        output[3] = label_code(info);
        Ok(())
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut block = [0; 32];
        self.expand_slice(info, &mut block).unwrap();
        OkmBlock::new(&block)
    }

    fn hash_len(&self) -> usize {
        32
    }
}

struct SymbolicHkdf;

impl Hkdf for SymbolicHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        Box::new(Expander {
            trail: [salt_code(salt), 0, 0],
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        Box::new(Expander {
            trail: [salt_code(salt), u8::from(secret == CID), 0],
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        // An expanded secret keeps its salt and input, and adds its label.
        let okm = okm.as_ref();
        Box::new(Expander {
            trail: [okm[0], okm[1], okm[3]],
        })
    }

    fn hmac_sign(&self, _key: &OkmBlock, _message: &[u8]) -> rustls::crypto::hmac::Tag {
        unreachable!("Initial keys sign nothing")
    }
}

/// A packet key that writes its key and IV derivations into the payload
struct SymbolicPacketKey {
    key: [u8; 4],
    iv: [u8; 4],
}

impl RustlsPacketKey for SymbolicPacketKey {
    fn encrypt_in_place(
        &self,
        _packet_number: u64,
        _header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, rustls::Error> {
        payload[..4].copy_from_slice(&self.key);
        payload[4..8].copy_from_slice(&self.iv);
        Ok(Tag::from(&[0; 16][..]))
    }

    fn decrypt_in_place<'a>(
        &self,
        _packet_number: u64,
        _header: &[u8],
        _payload: &'a mut [u8],
    ) -> Result<&'a [u8], rustls::Error> {
        unreachable!("the harness only encrypts")
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

/// A header key that writes its derivation over the packet number
struct SymbolicHeaderKey {
    key: [u8; 4],
}

impl HeaderProtectionKey for SymbolicHeaderKey {
    fn encrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        packet_number.copy_from_slice(&self.key);
        Ok(())
    }

    fn decrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), rustls::Error> {
        unreachable!("the harness only encrypts")
    }

    fn sample_len(&self) -> usize {
        16
    }
}

struct SymbolicAlgorithm;

impl Algorithm for SymbolicAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn RustlsPacketKey> {
        Box::new(SymbolicPacketKey {
            key: key.as_ref()[..4].try_into().unwrap(),
            iv: iv.as_ref()[..4].try_into().unwrap(),
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(SymbolicHeaderKey {
            key: key.as_ref()[..4].try_into().unwrap(),
        })
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

static SYMBOLIC_HKDF: SymbolicHkdf = SymbolicHkdf;
static SYMBOLIC_ALGORITHM: SymbolicAlgorithm = SymbolicAlgorithm;

/// The ring AES-128-GCM suite with its HKDF replaced by the symbolic one
fn symbolic_suite() -> Suite {
    let rustls::SupportedCipherSuite::Tls13(real) =
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
    else {
        unreachable!("a TLS 1.3 suite")
    };
    let suite = Box::leak(Box::new(rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: real.common.suite,
            hash_provider: real.common.hash_provider,
            confidentiality_limit: real.common.confidentiality_limit,
        },
        hkdf_provider: &SYMBOLIC_HKDF,
        aead_alg: real.aead_alg,
        quic: Some(&SYMBOLIC_ALGORITHM),
    }));
    Suite {
        suite,
        quic: &SYMBOLIC_ALGORITHM,
    }
}

/// A key's derivation: the salt, whether the input keying material was the
/// connection ID, the secret's label, and the key's own label
#[derive(Debug, Eq, PartialEq)]
struct Derivation {
    salt: Salt,
    from_cid: bool,
    secret: Label,
    label: Label,
}

impl Derivation {
    fn read(bytes: &[u8]) -> Self {
        Self {
            salt: salt_of(bytes[0]),
            from_cid: bytes[1] == 1,
            secret: label_of(bytes[2]),
            label: label_of(bytes[3]),
        }
    }
}

/// The salt and labels RFC 9001 and RFC 9369 assign to a wire version
fn expected_salt(version: u32) -> Salt {
    match version {
        QUIC_V2 => Salt::V2,
        0xff00_001d..=0xff00_0020 => Salt::Draft,
        _ => Salt::V1,
    }
}

fn expected_labels(version: u32) -> [Label; 3] {
    match version {
        QUIC_V2 => [Label::KeyV2, Label::IvV2, Label::HpV2],
        _ => [Label::Key, Label::Iv, Label::Hp],
    }
}

/// Every Initial key of every known version comes from that version's salt
/// and the client's Destination Connection ID, through the secret of the
/// sending side and the version's key, IV and header protection labels.
/// Unknown versions derive nothing.
#[kani::proof]
#[kani::unwind(66)]
fn initial_keys_use_the_salt_and_labels_of_their_version() {
    let version: u32 = kani::any();
    let client: bool = kani::any();
    let side = if client { Side::Client } else { Side::Server };
    let Ok(interpreted) = interpret_version(version) else {
        assert!(!is_known(version));
        return;
    };
    assert!(is_known(version));
    let keys = initial_keys(
        interpreted,
        ConnectionId::new(&CID),
        side,
        &symbolic_suite(),
    );

    let salt = expected_salt(version);
    let [key, iv, hp] = expected_labels(version);
    let (local, remote) = match side {
        Side::Client => (Label::ClientIn, Label::ServerIn),
        Side::Server => (Label::ServerIn, Label::ClientIn),
    };
    for (packet, header, secret) in [
        (&keys.packet.local, &keys.header.local, local),
        (&keys.packet.remote, &keys.header.remote, remote),
    ] {
        // One header byte, eight payload bytes, a sixteen byte tag.
        let mut buf = [0; 25];
        packet.encrypt(0, &mut buf, 1);
        let derived = |label| Derivation {
            salt,
            from_cid: true,
            secret,
            label,
        };
        assert_eq!(Derivation::read(&buf[1..5]), derived(key));
        assert_eq!(Derivation::read(&buf[5..9]), derived(iv));
        // A first byte, four packet number bytes, a sixteen byte sample.
        let mut header_buf = [0; 21];
        header.encrypt(1, &mut header_buf);
        assert_eq!(Derivation::read(&header_buf[1..5]), derived(hp));
    }
}

/// A Retry's integrity tag uses the key and nonce of the Retry's own
/// version, and a version the engine does not run has none. The adapter
/// runs version two's key schedule for exactly the version whose Long
/// Header type bits are version two's, so packet types and protection never
/// disagree on a version.
#[kani::proof]
fn retry_integrity_and_type_bits_follow_the_version() {
    let version: u32 = kani::any();
    let interpreted = interpret_version(version);
    assert_eq!(interpreted.is_ok(), is_known(version));
    assert_eq!(
        matches!(interpreted, Ok(Version::V2)),
        TypeBits::of(version) == TypeBits::V2
    );
    let integrity = interpreted.ok().and_then(retry_integrity);
    match version {
        QUIC_V2 => assert_eq!(integrity, Some((RETRY_NONCE_V2, RETRY_KEY_V2))),
        QUIC_V1 | 0xff00_0021..=0xff00_0022 => {
            assert_eq!(integrity, Some((RETRY_NONCE_V1, RETRY_KEY_V1)))
        }
        0xff00_001d..=0xff00_0020 => {
            let (nonce, key) = integrity.unwrap();
            assert!(nonce != RETRY_NONCE_V1 && nonce != RETRY_NONCE_V2);
            assert!(key != RETRY_KEY_V1 && key != RETRY_KEY_V2);
        }
        _ => assert_eq!(integrity, None),
    }
}

/// Neither Retry function reaches the cipher for a version the engine does
/// not run: a Retry in such a version is never valid and gets no tag.
#[kani::proof]
fn a_retry_in_an_unknown_version_is_never_valid() {
    let version: u32 = kani::any();
    kani::assume(!is_known(version));
    let cid = ConnectionId::new(&CID);
    let payload = [0; 24];
    assert!(!is_valid_retry(version, &cid, &[0xf0], &payload));
    assert!(retry_tag(version, &cid, &[0xf0]).is_none());
}
