//! Long Header packet types of QUIC versions one and two
//!
//! Compiled into `packet.rs` under `cfg(kani)`, so the harnesses call the
//! production `LongHeaderType::{from_byte, to_byte}`, `Header::encode` and
//! `ProtectedHeader::decode` without stubs. The expected type bits are the
//! tables of RFC 9000 section 17.2 and RFC 9369 section 3.2, written here
//! from the RFCs.

use super::*;
use crate::version::{QUIC_V1, QUIC_V2};

/// The four long header types, chosen symbolically
fn any_type() -> LongHeaderType {
    match kani::any::<u8>() % 4 {
        0 => LongHeaderType::Initial,
        1 => LongHeaderType::Standard(LongType::ZeroRtt),
        2 => LongHeaderType::Standard(LongType::Handshake),
        _ => LongHeaderType::Retry,
    }
}

/// The type bits RFC 9369 section 3.2 gives version two, and RFC 9000
/// section 17.2 every other version this engine runs
fn rfc_bits(version: u32, ty: LongHeaderType) -> u8 {
    let v1 = match ty {
        LongHeaderType::Initial => 0b00,
        LongHeaderType::Standard(LongType::ZeroRtt) => 0b01,
        LongHeaderType::Standard(LongType::Handshake) => 0b10,
        LongHeaderType::Retry => 0b11,
    };
    let v2 = match ty {
        LongHeaderType::Initial => 0b01,
        LongHeaderType::Standard(LongType::ZeroRtt) => 0b10,
        LongHeaderType::Standard(LongType::Handshake) => 0b11,
        LongHeaderType::Retry => 0b00,
    };
    if version == QUIC_V2 {
        v2
    } else {
        v1
    }
}

/// For every version, `to_byte` writes the RFC's type bits with the header
/// form and fixed bits set, and `from_byte` reads them back whatever the
/// reserved and packet number length bits are. `from_byte` is onto the
/// four types and one-to-one on the type bits, so each version's mapping
/// is a bijection between the four bit patterns and the four types.
#[kani::proof]
fn long_header_types_are_each_versions_rfc_bijection() {
    let version: u32 = kani::any();
    let ty = any_type();
    let byte = LongHeaderType::to_byte(ty, version);
    assert_eq!(byte & 0xc0, LONG_HEADER_FORM | FIXED_BIT);
    assert_eq!(byte & 0x0f, 0);
    assert_eq!((byte >> 4) & 0b11, rfc_bits(version, ty));

    let low: u8 = kani::any();
    assert_eq!(LongHeaderType::from_byte(byte | (low & 0x4f), version), ty);

    let first: u8 = kani::any();
    kani::assume(first & LONG_HEADER_FORM != 0);
    let read = LongHeaderType::from_byte(first, version);
    assert_eq!(LongHeaderType::to_byte(read, version) & 0x30, first & 0x30);
}

/// No packet type of version two reads as the same type under version
/// one's table, or the reverse: a header is only ever typed by its own
/// version.
#[kani::proof]
fn version_one_and_two_never_share_a_type_byte() {
    let ty = any_type();
    let low: u8 = kani::any();
    let v2 = LongHeaderType::to_byte(ty, QUIC_V2) | (low & 0x0f);
    let v1 = LongHeaderType::to_byte(ty, QUIC_V1) | (low & 0x0f);
    assert!(LongHeaderType::from_byte(v2, QUIC_V1) != ty);
    assert!(LongHeaderType::from_byte(v1, QUIC_V2) != ty);
}

fn long_header(header: &ProtectedHeader) -> Option<(LongHeaderType, u32)> {
    match *header {
        ProtectedHeader::Initial(ref initial) => Some((LongHeaderType::Initial, initial.version)),
        ProtectedHeader::Long { ty, version, .. } => Some((LongHeaderType::Standard(ty), version)),
        ProtectedHeader::Retry { version, .. } => Some((LongHeaderType::Retry, version)),
        _ => None,
    }
}

/// Decoding a long header of any first byte and version types it by the
/// table of the version in that same header; version zero is Version
/// Negotiation, and a version the endpoint does not accept is reported
/// with that version.
#[kani::proof]
#[kani::unwind(10)]
fn decoding_types_a_long_header_by_its_own_version() {
    let first: u8 = kani::any();
    let version: u32 = kani::any();
    kani::assume(first & (LONG_HEADER_FORM | FIXED_BIT) == LONG_HEADER_FORM | FIXED_BIT);
    let v = version.to_be_bytes();
    // Empty connection IDs, an empty token and a zero payload length.
    let bytes = [first, v[0], v[1], v[2], v[3], 0, 0, 0, 0, 0];
    let mut cursor = io::Cursor::new(&bytes[..]);
    let decoded = ProtectedHeader::decode(
        &mut cursor,
        &FixedLengthConnectionIdParser::new(0),
        &[QUIC_V1, QUIC_V2],
        false,
    );
    match decoded {
        Ok(ProtectedHeader::VersionNegotiate { .. }) => assert_eq!(version, 0),
        Ok(header) => {
            assert!(version == QUIC_V1 || version == QUIC_V2);
            let (ty, read_version) = long_header(&header).unwrap();
            assert_eq!(read_version, version);
            assert_eq!((first >> 4) & 0b11, rfc_bits(version, ty));
        }
        Err(PacketDecodeError::UnsupportedVersion {
            version: reported, ..
        }) => {
            assert!(version != 0 && version != QUIC_V1 && version != QUIC_V2);
            assert_eq!(reported, version);
        }
        Err(_) => panic!("a well-formed long header"),
    }
}

/// Encode a long header of `ty` in version one or two, chosen
/// symbolically, and decode it again.
fn encode_then_decode(ty: LongHeaderType) {
    let version = if kani::any() { QUIC_V1 } else { QUIC_V2 };
    let cid = ConnectionId::new(&[]);
    let header = match ty {
        LongHeaderType::Initial => Header::Initial(InitialHeader {
            dst_cid: cid,
            src_cid: cid,
            token: Bytes::new(),
            number: PacketNumber::U8(0),
            version,
        }),
        LongHeaderType::Standard(ty) => Header::Long {
            ty,
            dst_cid: cid,
            src_cid: cid,
            number: PacketNumber::U8(0),
            version,
        },
        LongHeaderType::Retry => Header::Retry {
            dst_cid: cid,
            src_cid: cid,
            version,
        },
    };
    let mut buf = Vec::with_capacity(16);
    header.encode(&mut buf);
    let mut cursor = io::Cursor::new(&buf[..]);
    let decoded = ProtectedHeader::decode(
        &mut cursor,
        &FixedLengthConnectionIdParser::new(0),
        &[QUIC_V1, QUIC_V2],
        false,
    )
    .unwrap();
    assert_eq!(long_header(&decoded), Some((ty, version)));
}

/// The engine's Initial headers decode as Initial in their own version.
#[kani::proof]
#[kani::unwind(10)]
fn encoded_initial_headers_decode_in_their_version() {
    encode_then_decode(LongHeaderType::Initial);
}

/// The engine's 0-RTT headers decode as 0-RTT in their own version.
#[kani::proof]
#[kani::unwind(10)]
fn encoded_zero_rtt_headers_decode_in_their_version() {
    encode_then_decode(LongHeaderType::Standard(LongType::ZeroRtt));
}

/// The engine's Handshake headers decode as Handshake in their own version.
#[kani::proof]
#[kani::unwind(10)]
fn encoded_handshake_headers_decode_in_their_version() {
    encode_then_decode(LongHeaderType::Standard(LongType::Handshake));
}

/// The engine's Retry headers decode as Retry in their own version.
#[kani::proof]
#[kani::unwind(10)]
fn encoded_retry_headers_decode_in_their_version() {
    encode_then_decode(LongHeaderType::Retry);
}
