//! Kani proofs over IP header arithmetic in `src/stdlib/network/ip.rs`:
//! the Internet checksum (`sum`, `fold` and `checksum`, lines 1464-1494),
//! the IPv4 reader (`v4` and `v4_checked`, 1185-1215), and the IPv6 check
//! and extension-header stripping (`chain6`, `strip_extension_headers`,
//! 1283-1442) that the IP layer's normalization rests on. Compiled only
//! under `cargo kani`, as a child module of `ip`, so every harness calls the
//! production code.

use super::*;

/// RFC 1071 written plainly: 16-bit big-endian words, an odd last byte
/// padded with zero, end-around carry, complement.
fn reference(data: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let hi = data[i] as u32;
        let lo = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        acc += (hi << 8) | lo;
        acc = (acc & 0xffff) + (acc >> 16);
        i += 2;
    }
    !(acc as u16)
}

/// For every byte string up to nine bytes, the four-bytes-at-a-time
/// checksum equals RFC 1071's.
#[kani::proof]
#[kani::unwind(10)]
fn checksum_matches_rfc_1071() {
    let bytes: [u8; 9] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 9);
    assert_eq!(checksum(&bytes[..n]), reference(&bytes[..n]));
}

/// For every IPv4 packet of up to 24 bytes, both readers stay inside the
/// bytes: the payload starts after the header's own length and ends at the
/// total length, or at the bytes present for a truncated read.
#[kani::proof]
#[kani::unwind(4)]
fn ipv4_reads_stay_inside_the_packet() {
    let bytes: [u8; 24] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 24);
    kani::assume(bytes[0] >> 4 == 4);
    let ihl = (bytes[0] & 0x0f) as usize * 4;
    let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let bytes = &bytes[..n];
    let truncated: bool = kani::any();
    let read = if truncated {
        Header::parse_truncated(bytes)
    } else {
        Header::parse(bytes)
    };
    if let Some(h) = read {
        assert!(n >= 20 && ihl >= 20 && h.payload.start == ihl);
        assert!(h.payload.start <= h.payload.end && h.payload.end <= n);
        assert_eq!(h.payload.end, if truncated { total.min(n) } else { total });
    }
}

/// For every 24-byte IPv4 packet, `check` takes only a header whose
/// checksum verifies, and reads it as `parse` does; `parse_whole` takes no
/// fragment.
#[kani::proof]
#[kani::unwind(8)]
fn ipv4_check_requires_the_header_checksum() {
    let mut bytes: [u8; 24] = kani::any();
    bytes[0] = 0x40 | (bytes[0] & 0x0f);
    if let Ok(h) = Header::check(&bytes) {
        assert_eq!(checksum(&bytes[..h.payload.start]), 0);
        assert_eq!(Some(h), Header::parse(&bytes));
    }
    if let Some(h) = Header::parse_whole(&bytes) {
        assert!(h.fragment.is_none());
    }
}

/// For every 56-byte IPv6 packet with 16 bytes of payload that starts with
/// an extension header of any of the five kinds, followed by a second one
/// or by upper-layer bytes, taking out the extension headers of a packet
/// that passes `check` gives the original's fixed header with the
/// upper-layer protocol, which is no extension header, in its next-header
/// byte, a payload length of the upper-layer bytes, and those bytes: the
/// packet `parse_whole` reads with its upper-layer header at 40, which
/// `IpPacket::checked` takes. A fragment is never stripped. The headers are
/// held to 8 bytes (their length bytes are 0). Calling `parse_whole` on the
/// stripped packet, rather than reading its bytes, took CBMC past the
/// 12 GB memory cap; a packet with no extension header is the
/// `checked_ipv6_packets_are_host_packets` case in `packet`.
#[kani::proof]
#[kani::unwind(7)]
fn ipv6_stripping_leaves_a_checked_packet() {
    use protocol::{AUTH, DEST_OPTIONS, FRAGMENT, HOP_BY_HOP, ROUTING};
    let extension =
        |next: u8| matches!(next, HOP_BY_HOP | ROUTING | DEST_OPTIONS | AUTH | FRAGMENT);
    let mut bytes: [u8; 56] = kani::any();
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
    kani::assume(extension(bytes[6]) && bytes[41] == 0 && bytes[49] == 0);
    let checked = Header::check(&bytes);
    match strip_extension_headers(&bytes) {
        Ok(None) => {
            let h = checked.expect("a stripped packet was checked");
            assert!(h.fragment.is_none() && h.payload.start == 40);
        }
        Ok(Some(stripped)) => {
            let h = checked.expect("a stripped packet was checked");
            assert!(h.fragment.is_none() && h.payload.start > 40);
            // What `parse_whole` needs of the stripped packet, read off its
            // bytes: the fixed header names the upper-layer protocol, which
            // is no extension header, and its payload length is the upper
            // bytes'. The fixed header's other bytes and the upper bytes
            // are the original's (compared at a symbolic index).
            let want = h.payload(&bytes);
            assert_eq!(stripped.len(), 40 + want.len());
            assert_eq!(stripped[6], h.protocol);
            assert!(!extension(stripped[6]));
            assert_eq!(
                u16::from_be_bytes([stripped[4], stripped[5]]) as usize,
                want.len()
            );
            let at: usize = kani::any();
            kani::assume(at < stripped.len() && !(4..7).contains(&at));
            let original = if at < 40 { bytes[at] } else { want[at - 40] };
            assert_eq!(stripped[at], original);
        }
        Err(_) => {
            assert!(checked.is_err() || checked.is_ok_and(|h| h.fragment.is_some()));
        }
    }
}

// Failing controls. Each harness below changes one thing, and must fail on
// the assertion its comment names.

/// RFC 1071 with the end-around carry dropped.
fn reference_without_carry(data: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i < data.len() {
        let hi = data[i] as u32;
        let lo = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        acc = (acc + ((hi << 8) | lo)) & 0xffff;
        i += 2;
    }
    !(acc as u16)
}

/// Compares the checksum with RFC 1071 less its end-around carry. Must
/// fail on "the sum without its carry".
#[kani::proof]
#[kani::unwind(10)]
fn checksum_without_the_end_around_carry() {
    let bytes: [u8; 9] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 9);
    assert!(
        checksum(&bytes[..n]) == reference_without_carry(&bytes[..n]),
        "the sum without its carry"
    );
}

/// Claims that a truncated read, too, ends at the total length. Must fail
/// on "the payload ends at the total length".
#[kani::proof]
#[kani::unwind(4)]
fn ipv4_truncated_reads_to_the_total_length() {
    let bytes: [u8; 24] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 24);
    kani::assume(bytes[0] >> 4 == 4);
    let total = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if let Some(h) = Header::parse_truncated(&bytes[..n]) {
        assert!(
            h.payload.end == total,
            "the payload ends at the total length"
        );
    }
}

/// Claims of `parse` what the proof claims of `check`: that a header it
/// reads has a checksum that verifies. Must fail on "a header read has a
/// verifying checksum".
#[kani::proof]
#[kani::unwind(8)]
fn ipv4_parse_without_the_header_checksum() {
    let mut bytes: [u8; 24] = kani::any();
    bytes[0] = 0x40 | (bytes[0] & 0x0f);
    if let Some(h) = Header::parse(&bytes) {
        assert!(
            checksum(&bytes[..h.payload.start]) == 0,
            "a header read has a verifying checksum"
        );
    }
}

/// Claims that a stripped packet keeps the original's payload length,
/// which counted the extension headers. Must fail on "the payload length
/// is the original's".
#[kani::proof]
#[kani::unwind(7)]
fn ipv6_stripping_keeping_the_payload_length() {
    use protocol::{AUTH, DEST_OPTIONS, FRAGMENT, HOP_BY_HOP, ROUTING};
    let extension =
        |next: u8| matches!(next, HOP_BY_HOP | ROUTING | DEST_OPTIONS | AUTH | FRAGMENT);
    let mut bytes: [u8; 56] = kani::any();
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
    kani::assume(extension(bytes[6]) && bytes[41] == 0 && bytes[49] == 0);
    if let Ok(Some(stripped)) = strip_extension_headers(&bytes) {
        assert!(
            u16::from_be_bytes([stripped[4], stripped[5]]) == 16,
            "the payload length is the original's"
        );
    }
}
