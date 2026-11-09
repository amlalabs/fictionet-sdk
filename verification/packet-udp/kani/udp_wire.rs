//! Kani proofs over UDP header, length and checksum arithmetic in
//! `src/stdlib/network/udp/wire.rs`: `Datagram::parse` (lines 23-34),
//! `encoded_len` (94-103), `encode` (112-128) and `Datagram::checksum_ok`
//! (60-62), over `ip::udp_checksum_ok` and `ip::transport_checksum` in
//! `src/stdlib/network/ip.rs`. Compiled only under `cargo kani`, as a child
//! module of the wire module, so every harness calls the production code.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The most bytes a symbolic datagram has here: a header and four bytes.
const MAX: usize = 12;

/// For every byte string up to 12 bytes, `parse` takes exactly those whose
/// length field is at least 8 and within the bytes, and reads the declared
/// length: the header, then the payload, an empty one included.
#[kani::proof]
#[kani::unwind(13)]
fn parse_reads_exactly_the_declared_length() {
    let bytes: [u8; MAX] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= MAX);
    let bytes = &bytes[..n];
    let declared = if n >= 6 {
        u16::from_be_bytes([bytes[4], bytes[5]]) as usize
    } else {
        0
    };
    match Datagram::parse(bytes) {
        Some(d) => {
            assert!(n >= 8 && declared >= 8 && declared <= n);
            assert_eq!(d.as_bytes(), &bytes[..declared]);
            assert_eq!(d.payload(), &bytes[8..declared]);
            assert_eq!(d.source_port(), u16::from_be_bytes([bytes[0], bytes[1]]));
            assert_eq!(
                d.destination_port(),
                u16::from_be_bytes([bytes[2], bytes[3]])
            );
        }
        None => {
            assert!(n < 8 || declared < 8 || declared > n);
        }
    }
}

/// For every payload length, `encoded_len` refuses mixed families and
/// takes a payload exactly when the datagram fits one IP packet with a
/// basic header, so the length `encode` writes into 16 bits never wraps.
#[kani::proof]
fn encoded_len_fits_one_ip_packet() {
    let len: usize = kani::any();
    let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
    let v6: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
    assert_eq!(encoded_len(v4, v6, len), Err(Error::AddressFamily));
    assert_eq!(encoded_len(v6, v4, len), Err(Error::AddressFamily));
    match encoded_len(v4, v4, len) {
        Ok(n) => {
            assert!(n == len + 8 && 20 + n <= 65_535);
        }
        Err(e) => {
            assert!(e == Error::Length && len > 65_535 - 20 - 8);
        }
    }
    match encoded_len(v6, v6, len) {
        Ok(n) => {
            assert!(n == len + 8 && n <= 65_535);
        }
        Err(e) => {
            assert!(e == Error::Length && len > 65_535 - 8);
        }
    }
}

/// Encodes a symbolic datagram of up to three payload bytes, empty
/// included, with any ports, between `src` and `dst`, and checks that it
/// reads back whole with a nonzero checksum field that verifies, and that
/// one flipped bit outside the length field fails the checksum, except
/// where the flip leaves an IPv4 checksum field of zero, which RFC 768
/// reads as "no checksum".
fn roundtrip(src: IpAddr, dst: IpAddr) {
    let payload: [u8; 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 3);
    let payload = &payload[..len];
    let from = SocketAddr::new(src, kani::any());
    let to = SocketAddr::new(dst, kani::any());
    let mut out = [0u8; 11];
    let n = encode(from, to, payload, &mut out).expect("a small datagram fits");
    assert_eq!(n, 8 + len);
    let wire = &out[..n];
    let d = Datagram::parse(wire).expect("an encoded datagram parses");
    assert_eq!(d.source_port(), from.port());
    assert_eq!(d.destination_port(), to.port());
    assert_eq!(d.payload(), payload);
    assert_ne!(&wire[6..8], &[0, 0]);
    assert!(d.checksum_ok(src, dst));

    let bit: usize = kani::any();
    kani::assume(bit < n * 8);
    kani::assume(bit / 8 != 4 && bit / 8 != 5);
    let mut flipped = out;
    flipped[bit / 8] ^= 1 << (bit % 8);
    let flipped = &flipped[..n];
    let d = Datagram::parse(flipped).expect("the length is unchanged");
    assert!(!d.checksum_ok(src, dst) || (src.is_ipv4() && flipped[6..8] == [0, 0]));
}

#[kani::proof]
#[kani::unwind(12)]
fn ipv4_datagrams_roundtrip_and_one_bit_fails_the_checksum() {
    roundtrip(
        Ipv4Addr::new(192, 0, 2, 1).into(),
        Ipv4Addr::new(198, 51, 100, 7).into(),
    );
}

#[kani::proof]
#[kani::unwind(12)]
fn ipv6_datagrams_roundtrip_and_one_bit_fails_the_checksum() {
    roundtrip(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).into(),
    );
}
