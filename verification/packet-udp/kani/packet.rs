//! Kani proofs over the host packet envelope in
//! `src/stdlib/network/packet.rs`: `CheckedIpPacket::checked` and
//! `Sort::read`. Compiled only under `cargo kani`, as a child module of
//! `packet`, so every harness calls the production code.

use super::*;

/// Whether two addresses are equal, compared as integers: a 16-byte
/// comparison loop would need an unwinding bound that unrolls the
/// extension-header walk past the solver's memory.
fn same_addr(a: std::net::IpAddr, b: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.to_bits() == b.to_bits(),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.to_bits() == b.to_bits(),
        _ => false,
    }
}

/// Which origin a symbolic choice names.
fn origin(choice: bool) -> Origin {
    if choice {
        Origin::Arrived
    } else {
        Origin::Reassembled
    }
}

/// For `bytes`, `checked` takes exactly the whole, non-fragment packets a
/// host takes in with no IPv6 extension headers left, under either origin,
/// and hands the bytes back otherwise. What it makes has the header
/// `parse_whole` reads, and goes to the transport `Sort::of` names, which
/// is TCP or UDP only for a TCP or UDP packet or an ICMP error.
fn checked_is_a_host_packet(bytes: &[u8]) {
    // The same bytes, compared at a symbolic index: every index at once,
    // without a 48-byte comparison loop for the solver to unwind.
    let at: usize = kani::any();
    kani::assume(at < bytes.len());
    let same = |got: &[u8]| got.len() == bytes.len() && got[at] == bytes[at];
    let whole = Header::parse_whole(bytes);
    match CheckedIpPacket::checked(Chunk::new(bytes.to_vec()), origin(kani::any())) {
        Ok(p) => {
            let h = whole.expect("a checked packet is whole");
            assert!(h.src.is_ipv4() || h.payload.start == 40);
            let got = p.header();
            assert!(same_addr(got.src, h.src) && same_addr(got.dst, h.dst));
            assert_eq!(
                (got.protocol, &got.payload, got.fragment),
                (h.protocol, &h.payload, h.fragment)
            );
            assert!(same(p.bytes()));
            assert_eq!(p.sort(), Sort::of(bytes));
            if matches!(p.sort(), Sort::Transport(_)) {
                assert!(matches!(
                    h.protocol,
                    protocol::TCP | protocol::UDP | protocol::ICMP | protocol::ICMPV6
                ));
            }
        }
        Err(back) => {
            assert!(same(&back));
            assert!(whole.is_none_or(|h| h.src.is_ipv6() && h.payload.start != 40));
        }
    }
}

/// 48-byte IPv4 packets with a 20-byte header, whose total length may be
/// anything: room for an ICMP error quoting a whole IPv4 header. The
/// header length is fixed to keep the checksum walk within the solver's
/// memory; `ipv4_check_requires_the_header_checksum` in `ip` covers others.
#[kani::proof]
#[kani::unwind(7)]
fn checked_ipv4_packets_are_host_packets() {
    let mut bytes: [u8; 48] = kani::any();
    bytes[0] = 0x45;
    checked_is_a_host_packet(&bytes);
}

/// IPv6 packets of 48 bytes, with up to eight bytes of extension headers or
/// upper-layer header.
#[kani::proof]
#[kani::unwind(7)]
fn checked_ipv6_packets_are_host_packets() {
    let mut bytes: [u8; 48] = kani::any();
    bytes[0] = 0x60;
    checked_is_a_host_packet(&bytes);
}

// Failing controls. Each harness below changes one thing, and must fail on
// the assertion its comment names.

/// Claims that `checked` hands back only IPv4 bytes `parse` cannot read,
/// leaving out the header checksum and fragments that the proof above
/// says it refuses. Must fail on "only unreadable IPv4 bytes are handed
/// back".
#[kani::proof]
#[kani::unwind(7)]
fn checked_ipv4_packets_without_the_header_checksum() {
    let mut bytes: [u8; 48] = kani::any();
    bytes[0] = 0x45;
    if CheckedIpPacket::checked(Chunk::new(bytes.to_vec()), Origin::Arrived).is_err() {
        assert!(
            Header::parse(&bytes).is_none(),
            "only unreadable IPv4 bytes are handed back"
        );
    }
}

/// Claims that `checked` takes every IPv6 packet `parse_whole` takes,
/// leaving out the extension headers that must be gone. Must fail on
/// "every whole IPv6 packet is checked".
#[kani::proof]
#[kani::unwind(7)]
fn checked_ipv6_packets_with_extension_headers_left() {
    let mut bytes: [u8; 48] = kani::any();
    bytes[0] = 0x60;
    if CheckedIpPacket::checked(Chunk::new(bytes.to_vec()), Origin::Arrived).is_err() {
        assert!(
            Header::parse_whole(&bytes).is_none(),
            "every whole IPv6 packet is checked"
        );
    }
}
