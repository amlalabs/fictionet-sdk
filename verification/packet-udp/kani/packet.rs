//! Kani proofs over the IP packet envelope in
//! `src/stdlib/network/packet.rs`: `IpPacket::checked`, `check` and `host`
//! (lines 258-285), `IpPacket::observed` (231-246), `is_checked` (324-326)
//! and `Transport::read` (155-184). Compiled only under `cargo kani`, as a
//! child module of `packet`, so every harness calls the production code.

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
fn origin(choice: u8) -> Origin {
    match choice % 3 {
        0 => Origin::Arrived,
        1 => Origin::Reassembled,
        _ => Origin::Observed,
    }
}

/// For `bytes`, `checked` takes exactly the whole, non-fragment packets a
/// host takes in with no IPv6 extension headers left, under any origin but
/// `Observed`, and hands the bytes back otherwise. What it makes is
/// checked, has the header `parse_whole` reads, and goes to the transport
/// `Transport::of` names, which is TCP or UDP only for a TCP or UDP packet
/// or an ICMP error. The same bytes observed are never checked.
fn checked_is_a_host_packet(bytes: &[u8]) {
    // The same bytes, compared at a symbolic index: every index at once,
    // without a 48-byte comparison loop for the solver to unwind.
    let at: usize = kani::any();
    kani::assume(at < bytes.len());
    let same = |got: &[u8]| got.len() == bytes.len() && got[at] == bytes[at];
    let choice: u8 = kani::any();
    let observed = matches!(origin(choice), Origin::Observed);
    let whole = Header::parse_whole(bytes);
    match IpPacket::checked(
        Chunk::new(bytes.to_vec()),
        Ingress::default(),
        origin(choice),
    ) {
        Ok(p) => {
            let h = whole.expect("a checked packet is whole");
            assert!(!observed);
            assert!(h.src.is_ipv4() || h.payload.start == 40);
            assert!(p.is_checked());
            let got = p.header().expect("a checked packet has its header");
            assert!(same_addr(got.src, h.src) && same_addr(got.dst, h.dst));
            assert_eq!(
                (got.protocol, &got.payload, got.fragment),
                (h.protocol, &h.payload, h.fragment)
            );
            assert!(same(p.bytes()));
            assert_eq!(p.transport(), Transport::of(bytes));
            if matches!(p.transport(), Transport::Tcp | Transport::Udp) {
                assert!(matches!(
                    h.protocol,
                    protocol::TCP | protocol::UDP | protocol::ICMP | protocol::ICMPV6
                ));
            }
        }
        Err(back) => {
            assert!(same(&back));
            assert!(observed || whole.is_none_or(|h| h.src.is_ipv6() && h.payload.start != 40));
        }
    }
    assert!(!IpPacket::observed(Chunk::new(bytes.to_vec()), Ingress::default()).is_checked());
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
