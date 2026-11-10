use super::*;

fn addresses() -> (IpAddress, IpAddress) {
    if kani::any() {
        (
            IpAddress::Ipv4(core::net::Ipv4Addr::new(192, 0, 2, 1)),
            IpAddress::Ipv4(core::net::Ipv4Addr::new(192, 0, 2, 2)),
        )
    } else {
        (
            IpAddress::Ipv6(core::net::Ipv6Addr::LOCALHOST),
            IpAddress::Ipv6(core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        )
    }
}

#[kani::proof]
#[kani::unwind(13)]
fn every_port_pair_roundtrips_and_checksums_are_required() {
    let source: u16 = kani::any();
    let destination: u16 = kani::any();
    let (source_address, destination_address) = addresses();
    let mut bytes = [0; HEADER_LEN];
    let mut packet = Packet::new_unchecked(&mut bytes[..]);
    packet.set_header_len(HEADER_LEN as u8);
    packet.set_src_port(source);
    packet.set_dst_port(destination);
    packet.fill_checksum(&source_address, &destination_address);

    let parsed = Repr::parse(
        &Packet::new_unchecked(&bytes[..]),
        &source_address,
        &destination_address,
    )
    .unwrap();
    assert_eq!(parsed.src_port, source);
    assert_eq!(parsed.dst_port, destination);

    bytes[0] ^= 1;
    assert!(
        Repr::parse(
            &Packet::new_unchecked(&bytes[..]),
            &source_address,
            &destination_address,
        )
        .is_err()
    );
}

#[kani::proof]
#[kani::unwind(15)]
fn renaming_ports_preserves_packet_validation() {
    let (source_address, destination_address) = addresses();
    let mut original: [u8; HEADER_LEN + 4] = kani::any();
    Packet::new_unchecked(&mut original[..]).fill_checksum(&source_address, &destination_address);
    let mut renamed = original;
    let source: u16 = kani::any();
    let destination: u16 = kani::any();
    let mut packet = Packet::new_unchecked(&mut renamed[..]);
    packet.set_src_port(source);
    packet.set_dst_port(destination);
    packet.fill_checksum(&source_address, &destination_address);

    let ignore_malformed: bool = kani::any();
    let original = Repr::parse_with(
        &Packet::new_unchecked(&original[..]),
        &source_address,
        &destination_address,
        ignore_malformed,
        Sum::Check,
    );
    let renamed = Repr::parse_with(
        &Packet::new_unchecked(&renamed[..]),
        &source_address,
        &destination_address,
        ignore_malformed,
        Sum::Check,
    );
    assert_eq!(original.is_ok(), renamed.is_ok());
    if let (Ok(mut original), Ok(renamed)) = (original, renamed) {
        original.src_port = source;
        original.dst_port = destination;
        assert_eq!(original, renamed);
    }
}

// Failing controls. Each harness below changes one thing, and must fail on
// the assertion its comment names.

/// Two bit flips that cancel in the ones'-complement sum, one in each port:
/// the checksum cannot see them, which is why the proof above claims only
/// that a single flipped bit is caught. Must fail on "a corrupted segment
/// is rejected".
#[kani::proof]
#[kani::unwind(13)]
fn every_port_pair_without_a_single_bit_flip() {
    let source: u16 = kani::any();
    let destination: u16 = kani::any();
    let (source_address, destination_address) = addresses();
    let mut bytes = [0; HEADER_LEN];
    let mut packet = Packet::new_unchecked(&mut bytes[..]);
    packet.set_header_len(HEADER_LEN as u8);
    packet.set_src_port(source);
    packet.set_dst_port(destination);
    packet.fill_checksum(&source_address, &destination_address);
    bytes[0] ^= 1;
    bytes[2] ^= 1;
    assert!(
        Repr::parse(
            &Packet::new_unchecked(&bytes[..]),
            &source_address,
            &destination_address,
        )
        .is_err(),
        "a corrupted segment is rejected"
    );
}

/// Renaming the ports without filling the checksum again. Must fail on
/// "renaming keeps the verdict".
#[kani::proof]
#[kani::unwind(15)]
fn renaming_ports_without_the_checksum_refilled() {
    let (source_address, destination_address) = addresses();
    let mut original: [u8; HEADER_LEN + 4] = kani::any();
    Packet::new_unchecked(&mut original[..]).fill_checksum(&source_address, &destination_address);
    let mut renamed = original;
    let source: u16 = kani::any();
    let destination: u16 = kani::any();
    let mut packet = Packet::new_unchecked(&mut renamed[..]);
    packet.set_src_port(source);
    packet.set_dst_port(destination);

    let ignore_malformed: bool = kani::any();
    let original = Repr::parse_with(
        &Packet::new_unchecked(&original[..]),
        &source_address,
        &destination_address,
        ignore_malformed,
        Sum::Check,
    );
    let renamed = Repr::parse_with(
        &Packet::new_unchecked(&renamed[..]),
        &source_address,
        &destination_address,
        ignore_malformed,
        Sum::Check,
    );
    assert!(
        original.is_ok() == renamed.is_ok(),
        "renaming keeps the verdict"
    );
}
