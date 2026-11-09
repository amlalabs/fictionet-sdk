// Kani proofs over the host packet dispatcher's sorting, `destination` in
// src/stdlib/network/endpoint.rs, included there as a child module under
// `cfg(kani)`. `drive` in the same file hands each packet its IP layer
// hands up to `destination`, and on to the one transport it names.
//
// The packets come from the production code: `IpPacket::observed`, as a
// replacement IP layer can make them, over every 28-byte packet, and the
// standard `IpLayer` taking in a 28-byte IPv4 packet on a symbolic network
// (`host_bytes` says which bytes are symbolic). Eight bytes after a
// 20-byte header are enough for `Transport::of` to sort TCP, UDP and ICMP.

use super::*;
use fictionet::Entropy;
use fictionet::stdlib::layer::{Budget, Env, Layer, Observe};
use fictionet::stdlib::network::packet::{IpLayer, IpReport};
use fictionet::time::Instant;

struct Quiet;

/// The IP layer draws no entropy for these packets; a constant source keeps
/// the seeded generator's CPU feature probe out of the proof.
struct Zeros;

impl Entropy for Zeros {
    fn fill_random(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

impl Observe<IpReport> for Quiet {
    fn observe(&mut self, _: IpReport) {}
}

/// The world's network, or a tunnel's.
fn any_scope() -> Scope {
    if kani::any() {
        Scope::ROOT
    } else {
        Scope::tunnel()
    }
}

/// What the standard IP layer hands up for `bytes` arriving on `scope`.
fn taken_in(bytes: [u8; 28], scope: Scope) -> Option<IpPacket> {
    let entropy = Zeros;
    let budget = Budget::unlimited();
    let mut quiet = Quiet;
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut quiet);
    let mut layer = IpLayer::host();
    let raw = fictionet::stdlib::layer::Datagram::new(
        Chunk::new(bytes.to_vec()),
        Ingress {
            scope,
            ..Ingress::default()
        },
    );
    let _ = layer.on_event(&mut env, PacketEvent::Packet(raw));
    match layer.take_event() {
        Some(PacketEvent::Packet(packet)) => Some(packet),
        _ => None,
    }
}

/// An observed copy reaches no transport and gets no answer, whatever its
/// bytes and whichever network it names.
#[kani::proof]
#[kani::unwind(30)]
fn an_observed_copy_reaches_nothing() {
    let bytes: [u8; 28] = kani::any();
    let scope = any_scope();
    let host = if kani::any() { scope } else { any_scope() };
    let packet = IpPacket::observed(
        Chunk::new(bytes.to_vec()),
        Ingress {
            scope,
            link: kani::any(),
            capture: None,
        },
    );
    assert_eq!(destination(&packet, host), Destination::Drop);
}

/// A 28-byte IPv4 packet from 10.0.0.2 to 10.0.0.1 with a 20-byte header:
/// any protocol, "don't fragment" set or not, any eight bytes after the
/// header, and a header checksum that verifies or is off by a symbolic
/// nonzero amount. With every header byte symbolic, and again with
/// symbolic fragment fields, the IP layer's parsing and reassembly ran past
/// 25 minutes: fragments go into `Reassembly`'s `HashMap`. Fragments are
/// checked by `verification/packet-udp` and the composition tests;
/// `an_observed_copy_reaches_nothing` takes every byte symbolic.
fn host_bytes() -> [u8; 28] {
    let mut bytes = [0u8; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
    // "Don't fragment" or not; never a fragment.
    bytes[6] = if kani::any() { 0x40 } else { 0 };
    bytes[8] = 64;
    bytes[9] = kani::any();
    bytes[12..16].copy_from_slice(&[10, 0, 0, 2]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, 1]);
    for byte in &mut bytes[20..] {
        *byte = kani::any();
    }
    fictionet::stdlib::network::ip::set_header_checksum(&mut bytes[..20]);
    if kani::any() {
        let off: u8 = kani::any();
        kani::assume(off != 0);
        bytes[10] ^= off;
    }
    bytes
}

/// A packet the standard IP layer takes in reaches exactly the transport
/// its own bytes name, only on the host's own network, and only whole and
/// with a header the host read; a packet of another network reaches
/// nothing.
#[kani::proof]
#[kani::unwind(30)]
fn a_host_packet_goes_only_to_its_transport_on_its_network() {
    let bytes = host_bytes();
    let from = any_scope();
    let host = any_scope();
    let Some(packet) = taken_in(bytes, from) else {
        return;
    };
    let destination = destination(&packet, host);
    if from != host || packet.header().is_none() {
        assert_eq!(destination, Destination::Drop);
        return;
    }
    let header = packet.header().unwrap();
    assert!(header.fragment.is_none_or(|f| f.offset == 0 && !f.more));
    assert_eq!(fictionet::stdlib::network::ip::checksum(&bytes[..20]), 0);
    match destination {
        Destination::Tcp => assert_eq!(Transport::of(&bytes), Transport::Tcp),
        Destination::Udp => assert_eq!(Transport::of(&bytes), Transport::Udp),
        Destination::Icmp => assert!(!matches!(
            Transport::of(&bytes),
            Transport::Tcp | Transport::Udp
        )),
        Destination::Drop => unreachable!("a checked packet of the host's network"),
    }
}
