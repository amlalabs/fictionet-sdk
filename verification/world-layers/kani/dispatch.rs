// Kani proofs over the host packet dispatcher's sorting, `destination` in
// src/stdlib/network/endpoint.rs, included there as a child module under
// `cfg(kani)`. `drive` in the same file hands each packet its IP layer
// hands up to `destination`, and on to the one transport it names.
//
// The packets come from the production code: `IpPacket::observed`, as a
// replacement IP layer can make them, and the standard `IpLayer` taking in
// symbolic bytes on a symbolic network. The bytes are a 28-byte IPv4
// packet: a 20-byte header and eight bytes of transport header, enough for
// `Transport::of` to sort TCP, UDP and ICMP. Every byte is symbolic,
// including the header length, so the packets range over unreadable ones,
// fragments, bad checksums and every protocol number.

use super::*;
use fictionet::stdlib::layer::{Budget, Env, Layer, Observe};
use fictionet::stdlib::network::packet::{IpLayer, IpReport};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

struct Quiet;

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
    let entropy = SeededEntropy::new(Seed::from_u64(1));
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

/// A packet the standard IP layer takes in reaches exactly the transport
/// its header names, only on the host's own network, and only with a
/// header the host read; a packet of another network reaches nothing.
#[kani::proof]
#[kani::unwind(30)]
fn a_host_packet_goes_only_to_its_transport_on_its_network() {
    let bytes: [u8; 28] = kani::any();
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
