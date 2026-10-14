//! Parsers that take one whole packet from the agent: sorting by protocol
//! (`ip::split_protocols`), echo replies (`icmp::echo_reply`) and DHCP
//! messages (`dhcp::Message::parse`).
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fictionet::Packet;
use fictionet::stdlib::test_support::contract::check_wire;
use fictionet::stdlib::{dhcp, icmp, udp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let proto = fictionet::fuzzing::sort(data);
    let _ = proto;
    let packet = Packet(data.to_vec());
    // The address the packet is for, so the reply path runs too.
    let to: Option<IpAddr> = match data.first().map(|b| b >> 4) {
        Some(4) if data.len() >= 20 => {
            Some(Ipv4Addr::new(data[16], data[17], data[18], data[19]).into())
        }
        Some(6) if data.len() >= 40 => {
            Some(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap()).into())
        }
        _ => None,
    };
    for addr in to.into_iter().chain([
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]) {
        if let Some(reply) = icmp::echo_reply(&packet, addr) {
            // A reply is the same size as the request's ICMP message plus a
            // fresh header, and is never itself a request.
            assert!(reply.0.len() <= data.len() + 40);
            assert!(icmp::echo_reply(&reply, addr).is_none());
        }
    }
    check_wire::<dhcp::Message>(data);
    if let Some(datagram) = udp::Datagram::parse(data) {
        assert!(datagram.as_bytes().len() <= data.len());
        for (src, dst) in [
            (
                IpAddr::from(Ipv4Addr::UNSPECIFIED),
                IpAddr::from(Ipv4Addr::BROADCAST),
            ),
            (
                IpAddr::from(Ipv6Addr::LOCALHOST),
                IpAddr::from(Ipv6Addr::LOCALHOST),
            ),
        ] {
            let _ = datagram.checksum_ok(src, dst);
            let Ok(len) = udp::encoded_len(src, dst, datagram.payload().len()) else {
                continue;
            };
            let mut out = vec![0; len];
            udp::encode(
                SocketAddr::new(src, datagram.source_port()),
                SocketAddr::new(dst, datagram.destination_port()),
                datagram.payload(),
                &mut out,
            )
            .unwrap();
            let encoded = udp::Datagram::parse(&out).unwrap();
            assert!(encoded.checksum_ok(src, dst));
            assert_eq!(encoded.payload(), datagram.payload());
        }
    }
});
