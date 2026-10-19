use super::*;

#[rstest]
#[case(Medium::Ip)]
fn test_no_icmp_no_unicast(#[case] medium: Medium) {
    let (mut iface, mut sockets, _) = setup(medium);

    // Unknown Ipv4 Protocol
    //
    // Because the destination is the broadcast address
    // this should not trigger and Destination Unreachable
    // response. See RFC 1122 § 3.2.2.
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 54];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    // Ensure that the unknown protocol frame does not trigger an
    // ICMP error response when the destination address is a
    // broadcast address

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        None
    );
}

#[rstest]
#[case(Medium::Ip)]
fn test_icmp_error_no_payload(#[case] medium: Medium) {
    static NO_BYTES: [u8; 0] = [];
    let (mut iface, mut sockets, _device) = setup(medium);

    // Unknown Ipv4 Protocol with no payload
    let repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
        dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
        next_header: IpProtocol::Unknown(0x0c),
        payload_len: 0,
        hop_limit: 0x40,
    });

    let mut bytes = vec![0u8; 34];
    repr.emit(&mut bytes, &ChecksumCapabilities::default());
    let frame = Ipv4Packet::new_unchecked(&bytes[..]);

    // The expected Destination Unreachable response due to the
    // unknown protocol
    let icmp_repr = Icmpv4Repr::DstUnreachable {
        reason: Icmpv4DstUnreachable::ProtoUnreachable,
        header: Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            next_header: IpProtocol::Unknown(12),
            payload_len: 0,
            hop_limit: 64,
        },
        data: &NO_BYTES,
    };

    let expected_repr = Packet::new_ipv4(
        Ipv4Repr {
            src_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x01),
            dst_addr: Ipv4Address::new(0x7f, 0x00, 0x00, 0x02),
            next_header: IpProtocol::Icmp,
            payload_len: icmp_repr.buffer_len(),
            hop_limit: 64,
        },
        IpPayload::Icmpv4(icmp_repr),
    );

    // Ensure that the unknown protocol triggers an error response.
    // And we correctly handle no payload.

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        Some(expected_repr)
    );
}

#[rstest]
#[case(Medium::Ip)]
fn test_local_subnet_broadcasts(#[case] medium: Medium) {
    let (mut iface, _, _device) = setup(medium);
    iface.update_ip_addrs(|addrs| {
        if let Some(addr) = addrs.iter_mut().next() {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 1, 23), 24));
        }
    });

    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 1, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 1, 254))
    );

    iface.update_ip_addrs(|addrs| {
        if let Some(addr) = addrs.iter_mut().next() {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 23, 24), 16));
        }
    });
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 23, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 23, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 168, 255, 255))
    );

    iface.update_ip_addrs(|addrs| {
        if let Some(addr) = addrs.iter_mut().next() {
            *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(192, 168, 23, 24), 8));
        }
    });
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(255, 255, 255, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 23, 1, 255))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 23, 1, 254))
    );
    assert!(
        !iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 255, 255, 254))
    );
    assert!(
        iface
            .inner
            .is_broadcast_v4(Ipv4Address::new(192, 255, 255, 255))
    );
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "proto-ipv4-fragmentation")]
fn test_packet_len(#[case] medium: Medium) {
    use crate::config::FRAGMENTATION_BUFFER_SIZE;

    let (mut iface, _, _) = setup(medium);

    struct TestTxToken {
        max_transmission_unit: usize,
    }

    impl TxToken for TestTxToken {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            net_debug!("TxToken get len: {}", len);
            assert!(len <= self.max_transmission_unit);
            let mut junk = [0; 1536];
            f(&mut junk[..len])
        }
    }

    for ip_packet_len in [
        100,
        iface.inner.ip_mtu(),
        iface.inner.ip_mtu() + 1,
        FRAGMENTATION_BUFFER_SIZE,
    ] {
        net_debug!("ip_packet_len: {}", ip_packet_len);

        let mut ip_repr = Ipv4Repr {
            src_addr: Ipv4Address::new(127, 0, 0, 1),
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: 0,
            hop_limit: 64,
        };
        let tcp_repr = TcpRepr {
            src_port: 12345,
            dst_port: 54321,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 1024,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };

        let ip_packet_payload_len = ip_packet_len - ip_repr.buffer_len();
        let tcp_packet_payload_len = ip_packet_payload_len - tcp_repr.header_len();
        ip_repr.payload_len = ip_packet_payload_len;

        let tcp_packet_payload = vec![1; tcp_packet_payload_len];
        let ip_payload = IpPayload::Tcp(TcpRepr {
            payload: &tcp_packet_payload,
            ..tcp_repr
        });
        let ip_packet = Packet::new_ipv4(ip_repr, ip_payload);

        assert_eq!(
            iface.inner.dispatch_ip(
                TestTxToken {
                    max_transmission_unit: iface.inner.caps.max_transmission_unit
                },
                PacketMeta::default(),
                ip_packet,
                &mut iface.fragmenter,
            ),
            Ok(())
        );
    }
}

#[rstest]
#[case(Medium::Ip)]
fn get_source_address(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    const OWN_UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 2);
    const OWN_UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 14);

    // List of addresses of the interface:
    //   172.18.1.2/24
    //   172.24.24.14/24
    iface.update_ip_addrs(|addrs| {
        addrs.clear();

        addrs
            .push(IpCidr::Ipv4(Ipv4Cidr::new(OWN_UNIQUE_LOCAL_ADDR1, 24)))
            .unwrap();
        addrs
            .push(IpCidr::Ipv4(Ipv4Cidr::new(OWN_UNIQUE_LOCAL_ADDR2, 24)))
            .unwrap();
    });

    // List of addresses we test:
    //   172.18.1.254 -> 172.18.1.2
    //   172.24.24.12 -> 172.24.24.14
    //   172.24.23.254 -> 172.18.1.2
    const UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 254);
    const UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 12);
    const UNIQUE_LOCAL_ADDR3: Ipv4Address = Ipv4Address::new(172, 24, 23, 254);

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR1),
        Some(OWN_UNIQUE_LOCAL_ADDR1)
    );

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR2),
        Some(OWN_UNIQUE_LOCAL_ADDR2)
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR3),
        Some(OWN_UNIQUE_LOCAL_ADDR1)
    );
}

#[rstest]
#[case(Medium::Ip)]
fn get_source_address_empty_interface(#[case] medium: Medium) {
    let (mut iface, _, _) = setup(medium);

    iface.update_ip_addrs(|ips| ips.clear());

    // List of addresses we test:
    //   172.18.1.254 -> None
    //   172.24.24.12 -> None
    //   172.24.23.254 -> None
    const UNIQUE_LOCAL_ADDR1: Ipv4Address = Ipv4Address::new(172, 18, 1, 254);
    const UNIQUE_LOCAL_ADDR2: Ipv4Address = Ipv4Address::new(172, 24, 24, 12);
    const UNIQUE_LOCAL_ADDR3: Ipv4Address = Ipv4Address::new(172, 24, 23, 254);

    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR1),
        None
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR2),
        None
    );
    assert_eq!(
        iface.inner.get_source_address_ipv4(&UNIQUE_LOCAL_ADDR3),
        None
    );
}

#[test]
#[cfg(feature = "proto-ipv4-fragmentation")]
fn test_ipv4_fragment_size() {
    use crate::phy::IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
    use crate::wire::ipv4::HEADER_LEN;
    let (_, _, device) = setup(Medium::Ip);
    let caps = device.capabilities();
    for i in 0..IPV4_FRAGMENT_PAYLOAD_ALIGNMENT {
        assert!(
            caps.max_ipv4_fragment_size(HEADER_LEN + i)
                .is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT)
        );
    }
}

#[rstest]
#[case(Medium::Ip)]
#[cfg(feature = "auto-icmp-echo-reply")]
fn test_handle_ipv4_broadcast(#[case] medium: Medium) {
    use crate::wire::{Icmpv4Packet, Icmpv4Repr};

    let (mut iface, mut sockets, _device) = setup(medium);

    let our_ipv4_addr = iface.ipv4_addr().unwrap();
    let src_ipv4_addr = Ipv4Address::new(127, 0, 0, 2);

    // ICMPv4 echo request
    let icmpv4_data: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    let icmpv4_repr = Icmpv4Repr::EchoRequest {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &icmpv4_data,
    };

    // Send to IPv4 broadcast address
    let ipv4_repr = Ipv4Repr {
        src_addr: src_ipv4_addr,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: icmpv4_repr.buffer_len(),
    };

    // Emit to ip frame
    let mut bytes = vec![0u8; ipv4_repr.buffer_len() + icmpv4_repr.buffer_len()];
    let frame = {
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut bytes[..]),
            &ChecksumCapabilities::default(),
        );
        icmpv4_repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut bytes[ipv4_repr.buffer_len()..]),
            &ChecksumCapabilities::default(),
        );
        Ipv4Packet::new_unchecked(&bytes[..])
    };

    // Expected ICMPv4 echo reply
    let expected_icmpv4_repr = Icmpv4Repr::EchoReply {
        ident: 0x1234,
        seq_no: 0xabcd,
        data: &icmpv4_data,
    };
    let expected_ipv4_repr = Ipv4Repr {
        src_addr: our_ipv4_addr,
        dst_addr: src_ipv4_addr,
        next_header: IpProtocol::Icmp,
        hop_limit: 64,
        payload_len: expected_icmpv4_repr.buffer_len(),
    };
    let expected_packet =
        Packet::new_ipv4(expected_ipv4_repr, IpPayload::Icmpv4(expected_icmpv4_repr));

    assert_eq!(
        iface.inner.process_ipv4(
            &mut sockets,
            PacketMeta::default(),
            HardwareAddress::default(),
            &frame,
            &mut iface.fragments
        ),
        Some(expected_packet)
    );
}
