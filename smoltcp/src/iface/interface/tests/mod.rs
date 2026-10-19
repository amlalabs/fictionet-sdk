use crate::tests::setup;

use super::*;

#[test]
pub fn tcp_not_accepted() {
    let (mut iface, mut sockets, _) = setup();
    let tcp = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(-10001),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];

    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        Some((
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }
            .into(),
            TcpRepr {
                src_port: 4243,
                dst_port: 4242,
                control: TcpControl::Rst,
                seq_number: TcpSeqNumber(0),
                ack_number: Some(TcpSeqNumber(-10000)),
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            }
        ))
    );
    // Unspecified destination address.
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::UNSPECIFIED.into(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::UNSPECIFIED,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        None,
    );
}

#[test]
pub fn tcp_listen_drops_unspecified_src() {
    use crate::socket::tcp;

    let (mut iface, mut sockets, _) = setup();

    let tcp_socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    let handle = sockets.add(tcp_socket);
    sockets.get_mut(handle).listen(1234).unwrap();

    let tcp = TcpRepr {
        src_port: 65000,
        dst_port: 1234,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv4Address::UNSPECIFIED.into(),
        &Ipv4Address::new(127, 0, 0, 1).into(),
    );

    let reply = iface.inner.process_tcp(
        &mut sockets,
        IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }),
        &tcp_bytes,
    );

    assert_eq!(reply, None);
    assert!(sockets.get_mut(handle).is_listening());
}

fn syn_bytes(ip: IpRepr) -> std::vec::Vec<u8> {
    let tcp = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(7),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let mut bytes = vec![0; ip.buffer_len()];
    ip.emit(&mut bytes);
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut bytes[ip.header_len()..]),
        &ip.src_addr(),
        &ip.dst_addr(),
    );
    bytes
}

#[test]
fn ipv4_fragments_are_dropped() {
    for (more, offset) in [(true, 0), (false, 8), (true, 8), (false, 0)] {
        let (mut iface, mut sockets, mut device) = setup();
        let mut bytes = syn_bytes(
            Ipv4Repr {
                src_addr: Ipv4Address::new(192, 168, 1, 2),
                dst_addr: Ipv4Address::new(192, 168, 1, 1),
                next_header: IpProtocol::Tcp,
                payload_len: 24,
                hop_limit: 64,
            }
            .into(),
        );
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
        packet.set_dont_frag(false);
        packet.set_more_frags(more);
        packet.set_frag_offset(offset);
        packet.fill_checksum();
        device.rx_queue.push_back(bytes);
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
        assert_eq!(device.tx_queue.len(), usize::from(!more && offset == 0));
    }
}

#[test]
fn ipv6_requires_tcp_next_header() {
    for next in [0u8, 17, 43, 44, 58, 59, 60, 253, 6] {
        let (mut iface, mut sockets, mut device) = setup();
        iface
            .inner
            .set_ip_addr(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 128));
        let mut bytes = syn_bytes(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::Tcp,
                payload_len: 20,
                hop_limit: 64,
            }
            .into(),
        );
        if next == 0 {
            bytes.splice(40..40, [6, 0, 0, 0, 0, 0, 0, 0]);
            Ipv6Packet::new_unchecked(&mut bytes).set_payload_len(28);
        }
        Ipv6Packet::new_unchecked(&mut bytes).set_next_header(next.into());
        device.rx_queue.push_back(bytes);
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
        assert_eq!(
            device.tx_queue.len(),
            usize::from(next == 6),
            "next header {next}"
        );
    }
}

#[test]
fn tcp_ingress_checks_addresses_and_checksums() {
    for ipv6 in [false, true] {
        for fault in [
            "none",
            "source",
            "destination",
            "protocol",
            "checksum",
            "short",
            "empty",
        ] {
            let (mut iface, mut sockets, mut device) = setup();
            let ip: IpRepr = if ipv6 {
                let dst = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
                iface.inner.set_ip_addr(IpCidr::new(dst.into(), 128));
                Ipv6Repr {
                    src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    dst_addr: dst,
                    next_header: IpProtocol::Tcp,
                    payload_len: 20,
                    hop_limit: 64,
                }
                .into()
            } else {
                Ipv4Repr {
                    src_addr: Ipv4Address::new(192, 168, 1, 2),
                    dst_addr: Ipv4Address::new(192, 168, 1, 1),
                    next_header: IpProtocol::Tcp,
                    payload_len: 20,
                    hop_limit: 64,
                }
                .into()
            };
            let mut bytes = syn_bytes(ip.clone());
            if ipv6 {
                let mut packet = Ipv6Packet::new_unchecked(&mut bytes);
                match fault {
                    "source" => packet.set_src_addr(Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2)),
                    "destination" => packet.set_dst_addr(Ipv6Address::LOCALHOST),
                    "protocol" => packet.set_next_header(IpProtocol::Unknown(253)),
                    _ => {}
                }
            } else {
                let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
                match fault {
                    "source" => packet.set_src_addr(Ipv4Address::BROADCAST),
                    "destination" => packet.set_dst_addr(Ipv4Address::LOCALHOST),
                    "protocol" => packet.set_next_header(IpProtocol::Unknown(253)),
                    _ => {}
                }
                packet.fill_checksum();
            }
            let (src, dst) = if ipv6 {
                let packet = Ipv6Packet::new_unchecked(&bytes);
                (packet.src_addr().into(), packet.dst_addr().into())
            } else {
                let packet = Ipv4Packet::new_unchecked(&bytes);
                (packet.src_addr().into(), packet.dst_addr().into())
            };
            TcpPacket::new_unchecked(&mut bytes[ip.header_len()..]).fill_checksum(&src, &dst);
            match fault {
                "checksum" => bytes[ip.header_len() + 16] ^= 1,
                "short" => bytes.truncate(ip.header_len() + 19),
                "empty" => bytes.clear(),
                _ => {}
            }
            device.rx_queue.push_back(bytes);
            iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
            assert_eq!(
                device.tx_queue.len(),
                usize::from(fault == "none"),
                "IPv6={ipv6}, {fault}"
            );
        }
    }
}

#[test]
fn egress_respects_ip_mtu() {
    for ipv6 in [false, true] {
        let (mut iface, _, mut device) = setup();
        let mtu = iface.inner.ip_mtu();
        for len in [100, mtu, mtu + 1, 4096] {
            let ip = if ipv6 {
                IpRepr::Ipv6(Ipv6Repr {
                    src_addr: Ipv6Address::LOCALHOST,
                    dst_addr: Ipv6Address::LOCALHOST,
                    next_header: IpProtocol::Tcp,
                    payload_len: len - 40,
                    hop_limit: 64,
                })
            } else {
                IpRepr::Ipv4(Ipv4Repr {
                    src_addr: Ipv4Address::LOCALHOST,
                    dst_addr: Ipv4Address::LOCALHOST,
                    next_header: IpProtocol::Tcp,
                    payload_len: len - 20,
                    hop_limit: 64,
                })
            };
            let data = vec![1; len - ip.header_len() - 20];
            let bytes = syn_bytes(IpRepr::new(
                ip.src_addr(),
                ip.dst_addr(),
                IpProtocol::Tcp,
                20,
                64,
            ));
            let packet = TcpPacket::new_unchecked(&bytes[ip.header_len()..]);
            let mut tcp = TcpRepr::parse(&packet, &ip.src_addr(), &ip.dst_addr()).unwrap();
            tcp.payload = &data;
            let token = device.transmit(Instant::ZERO).unwrap();
            iface.inner.dispatch_ip(token, ip.clone(), tcp);
            if len <= mtu {
                let bytes = device.tx_queue.pop_front().unwrap();
                assert_eq!(bytes.len(), len);
                assert!(bytes.len() <= mtu);
                assert_eq!(&bytes[ip.header_len() + 20..], data);
            }
            assert!(device.tx_queue.is_empty());
        }
    }
}

#[test]
fn tcp_reset_with_syn_or_fin_closes_connection() {
    use crate::socket::tcp::{Socket, SocketBuffer, State};

    for flags in [0x04, 0x05, 0x06, 0x07, 0x3f] {
        let (mut iface, mut sockets, mut device) = setup();
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; 64]),
            SocketBuffer::new(vec![0; 64]),
        );
        socket.listen(4243).unwrap();
        let handle = sockets.add(socket);
        let ip = IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address::new(192, 168, 1, 2),
            dst_addr: Ipv4Address::new(192, 168, 1, 1),
            next_header: IpProtocol::Tcp,
            payload_len: 20,
            hop_limit: 64,
        });
        let mut bytes = syn_bytes(ip.clone());
        device.rx_queue.push_back(bytes.clone());
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
        let reply = device.tx_queue.pop_front().unwrap();
        let syn_ack = TcpPacket::new_checked(&reply[20..]).unwrap();
        assert!(syn_ack.syn() && syn_ack.ack());
        let mut packet = TcpPacket::new_unchecked(&mut bytes[20..]);
        packet.set_syn(false);
        packet.set_ack(true);
        packet.set_seq_number(TcpSeqNumber(8));
        packet.set_ack_number(syn_ack.seq_number() + 1);
        packet.fill_checksum(&ip.src_addr(), &ip.dst_addr());
        device.rx_queue.push_back(bytes.clone());
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
        assert_eq!(sockets.get(handle).state(), State::Established);
        bytes[33] = flags;
        TcpPacket::new_unchecked(&mut bytes[20..]).fill_checksum(&ip.src_addr(), &ip.dst_addr());
        device.rx_queue.push_back(bytes);
        iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
        assert_eq!(
            sockets.get(handle).state(),
            State::Closed,
            "flags {flags:#x}"
        );
        assert!(device.tx_queue.is_empty());
    }
}
