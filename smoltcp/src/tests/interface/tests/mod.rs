use crate::tests::setup;

use super::*;

struct LimitedDevice {
    inner: crate::tests::TestingDevice,
    remaining: usize,
}

impl Device for LimitedDevice {
    type RxToken<'a> = crate::tests::RxToken;
    type TxToken<'a> = crate::tests::TxToken<'a>;

    fn capabilities(&self) -> crate::tests::phy::DeviceCapabilities {
        self.inner.capabilities()
    }

    fn receive(&mut self, now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inner.receive(now)
    }

    fn transmit(&mut self, now: Instant) -> Option<Self::TxToken<'_>> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.inner.transmit(now)
    }
}

#[test]
fn indexed_deadlines_follow_mutation_removal_and_slot_reuse() {
    use crate::socket::{
        PollAt,
        tcp::{Socket, SocketBuffer},
    };
    let (mut iface, mut sockets, mut device) = setup();
    let make = || {
        Socket::new(
            SocketBuffer::new(vec![0; 64]),
            SocketBuffer::new(vec![0; 64]),
        )
    };
    let check = |iface: &mut Interface, sockets: &mut SocketSet<'_>, now| {
        iface.poll_maintenance(now);
        let expected = sockets
            .iter()
            .filter_map(|(_, socket)| match socket.poll_at(iface.context()) {
                PollAt::Ingress => None,
                PollAt::Time(at) => Some(at),
                PollAt::Now => Some(Instant::ZERO),
            })
            .min();
        assert_eq!(iface.poll_at(now, sockets), expected);
    };
    let mut handles = Vec::new();
    for port in [80, 81, 82] {
        let mut socket = make();
        socket
            .connect(
                iface.context(),
                (Ipv4Address::new(192, 168, 1, 2), port),
                (Ipv4Address::new(192, 168, 1, 1), 4242),
            )
            .unwrap();
        handles.push(sockets.add(socket));
    }
    for millis in [0, 500, 1000, 2000] {
        let now = Instant::from_millis(millis);
        check(&mut iface, &mut sockets, now);
        iface.poll_egress(now, &mut device, &mut sockets);
        check(&mut iface, &mut sockets, now);
    }
    sockets
        .get_mut(handles[0])
        .set_timeout(Some(crate::time::Duration::from_millis(2500)));
    check(&mut iface, &mut sockets, Instant::from_millis(2000));
    sockets.remove(handles[0]);
    let mut listener = make();
    listener.listen(4243).unwrap();
    assert_eq!(sockets.add(listener), handles[0]);
    check(&mut iface, &mut sockets, Instant::from_millis(2000));
    for h in handles {
        sockets.remove(h);
    }
    assert_eq!(
        iface.poll_at(Instant::from_millis(3000), &mut sockets),
        None
    );
}

#[test]
fn egress_keeps_slot_order_after_an_unsaturated_pass() {
    use crate::socket::tcp::{Socket, SocketBuffer};
    let (mut iface, mut sockets, mut device) = setup();
    let local = (Ipv4Address::new(192, 168, 1, 1), 4242);
    let remote = Ipv4Address::new(192, 168, 1, 2);
    let mut handles = Vec::new();
    for port in [80, 81] {
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; 64]),
            SocketBuffer::new(vec![0; 64]),
        );
        socket
            .connect(iface.context(), (remote, port), local)
            .unwrap();
        handles.push(sockets.add(socket));
    }
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    sockets.get_mut(handles[0]).abort();
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    sockets
        .get_mut(handles[0])
        .connect(iface.context(), (remote, 80), local)
        .unwrap();
    sockets.get_mut(handles[1]).abort();
    device.tx_queue.clear();
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let ports: Vec<_> = device
        .tx_queue
        .iter()
        .map(|p| TcpPacket::new_checked(&p[20..]).unwrap().dst_port())
        .collect();
    assert_eq!(ports, [80, 81]);
}

#[test]
fn egress_rotates_when_an_earlier_socket_becomes_ready_again() {
    use crate::socket::tcp::{Socket, SocketBuffer};
    let (mut iface, mut sockets, device) = setup();
    let mut device = LimitedDevice {
        inner: device,
        remaining: 1,
    };
    let mut handles = Vec::new();
    for port in [80, 81] {
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; 64]),
            SocketBuffer::new(vec![0; 64]),
        );
        socket
            .connect(
                iface.context(),
                (Ipv4Address::new(192, 168, 1, 2), port),
                (Ipv4Address::new(192, 168, 1, 1), 4242),
            )
            .unwrap();
        handles.push(sockets.add(socket));
    }
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    sockets.get_mut(handles[0]).abort();
    device.remaining = 1;
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    let ports: Vec<_> = device
        .inner
        .tx_queue
        .iter()
        .map(|p| TcpPacket::new_checked(&p[20..]).unwrap().dst_port())
        .collect();
    assert_eq!(ports, [80, 81]);
    device.remaining = 1;
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert!(
        TcpPacket::new_checked(&device.inner.tx_queue.back().unwrap()[20..])
            .unwrap()
            .rst()
    );
}

#[test]
fn targeted_ingress_keeps_connection_precedence_and_validates_input() {
    use crate::socket::tcp::{Socket, SocketBuffer, State};
    let (mut iface, mut sockets, mut device) = setup();
    let make = || {
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; 64]),
            SocketBuffer::new(vec![0; 64]),
        );
        socket.listen(4243).unwrap();
        socket
    };
    let listener = sockets.add(make());
    let mut connection = make();
    connection.accept_syn_cookie(
        (Ipv4Address::new(192, 168, 1, 1), 4243).into(),
        (Ipv4Address::new(192, 168, 1, 2), 4242).into(),
        7,
        100,
        536,
        Instant::ZERO,
    );
    let target = sockets.add(connection);
    let ip = IpRepr::Ipv4(Ipv4Repr {
        identification: 0,
        options: Ipv4OptionBytes::EMPTY,
        wire_dst: None,
        src_addr: Ipv4Address::new(192, 168, 1, 2),
        dst_addr: Ipv4Address::new(192, 168, 1, 1),
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    let bytes = syn_bytes(ip.clone());
    device.rx_queue.push_back(bytes.clone());
    iface.poll_ingress_targeted(Instant::ZERO, &mut device, &mut sockets, target);
    assert_eq!(sockets.get(listener).state(), State::Listen);
    assert_eq!(sockets.get(target).state(), State::SynReceived);

    let mut invalid = bytes.clone();
    invalid[36] ^= 1;
    device.tx_queue.clear();
    device.rx_queue.push_back(invalid);
    iface.poll_ingress_targeted(Instant::ZERO, &mut device, &mut sockets, target);
    assert!(device.tx_queue.is_empty());
    assert_eq!(sockets.get(target).state(), State::SynReceived);

    // Once the owner is closed, a SYN for its tuple is answered as one for
    // a closed port, and the listener does not take it.
    sockets.get_mut(target).abort();
    device.tx_queue.clear();
    device.rx_queue.push_back(bytes.clone());
    iface.poll_ingress_targeted(Instant::ZERO, &mut device, &mut sockets, target);
    assert_eq!(sockets.get(target).state(), State::Closed);
    assert_eq!(sockets.get(listener).state(), State::Listen);
    let answer = device.tx_queue.pop_front().expect("a RST answers the SYN");
    assert!(TcpPacket::new_checked(&answer[20..]).unwrap().rst());

    // A segment for a tuple no connection owns finds the listener.
    let mut other = bytes;
    let mut tcp = TcpPacket::new_unchecked(&mut other[20..]);
    tcp.set_src_port(4244);
    tcp.fill_checksum(&ip.src_addr(), &ip.dst_addr());
    device.rx_queue.push_back(other);
    iface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(sockets.get(listener).state(), State::SynReceived);
    assert_eq!(sockets.get(listener).remote_endpoint().unwrap().port, 4244);
}

#[test]
fn tcp_not_accepted() {
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
        extra: &[],
        layout: crate::wire::OptionLayout {
            order: crate::wire::OptionOrder::WindowBeforeSack,
            align: false,
        },
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
                extra: &[],
                layout: crate::wire::OptionLayout {
                    order: crate::wire::OptionOrder::WindowBeforeSack,
                    align: false
                },
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
fn tcp_listen_drops_unspecified_src() {
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
        extra: &[],
        layout: crate::wire::OptionLayout {
            order: crate::wire::OptionOrder::WindowBeforeSack,
            align: false,
        },
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
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }),
        &tcp_bytes,
    );

    assert_eq!(reply, None);
    assert_eq!(
        sockets.get(handle).state(),
        crate::socket::tcp::State::Listen
    );
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
        extra: &[],
        layout: crate::wire::OptionLayout {
            order: crate::wire::OptionOrder::WindowBeforeSack,
            align: false,
        },
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
                identification: 0,
                options: crate::wire::Ipv4OptionBytes::EMPTY,
                wire_dst: None,
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
            .set_ip_addr(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into());
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
                iface.inner.set_ip_addr(dst.into());
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
                    identification: 0,
                    options: crate::wire::Ipv4OptionBytes::EMPTY,
                    wire_dst: None,
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
                    identification: 0,
                    options: crate::wire::Ipv4OptionBytes::EMPTY,
                    wire_dst: None,
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
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
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
