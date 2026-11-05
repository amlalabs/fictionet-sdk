use fictionet::stdlib::network::ip::{self, Header, transport_checksum};
use fictionet::stdlib::network::tcp::{self, CookieInput, SynCookies, TcpOption};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, Seed, block_on, lab, pair};
use fictionet_extras::linux::{self, Cookies};
use std::net::SocketAddr;
use std::time::Duration;

fn ipv4_reply(bytes: &[u8]) -> Option<ip::Ipv4Reply> {
    let local = "203.0.113.10".parse().unwrap();
    linux::ipv4_options(
        &ip::Ipv4Options::new(bytes).collect::<Vec<_>>(),
        local,
        "192.0.2.1".parse().unwrap(),
        0x01020304,
        |address| address != local && !address.is_broadcast() && !address.is_multicast(),
    )
}

fn echoed(bytes: &[u8]) -> Option<Vec<u8>> {
    ipv4_reply(bytes).map(|reply| ip::encode_ipv4_options(&reply.options).unwrap())
}

#[test]
fn ipv4_record_route_records_receive_and_reply_addresses() {
    assert_eq!(
        echoed(&[7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0]),
        Some(vec![7, 11, 12, 203, 0, 113, 10, 203, 0, 113, 10])
    );
    assert_eq!(
        echoed(&[7, 7, 4, 0, 0, 0, 0]),
        Some(vec![7, 7, 8, 203, 0, 113, 10])
    );
    assert_eq!(
        echoed(&[7, 7, 8, 192, 0, 2, 9]),
        Some(vec![7, 7, 8, 192, 0, 2, 9])
    );
    assert_eq!(
        echoed(&[7, 15, 5, 99, 0, 0, 0, 0, 0, 0, 0, 0, 88, 77, 66]),
        Some(vec![
            7, 15, 13, 99, 203, 0, 113, 10, 203, 0, 113, 10, 88, 77, 66
        ])
    );
    assert_eq!(echoed(&[7, 7, 5, 0, 0, 0, 0]), None);
}

#[test]
fn ipv4_timestamps_record_receive_and_reply_and_preserve_unaligned_pointers() {
    assert_eq!(
        echoed(&[68, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Some(vec![68, 12, 13, 0, 1, 2, 3, 4, 1, 2, 3, 4])
    );
    assert_eq!(
        echoed(&[68, 16, 6, 0, 99, 0, 0, 0, 0, 0, 0, 0, 0, 88, 77, 66]),
        Some(vec![68, 16, 14, 0, 99, 1, 2, 3, 4, 1, 2, 3, 4, 88, 77, 66])
    );
    assert_eq!(
        echoed(&[68, 20, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        Some(vec![
            68, 20, 21, 1, 203, 0, 113, 10, 1, 2, 3, 4, 203, 0, 113, 10, 1, 2, 3, 4
        ])
    );
    assert_eq!(echoed(&[68, 12, 6, 1, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    assert_eq!(
        echoed(&[
            68, 28, 6, 1, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8
        ]),
        Some(vec![
            68, 28, 22, 1, 99, 203, 0, 113, 10, 1, 2, 3, 4, 203, 0, 113, 10, 1, 2, 3, 4, 8, 8, 8,
            8, 8, 8, 8
        ])
    );
    assert_eq!(
        echoed(&[
            68, 28, 9, 3, 9, 9, 9, 9, 203, 0, 113, 10, 0, 0, 0, 0, 203, 0, 113, 10, 0, 0, 0, 0, 8,
            8, 8, 8
        ]),
        Some(vec![
            68, 28, 25, 3, 9, 9, 9, 9, 203, 0, 113, 10, 1, 2, 3, 4, 203, 0, 113, 10, 1, 2, 3, 4, 8,
            8, 8, 8
        ])
    );
}

#[test]
fn ipv4_prespecified_timestamps_use_route_classification() {
    for address in [[203, 0, 113, 10], [255, 255, 255, 255], [224, 0, 0, 1]] {
        let mut input = vec![68, 20, 5, 3];
        input.extend(address);
        input.extend([0; 4]);
        input.extend(address);
        input.extend([0; 4]);
        let mut expected = vec![68, 20, 21, 3];
        expected.extend(address);
        expected.extend([1, 2, 3, 4]);
        expected.extend(address);
        expected.extend([1, 2, 3, 4]);
        assert_eq!(echoed(&input), Some(expected));
    }
    let unicast = [
        68, 20, 5, 3, 192, 0, 2, 9, 0, 0, 0, 0, 203, 0, 113, 10, 0, 0, 0, 0,
    ];
    assert_eq!(echoed(&unicast), Some(unicast.to_vec()));
    assert_eq!(
        echoed(&[
            68, 20, 5, 3, 203, 0, 113, 10, 0, 0, 0, 0, 192, 0, 2, 9, 0, 0, 0, 0
        ]),
        Some(vec![
            68, 20, 13, 3, 203, 0, 113, 10, 1, 2, 3, 4, 192, 0, 2, 9, 0, 0, 0, 0
        ])
    );
}

#[test]
fn ipv4_timestamp_overflow_and_unknown_flags_follow_receive_rules() {
    for flags in 0..16 {
        let expected = if flags == 3 { 0xe3 } else { 0xf0 | flags };
        assert_eq!(
            echoed(&[68, 4, 5, 0xe0 | flags]),
            Some(vec![68, 4, 5, expected])
        );
        assert_eq!(
            echoed(&[68, 4, 255, 0xf0 | flags]),
            (flags == 3).then(|| vec![68, 4, 255, 0xf3])
        );
        if ![0, 1, 3].contains(&flags) {
            let input = [68, 8, 5, flags, 1, 2, 3, 4];
            assert_eq!(echoed(&input), Some(input.to_vec()));
            assert_eq!(echoed(&[68, 7, 5, flags, 1, 2, 3]), None);
        }
    }
    assert_eq!(
        echoed(&[68, 8, 5, 0xf0, 0, 0, 0, 0]),
        Some(vec![68, 8, 9, 0xf0, 1, 2, 3, 4])
    );
}

#[test]
fn ipv4_source_routes_reverse_consumed_hops_and_remove_duplicate_source() {
    for kind in [131, 137] {
        for pointer in [16, 255] {
            let reply =
                ipv4_reply(&[kind, 15, pointer, 192, 0, 2, 5, 192, 0, 2, 6, 192, 0, 2, 7]).unwrap();
            assert_eq!(reply.destination, Some("192.0.2.7".parse().unwrap()));
            assert_eq!(
                ip::encode_ipv4_options(&reply.options).unwrap(),
                [kind, 15, 4, 192, 0, 2, 6, 192, 0, 2, 5, 192, 0, 2, 1]
            );
        }
        let reply = ipv4_reply(&[kind, 15, 16, 192, 0, 2, 1, 192, 0, 2, 6, 192, 0, 2, 7]).unwrap();
        assert_eq!(reply.destination, Some("192.0.2.7".parse().unwrap()));
        assert_eq!(
            ip::encode_ipv4_options(&reply.options).unwrap(),
            [kind, 11, 4, 192, 0, 2, 6, 192, 0, 2, 1]
        );
        assert_eq!(
            ipv4_reply(&[kind, 7, 8, 192, 0, 2, 1]).unwrap(),
            ip::Ipv4Reply::default()
        );
        assert_eq!(
            ipv4_reply(&[kind, 7, 4, 192, 0, 2, 1]).unwrap(),
            ip::Ipv4Reply::default()
        );
        let reply = ipv4_reply(&[kind, 11, 8, 192, 0, 2, 6, 192, 0, 2, 7]).unwrap();
        assert_eq!(reply.destination, Some("192.0.2.6".parse().unwrap()));
        assert_eq!(
            ip::encode_ipv4_options(&reply.options).unwrap(),
            [kind, 7, 4, 192, 0, 2, 1]
        );
    }
}

#[test]
fn ipv4_invalid_and_duplicate_options_cannot_produce_a_reply() {
    for input in [
        &[7, 3, 3][..],
        &[68, 4, 4, 0],
        &[7, 9, 4, 0],
        &[7, 3, 4, 7, 3, 4],
        &[68, 4, 5, 0, 68, 4, 5, 3],
        &[131, 3, 4, 137, 3, 4],
    ] {
        assert_eq!(echoed(input), None, "{input:?}");
    }
    assert_eq!(echoed(&[1, 222, 4, 12, 13, 0, 7, 3, 3]), Some(vec![]));
    assert_eq!(
        echoed(&[68, 4, 5, 0, 7, 3, 4]),
        Some(vec![7, 3, 4, 68, 4, 5, 16])
    );
}

fn packet(
    from: SocketAddr,
    to: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
) -> Packet {
    let size = 20 + options.len().div_ceil(4) * 4;
    let mut tcp = vec![0; size];
    tcp[..2].copy_from_slice(&from.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&to.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = (size / 4) as u8 * 16;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
    tcp[20..20 + options.len()].copy_from_slice(options);
    let sum = transport_checksum(from.ip(), to.ip(), 6, &tcp);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    ip::packet(from.ip(), to.ip(), 6, &tcp)
}

async fn receive(raw: &mut End, cx: &Cx) -> Vec<u8> {
    let p = cx
        .race(Some(cx.now() + Duration::from_secs(1)), raw.recv(cx))
        .await
        .unwrap()
        .unwrap();
    Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec()
}

fn sequence(t: &[u8]) -> u32 {
    u32::from_be_bytes(t[4..8].try_into().unwrap())
}

fn timestamp(t: &[u8]) -> u32 {
    tcp::options(t)
        .unwrap()
        .iter()
        .find_map(|o| match o {
            TcpOption::Timestamps { tsval, .. } => Some(*tsval),
            _ => None,
        })
        .unwrap()
}

#[test]
fn syn_ack_bytes_offsets_and_repeated_syn() {
    block_on(lab(Seed::from_u64(7), |cx| async move {
        let (mut raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1000".parse()?;
        let server = tcp::endpoint_with(&cx, side, local.ip(), linux::tcp());
        let mut listener = server.listen(80)?;
        let options = [
            2, 4, 5, 180, 4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        let syn = packet(peer, local, 100, 0, 2, &options);
        raw.send(syn.clone());
        let first = receive(&mut raw, &cx).await;
        assert_eq!(first[13], 0x12);
        assert_eq!(&first[14..16], &65160u16.to_be_bytes());
        assert_eq!(&first[20..28], &[2, 4, 5, 180, 4, 2, 8, 10]);
        assert_eq!(&first[32..40], &[1, 2, 3, 4, 1, 3, 3, 7]);
        let ts = timestamp(&first);
        assert_ne!(ts, 0);
        raw.send(syn);
        let repeat = receive(&mut raw, &cx).await;
        assert_eq!(repeat, first);
        raw.send(packet(
            SocketAddr::new(peer.ip(), 1001),
            local,
            100,
            0,
            2,
            &options,
        ));
        let second = receive(&mut raw, &cx).await;
        assert_eq!(timestamp(&second), ts);
        raw.send(packet("10.0.0.3:1000".parse()?, local, 100, 0, 2, &options));
        assert_ne!(timestamp(&receive(&mut raw, &cx).await), ts);
        raw.send(packet(
            SocketAddr::new(peer.ip(), 1002),
            local,
            100,
            0,
            2,
            &[2, 4, 5, 180, 4, 2, 3, 3, 7],
        ));
        let plain = receive(&mut raw, &cx).await;
        assert_eq!(&plain[14..16], &64240u16.to_be_bytes());
        assert_eq!(&plain[20..32], &[2, 4, 5, 180, 1, 1, 4, 2, 1, 3, 3, 7]);
        let mut echo = vec![1, 1, 8, 10];
        echo.extend_from_slice(&0x0102_0305u32.to_be_bytes());
        echo.extend_from_slice(&ts.to_be_bytes());
        let next = sequence(&first).wrapping_add(1);
        raw.send(packet(peer, local, 101, next, 16, &echo));
        let _connection = listener.accept(&cx).await?;
        let out_of_order = packet(peer, local, 102, next, 16, &echo);
        let mut tcp = Header::parse_whole(&out_of_order.0)
            .unwrap()
            .payload(&out_of_order.0)
            .to_vec();
        tcp.extend_from_slice(b"hello");
        tcp[16..18].fill(0);
        let sum = transport_checksum(peer.ip(), local.ip(), 6, &tcp);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        raw.send(ip::packet(peer.ip(), local.ip(), 6, &tcp));
        let sack = receive(&mut raw, &cx).await;
        assert_eq!(&sack[20..24], &[1, 1, 8, 10]);
        assert_eq!(&sack[32..44], &[1, 1, 5, 10, 0, 0, 0, 102, 0, 0, 0, 107]);
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn cookie_encoding_keeps_options_and_authenticates_the_attempt() {
    for (local, remote, mss) in [
        ("10.0.0.1:80", "10.0.0.2:1000", 1460),
        ("[2001:db8::1]:80", "[2001:db8::2]:1000", 1440),
    ] {
        for scale in [None, Some(0), Some(7), Some(14)] {
            for sack in [false, true] {
                for timestamps in [false, true] {
                    let mut options = vec![TcpOption::MaxSegmentSize(mss)];
                    if let Some(scale) = scale {
                        options.push(TcpOption::WindowScale(scale));
                    }
                    if sack {
                        options.push(TcpOption::SackPermitted);
                    }
                    if timestamps {
                        options.push(TcpOption::Timestamps {
                            tsval: 1234,
                            tsecr: 0,
                        });
                    }
                    let key = [42; 32];
                    let mut input = CookieInput {
                        key: &key,
                        local: local.parse().unwrap(),
                        remote: remote.parse().unwrap(),
                        sequence: u32::MAX,
                        now: Duration::from_secs(59),
                        options: &options,
                        ecn: true,
                    };
                    let issued = Cookies.issue(&input);
                    let cookie = issued.sequence;
                    let sent = issued.options;
                    assert_eq!(issued.ecn, timestamps);
                    let ack: Vec<_> = sent
                        .iter()
                        .filter_map(|o| match o {
                            TcpOption::Timestamps { tsval, .. } => Some(TcpOption::Timestamps {
                                tsval: 1235,
                                tsecr: *tsval,
                            }),
                            _ => None,
                        })
                        .collect();
                    input.options = &ack;
                    let kept = Cookies.validate(&input, cookie).unwrap();
                    assert_eq!(kept.mss, mss);
                    assert_eq!(kept.scale, if timestamps { scale } else { None });
                    assert_eq!(kept.sack, timestamps && sack);
                    assert_eq!(kept.ecn, timestamps);
                    assert_eq!(kept.timestamp.is_some(), timestamps);
                    input.now = Duration::from_secs(119);
                    assert!(Cookies.validate(&input, cookie).is_some());
                    input.now = Duration::from_secs(120);
                    assert!(Cookies.validate(&input, cookie).is_none());
                    input.now = Duration::from_secs(59);
                    input.remote.set_port(1001);
                    assert!(Cookies.validate(&input, cookie).is_none());
                    input.remote.set_port(1000);
                    // The additive cookie format permits a small sequence change
                    // to select a smaller MSS index, exactly as the kernel does.
                    input.sequence = 1;
                    assert_eq!(
                        Cookies.validate(&input, cookie).unwrap().mss,
                        if input.local.is_ipv6() { 1220 } else { 1300 }
                    );
                    input.sequence = 1 << 20;
                    assert!(Cookies.validate(&input, cookie).is_none());
                }
            }
        }
    }
}

#[test]
fn cookie_connection_restores_timestamp_and_window_scale() {
    block_on(lab(Seed::from_u64(11), |cx| async move {
        let (mut raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1000".parse()?;
        let server = tcp::endpoint_with(&cx, side, local.ip(), linux::tcp().backlog(1));
        let mut listener = server.listen(80)?;
        let options = [
            2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 9, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        raw.send(packet(peer, local, 100, 0, 2, &options));
        let stateful = timestamp(&receive(&mut raw, &cx).await);
        let peer = SocketAddr::new(peer.ip(), 1001);
        raw.send(packet(peer, local, 100, 0, 2, &options));
        let syn_ack = receive(&mut raw, &cx).await;
        let ts = timestamp(&syn_ack);
        assert!(stateful.wrapping_sub(ts) < 64);
        let mut options = vec![1, 1, 8, 10];
        options.extend_from_slice(&10u32.to_be_bytes());
        options.extend_from_slice(&ts.to_be_bytes());
        raw.send(packet(
            peer,
            local,
            101,
            sequence(&syn_ack).wrapping_add(1),
            16,
            &options,
        ));
        let mut connection = listener.accept(&cx).await?;
        assert_eq!(
            connection.handshake().unwrap().origin,
            tcp::HandshakeOrigin::Cookie
        );
        use fictionet::stdlib::network::ConnectionExt;
        connection.write_all(&cx, b"hello").await?;
        // Restoring the smaller SYN window prompts an update to the full
        // receive buffer. Check it separately from the application's data.
        let update = receive(&mut raw, &cx).await;
        assert_eq!(update[13], 16);
        assert_eq!(sequence(&update), sequence(&syn_ack).wrapping_add(1));
        assert_eq!(update.len(), usize::from(update[12] >> 4) * 4);
        assert_eq!(&update[20..24], &[1, 1, 8, 10]);
        assert!(timestamp(&update).wrapping_sub(ts) < 64);
        assert_eq!(&update[14..16], &2048u16.to_be_bytes());
        let data = receive(&mut raw, &cx).await;
        assert_eq!(sequence(&data), sequence(&syn_ack).wrapping_add(1));
        assert_eq!(&data[usize::from(data[12] >> 4) * 4..], b"hello");
        assert_eq!(&data[20..24], &[1, 1, 8, 10]);
        assert!(timestamp(&data).wrapping_sub(ts) < 64);
        assert_eq!(&data[14..16], &2048u16.to_be_bytes());
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn mptcp_data_ack_width_matches_the_peer_mapping() {
    use fictionet::stdlib::protocols::mptcp::{
        DataLevel, Dss, Mapping, MptcpOption, Sequence, idsn,
    };
    let mut level = DataLevel::new(7, 9, 100, 200, false, None).ack_width(linux::mptcp_ack_width());
    let dsn = idsn(9).advance(1);
    assert_eq!(
        level.sent(101, b"", false, true).unwrap().data_ack,
        Some(Sequence::Short(dsn.short()))
    );
    for sequence in [Sequence::Long(dsn), Sequence::Short(dsn.short())] {
        level.received(
            201,
            0,
            [MptcpOption::Dss(Dss {
                data_ack: None,
                mapping: Some(Mapping {
                    data_sequence_number: sequence,
                    subflow_sequence_number: 1,
                    data_level_length: 5,
                    checksum: None,
                }),
                data_fin: false,
            })],
        );
        assert_eq!(level.error(), None);
        assert!(!level.fallen_back());
        assert_eq!(
            level.sent(101, b"", false, true).unwrap().data_ack,
            Some(sequence)
        );
    }
}

#[test]
fn time_wait_expires_after_sixty_seconds() {
    block_on(lab(Seed::from_u64(13), |cx| async move {
        let (mut raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1000".parse()?;
        let server = tcp::endpoint_with(&cx, side, local.ip(), linux::tcp());
        let mut listener = server.listen(80)?;
        raw.send(packet(peer, local, 100, 0, 2, &[]));
        let syn_ack = receive(&mut raw, &cx).await;
        let next = sequence(&syn_ack).wrapping_add(1);
        raw.send(packet(peer, local, 101, next, 16, &[]));
        drop(listener.accept(&cx).await?);
        let fin = receive(&mut raw, &cx).await;
        assert_eq!(fin[13] & 1, 1);
        let fin = packet(peer, local, 101, next.wrapping_add(1), 17, &[]);
        raw.send(fin.clone());
        let ack = raw.recv(&cx).await?;
        assert_eq!(Header::parse_whole(&ack.0).unwrap().payload(&ack.0)[13], 16);
        assert_eq!(&ack.0[4..6], &[0, 0]);
        cx.sleep(Duration::from_secs(59)).await?;
        raw.send(fin.clone());
        assert_eq!(receive(&mut raw, &cx).await[13], 16);
        // Retransmitting the FIN restarts the TIME-WAIT timer.
        cx.sleep(Duration::from_secs(60)).await?;
        raw.send(fin);
        assert_eq!(receive(&mut raw, &cx).await[13], 4);
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}
