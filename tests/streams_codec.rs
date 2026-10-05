//! Counted stream framers, strict wire values, and unchanged legacy APIs.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, chunks},
};
use fictionet::stdlib::{openvpn, rtcp, rtp, snmp, ssh};

fn round_trip<D>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D: Decode,
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_stack(&make, bytes);
    for pattern in [&[][..], &[1], &[1, 2, 3, 1, 257], &[7, 1, 128]] {
        let capacity = make().capacity();
        let mut stream = Stream::new(make());
        let mut items = Vec::new();
        for part in chunks(bytes, pattern) {
            assert_eq!(
                pump(&mut stream, part, |item| items.push(item)),
                Ok(part.len())
            );
            assert!(stream.buffered() <= capacity);
            assert_eq!(stream.held(), 0);
        }
        finish(&mut stream, |item| items.push(item)).unwrap();
        assert_eq!(items, expected);
        assert_eq!(stream.offset(), bytes.len() as u64);
        assert_eq!(stream.buffered(), 0);
        assert!(stream.is_done());
        assert!(stream.failed().is_none());
    }
}

fn truncated<D>(make: impl Fn() -> D, bytes: &[u8])
where
    D: Decode,
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    // Every nonempty proper prefix of one valid unit ends in truncation.
    for cut in 1..bytes.len() {
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(&bytes[..cut]), cut);
        assert_eq!(stream.next(), None);
        stream.end();
        let error = Fail::Truncated { unread: cut };
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.failed(), Some(&error));
        assert!(stream.is_done());
        assert_eq!(stream.next(), None);
    }
}

fn refused_header<D>(make: impl Fn() -> D, header: &[u8], expected: D::Error)
where
    D: Decode,
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode(&make, header);
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(header), header.len());
    let error = Fail::Protocol(expected);
    assert_eq!(stream.next(), Some(Err(error.clone())));
    assert_eq!(stream.failed(), Some(&error));
    assert!(stream.is_done());
    assert_eq!(stream.offset(), 0);
    assert_eq!(stream.unread(), header);
    assert_eq!(stream.held(), 0);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.push(b"discarded after failure"), 23);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.unread(), header);
}

fn wire_bytes<T: Wire + Debug + PartialEq>(value: &T) -> Vec<u8> {
    contract::check_wire_value(value);
    let bytes = Wire::to_bytes(value).unwrap();
    contract::check_wire::<T>(&bytes);
    assert_eq!(&T::parse(&bytes).unwrap(), value);
    bytes
}

fn refuses_value<T: Wire + Debug + PartialEq>(value: &T) {
    contract::check_wire_value(value);
    let mut out = vec![9, 8, 7];
    assert!(value.write(&mut out).is_err());
    assert_eq!(out, [9, 8, 7]);
}

fn vpn_control() -> openvpn::Packet {
    openvpn::Packet::Control {
        kind: openvpn::ControlKind::ControlV1,
        key_id: 2,
        body: openvpn::ControlBody::Plain(openvpn::Control {
            session_id: [7; 8],
            tls_auth: None,
            ack: Some(openvpn::Ack {
                ids: vec![3, 4],
                remote_session_id: [8; 8],
            }),
            message_id: 5,
            payload: b"TLS fragment".to_vec(),
        }),
    }
}

#[test]
fn openvpn_chunked_tcp_round_trip() {
    let packets = vec![
        vpn_control(),
        openvpn::Packet::DataV1 {
            key_id: 1,
            payload: vec![0x55; 41],
        },
        openvpn::Packet::DataV2 {
            key_id: 7,
            peer_id: 0x123456,
            payload: vec![3; 19],
        },
    ];
    let mut bytes = Vec::new();
    for packet in &packets {
        let frame = openvpn::Frame(packet.to_bytes().unwrap());
        let encoded = wire_bytes(&frame);
        assert_eq!(encoded, packet.to_tcp_bytes().unwrap());
        truncated(openvpn::Frames::new, &encoded);
        Wire::write(&frame, &mut bytes).unwrap();
    }
    round_trip(
        || {
            openvpn::Frames::new()
                .map(|frame| openvpn::Packet::parse(&frame.0, openvpn::Wrapping::None))
        },
        &bytes,
        &packets.into_iter().map(Ok).collect::<Vec<_>>(),
    );
}

#[test]
fn openvpn_packet_errors_and_framing_errors() {
    let packet = vpn_control();
    let mut bytes = wire_bytes(&openvpn::Frame(vec![0])); // Unknown opcode, valid envelope.
    openvpn::Frame(packet.to_bytes().unwrap())
        .write(&mut bytes)
        .unwrap();
    round_trip(
        || {
            openvpn::Frames::new()
                .map(|frame| openvpn::Packet::parse(&frame.0, openvpn::Wrapping::None))
        },
        &bytes,
        &[Err(openvpn::Error::Opcode(0)), Ok(packet)],
    );
    refused_header(
        || openvpn::Frames::with_limit(16),
        &[0, 17],
        openvpn::StreamError::TooLong {
            length: 17,
            limit: 16,
        },
    );
    refused_header(
        openvpn::Frames::new,
        &[0, 0],
        openvpn::StreamError::Frame(openvpn::FrameError::ZeroLength),
    );
}

#[test]
fn openvpn_wrapping_stays_explicit() {
    let mut packet = vpn_control();
    let openvpn::Packet::Control {
        body: openvpn::ControlBody::Plain(control),
        ..
    } = &mut packet
    else {
        panic!("control fixture");
    };
    control.tls_auth = Some(openvpn::TlsAuth {
        hmac: vec![9; 20],
        packet_id: 7,
        net_time: 8,
    });
    let bytes = wire_bytes(&openvpn::Frame(packet.to_bytes().unwrap()));
    round_trip(
        || {
            openvpn::Frames::new().map(|frame| {
                openvpn::Packet::parse(&frame.0, openvpn::Wrapping::TlsAuth { hmac_len: 20 })
            })
        },
        &bytes,
        &[Ok(packet)],
    );
}

#[test]
fn openvpn_wire_is_exact_and_transactional() {
    refuses_value(&openvpn::Frame(vec![]));
    refuses_value(&openvpn::Frame(vec![1; openvpn::MAX_PACKET + 1]));
    let mut bytes = wire_bytes(&openvpn::Frame(vec![1]));
    bytes.push(0);
    assert_eq!(
        <openvpn::Frame as Wire>::parse(&bytes),
        Err(openvpn::FrameParseError::Trailing)
    );
    assert_eq!(
        <openvpn::Frame as Wire>::parse(&[0, 2, 1]),
        Err(openvpn::FrameParseError::Truncated)
    );
}

fn media_packet() -> rtp::RtpPacket {
    rtp::RtpPacket {
        marker: true,
        payload_type: 96,
        sequence: 17,
        timestamp: 12345,
        ssrc: 42,
        csrcs: vec![1, 2],
        extension: Some(rtp::HeaderExtension::OneByte(vec![rtp::Element {
            id: 3,
            data: vec![4, 5],
        }])),
        payload: b"encoded media".to_vec(),
        padding: 3,
    }
}

#[test]
fn rtp_chunked_rfc4571_round_trip() {
    let a = media_packet();
    let mut b = a.clone();
    b.sequence += 1;
    b.extension = Some(rtp::HeaderExtension::TwoByte {
        app_bits: 7,
        elements: vec![rtp::Element {
            id: 255,
            data: vec![],
        }],
    });
    let mut c = a.clone();
    c.extension = Some(rtp::HeaderExtension::Other {
        profile: 0x4321,
        data: vec![1; 4],
    });
    let mut bytes = wire_bytes(&rtp::Frame::default());
    for packet in [&a, &b, &c] {
        let encoded = wire_bytes(&rtp::Frame(wire_bytes(packet)));
        truncated(rtp::Frames::new, &encoded);
        bytes.extend(encoded);
    }
    round_trip(
        || {
            rtp::Frames::new().map(|frame| {
                if frame.0.is_empty() {
                    Ok(None)
                } else {
                    rtp::RtpPacket::parse(&frame.0).map(Some)
                }
            })
        },
        &bytes,
        &[Ok(None), Ok(Some(a)), Ok(Some(b)), Ok(Some(c))],
    );
}

#[test]
fn rtp_body_error_keeps_stream_and_limit_error_ends_it() {
    let packet = media_packet();
    let mut bytes = wire_bytes(&rtp::Frame(vec![0, 0]));
    rtp::Frame(wire_bytes(&packet)).write(&mut bytes).unwrap();
    round_trip(
        || rtp::Frames::new().map(|frame| rtp::RtpPacket::parse(&frame.0)),
        &bytes,
        &[Err(rtp::RtpError::Version(0)), Ok(packet)],
    );
    refused_header(
        || rtp::Frames::with_limit(12),
        &[0, 13],
        rtcp::FrameError {
            length: 13,
            limit: 12,
        },
    );
}

#[test]
fn rtp_strict_writer_refuses_clipping_and_extension_aliases() {
    let good = media_packet();
    let mut bad = good.clone();
    bad.payload_type = 128;
    refuses_value(&bad);
    bad = good.clone();
    bad.csrcs = vec![0; rtp::MAX_CSRCS + 1];
    refuses_value(&bad);
    bad = good.clone();
    bad.payload = vec![0; rtp::MAX_PACKET];
    refuses_value(&bad);
    for extension in [
        rtp::HeaderExtension::OneByte(vec![rtp::Element {
            id: 0,
            data: vec![1],
        }]),
        rtp::HeaderExtension::OneByte(vec![rtp::Element {
            id: 1,
            data: vec![],
        }]),
        rtp::HeaderExtension::TwoByte {
            app_bits: 16,
            elements: vec![],
        },
        rtp::HeaderExtension::TwoByte {
            app_bits: 0,
            elements: vec![rtp::Element {
                id: 1,
                data: vec![0; 256],
            }],
        },
        rtp::HeaderExtension::Other {
            profile: rtp::ONE_BYTE_PROFILE,
            data: vec![0; 4],
        },
        rtp::HeaderExtension::Other {
            profile: 0x4321,
            data: vec![1],
        },
    ] {
        bad = good.clone();
        bad.extension = Some(extension);
        refuses_value(&bad);
        assert!(rtp::RtpPacket::parse(&bad.to_bytes()).is_ok()); // Legacy normalization remains.
    }
}

fn reports() -> Vec<rtcp::Packet> {
    vec![
        rtcp::Body::ReceiverReport(rtcp::ReceiverReport {
            ssrc: 7,
            reports: vec![],
            extension: vec![],
        })
        .into(),
        rtcp::Body::SourceDescription(vec![rtcp::SdesChunk {
            ssrc: 7,
            items: vec![rtcp::SdesItem {
                kind: rtcp::sdes::CNAME,
                text: b"sender@example".to_vec(),
            }],
        }])
        .into(),
        rtcp::Body::PayloadFeedback(rtcp::PayloadFeedback {
            sender_ssrc: 7,
            media_ssrc: 0,
            message: rtcp::PayloadMessage::Remb(rtcp::Remb {
                exponent: 3,
                mantissa: 12345,
                ssrcs: vec![1, 2],
            }),
        })
        .into(),
        rtcp::Body::ExtendedReport(rtcp::ExtendedReport {
            ssrc: 7,
            blocks: vec![rtcp::XrBlock::receiver_reference_time(0x123456789abcdef0)],
        })
        .into(),
    ]
}

#[test]
fn rtcp_chunked_compound_round_trip() {
    let packets = reports();
    let mut datagram = Vec::new();
    for packet in &packets {
        wire_bytes(packet);
        packet.write(&mut datagram).unwrap();
    }
    assert_eq!(rtcp::parse_compound(&datagram), Ok(packets.clone()));
    let encoded = wire_bytes(&rtcp::Frame(datagram));
    truncated(rtcp::Frames::new, &encoded);
    let bytes = [
        encoded.clone(),
        wire_bytes(&rtcp::Frame::default()),
        encoded,
    ]
    .concat();
    round_trip(
        || {
            rtcp::Frames::new().map(|frame| {
                if frame.0.is_empty() {
                    Ok(None)
                } else {
                    rtcp::parse_compound(&frame.0).map(Some)
                }
            })
        },
        &bytes,
        &[Ok(Some(packets.clone())), Ok(None), Ok(Some(packets))],
    );
}

#[test]
fn rtcp_body_error_keeps_stream_and_limit_error_ends_it() {
    let packet = reports().remove(0);
    let mut bytes = wire_bytes(&rtcp::Frame(vec![0x80, rtcp::packet_type::RR, 0, 0]));
    rtcp::Frame(wire_bytes(&packet)).write(&mut bytes).unwrap();
    round_trip(
        || rtcp::Frames::new().map(|frame| rtcp::parse_packets(&frame.0)),
        &bytes,
        &[
            Err(rtcp::ParseError::Malformed(rtcp::packet_type::RR)),
            Ok(vec![packet]),
        ],
    );
    refused_header(
        || rtcp::Frames::with_limit(8),
        &[0, 9],
        rtcp::FrameError {
            length: 9,
            limit: 8,
        },
    );
}

#[test]
fn rtcp_wire_is_exact_and_transactional() {
    let packet = reports().remove(0);
    let bytes = wire_bytes(&packet);
    assert_eq!(
        <rtcp::Packet as Wire>::parse(&[bytes.clone(), bytes.clone()].concat()),
        Err(rtcp::PacketParseError::Trailing)
    );
    assert!(<rtcp::Packet as Wire>::parse(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = packet.clone();
    bad.padding = 1;
    refuses_value(&bad);
    refuses_value(&rtcp::Packet::from(rtcp::Body::Other {
        packet_type: rtcp::packet_type::RR,
        count: 0,
        data: vec![0; 4],
    }));
    refuses_value(&rtcp::Packet::from(rtcp::Body::App(rtcp::App {
        subtype: 0,
        ssrc: 1,
        name: *b"test",
        data: vec![0; rtcp::MAX_PACKET],
    })));
    refuses_value(&rtcp::Frame(vec![0; rtcp::MAX_FRAME + 1]));
    assert_eq!(
        <rtcp::Frame as Wire>::parse(&[0, 0, 0]),
        Err(rtcp::FrameParseError::Trailing)
    );
    assert_eq!(
        <rtcp::Frame as Wire>::parse(&[0]),
        Err(rtcp::FrameParseError::Truncated)
    );
}

fn ssh_packet(payload: Vec<u8>) -> ssh::Packet {
    let mut padding = usize::from(ssh::MIN_PADDING);
    while !(5 + payload.len() + padding).is_multiple_of(ssh::BLOCK) {
        padding += 1;
    }
    ssh::Packet {
        payload,
        padding: vec![0xa5; padding],
    }
}

#[test]
fn ssh_chunked_cleartext_round_trip() {
    let packets = vec![
        ssh_packet(ssh::Message::ServiceRequest("ssh-userauth".into()).to_payload()),
        ssh_packet(ssh::Message::Ignore(vec![3; 31]).to_payload()),
        ssh_packet(ssh::Message::NewKeys.to_payload()),
    ];
    let mut bytes = Vec::new();
    for packet in &packets {
        let encoded = wire_bytes(packet);
        assert_eq!(encoded, packet.to_bytes());
        truncated(ssh::Frames::new, &encoded);
        packet.write(&mut bytes).unwrap();
    }
    round_trip(ssh::Frames::new, &bytes, &packets);
}

#[test]
fn ssh_header_errors_end_the_stream() {
    refused_header(
        ssh::Frames::new,
        &(ssh::MAX_PACKET_LENGTH + 1).to_be_bytes(),
        ssh::StreamError::PacketLength(ssh::MAX_PACKET_LENGTH + 1),
    );
    refused_header(
        || ssh::Frames::with_limit(16),
        &20u32.to_be_bytes(),
        ssh::StreamError::PacketLength(20),
    );
    refused_header(
        ssh::Frames::new,
        &[0, 0, 0, 12, 3],
        ssh::StreamError::Padding(3),
    );
    // Packet errors remain terminal even when the declared boundary is available.
    let mut bytes = vec![0, 0, 0, 12, 3];
    bytes.resize(16, 0);
    ssh_packet(vec![21]).write(&mut bytes).unwrap();
    let mut stream = Stream::new(ssh::Frames::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(ssh::StreamError::Padding(3))))
    );
    assert_eq!(stream.next(), None);
    assert_eq!(stream.offset(), 0);
}

#[test]
fn ssh_wire_refuses_padding_changes_and_trailing_bytes() {
    let packet = ssh_packet(vec![21]);
    let mut bytes = wire_bytes(&packet);
    bytes.push(0);
    assert_eq!(
        <ssh::Packet as Wire>::parse(&bytes),
        Err(ssh::PacketParseError::Trailing)
    );
    assert_eq!(
        <ssh::Packet as Wire>::parse(&[0, 0, 0]),
        Err(ssh::PacketParseError::Truncated)
    );
    for bad in [
        ssh::Packet::new(vec![21]),
        ssh::Packet {
            payload: vec![21],
            padding: vec![0; 4],
        },
        ssh::Packet {
            payload: vec![21],
            padding: vec![0; 256],
        },
        ssh::Packet {
            payload: vec![0; ssh::MAX_PAYLOAD + 1],
            padding: vec![0; 4],
        },
    ] {
        refuses_value(&bad);
        assert!(matches!(ssh::Packet::parse(&bad.to_bytes()), Ok(Some(_))));
    }
}

#[test]
fn ssh_version_limits_and_legacy_errors_are_preserved() {
    let id = ssh::Identification::new("2.0", "sdk", Some(&"x".repeat(ssh::MAX_VERSION_LINE - 14)))
        .unwrap();
    assert_eq!(id.to_bytes().len(), ssh::MAX_VERSION_LINE);
    assert!(
        ssh::Identification::new("2.0", "sdk", Some(&"x".repeat(ssh::MAX_VERSION_LINE - 13)))
            .is_err()
    );
    let mut bytes = id.to_bytes();
    let packet = ssh_packet(vec![21]);
    packet.write(&mut bytes).unwrap();
    let mut legacy = ssh::Decoder::new();
    assert_eq!(legacy.feed(&bytes), bytes.len());
    assert_eq!(legacy.next_event(), Some(Ok(ssh::Event::Version(id))));
    assert_eq!(
        legacy.next_event(),
        Some(Ok(ssh::Event::Packet {
            sequence: 0,
            packet
        }))
    );
    assert_eq!(legacy.next_event(), None);
    let mut too_long = b"SSH-".to_vec();
    too_long.resize(ssh::MAX_VERSION_LINE, b'x');
    let mut legacy = ssh::Decoder::new();
    legacy.feed(&too_long);
    assert_eq!(
        legacy.next_event(),
        Some(Err(ssh::StreamError::LineTooLong))
    );
    assert_eq!(legacy.buffered(), 0);
    assert_eq!(
        legacy.next_event(),
        Some(Err(ssh::StreamError::LineTooLong))
    );
}

fn snmp_message() -> snmp::Message {
    snmp::Message {
        version: snmp::Version::V2c,
        community: b"public".to_vec(),
        pdu: snmp::Pdu::Get(snmp::BasicPdu::new(
            42,
            vec![snmp::VarBind::new(
                "1.3.6.1.2.1.1.1.0".parse().unwrap(),
                snmp::Value::Null,
            )],
        )),
    }
}

#[test]
fn snmp_chunked_ber_round_trip() {
    let request = snmp_message();
    let response = request
        .response(vec![snmp::VarBind::new(
            "1.3.6.1.2.1.1.1.0".parse().unwrap(),
            snmp::Value::OctetString(vec![b'x'; 160]),
        )])
        .unwrap();
    let mut bytes = Vec::new();
    for message in [&request, &response] {
        let encoded = wire_bytes(message);
        truncated(snmp::Frames::new, &encoded);
        message.write(&mut bytes).unwrap();
    }
    round_trip(snmp::Frames::new, &bytes, &[Ok(request), Ok(response)]);
}

#[test]
fn snmp_body_error_keeps_stream_and_framing_error_ends_it() {
    let message = snmp_message();
    let mut bytes = vec![0x30, 0]; // A complete TLV with no message fields.
    message.write(&mut bytes).unwrap();
    round_trip(
        snmp::Frames::new,
        &bytes,
        &[Err(snmp::Error::Truncated), Ok(message)],
    );
    refused_header(
        snmp::Frames::new,
        &[0x30, 0x82, 0xff, 0xff],
        snmp::Error::TooLong(snmp::MAX_MESSAGE + 4),
    );
    refused_header(
        || snmp::Frames::with_limit(16),
        &[0x30, 17],
        snmp::Error::TooLong(19),
    );
    refused_header(snmp::Frames::new, &[0x30, 0x80], snmp::Error::Length);
    refused_header(snmp::Frames::new, &[0x04], snmp::Error::UnexpectedTag(0x04));
}

#[test]
fn snmp_nonminimal_ber_headers_keep_their_existing_tolerance() {
    let message = snmp_message();
    let canonical = wire_bytes(&message);
    assert!(canonical[1] < 128);
    let mut bytes = vec![0x30, 0xfe]; // 126 length bytes, most of them zero.
    bytes.extend([0; 125]);
    bytes.push(canonical[1]);
    bytes.extend_from_slice(&canonical[2..]);
    contract::check_wire::<snmp::Message>(&bytes);
    round_trip(snmp::Frames::new, &bytes, &[Ok(message)]);
    refused_header(
        || snmp::Frames::with_limit(16),
        &bytes[..128],
        snmp::Error::TooLong(bytes.len()),
    );
    contract::check_decode(|| snmp::Frames::with_limit(0), &[0x30, 0xfe]);
}

#[test]
fn snmp_wire_is_exact_and_transactional() {
    let message = snmp_message();
    let mut bytes = wire_bytes(&message);
    bytes.push(0);
    assert_eq!(
        <snmp::Message as Wire>::parse(&bytes),
        Err(snmp::Error::TrailingBytes)
    );
    let mut bad = message;
    bad.community = vec![0; snmp::MAX_MESSAGE];
    refuses_value(&bad);
}

#[test]
fn configured_limits_and_maximum_envelopes() {
    assert_eq!(
        openvpn::Frames::with_limit(usize::MAX).limit(),
        openvpn::MAX_PACKET
    );
    assert_eq!(openvpn::Frames::with_limit(0).capacity(), 2);
    assert_eq!(
        rtcp::Frames::with_limit(usize::MAX).limit(),
        rtcp::MAX_FRAME
    );
    assert_eq!(rtp::Frames::with_limit(0).capacity(), 2);
    assert_eq!(ssh::Frames::with_limit(usize::MAX).limit(), ssh::MAX_PACKET);
    assert_eq!(ssh::Frames::with_limit(0).limit(), ssh::MIN_PACKET);
    assert_eq!(
        snmp::Frames::with_limit(usize::MAX).limit(),
        snmp::MAX_MESSAGE
    );
    assert_eq!(snmp::Frames::with_limit(0).capacity(), 128);
    round_trip(
        || rtcp::Frames::with_limit(0),
        &[0, 0, 0, 0],
        &[rtcp::Frame::default(), rtcp::Frame::default()],
    );
    refused_header(
        || openvpn::Frames::with_limit(0),
        &[0, 1],
        openvpn::StreamError::TooLong {
            length: 1,
            limit: 0,
        },
    );
    for length in [1, openvpn::MAX_PACKET] {
        let frame = openvpn::Frame(vec![7; length]);
        round_trip(openvpn::Frames::new, &wire_bytes(&frame), &[frame]);
    }
    let frame = rtcp::Frame(vec![7; rtcp::MAX_FRAME]);
    round_trip(rtcp::Frames::new, &wire_bytes(&frame), &[frame]);
    let packet = ssh_packet(vec![7; ssh::MAX_PAYLOAD]);
    round_trip(ssh::Frames::new, &wire_bytes(&packet), &[packet]);
}

#[test]
fn legacy_buffering_and_error_behavior_stays_separate() {
    let mut vpn = openvpn::Decoder::new();
    assert_eq!(vpn.feed(&[0, 0]), 2);
    assert_eq!(
        vpn.next_packet(),
        Some(Err(openvpn::FrameError::ZeroLength))
    );
    assert_eq!(vpn.buffered(), 0);
    assert_eq!(
        vpn.next_packet(),
        Some(Err(openvpn::FrameError::ZeroLength))
    );
    assert_eq!(vpn.feed(b"tail"), 4);
    let mut snmp = snmp::Decoder::new();
    assert_eq!(snmp.feed(&[0x30, 0x80]), 2);
    assert_eq!(snmp.next_message(), Some(Err(snmp::Error::Length)));
    assert_eq!(snmp.buffered(), 0);
    assert_eq!(snmp.next_message(), Some(Err(snmp::Error::Length)));
    let mut rtp = rtp::Decoder::new();
    assert_eq!(rtp.feed(&vec![0; rtp::MAX_BUFFERED + 1]), rtp::MAX_BUFFERED);
    assert_eq!(rtp.buffered(), rtp::MAX_BUFFERED);
    let mut rtcp = rtcp::Decoder::new();
    assert_eq!(rtcp.feed(&[0, 3, 1]), 3);
    let mut cloned = rtcp.clone();
    assert_eq!(cloned.feed(&[2, 3]), 2);
    assert_eq!(cloned.next_frame(), Some(vec![1, 2, 3]));
    assert_eq!(rtcp.next_frame(), None);
    assert_eq!(rtcp.buffered(), 3);
}

#[test]
fn deterministic_contract_inputs_cover_all_framers() {
    let mut rng = Lcg::new(0x51ea);
    for length in [0, 1, 2, 4, 5, 16, 64, 128, 257] {
        let mut bytes = vec![0; length];
        for _ in 0..8 {
            rng.fill(&mut bytes);
            contract::check_decode(openvpn::Frames::new, &bytes);
            contract::check_decode(rtp::Frames::new, &bytes);
            contract::check_decode(ssh::Frames::new, &bytes);
            contract::check_decode(snmp::Frames::new, &bytes);
            contract::check_wire::<openvpn::Frame>(&bytes);
            contract::check_wire::<rtcp::Frame>(&bytes);
            contract::check_wire::<rtp::RtpPacket>(&bytes);
            contract::check_wire::<rtcp::Packet>(&bytes);
            contract::check_wire::<ssh::Packet>(&bytes);
            contract::check_wire::<snmp::Message>(&bytes);
        }
    }
}
