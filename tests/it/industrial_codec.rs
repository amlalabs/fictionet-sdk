//! Industrial transport frames through the shared codec driver.

use core::fmt::Debug;
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Fail, Step, Stream, Wire, finish, pump};
use fictionet::stdlib::protocols::{dnp3, enip, iec104, opcua, rdp, tpkt};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

fn check_frames<D>(make: impl Fn() -> D, values: &[D::Item]) -> Vec<u8>
where
    D: Decode,
    D::Item: Wire + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let mut bytes = Vec::new();
    for value in values {
        let written = assert_write(value).unwrap();
        for cut in 0..written.len() {
            assert!(
                <D::Item as Wire>::parse(&written[..cut]).is_err(),
                "prefix {cut}"
            );
        }
        for tail in [0x00, 0xff] {
            let trailing = [written.as_slice(), &[tail]].concat();
            assert!(
                <D::Item as Wire>::parse(&trailing).is_err(),
                "trailing byte {tail}"
            );
        }
        bytes.extend_from_slice(&written);
    }
    decode_frames(make, &bytes, values);
    bytes
}

fn decode_frames<D>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let alloc_limit = 2 * make().capacity();
    let (items, failure) =
        decode_chunks(&mut Stream::new(make()), chunks(bytes, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= alloc_limit);
        });
    assert_eq!(items, expected);
    assert_eq!(failure, None);
    assert_eq!(
        decode_chunks(&mut Stream::new(make()), chunks(bytes, &[1, 7, 64]), |s| {
            assert_eq!(s.held(), 0);
        }),
        decode_all(&make, bytes)
    );
    let mut stream = Stream::new(make());
    assert_eq!(pump(&mut stream, bytes, |_| {}), Ok(bytes.len()));
    finish(&mut stream, |_| {}).unwrap();
    assert_eq!(stream.buffered(), 0);
    assert_eq!(stream.offset(), bytes.len() as u64);
}

#[test]
fn dnp3_application_request_and_response() {
    let request = dnp3::Fragment {
        control: 0xc0,
        function: 1,
        indications: None,
        objects: vec![60, 1, 6],
    };
    let response = dnp3::Fragment {
        control: 0xc0,
        function: 0x81,
        indications: Some(0),
        objects: vec![1, 2, 0, 0, 1],
    };
    let frames: Vec<_> = [&request, &response]
        .into_iter()
        .enumerate()
        .map(|(i, fragment)| dnp3::Frame {
            control: 0xc4,
            destination: if i == 0 { 1 } else { 1024 },
            source: if i == 0 { 1024 } else { 1 },
            data: dnp3::Segment {
                first: true,
                final_segment: true,
                sequence: i as u8,
                data: fragment.to_bytes().unwrap(),
            }
            .to_bytes()
            .unwrap(),
        })
        .collect();
    let bytes = check_frames(Frames::<dnp3::Frame>::new, &frames);
    let make = || {
        Frames::<dnp3::Frame>::new()
            .map(|frame| frame.segment().map(|s| dnp3::Fragment::parse(&s.data)))
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(make()),
            chunks(&bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(make, &bytes)
    );
    decode_frames(make, &bytes, &[Ok(Ok(request)), Ok(Ok(response))]);
    let unit = frames[0].to_bytes().unwrap();
    assert_eq!(decode_all(Frames::<dnp3::Frame>::new, &[]), (vec![], None));
    for cut in 1..unit.len() {
        assert_eq!(
            decode_all(Frames::<dnp3::Frame>::new, &unit[..cut]),
            (vec![], Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }

    // Repeated maximum frames exercise counted pushes and every data CRC.
    let large = dnp3::Frame {
        data: vec![0x42; dnp3::MAX_DATA],
        ..frames[0].clone()
    };
    check_frames(
        Frames::<dnp3::Frame>::new,
        &[large.clone(), large.clone(), large],
    );
    assert_write(&dnp3::Frame {
        data: vec![0; dnp3::MAX_DATA + 1],
        ..frames[0].clone()
    })
    .unwrap_err();
}

#[test]
fn iec104_information_acknowledgment_and_link_control() {
    let asdu = iec104::Asdu {
        type_id: 100,
        sequence: false,
        count: 1,
        cause: 6,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
        data: vec![0, 0, 0, 20],
    };
    let frames = [
        iec104::Frame::Unnumbered(iec104::UFunction::StartDtAct),
        iec104::Frame::Information {
            send: 0,
            receive: 0,
            asdu: asdu.to_bytes().unwrap(),
        },
        iec104::Frame::Supervisory { receive: 1 },
    ];
    let bytes = check_frames(Frames::<iec104::Frame>::new, &frames);
    let make = || {
        Frames::<iec104::Frame>::new().map(|frame| match frame {
            iec104::Frame::Information { asdu, .. } => Some(iec104::Asdu::parse(&asdu)),
            _ => None,
        })
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(make()),
            chunks(&bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(make, &bytes)
    );
    decode_frames(make, &bytes, &[None, Some(Ok(asdu)), None]);
    let unit = frames[1].to_bytes().unwrap();
    assert_eq!(
        decode_all(Frames::<iec104::Frame>::new, &[]),
        (vec![], None)
    );
    for cut in 1..unit.len() {
        assert_eq!(
            decode_all(Frames::<iec104::Frame>::new, &unit[..cut]),
            (vec![], Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }
    let max = iec104::Frame::Information {
        send: 0x7fff,
        receive: 0x7fff,
        asdu: vec![0; iec104::MAX_ASDU],
    };
    check_frames(Frames::<iec104::Frame>::new, &[max.clone(), max]);
    for invalid in [
        iec104::Frame::Supervisory { receive: 0x8000 },
        iec104::Frame::Information {
            send: 0x8000,
            receive: 0,
            asdu: vec![0; 6],
        },
        iec104::Frame::Information {
            send: 0,
            receive: 0,
            asdu: vec![0; 5],
        },
        iec104::Frame::Information {
            send: 0,
            receive: 0,
            asdu: vec![0; iec104::MAX_ASDU + 1],
        },
    ] {
        assert_write(&invalid).unwrap_err();
    }
}

fn enip_packet(data: Vec<u8>) -> enip::Packet {
    enip::Packet {
        command: enip::Command::SendRRData,
        session_handle: 7,
        status: 0,
        sender_context: *b"request1",
        options: 0,
        data,
    }
}

#[test]
fn enip_cip_request_and_response() {
    let request = enip::MessageRequest {
        service: enip::service::GET_ATTRIBUTE_SINGLE,
        path: vec![
            enip::PathSegment::Class(1),
            enip::PathSegment::Instance(1),
            enip::PathSegment::Attribute(7),
        ],
        data: vec![],
    };
    let send = enip::SendData {
        interface_handle: 0,
        timeout: 0,
        cpf: enip::Cpf {
            items: vec![
                enip::CpfItem::null_address(),
                enip::CpfItem {
                    type_id: enip::item::UNCONNECTED_DATA,
                    data: request.to_bytes().unwrap(),
                },
            ],
        },
    };
    let packet = enip_packet(send.to_bytes().unwrap());
    let bytes = assert_write(&packet).unwrap();
    for cut in 0..bytes.len() {
        assert!(
            <enip::Packet as Wire>::parse(&bytes[..cut]).is_err(),
            "prefix {cut}"
        );
    }
    for tail in [0x00, 0xff] {
        let trailing = [bytes.as_slice(), &[tail]].concat();
        assert!(
            <enip::Packet as Wire>::parse(&trailing).is_err(),
            "trailing byte {tail}"
        );
    }
    decode_frames(
        Frames::<enip::Packet>::new,
        &bytes,
        core::slice::from_ref(&packet),
    );
    let make = || {
        Frames::<enip::Packet>::new().map(|p| {
            let send = enip::SendData::parse(&p.data)?;
            let item = send.cpf.items.get(1).ok_or(enip::Error::Items)?;
            enip::MessageRequest::parse(&item.data)
        })
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(make()),
            chunks(&bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(make, &bytes)
    );
    decode_frames(make, &bytes, &[Ok(request)]);
    let response = enip::MessageResponse {
        service: enip::service::GET_ATTRIBUTE_SINGLE,
        status: 0,
        additional_status: vec![],
        data: b"PLC".to_vec(),
    };
    let reply_data = enip::SendData {
        cpf: enip::Cpf {
            items: vec![
                enip::CpfItem::null_address(),
                enip::CpfItem {
                    type_id: enip::item::UNCONNECTED_DATA,
                    data: response.to_bytes().unwrap(),
                },
            ],
        },
        ..send
    };
    let reply = packet.reply(0, reply_data.to_bytes().unwrap());
    let make = || {
        Frames::<enip::Packet>::new().map(|p| {
            let send = enip::SendData::parse(&p.data)?;
            let item = send.cpf.items.get(1).ok_or(enip::Error::Items)?;
            enip::MessageResponse::parse(&item.data)
        })
    };
    decode_frames(make, &Wire::to_bytes(&reply).unwrap(), &[Ok(response)]);
    check_frames(Frames::<enip::Packet>::new, &[packet.clone(), reply]);
    let unit = packet.to_bytes().unwrap();
    assert_eq!(decode_all(Frames::<enip::Packet>::new, &[]), (vec![], None));
    for cut in 1..unit.len() {
        assert_eq!(
            decode_all(Frames::<enip::Packet>::new, &unit[..cut]),
            (vec![], Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }
    assert_write(&enip::Packet {
        options: 1,
        ..packet.clone()
    })
    .unwrap_err();
    assert_write(&enip::Packet {
        command: enip::Command::Other(0x006f),
        ..packet.clone()
    })
    .unwrap_err();
    assert_write(&enip::Packet {
        data: vec![0; enip::MAX_DATA + 1],
        ..packet
    })
    .unwrap_err();
}

#[test]
fn enip_preserves_permissive_framing_and_partial_packets() {
    let valid = enip_packet(vec![]);
    let mut bytes = valid.to_bytes().unwrap();
    bytes[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes.resize(enip::PACKETS_CAPACITY, 0xa5);
    let raw = enip::Packet::parse_prefix(&bytes).unwrap().0;
    assert_eq!(raw.data.len(), usize::from(u16::MAX));
    assert_eq!(raw.check(), Err(enip::Error::Options));
    assert_eq!(
        <enip::Packet as Wire>::parse(&bytes),
        Err(enip::Error::Options)
    );
    assert_write(&raw).unwrap_err();
    decode_frames(
        Frames::<enip::Packet>::new,
        &bytes,
        core::slice::from_ref(&raw),
    );
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        <enip::Packet as Wire>::parse(&bytes),
        Err(enip::Error::TooLong)
    );

    let mut decoder = Stream::new(Frames::<enip::Packet>::new());
    bytes.extend_from_slice(&valid.to_bytes().unwrap());
    assert_eq!(decoder.push(&bytes), enip::PACKETS_CAPACITY);
    let oversized = decoder.next().unwrap().unwrap();
    assert_eq!(oversized.data.len(), usize::from(u16::MAX));
    assert_eq!(decoder.buffered(), 0);
    assert_eq!(
        decoder.push(&bytes[enip::PACKETS_CAPACITY..]),
        enip::HEADER_LEN
    );
    assert_eq!(decoder.next(), Some(Ok(valid.clone())));

    // A consumed packet may precede a partial packet.
    let mut joined = valid.to_bytes().unwrap();
    joined.extend_from_slice(&valid.to_bytes().unwrap());
    let mut decoder = Stream::new(Frames::<enip::Packet>::new());
    assert_eq!(
        decoder.push(&joined[..enip::HEADER_LEN + 3]),
        enip::HEADER_LEN + 3
    );
    assert_eq!(decoder.next(), Some(Ok(valid.clone())));
    {
        let d = &mut decoder;
        assert_eq!(d.buffered(), 3);
        assert!(d.next().is_none());
        assert_eq!(
            d.push(&joined[enip::HEADER_LEN + 3..]),
            enip::HEADER_LEN - 3
        );
        assert_eq!(d.next(), Some(Ok(valid.clone())));
        assert!(d.next().is_none());
    }
}

#[test]
fn opcua_handshake_and_multichunk_message() {
    let limits = opcua::Limits::default();
    let hello = opcua::Hello {
        protocol_version: 0,
        receive_buffer_size: opcua::MIN_BUFFER_SIZE,
        send_buffer_size: opcua::MIN_BUFFER_SIZE,
        max_message_size: 0,
        max_chunk_count: 0,
        endpoint_url: "opc.tcp://plc:4840".into(),
    };
    let messages = [
        opcua::Message::Hello(hello.clone()),
        opcua::Message::Acknowledge(hello.acknowledge(&limits)),
        opcua::Message::Secure(opcua::SecureMessage {
            kind: opcua::SecureKind::Message { token_id: 1 },
            channel_id: 7,
            sequence_number: 1,
            request_id: 42,
            body: vec![0xa5; opcua::MIN_BUFFER_SIZE as usize + 1],
        }),
    ];
    let mut original = Vec::new();
    for message in &messages {
        for chunk in message.chunks(&limits).unwrap() {
            chunk.write(&mut original).unwrap();
        }
    }
    let (frames, failure) = decode_all(|| Frames::<opcua::Chunk>::with_limit(limits), &original);
    assert!(failure.is_none());
    assert!(
        frames
            .iter()
            .any(|c| c.chunk_type == opcua::ChunkType::Intermediate)
    );
    let bytes = check_frames(|| Frames::<opcua::Chunk>::with_limit(limits), &frames);
    assert_eq!(bytes, original);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(opcua::Messages::with_limits(limits)),
            chunks(&bytes, &[1, 7, 64]),
            |s| {
                assert!(s.held() <= limits.message_limit() as usize);
            }
        ),
        decode_all(|| opcua::Messages::with_limits(limits), &bytes)
    );
    let mut stream = Stream::new(opcua::Messages::with_limits(limits));
    let mut parsed = Vec::new();
    pump(&mut stream, &bytes, |message| parsed.push(message)).unwrap();
    finish(&mut stream, |message| parsed.push(message)).unwrap();
    assert_eq!(parsed, messages);
    assert_eq!(stream.held(), 0);
    let unit = Wire::to_bytes(&frames[0]).unwrap();
    assert_eq!(decode_all(Frames::<opcua::Chunk>::new, &[]), (vec![], None));
    for cut in 1..unit.len() {
        assert_eq!(
            decode_all(Frames::<opcua::Chunk>::new, &unit[..cut]),
            (vec![], Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }
    for message_type in [
        opcua::MessageType::Hello,
        opcua::MessageType::Open,
        opcua::MessageType::Close,
    ] {
        for chunk_type in [opcua::ChunkType::Intermediate, opcua::ChunkType::Abort] {
            assert_write(&opcua::Chunk {
                message_type,
                chunk_type,
                body: vec![],
            })
            .unwrap_err();
        }
    }
    assert_write(&opcua::Chunk {
        body: vec![0; opcua::MAX_BUFFER_SIZE as usize],
        ..frames[0].clone()
    })
    .unwrap_err();
}

#[test]
fn opcua_limits_headers_and_handshake_normalization() {
    for size in [0, 1, opcua::MIN_BUFFER_SIZE, u32::MAX] {
        let frames = Frames::<opcua::Chunk>::with_limit(opcua::Limits {
            receive_buffer_size: size,
            max_message_size: 1,
            max_chunk_count: 1,
        });
        assert_eq!(frames.limit().receive_buffer_size, size);
        assert_eq!(
            frames.capacity(),
            size.clamp(opcua::MIN_BUFFER_SIZE, opcua::MAX_BUFFER_SIZE)
                .max(opcua::MAX_HANDSHAKE_SIZE) as usize
        );
    }
    let mut header = b"MSGF".to_vec();
    header.extend_from_slice(&(opcua::MIN_BUFFER_SIZE + 1).to_le_bytes());
    let error = opcua::Error::TooLarge {
        size: opcua::MIN_BUFFER_SIZE + 1,
        limit: opcua::MIN_BUFFER_SIZE,
    };
    let mut stream = Stream::new(Frames::<opcua::Chunk>::new());
    assert_eq!(stream.push(&header), header.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(error.clone()))));
    assert_eq!(stream.failed(), Some(&Fail::Protocol(error)));
    assert!(stream.next().is_none());
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<opcua::Chunk>::new()),
            chunks(&header, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(Frames::<opcua::Chunk>::new, &header)
    );

    // Limits can change between items; a larger capacity grows on demand.
    let chunk = opcua::Chunk {
        message_type: opcua::MessageType::Message,
        chunk_type: opcua::ChunkType::Final,
        body: vec![0; opcua::MIN_BUFFER_SIZE as usize],
    };
    let mut stream = Stream::new(Frames::<opcua::Chunk>::new());
    stream.decoder().set_limit(opcua::Limits {
        receive_buffer_size: 65536,
        ..opcua::Limits::default()
    });
    let bytes = Wire::to_bytes(&chunk).unwrap();
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(chunk)));

    // Handshakes have room above the minimum secure chunk limit.
    let handshake = opcua::Chunk {
        message_type: opcua::MessageType::ReverseHello,
        chunk_type: opcua::ChunkType::Final,
        body: vec![0; opcua::MAX_HANDSHAKE_SIZE as usize - opcua::HEADER_LEN],
    };
    let handshake_bytes = assert_write(&handshake).unwrap();
    for cut in 0..handshake_bytes.len() {
        assert!(
            <opcua::Chunk as Wire>::parse(&handshake_bytes[..cut]).is_err(),
            "prefix {cut}"
        );
    }
    for tail in [0x00, 0xff] {
        let trailing = [handshake_bytes.as_slice(), &[tail]].concat();
        assert!(
            <opcua::Chunk as Wire>::parse(&trailing).is_err(),
            "trailing byte {tail}"
        );
    }
    decode_frames(
        Frames::<opcua::Chunk>::new,
        &handshake_bytes,
        core::slice::from_ref(&handshake),
    );
    let mut bytes = Wire::to_bytes(&handshake).unwrap();
    bytes[3] = 0;
    assert_eq!(<opcua::Chunk as Wire>::parse(&bytes), Ok(handshake));
    if let Ok(value) = <opcua::Chunk as Wire>::parse(&bytes) {
        assert_write(&value).unwrap();
    }

    let max = opcua::Chunk {
        message_type: opcua::MessageType::Message,
        chunk_type: opcua::ChunkType::Abort,
        body: vec![0; opcua::MAX_BUFFER_SIZE as usize - opcua::HEADER_LEN],
    };
    let _ = assert_write(&max);
    let bytes = Wire::to_bytes(&max).unwrap();
    let mut frames = Frames::<opcua::Chunk>::with_limit(opcua::Limits {
        receive_buffer_size: u32::MAX,
        ..opcua::Limits::default()
    });
    assert_eq!(
        frames.decode(&bytes, false),
        Ok(Step::Item(max, bytes.len()))
    );
}

#[test]
fn rdp_slow_path_negotiation_data_and_fast_path() {
    let request = rdp::Connection {
        kind: rdp::ConnectionKind::Request,
        source: 0,
        destination: 0,
        routing_token: vec![],
        negotiation: Some(rdp::Negotiation::Request {
            flags: 0,
            protocols: rdp::Protocols::TLS,
        }),
        correlation_id: None,
    };
    let confirm = rdp::Connection {
        kind: rdp::ConnectionKind::Confirm,
        negotiation: Some(rdp::Negotiation::Response {
            flags: 0,
            protocol: rdp::Protocols::TLS,
        }),
        ..request.clone()
    };
    let frames = [
        rdp::Frame::SlowPath(request.to_packet().unwrap()),
        rdp::Frame::SlowPath(confirm.to_packet().unwrap()),
        rdp::Frame::SlowPath(rdp::write_data(b"MCS payload").unwrap()),
        rdp::Frame::FastPath {
            header: 0x80,
            payload: vec![1, 2, 3],
        },
        rdp::Frame::FastPath {
            header: 0,
            payload: vec![0; 126],
        },
    ];
    let bytes = check_frames(Frames::<rdp::Frame>::new, &frames);
    let make = || {
        Frames::<rdp::Frame>::new().map(|frame| match frame {
            rdp::Frame::SlowPath(packet) => Some(rdp::Connection::from_packet(&packet)),
            _ => None,
        })
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(make()),
            chunks(&bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(make, &bytes)
    );
    decode_frames(
        make,
        &bytes,
        &[
            Some(Ok(request)),
            Some(Ok(confirm)),
            Some(Err(rdp::Error::Invalid("connection TPDU"))),
            None,
            None,
        ],
    );
    let rdp::Frame::SlowPath(packet) = &frames[2] else {
        panic!()
    };
    assert_eq!(rdp::read_data(packet).unwrap(), b"MCS payload");
    let unit = frames[0].to_bytes().unwrap();
    assert_eq!(decode_all(Frames::<rdp::Frame>::new, &[]), (vec![], None));
    for cut in 1..unit.len() {
        assert_eq!(
            decode_all(Frames::<rdp::Frame>::new, &unit[..cut]),
            (vec![], Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }
    let unit = frames[4].to_bytes().unwrap();
    assert_eq!(decode_all(Frames::<rdp::Frame>::new, &[]), (vec![], None));
    for cut in 1..unit.len() {
        assert_eq!(
            decode_all(Frames::<rdp::Frame>::new, &unit[..cut]),
            (vec![], Some(Fail::Truncated { unread: cut })),
            "prefix {cut}"
        );
    }
    for invalid in [
        rdp::Frame::FastPath {
            header: 1,
            payload: vec![],
        },
        rdp::Frame::FastPath {
            header: 0,
            payload: vec![0; rdp::MAX_FAST_PATH - 2],
        },
        rdp::Frame::SlowPath(tpkt::Packet::new(vec![])),
        rdp::Frame::SlowPath(tpkt::Packet::new(vec![0; tpkt::MAX_PAYLOAD + 1])),
    ] {
        assert_write(&invalid).unwrap_err();
    }
    // Fast-path lengths need not be minimal on input.
    let nonminimal = [0, 0x80, 3];
    if let Ok(value) = <rdp::Frame as Wire>::parse(&nonminimal) {
        assert_write(&value).unwrap();
    }
    assert_eq!(
        <rdp::Frame as Wire>::parse(&nonminimal)
            .unwrap()
            .to_bytes()
            .unwrap(),
        [0, 2]
    );
}

#[test]
fn framing_errors_are_terminal_once_and_keep_unread_bytes() {
    fn check<D>(make: impl Fn() -> D, bytes: &[u8], error: D::Error)
    where
        D: Decode,
        D::Item: PartialEq + Debug,
        D::Error: Clone + PartialEq + Debug,
    {
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(bytes, &[1, 7, 64]), |_| {}),
            (vec![], Some(Fail::Protocol(error)))
        );
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(bytes), bytes.len());
        stream.next().unwrap().unwrap_err();
        assert_eq!(stream.unread(), bytes);
    }
    check(
        Frames::<dnp3::Frame>::new,
        &[5, 0x64, 4],
        dnp3::Error::FrameLength,
    );
    check(
        Frames::<dnp3::Frame>::new,
        &[5, 0x64, 5, 0, 0, 0, 0, 0, 0, 0],
        dnp3::Error::Crc(8),
    );
    check(
        Frames::<iec104::Frame>::new,
        &[0x68, 254],
        iec104::Error::ApduLength,
    );
    check(
        Frames::<iec104::Frame>::new,
        &[0x68, 4, 3, 0, 0, 0],
        iec104::Error::Control,
    );
    check(
        Frames::<rdp::Frame>::new,
        &[1],
        rdp::Error::Invalid("fast-path action"),
    );
    check(
        Frames::<opcua::Chunk>::new,
        b"OPNC",
        opcua::Error::ChunkType(opcua::MessageType::Open, b'C'),
    );
}

#[test]
fn opcua_assembly_eof_and_limits() {
    for body in [Vec::new(), b"part".to_vec()] {
        let mut payload = Vec::new();
        for field in [7u32, 1, 1, 42] {
            payload.extend_from_slice(&field.to_le_bytes());
        }
        payload.extend_from_slice(&body);
        let chunk = opcua::Chunk {
            message_type: opcua::MessageType::Message,
            chunk_type: opcua::ChunkType::Intermediate,
            body: payload,
        };
        let bytes = chunk.to_bytes().unwrap();
        assert_eq!(
            decode_chunks(
                &mut Stream::new(opcua::Messages::new()),
                chunks(&bytes, &[1, 7, 64]),
                |s| {
                    assert!(s.held() <= opcua::MAX_MESSAGE_SIZE as usize);
                }
            ),
            decode_all(opcua::Messages::new, &bytes)
        );
        let mut stream = Stream::new(opcua::Messages::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(stream.next().is_none());
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.held(), body.len());
        stream.end();
        let error = Fail::Protocol(opcua::Error::Incomplete);
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.failed(), Some(&error));
        assert!(stream.next().is_none());
    }

    let limits = opcua::Limits {
        max_chunk_count: 1,
        ..Default::default()
    };
    let message = opcua::SecureMessage {
        kind: opcua::SecureKind::Message { token_id: 1 },
        channel_id: 7,
        sequence_number: 1,
        request_id: 42,
        body: vec![0; opcua::MIN_BUFFER_SIZE as usize],
    };
    assert_eq!(message.chunks(&limits), Err(opcua::Error::TooLong));
}

#[test]
fn industrial_body_writers_are_transactional() {
    assert_write(&dnp3::Segment {
        first: true,
        final_segment: true,
        sequence: 64,
        data: vec![1],
    })
    .unwrap_err();
    assert_write(&dnp3::Fragment {
        control: 0,
        function: 0x81,
        indications: None,
        objects: vec![],
    })
    .unwrap_err();
    assert_write(&iec104::Asdu {
        type_id: 1,
        sequence: false,
        count: 128,
        cause: 0,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
        data: vec![],
    })
    .unwrap_err();
    assert_write(&enip::Cpf {
        items: vec![enip::CpfItem::null_address(); enip::MAX_CPF_ITEMS + 1],
    })
    .unwrap_err();
    assert_write(&rdp::Negotiation::Response {
        flags: 0,
        protocol: rdp::Protocols(3),
    })
    .unwrap_err();
    assert_write(&rdp::DataBlocks(vec![
        rdp::DataBlock::ClientMessageChannel;
        rdp::MAX_BLOCKS + 1
    ]))
    .unwrap_err();
    assert_write(&opcua::ExpandedNodeId {
        node_id: opcua::NodeId::numeric(1, 1),
        namespace_uri: Some("urn:test".into()),
        server_index: 0,
    })
    .unwrap_err();
    assert_write(&opcua::DataValue {
        server_picoseconds: Some(10_000),
        ..Default::default()
    })
    .unwrap_err();
    assert_write(&opcua::RequestHeader {
        timestamp: -1,
        ..Default::default()
    })
    .unwrap_err();
    assert_write(&opcua::Variant::Scalar(opcua::Value::Reserved {
        type_id: 27,
        bytes: None,
    }))
    .unwrap_err();
    let nan = opcua::Variant::Scalar(opcua::Value::Float(f32::NAN));
    let _ = assert_write(&nan);
    if let Ok(value) = <opcua::Variant as Wire>::parse(&nan.to_bytes().unwrap()) {
        assert_write(&value).unwrap();
    }
}

#[test]
fn opcua_binary_output_limit() {
    let service = opcua::Service::Other {
        type_id: opcua::NodeId::numeric(0, 1),
        body: vec![0; opcua::MAX_MESSAGE_SIZE as usize],
    };
    assert_write(&service).unwrap_err();
    let mut bytes = vec![0; opcua::MAX_MESSAGE_SIZE as usize + 1];
    bytes[1] = 1;
    assert_eq!(
        <opcua::Service as Wire>::parse(&bytes),
        Err(opcua::Error::Length(bytes.len() as i32))
    );
}
