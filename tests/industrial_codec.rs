//! Industrial transport frames through the shared codec driver.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    contract, finish, pump, test_support::chunks, Decode, Fail, Step, Stream, Wire,
};
use fictionet::stdlib::{dnp3, enip, iec104, opcua, rdp, tpkt};

fn decode_chunks<D>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    contract::check_decode(&make, bytes);
    for pattern in [&[][..], &[3, 1, 37][..], &[1][..]] {
        let mut stream = Stream::new(make());
        let capacity = stream.decoder().capacity();
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
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.offset(), bytes.len() as u64);
        assert!(stream.is_done());
        assert!(stream.failed().is_none());
        assert!(stream.next().is_none());
    }
}

fn round_trip<D>(make: impl Fn() -> D, values: &[D::Item]) -> Vec<u8>
where
    D: Decode,
    D::Item: Wire + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
    <D::Item as Wire>::ParseError: Debug,
    <D::Item as Wire>::WriteError: Debug,
{
    let mut bytes = Vec::new();
    for value in values {
        contract::check_wire_value(value);
        let encoded = Wire::to_bytes(value).unwrap();
        contract::check_wire::<D::Item>(&encoded);
        assert_eq!(&<D::Item as Wire>::parse(&encoded).unwrap(), value);
        assert!(<D::Item as Wire>::parse(&[]).is_err());
        assert!(<D::Item as Wire>::parse(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(<D::Item as Wire>::parse(&trailing).is_err());
        value.write(&mut bytes).unwrap();
    }
    decode_chunks(make, &bytes, values);
    bytes
}

fn rollback<T: Wire + PartialEq + Debug>(value: &T)
where
    T::WriteError: Debug,
{
    contract::check_wire_value(value);
    let mut out = vec![0x5a, 0xc3, 0x17];
    assert!(value.write(&mut out).is_err());
    assert_eq!(out, [0x5a, 0xc3, 0x17]);
}

fn eof_at_every_prefix<D>(make: impl Fn() -> D, bytes: &[u8])
where
    D: Decode,
    D::Item: Debug,
    D::Error: Clone + PartialEq + Debug,
{
    for cut in 0..bytes.len() {
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(&bytes[..cut]), cut);
        assert!(stream.next().is_none());
        stream.end();
        if cut != 0 {
            assert!(
                matches!(stream.next(), Some(Err(Fail::Truncated { unread })) if unread == cut)
            );
            assert_eq!(stream.failed(), Some(&Fail::Truncated { unread: cut }));
        }
        assert!(stream.next().is_none());
        assert!(stream.is_done());
    }
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
    let bytes = round_trip(dnp3::Frames::new, &frames);
    let make = || dnp3::Frames.map(|frame| frame.segment().map(|s| dnp3::Fragment::parse(&s.data)));
    contract::check_stack(make, &bytes);
    decode_chunks(make, &bytes, &[Ok(Ok(request)), Ok(Ok(response))]);
    eof_at_every_prefix(dnp3::Frames::new, &frames[0].to_bytes().unwrap());

    // Repeated maximum frames exercise counted pushes and every data CRC.
    let large = dnp3::Frame {
        data: vec![0x42; dnp3::MAX_DATA],
        ..frames[0].clone()
    };
    round_trip(dnp3::Frames::new, &[large.clone(), large.clone(), large]);
    rollback(&dnp3::Frame {
        data: vec![0; dnp3::MAX_DATA + 1],
        ..frames[0].clone()
    });
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
    let bytes = round_trip(iec104::Frames::new, &frames);
    let make = || {
        iec104::Frames.map(|frame| match frame {
            iec104::Frame::Information { asdu, .. } => Some(iec104::Asdu::parse(&asdu)),
            _ => None,
        })
    };
    contract::check_stack(make, &bytes);
    decode_chunks(make, &bytes, &[None, Some(Ok(asdu)), None]);
    eof_at_every_prefix(iec104::Frames::new, &frames[1].to_bytes().unwrap());
    let max = iec104::Frame::Information {
        send: 0x7fff,
        receive: 0x7fff,
        asdu: vec![0; iec104::MAX_ASDU],
    };
    round_trip(iec104::Frames::new, &[max.clone(), max]);
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
        rollback(&invalid);
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
    let bytes = round_trip(enip::Frames::new, core::slice::from_ref(&packet));
    let make = || {
        enip::Frames.map(|p| {
            let send = enip::SendData::parse(&p.data)?;
            let item = send.cpf.items.get(1).ok_or(enip::DecodeError::Items)?;
            enip::MessageRequest::parse(&item.data)
        })
    };
    contract::check_stack(make, &bytes);
    decode_chunks(make, &bytes, &[Ok(request)]);
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
        enip::Frames.map(|p| {
            let send = enip::SendData::parse(&p.data)?;
            let item = send.cpf.items.get(1).ok_or(enip::DecodeError::Items)?;
            enip::MessageResponse::parse(&item.data)
        })
    };
    decode_chunks(make, &Wire::to_bytes(&reply).unwrap(), &[Ok(response)]);
    round_trip(enip::Frames::new, &[packet.clone(), reply]);
    eof_at_every_prefix(enip::Frames::new, &packet.to_bytes().unwrap());
    rollback(&enip::Packet {
        options: 1,
        ..packet.clone()
    });
    rollback(&enip::Packet {
        command: enip::Command::Other(0x006f),
        ..packet.clone()
    });
    rollback(&enip::Packet {
        data: vec![0; enip::MAX_DATA + 1],
        ..packet
    });
}

#[test]
fn enip_preserves_permissive_framing_and_legacy_clone() {
    let valid = enip_packet(vec![]);
    let mut bytes = valid.to_bytes().unwrap();
    bytes[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes.resize(enip::MAX_BUFFERED, 0xa5);
    let raw = enip::Packet::parse(&bytes).unwrap().0;
    assert_eq!(raw.data.len(), usize::from(u16::MAX));
    assert_eq!(raw.check(), Err(enip::DecodeError::Options));
    assert_eq!(
        <enip::Packet as Wire>::parse(&bytes),
        Err(enip::DecodeError::Options)
    );
    rollback(&raw);
    decode_chunks(enip::Frames::new, &bytes, core::slice::from_ref(&raw));
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        <enip::Packet as Wire>::parse(&bytes),
        Err(enip::DecodeError::TooLong)
    );

    let mut decoder = enip::Decoder::new();
    bytes.extend_from_slice(&valid.to_bytes().unwrap());
    assert_eq!(decoder.feed(&bytes), enip::MAX_BUFFERED);
    let oversized = decoder.next_packet().unwrap();
    assert_eq!(oversized.data.len(), usize::from(u16::MAX));
    assert_eq!(decoder.buffered(), 0);
    assert_eq!(decoder.feed(&bytes[enip::MAX_BUFFERED..]), enip::HEADER_LEN);
    assert_eq!(decoder.next_packet(), Some(valid.clone()));

    // Clone while a consumed packet precedes a partial packet.
    let mut joined = valid.to_bytes().unwrap();
    joined.extend_from_slice(&valid.to_bytes().unwrap());
    let mut decoder = enip::Decoder::default();
    assert_eq!(
        decoder.feed(&joined[..enip::HEADER_LEN + 3]),
        enip::HEADER_LEN + 3
    );
    assert_eq!(decoder.next_packet(), Some(valid.clone()));
    let mut cloned = decoder.clone();
    for d in [&mut decoder, &mut cloned] {
        assert_eq!(d.buffered(), 3);
        assert!(d.next_packet().is_none());
        assert_eq!(
            d.feed(&joined[enip::HEADER_LEN + 3..]),
            enip::HEADER_LEN - 3
        );
        assert_eq!(d.next_packet(), Some(valid.clone()));
        assert!(d.next_packet().is_none());
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
        original.extend_from_slice(&message.to_bytes(&limits).unwrap());
    }
    let mut rest = original.as_slice();
    let mut frames = Vec::new();
    while let Some((frame, used)) = opcua::Chunk::parse(rest, &limits).unwrap() {
        frames.push(frame);
        rest = &rest[used..];
    }
    assert!(rest.is_empty());
    assert!(frames
        .iter()
        .any(|c| c.chunk_type == opcua::ChunkType::Intermediate));
    let bytes = round_trip(|| opcua::Frames::with_limits(limits), &frames);
    assert_eq!(bytes, original);
    // The new chunk writer still feeds the existing message and sequence checks.
    for pattern in [&[][..], &[3, 1, 37][..], &[1][..]] {
        let mut decoder = opcua::Decoder::with_limits(limits);
        let mut parsed = Vec::new();
        for part in chunks(&bytes, pattern) {
            assert_eq!(decoder.feed(part), part.len());
            while let Some(message) = decoder.next_message() {
                parsed.push(message.unwrap());
            }
        }
        assert_eq!(parsed, messages);
        assert!(decoder.is_between_messages());
    }
    eof_at_every_prefix(opcua::Frames::new, &Wire::to_bytes(&frames[0]).unwrap());
    for message_type in [
        opcua::MessageType::Hello,
        opcua::MessageType::Open,
        opcua::MessageType::Close,
    ] {
        for chunk_type in [opcua::ChunkType::Intermediate, opcua::ChunkType::Abort] {
            rollback(&opcua::Chunk {
                message_type,
                chunk_type,
                body: vec![],
            });
        }
    }
    rollback(&opcua::Chunk {
        body: vec![0; opcua::MAX_BUFFER_SIZE as usize],
        ..frames[0].clone()
    });
}

#[test]
fn opcua_limits_headers_and_handshake_normalization() {
    for size in [0, 1, opcua::MIN_BUFFER_SIZE, u32::MAX] {
        let frames = opcua::Frames::with_limits(opcua::Limits {
            receive_buffer_size: size,
            max_message_size: 1,
            max_chunk_count: 1,
        });
        assert_eq!(frames.limits().receive_buffer_size, size);
        assert_eq!(
            frames.capacity(),
            size.clamp(opcua::MIN_BUFFER_SIZE, opcua::MAX_BUFFER_SIZE)
                .max(opcua::MAX_HANDSHAKE_SIZE) as usize
        );
    }
    let mut header = b"MSGF".to_vec();
    header.extend_from_slice(&(opcua::MIN_BUFFER_SIZE + 1).to_le_bytes());
    let error = opcua::ChunkError::TooLarge {
        size: opcua::MIN_BUFFER_SIZE + 1,
        limit: opcua::MIN_BUFFER_SIZE,
    };
    let mut stream = Stream::new(opcua::Frames::new());
    assert_eq!(stream.push(&header), header.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(error.clone()))));
    assert_eq!(stream.failed(), Some(&Fail::Protocol(error)));
    assert!(stream.next().is_none());
    contract::check_decode(opcua::Frames::new, &header);

    // Limits can change between items; a larger capacity grows on demand.
    let chunk = opcua::Chunk {
        message_type: opcua::MessageType::Message,
        chunk_type: opcua::ChunkType::Final,
        body: vec![0; opcua::MIN_BUFFER_SIZE as usize],
    };
    let mut stream = Stream::new(opcua::Frames::new());
    stream.decoder().set_limits(opcua::Limits {
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
    round_trip(opcua::Frames::new, core::slice::from_ref(&handshake));
    let mut bytes = Wire::to_bytes(&handshake).unwrap();
    bytes[3] = 0;
    assert_eq!(<opcua::Chunk as Wire>::parse(&bytes), Ok(handshake));
    contract::check_wire::<opcua::Chunk>(&bytes);

    let max = opcua::Chunk {
        message_type: opcua::MessageType::Message,
        chunk_type: opcua::ChunkType::Abort,
        body: vec![0; opcua::MAX_BUFFER_SIZE as usize - opcua::HEADER_LEN],
    };
    contract::check_wire_value(&max);
    let bytes = Wire::to_bytes(&max).unwrap();
    let mut frames = opcua::Frames::with_limits(opcua::Limits {
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
    let bytes = round_trip(rdp::Frames::new, &frames);
    let make = || {
        rdp::Frames.map(|frame| match frame {
            rdp::Frame::SlowPath(packet) => Some(rdp::Connection::from_packet(&packet)),
            _ => None,
        })
    };
    contract::check_stack(make, &bytes);
    decode_chunks(
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
    eof_at_every_prefix(rdp::Frames::new, &frames[0].to_bytes().unwrap());
    eof_at_every_prefix(rdp::Frames::new, &frames[4].to_bytes().unwrap());
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
        rollback(&invalid);
    }
    // Fast-path lengths need not be minimal on input.
    let nonminimal = [0, 0x80, 3];
    contract::check_wire::<rdp::Frame>(&nonminimal);
    assert_eq!(
        <rdp::Frame as Wire>::parse(&nonminimal)
            .unwrap()
            .to_bytes()
            .unwrap(),
        [0, 2]
    );
}

#[test]
fn legacy_errors_still_repeat_and_clear_buffers() {
    let mut d = dnp3::Decoder::new();
    assert_eq!(d.feed(&[0]), 1);
    for _ in 0..2 {
        assert_eq!(d.next_frame(), Some(Err(dnp3::FrameError::Start)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.feed(&[5, 0x64]), 2);
    }
    let mut d = iec104::Decoder::new();
    assert_eq!(d.feed(&[0]), 1);
    for _ in 0..2 {
        assert_eq!(d.next_frame(), Some(Err(iec104::FrameError::Start)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.feed(&[0x68]), 1);
    }
    let mut d = rdp::Decoder::new();
    assert_eq!(d.storage_capacity(), rdp::MAX_STORAGE);
    assert_eq!(d.feed(&[1]), 1);
    for _ in 0..2 {
        assert_eq!(
            d.next_frame(),
            Some(Err(rdp::Error::Invalid("fast-path action")))
        );
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.feed(&[0, 2]), 2);
        assert_eq!(d.clone().storage_capacity(), rdp::MAX_STORAGE);
    }
    let mut d = opcua::Decoder::new();
    assert_eq!(d.feed(b"BAD"), 3);
    for _ in 0..2 {
        assert_eq!(
            d.next_message(),
            Some(Err(opcua::ChunkError::MessageType(*b"BAD")))
        );
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.feed(b"HEL"), 3);
        assert!(!d.is_between_messages());
    }
}

#[test]
fn framing_errors_are_terminal_once_and_keep_unread_bytes() {
    fn check<D>(make: impl Fn() -> D, bytes: &[u8], error: D::Error)
    where
        D: Decode,
        D::Item: PartialEq + Debug,
        D::Error: Clone + PartialEq + Debug,
    {
        contract::check_decode(&make, bytes);
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(bytes), bytes.len());
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(error.clone()))));
        assert_eq!(stream.failed(), Some(&Fail::Protocol(error)));
        assert_eq!(stream.unread(), bytes);
        assert!(stream.next().is_none());
        assert_eq!(stream.push(b"more"), 4);
        assert!(stream.next().is_none());
    }
    check(dnp3::Frames::new, &[5, 0x64, 4], dnp3::FrameError::Length);
    check(
        dnp3::Frames::new,
        &[5, 0x64, 5, 0, 0, 0, 0, 0, 0, 0],
        dnp3::FrameError::Crc(8),
    );
    check(
        iec104::Frames::new,
        &[0x68, 254],
        iec104::FrameError::Length,
    );
    check(
        iec104::Frames::new,
        &[0x68, 4, 3, 0, 0, 0],
        iec104::FrameError::Control,
    );
    check(
        rdp::Frames::new,
        &[1],
        rdp::Error::Invalid("fast-path action"),
    );
    check(
        opcua::Frames::new,
        b"OPNC",
        opcua::ChunkError::ChunkType(opcua::MessageType::Open, b'C'),
    );
}
