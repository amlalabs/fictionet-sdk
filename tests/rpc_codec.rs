//! Counted-feed RPC and authentication framers through the shared driver.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Step, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, chunks},
};
use fictionet::stdlib::{dcerpc, diameter, nbss, radius, smb2};

#[test]
fn migrated_public_docs_do_not_reference_internal_design_sections() {
    for (module, source) in [
        ("dcerpc", include_str!("../src/stdlib/dcerpc.rs")),
        ("smb2", include_str!("../src/stdlib/smb2.rs")),
        ("nbss", include_str!("../src/stdlib/nbss.rs")),
        ("radius", include_str!("../src/stdlib/radius.rs")),
        ("diameter", include_str!("../src/stdlib/diameter.rs")),
    ] {
        let docs = source
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                line.strip_prefix("///")
                    .or_else(|| line.strip_prefix("//!"))
            })
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            !docs.to_ascii_lowercase().contains("design section"),
            "{module} public docs refer to an internal design section"
        );
    }
}

fn round_trip<M, D>(make: impl Fn() -> D, values: &[M], expected: &[D::Item]) -> Vec<u8>
where
    M: Wire + PartialEq + Debug,
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let mut bytes = Vec::new();
    for value in values {
        contract::check_wire_value(value);
        let start = bytes.len();
        value.write(&mut bytes).unwrap();
        let encoded = &bytes[start..];
        assert_eq!(&M::parse(encoded).unwrap(), value);
        contract::check_wire::<M>(encoded);
        assert!(M::parse(&[]).is_err());
        assert!(M::parse(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(M::parse(&trailing).is_err());
    }
    contract::check_decode(&make, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 7, 2, 257], &[19, 2, 5, 1024]] {
        let mut stream = Stream::new(make());
        let capacity = make().capacity();
        let mut got = Vec::new();
        for part in chunks(&bytes, pattern) {
            assert_eq!(pump(&mut stream, part, |item| got.push(item)), Ok(part.len()));
            assert!(stream.buffered() <= capacity);
            assert_eq!(stream.held(), 0);
        }
        finish(&mut stream, |item| got.push(item)).unwrap();
        assert_eq!(got, expected);
        assert_eq!(stream.offset(), bytes.len() as u64);
        assert_eq!(stream.buffered(), 0);
        assert!(stream.failed().is_none());
        assert!(stream.is_done());
        assert!(stream.next().is_none());
    }
    bytes
}

fn truncations<D>(make: impl Fn() -> D, bytes: &[u8])
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    for cut in 1..bytes.len() {
        let mut stream = Stream::new(make());
        for byte in &bytes[..cut] {
            assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
            assert_eq!(stream.next(), None);
        }
        stream.end();
        let failure = Fail::Truncated { unread: cut };
        assert_eq!(stream.next(), Some(Err(failure.clone())));
        assert_eq!(stream.failed(), Some(&failure));
        assert_eq!(stream.buffered(), cut);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(bytes), bytes.len());
        assert_eq!(stream.next(), None);
    }
}

fn terminal<D>(make: impl Fn() -> D, bytes: &[u8], error: D::Error)
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    assert_eq!(make().decode(bytes, false), Err(error.clone()));
    contract::check_decode(&make, bytes);
    for pattern in [&[][..], &[1]] {
        let mut stream = Stream::new(make());
        let failure = Fail::Protocol(error.clone());
        let mut errors = Vec::new();
        for chunk in chunks(bytes, pattern) {
            assert_eq!(stream.push(chunk), chunk.len());
            if let Some(item) = stream.next() {
                assert_eq!(item, Err(failure.clone()));
                errors.push(item);
            }
        }
        assert_eq!(errors.len(), 1);
        assert_eq!(stream.failed(), Some(&failure));
        assert!(stream.is_done());
        assert_eq!(stream.offset(), 0);
        assert!(stream.buffered() <= bytes.len());
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"after failure"), 13);
        assert_eq!(stream.next(), None);
    }
}

fn refused<M: Wire + PartialEq + Debug>(value: &M) {
    let mut out = vec![0xa5, 0x5a, 0x42];
    assert!(value.write(&mut out).is_err());
    assert_eq!(out, [0xa5, 0x5a, 0x42]);
    contract::check_wire_value(value);
}

fn rpc_request() -> dcerpc::Pdu {
    dcerpc::Pdu::new(
        7,
        dcerpc::Body::Request { alloc_hint: 5, context_id: 1, opnum: 2, object: None, stub: b"hello".to_vec() },
    )
}

#[test]
fn dcerpc_chunked_round_trip() {
    let mut request = rpc_request();
    request.auth = Some(dcerpc::Auth { kind: 10, level: 5, context_id: 3, value: vec![1, 2, 3] });
    let mut response = request.reply(dcerpc::Body::Response {
        alloc_hint: 6,
        context_id: 1,
        cancel_count: 0,
        stub: b"result".to_vec(),
    });
    response.drep = dcerpc::DataRep::BIG_ENDIAN;
    let values = [request, response, dcerpc::Pdu::new(9, dcerpc::Body::Shutdown)];
    let expected = values.iter().cloned().map(Ok).collect::<Vec<_>>();
    round_trip(|| dcerpc::Frames::with_limit(80), &values, &expected);
    truncations(dcerpc::Frames::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn dcerpc_body_errors_are_items_and_raw_spans_survive() {
    let good = rpc_request();
    let mut bad_type = Wire::to_bytes(&dcerpc::Pdu::new(1, dcerpc::Body::Shutdown)).unwrap();
    bad_type[2] = 0xff;
    let mut short_body = bad_type.clone();
    short_body[2] = dcerpc::ptype::REQUEST;
    let mut bytes = bad_type.clone();
    bytes.extend_from_slice(&short_body);
    good.write(&mut bytes).unwrap();
    contract::check_decode(dcerpc::Frames::new, &bytes);
    let mut stream = Stream::new(dcerpc::Frames::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(
        stream.with_next(|item, raw, span| {
            assert_eq!(raw, bad_type);
            assert_eq!(span, 0..16);
            item
        }),
        Some(Ok(Err(dcerpc::Error::Type(0xff))))
    );
    assert_eq!(stream.next_span(), Some(Ok((Err(dcerpc::Error::Truncated), 16..32))));
    assert_eq!(stream.next(), Some(Ok(Ok(good))));
    finish(&mut stream, |_| panic!("all items drained")).unwrap();
    assert!(stream.failed().is_none());
}

#[test]
fn dcerpc_header_errors_and_limits_end_the_stream() {
    let bytes = Wire::to_bytes(&rpc_request()).unwrap();
    terminal(
        || dcerpc::Frames::with_limit(24),
        &bytes[..10],
        dcerpc::FrameError::TooLong { length: bytes.len(), limit: 24 },
    );
    for (header, expected) in [
        (vec![4, 0], dcerpc::Error::Version { major: 4, minor: 0 }),
        (vec![5, 0, 0, 0, 0x20], dcerpc::Error::IntegerRep(2)),
        (vec![5, 0, 0, 0, 0x10, 0, 0, 0, 15, 0], dcerpc::Error::FragLength(15)),
    ] {
        terminal(dcerpc::Frames::new, &header, dcerpc::FrameError::Header(expected));
    }
    let mut broken = bytes;
    broken.extend_from_slice(&[4, 0]);
    rpc_request().write(&mut broken).unwrap();
    let mut stream = Stream::new(dcerpc::Frames::new());
    assert_eq!(stream.push(&broken), broken.len());
    assert_eq!(stream.next(), Some(Ok(Ok(rpc_request()))));
    assert!(matches!(stream.next(), Some(Err(Fail::Protocol(_)))));
    assert_eq!(stream.next(), None);
}

#[test]
fn dcerpc_writer_is_transactional_and_keeps_legacy_output() {
    let valid = rpc_request();
    assert_eq!(Wire::to_bytes(&valid).unwrap(), valid.to_bytes().unwrap());
    let mut invalid = valid.clone();
    invalid.flags |= dcerpc::flags::OBJECT_UUID;
    refused(&invalid);
    invalid = valid.clone();
    invalid.version_minor = 2;
    refused(&invalid);
    invalid = valid.clone();
    invalid.auth = Some(dcerpc::Auth { kind: 1, level: 1, context_id: 0, value: vec![] });
    refused(&invalid);
    invalid = valid;
    if let dcerpc::Body::Request { stub, .. } = &mut invalid.body {
        *stub = vec![0; dcerpc::MAX_FRAG];
    }
    refused(&invalid);
}

#[test]
fn dcerpc_wire_bounds_canonical_padding() {
    // This received PDU fits, but the existing writer adds four auth pad bytes.
    let mut pdu = rpc_request();
    if let dcerpc::Body::Request { stub, .. } = &mut pdu.body {
        *stub = vec![0; dcerpc::MAX_FRAG - 24 - 8 - 3];
    }
    let mut bytes = pdu.to_bytes().unwrap();
    bytes.extend_from_slice(&[10, 5, 0, 0, 0, 0, 0, 0, 1, 2, 3]);
    bytes[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[10..12].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(bytes.len(), dcerpc::MAX_FRAG);
    let received = dcerpc::Pdu::parse(&bytes).unwrap().unwrap().0;
    assert_eq!(received.to_bytes(), Err(dcerpc::EncodeError::TooLong));
    assert_eq!(
        <dcerpc::Pdu as Wire>::parse(&bytes),
        Err(dcerpc::ParseError::Unrepresentable(dcerpc::EncodeError::TooLong))
    );
    refused(&received);
    assert_eq!(dcerpc::Frames::new().decode(&bytes, false), Ok(Step::Item(Ok(received), bytes.len())));
    contract::check_wire::<dcerpc::Pdu>(&bytes);
}

fn smb_packet() -> smb2::Packet {
    let request = smb2::Message::from_request(smb2::Header::new(smb2::command::ECHO, 7), &smb2::Request::Echo).unwrap();
    smb2::Packet::Smb2(vec![request])
}

#[test]
fn smb2_chunked_round_trip() {
    let packet = smb_packet();
    let values = [
        smb2::Frame { payload: packet.to_bytes().unwrap() },
        smb2::Frame { payload: vec![] },
        smb2::Frame { payload: b"\xffSMBopaque".to_vec() },
        smb2::Frame { payload: packet.to_bytes().unwrap() },
    ];
    let bytes = round_trip(|| smb2::Frames::with_limit(80), &values, &values);
    let make = || smb2::Frames::new().map(|frame| smb2::Packet::parse(&frame.payload));
    contract::check_stack(make, &bytes);
    let mut stream = Stream::new(make());
    let mut got = Vec::new();
    for byte in &bytes {
        pump(&mut stream, core::slice::from_ref(byte), |item| got.push(item)).unwrap();
    }
    finish(&mut stream, |item| got.push(item)).unwrap();
    assert_eq!(
        got,
        [
            Ok(packet.clone()),
            Err(smb2::Error::Truncated),
            Ok(smb2::Packet::Smb1(b"\xffSMBopaque".to_vec())),
            Ok(packet)
        ]
    );
    truncations(smb2::Frames::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn smb2_length_errors_report_bounds() {
    let length = smb2::MAX_MESSAGE + 1;
    let bytes = (length as u32).to_be_bytes();
    let mut legacy = smb2::Decoder::new();
    assert_eq!(legacy.feed(&bytes), bytes.len());
    assert_eq!(
        legacy.next_frame().unwrap().unwrap_err().to_string(),
        format!("frame length {length}, more than {}", smb2::MAX_MESSAGE)
    );
    for limit in [0, 7, smb2::MAX_MESSAGE, usize::MAX] {
        let mut frames = smb2::Frames::with_limit(limit);
        let limit = frames.limit();
        let length = limit + 1;
        let bytes = (length as u32).to_be_bytes();
        assert_eq!(
            frames.decode(&bytes, false).unwrap_err().to_string(),
            format!("frame length {length}, more than {limit}")
        );
    }
}

#[test]
fn smb2_refuses_length_from_header_and_writer_rolls_back() {
    let length = smb2::MAX_MESSAGE + 1;
    let bytes = (length as u32).to_be_bytes();
    terminal(
        smb2::Frames::new,
        &bytes,
        smb2::FrameError::Length {
            length,
            limit: smb2::MAX_MESSAGE,
        },
    );
    terminal(smb2::Frames::new, &[0x81], smb2::FrameError::Type(0x81));
    terminal(
        || smb2::Frames::with_limit(7),
        &[0, 0, 0, 8],
        smb2::FrameError::Length {
            length: 8,
            limit: 7,
        },
    );
    let mut empty_only = smb2::Frames::with_limit(0);
    assert_eq!(empty_only.capacity(), smb2::FRAME_HEADER_LEN);
    assert_eq!(
        empty_only.decode(&[0, 0, 0, 0], false),
        Ok(Step::Item(smb2::Frame { payload: vec![] }, 4))
    );
    terminal(
        || smb2::Frames::with_limit(0),
        &[0, 0, 0, 1],
        smb2::FrameError::Length {
            length: 1,
            limit: 0,
        },
    );
    refused(&smb2::Frame {
        payload: vec![0; length],
    });
}

fn session_request() -> nbss::Packet {
    nbss::Packet::Request {
        called: nbss::Name::new("FILESERVER", 0x20),
        calling: nbss::Name { scope: vec![b"EXAMPLE".to_vec()], ..nbss::Name::new("CLIENT", 0) },
    }
}

#[test]
fn nbss_chunked_round_trip() {
    let values = [
        session_request(),
        nbss::Packet::Positive,
        nbss::Packet::Message(b"\xffSMBdata".to_vec()),
        nbss::Packet::KeepAlive,
        nbss::Packet::Negative(nbss::NegativeCode::Other(7)),
        nbss::Packet::Retarget { address: [192, 0, 2, 1], port: 139 },
    ];
    round_trip(|| nbss::Frames::with_limit(128), &values, &values);
    truncations(nbss::Frames::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn nbss_length_extension_and_zero_limit() {
    let packet = nbss::Packet::Message(vec![0x42; 0x1_0000]);
    let bytes = Wire::to_bytes(&packet).unwrap();
    assert_eq!(&bytes[..4], &[0, 1, 0, 0]);
    contract::check_decode(nbss::Frames::new, &bytes);
    assert_eq!(nbss::Frames::new().decode(&bytes, false), Ok(Step::Item(packet, bytes.len())));
    let mut frames = nbss::Frames::with_limit(0);
    assert_eq!(frames.capacity(), nbss::HEADER_LEN);
    assert_eq!(frames.decode(&[0x85, 0, 0, 0], false), Ok(Step::Item(nbss::Packet::KeepAlive, 4)));
    terminal(|| nbss::Frames::with_limit(0), &[0, 0, 0, 1], nbss::Error::TooLong(1));
    terminal(|| nbss::Frames::with_limit(65_535), &bytes[..4], nbss::Error::TooLong(65_536));
}

#[test]
fn nbss_errors_end_stream_and_writes_are_transactional() {
    terminal(nbss::Frames::new, &[0x99], nbss::Error::Type(0x99));
    terminal(nbss::Frames::new, &[0, 2], nbss::Error::Flags(2));
    let mut bad = session_request().to_bytes().unwrap();
    bad[5] = b'Z';
    terminal(nbss::Frames::new, &bad, nbss::Error::Body(nbss::kind::REQUEST));
    refused(&nbss::Packet::Negative(nbss::NegativeCode::Other(0x80)));
    refused(&nbss::Packet::Message(vec![0; nbss::MAX_LENGTH + 1]));
    refused(&nbss::Packet::Request {
        called: nbss::Name { scope: vec![vec![]], ..nbss::Name::new("X", 0) },
        calling: nbss::Name::new("Y", 0),
    });
}

fn radius_request() -> radius::Packet {
    let mut packet = radius::Packet::new(radius::Code::AccessRequest, 7, [0xa5; 16]);
    packet.attributes = vec![
        radius::Attribute { kind: radius::attr::USER_NAME, value: b"alice".to_vec() },
        radius::Attribute { kind: radius::attr::PROXY_STATE, value: vec![1, 2, 3] },
    ];
    packet
}

#[test]
fn radius_chunked_round_trip() {
    let request = radius_request();
    let reply = request.reply(radius::Code::AccessAccept);
    let values = [request, reply, radius::Packet::new(radius::Code::Other(240), 8, [0; 16])];
    round_trip(|| radius::Frames::with_limit(64), &values, &values);
    truncations(radius::Frames::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn radius_length_errors_report_bounds() {
    for length in [19u16, 4097] {
        let [hi, lo] = length.to_be_bytes();
        let mut legacy = radius::Decoder::new();
        assert_eq!(legacy.feed(&[1, 0, hi, lo]), 4);
        assert_eq!(
            legacy.next_packet().unwrap().unwrap_err().to_string(),
            format!("length field {length}, outside 20..=4096")
        );
    }
    for limit in [0, 20, 64, radius::MAX_PACKET, usize::MAX] {
        let mut frames = radius::Frames::with_limit(limit);
        let limit = frames.limit();
        let length = limit as u16 + 1;
        let [hi, lo] = length.to_be_bytes();
        assert_eq!(
            frames
                .decode(&[1, 0, hi, lo], false)
                .unwrap_err()
                .to_string(),
            format!("length field {length}, outside 20..={limit}")
        );
    }
}

#[test]
fn radius_refuses_lengths_and_attributes_without_recovery() {
    terminal(
        radius::Frames::new,
        &[1, 0, 0x10, 1],
        radius::PacketError::Length {
            length: 4097,
            limit: radius::MAX_PACKET,
        },
    );
    terminal(
        radius::Frames::new,
        &[1, 0, 0, 19],
        radius::PacketError::Length {
            length: 19,
            limit: radius::MAX_PACKET,
        },
    );
    terminal(
        || radius::Frames::with_limit(20),
        &[1, 0, 0, 21],
        radius::PacketError::Length {
            length: 21,
            limit: 20,
        },
    );
    let empty = radius::Packet::new(radius::Code::AccessRequest, 0, [0; 16]);
    let bytes = Wire::to_bytes(&empty).unwrap();
    assert_eq!(
        radius::Frames::with_limit(0).decode(&bytes, false),
        Ok(Step::Item(empty, radius::HEADER_LEN))
    );
    let mut bad = radius_request().to_bytes().unwrap();
    bad[21] = 1;
    terminal(radius::Frames::new, &bad, radius::PacketError::Attribute(20));
}

#[test]
fn radius_wire_is_exact_and_transactional() {
    let packet = radius_request();
    let mut bytes = packet.to_bytes().unwrap();
    bytes.extend_from_slice(&[0, 0]);
    assert_eq!(radius::Packet::parse(&bytes), Ok(packet.clone()));
    assert_eq!(<radius::Packet as Wire>::parse(&bytes), Err(radius::ParseError::Trailing { remaining: 2 }));
    let mut invalid = packet.clone();
    invalid.attributes.push(radius::Attribute { kind: 1, value: vec![0; radius::MAX_VALUE + 1] });
    refused(&invalid);
    invalid = packet;
    invalid.attributes = vec![radius::Attribute { kind: 0, value: vec![] }; radius::MAX_ATTRIBUTES + 1];
    refused(&invalid);
}

fn diameter_request() -> diameter::Message {
    let mut request = diameter::Message::request(diameter::command::DEVICE_WATCHDOG, 0, 7, 9);
    request.avps = vec![
        diameter::Avp { code: 264, vendor: None, mandatory: true, protected: false, data: b"host".to_vec() },
        diameter::Avp { code: 1, vendor: Some(10415), mandatory: false, protected: true, data: vec![1, 2, 3] },
    ];
    request
}

#[test]
fn diameter_chunked_round_trip() {
    let request = diameter_request();
    let mut reply = request.answer();
    reply.avps.push(diameter::Avp::new(diameter::avp::RESULT_CODE, &diameter::Value::Unsigned32(2001)));
    let values = [request, reply, diameter::Message::request(280, 0, 10, 11)];
    let expected = values.iter().cloned().map(Ok).collect::<Vec<_>>();
    round_trip(|| diameter::Frames::with_limit(64), &values, &expected);
    truncations(diameter::Frames::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn diameter_bad_avp_keeps_header_and_next_message() {
    let mut request = diameter::Message::request(
        diameter::command::CAPABILITIES_EXCHANGE,
        0,
        0x11223344,
        0x55667788,
    );
    request.proxiable = true;
    request.retransmit = true;
    request.avps.push(diameter::Avp::new(
        diameter::avp::ORIGIN_HOST,
        &diameter::Value::OctetString(b"host".to_vec()),
    ));
    let mut bytes = request.to_bytes();
    bytes[27] = 4;
    let bad = bytes.clone();
    request.avps.clear();
    let malformed = diameter::Malformed {
        header: request,
        error: diameter::Error::AvpLength {
            code: 264,
            length: 4,
        },
    };
    let next = diameter::Message::request(diameter::command::DEVICE_WATCHDOG, 0, 7, 9);
    next.write(&mut bytes).unwrap();
    let mut stream = Stream::new(diameter::Frames::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(
        stream.with_next(|item, raw, span| {
            assert_eq!(raw, bad);
            assert_eq!(span, 0..bad.len() as u64);
            item
        }),
        Some(Ok(Err(malformed.clone())))
    );
    assert_eq!(stream.next(), Some(Ok(Ok(next.clone()))));
    finish(&mut stream, |_| panic!("all items drained")).unwrap();
    assert!(stream.failed().is_none());
    assert_eq!(stream.offset(), bytes.len() as u64);
    contract::check_decode(diameter::Frames::new, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 7, 2]] {
        let mut stream = Stream::new(diameter::Frames::new());
        let mut items = Vec::new();
        for chunk in chunks(&bytes, pattern) {
            assert_eq!(
                pump(&mut stream, chunk, |item| items.push(item)),
                Ok(chunk.len())
            );
        }
        finish(&mut stream, |item| items.push(item)).unwrap();
        assert_eq!(items, [Err(malformed.clone()), Ok(next.clone())]);
        assert_eq!(stream.buffered(), 0);
        assert!(stream.failed().is_none());
    }
}

#[test]
fn diameter_header_errors_end_stream() {
    terminal(|| diameter::Frames::with_limit(20), &[1, 0, 0, 24], diameter::Error::TooBig(24));
    terminal(diameter::Frames::new, &[2], diameter::Error::Version(2));
    terminal(diameter::Frames::new, &[1, 0, 0, 21], diameter::Error::MessageLength(21));
}

#[test]
fn diameter_too_many_avps_is_a_message_error() {
    let header = diameter::Message::request(diameter::command::CAPABILITIES_EXCHANGE, 4, 17, 19);
    let mut bytes = header.to_bytes();
    for _ in 0..=diameter::MAX_AVPS {
        bytes.extend_from_slice(&[0, 0, 1, 8, 0, 0, 0, 8]);
    }
    let length = bytes.len();
    bytes[1..4].copy_from_slice(&(length as u32).to_be_bytes()[1..]);
    let next = diameter::Message::request(diameter::command::DEVICE_WATCHDOG, 0, 7, 9);
    next.write(&mut bytes).unwrap();
    let mut stream = Stream::new(diameter::Frames::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    let malformed = diameter::Malformed {
        header,
        error: diameter::Error::TooManyAvps,
    };
    assert_eq!(
        stream.next_span(),
        Some(Ok((Err(malformed), 0..length as u64)))
    );
    assert_eq!(stream.next(), Some(Ok(Ok(next))));
    finish(&mut stream, |_| panic!("all items drained")).unwrap();
    assert!(stream.failed().is_none());
}

#[test]
fn diameter_wire_preserves_values_that_semantic_checks_refuse() {
    let mut request = diameter_request();
    request.error = true;
    request.avps[1].vendor = Some(0);
    assert!(request.try_to_bytes().is_none());
    let bytes = Wire::to_bytes(&request).unwrap();
    assert_eq!(<diameter::Message as Wire>::parse(&bytes), Ok(request.clone()));
    contract::check_wire::<diameter::Message>(&bytes);
    contract::check_wire_value(&request);
    request.request = false;
    request.retransmit = true;
    contract::check_wire_value(&request);
    // Nonzero AVP padding and reserved header flags normalize once.
    let mut bytes = request.to_bytes();
    bytes[4] |= 0x0f;
    *bytes.last_mut().unwrap() = 0xff;
    contract::check_wire::<diameter::Message>(&bytes);
}

#[test]
fn diameter_strict_writer_refuses_clipping_transactionally() {
    let mut message = diameter_request();
    message.command = 0x0100_0000;
    refused(&message);
    assert!(diameter::Message::parse(&message.to_bytes()).is_ok());
    message = diameter_request();
    message.avps = vec![message.avps[0].clone(); diameter::MAX_AVPS + 1];
    refused(&message);
    assert!(diameter::Message::parse(&message.to_bytes()).is_ok());
    message = diameter_request();
    message.avps[0].data = vec![0; diameter::MAX_MESSAGE];
    refused(&message);
}

#[test]
fn capacity_limits_are_real_and_clamped() {
    assert_eq!(dcerpc::Frames::with_limit(0).capacity(), dcerpc::HEADER_LEN);
    assert_eq!(dcerpc::Frames::with_limit(usize::MAX).limit(), dcerpc::MAX_FRAG);
    assert_eq!(smb2::Frames::new().capacity(), smb2::MAX_BUFFERED);
    assert_eq!(smb2::Frames::default(), smb2::Frames::new());
    assert_eq!(
        smb2::Frames::with_limit(usize::MAX).limit(),
        smb2::MAX_MESSAGE
    );
    assert_eq!(
        smb2::Frames::with_limit(7).capacity(),
        smb2::FRAME_HEADER_LEN + 7
    );
    assert_eq!(
        nbss::Frames::with_limit(usize::MAX).limit(),
        nbss::MAX_LENGTH
    );
    assert_eq!(radius::Frames::new().capacity(), radius::MAX_PACKET);
    assert_eq!(radius::Frames::default(), radius::Frames::new());
    assert_eq!(radius::Frames::with_limit(0).limit(), radius::HEADER_LEN);
    assert_eq!(
        radius::Frames::with_limit(usize::MAX).limit(),
        radius::MAX_PACKET
    );
    assert_eq!(
        diameter::Frames::with_limit(0).limit(),
        diameter::HEADER_LEN
    );
    assert_eq!(
        diameter::Frames::with_limit(usize::MAX).capacity(),
        diameter::MAX_MESSAGE
    );
    assert_eq!(diameter::Frames::new().capacity(), diameter::DEFAULT_LIMIT);
    for limit in [0, 1, 19, 20, 21, 63, 64] {
        let mut frames = diameter::Frames::with_limit(limit);
        // A capacity not divisible by four still must decide from the header.
        let mut bytes = vec![0; frames.capacity()];
        bytes[..4].copy_from_slice(&[1, 0, 0, 64]);
        assert!(!matches!(frames.decode(&bytes, false), Ok(Step::Need)));
    }
}

#[test]
fn legacy_decoders_keep_repeated_errors_and_empty_failure_buffers() {
    let mut rpc = dcerpc::Decoder::new();
    assert_eq!(rpc.feed(&[4, 0]), 2);
    let error = rpc.next_pdu();
    assert_eq!(rpc.next_pdu(), error);
    assert_eq!(rpc.buffered(), 0);
    assert_eq!(rpc.feed(&[1, 2, 3]), 3);
    assert_eq!(rpc.buffered(), 0);
    let mut smb = smb2::Decoder::new();
    assert_eq!(smb.feed(&[1]), 1);
    let error = smb.next_frame();
    assert_eq!(smb.next_frame(), error);
    assert_eq!(smb.buffered(), 0);
    let mut session = nbss::Decoder::new();
    assert_eq!(session.feed(&[1]), 1);
    let error = session.next_packet();
    assert_eq!(session.next_packet(), error);
    assert_eq!(session.buffered(), 0);
    let mut rad = radius::Decoder::new();
    assert_eq!(rad.feed(&[1, 0, 0, 0]), 4);
    let error = rad.next_packet();
    assert_eq!(rad.next_packet(), error);
    assert_eq!(rad.buffered(), 0);
    let mut dia = diameter::Decoder::new();
    let mut bad = diameter_request().to_bytes();
    bad[25..28].copy_from_slice(&[0, 0, 7]);
    assert_eq!(dia.feed(&bad), bad.len());
    let error = dia.next_message();
    assert_eq!(dia.next_message(), error);
    assert_eq!(dia.buffered(), 0);
    let header = dia.failed_header().unwrap();
    assert!(header.avps.is_empty());
    assert_eq!(header.hop_by_hop, 7);
}

#[test]
fn contracts_on_deterministic_inputs_and_mutated_units() {
    let seeds = [
        Wire::to_bytes(&rpc_request()).unwrap(),
        Wire::to_bytes(&smb2::Frame { payload: smb_packet().to_bytes().unwrap() }).unwrap(),
        Wire::to_bytes(&session_request()).unwrap(),
        Wire::to_bytes(&radius_request()).unwrap(),
        Wire::to_bytes(&diameter_request()).unwrap(),
    ];
    let mut rng = Lcg::new(0x52_50_43);
    for _ in 0..64 {
        for seed in &seeds {
            let mut bytes = seed.clone();
            let at = rng.below(bytes.len() as u64) as usize;
            bytes[at] = rng.next() as u8;
            contract::check_decode(dcerpc::Frames::new, &bytes);
            contract::check_decode(smb2::Frames::new, &bytes);
            contract::check_decode(nbss::Frames::new, &bytes);
            contract::check_decode(radius::Frames::new, &bytes);
            contract::check_decode(diameter::Frames::new, &bytes);
            contract::check_wire::<dcerpc::Pdu>(&bytes);
            contract::check_wire::<smb2::Frame>(&bytes);
            contract::check_wire::<nbss::Packet>(&bytes);
            contract::check_wire::<radius::Packet>(&bytes);
            contract::check_wire::<diameter::Message>(&bytes);
        }
    }
}
