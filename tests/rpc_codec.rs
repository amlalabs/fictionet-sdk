//! Streaming RPC and authentication framers through the shared driver.

use fictionet::stdlib::codec::Frames;
use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Lcg, Step, Stream, Wire, contract, finish,
    test_support::{decode_all, mutate},
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
    contract::check_decode_with_alloc_limit(&make, &bytes, 2 * make().capacity());
    let (items, error) = decode_all(make, &bytes);
    assert_eq!(items, expected);
    assert_eq!(error, None);
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
    contract::check_decode_with_alloc_limit(&make, bytes, 2 * make().capacity());
    let mut stream = Stream::new(make());
    let failure = Fail::Protocol(error);
    for byte in &bytes[..bytes.len() - 1] {
        assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
        assert_eq!(stream.next(), None);
    }
    assert_eq!(stream.push(&bytes[bytes.len() - 1..]), 1);
    assert_eq!(stream.next(), Some(Err(failure.clone())));
    assert_eq!(stream.failed(), Some(&failure));
    assert!(stream.is_done());
    assert_eq!(stream.offset(), 0);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.push(b"after failure"), 13);
    assert_eq!(stream.next(), None);
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
    round_trip(|| Frames::<dcerpc::Pdu>::with_limit(80), &values, &expected);
    truncations(Frames::<dcerpc::Pdu>::new, &Wire::to_bytes(&values[0]).unwrap());
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
    contract::check_decode_with_alloc_limit(Frames::<dcerpc::Pdu>::new, &bytes, 2 * Frames::<dcerpc::Pdu>::new().capacity());
    let mut stream = Stream::new(Frames::<dcerpc::Pdu>::new());
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
        || Frames::<dcerpc::Pdu>::with_limit(24),
        &bytes[..10],
        dcerpc::Error::TooLong { length: bytes.len(), limit: 24 },
    );
    for (header, expected) in [
        (vec![4, 0], dcerpc::Error::Version { major: 4, minor: 0 }),
        (vec![5, 0, 0, 0, 0x20], dcerpc::Error::IntegerRep(2)),
        (vec![5, 0, 0, 0, 0x10, 0, 0, 0, 15, 0], dcerpc::Error::FragLength(15)),
    ] {
        terminal(Frames::<dcerpc::Pdu>::new, &header, expected);
    }
    let mut broken = bytes;
    broken.extend_from_slice(&[4, 0]);
    rpc_request().write(&mut broken).unwrap();
    let mut stream = Stream::new(Frames::<dcerpc::Pdu>::new());
    assert_eq!(stream.push(&broken), broken.len());
    assert_eq!(stream.next(), Some(Ok(Ok(rpc_request()))));
    assert!(matches!(stream.next(), Some(Err(Fail::Protocol(_)))));
    assert_eq!(stream.next(), None);
}

#[test]
fn dcerpc_writer_is_transactional() {
    let valid = rpc_request();
    contract::check_wire_value(&valid);
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
    let Step::Item(Ok(received), _) = Frames::<dcerpc::Pdu>::new().decode(&bytes, false).unwrap() else { panic!() };
    assert_eq!(received.to_bytes(), Err(dcerpc::Error::Unwritable));
    assert_eq!(
        <dcerpc::Pdu as Wire>::parse(&bytes),
        Err(dcerpc::Error::Unwritable)
    );
    refused(&received);
    assert_eq!(Frames::<dcerpc::Pdu>::new().decode(&bytes, false), Ok(Step::Item(Ok(received), bytes.len())));
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
    let bytes = round_trip(|| Frames::<smb2::Frame>::with_limit(80), &values, &values);
    let make = || Frames::<smb2::Frame>::new().map(|frame| smb2::Packet::parse(&frame.payload));
    contract::check_decode_with_alloc_limit(make, &bytes, 2 * Frames::<smb2::Frame>::new().capacity());
    let (got, error) = decode_all(make, &bytes);
    assert_eq!(error, None);
    assert_eq!(
        got,
        [
            Ok(packet.clone()),
            Err(smb2::Error::Truncated),
            Ok(smb2::Packet::Smb1(b"\xffSMBopaque".to_vec())),
            Ok(packet)
        ]
    );
    truncations(Frames::<smb2::Frame>::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn smb2_length_errors_report_bounds() {
    for limit in [0, 7, smb2::MAX_MESSAGE, usize::MAX] {
        let mut frames = Frames::<smb2::Frame>::with_limit(limit);
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
    terminal(Frames::<smb2::Frame>::new, &bytes, smb2::Error::Length { length, limit: smb2::MAX_MESSAGE });
    terminal(Frames::<smb2::Frame>::new, &[0x81], smb2::Error::FrameType(0x81));
    terminal(|| Frames::<smb2::Frame>::with_limit(7), &[0, 0, 0, 8], smb2::Error::Length { length: 8, limit: 7 });
    let mut empty_only = Frames::<smb2::Frame>::with_limit(0);
    assert_eq!(empty_only.capacity(), smb2::FRAME_HEADER_LEN);
    assert_eq!(
        empty_only.decode(&[0, 0, 0, 0], false),
        Ok(Step::Item(smb2::Frame { payload: vec![] }, 4))
    );
    terminal(|| Frames::<smb2::Frame>::with_limit(0), &[0, 0, 0, 1], smb2::Error::Length { length: 1, limit: 0 });
    refused(&smb2::Frame {
        payload: vec![0; length],
    });
}

#[test]
fn smb2_compound_padding_is_part_of_the_value() {
    let first = smb2::Request::Echo.message(1).unwrap();
    let last = smb2::Request::Echo.message(2).unwrap();
    refused(&smb2::Packet::Smb2(vec![first.clone(), last.clone()]));
    let packet = smb2::Packet::compound(vec![first.clone(), last.clone()]).unwrap();
    let smb2::Packet::Smb2(messages) = &packet else { panic!("compound packet") };
    assert_eq!(messages[0].body, [first.body, vec![0; 4]].concat());
    assert_eq!(messages[1], last);
    contract::check_wire_value(&packet);
    let bytes = packet.to_bytes().unwrap();
    assert_eq!(smb2::Message::parse(&bytes), Err(smb2::Error::NextCommand(72)));
    contract::check_wire_value(&last);
}

#[test]
fn smb2_typed_message_limit_includes_its_header() {
    let mut request = smb2::WriteRequest {
        data: vec![0; smb2::MAX_MESSAGE - smb2::HEADER_LEN - 48],
        ..Default::default()
    };
    let message = smb2::Request::Write(request.clone()).message(1).unwrap();
    assert_eq!(message.to_bytes().unwrap().len(), smb2::MAX_MESSAGE);
    request.data.push(0);
    assert_eq!(smb2::Request::Write(request).message(1), Err(smb2::Error::Unwritable));
}

#[test]
fn standalone_wire_units_are_exact_and_transactional() {
    let name = nbss::Name::new("server", 0x20);
    contract::check_wire_value(&name);
    let mut bytes = name.to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(nbss::Name::parse(&bytes), Err(nbss::Error::Trailing { remaining: 1 }));

    let attribute = radius::Attribute { kind: 1, value: b"name".to_vec() };
    contract::check_wire_value(&attribute);
    let mut bytes = attribute.to_bytes().unwrap();
    bytes.push(0);
    assert!(radius::Attribute::parse(&bytes).is_err());
    refused(&radius::Attribute { kind: 1, value: vec![0; radius::MAX_VALUE + 1] });

    let mut vsa = radius::Vsa { vendor: 9, data: vec![0; radius::MAX_VALUE - 4] };
    contract::check_wire_value(&vsa);
    let mut bytes = vsa.to_bytes().unwrap();
    bytes.push(0);
    assert!(radius::Vsa::parse(&bytes).is_err());
    vsa.data.push(0);
    refused(&vsa);
    let mut evs = radius::Evs { vendor: 9, evs_type: 1, data: vec![0; radius::MAX_LONG_EXTENDED_VALUE - 5] };
    contract::check_wire_value(&evs);
    let mut bytes = evs.to_bytes().unwrap();
    bytes.push(0);
    assert!(radius::Evs::parse(&bytes).is_err());
    evs.data.push(0);
    refused(&evs);

    let avp = diameter::Avp::new(1, &diameter::Value::OctetString(vec![42])).unwrap();
    contract::check_wire_value(&avp);
    let mut bytes = avp.to_bytes().unwrap();
    assert_eq!(diameter::Avp::parse(&bytes[..9]), Ok(avp.clone()));
    assert!(diameter::Avp::parse_list(&bytes[..9]).is_err());
    bytes.push(0);
    assert_eq!(diameter::Avp::parse(&bytes), Err(diameter::Error::Trailing { remaining: 1 }));
    refused(&diameter::Address::Other { family: diameter::Address::IPV4, bytes: vec![0; 4] });
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
    round_trip(|| Frames::<nbss::Packet>::with_limit(128), &values, &values);
    truncations(Frames::<nbss::Packet>::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn nbss_length_extension_and_zero_limit() {
    let packet = nbss::Packet::Message(vec![0x42; 0x1_0000]);
    let bytes = Wire::to_bytes(&packet).unwrap();
    assert_eq!(&bytes[..4], &[0, 1, 0, 0]);
    contract::check_decode_with_alloc_limit(Frames::<nbss::Packet>::new, &bytes, 2 * Frames::<nbss::Packet>::new().capacity());
    assert_eq!(Frames::<nbss::Packet>::new().decode(&bytes, false), Ok(Step::Item(packet, bytes.len())));
    let mut frames = Frames::<nbss::Packet>::with_limit(0);
    assert_eq!(frames.capacity(), nbss::HEADER_LEN);
    assert_eq!(frames.decode(&[0x85, 0, 0, 0], false), Ok(Step::Item(nbss::Packet::KeepAlive, 4)));
    terminal(|| Frames::<nbss::Packet>::with_limit(0), &[0, 0, 0, 1], nbss::Error::TooLong(1));
    terminal(|| Frames::<nbss::Packet>::with_limit(65_535), &bytes[..4], nbss::Error::TooLong(65_536));
}

#[test]
fn nbss_errors_end_stream_and_writes_are_transactional() {
    terminal(Frames::<nbss::Packet>::new, &[0x99], nbss::Error::Type(0x99));
    terminal(Frames::<nbss::Packet>::new, &[0, 2], nbss::Error::Flags(2));
    let mut bad = session_request().to_bytes().unwrap();
    bad[5] = b'Z';
    terminal(Frames::<nbss::Packet>::new, &bad, nbss::Error::Body(nbss::kind::REQUEST));
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
    round_trip(|| Frames::<radius::Packet>::with_limit(64), &values, &values);
    truncations(Frames::<radius::Packet>::new, &Wire::to_bytes(&values[0]).unwrap());
}

#[test]
fn radius_length_errors_report_bounds() {
    for limit in [0, 20, 64, radius::MAX_PACKET, usize::MAX] {
        let mut frames = Frames::<radius::Packet>::with_limit(limit);
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
    terminal(Frames::<radius::Packet>::new, &[1, 0, 0x10, 1], radius::Error::Length { length: 4097, limit: radius::MAX_PACKET });
    terminal(Frames::<radius::Packet>::new, &[1, 0, 0, 19], radius::Error::Length { length: 19, limit: radius::MAX_PACKET });
    terminal(|| Frames::<radius::Packet>::with_limit(20), &[1, 0, 0, 21], radius::Error::Length { length: 21, limit: 20 });
    let empty = radius::Packet::new(radius::Code::AccessRequest, 0, [0; 16]);
    let bytes = Wire::to_bytes(&empty).unwrap();
    assert_eq!(
        Frames::<radius::Packet>::with_limit(0).decode(&bytes, false),
        Ok(Step::Item(empty, radius::HEADER_LEN))
    );
    let mut bad = radius_request().to_bytes().unwrap();
    bad[21] = 1;
    terminal(Frames::<radius::Packet>::new, &bad, radius::Error::Attribute(20));
}

#[test]
fn radius_wire_is_exact_and_transactional() {
    let packet = radius_request();
    let mut bytes = packet.to_bytes().unwrap();
    bytes.extend_from_slice(&[0, 0]);
    assert_eq!(<radius::Packet as Wire>::parse(&bytes), Err(radius::Error::Trailing { remaining: 2 }));
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
    reply.avps.push(diameter::Avp::new(diameter::avp::RESULT_CODE, &diameter::Value::Unsigned32(2001)).unwrap());
    let values = [request, reply, diameter::Message::request(280, 0, 10, 11)];
    let expected = values.iter().cloned().map(Ok).collect::<Vec<_>>();
    round_trip(|| Frames::<diameter::Message>::with_limit(64), &values, &expected);
    truncations(Frames::<diameter::Message>::new, &Wire::to_bytes(&values[0]).unwrap());
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
    ).unwrap());
    let mut bytes = request.to_bytes().unwrap();
    bytes[27] = 4;
    let bad = bytes.clone();
    request.avps.clear();
    let malformed = diameter::AvpFault {
        header: request,
        error: diameter::Error::AvpLength {
            code: 264,
            length: 4,
        },
    };
    let next = diameter::Message::request(diameter::command::DEVICE_WATCHDOG, 0, 7, 9);
    next.write(&mut bytes).unwrap();
    let mut stream = Stream::new(Frames::<diameter::Message>::new());
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
    contract::check_decode_with_alloc_limit(Frames::<diameter::Message>::new, &bytes, 2 * Frames::<diameter::Message>::new().capacity());
    assert_eq!(decode_all(Frames::<diameter::Message>::new, &bytes), (vec![Err(malformed), Ok(next)], None));
}

#[test]
fn diameter_header_errors_end_stream() {
    terminal(|| Frames::<diameter::Message>::with_limit(20), &[1, 0, 0, 24], diameter::FrameError::TooBig(24));
    terminal(Frames::<diameter::Message>::new, &[2], diameter::FrameError::Version(2));
    terminal(Frames::<diameter::Message>::new, &[1, 0, 0, 21], diameter::FrameError::MessageLength(21));
}

#[test]
fn diameter_too_many_avps_is_a_message_error() {
    let header = diameter::Message::request(diameter::command::CAPABILITIES_EXCHANGE, 4, 17, 19);
    let mut bytes = header.to_bytes().unwrap();
    for _ in 0..=diameter::MAX_AVPS {
        bytes.extend_from_slice(&[0, 0, 1, 8, 0, 0, 0, 8]);
    }
    let length = bytes.len();
    bytes[1..4].copy_from_slice(&(length as u32).to_be_bytes()[1..]);
    let next = diameter::Message::request(diameter::command::DEVICE_WATCHDOG, 0, 7, 9);
    next.write(&mut bytes).unwrap();
    let mut stream = Stream::new(Frames::<diameter::Message>::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    let malformed = diameter::AvpFault {
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
    assert!(request.check_header().is_err());
    assert!(diameter::check(&request.avps, |_, _| None).is_err());
    let bytes = Wire::to_bytes(&request).unwrap();
    assert_eq!(<diameter::Message as Wire>::parse(&bytes), Ok(request.clone()));
    contract::check_wire::<diameter::Message>(&bytes);
    contract::check_wire_value(&request);
    request.request = false;
    request.retransmit = true;
    contract::check_wire_value(&request);
    // Nonzero AVP padding and reserved header flags normalize once.
    let mut bytes = request.to_bytes().unwrap();
    bytes[4] |= 0x0f;
    *bytes.last_mut().unwrap() = 0xff;
    contract::check_wire::<diameter::Message>(&bytes);
}

#[test]
fn diameter_strict_writer_refuses_clipping_transactionally() {
    let mut message = diameter_request();
    message.command = 0x0100_0000;
    refused(&message);
    message = diameter_request();
    message.avps = vec![message.avps[0].clone(); diameter::MAX_AVPS + 1];
    refused(&message);
    message = diameter_request();
    message.avps[0].data = vec![0; diameter::MAX_MESSAGE];
    refused(&message);
}

#[test]
fn capacity_limits_are_real_and_clamped() {
    assert_eq!(Frames::<dcerpc::Pdu>::with_limit(0).capacity(), dcerpc::HEADER_LEN);
    assert_eq!(Frames::<dcerpc::Pdu>::with_limit(usize::MAX).limit(), dcerpc::MAX_FRAG);
    assert_eq!(Frames::<smb2::Frame>::new().capacity(), smb2::MAX_FRAME);
    assert_eq!(Frames::<smb2::Frame>::default(), Frames::<smb2::Frame>::new());
    assert_eq!(
        Frames::<smb2::Frame>::with_limit(usize::MAX).limit(),
        smb2::MAX_MESSAGE
    );
    assert_eq!(
        Frames::<smb2::Frame>::with_limit(7).capacity(),
        smb2::FRAME_HEADER_LEN + 7
    );
    assert_eq!(
        Frames::<nbss::Packet>::with_limit(usize::MAX).limit(),
        nbss::MAX_LENGTH
    );
    assert_eq!(Frames::<radius::Packet>::new().capacity(), radius::MAX_PACKET);
    assert_eq!(Frames::<radius::Packet>::default(), Frames::<radius::Packet>::new());
    assert_eq!(Frames::<radius::Packet>::with_limit(0).limit(), radius::HEADER_LEN);
    assert_eq!(
        Frames::<radius::Packet>::with_limit(usize::MAX).limit(),
        radius::MAX_PACKET
    );
    assert_eq!(
        Frames::<diameter::Message>::with_limit(0).limit(),
        diameter::HEADER_LEN
    );
    assert_eq!(
        Frames::<diameter::Message>::with_limit(usize::MAX).capacity(),
        diameter::MAX_MESSAGE
    );
    assert_eq!(Frames::<diameter::Message>::new().capacity(), diameter::DEFAULT_LIMIT);
    for limit in [0, 1, 19, 20, 21, 63, 64] {
        let mut frames = Frames::<diameter::Message>::with_limit(limit);
        // A capacity not divisible by four still must decide from the header.
        let mut bytes = vec![0; frames.capacity()];
        bytes[..4].copy_from_slice(&[1, 0, 0, 64]);
        assert!(!matches!(frames.decode(&bytes, false), Ok(Step::Need)));
    }
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
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(Frames::<dcerpc::Pdu>::new, &bytes, 2 * Frames::<dcerpc::Pdu>::new().capacity());
            contract::check_decode_with_alloc_limit(Frames::<smb2::Frame>::new, &bytes, 2 * Frames::<smb2::Frame>::new().capacity());
            contract::check_decode_with_alloc_limit(Frames::<nbss::Packet>::new, &bytes, 2 * Frames::<nbss::Packet>::new().capacity());
            contract::check_decode_with_alloc_limit(Frames::<radius::Packet>::new, &bytes, 2 * Frames::<radius::Packet>::new().capacity());
            contract::check_decode_with_alloc_limit(Frames::<diameter::Message>::new, &bytes, 2 * Frames::<diameter::Message>::new().capacity());
            contract::check_wire::<dcerpc::Pdu>(&bytes);
            contract::check_wire::<smb2::Frame>(&bytes);
            contract::check_wire::<nbss::Packet>(&bytes);
            contract::check_wire::<radius::Packet>(&bytes);
            contract::check_wire::<diameter::Message>(&bytes);
        }
    }
}
