//! Length-framed application streams: BGP, FastCGI, Kafka, Thrift, Zabbix.
//! Bounded frame streams, exact wire values, and protocol errors.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Stream, Wire, contract, finish, pump, test_support::{chunks, decode_all},
};
use fictionet::stdlib::{bgp, fastcgi, kafka, thrift, zabbix};

fn stack<D>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    contract::check_decode_with_alloc_limit(&make, bytes, 2 * make().capacity());
    contract::check_decode_with_held_limit(&make, bytes, 0);
    let (items, error) = decode_all(&make, bytes);
    assert_eq!(error, None);
    assert_eq!(items, expected);
    let mut stream = Stream::new(make());
    let mut items = Vec::new();
    for chunk in chunks(bytes, &[1, 7, 2, 31]) {
        assert_eq!(pump(&mut stream, chunk, |item| items.push(item)).unwrap(), chunk.len());
    }
    finish(&mut stream, |item| items.push(item)).unwrap();
    assert_eq!(items, expected);
    assert_eq!(stream.offset(), bytes.len() as u64);
}

fn round_trip<D>(make: impl Fn() -> D, values: &[D::Item]) -> Vec<u8>
where
    D: Decode,
    D::Item: Wire + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let mut bytes = Vec::new();
    for value in values {
        contract::check_wire_value(value);
        let encoded = Wire::to_bytes(value).unwrap();
        contract::check_wire::<D::Item>(&encoded);
        assert_eq!(<D::Item as Wire>::parse(&encoded).unwrap(), *value);
        // Exact parsing refuses partial and trailing input.
        for end in 0..encoded.len() {
            assert!(<D::Item as Wire>::parse(encoded.get(..end).unwrap()).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(<D::Item as Wire>::parse(&trailing).is_err());
        value.write(&mut bytes).unwrap();
    }
    stack(&make, &bytes, values);

    // EOF in the final frame is a driver error, delivered once.
    let partial = bytes.get(..bytes.len() - 1).unwrap();
    let mut stream = Stream::new(make());
    let mut items = Vec::new();
    pump(&mut stream, partial, |item| items.push(item)).unwrap();
    assert_eq!(items, values.get(..values.len() - 1).unwrap());
    let unread = stream.buffered();
    assert!(unread > 0);
    let error = Fail::Truncated { unread };
    assert_eq!(
        finish(&mut stream, |_| panic!("partial frame emitted")),
        Err(error.clone())
    );
    assert_eq!(stream.failed(), Some(&error));
    assert!(stream.next().is_none());
    bytes
}

fn rejects<D>(make: impl Fn() -> D, header: &[u8], error: D::Error)
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    contract::check_decode_with_alloc_limit(&make, header, 2 * make().capacity());
    let capacity = make().capacity();
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(header), header.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(error.clone()))));
    assert_eq!(stream.failed(), Some(&Fail::Protocol(error.clone())));
    assert!(stream.next().is_none());
    assert_eq!(stream.push(&[0; 3]), 3);

    // Even an input larger than capacity holds only the named limit.
    let mut oversized = vec![0; capacity + 1];
    oversized
        .get_mut(..header.len())
        .unwrap()
        .copy_from_slice(header);
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(&oversized), capacity);
    assert_eq!(stream.buffered(), capacity);
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(error))));
    assert!(stream.next().is_none());
}

#[test]
fn bgp_chunked_round_trip() {
    let context = bgp::Context::default();
    let good = bgp::Message::Keepalive.to_frame(&context).unwrap();
    let bad = bgp::Frame {
        kind: bgp::kind::KEEPALIVE,
        body: vec![0],
    };
    let bytes = round_trip(|| bgp::Frames, &[good.clone(), bad, good]);
    stack(
        || bgp::Frames.map(|frame| bgp::Message::decode(&frame, &context)),
        &bytes,
        &[
            Ok(bgp::Message::Keepalive),
            Err(bgp::Error::BadMessageLength(20)),
            Ok(bgp::Message::Keepalive),
        ],
    );
}

#[test]
fn fastcgi_chunked_round_trip() {
    let body = fastcgi::BeginRequest {
        role: fastcgi::Role::Responder,
        flags: fastcgi::KEEP_CONN,
    };
    let good = fastcgi::Record::begin_request(7, body);
    let bad = fastcgi::Record {
        kind: fastcgi::kind::BEGIN_REQUEST,
        request_id: 8,
        content: vec![],
        padding: 255,
    };
    let bytes = round_trip(fastcgi::Records::new, &[good.clone(), bad, good]);
    stack(
        || fastcgi::Records::new().map(|record| fastcgi::BeginRequest::parse(&record.content)),
        &bytes,
        &[Ok(body), Err(fastcgi::Error::BodyLength), Ok(body)],
    );
}

#[test]
fn kafka_chunked_round_trip() {
    // ApiVersions v0, correlation ID 1, client ID "x".
    let payload = vec![0, 18, 0, 0, 0, 0, 0, 1, 0, 1, b'x'];
    let request = kafka::Request::parse(&payload).unwrap();
    assert_eq!(request.header.correlation_id, 1);
    assert_eq!(request.header.client_id.as_deref(), Some("x"));
    let good = kafka::Frame(payload);
    let bytes = round_trip(
        kafka::Frames::new,
        &[good.clone(), kafka::Frame(vec![]), good],
    );
    stack(
        || kafka::Frames::new().map(|frame| kafka::Request::parse(&frame.0)),
        &bytes,
        &[
            Ok(request.clone()),
            Err(kafka::Error::Truncated),
            Ok(request),
        ],
    );
}

#[test]
fn thrift_chunked_round_trip() {
    let call = thrift::Message {
        name: "ping".into(),
        kind: thrift::MessageType::Call,
        seq: 7,
        body: vec![],
    };
    for protocol in [
        thrift::Protocol::Binary,
        thrift::Protocol::BinaryOld,
        thrift::Protocol::Compact,
    ] {
        let payload = thrift::EncodedMessage { message: call.clone(), protocol }.to_bytes().unwrap();
        let good = thrift::Frame(payload);
        let bytes = round_trip(
            thrift::Frames::new,
            &[good.clone(), thrift::Frame(vec![]), good],
        );
        stack(
            || thrift::Frames::new().map(|frame| thrift::EncodedMessage::parse(&frame.0)),
            &bytes,
            &[
                Ok(thrift::EncodedMessage { message: call.clone(), protocol }),
                Err(thrift::Error::Truncated),
                Ok(thrift::EncodedMessage { message: call.clone(), protocol }),
            ],
        );
    }
}

#[test]
fn zabbix_chunked_round_trip() {
    let message = zabbix::Message::response(true, Some("processed: 1")).unwrap();
    let good = message.to_packet();
    let mut large = good.clone();
    large.flags |= zabbix::flags::LARGE;
    let bytes = round_trip(zabbix::Packets::new, &[good, large]);
    stack(
        || zabbix::Packets::new().map(|packet| zabbix::Message::parse(&packet.data)),
        &bytes,
        &[Ok(message.clone()), Ok(message)],
    );
    // Compression flags and opaque compressed bytes survive the wire layer.
    round_trip(
        zabbix::Packets::new,
        &[zabbix::Packet {
            flags: zabbix::flags::KNOWN,
            reserved: 64,
            data: vec![0xff, 0, 7],
        }],
    );
    let invalid = zabbix::Packet::new(vec![0xff]);
    let valid = zabbix::Message::response(false, None).unwrap();
    let bytes = round_trip(zabbix::Packets::new, &[invalid, valid.to_packet()]);
    stack(
        || zabbix::Packets::new().map(|packet| zabbix::Message::parse(&packet.data)),
        &bytes,
        &[Err(zabbix::Error::Utf8), Ok(valid)],
    );
}

#[test]
fn bgp_rejects_oversize_at_named_limit() {
    assert_eq!(bgp::Frames.capacity(), bgp::MAX_MESSAGE_LEN);
    let mut header = vec![0xff; bgp::MARKER_LEN];
    let length = u16::try_from(bgp::MAX_MESSAGE_LEN + 1).unwrap();
    header.extend_from_slice(&length.to_be_bytes());
    header.push(bgp::kind::UPDATE);
    rejects(
        || bgp::Frames,
        &header,
        bgp::Error::BadMessageLength(length),
    );
}

#[test]
fn fastcgi_rejects_oversize_at_named_limit() {
    assert_eq!(fastcgi::Records::new().capacity(), fastcgi::MAX_RECORD);
    // The wire fields cannot exceed MAX_RECORD. Use MAX_CONTENT as the
    // configured total record limit to refuse a record that also needs padding.
    let make = || fastcgi::Records::with_limit(fastcgi::MAX_CONTENT);
    assert_eq!(make().capacity(), fastcgi::MAX_CONTENT);
    let header = [
        fastcgi::VERSION,
        fastcgi::kind::STDIN,
        0,
        1,
        0xff,
        0xff,
        0xff,
        0,
    ];
    rejects(
        make,
        &header,
        fastcgi::Error::RecordTooLong {
            length: fastcgi::MAX_RECORD,
            limit: fastcgi::MAX_CONTENT,
        },
    );
    // The largest representable record is accepted at the default capacity.
    let record = fastcgi::Record {
        kind: fastcgi::kind::STDIN,
        request_id: 1,
        content: vec![0; fastcgi::MAX_CONTENT],
        padding: u8::MAX,
    };
    let bytes = Wire::to_bytes(&record).unwrap();
    let mut stream = Stream::new(fastcgi::Records::new());
    assert_eq!(stream.push(&bytes), fastcgi::MAX_RECORD);
    assert_eq!(stream.next(), Some(Ok(record)));
}

#[test]
fn kafka_rejects_oversize_at_named_limit() {
    assert_eq!(
        kafka::Frames::new().capacity(),
        kafka::MAX_FRAME + kafka::SIZE_LEN
    );
    let length = i32::try_from(kafka::MAX_FRAME + 1).unwrap();
    rejects(
        kafka::Frames::new,
        &length.to_be_bytes(),
        kafka::Error::FrameSize(length),
    );
}

#[test]
fn thrift_rejects_oversize_at_named_limit() {
    assert_eq!(
        thrift::Frames::new().capacity(),
        thrift::MAX_FRAME + thrift::FRAME_HEADER_LEN
    );
    let length = i32::try_from(thrift::MAX_FRAME + 1).unwrap();
    rejects(
        thrift::Frames::new,
        &length.to_be_bytes(),
        thrift::Error::FrameLength(length),
    );
}

#[test]
fn zabbix_rejects_oversize_at_named_limit() {
    assert_eq!(
        zabbix::Packets::new().capacity(),
        zabbix::DEFAULT_LIMIT + zabbix::LARGE_HEADER_LEN
    );
    for flags in [
        zabbix::flags::PROTOCOL,
        zabbix::flags::PROTOCOL | zabbix::flags::LARGE,
    ] {
        let len = (zabbix::DEFAULT_LIMIT + 1) as u64;
        let header = zabbix::Header {
            flags,
            data_len: len,
            reserved: 0,
        }
        .to_bytes().unwrap();
        rejects(
            zabbix::Packets::new,
            &header,
            zabbix::Error::TooLarge {
                len,
                limit: zabbix::DEFAULT_LIMIT,
            },
        );
        let header = zabbix::Header {
            flags,
            data_len: 0,
            reserved: len,
        }
        .to_bytes().unwrap();
        rejects(
            zabbix::Packets::new,
            &header,
            zabbix::Error::ReservedTooLarge {
                len,
                limit: zabbix::DEFAULT_LIMIT,
            },
        );
    }
}

fn refuses<M: Wire + PartialEq + Debug>(value: &M) {
    contract::check_wire_value(value);
    let mut destination = vec![1, 2, 3];
    assert!(value.write(&mut destination).is_err());
    assert_eq!(destination, [1, 2, 3]);
}

#[test]
fn strict_writers_are_transactional() {
    refuses(&bgp::Frame {
        kind: 255,
        body: vec![0; bgp::MAX_BODY_LEN + 1],
    });
    let record = fastcgi::Record {
        kind: 255,
        request_id: 1,
        content: vec![0; fastcgi::MAX_CONTENT + 1],
        padding: 255,
    };
    refuses(&record);
    refuses(&kafka::Frame(vec![0; kafka::MAX_FRAME + 1]));
    refuses(&thrift::Frame(vec![0; thrift::MAX_FRAME + 1]));
    let packet = zabbix::Packet {
        flags: 0xff,
        reserved: u64::MAX,
        data: vec![1, 2],
    };
    refuses(&packet);
    refuses(&zabbix::Packet {
        flags: zabbix::flags::PROTOCOL,
        ..packet.clone()
    });
}

#[test]
fn configurable_limits_clamp_and_accept_empty_frames() {
    assert_eq!(thrift::Frames::new().limit(), thrift::MAX_FRAME);
    assert_eq!(thrift::Frames::default().limit(), thrift::MAX_FRAME);
    assert_eq!(
        thrift::Frames::with_limit(usize::MAX).limit(),
        thrift::MAX_FRAME
    );
    stack(
        || thrift::Frames::with_limit(0),
        &[0; thrift::FRAME_HEADER_LEN],
        &[thrift::Frame(vec![])],
    );
    stack(
        || thrift::Frames::with_limit(2),
        &[0, 0, 0, 2, 7, 8],
        &[thrift::Frame(vec![7, 8])],
    );
    rejects(
        || thrift::Frames::with_limit(2),
        &[0, 0, 0, 3],
        thrift::Error::FrameLength(3),
    );
    assert_eq!(
        kafka::Frames::with_limit(usize::MAX).limit(),
        kafka::MAX_FRAME
    );
    assert_eq!(
        fastcgi::Records::with_limit(usize::MAX).limit(),
        fastcgi::MAX_RECORD
    );
    assert_eq!(fastcgi::Records::with_limit(0).limit(), fastcgi::HEADER_LEN);
    assert_eq!(
        zabbix::Packets::with_limit(usize::MAX).limit(),
        zabbix::MAX_DATA
    );
    stack(
        || kafka::Frames::with_limit(0),
        &[0; kafka::SIZE_LEN],
        &[kafka::Frame(vec![])],
    );
    let packet = zabbix::Packet::new(vec![]);
    stack(
        || zabbix::Packets::with_limit(0),
        &packet.to_bytes().unwrap(),
        &[packet],
    );
    let record = fastcgi::Record {
        kind: 255,
        request_id: 0,
        content: vec![],
        padding: 0,
    };
    stack(
        || fastcgi::Records::with_limit(0),
        &record.to_bytes().unwrap(),
        &[record],
    );
}
