//! Bounded frame streams, exact wire values, and compatibility behavior.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Stream, Wire, contract, finish, pump, test_support::chunks,
};
use fictionet::stdlib::{bgp, fastcgi, kafka, thrift, zabbix};

fn stack<D>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    contract::check_stack(&make, bytes);
    for pattern in [&[][..], &[1][..], &[3, 1, 37][..], &[64][..]] {
        let mut stream = Stream::new(make());
        let capacity = make().capacity();
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
{
    let mut bytes = Vec::new();
    for value in values {
        contract::check_wire_value(value);
        let encoded = Wire::to_bytes(value).unwrap();
        contract::check_wire::<D::Item>(&encoded);
        assert_eq!(<D::Item as Wire>::parse(&encoded).unwrap(), *value);
        // Wire is exact, while the inherent parsers retain prefix semantics.
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
    contract::check_decode(&make, header);
    let capacity = make().capacity();
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(header), header.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(error.clone()))));
    assert_eq!(stream.failed(), Some(&Fail::Protocol(error.clone())));
    assert!(stream.next().is_none());
    assert_eq!(stream.push(&[0; 3]), 3);

    // Even a feed larger than the capacity holds only the named limit.
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
    let bytes = round_trip(fastcgi::Frames::new, &[good.clone(), bad, good]);
    stack(
        || fastcgi::Frames::new().map(|record| fastcgi::BeginRequest::parse(&record.content)),
        &bytes,
        &[Ok(body), Err(fastcgi::BodyError), Ok(body)],
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
        let payload = call.to_bytes(protocol).unwrap();
        let size = payload.len();
        let good = thrift::Frame(payload);
        let bytes = round_trip(
            thrift::Frames::new,
            &[good.clone(), thrift::Frame(vec![]), good],
        );
        stack(
            || thrift::Frames::new().map(|frame| thrift::Message::parse(&frame.0)),
            &bytes,
            &[
                Ok((call.clone(), protocol, size)),
                Err(thrift::Error::Truncated),
                Ok((call.clone(), protocol, size)),
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
    let bytes = round_trip(zabbix::Frames::new, &[good, large]);
    stack(
        || zabbix::Frames::new().map(|packet| zabbix::Message::parse(&packet.data)),
        &bytes,
        &[Ok(message.clone()), Ok(message)],
    );
    // Compression flags and opaque compressed bytes survive the wire layer.
    round_trip(
        zabbix::Frames::new,
        &[zabbix::Packet {
            flags: zabbix::flags::KNOWN,
            reserved: 64,
            data: vec![0xff, 0, 7],
        }],
    );
    let invalid = zabbix::Packet::new(vec![0xff]);
    let valid = zabbix::Message::response(false, None).unwrap();
    let bytes = round_trip(zabbix::Frames::new, &[invalid, valid.to_packet()]);
    stack(
        || zabbix::Frames::new().map(|packet| zabbix::Message::parse(&packet.data)),
        &bytes,
        &[Err(zabbix::MessageError::Utf8), Ok(valid)],
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
    assert_eq!(fastcgi::Frames::new().capacity(), fastcgi::MAX_RECORD);
    // The wire fields cannot exceed MAX_RECORD. Use MAX_CONTENT as the
    // configured total record limit to refuse a record that also needs padding.
    let make = || fastcgi::Frames::with_limit(fastcgi::MAX_CONTENT);
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
        fastcgi::FrameError::TooLong {
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
    let mut stream = Stream::new(fastcgi::Frames::new());
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
        thrift::FrameError::Length(length),
    );
}

#[test]
fn zabbix_rejects_oversize_at_named_limit() {
    assert_eq!(
        zabbix::Frames::new().capacity(),
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
        .to_bytes();
        rejects(
            zabbix::Frames::new,
            &header,
            zabbix::PacketError::TooLarge {
                len,
                limit: zabbix::DEFAULT_LIMIT,
            },
        );
        let header = zabbix::Header {
            flags,
            data_len: 0,
            reserved: len,
        }
        .to_bytes();
        rejects(
            zabbix::Frames::new,
            &header,
            zabbix::PacketError::ReservedTooLarge {
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
fn strict_writers_are_transactional_and_old_writers_keep_their_meaning() {
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
    assert_eq!(
        fastcgi::Record::parse(&record.to_bytes())
            .unwrap()
            .unwrap()
            .0
            .content
            .len(),
        fastcgi::MAX_CONTENT
    );
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
    let normalized = zabbix::Packet::parse(&packet.to_bytes())
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(normalized.flags, zabbix::flags::KNOWN);
    assert_eq!(normalized.reserved, zabbix::MAX_DATA as u64);
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
        thrift::FrameError::Length(3),
    );
    assert_eq!(
        kafka::Frames::with_limit(usize::MAX).limit(),
        kafka::MAX_FRAME
    );
    assert_eq!(
        fastcgi::Frames::with_limit(usize::MAX).limit(),
        fastcgi::MAX_RECORD
    );
    assert_eq!(fastcgi::Frames::with_limit(0).limit(), fastcgi::HEADER_LEN);
    assert_eq!(
        zabbix::Frames::with_limit(usize::MAX).limit(),
        zabbix::MAX_DATA
    );
    stack(
        || kafka::Frames::with_limit(0),
        &[0; kafka::SIZE_LEN],
        &[kafka::Frame(vec![])],
    );
    let packet = zabbix::Packet::new(vec![]);
    stack(
        || zabbix::Frames::with_limit(0),
        &packet.to_bytes(),
        &[packet],
    );
    let record = fastcgi::Record {
        kind: 255,
        request_id: 0,
        content: vec![],
        padding: 0,
    };
    stack(
        || fastcgi::Frames::with_limit(0),
        &record.to_bytes(),
        &[record],
    );
}

#[test]
#[allow(deprecated)] // Check the original buffering and repeated errors.
fn compatibility_decoders_keep_buffering_and_error_timing() {
    let mut kafka = kafka::Decoder::with_limit(0);
    kafka.feed(&[0; 40]);
    assert_eq!(kafka.buffered(), 40);
    for _ in 0..10 {
        assert_eq!(kafka.next_frame(), Some(Ok(vec![])));
    }
    kafka.feed(&[0xff; 4]);
    assert_eq!(kafka.buffered(), 0); // Kafka checks the first header in feed.
    for _ in 0..2 {
        assert_eq!(kafka.next_frame(), Some(Err(kafka::Error::FrameSize(-1))));
    }
    let mut thrift = thrift::Decoder::new();
    thrift.feed(&[0xff; 4]);
    assert_eq!(thrift.buffered(), 4); // Thrift checks it only when pulled.
    for _ in 0..2 {
        assert_eq!(
            thrift.next_frame(),
            Some(Err(thrift::FrameError::Length(-1)))
        );
    }
    let mut zabbix = zabbix::Decoder::with_limit(0);
    let empty = zabbix::Packet::new(vec![]).to_bytes();
    zabbix.feed(&empty.repeat(3));
    assert_eq!(zabbix.buffered(), 3 * empty.len());
    let mut bgp = bgp::Decoder::new();
    assert_eq!(bgp.feed(&vec![0; bgp::MAX_BUFFERED + 1]), bgp::MAX_BUFFERED);
    for _ in 0..2 {
        assert_eq!(
            bgp.next_frame(),
            Some(Err(bgp::Error::ConnectionNotSynchronized))
        );
    }
    let mut fastcgi = fastcgi::Decoder::new();
    fastcgi.feed(&vec![0; fastcgi::MAX_BUFFERED + 1]);
    for _ in 0..2 {
        assert_eq!(
            fastcgi.next_record(),
            Some(Err(fastcgi::RecordError::TooLong))
        );
    }
}
