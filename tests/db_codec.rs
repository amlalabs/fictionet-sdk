//! Protocol frames and messages through the shared codec driver.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Lcg, Step, Stream, Wire, contract, finish, test_support::decode_all,
};
use fictionet::stdlib::{git_protocol, mongodb, mysql, sftp, tds};

fn round_trip<D>(make: impl Fn() -> D + Copy, expected: &[D::Item])
where
    D: Decode,
    D::Item: Wire + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let mut bytes = Vec::new();
    for value in expected {
        contract::check_wire_value(value);
        let start = bytes.len();
        Wire::write(value, &mut bytes).unwrap();
        contract::check_wire::<D::Item>(bytes.get(start..).unwrap());
    }
    contract::check_decode_with_alloc_limit(make, &bytes, 2 * make().capacity());
    contract::check_decode_with_held_limit(make, &bytes, 0);
    let (got, error) = decode_all(make, &bytes);
    assert_eq!(error, None);
    assert_eq!(got, expected);
}

fn header_refusal<D>(make: impl Fn() -> D + Copy, header: &[u8], error: D::Error)
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    contract::check_decode_with_alloc_limit(make, header, 2 * make().capacity());
    let mut stream = Stream::new(make());
    let prefix = header.len() - 1;
    assert_eq!(stream.push(&header[..prefix]), prefix);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.push(&header[prefix..]), 1);
    let failure = Fail::Protocol(error);
    assert_eq!(stream.next(), Some(Err(failure.clone())));
    assert_eq!(stream.failed(), Some(&failure));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.offset(), 0);
    assert_eq!(stream.held(), 0);
    assert_eq!(stream.unread(), header);
    assert_eq!(stream.push(b"body after failure"), 18);
    assert_eq!(stream.unread(), header);
    stream.end();
    assert_eq!(stream.next(), None);
}

fn eof_at_every_prefix<D>(make: impl Fn() -> D + Copy, value: D::Item)
where
    D: Decode,
    D::Item: Wire + Clone + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let bytes = Wire::to_bytes(&value).unwrap();
    contract::check_decode(make, bytes.get(..bytes.len() - 1).unwrap());
    for cut in 0..=bytes.len() {
        let prefix = bytes.get(..cut).unwrap();
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(prefix), cut);
        stream.end();
        let expected = match cut {
            0 => None,
            n if n == bytes.len() => Some(Ok(value.clone())),
            n => Some(Err(Fail::Truncated { unread: n })),
        };
        assert_eq!(stream.next(), expected, "prefix {cut}");
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.held(), 0);
    }
}

fn exact_wire<M: Wire + PartialEq + Debug>(value: &M) -> Vec<u8> {
    let bytes = Wire::to_bytes(value).unwrap();
    assert_eq!(&M::parse(&bytes).unwrap(), value);
    for cut in 0..bytes.len() {
        assert!(M::parse(bytes.get(..cut).unwrap()).is_err(), "prefix {cut}");
    }
    for tail in [&[0xff][..], bytes.as_slice()] {
        let joined = [bytes.as_slice(), tail].concat();
        assert!(M::parse(&joined).is_err());
    }
    contract::check_wire::<M>(&bytes);
    contract::check_wire_value(value);
    bytes
}

fn refused_write<M: Wire + PartialEq + Debug>(value: &M) {
    let mut out = vec![0x55, 0xaa];
    assert!(value.write(&mut out).is_err());
    assert_eq!(out, [0x55, 0xaa]);
    contract::check_wire_value(value);
}

fn mongo_ping() -> mongodb::Message {
    mongodb::Message {
        request_id: 7,
        response_to: 0,
        body: mongodb::Body::Msg(mongodb::Msg::new(
            mongodb::Document::new()
                .with("ping", mongodb::Bson::Int32(1))
                .with("$db", mongodb::Bson::String("admin".into())),
        )),
    }
}

#[test]
fn mongodb_chunked_round_trip() {
    use mongodb::{Body, Bson, Compressed, Document, Message, Msg, Query, Reply, Sequence, flag};
    let mut command = Msg::new(Document::new().with("insert", Bson::String("notes".into())));
    command.flags = flag::CHECKSUM_PRESENT;
    command.sequences.push(Sequence {
        identifier: "documents".into(),
        documents: vec![Document::new().with("text", Bson::String("hello".into()))],
    });
    let values = [
        mongo_ping(),
        Message {
            request_id: 8,
            response_to: 0,
            body: Body::Msg(command),
        },
        Message {
            request_id: 9,
            response_to: 0,
            body: Body::Query(Query {
                flags: 4,
                collection: "admin.$cmd".into(),
                number_to_skip: 0,
                number_to_return: -1,
                query: Document::new().with("hello", Bson::Int32(1)),
                fields: Some(Document::new()),
            }),
        },
        Message {
            request_id: 10,
            response_to: 9,
            body: Body::Reply(Reply::new(vec![
                Document::new().with("ok", Bson::Double(1.0)),
            ])),
        },
        Message {
            request_id: 11,
            response_to: 0,
            body: Body::Compressed(Compressed {
                original_op_code: mongodb::op_code::MSG,
                uncompressed_size: 3,
                compressor: mongodb::compressor::NOOP,
                data: vec![0, 0xff, 3],
            }),
        },
        Message {
            request_id: -1,
            response_to: i32::MIN,
            body: Body::Other {
                op_code: -1,
                data: vec![],
            },
        },
    ];
    round_trip(
        || mongodb::Messages::with_limit(128).map(Result::unwrap),
        &values,
    );
}

#[test]
fn mongodb_refuses_length_from_header() {
    header_refusal(
        || mongodb::Messages::with_limit(32),
        &33i32.to_le_bytes(),
        mongodb::Error::Length(33),
    );
    let length = mongodb::MAX_MESSAGE_SIZE as i32 + 1;
    header_refusal(
        mongodb::Messages::new,
        &length.to_le_bytes(),
        mongodb::Error::Length(length),
    );
}

#[test]
fn mongodb_truncated_frame_at_eof() {
    eof_at_every_prefix(|| mongodb::Messages::new().map(Result::unwrap), mongo_ping());
}

#[test]
fn mongodb_wire_is_exact_and_transactional() {
    let value = mongo_ping();
    let bytes = exact_wire(&value);
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(
        <mongodb::Message as Wire>::parse(&joined),
        Err(mongodb::Error::Trailing)
    );
    let mongodb::Body::Msg(mut msg) = value.body else {
        panic!("expected OP_MSG")
    };
    msg.flags = 1 << 20;
    refused_write(&mongodb::Message {
        request_id: 1,
        response_to: 0,
        body: mongodb::Body::Msg(msg),
    });
    let mut invalid = mongo_ping();
    invalid.body = mongodb::Body::Query(mongodb::Query {
        flags: 0,
        collection: "bad\0name".into(),
        number_to_skip: 0,
        number_to_return: 1,
        query: mongodb::Document::new(),
        fields: None,
    });
    refused_write(&invalid);
    refused_write(&mongodb::Message {
        request_id: 1,
        response_to: 0,
        body: mongodb::Body::Other {
            op_code: mongodb::op_code::MSG,
            data: vec![],
        },
    });
}

#[test]
fn mongodb_body_recovery_and_terminal_failure() {
    let good = mongo_ping();
    let mut bad = 20i32.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0; 8]);
    bad.extend_from_slice(&mongodb::op_code::MSG.to_le_bytes());
    bad.extend_from_slice(&[0; 4]); // No body section.
    let mut input = bad.clone();
    Wire::write(&good, &mut input).unwrap();
    contract::check_decode(mongodb::Messages::new, &input);

    let mut stream = Stream::new(mongodb::Messages::new());
    assert_eq!(stream.push(&input), input.len());
    assert_eq!(
        stream.next(),
        Some(Ok(Err(mongodb::Error::BodyCount(0))))
    );
    assert!(stream.failed().is_none());
    assert_eq!(stream.offset(), bad.len() as u64);
    assert_eq!(stream.unread(), &input[bad.len()..]);
    assert_eq!(stream.next(), Some(Ok(Ok(good.clone()))));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.buffered(), 0);
    assert_eq!(stream.offset(), input.len() as u64);

    assert_eq!(stream.push(&0i32.to_le_bytes()), 4);
    let failure = Fail::Protocol(mongodb::Error::Length(0));
    assert_eq!(stream.next(), Some(Err(failure.clone())));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.failed(), Some(&failure));
    assert_eq!(stream.push(&input), input.len());
    assert_eq!(stream.unread(), [0; 4]);
}

#[test]
fn mongodb_unknown_section_kind_ends_stream() {
    let mut bad = 21i32.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0; 8]);
    bad.extend_from_slice(&mongodb::op_code::MSG.to_le_bytes());
    bad.extend_from_slice(&[0; 4]);
    bad.push(2);
    header_refusal(
        mongodb::Messages::new,
        &bad,
        mongodb::Error::SectionKind(2),
    );
}

#[test]
fn mysql_chunked_round_trip() {
    round_trip(
        || mysql::Packets::with_limit(32),
        &[
            mysql::Packet {
                seq: 0,
                payload: b"\x03SELECT 1".to_vec(),
            },
            mysql::Packet {
                seq: 255,
                payload: vec![],
            },
            mysql::Packet {
                seq: 0,
                payload: vec![0xff, 0, 7, 0x80],
            },
            mysql::Packet {
                seq: 19,
                payload: vec![0xa5; 32],
            },
        ],
    );
}

#[test]
fn mysql_refuses_length_from_header() {
    header_refusal(
        || mysql::Packets::with_limit(8),
        &[9, 0, 0, 7],
        mysql::Error::TooLong(9),
    );
    header_refusal(
        || mysql::Packets::with_limit(0),
        &[1, 0, 0, 0],
        mysql::Error::TooLong(1),
    );
}

#[test]
fn mysql_truncated_frame_at_eof() {
    eof_at_every_prefix(
        mysql::Packets::new,
        mysql::Packet {
            seq: 255,
            payload: b"hello".to_vec(),
        },
    );
}

#[test]
fn mysql_wire_is_exact_and_transactional() {
    let value = mysql::Packet {
        seq: 7,
        payload: vec![0, 1, 2],
    };
    let bytes = exact_wire(&value);
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(
        <mysql::Packet as Wire>::parse(&joined),
        Err(mysql::Error::Trailing)
    );
    refused_write(&mysql::Packet {
        seq: 7,
        payload: vec![0; mysql::MAX_PACKET_PAYLOAD + 1],
    });
    let mut empty = mysql::Packets::with_limit(0);
    assert_eq!(
        empty.decode(&[0, 0, 0, 255], false),
        Ok(Step::Item(
            mysql::Packet {
                seq: 255,
                payload: vec![]
            },
            4
        ))
    );
}

#[test]
fn mysql_full_packet_and_message_assembly() {
    // A full physical packet requires a separate empty message terminator.
    let full = mysql::Packet {
        seq: 255,
        payload: vec![0x42; mysql::MAX_PACKET_PAYLOAD],
    };
    let bytes = Wire::to_bytes(&full).unwrap();
    assert_eq!(bytes.len(), mysql::MAX_FRAME);
    assert_eq!(<mysql::Packet as Wire>::parse(&bytes), Ok(full.clone()));
    let mut stream = Stream::new(mysql::Packets::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(full.clone())));
    finish(&mut stream, |_| panic!("extra frame")).unwrap();

    let mut stream = Stream::new(mysql::Messages::with_limit(mysql::MAX_PACKET_PAYLOAD));
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), None);
    assert_eq!(stream.held(), mysql::MAX_PACKET_PAYLOAD);
    assert_eq!(stream.push(&[0, 0, 0, 0]), 4);
    assert_eq!(stream.next(), Some(Ok(mysql::Message { seq: 255, payload: full.payload })));
    assert_eq!(stream.held(), 0);
    header_refusal(|| mysql::Messages::with_limit(0), &[1, 0, 0, 0], mysql::Error::TooLong(1));
}

fn tds_packet() -> tds::Packet {
    tds::Packet {
        packet_type: tds::packet_type::SQL_BATCH,
        status: tds::status::EOM,
        spid: 0x1234,
        id: 255,
        window: 0x80,
        data: vec![0, 0xff, 7, 8, 9],
    }
}

#[test]
fn tds_chunked_round_trip() {
    round_trip(
        || tds::Packets::with_limit(32),
        &[
            tds_packet(),
            tds::Packet {
                status: 0,
                id: 0,
                data: vec![],
                ..tds_packet()
            },
            tds::Packet {
                packet_type: 0xff,
                status: 0xff,
                id: 1,
                data: vec![0x42; 24],
                ..tds_packet()
            },
        ],
    );
}

#[test]
fn tds_refuses_length_from_header() {
    header_refusal(
        || tds::Packets::with_limit(16),
        &[1, 0, 0, 17],
        tds::Error::TooLong(17),
    );
    header_refusal(tds::Packets::new, &[1, 0, 0, 7], tds::Error::Length(7));
}

#[test]
fn tds_truncated_frame_at_eof() {
    eof_at_every_prefix(tds::Packets::new, tds_packet());
}

#[test]
fn tds_wire_is_exact_and_transactional() {
    let value = tds_packet();
    let bytes = exact_wire(&value);
    assert_eq!(bytes, value.to_bytes().unwrap());
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(
        <tds::Packet as Wire>::parse(&joined),
        Err(tds::Error::Trailing)
    );
    let large = tds::Packet {
        data: vec![0; tds::MAX_PACKET - tds::HEADER_LEN + 1],
        ..tds_packet()
    };
    refused_write(&large);
    let maximum = tds::Packet {
        data: vec![0; tds::MAX_PACKET - tds::HEADER_LEN],
        ..tds_packet()
    };
    contract::check_wire_value(&maximum);
    assert_eq!(Wire::to_bytes(&maximum).unwrap().len(), tds::MAX_PACKET);
}

#[test]
fn tds_message_assembly_and_terminal_failure() {
    let first = tds::Packet {
        status: tds::status::RESET_CONNECTION,
        data: b"abc".to_vec(),
        ..tds_packet()
    };
    let last = tds::Packet {
        spid: 9,
        data: b"def".to_vec(),
        ..tds_packet()
    };
    let mut stream = Stream::new(tds::Messages::with_limit(6));
    assert_eq!(stream.push(&first.to_bytes().unwrap()), 11);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.held(), 3);
    assert_eq!(stream.push(&last.to_bytes().unwrap()), 11);
    assert_eq!(stream.next(), Some(Ok(tds::Message {
        packet_type: first.packet_type, status: first.status | last.status,
        spid: first.spid, data: b"abcdef".to_vec(),
    })));
    assert_eq!(stream.held(), 0);
    header_refusal(|| tds::Messages::with_limit(6), &[1, 0, 0, 7], tds::Error::Length(7));
}

#[test]
fn git_chunked_round_trip() {
    use git_protocol::Packet;
    round_trip(
        git_protocol::Packets::new,
        &[
            Packet::Data(b"command=ls-refs\n".to_vec()),
            Packet::Delim,
            Packet::Data(vec![]),
            Packet::Data(vec![0, 0xff, 7]),
            Packet::Flush,
            Packet::ResponseEnd,
            Packet::Data(b"next request\n".to_vec()),
        ],
    );
}

#[test]
fn git_refuses_length_from_header() {
    header_refusal(
        git_protocol::Packets::new,
        b"fff1",
        git_protocol::Error::PacketTooLong(65521),
    );
    header_refusal(
        git_protocol::Packets::new,
        b"0003",
        git_protocol::Error::Reserved,
    );
    header_refusal(
        git_protocol::Packets::new,
        b"g",
        git_protocol::Error::Header,
    );
}

#[test]
fn git_truncated_frame_at_eof() {
    eof_at_every_prefix(
        git_protocol::Packets::new,
        git_protocol::Packet::Data(b"hello\n".to_vec()),
    );
}

#[test]
fn git_wire_is_exact_and_transactional() {
    use git_protocol::Packet;
    for value in [
        Packet::Flush,
        Packet::Delim,
        Packet::ResponseEnd,
        Packet::Data(vec![]),
        Packet::Data(vec![1; 10]),
    ] {
        let bytes = exact_wire(&value);
        assert_eq!(bytes, value.to_bytes().unwrap());
        let joined = [bytes.as_slice(), b"0000"].concat();
        assert_eq!(
            <Packet as Wire>::parse(&joined),
            Err(git_protocol::Error::Trailing)
        );
    }
    let upper = b"000Aabcdef";
    contract::check_wire::<Packet>(upper);
    assert_eq!(
        Wire::to_bytes(&<Packet as Wire>::parse(upper).unwrap()).unwrap(),
        b"000aabcdef"
    );
    let large = Packet::Data(vec![0; git_protocol::MAX_DATA + 1]);
    refused_write(&large);
    contract::check_wire_value(&Packet::Data(vec![0; git_protocol::MAX_DATA]));
}

#[test]
fn git_read_ahead_handoff_and_terminal_failure() {
    let bytes = b"0000".repeat(git_protocol::MAX_PACKET / 4 + 1);
    let mut stream = Stream::new(git_protocol::Packets::new());
    assert_eq!(stream.push(&bytes), git_protocol::MAX_PACKET);
    assert_eq!(stream.push(b"0000"), 0);
    assert_eq!(stream.next(), Some(Ok(git_protocol::Packet::Flush)));
    let (buffer, _) = stream.into_parts();
    assert_eq!(buffer.unread(), &bytes[4..git_protocol::MAX_PACKET]);
    let mut stream = Stream::new(git_protocol::Packets::new());
    assert_eq!(stream.push(b"0003PACK"), 8);
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(git_protocol::Error::Reserved))));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.push(b"discarded"), 9);
    assert_eq!(stream.unread(), b"0003PACK");
}

fn sftp_packet() -> sftp::Packet {
    sftp::Request::Stat {
        id: 7,
        path: b"/motd".to_vec(),
    }
    .to_packet().unwrap()
}

#[test]
fn sftp_chunked_round_trip() {
    round_trip(
        || sftp::Packets::with_limit(64),
        &[
            sftp::Request::Init {
                version: sftp::VERSION,
                extensions: vec![],
            }
            .to_packet().unwrap(),
            sftp_packet(),
            sftp::Response::status(7, sftp::Status::NoSuchFile, "No such file").to_packet().unwrap(),
            sftp::Packet {
                kind: 0xff,
                body: vec![],
            },
            sftp::Packet {
                kind: 0,
                body: vec![0xff; 63],
            },
        ],
    );
}

#[test]
fn sftp_refuses_length_from_header() {
    header_refusal(
        || sftp::Packets::with_limit(8),
        &9u32.to_be_bytes(),
        sftp::Error::PacketTooLong(9),
    );
    header_refusal(
        sftp::Packets::new,
        &u32::MAX.to_be_bytes(),
        sftp::Error::PacketTooLong(u32::MAX),
    );
    header_refusal(
        || sftp::Packets::with_limit(0),
        &1u32.to_be_bytes(),
        sftp::Error::PacketTooLong(1),
    );
    header_refusal(sftp::Packets::new, &[0; 4], sftp::Error::Empty);
}

#[test]
fn sftp_truncated_frame_at_eof() {
    eof_at_every_prefix(sftp::Packets::new, sftp_packet());
}

#[test]
fn sftp_wire_is_exact_and_transactional() {
    let value = sftp_packet();
    let bytes = exact_wire(&value);
    assert_eq!(bytes, value.to_bytes().unwrap());
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(
        <sftp::Packet as Wire>::parse(&joined),
        Err(sftp::Error::PacketTrailing)
    );
    let large = sftp::Packet {
        kind: 0xff,
        body: vec![0; sftp::MAX_PACKET],
    };
    refused_write(&large);
    contract::check_wire_value(&sftp::Packet {
        kind: 0xff,
        body: vec![0; sftp::MAX_PACKET - 1],
    });
    exact_wire(&sftp::Packet {
        kind: 0,
        body: vec![],
    });
}

#[test]
fn sftp_limits_and_terminal_failure() {
    let mut stream = Stream::new(sftp::Packets::with_limit(0));
    assert_eq!(stream.push(&[0, 0, 0, 1, 1]), 4);
    assert_eq!(stream.push(&[1]), 0);
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(sftp::Error::PacketTooLong(1)))));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.push(&[1; 9]), 9);
    assert_eq!(stream.unread(), [0, 0, 0, 1]);
}

#[test]
fn capacities_are_named_and_clamped() {
    assert_eq!(mongodb::Messages::new(), mongodb::Messages::default());
    assert_eq!(mysql::Packets::new(), mysql::Packets::default());
    assert_eq!(tds::Packets::new(), tds::Packets::default());
    assert_eq!(sftp::Packets::new(), sftp::Packets::default());
    assert_eq!(
        git_protocol::Packets::new().capacity(),
        git_protocol::MAX_PACKET
    );
    assert_eq!(mysql::Packets::new().capacity(), mysql::MAX_FRAME);
    assert_eq!(sftp::Packets::new().capacity(), sftp::MAX_FRAME);
    for limit in [0, 1, 16, 4096, usize::MAX] {
        let mongo = mongodb::Messages::with_limit(limit);
        assert_eq!(
            mongo.limit(),
            limit.clamp(mongodb::HEADER_LEN, mongodb::MAX_MESSAGE_SIZE)
        );
        assert_eq!(mongo.capacity(), mongo.limit());
        let mysql = mysql::Packets::with_limit(limit);
        assert_eq!(mysql.limit(), limit.min(mysql::MAX_PACKET_PAYLOAD));
        assert_eq!(mysql.capacity(), mysql::HEADER_LEN + mysql.limit());
        let tds = tds::Packets::with_limit(limit);
        assert_eq!(tds.limit(), limit.clamp(tds::HEADER_LEN, tds::MAX_PACKET));
        assert_eq!(tds.capacity(), tds.limit());
        let sftp = sftp::Packets::with_limit(limit);
        assert_eq!(sftp.limit(), limit.min(sftp::MAX_PACKET));
        assert_eq!(sftp.capacity(), sftp::LENGTH_LEN + sftp.limit());
    }
}

#[test]
fn arbitrary_bytes_obey_decoder_and_wire_contracts() {
    let mut rng = Lcg::new(0x1234_5678);
    for size in [0, 1, 3, 4, 7, 8, 16, 31, 64, 257] {
        let mut data = vec![0; size];
        rng.fill(&mut data);
        contract::check_decode_with_alloc_limit(mongodb::Messages::new, &data, 2 * mongodb::MAX_MESSAGE_SIZE);
        contract::check_decode_with_alloc_limit(mysql::Packets::new, &data, 2 * mysql::MAX_FRAME);
        contract::check_decode_with_alloc_limit(tds::Packets::new, &data, 2 * tds::MAX_PACKET);
        contract::check_decode_with_alloc_limit(git_protocol::Packets::new, &data, 2 * git_protocol::MAX_PACKET);
        contract::check_decode_with_alloc_limit(sftp::Packets::new, &data, 2 * sftp::MAX_FRAME);
        contract::check_wire::<mongodb::Message>(&data);
        contract::check_wire::<mysql::Packet>(&data);
        contract::check_wire::<tds::Packet>(&data);
        contract::check_wire::<git_protocol::Packet>(&data);
        contract::check_wire::<sftp::Packet>(&data);
    }
}

fn bytewise_frame<D>(make: impl Fn() -> D + Copy, value: D::Item)
where
    D: Decode,
    D::Item: Wire + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let bytes = value.to_bytes().unwrap();
    contract::check_decode_with_alloc_limit(make, &bytes, 2 * make().capacity());
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.with_next(|item, raw, span| {
        assert_eq!(raw, bytes);
        assert_eq!(span, 0..bytes.len() as u64);
        item
    }), Some(Ok(value)));
    finish(&mut stream, |_| panic!("extra frame")).unwrap();
}

#[test]
fn large_frames_arrive_one_byte_at_a_time() {
    const PAYLOAD: usize = 64 * 1024;
    bytewise_frame(
        || mongodb::Messages::with_limit(mongodb::HEADER_LEN + PAYLOAD).map(Result::unwrap),
        mongodb::Message {
            request_id: 1,
            response_to: 0,
            body: mongodb::Body::Other {
                op_code: -1,
                data: vec![0xa5; PAYLOAD],
            },
        },
    );
    bytewise_frame(
        || mysql::Packets::with_limit(PAYLOAD),
        mysql::Packet {
            seq: 255,
            payload: vec![0xa5; PAYLOAD],
        },
    );
    bytewise_frame(
        tds::Packets::new,
        tds::Packet {
            data: vec![0xa5; tds::MAX_PACKET - tds::HEADER_LEN],
            ..tds_packet()
        },
    );
    bytewise_frame(
        git_protocol::Packets::new,
        git_protocol::Packet::Data(vec![0xa5; git_protocol::MAX_DATA]),
    );
    bytewise_frame(
        sftp::Packets::new,
        sftp::Packet {
            kind: 0xff,
            body: vec![0xa5; sftp::MAX_PACKET - 1],
        },
    );
}

#[test]
fn mongodb_wire_size_limit() {
    let mut value = mongodb::Message {
        request_id: 1,
        response_to: 0,
        body: mongodb::Body::Other {
            op_code: -1,
            data: vec![0; mongodb::MAX_MESSAGE_SIZE - mongodb::HEADER_LEN],
        },
    };
    let bytes = Wire::to_bytes(&value).unwrap();
    assert_eq!(bytes.len(), mongodb::MAX_MESSAGE_SIZE);
    assert_eq!(<mongodb::Message as Wire>::parse(&bytes), Ok(value.clone()));
    let mongodb::Body::Other { data, .. } = &mut value.body else {
        panic!("expected raw body")
    };
    data.push(0);
    refused_write(&value);
}

#[test]
fn mongodb_writers_refuse_invalid_large_bodies() {
    // Invalid flags and duplicate keys both refuse oversized bodies
    // without changing the destination.
    let mut value = mongodb::Message {
        request_id: 0,
        response_to: 0,
        body: mongodb::Body::Msg(mongodb::Msg::new(mongodb::Document(vec![
            (
                String::new(),
                mongodb::Bson::Null
            );
            mongodb::MAX_ELEMENTS
                + 1
        ]))),
    };
    for flags in [0, 1 << 20] {
        let error = mongodb::Error::Unwritable;
        let mongodb::Body::Msg(msg) = &mut value.body else {
            panic!("expected OP_MSG")
        };
        msg.flags = flags;
        let mut out = vec![0x55];
        assert_eq!(value.to_bytes(), Err(error));
        assert_eq!(value.write(&mut out), Err(error));
        assert_eq!(out, [0x55]);
    }
}

#[test]
fn payload_readers_refuse_trailing_bytes() {
    let document = mongodb::Document::new();
    assert_eq!(mongodb::Document::parse(&[document.to_bytes().unwrap(), vec![0]].concat()),
        Err(mongodb::Error::BsonTrailing));
    let header = mongodb::Header { length: 16, request_id: 1, response_to: 0, op_code: -1 };
    assert_eq!(mongodb::Header::parse(&[header.to_bytes().unwrap(), vec![0]].concat()),
        Err(mongodb::Error::Trailing));
    let handshake = mysql::Handshake { auth_data: vec![1; 21], capabilities: mysql::capability::PLUGIN_AUTH,
        ..mysql::Handshake::default() };
    let response = mysql::HandshakeResponse {
        capabilities: mysql::capability::PROTOCOL_41, ..mysql::HandshakeResponse::default()
    };
    let mut bytes = handshake.to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(mysql::Handshake::parse(&bytes), Err(mysql::Error::Trailing));
    let mut bytes = response.to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(mysql::HandshakeResponse::parse(&bytes), Err(mysql::Error::Trailing));
    let column = mysql::Column::new(b"a", mysql::column_type::LONG);
    let mut bytes = column.to_bytes().unwrap();
    // COM_FIELD_LIST appends a length-encoded default after the fixed fields.
    bytes.extend_from_slice(&[1, b'0']);
    assert_eq!(mysql::Column::parse(&bytes), Err(mysql::Error::Trailing));
    let mut reader = mysql::ResultReader::new(mysql::capability::PROTOCOL_41);
    assert_eq!(reader.push(&[1]), Ok(mysql::ResultEvent::ColumnCount(1)));
    assert_eq!(reader.push(&bytes), Err(mysql::Error::Trailing));
    assert_eq!(reader.push(&column.to_bytes().unwrap()), Ok(mysql::ResultEvent::Column(column)));
    let mut bytes = tds::Prelogin::new(tds::Version::default(), tds::encryption::OFF).to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(tds::Prelogin::parse(&bytes), Err(tds::Error::Invalid("bytes after PRELOGIN")));
    let mut bytes = tds::Login7::new().to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(tds::Login7::parse(&bytes), Err(tds::Error::Invalid("bytes after LOGIN7")));
}

#[test]
fn mysql_writers_preserve_flags_and_optional_fields() {
    use mysql::{Error, HandshakeResponse, OkPacket, capability};
    refused_write(&HandshakeResponse::default());
    for capabilities in [0, capability::SSL, capability::PROTOCOL_41] {
        refused_write(&mysql::SslRequest { capabilities, ..mysql::SslRequest::default() });
    }
    refused_write(&mysql::Handshake { auth_data: vec![1; 21], auth_plugin: b"plugin".to_vec(),
        ..mysql::Handshake::default() });
    let base = HandshakeResponse { capabilities: capability::PROTOCOL_41, ..HandshakeResponse::default() };
    for response in [
        HandshakeResponse { database: b"db".to_vec(), ..base.clone() },
        HandshakeResponse { auth_plugin: b"plugin".to_vec(), ..base.clone() },
        HandshakeResponse { attributes: vec![(b"key".to_vec(), vec![])], ..base.clone() },
        HandshakeResponse { zstd_level: 3, ..base },
    ] { refused_write(&response); }
    for ok in [
        OkPacket { status: 1, ..OkPacket::default() },
        OkPacket { warnings: 1, ..OkPacket::default() },
        OkPacket { session_state: vec![1], ..OkPacket::default() },
    ] { assert_eq!(ok.message(0, 0), Err(Error::Unwritable)); }
    assert_eq!(mysql::Eof { status: 1, warnings: 0 }.message(0, 0), Err(Error::Unwritable));
    assert_eq!(mysql::ErrPacket::new(1, b"HY000", b"error").message(0, 0), Err(Error::Unwritable));
}

#[test]
fn tds_payload_limits_and_complete_messages() {
    let oversized = vec![0; tds::MAX_MESSAGE + 1];
    assert_eq!(tds::SqlBatch::parse(&oversized, false), Err(tds::Error::Limit("SQL batch data")));
    let mut tokens = tds::TokenReader::new(&oversized);
    assert_eq!(tokens.next(), Some(Err(tds::Error::Limit("response past MAX_MESSAGE"))));
    assert_eq!(tokens.next(), None);
    refused_write(&tds::Message { packet_type: 1, status: 0, spid: 0, data: vec![] });
    refused_write(&tds::Login7 { features: Some(vec![]), ..tds::Login7::new() });
    refused_write(&tds::Login7 { option_flags3: tds::option_flags3::EXTENSION, ..tds::Login7::new() });
    let oversized_batch = tds::SqlBatch { headers: None, text: "x".repeat(tds::MAX_MESSAGE / 2 + 1) };
    assert_eq!(oversized_batch.message(), Err(tds::Error::Unwritable));
}
