//! Counted-feed protocol frames through the shared codec driver.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Step, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, chunks},
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
    contract::check_decode(make, &bytes);
    contract::check_decode_with_held_limit(make, &bytes, 0);

    // Split inside headers and bodies, and carry several frames in one chunk.
    for pattern in [&[][..], &[1], &[3, 1, 2, 37], &[7, 19, 1, 256]] {
        let capacity = make().capacity();
        let mut stream = Stream::new(make());
        let mut got = Vec::new();
        for part in chunks(&bytes, pattern) {
            assert_eq!(
                pump(&mut stream, part, |item| got.push(item)),
                Ok(part.len())
            );
            assert!(stream.buffered() <= capacity);
            assert_eq!(stream.held(), 0);
        }
        finish(&mut stream, |item| got.push(item)).unwrap();
        assert_eq!(got, expected);
        assert_eq!(stream.offset(), bytes.len() as u64);
        assert_eq!(stream.buffered(), 0);
        assert!(stream.is_done());
        assert!(stream.failed().is_none());
        assert_eq!(stream.next(), None);
    }
}

fn header_refusal<D>(make: impl Fn() -> D + Copy, header: &[u8], error: D::Error)
where
    D: Decode,
    D::Item: PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    contract::check_decode(make, header);
    let mut stream = Stream::new(make());
    for (i, byte) in header.iter().enumerate() {
        assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
        if i + 1 < header.len() {
            assert_eq!(stream.next(), None);
        }
    }
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
        || mongodb::Frames::with_limit(128).map(Result::unwrap),
        &values,
    );
}

#[test]
fn mongodb_refuses_length_from_header() {
    header_refusal(
        || mongodb::Frames::with_limit(32),
        &33i32.to_le_bytes(),
        mongodb::MessageError::Length(33),
    );
    let length = mongodb::MAX_MESSAGE_SIZE as i32 + 1;
    header_refusal(
        mongodb::Frames::new,
        &length.to_le_bytes(),
        mongodb::MessageError::Length(length),
    );
}

#[test]
fn mongodb_truncated_frame_at_eof() {
    eof_at_every_prefix(|| mongodb::Frames::new().map(Result::unwrap), mongo_ping());
}

#[test]
fn mongodb_wire_is_exact_and_transactional() {
    let value = mongo_ping();
    let bytes = exact_wire(&value);
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(
        mongodb::Message::parse(&joined),
        Ok(Some((value.clone(), bytes.len())))
    );
    assert_eq!(
        <mongodb::Message as Wire>::parse(&joined),
        Err(mongodb::MessageError::Trailing)
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
fn mongodb_body_recovery_and_legacy_repeated_failure() {
    let good = mongo_ping();
    let mut bad = 20i32.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0; 8]);
    bad.extend_from_slice(&mongodb::op_code::MSG.to_le_bytes());
    bad.extend_from_slice(&[0; 4]); // No body section.
    let mut input = bad.clone();
    Wire::write(&good, &mut input).unwrap();
    contract::check_decode(mongodb::Frames::new, &input);

    let mut stream = Stream::new(mongodb::Frames::new());
    assert_eq!(stream.push(&input), input.len());
    assert_eq!(
        stream.next(),
        Some(Ok(Err(mongodb::MessageError::BodyCount(0))))
    );
    assert!(stream.failed().is_none());
    assert_eq!(stream.offset(), bad.len() as u64);
    assert_eq!(stream.unread(), &input[bad.len()..]);
    assert_eq!(stream.next(), Some(Ok(Ok(good.clone()))));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.buffered(), 0);
    assert_eq!(stream.offset(), input.len() as u64);

    let mut old = mongodb::Decoder::new();
    assert_eq!(old.feed(&input), input.len());
    assert_eq!(
        old.next_message(),
        Some(Err(mongodb::MessageError::BodyCount(0)))
    );
    assert_eq!(old.failed(), None);
    assert_eq!(old.next_message(), Some(Ok(good)));
    assert_eq!(old.next_message(), None);
    assert_eq!(old.feed(&0i32.to_le_bytes()), 4);
    for _ in 0..2 {
        assert_eq!(
            old.next_message(),
            Some(Err(mongodb::MessageError::Length(0)))
        );
    }
    assert_eq!(old.failed(), Some(mongodb::MessageError::Length(0)));
    assert_eq!(old.buffered(), 0);
    assert_eq!(old.feed(&input), input.len());
    assert_eq!(old.buffered(), 0);
}

#[test]
fn mongodb_unknown_section_kind_ends_stream() {
    let mut bad = 21i32.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0; 8]);
    bad.extend_from_slice(&mongodb::op_code::MSG.to_le_bytes());
    bad.extend_from_slice(&[0; 4]);
    bad.push(2);
    header_refusal(
        mongodb::Frames::new,
        &bad,
        mongodb::MessageError::SectionKind(2),
    );
}

#[test]
fn mysql_chunked_round_trip() {
    round_trip(
        || mysql::Frames::with_limit(32),
        &[
            mysql::Frame {
                seq: 0,
                payload: b"\x03SELECT 1".to_vec(),
            },
            mysql::Frame {
                seq: 255,
                payload: vec![],
            },
            mysql::Frame {
                seq: 0,
                payload: vec![0xff, 0, 7, 0x80],
            },
            mysql::Frame {
                seq: 19,
                payload: vec![0xa5; 32],
            },
        ],
    );
}

#[test]
fn mysql_refuses_length_from_header() {
    header_refusal(
        || mysql::Frames::with_limit(8),
        &[9, 0, 0, 7],
        mysql::FrameError::TooLong(9),
    );
    header_refusal(
        || mysql::Frames::with_limit(0),
        &[1, 0, 0, 0],
        mysql::FrameError::TooLong(1),
    );
}

#[test]
fn mysql_truncated_frame_at_eof() {
    eof_at_every_prefix(
        mysql::Frames::new,
        mysql::Frame {
            seq: 255,
            payload: b"hello".to_vec(),
        },
    );
}

#[test]
fn mysql_wire_is_exact_and_transactional() {
    let value = mysql::Frame {
        seq: 7,
        payload: vec![0, 1, 2],
    };
    let bytes = exact_wire(&value);
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(mysql::Frame::parse(&joined), Ok(Some((value, bytes.len()))));
    assert_eq!(
        <mysql::Frame as Wire>::parse(&joined),
        Err(mysql::FrameParseError::Trailing)
    );
    refused_write(&mysql::Frame {
        seq: 7,
        payload: vec![0; mysql::MAX_PACKET_PAYLOAD + 1],
    });
    let mut empty = mysql::Frames::with_limit(0);
    assert_eq!(
        empty.decode(&[0, 0, 0, 255], false),
        Ok(Step::Item(
            mysql::Frame {
                seq: 255,
                payload: vec![]
            },
            4
        ))
    );
}

#[test]
fn mysql_full_packet_and_legacy_message_assembly() {
    // A full physical packet requires a separate empty message terminator.
    let full = mysql::Frame {
        seq: 255,
        payload: vec![0x42; mysql::MAX_PACKET_PAYLOAD],
    };
    let bytes = Wire::to_bytes(&full).unwrap();
    assert_eq!(bytes.len(), mysql::MAX_FRAME);
    assert_eq!(<mysql::Frame as Wire>::parse(&bytes), Ok(full.clone()));
    let mut stream = Stream::new(mysql::Frames::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(full.clone())));
    finish(&mut stream, |_| panic!("extra frame")).unwrap();

    let mut old = mysql::Decoder::with_limit(mysql::MAX_PACKET_PAYLOAD);
    assert_eq!(old.feed(&bytes), bytes.len());
    assert_eq!(old.next_message(), None);
    assert_eq!(old.buffered(), mysql::MAX_PACKET_PAYLOAD);
    assert_eq!(old.feed(&[0, 0, 0, 0]), 4);
    assert_eq!(
        old.next_message(),
        Some(Ok(mysql::Message {
            seq: 255,
            payload: full.payload
        }))
    );
    assert_eq!(old.buffered(), 0);

    let mut old = mysql::Decoder::with_limit(0);
    assert_eq!(old.feed(&[1, 0, 0, 0, 0]), 4);
    for _ in 0..2 {
        assert_eq!(old.next_message(), Some(Err(mysql::FrameError::TooLong(1))));
    }
    assert_eq!(old.buffered(), 0);
    assert_eq!(old.feed(&[1; 9]), 9);
    assert_eq!(old.buffered(), 0);
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
        || tds::Frames::with_limit(32),
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
        || tds::Frames::with_limit(16),
        &[1, 0, 0, 17],
        tds::FrameError::TooLong(17),
    );
    header_refusal(tds::Frames::new, &[1, 0, 0, 7], tds::FrameError::Length(7));
}

#[test]
fn tds_truncated_frame_at_eof() {
    eof_at_every_prefix(tds::Frames::new, tds_packet());
}

#[test]
fn tds_wire_is_exact_and_transactional() {
    let value = tds_packet();
    let bytes = exact_wire(&value);
    assert_eq!(bytes, value.to_bytes());
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(tds::Packet::parse(&joined), Ok(Some((value, bytes.len()))));
    assert_eq!(
        <tds::Packet as Wire>::parse(&joined),
        Err(tds::PacketParseError::Trailing)
    );
    let large = tds::Packet {
        data: vec![0; tds::MAX_PACKET - tds::HEADER_LEN + 1],
        ..tds_packet()
    };
    refused_write(&large);
    assert_eq!(large.to_bytes().len(), tds::MAX_PACKET);
    let maximum = tds::Packet {
        data: vec![0; tds::MAX_PACKET - tds::HEADER_LEN],
        ..tds_packet()
    };
    contract::check_wire_value(&maximum);
    assert_eq!(Wire::to_bytes(&maximum).unwrap().len(), tds::MAX_PACKET);
}

#[test]
fn tds_legacy_message_assembly_and_repeated_failure() {
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
    let mut old = tds::Decoder::with_limit(6);
    assert_eq!(old.feed(&first.to_bytes()), 11);
    assert_eq!(old.next_message(), None);
    assert_eq!(old.buffered(), 3);
    assert_eq!(old.feed(&last.to_bytes()), 11);
    assert_eq!(
        old.next_message(),
        Some(Ok(tds::Message {
            packet_type: first.packet_type,
            status: first.status | last.status,
            spid: first.spid,
            data: b"abcdef".to_vec(),
        }))
    );
    assert_eq!(old.feed(&[1, 0, 0, 7]), 4);
    for _ in 0..2 {
        assert_eq!(old.next_message(), Some(Err(tds::FrameError::Length(7))));
    }
    assert_eq!(old.buffered(), 0);
    assert_eq!(old.feed(&[1; 9]), 9);
    assert_eq!(old.buffered(), 0);
}

#[test]
fn git_chunked_round_trip() {
    use git_protocol::Packet;
    round_trip(
        git_protocol::Frames::new,
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
        git_protocol::Frames::new,
        b"fff1",
        git_protocol::PacketError::TooLong(65521),
    );
    header_refusal(
        git_protocol::Frames::new,
        b"0003",
        git_protocol::PacketError::Reserved,
    );
    header_refusal(
        git_protocol::Frames::new,
        b"g",
        git_protocol::PacketError::Header,
    );
}

#[test]
fn git_truncated_frame_at_eof() {
    eof_at_every_prefix(
        git_protocol::Frames::new,
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
        assert_eq!(bytes, value.to_bytes());
        let joined = [bytes.as_slice(), b"0000"].concat();
        assert_eq!(Packet::parse(&joined), Ok(Some((value, bytes.len()))));
        assert_eq!(
            <Packet as Wire>::parse(&joined),
            Err(git_protocol::PacketParseError::Trailing)
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
    assert_eq!(large.to_bytes().len(), git_protocol::MAX_PACKET);
    contract::check_wire_value(&Packet::Data(vec![0; git_protocol::MAX_DATA]));
}

#[test]
fn git_legacy_read_ahead_handoff_and_repeated_failure() {
    let bytes = b"0000".repeat(git_protocol::MAX_BUFFERED / 4 + 1);
    let mut old = git_protocol::Decoder::new();
    assert_eq!(old.feed(&bytes), git_protocol::MAX_BUFFERED);
    assert_eq!(old.feed(b"0000"), 0);
    assert_eq!(old.next_packet(), Some(Ok(git_protocol::Packet::Flush)));
    assert_eq!(
        old.into_rest(),
        bytes.get(4..git_protocol::MAX_BUFFERED).unwrap()
    );
    let mut old = git_protocol::Decoder::new();
    assert_eq!(old.feed(b"0003PACK"), 8);
    for _ in 0..2 {
        assert_eq!(
            old.next_packet(),
            Some(Err(git_protocol::PacketError::Reserved))
        );
    }
    assert_eq!(old.buffered(), 0);
    assert_eq!(old.feed(b"discarded"), 9);
    assert!(old.into_rest().is_empty());
}

fn sftp_packet() -> sftp::Packet {
    sftp::Request::Stat {
        id: 7,
        path: b"/motd".to_vec(),
    }
    .to_packet()
}

#[test]
fn sftp_chunked_round_trip() {
    round_trip(
        || sftp::Frames::with_limit(64),
        &[
            sftp::Request::Init {
                version: sftp::VERSION,
                extensions: vec![],
            }
            .to_packet(),
            sftp_packet(),
            sftp::Response::status(7, sftp::Status::NoSuchFile, "No such file").to_packet(),
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
        || sftp::Frames::with_limit(8),
        &9u32.to_be_bytes(),
        sftp::PacketError::TooLong(9),
    );
    header_refusal(
        sftp::Frames::new,
        &u32::MAX.to_be_bytes(),
        sftp::PacketError::TooLong(u32::MAX),
    );
    header_refusal(
        || sftp::Frames::with_limit(0),
        &1u32.to_be_bytes(),
        sftp::PacketError::TooLong(1),
    );
    header_refusal(sftp::Frames::new, &[0; 4], sftp::PacketError::Empty);
}

#[test]
fn sftp_truncated_frame_at_eof() {
    eof_at_every_prefix(sftp::Frames::new, sftp_packet());
}

#[test]
fn sftp_wire_is_exact_and_transactional() {
    let value = sftp_packet();
    let bytes = exact_wire(&value);
    assert_eq!(bytes, value.to_bytes());
    let joined = [bytes.as_slice(), &[0xff]].concat();
    assert_eq!(sftp::Packet::parse(&joined), Ok(Some((value, bytes.len()))));
    assert_eq!(
        <sftp::Packet as Wire>::parse(&joined),
        Err(sftp::PacketParseError::Trailing)
    );
    let large = sftp::Packet {
        kind: 0xff,
        body: vec![0; sftp::MAX_PACKET],
    };
    refused_write(&large);
    assert_eq!(large.to_bytes().len(), sftp::MAX_FRAME);
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
fn sftp_legacy_limits_and_repeated_failure() {
    let mut old = sftp::Decoder::with_limit(0);
    assert_eq!(old.feed(&[0, 0, 0, 1, 1]), 4);
    assert_eq!(old.feed(&[1]), 0);
    for _ in 0..2 {
        assert_eq!(old.next_packet(), Some(Err(sftp::PacketError::TooLong(1))));
    }
    assert_eq!(old.buffered(), 0);
    assert_eq!(old.feed(&[1; 9]), 9);
    assert_eq!(old.buffered(), 0);
}

#[test]
fn capacities_are_named_and_clamped() {
    assert_eq!(mongodb::Frames::new(), mongodb::Frames::default());
    assert_eq!(mysql::Frames::new(), mysql::Frames::default());
    assert_eq!(tds::Frames::new(), tds::Frames::default());
    assert_eq!(sftp::Frames::new(), sftp::Frames::default());
    assert_eq!(
        git_protocol::Frames::new().capacity(),
        git_protocol::MAX_PACKET
    );
    assert_eq!(mysql::Frames::new().capacity(), mysql::MAX_FRAME);
    assert_eq!(sftp::Frames::new().capacity(), sftp::MAX_FRAME);
    for limit in [0, 1, 16, 4096, usize::MAX] {
        let mongo = mongodb::Frames::with_limit(limit);
        assert_eq!(
            mongo.limit(),
            limit.clamp(mongodb::HEADER_LEN, mongodb::MAX_MESSAGE_SIZE)
        );
        assert_eq!(mongo.capacity(), mongo.limit());
        let mysql = mysql::Frames::with_limit(limit);
        assert_eq!(mysql.limit(), limit.min(mysql::MAX_PACKET_PAYLOAD));
        assert_eq!(mysql.capacity(), mysql::HEADER_LEN + mysql.limit());
        let tds = tds::Frames::with_limit(limit);
        assert_eq!(tds.limit(), limit.clamp(tds::HEADER_LEN, tds::MAX_PACKET));
        assert_eq!(tds.capacity(), tds.limit());
        let sftp = sftp::Frames::with_limit(limit);
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
        contract::check_decode(mongodb::Frames::new, &data);
        contract::check_decode(mysql::Frames::new, &data);
        contract::check_decode(tds::Frames::new, &data);
        contract::check_decode(git_protocol::Frames::new, &data);
        contract::check_decode(sftp::Frames::new, &data);
        contract::check_wire::<mongodb::Message>(&data);
        contract::check_wire::<mysql::Frame>(&data);
        contract::check_wire::<tds::Packet>(&data);
        contract::check_wire::<git_protocol::Packet>(&data);
        contract::check_wire::<sftp::Packet>(&data);
    }
}

fn bytewise_frame<D>(decoder: D, value: D::Item)
where
    D: Decode,
    D::Item: Wire + PartialEq + Debug,
    D::Error: Clone + PartialEq + Debug,
{
    let bytes = Wire::to_bytes(&value).unwrap();
    let capacity = decoder.capacity();
    let mut stream = Stream::new(decoder);
    for (at, byte) in bytes.iter().enumerate() {
        assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
        if at + 1 < bytes.len() {
            assert_eq!(stream.next(), None);
        }
        assert!(stream.buffered() <= capacity);
        assert_eq!(stream.held(), 0);
    }
    assert_eq!(
        stream.with_next(|item, raw, span| {
            assert_eq!(raw, bytes);
            assert_eq!(span, 0..bytes.len() as u64);
            item
        }),
        Some(Ok(value))
    );
    finish(&mut stream, |_| panic!("extra frame")).unwrap();
}

#[test]
fn large_frames_arrive_one_byte_at_a_time() {
    const PAYLOAD: usize = 64 * 1024;
    bytewise_frame(
        mongodb::Frames::with_limit(mongodb::HEADER_LEN + PAYLOAD).map(Result::unwrap),
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
        mysql::Frames::with_limit(PAYLOAD),
        mysql::Frame {
            seq: 255,
            payload: vec![0xa5; PAYLOAD],
        },
    );
    bytewise_frame(
        tds::Frames::new(),
        tds::Packet {
            data: vec![0xa5; tds::MAX_PACKET - tds::HEADER_LEN],
            ..tds_packet()
        },
    );
    bytewise_frame(
        git_protocol::Frames::new(),
        git_protocol::Packet::Data(vec![0xa5; git_protocol::MAX_DATA]),
    );
    bytewise_frame(
        sftp::Frames::new(),
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
fn mongodb_writers_preserve_validation_order_for_large_bodies() {
    // Duplicate keys need no full-size field table. Both writers report
    // the same validation error, even when the body exceeds MAX_ELEMENTS.
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
    for (flags, error) in [
        (0, mongodb::MessageError::DuplicateField),
        (1 << 20, mongodb::MessageError::Flags(1 << 20)),
    ] {
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
