//! Control lines and counted bodies through the shared codec driver.

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{
    self, Decode, Fail, Lcg, Step, Stream, Wire, contract, finish, pump,
    test_support::{decode_all, mutate},
};
use fictionet::stdlib::{ftp, memcache, whois};
use std::fmt::Debug;

fn written<T: Wire + Debug + PartialEq>(items: &[T]) -> Vec<u8>
where
    T::WriteError: Debug,
{
    let mut bytes = Vec::new();
    for item in items {
        contract::check_wire_value(item);
        let start = bytes.len();
        item.write(&mut bytes).unwrap();
        contract::check_wire::<T>(&bytes[start..]);
    }
    bytes
}

fn round_trip<D: Decode>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode_with_alloc_limit(&make, bytes, 2 * make().capacity());
    let (items, failure) = decode_all(make, bytes);
    assert_eq!(failure, None);
    assert_eq!(items, expected);
}

#[test]
fn ftp_commands_and_multiline_replies_round_trip() {
    let commands = [
        ftp::Command::new("USER", Some("guest")),
        ftp::Command::new("RETR", Some("a\r\nb\rc")),
        ftp::Command::new("NOOP", None),
    ];
    let bytes = written(&commands);
    round_trip(ftp::Commands::new, &bytes, &commands.map(Ok));
    let replies = [
        ftp::Reply {
            code: ftp::code::READY,
            lines: vec!["Welcome".into(), " features".into(), "Ready".into()],
        },
        ftp::Reply::new(ftp::code::OK, "Done"),
    ];
    let bytes = written(&replies);
    round_trip(ftp::Replies::new, &bytes, &replies.map(Ok));
}

#[test]
fn ftp_wire_preserves_numeric_middle_lines() {
    for bytes in [
        b"230-Welcome\r\n230-second line\r\n230 Login ok\r\n".as_slice(),
        b"200-a\r\n123 b\r\n200 c\r\n",
    ] {
        let (items, failure) = decode_all(ftp::Replies::new, bytes);
        assert_eq!(failure, None);
        assert_eq!(items.len(), 1);
        let reply = items[0].as_ref().unwrap();
        assert_eq!(<ftp::Reply as Wire>::parse(bytes).as_ref(), Ok(reply));
        let mut out = b"prefix".to_vec();
        reply.write(&mut out).unwrap();
        assert_eq!(&out[b"prefix".len()..], bytes);
        contract::check_wire::<ftp::Reply>(bytes);
        assert_eq!(reply.to_bytes().unwrap(), bytes);
    }
}

#[test]
fn ftp_line_errors_recover_and_accept_bare_lf() {
    round_trip(
        ftp::Commands::new,
        b"123 bad\r\nNOOP\n",
        &[
            Err(ftp::Error::Verb),
            Ok(ftp::Command::new("NOOP", None)),
        ],
    );
    round_trip(
        ftp::Replies::new,
        b"999 bad\r\n220 ready\n",
        &[
            Err(ftp::Error::Syntax),
            Ok(ftp::Reply::new(ftp::code::READY, "ready")),
        ],
    );
    // Semantic validation remains a separate layer, as in the RPC stacks.
    let commands = || ftp::Commands::new().map(|item| item.map(|c| ftp::Request::from_command(&c)));
    contract::check_decode(commands, b"ZZZZ\r\nNOOP\r\n");
}

#[test]
fn ftp_line_limits_escape_boundaries_and_eof() {
    let mut too_long = vec![b'a'; ftp::MAX_LINE];
    too_long.extend_from_slice(b"\r\0\nignored\r\nNOOP\r\n");
    round_trip(
        ftp::Commands::new,
        &too_long,
        &[
            Err(ftp::Error::LineTooLong),
            Ok(ftp::Command::new("NOOP", None)),
        ],
    );
    // Several escaped physical lines still share one logical line limit.
    let escaped = [
        b"RETR ".as_slice(),
        &b"\r\0\n".repeat(ftp::MAX_LINE / 3),
        b"\r\nNOOP\n",
    ]
    .concat();
    round_trip(
        ftp::Commands::new,
        &escaped,
        &[
            Err(ftp::Error::LineTooLong),
            Ok(ftp::Command::new("NOOP", None)),
        ],
    );
    for input in [b"NOOP\r".as_slice(), b"RETR a\r\0\n"] {
        contract::check_decode(ftp::Commands::new, input);
        assert_eq!(
            decode_all(ftp::Commands::new, input).1,
            Some(Fail::Protocol(ftp::FrameError::Incomplete))
        );
    }
    for input in [b"220-hello\r\n".as_slice(), b"220-\r\n", b"220 hel"] {
        contract::check_decode(ftp::Replies::new, input);
        assert_eq!(
            decode_all(ftp::Replies::new, input).1,
            Some(Fail::Protocol(ftp::FrameError::Incomplete))
        );
    }
    let bad = [b"220-hello\n".as_slice(), &[0], b"\n220 done\n"].concat();
    contract::check_decode(ftp::Replies::new, &bad);
    assert_eq!(
        decode_all(ftp::Replies::new, &bad).1,
        Some(Fail::Protocol(ftp::FrameError::Reply(ftp::Error::Text)))
    );
    let long_reply = vec![b'1'; ftp::MAX_LINE];
    contract::check_decode(ftp::Replies::new, &long_reply);
    assert_eq!(
        decode_all(ftp::Replies::new, &long_reply).1,
        Some(Fail::Protocol(ftp::FrameError::Reply(ftp::Error::LineTooLong)))
    );
}

#[test]
fn ftp_reply_count_limit_recovers_at_matching_code() {
    let mut bytes = b"220-start\r\n".to_vec();
    for _ in 0..ftp::MAX_REPLY_LINES {
        bytes.extend_from_slice(b" x\r\n");
    }
    bytes.extend_from_slice(b"220 done\r\n200 OK\r\n");
    round_trip(
        ftp::Replies::new,
        &bytes,
        &[
            Err(ftp::Error::TooManyLines),
            Ok(ftp::Reply::new(ftp::code::OK, "OK")),
        ],
    );
    contract::check_decode_with_held_limit(ftp::Replies::new, &bytes, ftp::MAX_REPLY_BYTES);
}

#[test]
fn ftp_wire_is_exact_strict_and_transactional() {
    let lower = ftp::Command::new("noop", None);
    assert_eq!(lower.to_bytes(), Err(ftp::Error::Unwritable));
    let mut out = b"prefix".to_vec();
    assert!(lower.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    for reply in [
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec![],
        },
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec![String::new(); ftp::MAX_REPLY_LINES + 1],
        },
        ftp::Reply::new(ftp::code::OK, "bad\ntext"),
        ftp::Reply::new(ftp::code::OK, "bad\rtext"),
        ftp::Reply::new(ftp::code::OK, "bad\0text"),
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec!["first".into(), "200 text".into(), "last".into()],
        },
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec!["first".into(), "200".into(), "last".into()],
        },
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec!["x".repeat(ftp::MAX_LINE - 5), "last".into()],
        },
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec!["first".into(), "x".repeat(ftp::MAX_LINE - 5)],
        },
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec!["first".into(), "x".repeat(ftp::MAX_LINE - 1), "last".into()],
        },
        ftp::Reply {
            code: ftp::code::OK,
            lines: vec!["x".repeat(ftp::MAX_LINE)],
        },
    ] {
        contract::check_wire_value(&reply);
        assert!(reply.write(&mut out).is_err());
        assert_eq!(out, b"prefix");
    }
    assert!(<ftp::Command as Wire>::parse(b"NOOP\r\nextra").is_err());
    assert!(<ftp::Reply as Wire>::parse(b"200 OK\r\nextra").is_err());
    contract::check_wire::<ftp::Reply>(b"200-first\r\n123 raw\r\n200 last\r\n");
    contract::check_wire::<ftp::Command>(b"\xff\xf4NOOP\n");
    contract::check_wire::<ftp::Reply>(b"200\n");
}

#[test]
fn ftp_strict_reply_accepts_full_size_verbatim_text() {
    let edge = "x".repeat(ftp::MAX_LINE - 6);
    let middle = format!("123 {}", "x".repeat(ftp::MAX_LINE - 6));
    for lines in [
        vec![edge.clone()],
        vec![edge.clone(), middle, edge],
        vec![String::new(); ftp::MAX_REPLY_LINES],
    ] {
        let reply = ftp::Reply {
            code: ftp::code::OK,
            lines,
        };
        let bytes = written(std::slice::from_ref(&reply));
        round_trip(ftp::Replies::new, &bytes, &[Ok(reply)]);
    }
}

#[test]
fn whois_queries_and_eof_response_round_trip() {
    let queries = [
        whois::Query::new("example.test").unwrap(),
        whois::Query::new("-T inetnum 192.0.2.1").unwrap(),
    ];
    let bytes = written(&queries);
    round_trip(whois::Queries::new, &bytes, &queries.map(Ok));
    let response = whois::Response::new(b"domain: example.test\r\nstatus: active\r\n").unwrap();
    let bytes = written(std::slice::from_ref(&response));
    round_trip(
        whois::CollectedResponses::new,
        &bytes,
        &[whois::CollectedResponse {
            response,
            truncated: false,
        }],
    );
    let mut stream = Stream::new(whois::CollectedResponses::new());
    pump(&mut stream, &bytes, |_| panic!("response before EOF")).unwrap();
    assert!(stream.next().is_none());
    let mut got = Vec::new();
    finish(&mut stream, |item| got.push(item)).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].response.as_bytes(), bytes);
}

#[test]
fn whois_errors_limits_and_query_truncation() {
    round_trip(
        whois::Queries::new,
        b"bad\0query\r\ngood\n",
        &[
            Err(whois::Error::Control('\0')),
            Ok(whois::Query::new("good").unwrap()),
        ],
    );
    let mut bytes = vec![b'x'; whois::MAX_QUERY + 2];
    bytes.extend_from_slice(b"\nnext\r\n");
    round_trip(
        whois::Queries::new,
        &bytes,
        &[
            Err(whois::Error::QueryTooLong),
            Ok(whois::Query::new("next").unwrap()),
        ],
    );
    let mut stream = Stream::new(whois::Queries::new());
    assert_eq!(stream.push(&bytes), whois::MAX_QUERY + 2);
    assert_eq!(stream.next(), Some(Ok(Err(whois::Error::QueryTooLong))));
    let (items, failure) = decode_all(whois::Queries::new, b"query\r");
    assert!(items.is_empty());
    assert_eq!(
        failure,
        Some(Fail::Protocol(codec::LineError::Unterminated))
    );
    assert!(<whois::Query as Wire>::parse(b"one\nsecond\n").is_err());
    assert!(<whois::Query as Wire>::parse(b"unfinished").is_err());
    contract::check_decode(whois::Queries::new, b"query\r");
}

#[test]
fn whois_response_limit_reports_truncation() {
    for (bytes, truncated) in [
        (b"".as_slice(), false),
        (b"abc", false),
        (b"abcd", true),
        (b"abcdef", true),
    ] {
        let expected = whois::CollectedResponse {
            response: whois::Response::new(&bytes[..bytes.len().min(3)]).unwrap(),
            truncated,
        };
        round_trip(|| whois::CollectedResponses::with_limit(3), bytes, &[expected]);
        contract::check_decode_with_held_limit(|| whois::CollectedResponses::with_limit(3), bytes, 3);
    }
    round_trip(
        || whois::CollectedResponses::with_limit(0),
        b"x",
        &[whois::CollectedResponse {
            response: whois::Response::default(),
            truncated: true,
        }],
    );
    for size in [whois::MAX_RESPONSE, whois::MAX_RESPONSE + 1] {
        let bytes = vec![b'x'; size];
        let truncated = size > whois::MAX_RESPONSE;
        let (items, failure) = decode_all(whois::CollectedResponses::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(
            items,
            [whois::CollectedResponse {
                response: whois::Response::new(&bytes[..whois::MAX_RESPONSE]).unwrap(),
                truncated
            }]
        );
    }
    assert!(<whois::Response as Wire>::parse(&vec![0; whois::MAX_RESPONSE + 1]).is_err());
}

fn cache_packet(value: &[u8]) -> memcache::Packet {
    memcache::Packet {
        magic: memcache::Magic::Request,
        opcode: memcache::opcode::SET,
        data_type: 0,
        status: 0,
        opaque: 42,
        cas: 7,
        extras: memcache::StoreExtras {
            flags: 3,
            expiration: 0,
        }
        .to_bytes()
        .unwrap(),
        key: b"key".to_vec(),
        value: value.to_vec(),
    }
}

#[test]
fn memcache_text_and_binary_round_trips() {
    let commands = [
        memcache::Command::Store {
            verb: memcache::StoreVerb::Set,
            key: b"key".to_vec(),
            flags: 3,
            exptime: 0,
            data: b"a\r\nEND\0b".to_vec(),
            noreply: false,
        },
        memcache::Command::Get {
            keys: vec![b"key".to_vec()],
            cas: true,
        },
        memcache::Command::Version,
    ];
    let bytes = written(&commands);
    round_trip(memcache::Commands::new, &bytes, &commands.map(Ok));
    let responses = [
        memcache::Response::Value {
            key: b"key".to_vec(),
            flags: 3,
            cas: Some(42),
            data: b"a\r\nEND\0b".to_vec(),
        },
        memcache::Response::End,
        memcache::Response::MetaValue {
            flags: vec![],
            data: vec![],
        },
    ];
    let bytes = written(&responses);
    round_trip(memcache::Responses::new, &bytes, &responses.map(Ok));
    let packets = [cache_packet(b"a\0\r\nb"), cache_packet(b"second")];
    let bytes = written(&packets);
    round_trip(Frames::<memcache::Packet>::new, &bytes, &packets);
}

#[test]
fn memcache_recoverable_lines_and_bad_counted_trailer() {
    round_trip(
        memcache::Commands::new,
        b"unknown\r\nversion\n",
        &[
            Err(memcache::Error::UnknownCommand),
            Ok(memcache::Command::Version),
        ],
    );
    round_trip(
        memcache::Responses::new,
        b"unknown\r\nEND\n",
        &[
            Err(memcache::Error::UnknownCommand),
            Ok(memcache::Response::End),
        ],
    );
    round_trip(
        memcache::Commands::new,
        b"set key 0 0 3\nabcXXversion\r\n",
        &[
            Err(memcache::Error::BadDataChunk),
            Ok(memcache::Command::Version),
        ],
    );
    round_trip(
        memcache::Responses::new,
        b"VALUE key x 3\r\nabc\r\nEND\r\n",
        &[Err(memcache::Error::Format), Ok(memcache::Response::End)],
    );
    round_trip(
        memcache::Commands::new,
        b"ms key 3 Z\r\nabc\r\nversion\r\n",
        &[Err(memcache::Error::Format), Ok(memcache::Command::Version)],
    );
}

#[test]
fn memcache_limits_are_checked_before_body_assembly() {
    let header = b"set k 0 0 5\r\n";
    let mut decoder = memcache::Commands::with_limit(2);
    let Step::Item(Err(error), used) = decoder.decode(header, false).unwrap() else {
        panic!("expected an oversized block error from the header");
    };
    assert_eq!(used, header.len());
    assert_eq!(error, memcache::Error::TooLarge(5));
    assert_eq!(
        error.to_string(),
        "data block of 5 bytes exceeds the configured limit"
    );
    assert_eq!(decoder.held(), 0);

    let header = b"set key 0 0 4 noreply\r\n";
    let mut stream = Stream::new(memcache::Commands::with_limit(3));
    assert_eq!(stream.push(header), header.len());
    assert_eq!(stream.next(), Some(Ok(Err(memcache::Error::TooLarge(4)))));
    assert!(stream.decoder().quiet_error());
    assert_eq!(stream.held(), 0);
    assert!(stream.next().is_none());
    assert!(stream.decoder().quiet_error());
    pump(&mut stream, b"data\r\nversion\r\n", |item| {
        assert_eq!(item, Ok(memcache::Command::Version))
    })
    .unwrap();
    finish(&mut stream, |_| panic!("unexpected item")).unwrap();
    round_trip(
        || memcache::Commands::with_limit(3),
        b"set key 0 0 4\r\ndata\r\nversion\r\n",
        &[
            Err(memcache::Error::TooLarge(4)),
            Ok(memcache::Command::Version),
        ],
    );
    round_trip(
        || memcache::Responses::with_limit(3),
        b"VALUE key 0 4\r\ndata\r\nEND\r\n",
        &[
            Err(memcache::Error::TooLarge(4)),
            Ok(memcache::Response::End),
        ],
    );
    let mut bytes = vec![b'x'; memcache::MAX_LINE];
    bytes.extend_from_slice(b"\r\nversion\r\n");
    contract::check_decode_with_alloc_limit(memcache::Commands::new, &bytes, 2 * memcache::MAX_LINE);
    contract::check_decode_with_alloc_limit(
        memcache::Responses::new,
        &bytes,
        2 * memcache::MAX_LINE,
    );
    assert_eq!(
        decode_all(memcache::Commands::new, &bytes).1,
        Some(Fail::Protocol(memcache::FrameError::LineTooLong))
    );
    assert_eq!(
        decode_all(memcache::Responses::new, &bytes).1,
        Some(Fail::Protocol(memcache::FrameError::LineTooLong))
    );
    let mut header = [0; memcache::BINARY_HEADER_LEN];
    header[0] = memcache::REQUEST_MAGIC;
    header[8..12].copy_from_slice(&4u32.to_be_bytes());
    let mut binary = Stream::new(Frames::<memcache::Packet>::with_limit(3));
    assert_eq!(binary.push(&header), header.len());
    assert_eq!(
        binary.next(),
        Some(Err(Fail::Protocol(memcache::Error::BodyLength(4))))
    );
    assert_eq!(binary.buffered(), memcache::BINARY_HEADER_LEN);
    assert_eq!(binary.held(), 0);
    assert!(binary.next().is_none());
    contract::check_decode(|| Frames::<memcache::Packet>::with_limit(3), &header);
}

#[test]
fn memcache_eof_inside_headers_bodies_trailers_and_skips() {
    for bytes in [
        b"version\r".as_slice(),
        b"set key 0 0 3\r\n",
        b"set key 0 0 3\r\nab",
        b"set key 0 0 3\r\nabc\r",
    ] {
        contract::check_decode(memcache::Commands::new, bytes);
        assert_eq!(
            decode_all(memcache::Commands::new, bytes).1,
            Some(Fail::Protocol(memcache::FrameError::Incomplete))
        );
    }
    for bytes in [
        b"END\r".as_slice(),
        b"VALUE key 0 3\r\n",
        b"VALUE key 0 3\r\nabc\r",
    ] {
        contract::check_decode(memcache::Responses::new, bytes);
        assert_eq!(
            decode_all(memcache::Responses::new, bytes).1,
            Some(Fail::Protocol(memcache::FrameError::Incomplete))
        );
    }
    let bytes = b"set key 0 0 4\r\nda";
    contract::check_decode(|| memcache::Commands::with_limit(3), bytes);
    assert_eq!(
        decode_all(|| memcache::Commands::with_limit(3), bytes).1,
        Some(Fail::Protocol(memcache::FrameError::Incomplete))
    );
    let bytes = written(&[cache_packet(b"body")]);
    for cut in [1, 23, 24, bytes.len() - 1] {
        contract::check_decode(Frames::<memcache::Packet>::new, &bytes[..cut]);
        let (items, failure) = decode_all(Frames::<memcache::Packet>::new, &bytes[..cut]);
        assert!(items.is_empty());
        assert_eq!(failure, Some(Fail::Truncated { unread: cut }));
    }
}

#[test]
fn memcache_multiget_uses_its_own_line_limit() {
    let command = memcache::Command::Get {
        keys: vec![b"key".to_vec(); memcache::MAX_LINE / 2],
        cas: true,
    };
    let bytes = written(std::slice::from_ref(&command));
    assert!(bytes.len() > memcache::MAX_LINE);
    round_trip(memcache::Commands::new, &bytes, &[Ok(command)]);
    let mut long = b"get ".to_vec();
    long.resize(memcache::MAX_GET_LINE, b'x');
    contract::check_decode(memcache::Commands::new, &long);
    let (items, failure) = decode_all(memcache::Commands::new, &long);
    assert!(items.is_empty());
    assert_eq!(
        failure,
        Some(Fail::Protocol(memcache::FrameError::LineTooLong))
    );
}

#[test]
fn memcache_wire_exactness_and_transactional_refusal() {
    let mut out = b"prefix".to_vec();
    let bad = memcache::Command::Get {
        keys: vec![b"bad key".to_vec()],
        cas: false,
    };
    assert!(bad.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    let bad = memcache::Response::ServerError(b"bad\ntext".to_vec());
    assert!(bad.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    let mut packet = cache_packet(b"data");
    packet.extras = vec![0; 256];
    assert!(packet.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    assert!(<memcache::Command as Wire>::parse(b"version\r\nextra").is_err());
    assert!(<memcache::Response as Wire>::parse(b"END\r\nextra").is_err());
    let mut bytes = written(&[cache_packet(b"data")]);
    bytes.push(0);
    assert!(<memcache::Packet as Wire>::parse(&bytes).is_err());
    contract::check_wire::<memcache::Command>(b"  version\n");
    contract::check_wire::<memcache::Response>(b"0001   \n");
}

#[test]
fn contracts_cover_random_and_mutated_input() {
    let mut rng = Lcg::new(52);
    for size in 0..64 {
        let mut bytes = vec![0; size * 3];
        rng.fill(&mut bytes);
        contract::check_decode_with_alloc_limit(ftp::Commands::new, &bytes, 2 * ftp::MAX_LINE);
        contract::check_decode_with_alloc_limit(ftp::Replies::new, &bytes, 2 * ftp::MAX_LINE);
        contract::check_decode_with_alloc_limit(whois::Queries::new, &bytes, 2 * (whois::MAX_QUERY + 2));
        contract::check_decode_with_alloc_limit(|| whois::CollectedResponses::with_limit(17), &bytes, 2 * whois::RESPONSE_WINDOW);
        contract::check_decode_with_alloc_limit(memcache::Commands::new, &bytes, 2 * memcache::MAX_LINE);
        contract::check_decode_with_alloc_limit(memcache::Responses::new, &bytes, 2 * memcache::MAX_LINE);
        contract::check_decode_with_alloc_limit(|| Frames::<memcache::Packet>::with_limit(17), &bytes, 2 * (memcache::BINARY_HEADER_LEN + 17));
        contract::check_wire::<ftp::Command>(&bytes);
        contract::check_wire::<ftp::Reply>(&bytes);
        contract::check_wire::<ftp::Request>(&bytes);
        contract::check_wire::<ftp::PortAddress>(&bytes);
        contract::check_wire::<ftp::EprtAddress>(&bytes);
        contract::check_wire::<whois::Query>(&bytes);
        contract::check_wire::<whois::Response>(&bytes);
        contract::check_wire::<memcache::Command>(&bytes);
        contract::check_wire::<memcache::Response>(&bytes);
        contract::check_wire::<memcache::Packet>(&bytes);
        contract::check_wire::<memcache::UdpFrame>(&bytes);
        contract::check_wire::<memcache::StoreExtras>(&bytes);
        contract::check_wire::<memcache::CounterExtras>(&bytes);
    }
    let source = b"set key 0 0 4\r\na\r\nb\r\nversion\r\n";
    for at in 0..source.len() {
        let mut bytes = source.to_vec();
        bytes[at] = rng.next() as u8;
        mutate(&mut rng, &mut bytes);
        contract::check_decode_with_alloc_limit(memcache::Commands::new, &bytes, 2 * memcache::MAX_LINE);
        contract::check_wire::<memcache::Command>(&bytes);
    }
}

#[test]
fn unwritable_errors_have_one_description() {
    for message in [
        ftp::Error::Unwritable.to_string(),
        whois::Error::Unwritable.to_string(),
        memcache::Error::Unwritable.to_string(),
    ] {
        assert_eq!(message, "value cannot be written without changing it");
    }
}

#[test]
fn decoder_capacity_and_empty_eof() {
    let _ = format!(
        "{:?}",
        (
            ftp::Commands::new(),
            ftp::Replies::new(),
            whois::Queries::new(),
            whois::CollectedResponses::new(),
            memcache::Commands::new(),
            memcache::Responses::new(),
            Frames::<memcache::Packet>::new(),
        )
    );
    assert_eq!(ftp::Commands::new().capacity(), ftp::MAX_LINE);
    assert_eq!(ftp::Replies::new().capacity(), ftp::MAX_LINE);
    assert_eq!(whois::Queries::new().capacity(), whois::MAX_QUERY + 2);
    assert_eq!(whois::CollectedResponses::new().capacity(), whois::RESPONSE_WINDOW);
    assert_eq!(
        whois::CollectedResponses::with_limit(0).capacity(),
        whois::RESPONSE_WINDOW
    );
    assert_eq!(
        Frames::<memcache::Packet>::with_limit(usize::MAX).capacity(),
        memcache::MAX_BINARY_BUFFERED
    );
    assert_eq!(memcache::Responses::new().capacity(), memcache::MAX_LINE);
    assert_eq!(memcache::Commands::new().capacity(), memcache::MAX_LINE);
    assert_eq!(
        Frames::<memcache::Packet>::with_limit(0).decode(&[], true),
        Ok(Step::Need)
    );
    round_trip(ftp::Commands::new, b"", &[]);
    round_trip(ftp::Replies::new, b"", &[]);
    round_trip(whois::Queries::new, b"", &[]);
    round_trip(
        whois::CollectedResponses::new,
        b"",
        &[whois::CollectedResponse {
            response: whois::Response::default(),
            truncated: false,
        }],
    );
    round_trip(memcache::Commands::new, b"", &[]);
    round_trip(memcache::Responses::new, b"", &[]);
    round_trip(Frames::<memcache::Packet>::new, b"", &[]);
}

#[test]
fn memcache_long_line_crlf_crosses_the_input_window() {
    let command = memcache::Command::Get {
        keys: vec![b"a".to_vec(); 4094],
        cas: false,
    };
    let bytes = written(std::slice::from_ref(&command));
    assert_eq!(bytes.len(), memcache::MAX_LINE + 1);
    assert_eq!(bytes[memcache::MAX_LINE - 1], b'\r');
    round_trip(memcache::Commands::new, &bytes, &[Ok(command)]);
    contract::check_decode_with_held_limit(
        memcache::Commands::new,
        &bytes,
        memcache::MAX_TEXT_HELD,
    );
}

#[test]
fn memcache_long_get_line_keeps_the_content_limit_after_a_cr() {
    for content_len in [memcache::MAX_GET_LINE - 2, memcache::MAX_GET_LINE - 1] {
        let mut bytes = b"get ".to_vec();
        bytes.resize(content_len, b'x');
        bytes[memcache::MAX_LINE - 1] = b'\r';
        bytes.extend_from_slice(b"\r\n");
        contract::check_decode_with_alloc_limit(
            memcache::Commands::new, &bytes, 2 * memcache::MAX_LINE,
        );
        let (items, failure) = decode_all(memcache::Commands::new, &bytes);
        if content_len == memcache::MAX_GET_LINE - 2 {
            assert_eq!(failure, None);
            assert_eq!(items, [Err(memcache::Error::Key)]);
        } else {
            assert!(items.is_empty());
            assert_eq!(
                failure,
                Some(Fail::Protocol(memcache::FrameError::LineTooLong))
            );
        }
    }
}

#[test]
fn memcache_long_get_consumes_the_scanned_window() {
    for trailing_cr in [false, true] {
        let mut bytes = b"get ".to_vec();
        bytes.resize(4 * memcache::MAX_LINE, b'x');
        if trailing_cr {
            *bytes.last_mut().unwrap() = b'\r';
        }
        let mut decoder = memcache::Commands::new();
        let used = bytes.len() - usize::from(trailing_cr);
        assert_eq!(decoder.decode(&bytes, false), Ok(Step::Skip(used)));
        assert_eq!(decoder.held(), used);
    }
}

#[test]
fn memcache_binary_key_length_precedes_body_length() {
    let key_len = memcache::MAX_KEY + 1;
    for body_len in [4, memcache::MAX_BODY + 1] {
        let mut header = [0; memcache::BINARY_HEADER_LEN];
        header[0] = memcache::REQUEST_MAGIC;
        header[2..4].copy_from_slice(&(key_len as u16).to_be_bytes());
        header[8..12].copy_from_slice(&(body_len as u32).to_be_bytes());
        let error = memcache::Error::KeyLength(key_len);
        assert_eq!(
            <memcache::Packet as Wire>::parse(&header),
            Err(error)
        );
        assert_eq!(
            Frames::<memcache::Packet>::with_limit(3).decode(&header, false),
            Err(error)
        );
        assert_eq!(Frames::<memcache::Packet>::new().decode(&header, false), Err(error));
    }
}

#[test]
fn overlong_wire_lines_report_length_errors() {
    for tail in [b"".as_slice(), b"\r\n"] {
        let mut bytes = vec![b'a'; 5000];
        bytes.extend_from_slice(tail);
        assert_eq!(
            <ftp::Command as Wire>::parse(&bytes),
            Err(ftp::Error::LineTooLong)
        );
        assert_eq!(
            <whois::Query as Wire>::parse(&bytes),
            Err(whois::Error::QueryTooLong)
        );
    }
}
