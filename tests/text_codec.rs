//! Control lines and counted bodies through the shared codec driver.

use fictionet::stdlib::codec::{
    self, Decode, Fail, Step, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, chunks},
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

fn drive<D: Decode>(decoder: D, bytes: &[u8], pattern: &[usize]) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Error: Clone + Debug,
{
    let capacity = decoder.capacity();
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    let mut failure = None;
    for part in chunks(bytes, pattern) {
        if let Err(e) = pump(&mut stream, part, |item| items.push(item)) {
            failure = Some(e);
            break;
        }
        assert!(stream.buffered() <= capacity);
    }
    if failure.is_none() {
        failure = finish(&mut stream, |item| items.push(item)).err();
    }
    assert!(stream.is_done());
    assert!(stream.next().is_none());
    assert!(stream.next().is_none());
    (items, failure)
}

fn round_trip<D: Decode>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_stack(&make, bytes);
    for pattern in [&[][..], &[1], &[3, 1, 7, 2, 19], &[64]] {
        let (items, failure) = drive(make(), bytes, pattern);
        assert_eq!(failure, None);
        assert_eq!(items, expected);
    }
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
fn ftp_line_errors_recover_and_accept_bare_lf() {
    round_trip(
        ftp::Commands::new,
        b"123 bad\r\nNOOP\n",
        &[Err(ftp::CommandError::Verb), Ok(ftp::Command::new("NOOP", None))],
    );
    round_trip(
        ftp::Replies::new,
        b"999 bad\r\n220 ready\n",
        &[Err(ftp::ReplyError::Syntax), Ok(ftp::Reply::new(ftp::code::READY, "ready"))],
    );
    // Semantic validation remains a separate layer, as in the RPC stacks.
    let commands = || ftp::Commands::new().map(|item| item.map(|c| ftp::Request::from_command(&c)));
    contract::check_stack(commands, b"ZZZZ\r\nNOOP\r\n");
}

#[test]
fn ftp_line_limits_escape_boundaries_and_eof() {
    let mut too_long = vec![b'a'; ftp::MAX_LINE];
    too_long.extend_from_slice(b"\r\0\nignored\r\nNOOP\r\n");
    round_trip(
        ftp::Commands::new,
        &too_long,
        &[Err(ftp::CommandError::LineTooLong), Ok(ftp::Command::new("NOOP", None))],
    );
    // Several escaped physical lines still share one logical line limit.
    let escaped = [b"RETR ".as_slice(), &b"\r\0\n".repeat(ftp::MAX_LINE / 3), b"\r\nNOOP\n"].concat();
    round_trip(
        ftp::Commands::new,
        &escaped,
        &[Err(ftp::CommandError::LineTooLong), Ok(ftp::Command::new("NOOP", None))],
    );
    for input in [b"NOOP\r".as_slice(), b"RETR a\r\0\n"] {
        contract::check_decode(ftp::Commands::new, input);
        assert_eq!(
            drive(ftp::Commands::new(), input, &[1]).1,
            Some(Fail::Protocol(ftp::DecodeError::Incomplete))
        );
    }
    for input in [b"220-hello\r\n".as_slice(), b"220-\r\n", b"220 hel"] {
        contract::check_decode(ftp::Replies::new, input);
        assert_eq!(
            drive(ftp::Replies::new(), input, &[1]).1,
            Some(Fail::Protocol(ftp::DecodeError::Incomplete))
        );
    }
    let bad = [b"220-hello\n".as_slice(), &[0], b"\n220 done\n"].concat();
    assert_eq!(
        drive(ftp::Replies::new(), &bad, &[1]).1,
        Some(Fail::Protocol(ftp::DecodeError::Reply(ftp::ReplyError::Text)))
    );
    let long_reply = vec![b'1'; ftp::MAX_LINE];
    contract::check_decode(ftp::Replies::new, &long_reply);
    assert_eq!(
        drive(ftp::Replies::new(), &long_reply, &[1]).1,
        Some(Fail::Protocol(ftp::DecodeError::Reply(ftp::ReplyError::LineTooLong)))
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
        &[Err(ftp::ReplyError::TooManyLines), Ok(ftp::Reply::new(ftp::code::OK, "OK"))],
    );
    contract::check_decode_with_held_limit(ftp::Replies::new, &bytes, ftp::MAX_REPLY_BYTES);
}

#[test]
fn ftp_wire_is_exact_strict_and_transactional() {
    let lower = ftp::Command::new("noop", None);
    assert_eq!(lower.to_bytes().unwrap(), b"NOOP\r\n");
    let mut out = b"prefix".to_vec();
    assert!(lower.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    for reply in [
        ftp::Reply { code: ftp::code::OK, lines: vec![] },
        ftp::Reply::new(ftp::code::OK, "bad\ntext"),
        ftp::Reply { code: ftp::code::OK, lines: vec!["first".into(), "123 text".into(), "last".into()] },
        ftp::Reply { code: ftp::code::OK, lines: vec!["x".repeat(ftp::MAX_LINE)] },
    ] {
        contract::check_wire_value(&reply);
        assert!(reply.write(&mut out).is_err());
        assert_eq!(out, b"prefix");
    }
    assert!(<ftp::Command as Wire>::parse(b"NOOP\r\nextra").is_err());
    assert!(<ftp::Reply as Wire>::parse(b"200 OK\r\nextra").is_err());
    assert!(<ftp::Reply as Wire>::parse(b"200-first\r\n123 raw\r\n200 last\r\n").is_err());
    contract::check_wire::<ftp::Command>(b"\xff\xf4NOOP\n");
    contract::check_wire::<ftp::Reply>(b"200\n");
}

#[test]
fn whois_queries_and_eof_response_round_trip() {
    let queries =
        [whois::Query::new("example.test").unwrap(), whois::Query::new("-T inetnum 192.0.2.1").unwrap()];
    let bytes = written(&queries);
    round_trip(whois::Queries::new, &bytes, &queries.map(Ok));
    let response = whois::Response::new(b"domain: example.test\r\nstatus: active\r\n").unwrap();
    let bytes = written(std::slice::from_ref(&response));
    round_trip(whois::Responses::new, &bytes, &[whois::CollectedResponse { response, truncated: false }]);
    let mut stream = Stream::new(whois::Responses::new());
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
        &[Err(whois::QueryError::Control('\0')), Ok(whois::Query::new("good").unwrap())],
    );
    let mut bytes = vec![b'x'; whois::MAX_QUERY + 2];
    bytes.extend_from_slice(b"\nnext\r\n");
    round_trip(
        whois::Queries::new,
        &bytes,
        &[Err(whois::QueryError::TooLong), Ok(whois::Query::new("next").unwrap())],
    );
    let mut stream = Stream::new(whois::Queries::new());
    assert_eq!(stream.push(&bytes), whois::MAX_QUERY + 2);
    assert_eq!(stream.next(), Some(Ok(Err(whois::QueryError::TooLong))));
    let (items, failure) = drive(whois::Queries::new(), b"query\r", &[1]);
    assert!(items.is_empty());
    assert_eq!(failure, Some(Fail::Protocol(codec::LineError::Unterminated)));
    assert!(<whois::Query as Wire>::parse(b"one\nsecond\n").is_err());
    assert!(<whois::Query as Wire>::parse(b"unfinished").is_err());
    contract::check_decode(whois::Queries::new, b"query\r");
}

#[test]
fn whois_response_limit_preserves_the_legacy_flag() {
    for (bytes, truncated) in [(b"".as_slice(), false), (b"abc", false), (b"abcd", true), (b"abcdef", true)] {
        let expected = whois::CollectedResponse {
            response: whois::Response::new(&bytes[..bytes.len().min(3)]).unwrap(),
            truncated,
        };
        round_trip(|| whois::Responses::with_limit(3), bytes, &[expected]);
        contract::check_decode_with_held_limit(|| whois::Responses::with_limit(3), bytes, 3);
    }
    round_trip(
        || whois::Responses::with_limit(0),
        b"x",
        &[whois::CollectedResponse { response: whois::Response::default(), truncated: true }],
    );
    for size in [whois::MAX_RESPONSE, whois::MAX_RESPONSE + 1] {
        let bytes = vec![b'x'; size];
        let mut old = whois::ResponseDecoder::new();
        old.feed(&bytes);
        let truncated = old.truncated();
        let (items, failure) = drive(whois::Responses::new(), &bytes, &[7, 4096]);
        assert_eq!(failure, None);
        assert_eq!(items, [whois::CollectedResponse { response: old.finish(), truncated }]);
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
        extras: memcache::StoreExtras { flags: 3, expiration: 0 }.to_bytes().to_vec(),
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
        memcache::Command::Get { keys: vec![b"key".to_vec()], cas: true },
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
        memcache::Response::MetaValue { flags: vec![], data: vec![] },
    ];
    let bytes = written(&responses);
    round_trip(memcache::Responses::new, &bytes, &responses.map(Ok));
    let packets = [cache_packet(b"a\0\r\nb"), cache_packet(b"second")];
    let bytes = written(&packets);
    round_trip(memcache::Frames::new, &bytes, &packets);
}

#[test]
fn memcache_recoverable_lines_and_bad_counted_trailer() {
    round_trip(
        memcache::Commands::new,
        b"unknown\r\nversion\n",
        &[Err(memcache::Error::UnknownCommand), Ok(memcache::Command::Version)],
    );
    round_trip(
        memcache::Responses::new,
        b"unknown\r\nEND\n",
        &[Err(memcache::Error::UnknownCommand), Ok(memcache::Response::End)],
    );
    round_trip(
        memcache::Commands::new,
        b"set key 0 0 3\nabcXXversion\r\n",
        &[Err(memcache::Error::BadDataChunk), Ok(memcache::Command::Version)],
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
    let header = b"set key 0 0 4 noreply\r\n";
    let mut stream = Stream::new(memcache::Commands::with_limit(3));
    assert_eq!(stream.push(header), header.len());
    assert_eq!(stream.next(), Some(Ok(Err(memcache::Error::TooLarge(4)))));
    assert!(stream.decoder().quiet_error());
    assert_eq!(stream.held(), 0);
    pump(&mut stream, b"data\r\nversion\r\n", |item| assert_eq!(item, Ok(memcache::Command::Version)))
        .unwrap();
    finish(&mut stream, |_| panic!("unexpected item")).unwrap();
    round_trip(
        || memcache::Commands::with_limit(3),
        b"set key 0 0 4\r\ndata\r\nversion\r\n",
        &[Err(memcache::Error::TooLarge(4)), Ok(memcache::Command::Version)],
    );
    round_trip(
        || memcache::Responses::with_limit(3),
        b"VALUE key 0 4\r\ndata\r\nEND\r\n",
        &[Err(memcache::Error::TooLarge(4)), Ok(memcache::Response::End)],
    );
    let mut bytes = vec![b'x'; memcache::MAX_LINE];
    bytes.extend_from_slice(b"\r\nversion\r\n");
    contract::check_decode(memcache::Commands::new, &bytes);
    assert_eq!(
        drive(memcache::Commands::new(), &bytes, &[1]).1,
        Some(Fail::Protocol(memcache::TextFrameError::LineTooLong))
    );
    assert_eq!(
        drive(memcache::Responses::new(), &bytes, &[1]).1,
        Some(Fail::Protocol(memcache::TextFrameError::LineTooLong))
    );
    let mut header = [0; memcache::BINARY_HEADER_LEN];
    header[0] = memcache::REQUEST_MAGIC;
    header[8..12].copy_from_slice(&4u32.to_be_bytes());
    let mut binary = Stream::new(memcache::Frames::with_limit(3));
    assert_eq!(binary.push(&header), header.len());
    assert_eq!(binary.next(), Some(Err(Fail::Protocol(memcache::BinaryError::BodyLength(4)))));
    assert_eq!(binary.buffered(), memcache::BINARY_HEADER_LEN);
    assert_eq!(binary.held(), 0);
    assert!(binary.next().is_none());
    contract::check_decode(|| memcache::Frames::with_limit(3), &header);
}

#[test]
fn memcache_eof_inside_headers_bodies_trailers_and_skips() {
    for bytes in
        [b"version\r".as_slice(), b"set key 0 0 3\r\n", b"set key 0 0 3\r\nab", b"set key 0 0 3\r\nabc\r"]
    {
        contract::check_decode(memcache::Commands::new, bytes);
        assert_eq!(
            drive(memcache::Commands::new(), bytes, &[1]).1,
            Some(Fail::Protocol(memcache::TextFrameError::Incomplete))
        );
    }
    for bytes in [b"END\r".as_slice(), b"VALUE key 0 3\r\n", b"VALUE key 0 3\r\nabc\r"] {
        contract::check_decode(memcache::Responses::new, bytes);
        assert_eq!(
            drive(memcache::Responses::new(), bytes, &[1]).1,
            Some(Fail::Protocol(memcache::TextFrameError::Incomplete))
        );
    }
    let bytes = b"set key 0 0 4\r\nda";
    contract::check_decode(|| memcache::Commands::with_limit(3), bytes);
    assert_eq!(
        drive(memcache::Commands::with_limit(3), bytes, &[1]).1,
        Some(Fail::Protocol(memcache::TextFrameError::Incomplete))
    );
    let bytes = written(&[cache_packet(b"body")]);
    for cut in [1, 23, 24, bytes.len() - 1] {
        let (items, failure) = drive(memcache::Frames::new(), &bytes[..cut], &[1]);
        assert!(items.is_empty());
        assert_eq!(failure, Some(Fail::Truncated { unread: cut }));
    }
}

#[test]
fn memcache_multiget_uses_its_own_line_limit() {
    let command = memcache::Command::Get { keys: vec![b"key".to_vec(); memcache::MAX_LINE / 2], cas: true };
    let bytes = written(std::slice::from_ref(&command));
    assert!(bytes.len() > memcache::MAX_LINE);
    round_trip(memcache::Commands::new, &bytes, &[Ok(command)]);
    let mut long = b"get ".to_vec();
    long.resize(memcache::MAX_GET_LINE, b'x');
    let (items, failure) = drive(memcache::Commands::new(), &long, &[1]);
    assert!(items.is_empty());
    assert_eq!(failure, Some(Fail::Protocol(memcache::TextFrameError::LineTooLong)));
}

#[test]
fn memcache_wire_exactness_and_transactional_refusal() {
    let mut out = b"prefix".to_vec();
    let bad = memcache::Command::Get { keys: vec![b"bad key".to_vec()], cas: false };
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
        contract::check_decode(ftp::Commands::new, &bytes);
        contract::check_decode(ftp::Replies::new, &bytes);
        contract::check_decode(whois::Queries::new, &bytes);
        contract::check_decode(|| whois::Responses::with_limit(17), &bytes);
        contract::check_decode(memcache::Commands::new, &bytes);
        contract::check_decode(memcache::Responses::new, &bytes);
        contract::check_decode(|| memcache::Frames::with_limit(17), &bytes);
        contract::check_wire::<ftp::Command>(&bytes);
        contract::check_wire::<ftp::Reply>(&bytes);
        contract::check_wire::<whois::Query>(&bytes);
        contract::check_wire::<whois::Response>(&bytes);
        contract::check_wire::<memcache::Command>(&bytes);
        contract::check_wire::<memcache::Response>(&bytes);
        contract::check_wire::<memcache::Packet>(&bytes);
    }
    let source = b"set key 0 0 4\r\na\r\nb\r\nversion\r\n";
    for at in 0..source.len() {
        let mut bytes = source.to_vec();
        bytes[at] = rng.next() as u8;
        contract::check_decode(memcache::Commands::new, &bytes);
        contract::check_wire::<memcache::Command>(&bytes);
    }
}

#[test]
fn decoder_capacity_and_empty_eof() {
    assert_eq!(ftp::Commands::new().capacity(), ftp::MAX_LINE);
    assert_eq!(ftp::Replies::new().capacity(), ftp::MAX_LINE);
    assert_eq!(whois::Queries::new().capacity(), whois::MAX_QUERY + 2);
    assert_eq!(memcache::Frames::with_limit(usize::MAX).capacity(), memcache::MAX_BINARY_BUFFERED);
    assert_eq!(memcache::Responses::new().capacity(), memcache::MAX_LINE);
    assert_eq!(memcache::Commands::new().capacity(), memcache::MAX_LINE);
    assert_eq!(memcache::Frames::with_limit(0).decode(&[], true), Ok(Step::Need));
    round_trip(ftp::Commands::new, b"", &[]);
    round_trip(ftp::Replies::new, b"", &[]);
    round_trip(whois::Queries::new, b"", &[]);
    round_trip(
        whois::Responses::new,
        b"",
        &[whois::CollectedResponse { response: whois::Response::default(), truncated: false }],
    );
    round_trip(memcache::Commands::new, b"", &[]);
    round_trip(memcache::Responses::new, b"", &[]);
    round_trip(memcache::Frames::new, b"", &[]);
}

#[test]
fn memcache_long_line_crlf_crosses_the_input_window() {
    let command = memcache::Command::Get { keys: vec![b"a".to_vec(); 4094], cas: false };
    let bytes = written(std::slice::from_ref(&command));
    assert_eq!(bytes.len(), memcache::MAX_LINE + 1);
    assert_eq!(bytes[memcache::MAX_LINE - 1], b'\r');
    round_trip(memcache::Commands::new, &bytes, &[Ok(command)]);
    contract::check_decode_with_held_limit(memcache::Commands::new, &bytes, memcache::MAX_TEXT_HELD);
}
