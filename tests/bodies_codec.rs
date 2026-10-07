//! Session handoffs and bounded mail and print bodies through the codec driver.

use fictionet::stdlib::codec::{
    Collect, CollectError, Decode, Fail, Step, Stream, Wire, contract, pump,
    test_support::{chunks, decode_all},
};
use fictionet::stdlib::{imf, ipp, postgres as pg};

fn read<D: Decode + Clone>(decoder: D, bytes: &[u8]) -> Vec<D::Item>
where
    D::Error: Clone + core::fmt::Debug,
{
    let (items, failure) = decode_all(|| decoder.clone(), bytes);
    assert!(failure.is_none(), "{failure:?}");
    items
}

fn check<D: Decode>(make: impl Fn() -> D, bytes: &[u8])
where
    D::Error: Clone + PartialEq + core::fmt::Debug,
    D::Item: PartialEq + core::fmt::Debug,
{
    let capacity = make().capacity();
    contract::check_decode_with_held_limit(&make, bytes, 0);
    contract::check_decode_with_alloc_limit(make, bytes, 2 * capacity);
}

fn failure<D: Decode>(decoder: D, bytes: &[u8], eof: bool, expected: Fail<D::Error>)
where
    D::Error: Clone + PartialEq + core::fmt::Debug,
    D::Item: core::fmt::Debug,
{
    let mut stream = Stream::new(decoder);
    assert_eq!(stream.push(bytes), bytes.len());
    if eof {
        stream.end();
    }
    assert_eq!(stream.next().unwrap().unwrap_err(), expected);
    assert!(stream.is_done());
    assert_eq!(stream.failed(), Some(&expected));
    assert!(stream.next().is_none());
    assert_eq!(stream.unread(), bytes);
}

#[test]
fn postgres_frontend_and_backend_round_trips() {
    let frontend = vec![
        pg::Frontend::Startup(pg::Startup::new("alice", "mail")),
        pg::Frontend::Query("select 1".into()),
        pg::Frontend::Bind(pg::Bind::default()),
        pg::Frontend::Sync,
        pg::Frontend::Terminate,
    ];
    let mut bytes = Vec::new();
    for message in &frontend {
        message.write(&mut bytes).unwrap();
        contract::check_wire_value(message);
        contract::check_wire::<pg::Frontend>(&Wire::to_bytes(message).unwrap());
    }
    check(pg::FrontendMessages::new, &bytes);
    assert_eq!(
        read(pg::FrontendMessages::new(), &bytes),
        frontend.iter().cloned().map(Ok).collect::<Vec<_>>()
    );

    let backend = vec![
        pg::Backend::Authentication(pg::Authentication::Ok),
        pg::Backend::ParameterStatus {
            name: "client_encoding".into(),
            value: "UTF8".into(),
        },
        pg::Backend::DataRow(vec![Some(b"1".to_vec()), None]),
        pg::Backend::CommandComplete("SELECT 1".into()),
        pg::Backend::ReadyForQuery(pg::TransactionStatus::Idle),
    ];
    let mut bytes = Vec::new();
    for message in &backend {
        message.write(&mut bytes).unwrap();
        contract::check_wire_value(message);
        contract::check_wire::<pg::Backend>(&Wire::to_bytes(message).unwrap());
    }
    check(pg::BackendMessages::new, &bytes);
    assert_eq!(
        read(pg::BackendMessages::new(), &bytes),
        backend
            .iter()
            .cloned()
            .map(|m| Ok(pg::BackendEvent::Message(m)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn postgres_encryption_requests_end_with_exact_unread_transport_bytes() {
    for (request, reply) in [
        (pg::Frontend::SslRequest, pg::EncryptionReply::Ssl),
        (pg::Frontend::GssEncRequest, pg::EncryptionReply::Gss),
    ] {
        let trailing = b"\x16\x03\x03\0\x08\0\xffhello!";
        let mut bytes = Wire::to_bytes(&request).unwrap();
        let boundary = bytes.len();
        bytes.extend_from_slice(trailing);
        check(pg::FrontendMessages::new, &bytes);
        let mut stream = Stream::new(pg::FrontendMessages::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(Ok(request.clone()))));
        assert_eq!(stream.offset(), boundary as u64);
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        let (buffer, mut decoder) = stream.into_parts();
        assert_eq!(buffer.unread(), trailing);
        assert_eq!(buffer.offset(), boundary as u64);
        decoder.start_encryption();
        let startup = pg::Frontend::Startup(pg::Startup::new("u", "d"));
        assert_eq!(
            read(decoder, &Wire::to_bytes(&startup).unwrap()),
            [Ok(startup)]
        );

        // On the client, only the one-byte acceptance belongs to PostgreSQL.
        let make = || {
            let mut decoder = pg::BackendMessages::new();
            decoder.expect_encryption();
            decoder
        };
        let mut response = Wire::to_bytes(&reply).unwrap();
        response.extend_from_slice(trailing);
        check(make, &response);
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(&response), response.len());
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(pg::BackendEvent::Encryption(reply))))
        );
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        let (buffer, _) = stream.into_parts();
        assert_eq!(buffer.unread(), trailing);
        assert_eq!(buffer.offset(), 1);
    }
}

#[test]
fn postgres_refusal_resumes_startup_then_typed_messages() {
    let messages = vec![
        pg::Frontend::SslRequest,
        pg::Frontend::GssEncRequest,
        pg::Frontend::Startup(pg::Startup::new("u", "d")),
        pg::Frontend::Query("select 1".into()),
        pg::Frontend::Sync,
    ];
    let mut bytes = Vec::new();
    for message in &messages {
        message.write(&mut bytes).unwrap();
    }
    for pattern in [&[][..], &[1], &[3, 1, 11]] {
        for after_end in [false, true] {
            let mut stream = Stream::new(pg::FrontendMessages::new());
            let mut got = Vec::new();
            for part in chunks(&bytes, pattern) {
                assert_eq!(stream.push(part), part.len());
                assert_eq!(stream.held(), 0);
                assert!(stream.buffered() <= stream.decoder().capacity());
                while let Some(item) = stream.next() {
                    let message = item.unwrap().unwrap();
                    if matches!(
                        message,
                        pg::Frontend::SslRequest | pg::Frontend::GssEncRequest
                    ) {
                        if after_end {
                            assert_eq!(stream.next(), None);
                            assert!(stream.is_done());
                            let mut next = stream.decoder().clone();
                            next.refuse_encryption();
                            stream = stream.swap(next);
                        } else {
                            stream.decoder().refuse_encryption();
                        }
                    }
                    got.push(message);
                }
            }
            assert_eq!(stream.decoder().phase(), pg::Phase::Messages);
            stream.end();
            assert_eq!(stream.next(), None);
            assert!(stream.failed().is_none());
            assert_eq!(got, messages);
            assert_eq!(stream.offset(), bytes.len() as u64);
        }
    }

    let mut backend = Wire::to_bytes(&pg::EncryptionReply::Refused).unwrap();
    let ready = pg::Backend::ReadyForQuery(pg::TransactionStatus::Idle);
    ready.write(&mut backend).unwrap();
    let make = || {
        let mut d = pg::BackendMessages::new();
        d.expect_encryption();
        d
    };
    check(make, &backend);
    assert_eq!(
        read(make(), &backend),
        [
            Ok(pg::BackendEvent::Encryption(pg::EncryptionReply::Refused)),
            Ok(pg::BackendEvent::Message(ready)),
        ]
    );
}

#[test]
fn postgres_repeated_negotiation_and_direct_tls_keep_bytes() {
    let request = Wire::to_bytes(&pg::Frontend::SslRequest).unwrap();
    let bytes = [request.as_slice(), request.as_slice()].concat();
    let mut stream = Stream::new(pg::FrontendMessages::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert!(stream.next().unwrap().unwrap().is_ok());
    stream.decoder().refuse_encryption();
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(pg::Error::UnsupportedProtocol(
            pg::SSL_REQUEST_CODE
        ))))
    );
    assert_eq!(stream.unread(), request);
    assert_eq!(stream.next(), None);

    let hello = b"\x16\x03\x03\0\x03abc";
    let mut stream = Stream::new(pg::FrontendMessages::new());
    assert_eq!(stream.push(hello), hello.len());
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(pg::Error::DirectTls)))
    );
    let (buffer, mut decoder) = stream.into_parts();
    assert_eq!(buffer.unread(), hello);
    decoder.start_encryption();
    assert_eq!(
        decoder.decode(&request, false),
        Ok(Step::Item(Ok(pg::Frontend::SslRequest), request.len()))
    );
}

#[test]
fn postgres_cancel_and_terminate_end_at_the_item_boundary() {
    for (decoder, message) in [
        (
            pg::FrontendMessages::new(),
            pg::Frontend::CancelRequest {
                process_id: 1,
                secret_key: vec![2; 4],
            },
        ),
        (
            pg::FrontendMessages::established(64),
            pg::Frontend::Terminate,
        ),
    ] {
        let mut bytes = Wire::to_bytes(&message).unwrap();
        bytes.extend_from_slice(b"unread");
        let mut stream = Stream::new(decoder);
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(Ok(message))));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.into_parts().0.unread(), b"unread");
    }
}

#[test]
fn postgres_body_errors_are_items_and_framing_errors_end_once() {
    let mut bytes = b"Q\0\0\0\x05x".to_vec(); // Missing string terminator.
    pg::Frontend::Sync.write(&mut bytes).unwrap();
    check(|| pg::FrontendMessages::established(64), &bytes);
    assert_eq!(
        read(pg::FrontendMessages::established(64), &bytes),
        [
            Err(pg::Error::Malformed {
                tag: b'Q',
                reason: pg::Malformed::UnterminatedString
            }),
            Ok(pg::Frontend::Sync),
        ]
    );
    let mut bytes = b"Z\0\0\0\x05?".to_vec();
    pg::Backend::BindComplete.write(&mut bytes).unwrap();
    check(|| pg::BackendMessages::with_limit(64), &bytes);
    assert_eq!(
        read(pg::BackendMessages::with_limit(64), &bytes),
        [
            Err(pg::Error::Malformed {
                tag: b'Z',
                reason: pg::Malformed::BadStatus(b'?')
            }),
            Ok(pg::BackendEvent::Message(pg::Backend::BindComplete)),
        ]
    );
    failure(
        pg::FrontendMessages::established(64),
        b"?",
        false,
        Fail::Protocol(pg::Error::UnknownType(b'?')),
    );
    failure(
        pg::BackendMessages::new(),
        b"Z\0\0\0\x03",
        false,
        Fail::Protocol(pg::Error::BadLength(3)),
    );
    failure(
        pg::FrontendMessages::new(),
        b"\0\0\0\x07",
        false,
        Fail::Protocol(pg::Error::BadLength(7)),
    );
}

#[test]
fn postgres_limits_are_refused_from_headers_and_partial_units_truncate() {
    let startup = u32::try_from(pg::MAX_STARTUP + 5).unwrap().to_be_bytes();
    failure(
        pg::FrontendMessages::new(),
        &startup,
        false,
        Fail::Protocol(pg::Error::TooLong {
            length: pg::MAX_STARTUP as u32 + 5,
            max: pg::MAX_STARTUP + 4,
        }),
    );
    for frontend in [true, false] {
        let bytes = b"d\0\0\0\x41";
        let expected = Fail::Protocol(pg::Error::TooLong {
            length: 65,
            max: 64,
        });
        if frontend {
            failure(
                pg::FrontendMessages::established(64),
                bytes,
                false,
                expected,
            );
            check(|| pg::FrontendMessages::established(64), bytes);
        } else {
            failure(pg::BackendMessages::with_limit(64), bytes, false, expected);
            check(|| pg::BackendMessages::with_limit(64), bytes);
        }
    }
    failure(
        pg::FrontendMessages::new(),
        b"\0\0\0\x08\x04",
        true,
        Fail::Truncated { unread: 5 },
    );
    failure(
        pg::FrontendMessages::established(64),
        b"Q\0\0\0\x08ab",
        true,
        Fail::Truncated { unread: 7 },
    );
    failure(
        pg::BackendMessages::with_limit(64),
        b"Z\0\0\0",
        true,
        Fail::Truncated { unread: 4 },
    );
}

#[test]
fn postgres_modes_and_minimum_limit_are_explicit() {
    let frontend = pg::FrontendMessages::established(0);
    assert_eq!(frontend.limit(), 4);
    assert_eq!(frontend.phase(), pg::Phase::Messages);
    assert_eq!(
        read(frontend.clone(), b"S\0\0\0\x04"),
        [Ok(pg::Frontend::Sync)]
    );
    failure(
        frontend,
        b"C\0\0\0\x06",
        false,
        Fail::Protocol(pg::Error::TooLong { length: 6, max: 4 }),
    );

    let mut backend = pg::BackendMessages::new();
    backend.expect_encryption();
    let reply = pg::Backend::ErrorResponse(pg::Diagnostic::fatal(
        pg::sqlstate::PROTOCOL_VIOLATION,
        "SSL unsupported",
    ));
    failure(
        backend,
        &Wire::to_bytes(&reply).unwrap(),
        false,
        Fail::Protocol(pg::Error::UnknownType(b'E')),
    );
}

fn mail_header() -> imf::Header {
    let mut header = imf::Header::default();
    header.push("From", "a@example.test");
    header.push("Subject", "A mail message");
    header
}

// The world chooses an opaque body value and a collection budget.
#[derive(Debug, PartialEq, Eq)]
struct Body(Vec<u8>);
impl Wire for Body {
    type ParseError = core::convert::Infallible;
    type WriteError = core::convert::Infallible;
    /// Copies an opaque body. The collector enforces its size limit. Refuses no bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Self::ParseError> {
        Ok(Self(bytes.to_vec()))
    }
    /// Appends the body unchanged. Refuses no values.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}
const MAX_MAIL_BODY: usize = 16 * 1024 * 1024;

fn read_head_and_body<D: Decode>(
    decoder: D,
    bytes: &[u8],
    pattern: &[usize],
    limit: usize,
) -> (D::Item, Vec<u8>)
where
    D::Error: Clone + core::fmt::Debug,
    D::Item: core::fmt::Debug,
{
    let mut stream = Stream::new(decoder);
    let mut pieces = chunks(bytes, pattern);
    let mut pending = &[][..];
    let item = loop {
        if let Some(item) = stream.next() {
            break item.unwrap();
        }
        if pending.is_empty() {
            pending = pieces.next().expect("header boundary");
        }
        let took = stream.push(pending);
        assert!(took > 0);
        assert_eq!(stream.held(), 0);
        assert!(stream.buffered() <= stream.decoder().capacity());
        pending = &pending[took..];
    };
    assert!(stream.next().is_none());
    assert!(stream.is_done());
    let mut body = stream.swap(Collect::<Body>::new(limit));
    for part in core::iter::once(pending).chain(pieces) {
        assert_eq!(
            pump(&mut body, part, |_| panic!("body before EOF")).unwrap(),
            part.len()
        );
        assert_eq!(body.held(), 0);
        assert!(body.buffered() <= body.decoder().capacity());
    }
    body.end();
    let Body(bytes) = body.next().unwrap().unwrap();
    assert_eq!(body.next(), None);
    (item, bytes)
}

#[test]
fn imf_header_and_collected_body_round_trip() {
    let header = mail_header();
    let mut bytes = Wire::to_bytes(&header).unwrap();
    contract::check_wire::<imf::Header>(&bytes);
    contract::check_wire_value(&header);
    let body: Vec<u8> = (0..=255).cycle().take(1031).collect();
    bytes.extend_from_slice(&body);
    let make = || imf::Head::with_limit(128);
    check(make, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 59, 2, 83]] {
        assert_eq!(
            read_head_and_body(make(), &bytes, pattern, MAX_MAIL_BODY),
            (Ok(header.clone()), body.clone())
        );
    }
    assert_eq!(
        read(make(), &Wire::to_bytes(&header).unwrap()),
        [Ok(header)]
    );
}

#[test]
fn imf_bad_fields_are_items_and_header_limits_end_once() {
    let bytes = b"bad field\r\n\r\nbody";
    let make = || imf::Head::with_limit(32);
    check(make, bytes);
    for pattern in [&[][..], &[1], &[3, 7]] {
        assert_eq!(
            read_head_and_body(make(), bytes, pattern, MAX_MAIL_BODY),
            (Err(imf::Error::FieldName), b"body".to_vec())
        );
    }
    // Reaching the cap without a blank line refuses the header before
    // any body is read, including at EOF.
    let oversized = b"Subject: longxxx";
    check(|| imf::Head::with_limit(16), oversized);
    for eof in [false, true] {
        failure(
            imf::Head::with_limit(16),
            oversized,
            eof,
            Fail::Protocol(imf::Error::TooLarge),
        );
    }
}

fn print_head() -> ipp::Header {
    let mut message = ipp::Message::request(ipp::operation::PRINT_JOB, 42);
    message.add(
        ipp::tag::JOB_ATTRIBUTES,
        ipp::Attribute::new("copies", ipp::Value::Integer(2)),
    );
    message.add(
        ipp::tag::JOB_ATTRIBUTES,
        ipp::Attribute::new(
            "media-col",
            ipp::Value::Collection(vec![ipp::Attribute::new(
                "media-size",
                ipp::Value::Collection(vec![ipp::Attribute::new(
                    "x-dimension",
                    ipp::Value::Integer(21000),
                )]),
            )]),
        ),
    );
    ipp::Header::from(message)
}

#[test]
fn ipp_head_and_collected_document_round_trip() {
    let head = print_head();
    let mut bytes = Wire::to_bytes(&head).unwrap();
    contract::check_wire::<ipp::Header>(&bytes);
    contract::check_wire_value(&head);
    let document: Vec<u8> = (0..=255).rev().cycle().take(2057).collect();
    bytes.extend_from_slice(&document);
    let make = || ipp::Head::with_limit(512);
    check(make, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 2, 257]] {
        assert_eq!(
            read_head_and_body(make(), &bytes, pattern, ipp::MAX_DOCUMENT),
            (Ok(head.clone()), document.clone())
        );
    }
    assert_eq!(
        read(make(), &Wire::to_bytes(&head).unwrap()),
        [Ok(head)]
    );
}

#[test]
fn ipp_attribute_errors_carry_request_ids_and_bad_lengths_end_once() {
    let bytes = b"\x01\x01\0\x02\0\0\0\x07\0\x03document";
    let make = || ipp::Head::with_limit(64);
    check(make, bytes);
    let error = ipp::Error::BadRequest { request_id: 7, error: Box::new(ipp::Error::ReservedGroup) };
    for pattern in [&[][..], &[1], &[3, 7]] {
        assert_eq!(
            read_head_and_body(make(), bytes, pattern, ipp::MAX_DOCUMENT),
            (Err(error.clone()), b"document".to_vec())
        );
    }
    let bytes = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\0\0\x80\0";
    check(ipp::Head::new, bytes);
    failure(
        ipp::Head::new(),
        bytes,
        false,
        Fail::Protocol(ipp::FrameError::Length(0x8000)),
    );
}

#[test]
fn ipp_overlong_names_are_bad_request_items() {
    let mut bytes = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\x01\0".to_vec();
    let mut stream = Stream::new(ipp::Head::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), None);
    assert!(!stream.is_done());
    bytes.extend_from_slice(&[b'a'; ipp::MAX_NAME + 1]);
    bytes.extend_from_slice(b"\0\x01x\x03");
    assert_eq!(
        <ipp::Header as Wire>::parse(&bytes),
        Err(ipp::Error::BadName)
    );
    check(ipp::Head::new, &bytes);
    bytes.extend_from_slice(b"document");
    let error = ipp::Error::BadRequest { request_id: 7, error: Box::new(ipp::Error::BadName) };
    for pattern in [&[][..], &[1], &[3, 7]] {
        assert_eq!(
            read_head_and_body(ipp::Head::new(), &bytes, pattern, ipp::MAX_DOCUMENT),
            (Err(error.clone()), b"document".to_vec())
        );
    }
}

#[test]
fn ipp_limits_are_refused_from_attribute_headers_and_partial_heads_truncate() {
    let name = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\x01\0";
    failure(
        ipp::Head::new(),
        name,
        true,
        Fail::Truncated { unread: name.len() },
    );
    check(ipp::Head::new, name);
    let value = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\0\x01n\x7f\xff";
    failure(
        ipp::Head::with_limit(64),
        value,
        false,
        Fail::Protocol(ipp::FrameError::TooLong),
    );
    check(|| ipp::Head::with_limit(64), value);
    let truncated = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\0\x01n\0\x03a";
    failure(
        ipp::Head::new(),
        truncated,
        true,
        Fail::Truncated {
            unread: truncated.len(),
        },
    );
    let bytes = Wire::to_bytes(&print_head()).unwrap();
    for end in 0..bytes.len() {
        assert_eq!(
            <ipp::Header as Wire>::parse(&bytes[..end]),
            Err(ipp::Error::Truncated)
        );
    }
}

#[test]
fn swapped_document_collection_enforces_its_limit() {
    const DOCUMENT_LIMIT: usize = 4;
    const _: () = assert!(DOCUMENT_LIMIT < ipp::MAX_DOCUMENT);
    for (document, accepted) in [(b"".as_slice(), true), (b"four", true), (b"extra", false)] {
        let mut bytes = Wire::to_bytes(&print_head()).unwrap();
        bytes.extend_from_slice(document);
        let mut stream = Stream::new(ipp::Head::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        stream.end();
        assert!(stream.next().unwrap().unwrap().is_ok());
        assert_eq!(stream.next(), None);
        let mut body = stream.swap(Collect::<Body>::new(DOCUMENT_LIMIT));
        if accepted {
            assert_eq!(body.next(), Some(Ok(Body(document.to_vec()))));
        } else {
            let error = Fail::Protocol(CollectError::TooLong {
                limit: DOCUMENT_LIMIT,
            });
            assert_eq!(body.next(), Some(Err(error.clone())));
            assert_eq!(body.failed(), Some(&error));
            assert_eq!(body.unread(), document);
        }
        assert_eq!(body.next(), None);
    }
}

#[test]
fn strict_writers_reject_lossy_values_without_changing_the_destination() {
    let mut out = b"prefix".to_vec();
    for value in [
        pg::Frontend::Query("a\0b".into()),
        pg::Frontend::CancelRequest {
            process_id: 1,
            secret_key: vec![],
        },
    ] {
        contract::check_wire_value(&value);
        assert!(value.write(&mut out).is_err());
        assert_eq!(out, b"prefix");
    }
    let backend = pg::Backend::ParameterStatus {
        name: "a\0b".into(),
        value: "v".into(),
    };
    contract::check_wire_value(&backend);
    assert!(backend.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    let mut header = mail_header();
    header.push("Subject", " leading");
    contract::check_wire_value(&header);
    assert!(header.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    let mut head = print_head();
    head.groups.push(ipp::Group {
        tag: 0,
        attributes: vec![],
    });
    contract::check_wire_value(&head);
    assert!(head.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    head.groups.pop();
    head.groups.push(ipp::Group {
        tag: ipp::tag::JOB_ATTRIBUTES,
        attributes: vec![ipp::Attribute::new(
            "huge",
            ipp::Value::OctetString(vec![0; ipp::MAX_FIELD + 1]),
        )],
    });
    contract::check_wire_value(&head);
    assert!(head.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
}

#[test]
fn wire_parsers_require_exact_units() {
    for message in [pg::Frontend::SslRequest, pg::Frontend::Query("q".into())] {
        let mut bytes = Wire::to_bytes(&message).unwrap();
        bytes.push(0);
        assert_eq!(
            <pg::Frontend as Wire>::parse(&bytes),
            Err(pg::ParseError::Trailing)
        );
    }
    let mut bytes = Wire::to_bytes(&mail_header()).unwrap();
    bytes.push(0);
    assert_eq!(
        <imf::Header as Wire>::parse(&bytes),
        Err(imf::Error::Trailing)
    );
    let mut bytes = Wire::to_bytes(&print_head()).unwrap();
    bytes.push(0);
    assert_eq!(
        <ipp::Header as Wire>::parse(&bytes),
        Err(ipp::Error::Trailing)
    );
}

fn check_line_handoff<D: Decode>(stream: Stream<D>, boundary: usize) {
    use fictionet::stdlib::codec::{Ending, Lines};
    let mut lines = stream.swap(Lines::new(6, Ending::Crlf));
    assert_eq!(lines.offset(), boundary as u64);
    for (line, raw) in [
        (b"first".as_slice(), b"first\r\n".as_slice()),
        (b"second", b"second\r\n"),
    ] {
        let at = lines.offset();
        assert_eq!(
            lines.with_next(|item, bytes, span| {
                assert_eq!(bytes, raw);
                assert_eq!(span, at..at + raw.len() as u64);
                item
            }),
            Some(Ok(Ok(line.to_vec())))
        );
    }
    // EOF survives swap even when the unread suffix exceeds the new capacity.
    assert_eq!(lines.next(), None);
    assert!(lines.is_done());
    assert!(lines.unread().is_empty());
    assert_eq!(lines.offset(), (boundary + 15) as u64);
}

#[test]
fn body_handoffs_preserve_eof_offsets_and_exact_bytes_through_swap() {
    let mut bytes = Wire::to_bytes(&mail_header()).unwrap();
    let boundary = bytes.len();
    bytes.extend_from_slice(b"first\r\nsecond\r\n");
    let mut stream = Stream::new(imf::Head::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    stream.end();
    assert!(matches!(stream.next(), Some(Ok(Ok(_)))));
    assert_eq!(stream.next(), None);
    check_line_handoff(stream, boundary);

    let mut bytes = Wire::to_bytes(&print_head()).unwrap();
    let boundary = bytes.len();
    bytes.extend_from_slice(b"first\r\nsecond\r\n");
    let mut stream = Stream::new(ipp::Head::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    stream.end();
    assert!(matches!(stream.next(), Some(Ok(Ok(_)))));
    assert_eq!(stream.next(), None);
    check_line_handoff(stream, boundary);
}

#[test]
fn exact_and_minimum_header_limits_make_progress() {
    let header = mail_header();
    let bytes = Wire::to_bytes(&header).unwrap();
    let make = || imf::Head::with_limit(bytes.len());
    check(make, &bytes);
    assert_eq!(read(make(), &bytes), [Ok(header)]);
    let head = print_head();
    let bytes = Wire::to_bytes(&head).unwrap();
    let make = || ipp::Head::with_limit(bytes.len());
    check(make, &bytes);
    assert_eq!(read(make(), &bytes), [Ok(head)]);
    check(|| imf::Head::with_limit(0), b"\nbody");
    check(
        || ipp::Head::with_limit(0),
        b"\x01\x01\0\x02\0\0\0\x07\x03body",
    );
    assert_eq!(
        imf::Head::with_limit(usize::MAX).capacity(),
        imf::MAX_HEADER_BYTES
    );
    assert_eq!(ipp::Head::with_limit(usize::MAX).capacity(), ipp::MAX_HEAD);
    assert!(
        pg::FrontendMessages::with_limit(usize::MAX).capacity()
            <= fictionet::stdlib::codec::Buffer::MAX_LIMIT
    );
}

#[test]
fn malformed_startup_body_ends_the_stream_once() {
    let mut bytes = b"\0\0\0\x09\0\x03\0\0x".to_vec();
    let startup = pg::Frontend::Startup(pg::Startup::new("u", "d"));
    startup.write(&mut bytes).unwrap();
    check(pg::FrontendMessages::new, &bytes);
    failure(
        pg::FrontendMessages::new(),
        &bytes,
        false,
        Fail::Protocol(pg::Error::Malformed {
            tag: 0,
            reason: pg::Malformed::UnterminatedString,
        }),
    );
}

#[test]
fn imf_header_only_at_eof_matches_split_message() {
    for bytes in [
        b"Subject: hi\r\n".as_slice(),
        b"Subject: hi\r\nFrom: a@b.test\r\n",
        b"Subject: hi\r\nFrom: a@b.example\r\n",
        b"Subject: incomplete\r\n",
    ] {
        check(imf::Head::new, bytes);
        let (header, body) = imf::split_message(bytes).unwrap();
        assert!(body.is_empty());
        assert_eq!(read(imf::Head::new(), bytes), [Ok(header)]);
    }
}

#[test]
fn imf_head_ends_unconditionally_with_body_unread() {
    let bytes = b"Subject: hi\r\n\r\nbody";
    let mut stream = Stream::new(imf::Head::new());
    assert_eq!(stream.push(bytes), bytes.len());
    assert!(matches!(stream.next(), Some(Ok(Ok(_)))));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.unread(), b"body");
}

#[test]
fn ipp_head_ends_unconditionally_with_document_unread() {
    let bytes = b"\x01\x01\0\x02\0\0\0\x07\x03document";
    let mut stream = Stream::new(ipp::Head::new());
    assert_eq!(stream.push(bytes), bytes.len());
    assert!(matches!(stream.next(), Some(Ok(Ok(_)))));
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    assert_eq!(stream.unread(), b"document");
}

#[test]
fn malformed_startup_requests_end_the_stream_once() {
    let mut cases = vec![
        (
            b"\0\0\0\x09\x04\xd2\x16\x2f\0".to_vec(),
            pg::Malformed::TrailingBytes,
        ),
        (
            b"\0\0\0\x09\x04\xd2\x16\x30\0".to_vec(),
            pg::Malformed::TrailingBytes,
        ),
    ];
    for length in [0, pg::MAX_SECRET_KEY + 1] {
        let mut bytes = u32::try_from(12 + length).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(&pg::CANCEL_REQUEST_CODE.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.resize(12 + length, 0);
        cases.push((bytes, pg::Malformed::BadKeyLength(length)));
    }
    for (mut bytes, reason) in cases {
        pg::Frontend::Startup(pg::Startup::new("u", "d"))
            .write(&mut bytes)
            .unwrap();
        failure(
            pg::FrontendMessages::new(),
            &bytes,
            false,
            Fail::Protocol(pg::Error::Malformed { tag: 0, reason }),
        );
    }
}

#[test]
fn empty_heads_end_cleanly_without_an_item() {
    assert!(read(imf::Head::new(), b"").is_empty());
    assert!(read(ipp::Head::new(), b"").is_empty());
    assert_eq!(
        read(imf::Head::new(), b"\r\n"),
        [Ok(imf::Header::default())]
    );
    assert_eq!(
        read(imf::Head::new(), b"bad field"),
        [Err(imf::Error::FieldName)]
    );
}
