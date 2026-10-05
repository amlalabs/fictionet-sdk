//! Session handoffs and bounded mail and print bodies through the codec driver.

use fictionet::stdlib::codec::{Decode, Fail, Step, Stream, Wire, contract, finish, pump, test_support::chunks};
use fictionet::stdlib::{imf, ipp, postgres as pg};

fn read<D: Decode>(decoder: D, bytes: &[u8], pattern: &[usize]) -> Vec<D::Item>
where
    D::Error: Clone + core::fmt::Debug,
{
    let capacity = decoder.capacity();
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    for part in chunks(bytes, pattern) {
        assert_eq!(pump(&mut stream, part, |item| items.push(item)).unwrap(), part.len());
        assert!(stream.buffered() <= capacity);
        assert_eq!(stream.held(), 0);
    }
    finish(&mut stream, |item| items.push(item)).unwrap();
    assert!(stream.is_done());
    assert!(stream.failed().is_none());
    assert!(stream.next().is_none());
    items
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
fn postgres_frontend_and_backend_chunked_round_trips() {
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
    contract::check_stack(pg::FrontendMessages::new, &bytes);
    for pattern in [&[][..], &[1], &[2, 3, 1, 7, 37]] {
        assert_eq!(
            read(pg::FrontendMessages::new(), &bytes, pattern),
            frontend.iter().cloned().map(Ok).collect::<Vec<_>>()
        );
    }

    let backend = vec![
        pg::Backend::Authentication(pg::Authentication::Ok),
        pg::Backend::ParameterStatus { name: "client_encoding".into(), value: "UTF8".into() },
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
    contract::check_stack(pg::BackendMessages::new, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 2, 47]] {
        assert_eq!(
            read(pg::BackendMessages::new(), &bytes, pattern),
            backend.iter().cloned().map(|m| Ok(pg::BackendEvent::Message(m))).collect::<Vec<_>>()
        );
    }
}

#[test]
fn postgres_encryption_requests_end_with_exact_unread_transport_bytes() {
    for (request, reply) in
        [(pg::Frontend::SslRequest, pg::EncryptionReply::Ssl), (pg::Frontend::GssEncRequest, pg::EncryptionReply::Gss)]
    {
        let trailing = b"\x16\x03\x03\0\x08\0\xffhello!";
        let mut bytes = Wire::to_bytes(&request).unwrap();
        let boundary = bytes.len();
        bytes.extend_from_slice(trailing);
        contract::check_decode(pg::FrontendMessages::new, &bytes);
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
        assert_eq!(read(decoder, &Wire::to_bytes(&startup).unwrap(), &[1]), [Ok(startup)]);

        // On the client, only the one-byte acceptance belongs to PostgreSQL.
        let make = || {
            let mut decoder = pg::BackendMessages::new();
            decoder.expect_encryption();
            decoder
        };
        let mut response = Wire::to_bytes(&reply).unwrap();
        response.extend_from_slice(trailing);
        contract::check_decode(make, &response);
        let mut stream = Stream::new(make());
        assert_eq!(stream.push(&response), response.len());
        assert_eq!(stream.next(), Some(Ok(Ok(pg::BackendEvent::Encryption(reply)))));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        let (buffer, _) = stream.into_parts();
        assert_eq!(buffer.unread(), trailing);
        assert_eq!(buffer.offset(), 1);
    }
}

// World policy: refuse each encryption request before asking for another item.
struct RefusedFrontend(pg::FrontendMessages);
impl Decode for RefusedFrontend {
    type Item = Result<pg::Frontend, pg::Error>;
    type Error = pg::Error;
    const NAME: &'static str = "test PostgreSQL refusal";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.0.decode(bytes, eof)?;
        if matches!(step, Step::Item(Ok(pg::Frontend::SslRequest | pg::Frontend::GssEncRequest), _)) {
            self.0.refuse_encryption();
        }
        Ok(step)
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
    let make = || RefusedFrontend(pg::FrontendMessages::new());
    contract::check_stack(make, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 11]] {
        assert_eq!(read(make(), &bytes, pattern), messages.iter().cloned().map(Ok).collect::<Vec<_>>());
    }

    // A decision made after observing End resumes through swap, with the
    // negotiation history and the exact buffered startup suffix intact.
    let mut stream = Stream::new(pg::FrontendMessages::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    for request in [pg::Frontend::SslRequest, pg::Frontend::GssEncRequest] {
        assert_eq!(stream.next(), Some(Ok(Ok(request))));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        let mut next = stream.decoder().clone();
        next.refuse_encryption();
        stream = stream.swap(next);
    }
    for message in messages.iter().skip(2) {
        assert_eq!(stream.next(), Some(Ok(Ok(message.clone()))));
    }
    assert_eq!(stream.decoder().phase(), pg::Phase::Messages);
    stream.end();
    assert_eq!(stream.next(), None);
    assert_eq!(stream.offset(), bytes.len() as u64);

    let mut backend = Wire::to_bytes(&pg::EncryptionReply::Refused).unwrap();
    let ready = pg::Backend::ReadyForQuery(pg::TransactionStatus::Idle);
    ready.write(&mut backend).unwrap();
    let make = || {
        let mut d = pg::BackendMessages::new();
        d.expect_encryption();
        d
    };
    contract::check_decode(make, &backend);
    assert_eq!(
        read(make(), &backend, &[1]),
        [Ok(pg::BackendEvent::Encryption(pg::EncryptionReply::Refused)), Ok(pg::BackendEvent::Message(ready)),]
    );
}

#[test]
fn postgres_repeated_negotiation_and_direct_tls_keep_bytes() {
    let request = Wire::to_bytes(&pg::Frontend::SslRequest).unwrap();
    let bytes = [request.as_slice(), request.as_slice()].concat();
    contract::check_decode(|| RefusedFrontend(pg::FrontendMessages::new()), &bytes);
    let mut stream = Stream::new(pg::FrontendMessages::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert!(stream.next().unwrap().unwrap().is_ok());
    stream.decoder().refuse_encryption();
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(pg::Error::UnsupportedProtocol(pg::SSL_REQUEST_CODE)))));
    assert_eq!(stream.unread(), request);
    assert_eq!(stream.next(), None);

    let hello = b"\x16\x03\x03\0\x03abc";
    let mut stream = Stream::new(pg::FrontendMessages::new());
    assert_eq!(stream.push(hello), hello.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(pg::Error::DirectTls))));
    let (buffer, mut decoder) = stream.into_parts();
    assert_eq!(buffer.unread(), hello);
    decoder.start_encryption();
    assert_eq!(decoder.decode(&request, false), Ok(Step::Item(Ok(pg::Frontend::SslRequest), request.len())));
}

#[test]
fn postgres_cancel_and_terminate_end_at_the_item_boundary() {
    for (decoder, message) in [
        (pg::FrontendMessages::new(), pg::Frontend::CancelRequest { process_id: 1, secret_key: vec![2; 4] }),
        (pg::FrontendMessages::typed(64), pg::Frontend::Terminate),
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
    contract::check_decode(|| pg::FrontendMessages::typed(64), &bytes);
    assert_eq!(
        read(pg::FrontendMessages::typed(64), &bytes, &[1]),
        [Err(pg::Error::Malformed { tag: b'Q', reason: pg::Malformed::UnterminatedString }), Ok(pg::Frontend::Sync),]
    );
    let mut bytes = b"Z\0\0\0\x05?".to_vec();
    pg::Backend::BindComplete.write(&mut bytes).unwrap();
    contract::check_decode(|| pg::BackendMessages::with_limit(64), &bytes);
    assert_eq!(
        read(pg::BackendMessages::with_limit(64), &bytes, &[1]),
        [
            Err(pg::Error::Malformed { tag: b'Z', reason: pg::Malformed::BadStatus(b'?') }),
            Ok(pg::BackendEvent::Message(pg::Backend::BindComplete)),
        ]
    );
    failure(pg::FrontendMessages::typed(64), b"?", false, Fail::Protocol(pg::Error::UnknownType(b'?')));
    failure(pg::BackendMessages::new(), b"Z\0\0\0\x03", false, Fail::Protocol(pg::Error::BadLength(3)));
    failure(pg::FrontendMessages::new(), b"\0\0\0\x07", false, Fail::Protocol(pg::Error::BadLength(7)));
}

#[test]
fn postgres_limits_are_refused_from_headers_and_partial_units_truncate() {
    let startup = u32::try_from(pg::MAX_STARTUP + 5).unwrap().to_be_bytes();
    failure(
        pg::FrontendMessages::new(),
        &startup,
        false,
        Fail::Protocol(pg::Error::TooLong { length: pg::MAX_STARTUP as u32 + 5, max: pg::MAX_STARTUP + 4 }),
    );
    for frontend in [true, false] {
        let bytes = b"d\0\0\0\x41";
        let expected = Fail::Protocol(pg::Error::TooLong { length: 65, max: 64 });
        if frontend {
            failure(pg::FrontendMessages::typed(64), bytes, false, expected);
            contract::check_decode(|| pg::FrontendMessages::typed(64), bytes);
        } else {
            failure(pg::BackendMessages::with_limit(64), bytes, false, expected);
            contract::check_decode(|| pg::BackendMessages::with_limit(64), bytes);
        }
    }
    failure(pg::FrontendMessages::new(), b"\0\0\0\x08\x04", true, Fail::Truncated { unread: 5 });
    failure(pg::FrontendMessages::typed(64), b"Q\0\0\0\x08ab", true, Fail::Truncated { unread: 7 });
    failure(pg::BackendMessages::with_limit(64), b"Z\0\0\0", true, Fail::Truncated { unread: 4 });
}

fn mail_header() -> imf::Header {
    let mut header = imf::Header::default();
    header.push("From", "a@example.test");
    header.push("Subject", "A mail message");
    header
}

#[test]
fn imf_header_and_body_chunked_round_trip() {
    let header = mail_header();
    let mut bytes = Wire::to_bytes(&header).unwrap();
    contract::check_wire::<imf::Header>(&bytes);
    contract::check_wire_value(&header);
    let body: Vec<u8> = (0..=255).cycle().take(1031).collect();
    bytes.extend_from_slice(&body);
    let make = || imf::Messages::with_limits(128, 7);
    contract::check_stack(make, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 59, 2, 83]] {
        let items = read(make(), &bytes, pattern);
        assert_eq!(items.first(), Some(&imf::Event::Header(Ok(header.clone()))));
        let mut got = Vec::new();
        for item in items.into_iter().skip(1) {
            let imf::Event::Body(part) = item else { panic!("second header") };
            assert!(!part.is_empty() && part.len() <= 7);
            got.extend(part);
        }
        assert_eq!(got, body);
    }
    assert_eq!(read(make(), &Wire::to_bytes(&header).unwrap(), &[1]), [imf::Event::Header(Ok(header))]);
}

#[test]
fn imf_can_handoff_the_body_after_its_header() {
    let mut stream = Stream::new(imf::Messages::new());
    let bytes = b"Subject: mail\r\n\r\n\0body\xff";
    assert_eq!(stream.push(bytes), bytes.len());
    assert!(matches!(stream.next(), Some(Ok(imf::Event::Header(Ok(_))))));
    stream.decoder().handoff_body();
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    let (buffer, _) = stream.into_parts();
    assert_eq!(buffer.unread(), b"\0body\xff");
}

#[test]
fn imf_bad_fields_are_items_but_a_header_without_a_boundary_fails() {
    let bytes = b"bad field\r\n\r\nbody";
    contract::check_decode(|| imf::Messages::with_limits(32, 3), bytes);
    assert_eq!(
        read(imf::Messages::with_limits(32, 3), bytes, &[1]),
        [
            imf::Event::Header(Err(imf::Error::FieldName)),
            imf::Event::Body(b"bod".to_vec()),
            imf::Event::Body(b"y".to_vec()),
        ]
    );
    // IMF has no declared header length. Reaching the cap without a blank
    // line refuses the header before any body is read.
    let oversized = b"Subject: longxxx";
    contract::check_decode(|| imf::Messages::with_limits(16, 3), oversized);
    failure(imf::Messages::with_limits(16, 3), oversized, false, Fail::Protocol(imf::Error::TooLarge));
    failure(imf::Messages::new(), b"Subject: incomplete\r\n", true, Fail::Truncated { unread: 21 });
}

fn print_head() -> ipp::Head {
    let mut message = ipp::Message::request(ipp::operation::PRINT_JOB, 42);
    message.add(ipp::tag::JOB_ATTRIBUTES, ipp::Attribute::new("copies", ipp::Value::Integer(2)));
    message.add(
        ipp::tag::JOB_ATTRIBUTES,
        ipp::Attribute::new(
            "media-col",
            ipp::Value::Collection(vec![ipp::Attribute::new(
                "media-size",
                ipp::Value::Collection(vec![ipp::Attribute::new("x-dimension", ipp::Value::Integer(21000))]),
            )]),
        ),
    );
    ipp::Head { version: message.version, code: message.code, request_id: message.request_id, groups: message.groups }
}

#[test]
fn ipp_head_and_document_chunked_round_trip() {
    let head = print_head();
    let mut bytes = Wire::to_bytes(&head).unwrap();
    contract::check_wire::<ipp::Head>(&bytes);
    contract::check_wire_value(&head);
    let document: Vec<u8> = (0..=255).rev().cycle().take(2057).collect();
    bytes.extend_from_slice(&document);
    let make = || ipp::Messages::with_limits(512, 11);
    contract::check_stack(make, &bytes);
    for pattern in [&[][..], &[1], &[3, 1, 2, 257]] {
        let items = read(make(), &bytes, pattern);
        assert_eq!(items.first(), Some(&ipp::Event::Head(Ok(head.clone()))));
        let mut got = Vec::new();
        for item in items.into_iter().skip(1) {
            let ipp::Event::Data(part) = item else { panic!("second head") };
            assert!(!part.is_empty() && part.len() <= 11);
            got.extend(part);
        }
        assert_eq!(got, document);
    }
    assert_eq!(read(make(), &Wire::to_bytes(&head).unwrap(), &[1]), [ipp::Event::Head(Ok(head))]);
}

#[test]
fn ipp_can_handoff_the_document_after_its_head() {
    let mut bytes = Wire::to_bytes(&print_head()).unwrap();
    let used = bytes.len();
    bytes.extend_from_slice(b"%PDF-1.7\n\0\xff");
    let mut stream = Stream::new(ipp::Messages::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    assert!(matches!(stream.next(), Some(Ok(ipp::Event::Head(Ok(_))))));
    stream.decoder().handoff_data();
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
    let (buffer, _) = stream.into_parts();
    assert_eq!(buffer.unread(), &bytes[used..]);
    assert_eq!(buffer.offset(), used as u64);
}

#[test]
fn ipp_attribute_errors_are_items_and_bad_lengths_end_once() {
    let bytes = b"\x01\x01\0\x02\0\0\0\x07\0\x03document";
    contract::check_decode(|| ipp::Messages::with_limits(64, 5), bytes);
    assert_eq!(
        read(ipp::Messages::with_limits(64, 5), bytes, &[1]),
        [
            ipp::Event::Head(Err(ipp::Error::ReservedGroup)),
            ipp::Event::Data(b"docum".to_vec()),
            ipp::Event::Data(b"ent".to_vec()),
        ]
    );
    let bytes = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\0\0\x80\0";
    contract::check_decode(ipp::Messages::new, bytes);
    failure(ipp::Messages::new(), bytes, false, Fail::Protocol(ipp::Error::Length(0x8000)));
}

#[test]
fn ipp_limits_are_refused_from_attribute_headers_and_partial_heads_truncate() {
    let name = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\x01\0";
    failure(ipp::Messages::new(), name, false, Fail::Protocol(ipp::Error::BadName));
    contract::check_decode(ipp::Messages::new, name);
    let value = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\0\x01n\x7f\xff";
    failure(ipp::Messages::with_limits(64, 3), value, false, Fail::Protocol(ipp::Error::TooLong));
    contract::check_decode(|| ipp::Messages::with_limits(64, 3), value);
    let truncated = b"\x01\x01\0\x02\0\0\0\x07\x01\x41\0\x01n\0\x03a";
    failure(ipp::Messages::new(), truncated, true, Fail::Truncated { unread: truncated.len() });
}

#[test]
fn strict_writers_reject_lossy_values_without_changing_the_destination() {
    let mut out = b"prefix".to_vec();
    for value in [pg::Frontend::Query("a\0b".into()), pg::Frontend::CancelRequest { process_id: 1, secret_key: vec![] }]
    {
        contract::check_wire_value(&value);
        assert!(value.write(&mut out).is_err());
        assert_eq!(out, b"prefix");
    }
    let backend = pg::Backend::ParameterStatus { name: "a\0b".into(), value: "v".into() };
    contract::check_wire_value(&backend);
    assert!(backend.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    let mut header = mail_header();
    header.push("Subject", " leading");
    contract::check_wire_value(&header);
    assert!(header.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    let mut head = print_head();
    head.groups.push(ipp::Group { tag: 0, attributes: vec![] });
    contract::check_wire_value(&head);
    assert!(head.write(&mut out).is_err());
    assert_eq!(out, b"prefix");
    head.groups.pop();
    head.groups.push(ipp::Group {
        tag: ipp::tag::JOB_ATTRIBUTES,
        attributes: vec![ipp::Attribute::new("huge", ipp::Value::OctetString(vec![0; ipp::MAX_FIELD + 1]))],
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
        assert_eq!(<pg::Frontend as Wire>::parse(&bytes), Err(pg::ParseError::Trailing));
    }
    let mut bytes = Wire::to_bytes(&mail_header()).unwrap();
    bytes.push(0);
    assert_eq!(<imf::Header as Wire>::parse(&bytes), Err(imf::ParseError::Trailing));
    let mut bytes = Wire::to_bytes(&print_head()).unwrap();
    bytes.push(0);
    assert_eq!(<ipp::Head as Wire>::parse(&bytes), Err(ipp::ParseError::Trailing));
}

fn check_line_handoff<D: Decode>(stream: Stream<D>, boundary: usize) {
    use fictionet::stdlib::codec::{Ending, Lines};
    let mut lines = stream.swap(Lines::new(6, Ending::Crlf));
    assert_eq!(lines.offset(), boundary as u64);
    for (line, raw) in [(b"first".as_slice(), b"first\r\n".as_slice()), (b"second", b"second\r\n")] {
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
    let mut stream = Stream::new(imf::Messages::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    stream.end();
    assert!(matches!(stream.next(), Some(Ok(imf::Event::Header(Ok(_))))));
    stream.decoder().handoff_body();
    assert_eq!(stream.next(), None);
    check_line_handoff(stream, boundary);

    let mut bytes = Wire::to_bytes(&print_head()).unwrap();
    let boundary = bytes.len();
    bytes.extend_from_slice(b"first\r\nsecond\r\n");
    let mut stream = Stream::new(ipp::Messages::new());
    assert_eq!(stream.push(&bytes), bytes.len());
    stream.end();
    assert!(matches!(stream.next(), Some(Ok(ipp::Event::Head(Ok(_))))));
    stream.decoder().handoff_data();
    assert_eq!(stream.next(), None);
    check_line_handoff(stream, boundary);
}

#[test]
fn exact_header_limits_and_minimum_chunk_sizes_make_progress() {
    let header = mail_header();
    let bytes = Wire::to_bytes(&header).unwrap();
    let make = || imf::Messages::with_limits(bytes.len(), 0);
    contract::check_decode(make, &bytes);
    assert_eq!(read(make(), &bytes, &[1]), [imf::Event::Header(Ok(header))]);
    let head = print_head();
    let bytes = Wire::to_bytes(&head).unwrap();
    let make = || ipp::Messages::with_limits(bytes.len(), 0);
    contract::check_decode(make, &bytes);
    assert_eq!(read(make(), &bytes, &[1]), [ipp::Event::Head(Ok(head))]);
    contract::check_decode(|| imf::Messages::with_limits(0, 0), b"\nbody");
    contract::check_decode(|| ipp::Messages::with_limits(0, 0), b"\x01\x01\0\x02\0\0\0\x07\x03body");
    assert_eq!(imf::Messages::with_limits(usize::MAX, usize::MAX).capacity(), imf::MAX_HEADER_BYTES);
    assert_eq!(ipp::Messages::with_limits(usize::MAX, usize::MAX).capacity(), ipp::MAX_HEAD);
    assert!(pg::FrontendMessages::with_limit(usize::MAX).capacity() <= fictionet::stdlib::codec::Buffer::MAX_LIMIT);
}

#[test]
fn malformed_startup_body_is_an_item_with_a_known_next_boundary() {
    let mut bytes = b"\0\0\0\x09\0\x03\0\0x".to_vec();
    let startup = pg::Frontend::Startup(pg::Startup::new("u", "d"));
    startup.write(&mut bytes).unwrap();
    contract::check_decode(pg::FrontendMessages::new, &bytes);
    assert_eq!(
        read(pg::FrontendMessages::new(), &bytes, &[1]),
        [Err(pg::Error::Malformed { tag: 0, reason: pg::Malformed::UnterminatedString }), Ok(startup),]
    );
}
