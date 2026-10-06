use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire, contract, finish, pump};
use fictionet::stdlib::{json, mime_multipart as mime, protobuf, urlencoded_form as form, xml};
use std::fmt::Debug;
use fictionet::stdlib::codec::Lcg;
use fictionet::stdlib::codec::test_support::{decode_all, mutate};

fn check<D: Decode>(make: impl Fn() -> D, input: &[u8])
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + Debug + PartialEq,
{
    let allocation = 2 * make().capacity();
    contract::check_decode_with_alloc_limit(&make, input, allocation);
    for cut in 0..=input.len().min(256) {
        contract::check_decode_with_alloc_limit(&make, &input[..cut], allocation);
    }
}

#[test]
fn multipart_body_for_http_form_data() {
    let body = mime::Body {
        boundary: "upload".into(),
        multipart: mime::Multipart {
            parts: vec![mime::Part::field("name", "Alice").unwrap()],
            ..mime::Multipart::default()
        },
    };
    let bytes = body.to_bytes().unwrap();
    assert_eq!(
        bytes,
        b"--upload\r\nContent-Disposition: form-data; name=name\r\n\r\nAlice\r\n--upload--\r\n"
    );
    let header = mime::content_type("form-data", &body.boundary).unwrap();
    let header = String::from_utf8(header.to_bytes().unwrap()).unwrap();
    assert_eq!(
        mime::Multipart::parse(&bytes, &mime::boundary(&header).unwrap()),
        Ok(body.multipart.clone())
    );
    assert_eq!(mime::Body::parse(&bytes), Ok(body.clone()));
    contract::check_wire_value(&body);
}

#[test]
fn multipart_body_boundaries_and_refusals() {
    for input in [
        b"--b--".as_slice(),
        b"--b-- \t\r\nepilogue",
        b"--b \t\r\n\r\npart\r\n--b--\r\nepilogue",
        b"--b----\r\nepilogue",
    ] {
        let body = mime::Body::parse(input).unwrap();
        assert!(body.multipart.preamble.is_empty());
        contract::check_wire_value(&body);
        contract::check_wire::<mime::Body>(input);
    }
    for input in [b"preamble\r\n--b--".as_slice(), b"--b\r\n\r\npart"] {
        assert!(mime::Body::parse(input).is_err());
        contract::check_wire::<mime::Body>(input);
    }
    let mut body = mime::Body {
        boundary: "b".into(),
        multipart: mime::Multipart {
            preamble: b"preamble".to_vec(),
            ..mime::Multipart::default()
        },
    };
    let mut out = b"keep".to_vec();
    assert_eq!(body.write(&mut out), Err(mime::WriteError::Unwritable));
    assert_eq!(out, b"keep");
    body.multipart.preamble.clear();
    body.multipart.parts.push(mime::Part::default());
    body.boundary = "b--".into();
    assert_eq!(body.write(&mut out), Err(mime::WriteError::Unwritable));
    assert_eq!(out, b"keep");
    contract::check_wire_value(&body);
    body.boundary = "b".into();
    body.multipart.parts[0].body = b"--b".to_vec();
    assert_eq!(body.write(&mut out), Err(mime::WriteError::BoundaryInData));
    assert_eq!(out, b"keep");
    contract::check_wire_value(&body);
}

#[test]
fn json_chunked_round_trip_and_eof() {
    let bytes = br#" {"method":"echo","params":["hi",2]} [true,null] "last" 12.5"#;
    check(json::Values::new, bytes);
    let (values, error) = decode_all(json::Values::new, bytes);
    assert_eq!(error, None);
    assert_eq!(values.len(), 4);
    let mut written = Vec::new();
    for value in &values {
        let one = Wire::to_bytes(value).unwrap();
        contract::check_wire::<json::Value>(&one);
        assert_eq!(<json::Value as Wire>::parse(&one).as_ref(), Ok(value));
        Wire::write(value, &mut written).unwrap();
        written.push(b' ');
    }
    assert_eq!(decode_all(json::Values::new, &written), (values, None));
    for partial in [b"tru".as_slice(), b"1e-", b"-", b"[1", b"\"abc"] {
        assert_eq!(
            decode_all(json::Values::new, partial).1,
            Some(Fail::Truncated { unread: partial.len() })
        );
    }
    assert!(matches!(
        decode_all(json::Values::new, b"{} [x]").1,
        Some(Fail::Protocol(json::Error {
            kind: json::ErrorKind::UnexpectedByte(b'x'),
            ..
        }))
    ));
}

#[test]
fn json_rejects_oversize_at_named_capacity() {
    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.decoder().capacity(), json::MAX_SIZE + 1);
    let mut bytes = vec![b'a'; json::MAX_SIZE + 2];
    bytes[0] = b'"';
    assert_eq!(stream.push(&bytes), json::MAX_SIZE + 1);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(json::Error {
            kind: json::ErrorKind::TooLarge,
            offset: json::MAX_SIZE,
        })))
    );
    assert!(stream.next().is_none());
    let exact = json::Value::String("a".repeat(json::MAX_SIZE - 2));
    let bytes = Wire::to_bytes(&exact).unwrap();
    assert_eq!(
        decode_all(json::Values::new, &bytes),
        (vec![exact], None)
    );
}

#[test]
fn json_eof_preserves_scalar_limit_errors() {
    for bytes in [b"true".as_slice(), b"12", b"null"] {
        let limits = json::Limits {
            elements: 0,
            ..json::Limits::default()
        };
        assert!(matches!(
            decode_all(|| json::Values::with_limits(limits), bytes).1,
            Some(Fail::Protocol(json::Error {
                kind: json::ErrorKind::TooManyElements,
                ..
            }))
        ));
    }
}

#[test]
fn json_scalar_delimiter_errors() {
    for (input, byte, offset) in [
        (b"tru}".as_slice(), b'}', 3),
        (b"[0] fals]", b']', 8),
        (b"nul,", b',', 3),
        (b"tr ", b' ', 2),
    ] {
        check(json::Values::new, input);
        assert_eq!(decode_all(json::Values::new, input).1,
            Some(Fail::Protocol(json::Error { kind: json::ErrorKind::UnexpectedByte(byte), offset })));
    }
}

#[test]
fn json_depth_errors() {
    let mut nested = b"[1".to_vec();
    nested.extend_from_slice(&[b'['; 128]);
    for (input, limits) in [
        (nested, json::Limits::default()),
        (b"{{".to_vec(), json::Limits { depth: 1, ..json::Limits::default() }),
    ] {
        let expected = json::parse_with(&input, &limits).unwrap_err();
        assert_eq!(
            decode_all(|| json::Values::with_limits(limits), &input).1,
            Some(Fail::Protocol(expected))
        );
        check(|| json::Values::with_limits(limits), &input);
    }
}

#[test]
fn json_zero_depth_precedes_zero_size() {
    let limits = json::Limits { depth: 0, size: 0, ..json::Limits::default() };
    let expected = json::Error { kind: json::ErrorKind::TooDeep, offset: 0 };
    assert_eq!(
        decode_all(|| json::Values::with_limits(limits), b"[").1,
        Some(Fail::Protocol(expected))
    );
    check(|| json::Values::with_limits(limits), b"[");
}

#[test]
fn form_stream_accepts_expanding_replacement_text() {
    let mut input = b"a=".to_vec();
    input.extend(vec![0xff; 200_000]);
    let expected = vec![form::Field(("a".into(), "�".repeat(200_000)))];
    let (fields, error) = decode_all(form::Fields::new, &input);
    assert_eq!(error, None);
    assert!(fields == expected);
    assert_eq!(
        <form::Field as Wire>::parse(&input),
        Err(form::FieldError::Form(form::FormError::TooLong))
    );
}

#[test]
fn multipart_skips_preamble_without_buffering_it() {
    let mut stream = Stream::new(mime::Parts::new("b").unwrap());
    for _ in 0..32 {
        pump(&mut stream, &[b'x'; 4096], |_| panic!("no part yet")).unwrap();
        assert_eq!(stream.buffered(), 0);
    }
    // A candidate boundary stays unread until its suffix arrives.
    pump(&mut stream, b"\r\n--b", |_| panic!("no part yet")).unwrap();
    assert_eq!(stream.unread(), b"\r\n--b");
    pump(&mut stream, b"--\r\n", |_| panic!("no part yet")).unwrap();
    finish(&mut stream, |_| panic!("no parts")).unwrap();
}

#[test]
fn multipart_preamble_padding_with_crlf_contract() {
    let mut input = b"x\r\n--a".to_vec();
    input.extend_from_slice(&[b' '; 65]);
    input.extend_from_slice(b"\r\n");
    check(|| mime::Parts::new("a").unwrap(), &input);
}

#[test]
fn multipart_preamble_padding_without_crlf_contract() {
    let mut input = b"x\r\n--a".to_vec();
    input.extend_from_slice(&[b' '; 65]);
    check(|| mime::Parts::new("a").unwrap(), &input);
}

#[test]
fn multipart_preamble_over_limit_with_boundary_contract() {
    let mut input = vec![b'x'; mime::MAX_PART + 10];
    input.extend_from_slice(b"\r\n--b--\r\n");
    check(|| mime::Parts::new("b").unwrap(), &input);
}

#[test]
fn multipart_preamble_over_limit_without_boundary_contract() {
    let input = vec![b'p'; mime::MAX_PART + 10];
    check(|| mime::Parts::new("a").unwrap(), &input);
}

#[test]
fn multipart_preamble_fuzz_crash_contract() {
    let mut input = b"\r\n--=a  \r\n--a".to_vec();
    input.extend_from_slice(&[b'\t'; 17]);
    input.extend_from_slice(&[b' '; 27]);
    input.extend_from_slice(&[b'\t'; 3]);
    input.extend_from_slice(&[b' '; 20]);
    input.extend_from_slice(&[b'\t'; 2]);
    // The fuzz target uses 0x0d % 8 candidate bytes as the boundary.
    // They start with LF, so it falls back to "a" and drops only 0x0d.
    assert!(!mime::valid_boundary(std::str::from_utf8(&input[1..6]).unwrap()));
    check(|| mime::Parts::new("a").unwrap(), &input[1..]);
}

#[test]
fn multipart_preamble_keeps_limits_and_line_boundaries() {
    let make = || mime::Parts::new("b").unwrap();
    // A delimiter may start the body or follow CR LF, never a skipped byte.
    for input in [
        b"x--b--\r\n".as_slice(),
        b"x--b\r\n\r\nignored\r\n--b--\r\n",
        b"x\r\n--bx\r\n--b\r\n\r\nbody\r\n--b--\r\n",
        b"x\r\n--b-- \t",
    ] {
            check(make, input);
        match mime::Multipart::parse(input, "b") {
            Ok(body) => assert_eq!(decode_all(make, input), (body.parts, None)),
            Err(_) => assert!(decode_all(make, input).1.is_some()),
        }
    }
    for size in [mime::MAX_PART, mime::MAX_PART + 1] {
        let mut input = vec![b'x'; size];
        input.extend_from_slice(b"\r\n--b--\r\n");
        let error = decode_all(make, &input).1;
        if size == mime::MAX_PART {
            assert_eq!(error, None);
        } else {
            assert_eq!(error, Some(Fail::Protocol(mime::Error::TooLong)));
        }
    }
}

#[test]
fn document_streams_distinguish_empty_from_unfinished() {
    assert_eq!(decode_all(xml::Events::new, b""), (vec![], None));
    assert_eq!(
        xml::Document::parse(b"").unwrap_err().kind,
        xml::ErrorKind::UnexpectedEnd
    );
    for input in [b" ".as_slice(), b"<?xml version='1.0'?>", b"<r>"] {
        assert!(matches!(
            decode_all(xml::Events::new, input).1,
            Some(Fail::Protocol(xml::Error {
                kind: xml::ErrorKind::UnexpectedEnd,
                ..
            }))
        ));
    }
    let make = || mime::Parts::new("b").unwrap();
    assert_eq!(decode_all(make, b""), (vec![], None));
    assert_eq!(
        mime::Multipart::parse(b"", "b"),
        Err(mime::Error::Truncated)
    );
    for input in [b"hello".as_slice(), b"--b\r\n"] {
        assert_eq!(
            decode_all(make, input).1,
            Some(Fail::Protocol(mime::Error::Truncated))
        );
    }
}

#[test]
fn grpc_composes_with_protobuf_messages() {
    use fictionet::stdlib::grpc;
    let message = protobuf::Message {
        fields: vec![protobuf::Field { number: 1, value: protobuf::Value::Varint(1) }],
    };
    let frame = grpc::Message { compressed: false, data: message.to_bytes().unwrap() };
    let bytes = Wire::to_bytes(&frame).unwrap();
    check(grpc::Messages::new, &bytes);
    let (items, error) = decode_all(|| grpc::Messages::new().map(|frame| protobuf::Message::parse(&frame.data)), &bytes);
    assert_eq!(items, [Ok(message)]);
    assert_eq!(error, None);
}

#[test]
fn xml_chunked_round_trip_and_eof() {
    let bytes = br#"<?xml version="1.0"?><!DOCTYPE r [<!ATTLIST r n CDATA "v">]><r xmlns:p="urn:p"><p:c/>text&amp;more</r><!--tail--> "#;
    check(xml::Events::new, bytes);
    contract::check_wire::<xml::Document>(bytes);
    let expected = xml::Document::parse(bytes).unwrap().events().unwrap();
    assert_eq!(decode_all(xml::Events::new, bytes), (expected.clone(), None));
    let frame = <xml::Document as Wire>::parse(bytes).unwrap();
    let encoded = Wire::to_bytes(&frame).unwrap();
    assert_eq!(encoded, bytes);
    assert_eq!(decode_all(xml::Events::new, &encoded), (expected, None));
    assert!(<xml::Document as Wire>::parse(b"<r/><s/>").is_err());
    assert!(matches!(
        decode_all(xml::Events::new, b"<!--unfinished").1,
        Some(Fail::Truncated { .. })
    ));
    let (events, error) = decode_all(xml::Events::new, b"<r>final text");
    assert_eq!(events.last(), Some(&xml::Event::Text("final text".into())));
    assert!(matches!(
        error,
        Some(Fail::Protocol(xml::Error {
            kind: xml::ErrorKind::UnexpectedEnd,
            ..
        }))
    ));
    assert!(matches!(
        decode_all(xml::Events::new, b"<r><").1,
        Some(Fail::Protocol(xml::Error {
            kind: xml::ErrorKind::UnexpectedEnd,
            ..
        }))
    ));
}

#[test]
fn xml_rejects_oversize_at_named_capacity() {
    let mut stream = Stream::new(xml::Events::new());
    assert_eq!(stream.decoder().capacity(), xml::MAX_DOCUMENT + 1);
    let mut bytes = b"<!--".to_vec();
    bytes.resize(xml::MAX_DOCUMENT + 2, b'a');
    assert_eq!(stream.push(&bytes), xml::MAX_DOCUMENT + 1);
    assert!(matches!(
        stream.next(),
        Some(Err(Fail::Protocol(xml::Error {
            kind: xml::ErrorKind::TooLarge,
            ..
        })))
    ));
    assert!(stream.next().is_none());
}

#[test]
fn form_chunked_round_trip_and_eof() {
    let bytes = b"&name=Alice+Smith&&x=%E2%82%AC&flag&last=%";
    check(form::Fields::new, bytes);
    let expected: Vec<_> = form::Form::parse(bytes)
        .unwrap().pairs
        .into_iter()
        .map(form::Field)
        .collect();
    assert_eq!(decode_all(form::Fields::new, bytes), (expected.clone(), None));
    let mut written = Vec::new();
    for frame in &expected {
        let one = Wire::to_bytes(frame).unwrap();
        contract::check_wire::<form::Field>(&one);
        assert_eq!(<form::Field as Wire>::parse(&one).as_ref(), Ok(frame));
        if !written.is_empty() {
            written.push(b'&');
        }
        frame.write(&mut written).unwrap();
    }
    assert_eq!(decode_all(form::Fields::new, &written), (expected, None));
    assert_eq!(
        <form::Field as Wire>::parse(b"a=b&c=d"),
        Err(form::FieldError::Trailing)
    );
    assert_eq!(
        <form::Field as Wire>::parse(b""),
        Err(form::FieldError::Empty)
    );
    // Malformed escapes are complete fields under the form grammar.
    assert_eq!(
        decode_all(form::Fields::new, b"a=%A"),
        (vec![form::Field(("a".into(), "%A".into()))], None)
    );
}

#[test]
fn form_rejects_oversize_at_named_capacity() {
    let mut stream = Stream::new(form::Fields::new());
    assert_eq!(stream.decoder().capacity(), form::MAX_INPUT + 1);
    assert_eq!(
        stream.push(&vec![b'a'; form::MAX_INPUT + 2]),
        form::MAX_INPUT + 1
    );
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(form::FieldError::Form(
            form::FormError::TooLong
        ))))
    );
    assert!(stream.next().is_none());
}

fn multipart() -> mime::Multipart {
    mime::Multipart {
        preamble: b"preamble".to_vec(),
        parts: vec![
            mime::Part::field("name", b"Alice".to_vec()).unwrap(),
            mime::Part::default(),
        ],
        epilogue: b"epilogue".to_vec(),
    }
}

#[test]
fn multipart_chunked_round_trip_and_eof() {
    let body = multipart();
    let entity = body.clone().with_boundary("boundary").to_bytes().unwrap();
    let bytes = entity_body(&entity);
    let make = || mime::Parts::new("boundary").unwrap();
    check(make, bytes);
    assert_eq!(decode_all(make, bytes), (body.parts.clone(), None));
    let mut parts = Vec::new();
    for part in &body.parts {
        let one = Wire::to_bytes(part).unwrap();
        contract::check_wire::<mime::Part>(&one);
        parts.push(<mime::Part as Wire>::parse(&one).unwrap());
    }
    let rewritten = mime::Multipart {
        parts,
        ..mime::Multipart::default()
    }
    .with_boundary("boundary").to_bytes()
    .unwrap();
    assert_eq!(decode_all(make, entity_body(&rewritten)), (body.parts, None));
    for bytes in [b"--boundary--".as_slice(), b"--boundary-- \t"] {
        assert_eq!(decode_all(make, bytes), (vec![], None));
    }
    let bytes = b"--boundary\r\n\r\nlast\r\n--boundary--";
    assert_eq!(
        decode_all(make, bytes),
        (
            vec![mime::Part {
                body: b"last".to_vec(),
                ..mime::Part::default()
            }],
            None
        )
    );
    assert_eq!(
        decode_all(make, b"--boundary\r\n\r\nlast").1,
        Some(Fail::Protocol(mime::Error::Truncated))
    );
    assert!(matches!(
        decode_all(make, b"--boundary\r\nX: value").1,
        Some(Fail::Truncated { .. })
    ));
}

#[test]
fn multipart_header_errors_before_body_ends() {
    let mut too_many = b"--b\r\n".to_vec();
    for _ in 0..=mime::MAX_HEADERS {
        too_many.extend_from_slice(b"X: a\r\n");
    }
    too_many.extend_from_slice(b"\r\nunterminated");
    for (input, expected) in [
        (b"\r\n--b\r\n\r\r\n\r\n\xff a\r\n\xff\r\n\r".as_slice(), mime::Error::Header),
        (too_many.as_slice(), mime::Error::TooManyHeaders),
    ] {
        assert_eq!(mime::Multipart::parse(input, "b"), Err(expected));
        let make = || mime::Parts::new("b").unwrap();
        let mut stream = Stream::new(make());
        assert_eq!(
            pump(&mut stream, input, |_| panic!("invalid headers")),
            Err(Fail::Protocol(expected))
        );
        assert_eq!(decode_all(make, input), (vec![], Some(Fail::Protocol(expected))));
        check(make, input);
    }
}

#[test]
fn multipart_generated_bodies() {
    let starts: &[&[u8]] = &[
        b"preamble",
        b"--b\r\n",
        b"x\r\n--b\r\n\r\n",
        b"--b\r\nX: a\r\n folded\r\n\r\n",
    ];
    let tokens: &[&[u8]] = &[
        b"X: a\r\n", b"\r\n", b"x", b"\r", b"\n", b"--b", b"--b--",
        b"\t", b"\xff", b":", b" ", b"\r\n--b\r\n", b"\r\n--b--\r\n",
    ];
    let mut rng = Lcg::new(0x726f756e6432);
    for _ in 0..2000 {
        let mut input = starts[rng.index(starts.len())].to_vec();
        for _ in 0..rng.index(40) {
            input.extend_from_slice(tokens[rng.index(tokens.len())]);
        }
        check(|| mime::Parts::new("b").unwrap(), &input);
        let expected = mime::Multipart::parse(&input, "b").map(|body| body.parts);
        let (parts, error) = decode_all(|| mime::Parts::new("b").unwrap(), &input);
        let actual = match error {
            None => Ok(parts),
            Some(Fail::Protocol(e)) => Err(e),
            Some(Fail::Truncated { .. }) => Err(mime::Error::Truncated),
            Some(e) => panic!("{e:?}"),
        };
        assert_eq!(actual, expected, "input {input:?}");
    }
}

#[test]
fn multipart_parsed_headers_are_held_until_the_part_ends() {
    let mut stream = Stream::new(mime::Parts::new("b").unwrap());
    let initial = stream.held();
    pump(&mut stream, b"--b\r\nX: value\r\n\r\n", |_| panic!("no part yet")).unwrap();
    assert_eq!(stream.held(), initial + "X".len() + "value".len());
    pump(&mut stream, b"body", |_| panic!("no part yet")).unwrap();
    let mut parts = Vec::new();
    pump(&mut stream, b"\r\n--b--\r\n", |part| parts.push(part)).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].headers.get("x"), Some("value"));
    assert_eq!(parts[0].body, b"body");
    assert_eq!(stream.held(), initial);
    finish(&mut stream, |_| panic!("no more parts")).unwrap();
}

#[test]
fn multipart_rejects_oversize_at_named_capacity() {
    let mut stream = Stream::new(mime::Parts::new("b").unwrap());
    let capacity = mime::MAX_PART + mime::MAX_BOUNDARY_LINE + 1;
    assert_eq!(stream.decoder().capacity(), capacity);
    pump(&mut stream, b"--b\r\n", |_| panic!("no part yet")).unwrap();
    let mut bytes = b"\r\n".to_vec();
    bytes.resize(capacity + 1, b'x');
    assert_eq!(stream.push(&bytes), capacity);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(mime::Error::TooLong)))
    );
    assert!(stream.next().is_none());
}

#[test]
fn protobuf_round_trip_and_eof() {
    let message = protobuf::Message {
        fields: vec![protobuf::Field { number: 1, value: protobuf::Value::Varint(150) }],
    };
    let frame = protobuf::Frame::from_message(&message).unwrap();
    contract::check_wire_value(&message);
    contract::check_wire_value(&frame);
    let bytes = Wire::to_bytes(&frame).unwrap();
    check(protobuf::Frames::new, &bytes);
    for cut in 1..bytes.len() {
        assert!(matches!(decode_all(protobuf::Frames::new, &bytes[..cut]).1,
            Some(Fail::Truncated { .. })));
    }
    assert_eq!(decode_all(protobuf::Frames::new, &bytes), (vec![frame], None));
    let mut batch = bytes.clone();
    protobuf::Frame { data: vec![0] }.write(&mut batch).unwrap();
    batch.extend_from_slice(&bytes);
    let make = || protobuf::Frames::new().map(|f| protobuf::Message::parse(&f.data));
    check(make, &batch);
    assert_eq!(decode_all(make, &batch), (vec![Ok(message.clone()),
        Err(protobuf::Error::FieldNumber(0)), Ok(message)], None));
    assert_eq!(protobuf::Frame::parse(&batch), Err(protobuf::Error::Trailing { remaining: batch.len() - bytes.len() }));
}

#[test]
fn protobuf_rejects_oversize_at_named_capacity() {
    let mut stream = Stream::new(protobuf::Frames::new());
    assert_eq!(stream.decoder().capacity(), protobuf::MAX_MESSAGE + protobuf::MAX_VARINT_LEN);
    let bytes = protobuf::Varint((protobuf::MAX_MESSAGE + 1) as u64).to_bytes().unwrap();
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(protobuf::Error::TooLong))));
    assert!(stream.next().is_none());
}

#[test]
fn strict_writers_leave_existing_output_unchanged() {
    contract::check_wire_value(&json::Value::String("a".repeat(json::MAX_SIZE)));
    contract::check_wire_value(&xml::Document {
        data: b"<a>".to_vec(),
    });
    contract::check_wire_value(&form::Field((" ".repeat(form::MAX_INPUT), "x".into())));
    contract::check_wire_value(&mime::Part {
        headers: mime::Headers {
            fields: vec![("bad:name".into(), "x".into())],
        },
        body: vec![],
    });
    contract::check_wire_value(&protobuf::Frame { data: vec![0; protobuf::MAX_MESSAGE + 1] });
    contract::check_wire_value(&protobuf::Message {
        fields: vec![protobuf::Field {
            number: 0,
            value: protobuf::Value::Varint(0),
        }],
    });
}

#[test]
fn contracts_on_malformed_and_mutated_inputs() {
    let seeds: &[&[u8]] = &[
        b"",
        b"{} [1,2] false",
        b"<r xmlns:p='urn:p'><p:c/>text</r>",
        b"--b\r\nX: value\r\n\r\nbody\r\n--b--\r\n",
        b"a=%FF&b=x",
        b"\x00\x00\x00\x00\x02\x08\x01",
        b"\x02\x08\x01",
    ];
    let mut rng = Lcg::new(0xfeed);
    for seed in seeds {
        for _ in 0..16 {
            let mut bytes = seed.to_vec();
            mutate(&mut rng, &mut bytes);
            check(json::Values::new, &bytes);
            check(xml::Events::new, &bytes);
            check(form::Fields::new, &bytes);
            check(|| mime::Parts::new("b").unwrap(), &bytes);
            check(protobuf::Frames::new, &bytes);
            contract::check_wire::<json::Value>(&bytes);
            contract::check_wire::<xml::Document>(&bytes);
            contract::check_wire::<form::Field>(&bytes);
            contract::check_wire::<mime::Part>(&bytes);
            contract::check_wire::<protobuf::Frame>(&bytes);
            contract::check_wire::<protobuf::Varint>(&bytes);
            contract::check_wire::<form::Form>(&bytes);
            contract::check_wire::<form::PercentEncoded>(&bytes);
            contract::check_wire::<mime::Entity>(&bytes);
            contract::check_wire::<mime::ParamValue>(&bytes);
            contract::check_wire::<protobuf::Message>(&bytes);
        }
    }
}

#[test]
fn content_limits_accept_complete_units_at_the_limit() {
    let field = form::Field(("a".repeat(form::MAX_INPUT - 1), String::new()));
    let bytes = Wire::to_bytes(&field).unwrap();
    assert_eq!(bytes.len(), form::MAX_INPUT);
    assert_eq!(
        decode_all(form::Fields::new, &bytes),
        (vec![field], None)
    );

    let mut bytes = b"<r>".to_vec();
    bytes.resize(xml::MAX_DOCUMENT - 4, b'x');
    bytes.extend_from_slice(b"</r>");
    assert_eq!(bytes.len(), xml::MAX_DOCUMENT);
    let (events, error) = decode_all(xml::Events::new, &bytes);
    assert_eq!(events.len(), 3);
    assert_eq!(error, None);

    let part = mime::Part {
        body: vec![b'x'; mime::MAX_PART - 2],
        ..mime::Part::default()
    };
    assert_eq!(Wire::to_bytes(&part).unwrap().len(), mime::MAX_PART);
    let boundary = "b".repeat(mime::MAX_BOUNDARY);
    let body = mime::Multipart {
        parts: vec![part.clone()],
        ..mime::Multipart::default()
    };
    let entity = body.with_boundary(boundary.clone()).to_bytes().unwrap();
    let bytes = entity_body(&entity);
    assert_eq!(
        decode_all(|| mime::Parts::new(&boundary).unwrap(), bytes),
        (vec![part], None)
    );
}

fn entity_body(bytes: &[u8]) -> &[u8] {
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    &bytes[end..]
}
