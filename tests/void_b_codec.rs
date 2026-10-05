use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire, contract, finish, pump};
use fictionet::stdlib::{json, mime_multipart as mime, protobuf, urlencoded_form as form, xml};
use std::fmt::Debug;

fn run<D: Decode>(decoder: D, input: &[u8], chunk: usize) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Error: Clone + Debug + PartialEq,
{
    let capacity = decoder.capacity();
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    let mut failure = None;
    for bytes in input.chunks(chunk.max(1)) {
        if let Err(e) = pump(&mut stream, bytes, |item| items.push(item)) {
            failure = Some(e);
            break;
        }
        assert!(stream.buffered() <= capacity);
    }
    if failure.is_none() {
        failure = finish(&mut stream, |item| items.push(item)).err();
    }
    assert!(stream.is_done());
    assert_eq!(stream.failed(), failure.as_ref());
    assert!(stream.next().is_none());
    (items, failure)
}

fn prefixes<D: Decode>(make: impl Fn() -> D, input: &[u8])
where
    D::Item: PartialEq + Debug,
    D::Error: Clone + Debug + PartialEq,
{
    for cut in 0..=input.len() {
        let prefix = &input[..cut];
        assert_eq!(
            run(make(), prefix, input.len()),
            run(make(), prefix, 1),
            "prefix {cut}"
        );
    }
}

#[test]
fn json_chunked_round_trip_and_eof() {
    let bytes = br#" {"method":"echo","params":["hi",2]} [true,null] "last" 12.5"#;
    contract::check_stack(json::Values::new, bytes);
    prefixes(json::Values::new, bytes);
    let (values, error) = run(json::Values::new(), bytes, 1);
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
    assert_eq!(run(json::Values::new(), &written, 3), (values, None));
    for partial in [b"tru".as_slice(), b"1e-", b"-", b"[1", b"\"abc"] {
        assert!(matches!(
            run(json::Values::new(), partial, 1).1,
            Some(Fail::Truncated { .. })
        ));
    }
    assert!(matches!(
        run(json::Values::new(), b"{} [x]", 1).1,
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
        run(json::Values::new(), &bytes, bytes.len()),
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
            run(json::Values::with_limits(limits), bytes, 1).1,
            Some(Fail::Protocol(json::Error {
                kind: json::ErrorKind::TooManyElements,
                ..
            }))
        ));
    }
}

#[test]
#[allow(deprecated)]
fn json_scalar_delimiter_errors_match_legacy() {
    for input in [b"tru}".as_slice(), b"[0] fals]", b"nul,", b"tr "] {
        let mut legacy = json::Decoder::new();
        legacy.feed(input);
        let expected = loop {
            if let Err(error) = legacy.next_value().expect("delimiter completes the scalar") {
                break error;
            }
        };
        for chunk in [1, input.len()] {
            assert_eq!(
                run(json::Values::new(), input, chunk).1,
                Some(Fail::Protocol(expected))
            );
        }
    }
}

#[test]
fn form_stream_accepts_expanding_replacement_text() {
    let mut input = b"a=".to_vec();
    input.extend(vec![0xff; 200_000]);
    let expected: Vec<_> = form::parse(&input)
        .unwrap()
        .into_iter()
        .map(form::Field)
        .collect();
    let (fields, error) = run(form::Fields::new(), &input, 4096);
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
fn multipart_preamble_keeps_limits_and_line_boundaries() {
    let make = || mime::Parts::new("b").unwrap();
    // A delimiter may start the body or follow CR LF, never a skipped byte.
    for input in [
        b"x--b--\r\n".as_slice(),
        b"x--b\r\n\r\nignored\r\n--b--\r\n",
        b"x\r\n--bx\r\n--b\r\n\r\nbody\r\n--b--\r\n",
        b"x\r\n--b-- \t",
    ] {
        prefixes(make, input);
        contract::check_decode(make, input);
        match mime::Multipart::parse(input, "b") {
            Ok(body) => assert_eq!(run(make(), input, 1), (body.parts, None)),
            Err(_) => assert!(run(make(), input, 1).1.is_some()),
        }
    }
    for size in [mime::MAX_PART, mime::MAX_PART + 1] {
        let mut input = vec![b'x'; size];
        input.extend_from_slice(b"\r\n--b--\r\n");
        let error = run(make(), &input, 4096).1;
        if size == mime::MAX_PART {
            assert_eq!(error, None);
        } else {
            assert_eq!(error, Some(Fail::Protocol(mime::Error::TooLong)));
        }
    }
}

#[test]
fn document_streams_distinguish_empty_from_unfinished() {
    assert_eq!(run(xml::Events::new(), b"", 1), (vec![], None));
    assert_eq!(
        xml::parse(b"").unwrap_err().kind,
        xml::ErrorKind::UnexpectedEnd
    );
    for input in [b" ".as_slice(), b"<?xml version='1.0'?>", b"<r>"] {
        assert!(matches!(
            run(xml::Events::new(), input, 1).1,
            Some(Fail::Protocol(xml::Error {
                kind: xml::ErrorKind::UnexpectedEnd,
                ..
            }))
        ));
    }
    let make = || mime::Parts::new("b").unwrap();
    assert_eq!(run(make(), b"", 1), (vec![], None));
    assert_eq!(
        mime::Multipart::parse(b"", "b"),
        Err(mime::Error::Truncated)
    );
    for input in [b"hello".as_slice(), b"--b\r\n"] {
        assert_eq!(
            run(make(), input, 1).1,
            Some(Fail::Protocol(mime::Error::Truncated))
        );
    }
}

#[test]
fn protobuf_grpc_matches_prefix_parser() {
    use fictionet::stdlib::codec::Step;
    let framing = protobuf::Framing::Grpc;
    let mut cases = vec![
        vec![],
        vec![2],
        vec![0xff],
        vec![0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 2, 8, 1],
    ];
    let mut oversize = vec![0];
    oversize.extend_from_slice(&((protobuf::MAX_MESSAGE + 1) as u32).to_be_bytes());
    cases.push(oversize);
    for bytes in cases {
        for cut in 0..=bytes.len() {
            let input = &bytes[..cut];
            let expected = protobuf::Frame::parse(framing, input).map(|parsed| match parsed {
                Some((frame, used)) => Step::Item(frame, used),
                None => Step::Need,
            });
            for eof in [false, true] {
                assert_eq!(protobuf::Frames::new(framing).decode(input, eof), expected);
            }
        }
    }
}

#[test]
fn xml_chunked_round_trip_and_eof() {
    let bytes = br#"<?xml version="1.0"?><!DOCTYPE r [<!ATTLIST r n CDATA "v">]><r xmlns:p="urn:p"><p:c/>text&amp;more</r><!--tail--> "#;
    contract::check_decode(xml::Events::new, bytes);
    contract::check_wire::<xml::Document>(bytes);
    prefixes(xml::Events::new, bytes);
    let expected = xml::parse(bytes).unwrap();
    assert_eq!(run(xml::Events::new(), bytes, 1), (expected.clone(), None));
    let frame = <xml::Document as Wire>::parse(bytes).unwrap();
    let encoded = Wire::to_bytes(&frame).unwrap();
    assert_eq!(encoded, bytes);
    assert_eq!(run(xml::Events::new(), &encoded, 7), (expected, None));
    assert!(<xml::Document as Wire>::parse(b"<r/><s/>").is_err());
    assert!(matches!(
        run(xml::Events::new(), b"<!--unfinished", 1).1,
        Some(Fail::Truncated { .. })
    ));
    let (events, error) = run(xml::Events::new(), b"<r>final text", 1);
    assert_eq!(events.last(), Some(&xml::Event::Text("final text".into())));
    assert!(matches!(
        error,
        Some(Fail::Protocol(xml::Error {
            kind: xml::ErrorKind::UnexpectedEnd,
            ..
        }))
    ));
    assert!(matches!(
        run(xml::Events::new(), b"<r><", 1).1,
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
    contract::check_decode(form::Fields::new, bytes);
    prefixes(form::Fields::new, bytes);
    let expected: Vec<_> = form::parse(bytes)
        .unwrap()
        .into_iter()
        .map(form::Field)
        .collect();
    assert_eq!(run(form::Fields::new(), bytes, 1), (expected.clone(), None));
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
    assert_eq!(run(form::Fields::new(), &written, 3), (expected, None));
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
        run(form::Fields::new(), b"a=%A", 1),
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
    let bytes = body.to_bytes("boundary").unwrap();
    let make = || mime::Parts::new("boundary").unwrap();
    contract::check_decode(make, &bytes);
    prefixes(make, &bytes);
    assert_eq!(run(make(), &bytes, 1), (body.parts.clone(), None));
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
    .to_bytes("boundary")
    .unwrap();
    assert_eq!(run(make(), &rewritten, 7), (body.parts, None));
    for bytes in [b"--boundary--".as_slice(), b"--boundary-- \t"] {
        assert_eq!(run(make(), bytes, 1), (vec![], None));
    }
    let bytes = b"--boundary\r\n\r\nlast\r\n--boundary--";
    prefixes(make, bytes);
    assert_eq!(
        run(make(), bytes, 1),
        (
            vec![mime::Part {
                body: b"last".to_vec(),
                ..mime::Part::default()
            }],
            None
        )
    );
    assert_eq!(
        run(make(), b"--boundary\r\n\r\nlast", 1).1,
        Some(Fail::Protocol(mime::Error::Truncated))
    );
    assert!(matches!(
        run(make(), b"--boundary\r\nX: value", 1).1,
        Some(Fail::Truncated { .. })
    ));
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
fn protobuf_chunked_round_trip_and_eof() {
    let mut message = protobuf::Message::new();
    message.fields.push(protobuf::Field {
        number: 1,
        value: protobuf::Value::Varint(150),
    });
    let frame = protobuf::Frame {
        compressed: false,
        data: Wire::to_bytes(&message).unwrap(),
    };
    contract::check_wire_value(&message);
    contract::check_wire_value(&frame);
    contract::check_wire_value(&protobuf::DelimitedFrame(frame.clone()));
    for framing in [protobuf::Framing::Grpc, protobuf::Framing::Delimited] {
        let bytes = frame.to_bytes(framing).unwrap();
        let make = || protobuf::Frames::new(framing);
        contract::check_decode(make, &bytes);
        contract::check_stack(|| make().map(|f| protobuf::Message::parse(&f.data)), &bytes);
        prefixes(make, &bytes);
        for cut in 1..bytes.len() {
            assert!(matches!(
                run(make(), &bytes[..cut], 1).1,
                Some(Fail::Truncated { .. })
            ));
        }
        assert_eq!(run(make(), &bytes, 1), (vec![frame.clone()], None));
        let mut batch = bytes.clone();
        // A bad message body is a per-item error, while framing continues.
        batch.extend_from_slice(
            &protobuf::Frame {
                compressed: false,
                data: vec![0],
            }
            .to_bytes(framing)
            .unwrap(),
        );
        batch.extend_from_slice(&bytes);
        let (items, error) = run(make().map(|f| protobuf::Message::parse(&f.data)), &batch, 1);
        assert_eq!(
            items,
            vec![
                Ok(message.clone()),
                Err(protobuf::Error::FieldNumber(0)),
                Ok(message.clone())
            ]
        );
        assert_eq!(error, None);
        contract::check_stack(|| make().map(|f| protobuf::Message::parse(&f.data)), &batch);
    }
    let mut extra = Wire::to_bytes(&frame).unwrap();
    extra.push(0);
    assert!(matches!(
        <protobuf::Frame as Wire>::parse(&extra),
        Err(protobuf::FrameParseError::Trailing { remaining: 1 })
    ));
}

#[test]
fn protobuf_rejects_oversize_at_named_capacity() {
    for framing in [protobuf::Framing::Grpc, protobuf::Framing::Delimited] {
        let header = match framing {
            protobuf::Framing::Grpc => protobuf::GRPC_HEADER_LEN,
            protobuf::Framing::Delimited => protobuf::MAX_VARINT_LEN,
        };
        let mut stream = Stream::new(protobuf::Frames::new(framing));
        assert_eq!(stream.decoder().capacity(), protobuf::MAX_MESSAGE + header);
        let mut bytes = Vec::new();
        match framing {
            protobuf::Framing::Grpc => {
                bytes.push(0);
                bytes.extend_from_slice(&((protobuf::MAX_MESSAGE + 1) as u32).to_be_bytes());
            }
            protobuf::Framing::Delimited => {
                protobuf::encode_varint((protobuf::MAX_MESSAGE + 1) as u64, &mut bytes)
            }
        }
        // The header alone is enough to reject the declared oversized frame.
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(protobuf::Error::TooLong)))
        );
        assert!(stream.next().is_none());
    }
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
    contract::check_wire_value(&protobuf::DelimitedFrame(protobuf::Frame {
        compressed: true,
        data: vec![],
    }));
    contract::check_wire_value(&protobuf::Message {
        fields: vec![protobuf::Field {
            number: 0,
            value: protobuf::Value::Varint(0),
        }],
    });
}

#[test]
fn contracts_on_malformed_and_mutated_inputs() {
    use fictionet::stdlib::codec::test_support::Lcg;
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
            if !bytes.is_empty() {
                let at = rng.below(bytes.len() as u64) as usize;
                bytes[at] = rng.next() as u8;
            }
            contract::check_decode(json::Values::new, &bytes);
            contract::check_decode(xml::Events::new, &bytes);
            contract::check_decode(form::Fields::new, &bytes);
            contract::check_decode(|| mime::Parts::new("b").unwrap(), &bytes);
            for framing in [protobuf::Framing::Grpc, protobuf::Framing::Delimited] {
                contract::check_decode(|| protobuf::Frames::new(framing), &bytes);
            }
            contract::check_wire::<json::Value>(&bytes);
            contract::check_wire::<xml::Document>(&bytes);
            contract::check_wire::<form::Field>(&bytes);
            contract::check_wire::<mime::Part>(&bytes);
            contract::check_wire::<protobuf::Frame>(&bytes);
            contract::check_wire::<protobuf::DelimitedFrame>(&bytes);
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
        run(form::Fields::new(), &bytes, bytes.len()),
        (vec![field], None)
    );

    let mut bytes = b"<r>".to_vec();
    bytes.resize(xml::MAX_DOCUMENT - 4, b'x');
    bytes.extend_from_slice(b"</r>");
    assert_eq!(bytes.len(), xml::MAX_DOCUMENT);
    let (events, error) = run(xml::Events::new(), &bytes, bytes.len());
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
    let bytes = body.to_bytes(&boundary).unwrap();
    assert_eq!(
        run(mime::Parts::new(&boundary).unwrap(), &bytes, bytes.len()),
        (vec![part], None)
    );
}

#[test]
#[allow(deprecated)] // Verify unchanged void feeds and repeating errors.
fn compatibility_decoders_keep_their_buffering_and_errors() {
    let mut json = json::Decoder::new();
    let json_batch = b"{}".repeat(json::MAX_SIZE);
    json.feed(&json_batch);
    assert_eq!(json.buffered(), json_batch.len());
    assert!(json.next_value().unwrap().is_ok());

    let mut multipart = mime::Parser::new("b").unwrap();
    let batch = vec![b'x'; mime::MAX_PART + mime::MAX_BOUNDARY_LINE + 2];
    multipart.feed(&batch);
    assert_eq!(multipart.buffered(), batch.len());

    let mut decoder = protobuf::Decoder::new(protobuf::Framing::Grpc);
    decoder.feed(&[2]);
    assert_eq!(decoder.next_frame(), Some(Err(protobuf::Error::Flag(2))));
    assert_eq!(decoder.next_frame(), Some(Err(protobuf::Error::Flag(2))));
    let mut decoder = form::Decoder::new();
    decoder.feed(&vec![b'a'; form::MAX_INPUT + 1]);
    assert_eq!(decoder.next_pair(), Some(Err(form::FormError::TooLong)));
    assert_eq!(decoder.next_pair(), Some(Err(form::FormError::TooLong)));
    let mut parser = xml::Parser::new();
    parser.feed(b"<r>");
    parser.finish();
    assert!(parser.next_event().unwrap().is_ok());
    let error = parser.next_event();
    assert!(matches!(
        error,
        Some(Err(xml::Error {
            kind: xml::ErrorKind::UnexpectedEnd,
            ..
        }))
    ));
    assert_eq!(parser.next_event(), error);
}
