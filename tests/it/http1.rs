use crate::common::alloc::allocations;
use fictionet::stdlib::codec::{Decode, Step, Stream, Wire};
use fictionet::stdlib::protocols::http1::{
    Event, Header, Limits, Request, RequestEvents, Requests, Response, ResponseEvents, Responses,
};
use fictionet::stdlib::test_support;
use fictionet::stdlib::test_support::contract;

const FIRST: &[u8] = b"POST /tools HTTP/1.1\r\nHost: api.test\r\nTransfer-Encoding: chunked\r\nX-Raw:\t keep \t\r\n\r\n01\r\n{\r\n1\r\n}\r\n000\r\n\r\n";
const SECOND: &[u8] = b"GET /next HTTP/1.1\r\nHost:api.test\r\n\r\n";

#[test]
fn whole_message_allocations_do_not_depend_on_body_block_size() {
    fn check<D: Decode>(make: impl Fn(Limits) -> D, bytes: &[u8])
    where
        D::Item: std::fmt::Debug + PartialEq,
    {
        let decode = |body_chunk, bytewise| {
            let mut decoder = make(Limits {
                body_chunk,
                ..Limits::default()
            });
            let (step, count) = allocations(|| {
                if bytewise {
                    for end in 0..bytes.len() {
                        assert!(matches!(
                            decoder.decode(&bytes[..end], false),
                            Ok(Step::Need)
                        ));
                    }
                }
                decoder.decode(bytes, true)
            });
            let Step::Item(item, used) = step.unwrap() else {
                panic!("expected a complete message");
            };
            assert_eq!(used, bytes.len());
            (item, count)
        };
        for bytewise in [false, true] {
            let (small, small_count) = decode(1, bytewise);
            let (large, large_count) = decode(8192, bytewise);
            assert_eq!(small, large);
            assert_eq!(small_count, large_count, "body blocks must stay borrowed");
        }
    }

    for bytes in [
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",
    ] {
        check(Requests::with_limits, bytes);
    }
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\nhello",
    ] {
        check(Responses::with_limits, bytes);
    }
}

#[test]
fn public_body_events_allocate_owned_blocks() {
    fn check<H>(mut decoder: impl Decode<Item = Event<H>>, head: &[u8]) {
        assert!(
            matches!(decoder.decode(head, false), Ok(Step::Item(Event::Head(_), n)) if n == head.len())
        );
        let mut input = b"hello".to_vec();
        let (step, count) = allocations(|| decoder.decode(&input, false));
        let Step::Item(Event::Body(body), used) = step.unwrap() else {
            panic!("expected a body block");
        };
        assert_eq!(count, 1);
        assert_eq!(used, input.len());
        input.fill(b'x');
        assert_eq!(body, b"hello");
    }
    check(
        RequestEvents::new(),
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n",
    );
    check(
        ResponseEvents::new(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
    );
}

#[test]
fn response_bodies_and_wire_ranges_agree_at_every_input_split() {
    fn drain<D: Decode>(
        stream: &mut Stream<D>,
        items: &mut Vec<(D::Item, std::ops::Range<u64>)>,
        input: &[u8],
    ) where
        D::Error: Clone,
    {
        while let Some(result) = stream.with_next(|item, bytes, range| {
            let start = usize::try_from(range.start).unwrap();
            let end = usize::try_from(range.end).unwrap();
            assert_eq!(bytes, &input[start..end]);
            (item, range)
        }) {
            items.push(result.unwrap());
        }
    }

    for (head, body, spans) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".as_slice(),
            b"hello".as_slice(),
            [0..2, 2..4, 4..5],
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n",
            [3..5, 5..6, 11..13],
        ),
        (b"HTTP/1.1 200 OK\r\n\r\n", b"hello", [0..2, 2..4, 4..5]),
    ] {
        let input = [head, body].concat();
        let response = Response::parse(&input).unwrap();
        assert_eq!(response.body, b"hello");
        let end = u64::try_from(input.len()).unwrap();
        let head_end = u64::try_from(head.len()).unwrap();
        let mut expected = vec![(Event::Head(response.head.clone()), 0..head_end)];
        for span in spans {
            let range = head_end + u64::try_from(span.start).unwrap()
                ..head_end + u64::try_from(span.end).unwrap();
            expected.push((Event::Body(body[span].to_vec()), range));
        }
        expected.push((Event::Done, end..end));
        let limits = Limits {
            body_chunk: 2,
            body: 5,
            message: input.len(),
            ..Limits::default()
        };
        for split in 0..=input.len() {
            let mut events = Stream::new(ResponseEvents::with_limits(limits));
            let mut messages = Stream::new(Responses::with_limits(limits));
            let mut decoded_events = Vec::new();
            let mut decoded_messages = Vec::new();
            for part in [Some(&input[..split]), Some(&input[split..]), None] {
                if let Some(part) = part {
                    assert_eq!(events.push(part), part.len());
                    assert_eq!(messages.push(part), part.len());
                } else {
                    events.end();
                    messages.end();
                }
                drain(&mut events, &mut decoded_events, &input);
                drain(&mut messages, &mut decoded_messages, &input);
            }
            assert_eq!(decoded_events, expected);
            assert_eq!(decoded_messages, [(response.clone(), 0..end)]);
            assert!(events.is_done());
            assert!(messages.is_done());
        }
    }
}

#[test]
fn keep_alive_requests_decode_and_round_trip_at_each_chunking() {
    let input = [FIRST, SECOND].concat();
    let expected = [
        Request::parse(FIRST).unwrap(),
        Request::parse(SECOND).unwrap(),
    ];
    for sizes in [&[input.len()][..], &[1], &[3, 7, 2]] {
        let mut stream = Stream::new(Requests::default());
        let mut requests = Vec::new();
        for part in test_support::chunks(&input, sizes) {
            assert_eq!(stream.push(part), part.len());
            while let Some(result) = stream.next() {
                requests.push(result.unwrap());
            }
        }
        assert_eq!(requests, expected);
        assert_eq!(requests[0].body, b"{}");
        assert!(requests[1].body.is_empty());
        assert!(!stream.is_done());
        assert!(stream.unread().is_empty());
        assert_eq!(stream.held(), 0);
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.next(), None);

        let mut output = Vec::new();
        for request in &requests {
            contract::check_wire_value(request);
            request.write(&mut output).unwrap();
        }
        assert_eq!(
            test_support::decode_all(Requests::default, &output),
            (requests, None)
        );
    }
    contract::check_decode(Requests::default, &input);
}

#[test]
fn next_span_covers_each_complete_request_at_each_chunking() {
    let input = [FIRST, SECOND].concat();
    let boundary = u64::try_from(FIRST.len()).unwrap();
    let end = u64::try_from(input.len()).unwrap();
    let expected = [
        (Request::parse(FIRST).unwrap(), 0..boundary),
        (Request::parse(SECOND).unwrap(), boundary..end),
    ];
    for sizes in [&[input.len()][..], &[1], &[3, 7, 2]] {
        let mut stream = Stream::new(Requests::default());
        let mut items = Vec::new();
        for part in test_support::chunks(&input, sizes) {
            assert_eq!(stream.push(part), part.len());
            while let Some(result) = stream.next_span() {
                items.push(result.unwrap());
            }
        }
        assert_eq!(items, expected);
        for ((_, range), bytes) in items.iter().zip([FIRST, SECOND]) {
            let start = usize::try_from(range.start).unwrap();
            let end = usize::try_from(range.end).unwrap();
            assert_eq!(input.get(start..end), Some(bytes));
        }
        assert!(!stream.is_done());
        stream.end();
        assert_eq!(stream.next_span(), None);
        assert!(stream.is_done());
    }
}

#[test]
fn with_next_preserves_chunk_framing_and_message_ranges_at_each_chunking() {
    let input = [FIRST, SECOND].concat();
    let boundary = u64::try_from(FIRST.len()).unwrap();
    let end = u64::try_from(input.len()).unwrap();
    let expected = [
        (Request::parse(FIRST).unwrap(), FIRST.to_vec(), 0..boundary),
        (
            Request::parse(SECOND).unwrap(),
            SECOND.to_vec(),
            boundary..end,
        ),
    ];
    for sizes in [&[input.len()][..], &[1], &[3, 7, 2]] {
        let mut stream = Stream::new(Requests::default());
        let mut items = Vec::new();
        for part in test_support::chunks(&input, sizes) {
            assert_eq!(stream.push(part), part.len());
            while let Some(result) =
                stream.with_next(|request, bytes, range| (request, bytes.to_vec(), range))
            {
                items.push(result.unwrap());
            }
        }
        assert_eq!(items, expected);
        assert!(!stream.is_done());
        assert!(stream.unread().is_empty());
        assert_eq!(stream.held(), 0);
        stream.end();
        assert_eq!(stream.with_next(|_, _, _| ()), None);
        assert!(stream.is_done());
        assert_eq!(stream.with_next(|_, _, _| ()), None);
    }
}

#[test]
fn edited_bodies_and_duplicate_requests_round_trip_through_wire() {
    let input = [FIRST, SECOND].concat();
    let mut stream = Stream::new(Requests::default());
    assert_eq!(stream.push(&input), input.len());
    let mut expected = Vec::new();
    let mut output = Vec::new();
    while let Some(result) = stream.next() {
        let mut request = result.unwrap();
        if request.head.target == "/next" {
            request.write(&mut output).unwrap();
            expected.push(request.clone());
        } else {
            request.head.headers.retain(|h| {
                !h.name.eq_ignore_ascii_case("transfer-encoding")
                    && !h.name.eq_ignore_ascii_case("content-length")
            });
            request.body = br#"{"test":true}"#.to_vec();
            request.head.headers.push(Header {
                name: "Content-Length".into(),
                value: request.body.len().to_string().into_bytes(),
            });
        }
        request.write(&mut output).unwrap();
        expected.push(request);
    }
    assert_eq!(expected.len(), 3);
    assert_eq!(expected[0].body, br#"{"test":true}"#);
    assert_eq!(expected[1], expected[2]);
    assert_eq!(expected[1].head.target, "/next");
    assert_eq!(
        test_support::decode_all(Requests::default, &output),
        (expected, None)
    );
}

#[test]
fn queued_head_and_get_responses_preserve_framing_after_edits() {
    let make = || {
        let mut decoder = Responses::default();
        decoder.expect_method("HEAD").unwrap();
        decoder.expect_method("GET").unwrap();
        decoder
    };
    let first = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
    let second = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    let input = [first.as_slice(), second.as_slice()].concat();
    for sizes in [&[input.len()][..], &[1], &[3, 7, 2]] {
        let mut stream = Stream::new(make());
        let mut output = Vec::new();
        let mut expected = Vec::new();
        for part in test_support::chunks(&input, sizes) {
            assert_eq!(stream.push(part), part.len());
            while let Some(result) = stream.with_next(|mut response, bytes, _| {
                if response.body.is_empty() {
                    assert_eq!(bytes, first);
                    assert_eq!(response, Response::parse_for(first, "HEAD").unwrap());
                    output.extend_from_slice(bytes);
                } else {
                    assert_eq!(bytes, second);
                    response.head.status = 503;
                    response.head.reason = b"Service Unavailable".to_vec();
                    response.head.headers.push(Header {
                        name: "Retry-After".into(),
                        value: b"1".to_vec(),
                    });
                    response.write(&mut output).unwrap();
                }
                response
            }) {
                expected.push(result.unwrap());
            }
        }
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[1].head.status, 503);
        assert_eq!(expected[1].body, b"{}");
        assert_eq!(output.get(..first.len()), Some(first.as_slice()));
        assert!(!stream.is_done());
        assert!(stream.unread().is_empty());
        assert_eq!(stream.held(), 0);
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(test_support::decode_all(make, &output), (expected, None));
    }
    contract::check_decode(make, &input);
}

#[test]
fn copied_message_decoders_preserve_bytes_and_share_wire_traits() {
    use fictionet_copy_modules::protocols::http1 as copied;
    let mut stream = Stream::new(copied::Requests::default());
    let input = [FIRST, SECOND].concat();
    assert_eq!(stream.push(&input), input.len());
    let mut raw = Vec::new();
    let mut output = Vec::new();
    let mut expected = Vec::new();
    while let Some(result) = stream.with_next(|request, bytes, _| {
        raw.extend_from_slice(bytes);
        request
    }) {
        let request = result.unwrap();
        contract::check_wire_value(&request);
        request.write(&mut output).unwrap();
        expected.push(request);
    }
    assert_eq!(raw, input);
    assert_eq!(expected.len(), 2);
    assert_eq!(
        test_support::decode_all(copied::Requests::default, &output),
        (expected, None)
    );
    let response = copied::Response::json(b"{}").unwrap();
    assert_eq!(
        Response::parse(&response.to_bytes().unwrap()).unwrap().body,
        b"{}"
    );
    contract::check_decode(copied::Responses::new, b"HTTP/1.1 204 \r\n\r\n");
}

#[test]
fn message_buffer_bounds_do_not_change_between_messages() {
    let mut stream = Stream::new(Requests::with_limits(Limits {
        body: 2,
        message: FIRST.len(),
        ..Limits::default()
    }));
    let capacity = FIRST.len().checked_add(1).unwrap();
    let input = [FIRST, SECOND, FIRST, SECOND].concat();
    let mut rest = input.as_slice();
    let mut items = Vec::new();
    let mut raw = Vec::new();
    while !rest.is_empty() {
        let room = capacity.checked_sub(stream.unread().len()).unwrap();
        let accepted = stream.push(rest);
        assert_eq!(accepted, rest.len().min(room));
        assert!(accepted > 0);
        rest = &rest[accepted..];
        assert!(stream.unread().len() <= capacity);
        while let Some(result) = stream.with_next(|request, bytes, _| {
            raw.extend_from_slice(bytes);
            request
        }) {
            items.push(result.unwrap());
        }
        assert!(!stream.is_done());
    }
    assert_eq!(raw, input);
    assert_eq!(
        items,
        [FIRST, SECOND, FIRST, SECOND].map(|bytes| Request::parse(bytes).unwrap())
    );
    assert!(stream.unread().is_empty());
    assert_eq!(stream.held(), 0);
    stream.end();
    assert_eq!(stream.next(), None);
    assert!(stream.is_done());
}

#[test]
fn header_line_check_matches_lenient_field_parsing() {
    use fictionet::stdlib::protocols::http1::{RequestHead, header_line_ok};

    for (line, valid) in [
        (b"X-Name: value".as_slice(), true),
        (b"X-Empty:", true),
        (b"X-Raw: \t\xff\x80 \t", true),
        (b"", false),
        (b": value", false),
        (b"Missing-Colon", false),
        (b"Bad Name: value", false),
        (b"Name : value", false),
        (b"Name: bad\x00", false),
        (b"Name: bad\x7f", false),
        (b"Name: bad\ra", false),
    ] {
        assert_eq!(header_line_ok(line), valid, "{line:?}");
        let request = [b"GET / HTTP/1.1\r\n".as_slice(), line, b"\r\n\r\n"].concat();
        if !line.is_empty() {
            assert_eq!(
                RequestHead::parse_lenient(&request).is_ok(),
                valid,
                "{line:?}"
            );
        }
    }
}
