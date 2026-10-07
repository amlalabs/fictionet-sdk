use fictionet::stdlib::codec::{Stream, Wire, contract, test_support};
use fictionet::stdlib::http1::{
    Header, Limits, Request, Requests, Response, Responses,
};

const FIRST: &[u8] = b"POST /tools HTTP/1.1\r\nHost: api.test\r\nTransfer-Encoding: chunked\r\nX-Raw:\t keep \t\r\n\r\n01\r\n{\r\n1\r\n}\r\n000\r\n\r\n";
const SECOND: &[u8] = b"GET /next HTTP/1.1\r\nHost:api.test\r\n\r\n";

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
    use fictionet_copy_modules::http1 as copied;
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
    contract::check_decode(
        copied::Responses::new,
        b"HTTP/1.1 204 \r\n\r\n",
    );
}

#[test]
fn message_buffer_bounds_do_not_change_between_messages() {
    let mut stream = Stream::new(Requests::with_limits(Limits { body: 2, message: FIRST.len(), ..Limits::default() }));
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
