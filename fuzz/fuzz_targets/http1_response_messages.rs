#![no_main]

use fictionet::stdlib::codec::{Stream, Wire, contract, test_support};
use fictionet::stdlib::http1::{Limits, Response, ResponseMessages};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        start_line: 256,
        header_line: 256,
        headers: 16,
        head: 2048,
        body_chunk: 31,
        body: 1024,
        message: 4096,
    };
    for method in ["GET", "HEAD", "CONNECT"] {
        let make = || {
            let mut decoder = ResponseMessages::with_limits(limits);
            decoder.expect_method(method).unwrap();
            decoder.expect_method("GET").unwrap();
            decoder
        };
        contract::check_decode_with_held_limit(make, data, 3074);
        contract::check_decode_with_alloc_limit(make, data, 8194);
    }
    let body = &data[..data.len().min(512)];
    let interim = b"HTTP/1.1 103 Early Hints\r\nConnection: close\r\n\r\n";
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
    let mut input = [interim.as_slice(), head.as_slice()].concat();
    let get_start = input.len();
    input.extend_from_slice(
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
    );
    input.extend_from_slice(body);
    let make = || {
        let mut decoder = ResponseMessages::with_limits(limits);
        decoder.expect_method("HEAD").unwrap();
        decoder.expect_method("GET").unwrap();
        decoder
    };
    contract::check_decode(make, &input);
    let expected = [
        Response::parse(interim).unwrap(),
        Response::parse_for(head, "HEAD").unwrap(),
        Response::parse(&input[get_start..]).unwrap(),
    ];
    for sizes in [&[input.len()][..], &[1], &[3, 7, 2]] {
        let mut stream = Stream::new(make());
        let mut raw = Vec::new();
        let mut encoded = Vec::new();
        let mut responses = Vec::new();
        for part in test_support::chunks(&input, sizes) {
            assert_eq!(stream.push(part), part.len());
            while let Some(result) = stream.with_next(|response, bytes, range| {
                assert_eq!(range.start, u64::try_from(raw.len()).unwrap());
                raw.extend_from_slice(bytes);
                assert_eq!(range.end, u64::try_from(raw.len()).unwrap());
                if range.start == u64::try_from(interim.len()).unwrap() {
                    assert_eq!(bytes, head);
                    encoded.extend_from_slice(bytes);
                } else {
                    contract::check_wire_value(&response);
                    response.write(&mut encoded).unwrap();
                }
                response
            }) {
                responses.push(result.unwrap());
            }
        }
        assert_eq!(raw, input);
        assert_eq!(responses, expected);
        assert!(stream.unread().is_empty());
        assert_eq!(stream.held(), 0);
        assert!(!stream.is_done());
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(test_support::decode_all(make, &encoded), (responses, None));
    }
});
