#![no_main]

use fictionet::stdlib::codec::{Stream, Wire, contract, test_support};
use fictionet::stdlib::http1::{Limits, Request, RequestMessages};
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
    let make = || RequestMessages::with_limits(limits);
    contract::check_decode_with_held_limit(make, data, 3072);
    contract::check_decode_with_alloc_limit(make, data, 8194);
    // Also exercise valid pipelined messages with arbitrary body bytes.
    let body = &data[..data.len().min(512)];
    let mut input = format!(
        "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    input.extend_from_slice(body);
    let first_len = input.len();
    input.extend_from_slice(b"GET /next HTTP/1.1\r\nHost:test\r\n\r\n");
    contract::check_decode(make, &input);
    let expected = [
        Request::parse(&input[..first_len]).unwrap(),
        Request::parse(&input[first_len..]).unwrap(),
    ];
    for sizes in [&[input.len()][..], &[1], &[3, 7, 2]] {
        let mut stream = Stream::new(make());
        let mut raw = Vec::new();
        let mut encoded = Vec::new();
        let mut requests = Vec::new();
        for part in test_support::chunks(&input, sizes) {
            assert_eq!(stream.push(part), part.len());
            while let Some(result) = stream.with_next(|request, bytes, range| {
                assert_eq!(range.start, u64::try_from(raw.len()).unwrap());
                raw.extend_from_slice(bytes);
                assert_eq!(range.end, u64::try_from(raw.len()).unwrap());
                request
            }) {
                let request = result.unwrap();
                contract::check_wire_value(&request);
                request.write(&mut encoded).unwrap();
                requests.push(request);
            }
        }
        assert_eq!(raw, input);
        assert_eq!(requests, expected);
        assert!(stream.unread().is_empty());
        assert_eq!(stream.held(), 0);
        assert!(!stream.is_done());
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(test_support::decode_all(make, &encoded), (requests, None));
    }
    contract::check_wire::<Request>(data);
    if let Ok(request) = Request::parse(data) {
        contract::check_decode(RequestMessages::default, &request.to_bytes().unwrap());
    }
});
