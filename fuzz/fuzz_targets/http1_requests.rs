#![no_main]

use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};

use fictionet::stdlib::protocols::http1::{Request, Requests};
use fictionet::stdlib::test_support;
use fictionet_fuzz::http1::message_limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = message_limits();
    let make = || Requests::with_limits(limits);
    assert_eq!(
        decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.held() <= 3072);
            assert!(s.allocated() <= 8194);
        }),
        decode_all(make, data),
    );
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
    assert_eq!(
        decode_chunks(
            &mut Stream::new(make()),
            chunks(&input, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(make, &input),
    );
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
                let _ = assert_write(&request);
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
    if let Ok(value) = <Request as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(request) = Request::parse(data) {
        assert_eq!(
            decode_chunks(
                &mut Stream::new(Requests::default()),
                chunks(&request.to_bytes().unwrap(), &[1, 7, 64]),
                |_| {}
            ),
            decode_all(Requests::default, &request.to_bytes().unwrap()),
        );
    }
});
