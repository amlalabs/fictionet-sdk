#![no_main]

use fictionet::stdlib::codec::Collect;
use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::protocols::http1::{
    Header, MAX_PENDING_REQUESTS, Response, ResponseEvents, ResponseHead, Version,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet_fuzz::http1::event_limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = event_limits();
    for method in ["GET", "HEAD", "CONNECT"] {
        let make = || {
            let mut decoder = ResponseEvents::with_limits(limits);
            decoder.expect_method(method).unwrap();
            decoder.expect_method("GET").unwrap();
            decoder
        };
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.held() <= MAX_PENDING_REQUESTS);
            }),
            decode_all(make, data),
        );
        if let Ok(response) = Response::parse_for(data, method) {
            let mut out = Vec::new();
            response.write_for(method, &mut out).unwrap();
            assert_eq!(Response::parse_for(&out, method), Ok(response));
        }
    }
    assert_eq!(
        decode_chunks(
            &mut Stream::new(ResponseEvents::with_limits(limits)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 4096);
            }
        ),
        decode_all(|| ResponseEvents::with_limits(limits), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Collect::<Response>::new(4096)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Collect::<Response>::new(4096), data),
    );
    if let Ok(value) = <Response as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ResponseHead as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let bounded = &data[..data.len().min(512)];
    let response = Response {
        head: ResponseHead {
            version: Version::Http11,
            status: data
                .first()
                .map_or(200, |b| u16::from(*b).saturating_mul(3)),
            reason: bounded.to_vec(),
            headers: vec![Header {
                name: "Content-Length".into(),
                value: bounded.len().to_string().into_bytes(),
            }],
        },
        body: bounded.to_vec(),
    };
    let _ = assert_write(&response);
});
