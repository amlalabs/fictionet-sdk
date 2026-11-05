#![no_main]

use fictionet::stdlib::codec::Collect;
use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::protocols::http1::{
    Chunk, Header, Request, RequestEvents, RequestHead, Version,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet_fuzz::http1::event_limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = event_limits();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(RequestEvents::with_limits(limits)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert_eq!(s.held(), 0);
                assert!(s.allocated() <= 4096);
            }
        ),
        decode_all(|| RequestEvents::with_limits(limits), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Collect::<Request>::new(4096)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Collect::<Request>::new(4096), data),
    );
    if let Ok(value) = <Request as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <RequestHead as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Chunk as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let bounded = &data[..data.len().min(512)];
    let request = Request {
        head: RequestHead {
            method: "POST".into(),
            target: "/".into(),
            version: Version::Http11,
            headers: vec![
                Header {
                    name: "Host".into(),
                    value: b"example.test".to_vec(),
                },
                Header {
                    name: "Content-Length".into(),
                    value: bounded.len().to_string().into_bytes(),
                },
                Header {
                    name: String::from_utf8_lossy(bounded).into_owned(),
                    value: bounded.to_vec(),
                },
            ],
        },
        body: bounded.to_vec(),
    };
    let _ = assert_write(&request);
    let _ = assert_write(&Chunk(bounded.to_vec()));
});
