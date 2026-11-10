#![no_main]

use fictionet::stdlib::codec::Collect;
use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire};
use fictionet::stdlib::protocols::http1::{Chunk, Request, RequestError, RequestEvents, Version};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet::stdlib::web::Head;
use fictionet_fuzz::http1::event_limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = event_limits();
    let mut stream = Stream::new(RequestEvents::with_limits(limits));
    let fragmented = decode_chunks(&mut stream, chunks(data, &[1, 7, 64]), |s| {
        assert_eq!(s.held(), 0);
        assert!(s.allocated() <= 4096);
    });
    let whole = decode_all(|| RequestEvents::with_limits(limits), data);
    assert_eq!(fragmented.0, whole.0);
    match (fragmented.1, whole.1) {
        (
            Some(Fail::Protocol(RequestError::Rejected(fragmented))),
            Some(Fail::Protocol(RequestError::Rejected(whole))),
        ) => {
            assert_eq!(
                (
                    &fragmented.error,
                    &fragmented.head,
                    fragmented.head_bytes,
                    fragmented.framing
                ),
                (&whole.error, &whole.head, whole.head_bytes, whole.framing)
            );
            assert!(fragmented.received_body_bytes <= stream.buffered() - fragmented.head_bytes);
            // The payload snapshot reflects the bytes present at rejection.
            assert_eq!(
                RequestEvents::with_limits(limits).decode(stream.unread(), stream.is_eof()),
                Err(RequestError::Rejected(fragmented))
            );
        }
        (fragmented, whole) => assert_eq!(fragmented, whole),
    }
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
    if let Ok(value) = <Head as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Chunk as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let bounded = &data[..data.len().min(512)];
    let request = Request {
        head: Head::new(
            "POST",
            "/",
            Version::Http11,
            [
                ("Host".to_owned(), b"example.test".to_vec()),
                (
                    "Content-Length".to_owned(),
                    bounded.len().to_string().into_bytes(),
                ),
                (
                    String::from_utf8_lossy(bounded).into_owned(),
                    bounded.to_vec(),
                ),
            ],
        ),
        body: bounded.to_vec(),
    };
    let _ = assert_write(&request);
    let _ = assert_write(&Chunk(bounded.to_vec()));
});
