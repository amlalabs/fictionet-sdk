use fictionet::stdlib::{codec, protocols::http1};

/// Validates one whole response. Close-delimited bodies need explicit opt-in and EOF.
pub fn response(bytes: &[u8], method: &str, allow_close_delimited: bool) -> http1::Response {
    let response = http1::Response::parse_for(bytes, method).expect("complete HTTP response");
    if !allow_close_delimited {
        let mut decoder = http1::ResponseEvents::default();
        decoder.expect_method(method).expect("request method");
        let mut stream = codec::Stream::new(decoder);
        let mut done = false;
        // Without end(), only a self-delimited response can produce Done.
        let taken = codec::pump(&mut stream, bytes, |event| {
            done |= matches!(event, http1::Event::Done);
        })
        .expect("HTTP framing");
        assert_eq!(taken, bytes.len(), "unconsumed HTTP bytes");
        assert!(
            done,
            "close-delimited HTTP response requires explicit opt-in"
        );
    }
    response
}
