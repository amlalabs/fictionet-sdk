//! OCSP requests and responses, as a world playing a responder reads
//! them, and the GET path a request comes in.
#![no_main]

use fictionet::stdlib::ocsp::{BasicResponse, Decoder, OcspRequest, OcspResponse, decode_get_path};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The body, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut messages = Vec::new();
    while let Some(Ok(m)) = whole.next_message() {
        messages.push(m);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(m)) = bytewise.next_message() {
            again.push(m);
        }
    }
    assert_eq!(messages, again);

    // Any bytes as each message on its own. What reads can be written,
    // and reads back the same.
    for m in messages.iter().map(Vec::as_slice).chain([data]) {
        if let Ok(req) = OcspRequest::parse(m) {
            let der = req.to_der().unwrap();
            assert_eq!(OcspRequest::parse(&der).unwrap(), req);
            let path = req.to_get_path().unwrap();
            assert_eq!(OcspRequest::from_get_path(&path).unwrap(), req);
        }
        if let Ok(resp) = OcspResponse::parse(m) {
            let der = resp.to_der().unwrap();
            assert_eq!(OcspResponse::parse(&der).unwrap(), resp);
        }
        if let Ok(basic) = BasicResponse::parse(m) {
            let der = basic.to_der().unwrap();
            assert_eq!(BasicResponse::parse(&der).unwrap(), basic);
        }
    }
    // Any text as a GET path.
    if let Ok(der) = decode_get_path(&String::from_utf8_lossy(data)) {
        let _ = OcspRequest::parse(&der);
    }
});
