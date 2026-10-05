//! Modbus/TCP frames, requests and responses, as a world playing a PLC
//! reads them.
#![no_main]

use fictionet::stdlib::modbus::{Decoder, Frame, Request, Response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut frames = Vec::new();
    while let Some(Ok(f)) = whole.next_frame() {
        frames.push(f);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(f)) = bytewise.next_frame() {
            again.push(f);
        }
    }
    assert_eq!(frames, again);

    for f in &frames {
        // A frame read can be written, and reads back the same.
        let bytes = f.to_bytes();
        let (back, used) = Frame::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, f);
        assert_eq!(used, bytes.len());
        if let Ok(req) = Request::parse(&f.pdu) {
            let pdu = req.to_pdu();
            if !matches!(req, Request::Other { .. }) {
                assert_eq!(Request::parse(&pdu), Ok(req));
            }
        }
        if let Ok((function, resp)) = Response::parse(&f.pdu) {
            let pdu = resp.to_pdu(function);
            assert!(Response::parse(&pdu).is_ok());
        }
    }
    // Any bytes as a PDU on their own.
    let _ = Request::parse(data);
    let _ = Response::parse(data);
});
