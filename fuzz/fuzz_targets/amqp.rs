//! AMQP 0-9-1 frames, methods, content headers and field tables, as a
//! world playing a broker reads them.
#![no_main]

use fictionet::stdlib::amqp::{ContentHeader, Decoder, Frame, FrameError, Method, Table, plain_credentials};
use libfuzzer_sys::fuzz_target;

/// Every frame, then the error that broke the stream, if one did.
fn split(mut decoder: Decoder, data: &[u8], bytewise: bool) -> (Vec<Frame>, Option<FrameError>) {
    let mut frames = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        decoder.feed(chunk);
        while let Some(r) = decoder.next_frame() {
            match r {
                Ok(f) => frames.push(f),
                Err(e) => return (frames, Some(e)),
            }
        }
    }
    (frames, None)
}

/// A payload read as each kind of thing it might be. Whatever reads can be
/// written, and what is written reads back to the same bytes.
fn payload(p: &[u8]) {
    if let Ok(m) = Method::parse(p) {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Method::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }
    if let Ok(h) = ContentHeader::parse(p) {
        let bytes = h.to_bytes().unwrap();
        assert_eq!(ContentHeader::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }
    if let Ok(t) = Table::decode(p) {
        let bytes = t.to_bytes().unwrap();
        assert_eq!(Table::decode(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time, as a
    // client's frames and as a broker's input with the protocol header.
    for server in [false, true] {
        let make = || if server { Decoder::server() } else { Decoder::new() };
        let whole = split(make(), data, false);
        assert_eq!(whole, split(make(), data, true));
        for f in &whole.0 {
            // A frame read can be written, and reads back the same.
            let bytes = f.to_bytes();
            let (back, used) = Frame::parse(&bytes, 0).unwrap().unwrap();
            assert_eq!(&back, f);
            assert_eq!(used, bytes.len());
            payload(&f.payload);
        }
    }
    // Any bytes as a payload on their own, and as a SASL PLAIN response.
    payload(data);
    if let Some((user, password)) = plain_credentials(data) {
        assert!(user.len() + password.len() + 2 <= data.len());
    }
});
