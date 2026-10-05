//! MongoDB wire protocol messages and BSON documents, as a world playing a
//! database server reads them.
#![no_main]

use fictionet::stdlib::mongodb::{Decoder, Document, Message, MessageError};
use libfuzzer_sys::fuzz_target;

/// Every message the decoder gives, stopping where the stream breaks.
fn decode(data: &[u8], chunk: usize) -> Vec<Result<Message, MessageError>> {
    let mut decoder = Decoder::new();
    let mut out = Vec::new();
    for piece in data.chunks(chunk.max(1)) {
        decoder.feed(piece);
        while let Some(m) = decoder.next_message() {
            out.push(m);
            if decoder.failed().is_some() {
                return out;
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let messages = decode(data, data.len());
    assert_eq!(messages, decode(data, 1));

    for m in messages.into_iter().flatten() {
        // A message read can be written, and reads back the same. Inputs
        // here are far below the size limits, so writing cannot fail.
        let bytes = m.to_bytes().unwrap();
        let (back, used) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(back, m);
        assert_eq!(used, bytes.len());
    }
    // Any bytes as a BSON document on their own.
    if let Ok((doc, used)) = Document::parse(data) {
        assert!(used <= data.len());
        let bytes = doc.to_bytes().unwrap();
        assert_eq!(Document::parse(&bytes).unwrap(), (doc, bytes.len()));
    }
});
