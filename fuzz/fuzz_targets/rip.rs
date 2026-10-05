//! RIP and RIPng messages, as a world playing a router reads them.
#![no_main]

use fictionet::stdlib::rip::{Decoder, Message, NgDecoder, NgMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // As a RIP message, fed two ways: all at once, and a byte at a time.
    let parsed = Message::parse(data);
    let mut whole = Decoder::new();
    let _ = whole.feed(data);
    assert_eq!(whole.finish(), parsed);
    let mut bytewise = Decoder::new();
    for b in data {
        let _ = bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), parsed);
    if let Ok(m) = &parsed {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
    }

    // The same bytes as a RIPng message.
    let parsed = NgMessage::parse(data);
    let mut whole = NgDecoder::new();
    let _ = whole.feed(data);
    assert_eq!(whole.finish(), parsed);
    let mut bytewise = NgDecoder::new();
    for b in data {
        let _ = bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), parsed);
    if let Ok(m) = &parsed {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(NgMessage::parse(&bytes).as_ref(), Ok(m));
    }
});
