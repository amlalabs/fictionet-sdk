//! STUN messages, as a world playing a STUN server reads them from UDP
//! datagrams and TCP streams.
#![no_main]

use fictionet::stdlib::stun::{Decoder, Message, answer_binding};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram. A message read can be written, and the
    // bytes read back and write the same. Writing only drops attributes a
    // reader ignores and cuts text to the sending limits, so the bytes are
    // never longer. Any answer reads back too.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes();
        assert!(bytes.len() <= data.len());
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!((back.method, back.class, back.transaction), (m.method, m.class, m.transaction));
        // Each attribute that reads back is the first of its type in both.
        assert_eq!(back.xor_mapped_address(), m.xor_mapped_address());
        assert_eq!(back.mapped_address(), m.mapped_address());
        assert_eq!(back.alternate_server(), m.alternate_server());
        assert_eq!(back.unknown_attributes(), m.unknown_attributes());
        let _ = (back.username(), back.realm(), back.nonce(), back.software(), back.error_code());
        let source = "192.0.2.1:32853".parse().unwrap();
        if let Some(reply) = answer_binding(&m, source) {
            let back = Message::parse(&reply.to_bytes()).unwrap();
            assert_eq!(back.transaction, m.transaction);
        }
    }

    // The bytes as a stream, split two ways: all at once, and a byte at a
    // time. Both give the same messages and errors.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut messages = Vec::new();
    while let Some(r) = whole.next_message() {
        messages.push(r);
        if whole.is_broken() {
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(r) = bytewise.next_message() {
            again.push(r);
            if bytewise.is_broken() {
                break;
            }
        }
        if bytewise.is_broken() {
            break;
        }
    }
    assert_eq!(messages, again);
});
