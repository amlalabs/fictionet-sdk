//! STUN messages, as a world playing a STUN server reads them from UDP
//! datagrams and TCP streams.
#![no_main]

use fictionet::stdlib::codec::{Decode, contract};
use fictionet::stdlib::stun::{Attribute, Decoder, Frames, MAX_BUFFERED, MAX_VALUE, Message, answer_binding};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode(|| Frames::new().map(|frame| Message::parse(&frame)), data);
    contract::check_wire::<Message>(data);

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
            contract::check_wire_value(&reply);
            let back = Message::parse(&reply.to_bytes()).unwrap();
            assert_eq!(back.transaction, m.transaction);
        }
    }

    // The bytes as one attribute: a type from the first two bytes and the
    // rest as the value. A value no message can hold is refused.
    if let [hi, lo, value @ ..] = data {
        let typ = u16::from_be_bytes([*hi, *lo]);
        let r = Attribute::parse(typ, value, &[0x5a; 12]);
        let mut message = Message::binding_request([0x5a; 12]);
        message.attributes.push(Attribute::Other { typ, value: value.iter().take(MAX_VALUE + 1).copied().collect() });
        contract::check_wire_value(&message);
        message.method = typ;
        contract::check_wire_value(&message);
        if let Ok(attribute) = &r {
            message.method = 1;
            message.attributes = vec![attribute.clone()];
            contract::check_wire_value(&message);
        }
        if value.len() > MAX_VALUE {
            assert!(r.is_err());
        }
    }

    // The bytes as a stream, split two ways: all at once, and a byte at a
    // time. Both give the same messages and errors, and a loop that takes
    // messages out until `None` ends, even after a framing error. Each
    // frame is the bytes as they came, and reads as the message does.
    let mut whole = Decoder::new();
    let mut messages = Vec::new();
    let mut rest = data;
    let mut at = 0;
    loop {
        let took = whole.feed(rest);
        rest = &rest[took..];
        while let Some(r) = whole.next_frame() {
            let r = r.and_then(|frame| {
                assert_eq!(frame, &data[at..at + frame.len()]);
                at += frame.len();
                Message::parse(frame)
            });
            messages.push(r);
        }
        assert!(whole.buffered() <= MAX_BUFFERED);
        if rest.is_empty() {
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        while let Some(r) = bytewise.next_message() {
            again.push(r);
        }
    }
    assert_eq!(messages, again);
    assert_eq!(whole.error(), bytewise.error());
});
