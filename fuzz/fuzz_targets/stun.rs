//! STUN messages, as a world playing a STUN server reads them from UDP
//! datagrams and TCP streams.
#![no_main]

use fictionet::stdlib::codec::{Decode, Stream, Wire};
use fictionet::stdlib::stun::{Attribute, Frames, MAX_VALUE, Message, answer_binding};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode(
        || Frames::new().map(|frame| <Message as Wire>::parse(&frame)),
        data,
    );
    contract::check_wire::<Message>(data);

    // MESSAGE-INTEGRITY uses each frame's original bytes at its stream offset.
    let mut stream = Stream::new(Frames::new());
    let mut remaining = data;
    loop {
        let taken = stream.push(remaining);
        remaining = &remaining[taken..];
        if remaining.is_empty() {
            stream.end();
        }
        while let Some(result) = stream.with_next(|frame, raw, span| {
            let start = usize::try_from(span.start).unwrap();
            let end = usize::try_from(span.end).unwrap();
            assert_eq!(Some(raw), data.get(start..end));
            assert_eq!(frame, raw);
        }) {
            if result.is_err() {
                break;
            }
        }
        if stream.is_done() {
            break;
        }
        assert!(taken > 0);
    }

    // A parsed datagram writes without changing its value. Canonical
    // padding and ignored attributes may shorten its bytes. Replies
    // preserve the transaction ID.
    if let Ok(m) = <Message as Wire>::parse(data) {
        let bytes = m.to_bytes().unwrap();
        assert!(bytes.len() <= data.len());
        let back = <Message as Wire>::parse(&bytes).unwrap();
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(back, m);
        assert_eq!(
            (back.method, back.class, back.transaction),
            (m.method, m.class, m.transaction)
        );
        // Each attribute that reads back is the first of its type in both.
        assert_eq!(back.xor_mapped_address(), m.xor_mapped_address());
        assert_eq!(back.mapped_address(), m.mapped_address());
        assert_eq!(back.alternate_server(), m.alternate_server());
        assert_eq!(back.unknown_attributes(), m.unknown_attributes());
        let _ = (
            back.username(),
            back.realm(),
            back.nonce(),
            back.software(),
            back.error_code(),
        );
        let source = "192.0.2.1:32853".parse().unwrap();
        if let Some(reply) = answer_binding(&m, source) {
            contract::check_wire_value(&reply);
            let back = <Message as Wire>::parse(&reply.to_bytes().unwrap()).unwrap();
            assert_eq!(back.transaction, m.transaction);
        }
    }

    // The bytes as one attribute: a type from the first two bytes and the
    // rest as the value. A value no message can hold is refused.
    if let [hi, lo, value @ ..] = data {
        let typ = u16::from_be_bytes([*hi, *lo]);
        let r = Attribute::parse(typ, value, &[0x5a; 12]);
        let mut message = Message::binding_request([0x5a; 12]);
        message.attributes.push(Attribute::Other {
            typ,
            value: value.iter().take(MAX_VALUE + 1).copied().collect(),
        });
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
});
