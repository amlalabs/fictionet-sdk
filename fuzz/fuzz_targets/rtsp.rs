//! RTSP messages, interleaved frames, and header values through codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract, test_support::decode_all};
use fictionet::stdlib::rtsp::{
    Frames, Interleaved, Item, MAX_BODY, MAX_INTERLEAVED, MAX_MESSAGE, Message, Range, Session, Transport,
    Transports, Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_MESSAGE);
    contract::check_decode_with_held_limit(Frames::new, data, 0);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Item>(data);
    contract::check_wire::<Interleaved>(data);
    contract::check_wire::<Session>(data);
    contract::check_wire::<Range>(data);
    contract::check_wire::<Transport>(data);
    contract::check_wire::<Transports>(data);

    let frame = Interleaved {
        channel: data.first().copied().unwrap_or(0),
        data: data.get(..MAX_INTERLEAVED + 1).unwrap_or(data).to_vec(),
    };
    contract::check_wire_value(&frame);
    let mut message = Message::response(Version::Rtsp20, 200, "OK");
    message.body = data.get(..MAX_BODY + 1).unwrap_or(data).to_vec();
    message.push_header("Content-Length", &message.body.len().to_string());
    contract::check_wire_value(&message);
    if let Ok(bytes) = message.to_bytes() {
        contract::check_wire::<Message>(&bytes);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_MESSAGE);
    }
    message.push_header("X", " leading");
    contract::check_wire_value(&message);

    let (items, _) = decode_all(Frames::new, data);
    for item in items.iter().flatten() {
        contract::check_wire_value(item);
        if let Item::Message(message) = item {
            if let Ok(value) = message.session() {
                contract::check_wire_value(&value);
            }
            if let Ok(value) = message.range() {
                contract::check_wire_value(&value);
            }
            if let Ok(values) = message.transports() {
                contract::check_wire_value(&Transports { values });
            }
        }
    }
});
