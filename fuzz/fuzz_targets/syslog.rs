//! Syslog messages and TCP frames through the shared codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::syslog::{
    BsdMessage, BsdTimestamp, Entry, Frame, Frames, Framing, MAX_BUFFERED, MAX_MESSAGE_LEN, Message, Priority,
    SdElement, Timestamp,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_BUFFERED);
    contract::check_decode_with_alloc_limit(
        || Frames::new().map(|frame| Entry::parse(&frame.message)),
        data,
        2 * MAX_BUFFERED,
    );
    contract::check_wire::<Frame>(data);
    round_trip(data);
    for frame in decode_all(Frames::new, data).0 {
        contract::check_wire_value(&frame);
        assert!(!frame.message.is_empty() && frame.message.len() <= MAX_MESSAGE_LEN);
        round_trip(&frame.message);
    }
    let priority = Priority::from_value(data.first().map_or(13, |&b| b % 192)).unwrap();
    let rest = data.get(1..).unwrap_or(&[]);
    let entry = Entry::Bsd(BsdMessage::new(priority, rest));
    contract::check_wire_value(&entry);
    let mut message = Message::new(priority);
    let value = String::from_utf8_lossy(rest).repeat(1 + MAX_MESSAGE_LEN / rest.len().saturating_add(1) / 2);
    message.structured_data.push(SdElement::new("x@32473").param("p", value));
    contract::check_wire_value(&message);
    for framing in [Framing::OctetCounting, Framing::NonTransparent] {
        let mut frame = Frame::new(framing, rest.iter().take(MAX_MESSAGE_LEN + 1).copied().collect());
        contract::check_wire_value(&frame);
        frame.truncated = true;
        contract::check_wire_value(&frame);
    }
});

fn round_trip(bytes: &[u8]) {
    contract::check_wire::<Message>(bytes);
    contract::check_wire::<BsdMessage>(bytes);
    contract::check_wire::<Entry>(bytes);
    contract::check_wire::<Timestamp>(bytes);
    contract::check_wire::<BsdTimestamp>(bytes);
}
