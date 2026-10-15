//! Syslog messages and TCP frames through the shared codec contracts.
#![no_main]

use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::syslog::harness::{check_round_trip, check_stream};
use fictionet::stdlib::syslog::{
    BsdMessage, Entry, Frame, Framing, MAX_MESSAGE_LEN, Message, Priority, SdElement,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_round_trip(data);
    check_stream(data);
    let priority = Priority::from_value(data.first().map_or(13, |&b| b % 192)).unwrap();
    let rest = data.get(1..).unwrap_or(&[]);
    let entry = Entry::Bsd(BsdMessage::new(priority, rest));
    contract::check_wire_value(&entry);
    let mut message = Message::new(priority);
    let value = String::from_utf8_lossy(rest)
        .repeat(1 + MAX_MESSAGE_LEN / rest.len().saturating_add(1) / 2);
    message
        .structured_data
        .push(SdElement::new("x@32473").param("p", value));
    contract::check_wire_value(&message);
    for framing in [Framing::OctetCounting, Framing::NonTransparent] {
        let mut frame = Frame::new(
            framing,
            rest.iter().take(MAX_MESSAGE_LEN + 1).copied().collect(),
        );
        contract::check_wire_value(&frame);
        frame.truncated = true;
        contract::check_wire_value(&frame);
    }
});
