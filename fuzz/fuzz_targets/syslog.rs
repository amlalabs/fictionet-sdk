//! Syslog messages and TCP frames through the shared codec contracts.
#![no_main]

use fictionet::stdlib::protocols::syslog::harness::{check_round_trip, check_stream};
use fictionet::stdlib::protocols::syslog::{
    BsdMessage, Entry, Frame, Framing, MAX_MESSAGE_LEN, Message, Priority, SdElement,
};
use fictionet::stdlib::test_support::assert_write;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_round_trip(data);
    check_stream(data);
    let priority = Priority::from_value(data.first().map_or(13, |&b| b % 192)).unwrap();
    let rest = data.get(1..).unwrap_or(&[]);
    let entry = Entry::Bsd(BsdMessage::new(priority, rest));
    let _ = assert_write(&entry);
    let mut message = Message::new(priority);
    let value = String::from_utf8_lossy(rest)
        .repeat(1 + MAX_MESSAGE_LEN / rest.len().saturating_add(1) / 2);
    message
        .structured_data
        .push(SdElement::new("x@32473").param("p", value));
    let _ = assert_write(&message);
    for framing in [Framing::OctetCounting, Framing::NonTransparent] {
        let mut frame = Frame::new(
            framing,
            rest.iter().take(MAX_MESSAGE_LEN + 1).copied().collect(),
        );
        let _ = assert_write(&frame);
        frame.truncated = true;
        let _ = assert_write(&frame);
    }
});
