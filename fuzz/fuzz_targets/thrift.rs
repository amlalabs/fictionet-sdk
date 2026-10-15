//! Thrift frames, messages, and values in the binary and compact protocols.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::thrift::{
    EncodedMessage, EncodedMessages, Frame, MAX_FRAME, ValueBody, harness,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check_messages(EncodedMessages::new, data);
    contract::check_decode_capacity(Frames::<Frame>::new, data);
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_capacity(|| Frames::<Frame>::with_limit(limit), data);
    contract::check_wire::<Frame>(data);
    contract::check_decode_with_alloc_limit(
        || Frames::<Frame>::new().map(|frame| EncodedMessage::parse(&frame.0)),
        data,
        2 * Frames::<Frame>::new().capacity(),
    );
    contract::check_wire_value(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));
    for frame in decode_all(Frames::<Frame>::new, data).0 {
        contract::check_wire_value(&frame);
        contract::check_wire::<EncodedMessage>(&frame.0);
    }
    macro_rules! values {
        ($($code:literal),*) => { $(
            contract::check_wire::<ValueBody<false, $code>>(data);
            contract::check_wire::<ValueBody<true, $code>>(data);
        )* };
    }
    values!(2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16);
});
