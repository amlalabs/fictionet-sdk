//! Thrift frames, messages, and values in the binary and compact protocols.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::thrift::{
    EncodedMessage, Frame, Frames, MAX_FRAME, Messages, Protocol, Type, Value, ValueBody,
};
use libfuzzer_sys::fuzz_target;

fn check_value<const COMPACT: bool, const TYPE: u8>(data: &[u8]) {
    contract::check_wire::<ValueBody<COMPACT, TYPE>>(data);
    let protocol = if COMPACT { Protocol::Compact } else { Protocol::Binary };
    if let Some(ty) = Type::from_binary_code(TYPE)
        && let Ok((value, used)) = Value::parse(protocol, ty, data)
    {
        assert!(used <= data.len());
        contract::check_wire_value(&ValueBody::<COMPACT, TYPE>(value));
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Messages::new, data, 2 * Messages::new().capacity());
    contract::check_decode_with_held_limit(Messages::new, data, Messages::new().held());
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * Frames::new().capacity());
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(limit), data, 2 * Frames::with_limit(limit).capacity());
    contract::check_wire::<Frame>(data);
    contract::check_wire::<EncodedMessage>(data);
    contract::check_decode_with_alloc_limit(|| Frames::new().map(|frame| EncodedMessage::parse(&frame.0)), data, 2 * Frames::new().capacity());
    contract::check_wire_value(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));
    for frame in decode_all(Frames::new, data).0 {
        contract::check_wire_value(&frame);
        contract::check_wire::<EncodedMessage>(&frame.0);
    }
    for (message, protocol) in decode_all(Messages::new, data).0 {
        contract::check_wire_value(&EncodedMessage { message, protocol });
    }
    macro_rules! values {
        ($($code:literal),*) => { $(
            check_value::<false, $code>(data);
            check_value::<true, $code>(data);
        )* };
    }
    values!(2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16);
});
