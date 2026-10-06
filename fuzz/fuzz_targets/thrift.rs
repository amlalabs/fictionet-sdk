//! Thrift frames, messages, and values in the binary and compact protocols.
#![no_main]

use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire, contract, test_support::decode_all};
use fictionet::stdlib::thrift::{
    EncodedMessage, Error, Frame, Frames, MAX_FRAME, MAX_MESSAGE, Messages, ValueBody,
};
use libfuzzer_sys::fuzz_target;

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
    let mut stream = Stream::new(Messages::new());
    let mut pushed = 0;
    let mut start = 0;
    while !stream.is_done() {
        pushed += stream.push(&data[pushed..]);
        if pushed == data.len() {
            stream.end();
        }
        while let Some(item) = stream.next() {
            let Ok(value) = item else { break };
            let end = usize::try_from(stream.offset()).unwrap();
            assert_eq!(EncodedMessage::parse(&data[start..end]), Ok(value.clone()));
            contract::check_wire_value(&value);
            start = end;
        }
    }
    let rest = &data[start..];
    match stream.failed() {
        Some(Fail::Protocol(error)) => {
            let expected = EncodedMessage::parse(rest).unwrap_err();
            // An exact read checks the total length before the header. The
            // stream can report a malformed prefix before reaching that limit.
            if rest.len() <= MAX_MESSAGE && !matches!(expected, Error::Truncated | Error::Trailing) {
                assert_eq!(*error, expected);
            }
        }
        Some(Fail::Truncated { .. }) => {
            assert_eq!(EncodedMessage::parse(rest), Err(Error::Truncated));
        }
        Some(Fail::Stuck { .. }) => panic!("message decoder made no progress"),
        None => assert!(rest.is_empty()),
    }
    macro_rules! values {
        ($($code:literal),*) => { $(
            contract::check_wire::<ValueBody<false, $code>>(data);
            contract::check_wire::<ValueBody<true, $code>>(data);
        )* };
    }
    values!(2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16);
});
