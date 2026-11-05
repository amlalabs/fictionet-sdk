//! Thrift frames, messages, and values in the binary and compact protocols.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::protocols::thrift::{
    EncodedMessage, EncodedMessages, Frame, MAX_FRAME, ValueBody, harness,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check_messages(EncodedMessages::new, data);
    let bound = 2 * Frames::<Frame>::new().capacity();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    let limit = usize::from(data.first().copied().unwrap_or(0));
    let bound = 2 * Frames::<Frame>::with_limit(limit).capacity();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::with_limit(limit)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Frames::<Frame>::with_limit(limit), data),
    );
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let bound = 2 * Frames::<Frame>::new().capacity();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new().map(|frame| EncodedMessage::parse(&frame.0))),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(
            || Frames::<Frame>::new().map(|frame| EncodedMessage::parse(&frame.0)),
            data
        ),
    );
    let _ = assert_write(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));
    for frame in decode_all(Frames::<Frame>::new, data).0 {
        let _ = assert_write(&frame);
        if let Ok(value) = <EncodedMessage as Wire>::parse(&frame.0) {
            let _ = assert_write(&value);
        }
    }
    macro_rules! values {
        ($($code:literal),*) => { $(
            if let Ok(value) = <ValueBody<false, $code> as Wire>::parse(data) {
                let _ = assert_write(&value);
            }
            if let Ok(value) = <ValueBody<true, $code> as Wire>::parse(data) {
                let _ = assert_write(&value);
            }
        )* };
    }
    values!(2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16);
});
