//! CME MDP 3.0: generated SBE messages, hand-written packets, and the
//! size-prefixed message framer.
#![no_main]

use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::protocols::cme_mdp3::{Message, Messages, PACKET_HEADER, Packet};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 8192;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let bound = 4 * usize::from(u16::MAX);
    assert_eq!(
        decode_chunks(&mut Stream::new(Messages), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(|| Messages, data),
    );
    if let Some(body) = data.get(PACKET_HEADER..) {
        let bound = 4 * usize::from(u16::MAX);
        assert_eq!(
            decode_chunks(&mut Stream::new(Messages), chunks(body, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= bound);
            }),
            decode_all(|| Messages, body),
        );
    }
});
