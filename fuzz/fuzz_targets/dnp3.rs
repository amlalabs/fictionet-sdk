//! DNP3 framing, CRCs, transport and application fragments.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::dnp3::{Fragment, Frame, MAX_FRAGMENT, Reassembler, Segment};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let (frames, _) = decode_all(Frames::<Frame>::new, data);
    for frame in &frames {
        let _ = assert_write(frame);
        if let Ok(segment) = frame.segment() {
            let _ = assert_write(&segment);
        }
    }
    // Structured input reaches CRC-protected payloads even for random bytes.
    for chunk in data.chunks(250) {
        let frame = Frame {
            control: data[0],
            destination: 1,
            source: 1024,
            data: chunk.to_vec(),
        };
        let _ = assert_write(&frame);
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(
            decode_chunks(
                &mut Stream::new(Frames::<Frame>::new()),
                chunks(&bytes, &[1, 7, 64]),
                |_| {}
            ),
            decode_all(Frames::<Frame>::new, &bytes),
        );
        let (back, failure) = decode_all(Frames::<Frame>::new, &bytes);
        assert!(failure.is_none());
        assert_eq!(back, [frame]);
    }
    let _ = assert_write(&Frame {
        control: data.first().copied().unwrap_or(0),
        destination: 1,
        source: 1024,
        data: data
            .get(
                ..data
                    .len()
                    .min(fictionet::stdlib::protocols::dnp3::MAX_DATA + 1),
            )
            .unwrap_or_default()
            .to_vec(),
    });
    if let Ok(value) = <Segment as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Fragment as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if data.len() >= 4 {
        let fragment = Fragment {
            control: data[0],
            function: data[1],
            indications: (data[2] & 1 != 0).then_some(u16::from_le_bytes([data[2], data[3]])),
            objects: data[4..].to_vec(),
        };
        let _ = assert_write(&fragment);
    }
    let mut reassembler = Reassembler::new();
    for chunk in data.chunks(250) {
        if let Ok(segment) = <Segment as Wire>::parse(chunk) {
            let _ = reassembler.push(&segment);
            assert!(reassembler.pending() <= MAX_FRAGMENT);
        }
    }
    if !data.is_empty() && data.len() <= MAX_FRAGMENT {
        let mut reassembler = Reassembler::new();
        let mut result = None;
        let count = data.len().div_ceil(249);
        for (i, chunk) in data.chunks(249).enumerate() {
            let segment = Segment {
                first: i == 0,
                final_segment: i + 1 == count,
                sequence: ((usize::from(data[0]) + i) & 63) as u8,
                data: chunk.to_vec(),
            };
            result = reassembler.push(&segment).unwrap();
        }
        assert_eq!(result.as_deref(), Some(data));
    }
});
