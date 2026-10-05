//! DNP3 framing, CRCs, transport and application fragments.
#![no_main]

use fictionet::stdlib::dnp3::{
    Decoder, Fragment, Frame, FrameError, MAX_BUFFERED, MAX_FRAGMENT, Reassembler, Segment,
};
use libfuzzer_sys::fuzz_target;

fn split(data: &[u8], size: usize, drain_each: bool) -> Vec<Result<Frame, FrameError>> {
    let mut decoder = Decoder::new();
    let mut out = Vec::new();
    for mut chunk in data.chunks(size.max(1)) {
        while !chunk.is_empty() {
            let n = decoder.feed(chunk);
            chunk = &chunk[n..];
            assert!(decoder.buffered() <= MAX_BUFFERED);
            if drain_each || !chunk.is_empty() {
                let before = out.len();
                while let Some(frame) = decoder.next_frame() {
                    let failed = frame.is_err();
                    out.push(frame);
                    if failed {
                        assert_eq!(decoder.buffered(), 0);
                        assert_eq!(decoder.next_frame(), out.last().cloned());
                        return out;
                    }
                }
                assert!(n > 0 || out.len() > before);
            }
        }
    }
    while let Some(frame) = decoder.next_frame() {
        let failed = frame.is_err();
        out.push(frame);
        if failed {
            break;
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let frames = split(data, data.len(), true);
    for (size, drain) in [(1, true), (7, false), (MAX_BUFFERED + 1, false)] {
        assert_eq!(split(data, size, drain), frames);
    }
    for frame in frames.iter().flatten() {
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(Frame::parse(&bytes), Ok(Some((frame.clone(), bytes.len()))));
        if let Ok(segment) = frame.segment() {
            assert_eq!(Segment::parse(&segment.to_bytes().unwrap()), Ok(segment));
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
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(split(&bytes, 1, true), vec![Ok(frame)]);
    }
    let _ = Frame::parse(data);
    if let Ok(segment) = Segment::parse(data) {
        assert_eq!(Segment::parse(&segment.to_bytes().unwrap()), Ok(segment));
    }
    if let Ok(fragment) = Fragment::parse(data) {
        assert_eq!(Fragment::parse(&fragment.to_bytes().unwrap()), Ok(fragment));
    }
    if data.len() >= 4 {
        let fragment = Fragment {
            control: data[0],
            function: data[1],
            indications: (data[2] & 1 != 0).then_some(u16::from_le_bytes([data[2], data[3]])),
            objects: data[4..].to_vec(),
        };
        if let Ok(bytes) = fragment.to_bytes() {
            assert_eq!(Fragment::parse(&bytes), Ok(fragment));
        }
    }
    let mut reassembler = Reassembler::new();
    for chunk in data.chunks(250) {
        if let Ok(segment) = Segment::parse(chunk) {
            let _ = reassembler.push(&segment);
            assert!(reassembler.buffered() <= MAX_FRAGMENT);
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
