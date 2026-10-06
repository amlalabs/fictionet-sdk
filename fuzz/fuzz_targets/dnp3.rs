//! DNP3 framing, CRCs, transport and application fragments.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Stream, Wire, pump};
use fictionet::stdlib::dnp3::Frames;
use fictionet::stdlib::dnp3::{Fragment, Frame, MAX_FRAGMENT, Reassembler, Segment};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode(Frames::new, data);
    check_wire::<Frame>(data);
    let mut stream = Stream::new(Frames);
    let mut frames = Vec::new();
    let _ = pump(&mut stream, data, |frame| frames.push(frame));
    for frame in &frames {
        check_wire_value(frame);
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(<Frame as Wire>::parse(&bytes), Ok(frame.clone()));
        if let Ok(segment) = frame.segment() {
            assert_eq!(
                <Segment as Wire>::parse(&segment.to_bytes().unwrap()),
                Ok(segment)
            );
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
        check_wire_value(&frame);
        let bytes = frame.to_bytes().unwrap();
        check_decode(Frames::new, &bytes);
    }
    check_wire_value(&Frame {
        control: data.first().copied().unwrap_or(0),
        destination: 1,
        source: 1024,
        data: data
            .get(..data.len().min(fictionet::stdlib::dnp3::MAX_DATA + 1))
            .unwrap_or_default()
            .to_vec(),
    });
    check_wire::<Segment>(data);
    check_wire::<Fragment>(data);
    if let Ok(segment) = <Segment as Wire>::parse(data) {
        assert_eq!(
            <Segment as Wire>::parse(&segment.to_bytes().unwrap()),
            Ok(segment)
        );
    }
    if let Ok(fragment) = <Fragment as Wire>::parse(data) {
        assert_eq!(
            <Fragment as Wire>::parse(&fragment.to_bytes().unwrap()),
            Ok(fragment)
        );
    }
    if data.len() >= 4 {
        let fragment = Fragment {
            control: data[0],
            function: data[1],
            indications: (data[2] & 1 != 0).then_some(u16::from_le_bytes([data[2], data[3]])),
            objects: data[4..].to_vec(),
        };
        if let Ok(bytes) = fragment.to_bytes() {
            assert_eq!(<Fragment as Wire>::parse(&bytes), Ok(fragment));
        }
    }
    let mut reassembler = Reassembler::new();
    for chunk in data.chunks(250) {
        if let Ok(segment) = <Segment as Wire>::parse(chunk) {
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
