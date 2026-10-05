//! IEC 104 APDUs, ASDUs and both information object address layouts.
#![no_main]

use fictionet::stdlib::iec104::{Asdu, Decoder, Frame, FrameError, MAX_BUFFERED, Object};
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

fn asdu(bytes: &[u8]) {
    if let Ok(asdu) = Asdu::parse(bytes) {
        assert_eq!(Asdu::parse(&asdu.to_bytes().unwrap()), Ok(asdu.clone()));
        for width in [0, 1, 2, 3, 5, 7, 8, 12, usize::MAX] {
            if let Ok(objects) = asdu.objects(width) {
                let mut back = asdu.clone();
                back.set_objects(&objects, asdu.sequence).unwrap();
                assert_eq!(back, asdu);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let frames = split(data, data.len(), true);
    for (size, drain) in [(1, true), (7, false), (MAX_BUFFERED + 1, false)] {
        assert_eq!(split(data, size, drain), frames);
    }
    for frame in frames.iter().flatten() {
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(Frame::parse(&bytes), Ok(Some((frame.clone(), bytes.len()))));
        if let Frame::Information { asdu: bytes, .. } = frame {
            asdu(bytes);
        }
    }
    let _ = Frame::parse(data);
    asdu(data);
    if data.len() >= 4 {
        let send = u16::from_le_bytes([data[0], data[1]]);
        let receive = u16::from_le_bytes([data[2], data[3]]);
        for frame in [
            Frame::Information {
                send,
                receive,
                asdu: data[4..].to_vec(),
            },
            Frame::Supervisory { receive },
        ] {
            if let Ok(bytes) = frame.to_bytes() {
                assert_eq!(Frame::parse(&bytes), Ok(Some((frame, bytes.len()))));
            }
        }
        let mut built = Asdu {
            type_id: data[0],
            sequence: false,
            count: data[1],
            cause: data[2],
            negative: false,
            test: true,
            originator: data[3],
            common_address: 1,
            data: data[4..].to_vec(),
        };
        if let Ok(bytes) = built.to_bytes() {
            assert_eq!(Asdu::parse(&bytes), Ok(built.clone()));
        }
        let objects: Vec<_> = data
            .chunks(4)
            .map(|b| Object {
                address: u32::from(b[0]),
                value: b[1..].to_vec(),
            })
            .collect();
        for sequence in [false, true] {
            let before = built.clone();
            if built.set_objects(&objects, sequence).is_ok() {
                if built.cause <= 63 {
                    let width = objects.first().map_or(1, |o| o.value.len());
                    assert_eq!(built.objects(width), Ok(objects.clone()));
                }
            } else {
                assert_eq!(built, before);
            }
        }
    }
});
