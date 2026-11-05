//! IEC 104 APDUs, ASDUs and both information object address layouts.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::iec104::{Asdu, Frame, Object};
use libfuzzer_sys::fuzz_target;

fn asdu(bytes: &[u8]) {
    if let Ok(value) = <Asdu as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(asdu) = <Asdu as Wire>::parse(bytes) {
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
        if let Frame::Information { asdu: bytes, .. } = frame {
            asdu(bytes);
        }
    }
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
            let _ = assert_write(&frame);
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
        let _ = assert_write(&built);
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
