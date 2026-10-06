//! IEC 104 APDUs, ASDUs and both information object address layouts.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Stream, Wire, pump};
use fictionet::stdlib::iec104::Frames;
use fictionet::stdlib::iec104::{Asdu, Frame, Object};
use libfuzzer_sys::fuzz_target;

fn asdu(bytes: &[u8]) {
    if let Ok(asdu) = <Asdu as Wire>::parse(bytes) {
        assert_eq!(
            <Asdu as Wire>::parse(&asdu.to_bytes().unwrap()),
            Ok(asdu.clone())
        );
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
    check_decode(Frames::new, data);
    check_wire::<Frame>(data);
    let mut stream = Stream::new(Frames);
    let mut frames = Vec::new();
    let _ = pump(&mut stream, data, |frame| frames.push(frame));
    for frame in &frames {
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(<Frame as Wire>::parse(&bytes), Ok(frame.clone()));
        if let Frame::Information { asdu: bytes, .. } = frame {
            asdu(bytes);
        }
    }
    check_wire::<Asdu>(data);
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
            check_wire_value(&frame);
            if let Ok(bytes) = frame.to_bytes() {
                assert_eq!(<Frame as Wire>::parse(&bytes), Ok(frame));
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
            assert_eq!(<Asdu as Wire>::parse(&bytes), Ok(built.clone()));
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
