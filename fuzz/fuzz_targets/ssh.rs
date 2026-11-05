//! SSH version exchange, cleartext packets, messages, and primitive fields.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::protocols::ssh::*;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_PACKET);
            }
        ),
        decode_all(Frames::<Packet>::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Events::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_PACKET);
            }
        ),
        decode_all(Events::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Events::after_version()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_PACKET);
            }
        ),
        decode_all(Events::after_version, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Lines::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_BANNER_LINE);
            }
        ),
        decode_all(Lines::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::with_limit(usize::from(
                data.first().copied().unwrap_or(0)
            ))),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 510);
            }
        ),
        decode_all(
            || Frames::<Packet>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
            data
        ),
    );
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Line as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Identification as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Byte as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Boolean as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Uint32 as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Uint64 as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <SshString as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Mpint as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <NameList as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let payload = &data[..data.len().min(MAX_PAYLOAD + 1)];
    let _ = assert_write(&Packet {
        payload: payload.to_vec(),
        padding: vec![0; usize::from(data.first().copied().unwrap_or(0))],
    });
    let _ = assert_write(&SshString(payload.to_vec()));
    let _ = assert_write(&Message::Other {
        number: data.first().copied().unwrap_or(0),
        data: payload.to_vec(),
    });
    let _ = assert_write(&Line::Banner(payload.to_vec()));
    for event in decode_all(Events::new, data).0 {
        match event {
            Event::Banner(text) => {
                let _ = assert_write(&Line::Banner(text));
            }
            Event::Version(id) => {
                let _ = assert_write(&id);
            }
            Event::Packet { packet, .. } => {
                let _ = assert_write(&packet);
                if let Ok(value) = <Message as Wire>::parse(&packet.payload) {
                    let _ = assert_write(&value);
                }
            }
        }
    }
    let mut r = Reader::new(data);
    let _ = (
        r.mpint(),
        r.name_list(usize::MAX),
        r.text(usize::MAX),
        r.uint64(),
        r.boolean(),
    );
});
