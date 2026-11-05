//! SFTP packets and typed payloads through the shared contracts.
#![no_main]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::sftp::harness::check_packet;
use fictionet::stdlib::protocols::sftp::{
    Attrs, MAX_FRAME, MAX_PACKET, Packet, Request, Response, Status,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_FRAME);
            }
        ),
        decode_all(Frames::<Packet>::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::with_limit(64)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 136);
            }
        ),
        decode_all(|| Frames::<Packet>::with_limit(64), data),
    );
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Request as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Response as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Attrs as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for packet in decode_all(Frames::<Packet>::new, data).0 {
        if let Ok(value) = <Request as Wire>::parse(&packet.to_bytes().unwrap()) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <Response as Wire>::parse(&packet.to_bytes().unwrap()) {
            let _ = assert_write(&value);
        }
    }
    if let Some((&kind, body)) = data.split_first() {
        let packet = Packet {
            kind,
            body: body[..body.len().min(MAX_PACKET)].to_vec(),
        };
        let _ = assert_write(&packet);
        check_packet(&packet);
    }
    let text = String::from_utf8_lossy(data);
    let _ = assert_write(&Response::status(1, Status::Failure, &text));
    let _ = assert_write(&Response::Status {
        id: 1,
        status: Status::Failure,
        message: text.as_bytes().to_vec(),
        language: vec![],
    });
});
