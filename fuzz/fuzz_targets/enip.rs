//! EtherNet/IP packets and the CIP messages inside them, as a world
//! playing a device reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::enip::{
    Cpf, ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
    Packet, RegisterSession, SendData, harness,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::new()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(Frames::<Packet>::new, data),
    );
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let (packets, _) = decode_all(Frames::<Packet>::new, data);
    let built = Packet {
        command: fictionet::stdlib::protocols::enip::Command::Other(u16::from(
            data.first().copied().unwrap_or(0),
        )),
        session_handle: 1,
        status: 0,
        sender_context: [0; 8],
        options: u32::from(data.get(1).copied().unwrap_or(0)),
        data: data
            .get(
                ..data
                    .len()
                    .min(fictionet::stdlib::protocols::enip::MAX_PACKET),
            )
            .unwrap_or_default()
            .to_vec(),
    };
    let _ = assert_write(&built);
    for p in &packets {
        harness::check_packet(p);
    }

    // Any bytes on their own, as each structure. None may panic, and each
    // read must write back to bytes that read the same.
    if let Ok(value) = <Cpf as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <SendData as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <RegisterSession as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ForwardOpenRequest as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ForwardOpenResponse as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ForwardCloseRequest as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ForwardCloseResponse as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    harness::check_item(data);
});
