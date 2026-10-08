//! SFTP packets and typed payloads through the shared contracts.
#![no_main]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::sftp::{Attrs, MAX_FRAME, MAX_PACKET, Packet, Request, Response, Status};
use fictionet::stdlib::sftp::harness::{check_packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Packet>::new, data, 2 * MAX_FRAME);
    contract::check_decode_with_alloc_limit(|| Frames::<Packet>::with_limit(64), data, 136);
    contract::check_wire::<Packet>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<Attrs>(data);
    for packet in decode_all(Frames::<Packet>::new, data).0 {
        contract::check_wire::<Request>(&packet.to_bytes().unwrap());
        contract::check_wire::<Response>(&packet.to_bytes().unwrap());
    }
    if let Some((&kind, body)) = data.split_first() {
        let packet = Packet { kind, body: body[..body.len().min(MAX_PACKET)].to_vec() };
        contract::check_wire_value(&packet);
        check_packet(&packet);
    }
    let text = String::from_utf8_lossy(data);
    contract::check_wire_value(&Response::status(1, Status::Failure, &text));
    contract::check_wire_value(&Response::Status { id: 1, status: Status::Failure,
        message: text.as_bytes().to_vec(), language: vec![] });
});
