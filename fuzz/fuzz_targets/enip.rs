//! EtherNet/IP packets and the CIP messages inside them, as a world
//! playing a device reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::test_support::decode_all;

use fictionet::stdlib::enip::{
    Cpf, ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
    Identity, MessageRequest, MessageResponse, Packet, RegisterSession, SendData,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode(Frames::<Packet>::new, data);
    check_wire::<Packet>(data);
    let (packets, _) = decode_all(Frames::<Packet>::new, data);
    let built = Packet {
        command: fictionet::stdlib::enip::Command::Other(u16::from(
            data.first().copied().unwrap_or(0),
        )),
        session_handle: 1,
        status: 0,
        sender_context: [0; 8],
        options: u32::from(data.get(1).copied().unwrap_or(0)),
        data: data
            .get(..data.len().min(fictionet::stdlib::enip::MAX_PACKET))
            .unwrap_or_default()
            .to_vec(),
    };
    check_wire_value(&built);
    for p in &packets {
        check_wire_value(p);
        // Validation and writing must agree on whether a packet is allowed.
        assert_eq!(p.check().is_ok(), p.to_bytes().is_ok());
        // The data as each CIP structure: any that reads must write back to
        // bytes that read the same.
        check_wire::<SendData>(&p.data);
        if let Ok(send) = <SendData as Wire>::parse(&p.data) {
            for it in &send.cpf.items {
                check_item(&it.data);
            }
        }
        check_wire::<Cpf>(&p.data);
        if let Ok(cpf) = <Cpf as Wire>::parse(&p.data) {
            for it in &cpf.items {
                check_item(&it.data);
            }
        }
        check_item(&p.data);
    }

    // Any bytes on their own, as each structure. None may panic, and each
    // read must write back to bytes that read the same.
    check_wire::<Cpf>(data);
    check_wire::<SendData>(data);
    check_wire::<RegisterSession>(data);
    check_wire::<ForwardOpenRequest>(data);
    check_wire::<ForwardOpenResponse>(data);
    check_wire::<ForwardCloseRequest>(data);
    check_wire::<ForwardCloseResponse>(data);
    check_item(data);
});

/// The bytes of one item as each CIP structure, and the bodies inside a
/// message: any that reads must write back to bytes that read the same.
fn check_item(b: &[u8]) {
    check_wire::<MessageRequest>(b);
    check_wire::<MessageResponse>(b);
    check_wire::<Identity>(b);
    if let Ok(req) = <MessageRequest as Wire>::parse(b) {
        check_wire::<ForwardOpenRequest>(&req.data);
        check_wire::<ForwardCloseRequest>(&req.data);
    }
    if let Ok(resp) = <MessageResponse as Wire>::parse(b) {
        check_wire::<ForwardOpenResponse>(&resp.data);
        check_wire::<ForwardCloseResponse>(&resp.data);
    }
}
