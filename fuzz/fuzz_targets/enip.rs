//! EtherNet/IP packets and the CIP messages inside them, as a world
//! playing a device reads them.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Stream, Wire, pump};
use fictionet::stdlib::enip::Frames;
use fictionet::stdlib::enip::{
    Cpf, ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
    Identity, MessageRequest, MessageResponse, Packet, RegisterSession, SendData,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode(Frames::new, data);
    check_wire::<Packet>(data);
    let mut stream = Stream::new(Frames);
    let mut packets = Vec::new();
    let _ = pump(&mut stream, data, |packet| packets.push(packet));
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
        // A packet that passes the check writes back to bytes that read the
        // same; one that fails it cannot be written.
        match (p.check(), p.to_bytes()) {
            (Ok(()), Ok(bytes)) => {
                let back = <Packet as Wire>::parse(&bytes).unwrap();
                assert_eq!(&back, p);
            }
            (Err(_), Err(_)) => {}
            other => panic!("check and writer disagree: {other:?}"),
        }
        // The data as each CIP structure: any that reads must write back to
        // bytes that read the same.
        if let Ok(send) = <SendData as Wire>::parse(&p.data) {
            for it in &send.cpf.items {
                check_item(&it.data);
            }
            assert_eq!(
                <SendData as Wire>::parse(&send.to_bytes().unwrap()),
                Ok(send)
            );
        }
        if let Ok(cpf) = <Cpf as Wire>::parse(&p.data) {
            for it in &cpf.items {
                check_item(&it.data);
            }
            assert_eq!(<Cpf as Wire>::parse(&cpf.to_bytes().unwrap()), Ok(cpf));
        }
        check_item(&p.data);
    }

    // Any bytes on their own, as each structure. None may panic, and each
    // read must write back to bytes that read the same.
    if let Ok(cpf) = <Cpf as Wire>::parse(data) {
        assert_eq!(<Cpf as Wire>::parse(&cpf.to_bytes().unwrap()), Ok(cpf));
    }
    if let Ok(send) = <SendData as Wire>::parse(data) {
        assert_eq!(
            <SendData as Wire>::parse(&send.to_bytes().unwrap()),
            Ok(send)
        );
    }
    if let Ok(rs) = <RegisterSession as Wire>::parse(data) {
        assert_eq!(
            <RegisterSession as Wire>::parse(&rs.to_bytes().unwrap()),
            Ok(rs)
        );
    }
    if let Ok(fo) = <ForwardOpenRequest as Wire>::parse(data) {
        assert_eq!(
            <ForwardOpenRequest as Wire>::parse(&fo.to_bytes().unwrap()),
            Ok(fo)
        );
    }
    if let Ok(fo) = <ForwardOpenResponse as Wire>::parse(data) {
        assert_eq!(
            <ForwardOpenResponse as Wire>::parse(&fo.to_bytes().unwrap()),
            Ok(fo)
        );
    }
    if let Ok(fc) = <ForwardCloseRequest as Wire>::parse(data) {
        assert_eq!(
            <ForwardCloseRequest as Wire>::parse(&fc.to_bytes().unwrap()),
            Ok(fc)
        );
    }
    if let Ok(fc) = <ForwardCloseResponse as Wire>::parse(data) {
        assert_eq!(
            <ForwardCloseResponse as Wire>::parse(&fc.to_bytes().unwrap()),
            Ok(fc)
        );
    }
    check_wire::<Cpf>(data);
    check_wire::<SendData>(data);
    check_wire::<RegisterSession>(data);
    check_wire::<MessageRequest>(data);
    check_wire::<MessageResponse>(data);
    check_wire::<Identity>(data);
    check_wire::<ForwardOpenRequest>(data);
    check_wire::<ForwardOpenResponse>(data);
    check_wire::<ForwardCloseRequest>(data);
    check_wire::<ForwardCloseResponse>(data);
    check_item(data);
});

/// The bytes of one item as each CIP structure, and the bodies inside a
/// message: any that reads must write back to bytes that read the same.
fn check_item(b: &[u8]) {
    if let Ok(req) = <MessageRequest as Wire>::parse(b) {
        if let Ok(fo) = <ForwardOpenRequest as Wire>::parse(&req.data) {
            assert_eq!(
                <ForwardOpenRequest as Wire>::parse(&fo.to_bytes().unwrap()),
                Ok(fo)
            );
        }
        if let Ok(fc) = <ForwardCloseRequest as Wire>::parse(&req.data) {
            assert_eq!(
                <ForwardCloseRequest as Wire>::parse(&fc.to_bytes().unwrap()),
                Ok(fc)
            );
        }
        assert_eq!(
            <MessageRequest as Wire>::parse(&req.to_bytes().unwrap()),
            Ok(req)
        );
    }
    if let Ok(resp) = <MessageResponse as Wire>::parse(b) {
        if let Ok(fo) = <ForwardOpenResponse as Wire>::parse(&resp.data) {
            assert_eq!(
                <ForwardOpenResponse as Wire>::parse(&fo.to_bytes().unwrap()),
                Ok(fo)
            );
        }
        if let Ok(fc) = <ForwardCloseResponse as Wire>::parse(&resp.data) {
            assert_eq!(
                <ForwardCloseResponse as Wire>::parse(&fc.to_bytes().unwrap()),
                Ok(fc)
            );
        }
        assert_eq!(
            <MessageResponse as Wire>::parse(&resp.to_bytes().unwrap()),
            Ok(resp)
        );
    }
    if let Ok(id) = <Identity as Wire>::parse(b) {
        assert_eq!(<Identity as Wire>::parse(&id.to_bytes().unwrap()), Ok(id));
    }
}
