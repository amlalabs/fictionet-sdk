//! EtherNet/IP packets and the CIP messages inside them, as a world
//! playing a device reads them.
#![no_main]

use fictionet::stdlib::enip::{
    Cpf, Decoder, ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
    Identity, MessageRequest, MessageResponse, Packet, RegisterSession, SendData,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(p) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(p) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        let (back, used) = Packet::parse(&bytes).unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
        // The data as each CIP structure: any that reads must write back to
        // bytes that read the same.
        if let Ok(send) = SendData::parse(&p.data) {
            for it in &send.cpf.items {
                check_item(&it.data);
            }
            assert_eq!(SendData::parse(&send.to_bytes()), Ok(send));
        }
        if let Ok(cpf) = Cpf::parse(&p.data) {
            for it in &cpf.items {
                check_item(&it.data);
            }
            assert_eq!(Cpf::parse(&cpf.to_bytes()), Ok(cpf));
        }
        check_item(&p.data);
    }

    // Any bytes on their own, as each structure. None may panic, and each
    // read must write back to bytes that read the same.
    if let Ok(cpf) = Cpf::parse(data) {
        assert_eq!(Cpf::parse(&cpf.to_bytes()), Ok(cpf));
    }
    if let Ok(rs) = RegisterSession::parse(data) {
        assert_eq!(RegisterSession::parse(&rs.to_bytes()), Ok(rs));
    }
    if let Ok(fo) = ForwardOpenRequest::parse(data) {
        assert_eq!(ForwardOpenRequest::parse(&fo.to_bytes()), Ok(fo));
    }
    if let Ok(fo) = ForwardOpenResponse::parse(data) {
        assert_eq!(ForwardOpenResponse::parse(&fo.to_bytes()), Ok(fo));
    }
    if let Ok(fc) = ForwardCloseRequest::parse(data) {
        assert_eq!(ForwardCloseRequest::parse(&fc.to_bytes()), Ok(fc));
    }
    if let Ok(fc) = ForwardCloseResponse::parse(data) {
        assert_eq!(ForwardCloseResponse::parse(&fc.to_bytes()), Ok(fc));
    }
    check_item(data);
});

/// The bytes of one item as each CIP structure, and the bodies inside a
/// message: any that reads must write back to bytes that read the same.
fn check_item(b: &[u8]) {
    if let Ok(req) = MessageRequest::parse(b) {
        if let Ok(fo) = ForwardOpenRequest::parse(&req.data) {
            assert_eq!(ForwardOpenRequest::parse(&fo.to_bytes()), Ok(fo));
        }
        if let Ok(fc) = ForwardCloseRequest::parse(&req.data) {
            assert_eq!(ForwardCloseRequest::parse(&fc.to_bytes()), Ok(fc));
        }
        assert_eq!(MessageRequest::parse(&req.to_bytes()), Ok(req));
    }
    if let Ok(resp) = MessageResponse::parse(b) {
        if let Ok(fo) = ForwardOpenResponse::parse(&resp.data) {
            assert_eq!(ForwardOpenResponse::parse(&fo.to_bytes()), Ok(fo));
        }
        assert_eq!(MessageResponse::parse(&resp.to_bytes()), Ok(resp));
    }
    if let Ok(id) = Identity::parse(b) {
        assert_eq!(Identity::parse(&id.to_bytes()), Ok(id));
    }
}
