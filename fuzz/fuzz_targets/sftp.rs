//! SFTP packets, requests and responses, as a world playing a file server
//! reads them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::sftp::{Decoder, Frames, LENGTH_LEN, MAX_PACKET, MAX_TEXT, Packet, Request, Response, Status};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in pieces of `step` bytes, taking packets out after each
/// feed, and checks the decoder never holds more than one packet.
fn decode(data: &[u8], step: usize) -> Vec<Packet> {
    let mut decoder = Decoder::new();
    let mut packets = Vec::new();
    let mut rest = data;
    loop {
        let piece = &rest[..rest.len().min(step)];
        let used = decoder.feed(piece);
        assert!(used <= piece.len());
        assert!(decoder.buffered() <= LENGTH_LEN + MAX_PACKET);
        rest = &rest[used..];
        let mut took = false;
        while let Some(p) = decoder.next_packet() {
            match p {
                Ok(p) => packets.push(p),
                Err(_) => return packets,
            }
            took = true;
        }
        if rest.is_empty() {
            return packets;
        }
        // A decoder that takes no bytes always has a packet to give.
        assert!(used > 0 || took);
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode(|| Frames::with_limit(64), data);
    contract::check_wire::<Packet>(data);

    // The stream, split three ways: all at once, a byte at a time, and in
    // pieces whose size the first byte picks.
    let packets = decode(data, usize::MAX);
    assert_eq!(packets, decode(data, 1));
    let step = usize::from(data.first().copied().unwrap_or(0)) + 1;
    assert_eq!(packets, decode(data, step));

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        contract::check_wire::<Packet>(&bytes);
        let (back, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
        if let Ok(req) = Request::parse(p) {
            assert_eq!(Request::parse(&req.to_packet()), Ok(req));
        }
        if let Ok(resp) = Response::parse(p) {
            assert_eq!(Response::parse(&resp.to_packet()), Ok(resp));
        }
    }
    // Any bytes as the body of a packet of the type the first byte names.
    if let Some((&kind, body)) = data.split_first() {
        let p = Packet { kind, body: body.to_vec() };
        let bounded = Packet { kind, body: body.get(..MAX_PACKET).unwrap_or(body).to_vec() };
        contract::check_wire_value(&bounded);
        if let Ok(bytes) = Wire::to_bytes(&bounded) {
            contract::check_decode(Frames::new, &bytes);
        }
        if let Ok(req) = Request::parse(&p) {
            assert_eq!(Request::parse(&req.to_packet()), Ok(req));
        }
        if let Ok(resp) = Response::parse(&p) {
            assert_eq!(Response::parse(&resp.to_packet()), Ok(resp));
        }
    }
    // Any text as a STATUS message, written whole or cut, stays UTF-8.
    let text = String::from_utf8_lossy(data);
    for resp in [
        Response::status(1, Status::Failure, &text),
        Response::Status { id: 1, status: Status::Failure, message: text.as_bytes().to_vec(), language: vec![] },
    ] {
        let Ok(Response::Status { message, .. }) = Response::parse(&resp.to_packet()) else { panic!() };
        assert!(message.len() <= MAX_TEXT);
        assert!(std::str::from_utf8(&message).is_ok());
        assert!(text.as_bytes().starts_with(&message));
    }
});
