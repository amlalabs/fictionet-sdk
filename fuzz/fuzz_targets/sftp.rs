//! SFTP packets, requests and responses, as a world playing a file server
//! reads them.
#![no_main]

use fictionet::stdlib::sftp::{Decoder, Packet, Request, Response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
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
        if let Ok(req) = Request::parse(&p) {
            assert_eq!(Request::parse(&req.to_packet()), Ok(req));
        }
        if let Ok(resp) = Response::parse(&p) {
            assert_eq!(Response::parse(&resp.to_packet()), Ok(resp));
        }
    }
});
