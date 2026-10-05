//! CoAP datagrams and CoAP-over-TCP streams, as a world playing a device
//! reads them.
#![no_main]

use fictionet::stdlib::coap::{Assembler, Block, Code, Decoder, Frame, MAX_DATAGRAM, Message, Options, option, peek_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram. The encoding has one form for each
    // message, so a message read writes back as the same bytes.
    let _ = peek_header(data);
    if let Ok(m) = Message::parse(data) {
        assert_eq!(m.to_bytes(), data);
        let o = &m.options;
        let _ = (m.bad_option(), o.uri_path(), o.uri_query(), o.content_format(), o.accept(), o.max_age());
        let _ = (o.observe(), o.size1(), o.size2(), o.uri_host(), o.uri_port());
        // A path read writes back as the same segments, except one empty
        // segment, which reads as `/` like no segment at all.
        if let Some(path) = o.uri_path() {
            let mut again = Options::new();
            again.set_uri_path(&path);
            let segments: Vec<&[u8]> = o.get_all(option::URI_PATH).collect();
            let back: Vec<&[u8]> = again.get_all(option::URI_PATH).collect();
            assert!(back == segments || (segments == [&b""[..]] && back.is_empty()));
        }
        if let Some(path) = o.location_path() {
            let mut again = Options::new();
            again.set_location_path(&path);
            let segments: Vec<&[u8]> = o.get_all(option::LOCATION_PATH).collect();
            let back: Vec<&[u8]> = again.get_all(option::LOCATION_PATH).collect();
            assert!(back == segments || (segments == [&b""[..]] && back.is_empty()));
        }
        // A reply always reads back.
        let reply = m.reply(Code::CONTENT, 1).to_bytes();
        assert!(reply.len() <= MAX_DATAGRAM);
        assert!(Message::parse(&reply).is_ok());
        // A Block1 block the message carries goes into an assembler
        // without trouble, and its payload stays in bounds.
        if let Some(block) = o.block1() {
            let mut a = Assembler::new(1 << 16);
            let _ = a.push(block, &m.payload);
            assert!(a.body().len() <= 1 << 16);
        }
        if let Some(Block { num, szx, .. }) = o.block2() {
            let _ = Block::take(&m.payload, num, szx);
        }
    }

    // The bytes as a TCP stream, split two ways: all at once, and a byte
    // at a time. Both give the same frames and errors.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut frames = Vec::new();
    while let Some(r) = whole.next_frame() {
        frames.push(r);
        if whole.is_broken() {
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(r) = bytewise.next_frame() {
            again.push(r);
            if bytewise.is_broken() {
                break;
            }
        }
        if bytewise.is_broken() {
            break;
        }
    }
    assert_eq!(frames, again);

    // A frame read writes back as the same bytes, and reads back the same.
    for f in frames.iter().flatten() {
        let bytes = f.to_bytes();
        let (back, used) = Frame::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, f);
        assert_eq!(used, bytes.len());
        let _ = (f.bad_option(), f.max_message_size());
        assert!(Frame::parse(&f.pong().to_bytes()).unwrap().is_some());
    }
});
