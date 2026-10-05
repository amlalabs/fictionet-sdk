//! CoAP datagrams and CoAP-over-TCP streams, as a world playing a device
//! reads them.
#![no_main]

use fictionet::stdlib::coap::{
    Assembler, Block, BlockError, Code, Decoder, Frame, Frames, MAX_BUFFERED, MAX_DATAGRAM, Message, Options, Type, option, peek_header,
};
use libfuzzer_sys::fuzz_target;
use fictionet::stdlib::codec::contract;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Frame>(data);
    let mut built = Message::new(Type::Reset, Code(data.first().copied().unwrap_or(0)), 1);
    built.token = data.iter().take(9).copied().collect();
    built.payload = data.iter().take(MAX_DATAGRAM + 1).copied().collect();
    contract::check_wire_value(&built);
    contract::check_wire_value(&Frame {
        code: built.code,
        token: built.token.clone(),
        options: Options::new(),
        payload: built.payload.clone(),
    });
    // The bytes as one datagram. The encoding has one form for each
    // message, so a message read writes back as the same bytes.
    let _ = peek_header(data);
    if let Ok(m) = Message::parse(data) {
        contract::check_wire_value(&m);
        let mut reordered = m.clone();
        reordered.options.0.reverse();
        contract::check_wire_value(&reordered);
        assert_eq!(m.to_bytes(), data);
        // RFC 7252 sections 4.2 and 4.3: a reader keeps only the forms a
        // type allows.
        match m.kind {
            Type::Acknowledgement => assert!(m.code.is_empty() || m.code.is_response()),
            Type::Reset => assert!(m.code.is_empty()),
            Type::NonConfirmable => assert!(!m.code.is_empty()),
            Type::Confirmable => {}
        }
        // A message read writes back whole, unless it carries SZX 7.
        assert_eq!(m.try_to_bytes().is_some(), m.bad_block().is_none());
        let o = &m.options;
        let _ = (m.bad_option(), o.uri_path(), o.uri_query(), o.content_format(), o.accept(), o.max_age());
        let _ = (o.observe(), o.size1(), o.size2(), o.uri_host(), o.uri_port());
        // A Uri-Path of `.` or `..` is a bad critical option, and no path
        // reads from it.
        if o.get_all(option::URI_PATH).any(|s| s == b"." || s == b"..") {
            assert!(m.bad_option().is_some());
            assert_eq!(o.uri_path(), None);
        }
        // A critical string option that is not UTF-8 is a bad option.
        if o.get(option::URI_HOST).is_some_and(|v| std::str::from_utf8(v).is_err()) {
            assert!(m.bad_option().is_some());
        }
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
        // A Block1 block the message carries: SZX 7 is refused with 4.00
        // over UDP, any last block within the limit is taken, and the
        // body stays in bounds.
        if let Some(block) = o.block1() {
            let mut a = Assembler::new(1 << 16);
            let r = a.push(block, &m.payload);
            if block.is_bert() {
                assert_eq!(m.bad_block(), Some(option::BLOCK1));
                if block.num == 0 {
                    assert_eq!(r, Err(BlockError::Size));
                }
            } else if block.num == 0 && !block.more {
                assert_eq!(r, Ok(true));
            }
            assert!(a.body().len() <= 1 << 16);
        }
        if let Some(Block { num, szx, .. }) = o.block2() {
            let _ = Block::take(&m.payload, num, szx);
        }
    }

    // The bytes as a series of blocks: a body cut with Block::take goes
    // back together whatever the block size, and a cut that is out of
    // order or the wrong size is refused without changing the body.
    if let [szx, rest @ ..] = data {
        let szx = szx % 7;
        let mut a = Assembler::new(rest.len());
        let mut num = 0;
        while let Some((block, chunk)) = Block::take(rest, num, szx) {
            let before = a.body().len();
            if num > 0 {
                let skipped = Block { num: num + 1, ..block };
                assert!(matches!(a.push(skipped, chunk), Err(BlockError::OutOfOrder { .. })));
                assert_eq!(a.body().len(), before);
            }
            if a.push(block, chunk).unwrap() {
                break;
            }
            num += 1;
        }
        assert!(a.is_done());
        assert_eq!(a.body(), rest);
    }

    // The bytes as a TCP stream, split two ways: all at once, and a byte
    // at a time. Both give the same frames and errors, and a decoder
    // never holds more than MAX_BUFFERED bytes.
    let mut whole = Decoder::new();
    let mut frames = Vec::new();
    let mut at = 0;
    loop {
        at += whole.feed(&data[at..]);
        assert!(whole.buffered() <= MAX_BUFFERED);
        match whole.next_frame() {
            Some(r) => frames.push(r),
            None => break,
        }
        if whole.is_broken() {
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
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
        contract::check_wire_value(f);
        let bytes = f.to_bytes();
        contract::check_wire::<Frame>(&bytes);
        assert_eq!(f.try_to_bytes().as_ref(), Some(&bytes));
        let (back, used) = Frame::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, f);
        assert_eq!(used, bytes.len());
        let _ = (f.bad_option(), f.max_message_size());
        assert!(Frame::parse(&f.pong().to_bytes()).unwrap().is_some());
    }
});
