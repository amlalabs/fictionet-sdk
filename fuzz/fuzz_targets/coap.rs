//! CoAP datagrams and CoAP-over-TCP streams, as a world playing a device
//! reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::protocols::coap::Reassembler;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::coap::Block;

use fictionet::stdlib::protocols::coap::Error;

use fictionet::stdlib::protocols::coap::Code;

use fictionet::stdlib::protocols::coap::Frame;

use fictionet::stdlib::protocols::coap::MAX_BUFFERED;

use fictionet::stdlib::protocols::coap::MAX_DATAGRAM;

use fictionet::stdlib::protocols::coap::Message;

use fictionet::stdlib::protocols::coap::Options;

use fictionet::stdlib::protocols::coap::Type;

use fictionet::stdlib::protocols::coap::option;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::coap::harness::check_blocks;
use fictionet::stdlib::protocols::coap::peek_header;
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_BUFFERED);
            }
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    if let Ok(value) = <fictionet::stdlib::protocols::coap::Uint as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let mut built = Message::new(Type::Reset, Code(data.first().copied().unwrap_or(0)), 1);
    built.token = data.iter().take(9).copied().collect();
    built.payload = data.iter().take(MAX_DATAGRAM + 1).copied().collect();
    let _ = assert_write(&built);
    let _ = assert_write(&Frame {
        code: built.code,
        token: built.token.clone(),
        options: Options::new(),
        payload: built.payload.clone(),
    });
    // The bytes as one datagram. The encoding has one form for each
    // message, so a message read writes back as the same bytes.
    let _ = peek_header(data);
    if let Ok(m) = Message::parse(data) {
        let _ = assert_write(&m);
        let mut reordered = m.clone();
        reordered.options.0.reverse();
        let _ = assert_write(&reordered);
        assert_eq!(m.to_bytes().unwrap(), data);
        // RFC 7252 sections 4.2 and 4.3: a reader keeps only the forms a
        // type allows.
        match m.kind {
            Type::Acknowledgement => assert!(m.code.is_empty() || m.code.is_response()),
            Type::Reset => assert!(m.code.is_empty()),
            Type::NonConfirmable => assert!(!m.code.is_empty()),
            Type::Confirmable => {}
        }
        let bad_block = if m.options.block1().is_some_and(|b| b.szx == 7) {
            Some(option::BLOCK1)
        } else if m.options.block2().is_some_and(|b| b.szx == 7) {
            Some(option::BLOCK2)
        } else {
            None
        };
        assert_eq!(m.bad_block(), bad_block);
        let o = &m.options;
        let _ = (
            m.bad_option(),
            o.uri_path(),
            o.uri_query(),
            o.content_format(),
            o.accept(),
            o.max_age(),
        );
        let _ = (
            o.observe(),
            o.size1(),
            o.size2(),
            o.uri_host(),
            o.uri_port(),
        );
        // A Uri-Path of `.` or `..` is a bad critical option, and no path
        // reads from it.
        if o.get_all(option::URI_PATH).any(|s| s == b"." || s == b"..") {
            assert!(m.bad_option().is_some());
            assert_eq!(o.uri_path(), None);
        }
        // A critical string option that is not UTF-8 is a bad option.
        if o.get(option::URI_HOST)
            .is_some_and(|v| std::str::from_utf8(v).is_err())
        {
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
        let reply = m.reply(Code::CONTENT, 1).to_bytes().unwrap();
        assert!(reply.len() <= MAX_DATAGRAM);
        assert!(Message::parse(&reply).is_ok());
        // A Block1 block the message carries: SZX 7 is refused with 4.00
        // over UDP, any last block within the limit is taken, and the
        // body stays in bounds.
        if let Some(block) = o.block1() {
            let mut a = Reassembler::new(1 << 16);
            let r = a.push(block, &m.payload);
            if block.is_bert() {
                assert_eq!(m.bad_block(), Some(option::BLOCK1));
                if block.num == 0 {
                    assert_eq!(r, Err(Error::BlockSize));
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

    // Constructed blocks round-trip within the effective body limit.
    // Oversized bodies are refused or exhaust the block numbers.
    if let [szx, rest @ ..] = data {
        check_blocks(rest, szx % 7, rest.len());
    }

    for frame in decode_all(Frames::<Frame>::new, data).0 {
        let _ = assert_write(&frame);
        let _ = (frame.bad_option(), frame.max_message_size());
        assert!(frame.pong().to_bytes().is_ok());
        let _ = assert_write(&frame.pong());
    }
});
