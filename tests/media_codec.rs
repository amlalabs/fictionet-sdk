//! RTSP and SIP lines, bodies, recovery, and strict wire values.

use fictionet::stdlib::codec::{
    Decode, Fail, Step, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, chunks},
};
use fictionet::stdlib::{rtsp, sdp, sip};

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=media\r\nt=0 0\r\n";

fn decode<D: Decode>(make: impl Fn() -> D, bytes: &[u8], pattern: &[usize]) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Error: Clone,
{
    let mut stream = Stream::new(make());
    let mut items = Vec::new();
    for chunk in chunks(bytes, pattern) {
        if pump(&mut stream, chunk, |item| items.push(item)).is_err() {
            break;
        }
    }
    let _ = finish(&mut stream, |item| items.push(item));
    assert!(stream.is_done());
    assert_eq!(stream.next().map(|_| ()), None);
    (items, stream.failed().cloned())
}

fn rtsp_body() -> rtsp::Message {
    let mut message = rtsp::Message::request(rtsp::Version::Rtsp20, "ANNOUNCE", "rtsp://camera/media");
    message.push_header("CSeq", "1");
    message.push_header("Content-Type", "application/sdp");
    message.body = Wire::to_bytes(&<sdp::SessionDescription as Wire>::parse(SDP).unwrap()).unwrap();
    message.push_header("Content-Length", &message.body.len().to_string());
    message
}

fn sip_body() -> sip::Message {
    let mut message = sip::Message::request("INVITE", "sip:alice@example.com");
    message.push_header("CSeq", "1 INVITE");
    message.push_header("c", "application/sdp");
    message.body = Wire::to_bytes(&<sdp::SessionDescription as Wire>::parse(SDP).unwrap()).unwrap();
    message.push_header("l", &message.body.len().to_string());
    message
}

#[test]
fn rtsp_chunked_round_trip_with_interleaved_media_and_recovery() {
    let body = rtsp_body();
    let mut response = rtsp::Message::response(rtsp::Version::Rtsp10, 204, "No Content");
    // This version and status ignore even an invalid Content-Length.
    response.push_header("Content-Length", "ignored");
    let binary = rtsp::Interleaved { channel: 7, data: b"$\r\n\r\n\0\xff".to_vec() };
    let mut bytes = b"\r\n\n".to_vec();
    Wire::write(&body, &mut bytes).unwrap();
    Wire::write(&binary, &mut bytes).unwrap();
    bytes.extend_from_slice(b"bad start\r\nContent-Length: 4\r\n\r\nbody");
    Wire::write(&response, &mut bytes).unwrap();
    Wire::write(&body, &mut bytes).unwrap();
    let expected = vec![
        Ok(rtsp::Item::Message(body.clone())),
        Ok(rtsp::Item::Interleaved(binary)),
        Err(rtsp::Error::StartLine),
        Ok(rtsp::Item::Message(response)),
        Ok(rtsp::Item::Message(body)),
    ];
    contract::check_stack(rtsp::Frames::new, &bytes);
    contract::check_decode_with_held_limit(rtsp::Frames::new, &bytes, 0);
    for pattern in [&[][..], &[1], &[3, 1, 37], &[64]] {
        assert_eq!(decode(rtsp::Frames::new, &bytes, pattern), (expected.clone(), None));
    }
    for item in expected.iter().flatten() {
        let encoded = Wire::to_bytes(item).unwrap();
        contract::check_wire::<rtsp::Item>(&encoded);
        assert_eq!(<rtsp::Item as Wire>::parse(&encoded), Ok(item.clone()));
        assert_eq!(decode(rtsp::Frames::new, &encoded, &[1]), (vec![Ok(item.clone())], None));
        if let rtsp::Item::Message(m) = item {
            contract::check_wire::<rtsp::Message>(&encoded);
            if !m.body.is_empty() {
                assert_eq!(<sdp::SessionDescription as Wire>::parse(&m.body).unwrap().name, "media");
            }
        }
    }
}

#[test]
fn sip_chunked_round_trip_with_recovery_and_bodiless_response() {
    let body = sip_body();
    let mut response = sip::Message::response(100, "Trying");
    response.push_header("Content-Length", "0");
    let mut bytes = b"\r\n".to_vec();
    Wire::write(&body, &mut bytes).unwrap();
    bytes.extend_from_slice(b"SIP/2.0 200 OK\r\nBad Header\r\nl: 4\r\n\r\nbody");
    Wire::write(&response, &mut bytes).unwrap();
    Wire::write(&body, &mut bytes).unwrap();
    let expected = vec![Ok(body.clone()), Err(sip::Error::HeaderLine), Ok(response), Ok(body)];
    contract::check_stack(sip::Frames::new, &bytes);
    contract::check_decode_with_held_limit(sip::Frames::new, &bytes, 0);
    for pattern in [&[][..], &[1], &[3, 1, 37], &[64]] {
        assert_eq!(decode(sip::Frames::new, &bytes, pattern), (expected.clone(), None));
    }
    for message in expected.iter().flatten() {
        let encoded = Wire::to_bytes(message).unwrap();
        contract::check_wire::<sip::Message>(&encoded);
        assert_eq!(<sip::Message as Wire>::parse(&encoded), Ok(message.clone()));
        assert_eq!(decode(sip::Frames::new, &encoded, &[1]), (vec![Ok(message.clone())], None));
        if !message.body.is_empty() {
            let mut sdp_stream = Stream::new(sdp::Descriptions::new());
            let mut descriptions = Vec::new();
            for byte in &message.body {
                pump(&mut sdp_stream, core::slice::from_ref(byte), |m| descriptions.push(m)).unwrap();
            }
            finish(&mut sdp_stream, |m| descriptions.push(m)).unwrap();
            assert_eq!(descriptions, [<sdp::SessionDescription as Wire>::parse(SDP).unwrap()]);
        }
    }
}

#[test]
fn complete_raw_spans_and_one_item_per_call() {
    let first = Wire::to_bytes(&rtsp_body()).unwrap();
    let second = b"$\x01\x00\x03abc";
    let mut bytes = b"\r\n".to_vec();
    bytes.extend_from_slice(&first);
    bytes.extend_from_slice(second);
    let mut stream = Stream::new(rtsp::Frames::new());
    for byte in bytes.get(..bytes.len() - second.len()).unwrap() {
        assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
        // Wait until the final byte to take the message.
        if stream.offset() + stream.buffered() as u64 != 2 + first.len() as u64 {
            assert!(stream.next().is_none());
            assert_eq!(stream.held(), 0);
        }
    }
    assert_eq!(stream.push(second), second.len());
    stream
        .with_next(|item, raw, range| {
            assert!(item.is_ok());
            assert_eq!(raw, first);
            assert_eq!(range, 2..2 + first.len() as u64);
        })
        .unwrap()
        .unwrap();
    assert_eq!(stream.unread(), second);
    stream
        .with_next(|item, raw, range| {
            assert!(matches!(item, Ok(rtsp::Item::Interleaved(_))));
            assert_eq!(raw, second);
            assert_eq!(range.start, 2 + first.len() as u64);
        })
        .unwrap()
        .unwrap();

    let first = Wire::to_bytes(&sip_body()).unwrap();
    let mut stream = Stream::new(sip::Frames::new());
    let bytes = [first.as_slice(), first.as_slice()].concat();
    assert_eq!(stream.push(&bytes), bytes.len());
    stream
        .with_next(|item, raw, range| {
            assert!(item.is_ok());
            assert_eq!(raw, first);
            assert_eq!(range, 0..first.len() as u64);
        })
        .unwrap()
        .unwrap();
    assert_eq!(stream.unread(), first);
    assert!(stream.next().unwrap().unwrap().is_ok());
}

#[test]
fn sip_bare_lf_ends_the_stream_before_another_message() {
    let bytes = b"INVITE sip:a@b SIP/2.0\r\nl: 0\r\nX: a\n\nINVITE sip:b@c SIP/2.0\r\nl: 0\r\n\r\n";
    for pattern in [&[][..], &[1], &[3, 1, 37], &[64]] {
        assert_eq!(decode(sip::Frames::new, bytes, pattern), (vec![], Some(Fail::Protocol(sip::Error::LineEnding))));
    }
    contract::check_decode(sip::Frames::new, bytes);
}

#[test]
fn rtsp20_bare_lf_ends_the_stream_at_the_head() {
    for head in [
        &b"RTSP/2.0 200 OK\nContent-Length: 1\r\n\r\n"[..],
        b"RTSP/2.0 200 OK\r\nContent-Length: 1\n\r\n",
        b"RTSP/2.0 200 OK\r\nContent-Length: 1\r\n\n",
        b"OPTIONS * RTSP/2.0\r\nContent-Length: 1\r\nX: a\n\r\n",
    ] {
        let bytes = [head, b"xRTSP/2.0 200 OK\r\n\r\n"].concat();
        for input in [head, bytes.as_slice()] {
            for pattern in [&[][..], &[1], &[3, 1, 37], &[64]] {
                assert_eq!(
                    decode(rtsp::Frames::new, input, pattern),
                    (vec![], Some(Fail::Protocol(rtsp::Error::LineEnding)))
                );
            }
            contract::check_decode(rtsp::Frames::new, input);
        }
    }
}

#[test]
fn line_endings_and_status_body_rules() {
    let lf = b"RTSP/1.0 200 OK\nContent-Length: 1\n\nx";
    assert!(decode(rtsp::Frames::new, lf, &[1]).0[0].is_ok());
    contract::check_wire::<rtsp::Message>(lf);
    let new_lf = b"RTSP/2.0 200 OK\nContent-Length: 1\n\nx";
    assert_eq!(decode(rtsp::Frames::new, new_lf, &[1]), (vec![], Some(Fail::Protocol(rtsp::Error::LineEnding))));
    let sip_lf = b"SIP/2.0 200 OK\nl: 1\n\nx";
    assert_eq!(decode(sip::Frames::new, sip_lf, &[1]), (vec![], Some(Fail::Protocol(sip::Error::LineEnding))));
    contract::check_decode(rtsp::Frames::new, new_lf);
    contract::check_decode(sip::Frames::new, sip_lf);
    for code in [100, 199, 204, 304] {
        for version in [rtsp::Version::Rtsp10, rtsp::Version::Rtsp20] {
            let text = format!("{} {code} Status\r\nContent-Length: 1\r\n\r\n", version.as_str());
            let mut bytes = text.as_bytes().to_vec();
            if version == rtsp::Version::Rtsp20 {
                bytes.push(b'x');
            }
            let parsed = <rtsp::Message as Wire>::parse(&bytes).unwrap();
            assert_eq!(parsed.body, if version == rtsp::Version::Rtsp20 { b"x".to_vec() } else { vec![] });
            contract::check_wire::<rtsp::Message>(&bytes);
        }
        let bytes = format!("SIP/2.0 {code} Status\r\nl: 1\r\n\r\nx");
        assert_eq!(<sip::Message as Wire>::parse(bytes.as_bytes()).unwrap().body, b"x");
    }
    // No length on RTSP means no body; SIP must carry a length even at 100.
    assert!(<rtsp::Message as Wire>::parse(b"RTSP/2.0 200 OK\r\n\r\n").is_ok());
    assert_eq!(
        decode(sip::Frames::new, b"SIP/2.0 100 Trying\r\n\r\n", &[1]).1,
        Some(Fail::Protocol(sip::Error::MissingContentLength))
    );
}

#[test]
fn untrusted_lengths_end_the_stream_once() {
    for headers in [
        "Content-Length: x",
        "Content-Length 4",
        "Content-Length\0: 4",
        "Content-Length: 1\r\nContent-Length: 2",
        "Content-Length: 1\r\n 2",
        "Content-Length: 999999999999999999999999999999999",
    ] {
        let bytes = format!("RTSP/2.0 200 OK\r\n{headers}\r\n\r\nbody");
        contract::check_decode(rtsp::Frames::new, bytes.as_bytes());
        assert!(decode(rtsp::Frames::new, bytes.as_bytes(), &[1]).1.is_some());
        let bytes = format!("SIP/2.0 200 OK\r\n{headers}\r\n\r\nbody");
        contract::check_decode(sip::Frames::new, bytes.as_bytes());
        assert!(decode(sip::Frames::new, bytes.as_bytes(), &[1]).1.is_some());
    }
    let repeated = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\nl: 0\r\n\r\n";
    assert_eq!(decode(sip::Frames::new, repeated, &[]).1, Some(Fail::Protocol(sip::Error::ContentLength)));
    let equal = b"RTSP/2.0 200 OK\r\nContent-Length: 01\r\nContent-Length: 1\r\n\r\nx";
    contract::check_wire::<rtsp::Message>(equal);
    assert!(<rtsp::Message as Wire>::parse(equal).is_ok());
}

#[test]
fn folded_lengths_and_unrelated_bad_headers_keep_boundaries() {
    let rtsp = b"bad start\r\nContent-Length:\r\n 4\r\n\r\nbodyRTSP/1.0 200 OK\r\n\r\n";
    let sip = b"bad start\r\nl:\r\n 4\r\n\r\nbodySIP/2.0 200 OK\r\nl: 0\r\n\r\n";
    contract::check_decode(rtsp::Frames::new, rtsp);
    contract::check_decode(sip::Frames::new, sip);
    let (items, failure) = decode(rtsp::Frames::new, rtsp, &[1]);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(rtsp::Error::StartLine));
    assert!(items[1].is_ok());
    let (items, failure) = decode(sip::Frames::new, sip, &[1]);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(sip::Error::StartLine));
    assert!(items[1].is_ok());
    for bad in [&b"Bad Header"[..], b"X: bad\0", b"X: \xff"] {
        let mut bytes = b"RTSP/2.0 200 OK\r\n".to_vec();
        bytes.extend_from_slice(bad);
        bytes.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\nRTSP/2.0 200 OK\r\n\r\n");
        contract::check_decode(rtsp::Frames::new, &bytes);
        let (items, failure) = decode(rtsp::Frames::new, &bytes, &[1]);
        assert_eq!(failure, None);
        assert!(items[0].is_err());
        assert!(items[1].is_ok());
        let mut bytes = b"SIP/2.0 200 OK\r\n".to_vec();
        bytes.extend_from_slice(bad);
        bytes.extend_from_slice(b"\r\nl: 0\r\n\r\nSIP/2.0 200 OK\r\nl: 0\r\n\r\n");
        contract::check_decode(sip::Frames::new, &bytes);
        let (items, failure) = decode(sip::Frames::new, &bytes, &[1]);
        assert_eq!(failure, None);
        assert!(items[0].is_err());
        assert!(items[1].is_ok());
    }
}

#[test]
fn exact_parsers_and_transactional_writers_preserve_fields() {
    let rtsp = b"RTSP/1.0 200 OK\r\ncontent-length: 01\r\nX: a\r\n b\r\n\r\nx";
    let sip = b"SIP/2.0 200 OK\r\nl: 01\r\nX: a\r\n b\r\n\r\nx";
    let mut r = <rtsp::Message as Wire>::parse(rtsp).unwrap();
    let mut s = <sip::Message as Wire>::parse(sip).unwrap();
    assert_eq!(Wire::to_bytes(&r).unwrap(), b"RTSP/1.0 200 OK\r\ncontent-length: 01\r\nX: a b\r\n\r\nx");
    assert_eq!(Wire::to_bytes(&s).unwrap(), b"SIP/2.0 200 OK\r\nl: 01\r\nX: a b\r\n\r\nx");
    assert_eq!(<rtsp::Message as Wire>::parse(&[rtsp.as_slice(), b"junk"].concat()), Err(rtsp::WireError::Trailing));
    assert_eq!(<sip::Message as Wire>::parse(&[sip.as_slice(), b"junk"].concat()), Err(sip::WireError::Trailing));
    assert_eq!(<rtsp::Interleaved as Wire>::parse(b"$\0\0\0junk"), Err(rtsp::WireError::Trailing));
    // Old names retain prefix and datagram behavior, and length rewriting.
    assert!(rtsp::Message::parse(&[rtsp.as_slice(), b"junk"].concat()).unwrap().is_some());
    assert!(sip::Message::parse(&[sip.as_slice(), b"junk"].concat()).is_ok());
    assert!(sip::Message::parse(b"SIP/2.0 200 OK\r\n\r\nbody").is_ok());
    for bad in [" leading", "trailing ", "a\r\nInjected: x", "\0"] {
        r.headers[1].value = bad.into();
        s.headers[1].value = bad.into();
        contract::check_wire_value(&r);
        contract::check_wire_value(&s);
        let mut out = b"prefix".to_vec();
        assert!(Wire::write(&r, &mut out).is_err());
        assert_eq!(out, b"prefix");
        assert!(Wire::write(&s, &mut out).is_err());
        assert_eq!(out, b"prefix");
    }
    r.headers[1].value = "ok".into();
    s.headers[1].value = "ok".into();
    r.body.push(b'y');
    s.body.push(b'y');
    assert!(Wire::to_bytes(&r).is_err());
    assert!(Wire::to_bytes(&s).is_err());
    assert!(r.to_bytes().is_ok());
    assert!(s.to_bytes().is_ok());
}

#[test]
fn wire_body_length_mismatches_are_unrepresentable() {
    for (length, body) in [("5", &b"ab"[..]), ("5", b"abcdefg"), ("0", b"x")] {
        let mut r = rtsp::Message::request(rtsp::Version::Rtsp20, "ANNOUNCE", "rtsp://camera/media");
        r.push_header("Content-Length", length);
        r.body = body.to_vec();
        let mut out = b"prefix".to_vec();
        assert_eq!(Wire::write(&r, &mut out), Err(rtsp::WireError::Unrepresentable));
        assert_eq!(out, b"prefix");
        for name in ["Content-Length", "l"] {
            let mut s = sip::Message::request("INVITE", "sip:a@b");
            s.push_header(name, length);
            s.body = body.to_vec();
            assert_eq!(Wire::write(&s, &mut out), Err(sip::WireError::Unrepresentable));
            assert_eq!(out, b"prefix");
        }
    }
}

#[test]
fn wire_writers_preserve_syntax_and_limit_errors() {
    for (length, rtsp_error, sip_error) in [
        ("invalid".to_owned(), rtsp::Error::ContentLength, sip::Error::ContentLength),
        ((rtsp::MAX_BODY + 1).to_string(), rtsp::Error::TooLong, sip::Error::TooLong),
    ] {
        let mut r = rtsp::Message::response(rtsp::Version::Rtsp20, 200, "OK");
        r.push_header("Content-Length", &length);
        let mut s = sip::Message::response(200, "OK");
        s.push_header("l", &length);
        let mut out = b"prefix".to_vec();
        assert_eq!(Wire::write(&r, &mut out), Err(rtsp::WireError::Protocol(rtsp_error)));
        assert_eq!(out, b"prefix");
        assert_eq!(Wire::write(&s, &mut out), Err(sip::WireError::Protocol(sip_error)));
        assert_eq!(out, b"prefix");
    }
}

#[test]
fn partial_units_are_driver_truncation() {
    for bytes in
        [&b"RTSP/2.0"[..], b"RTSP/2.0 200 OK\r\n", b"RTSP/2.0 200 OK\r\nContent-Length: 2\r\n\r\nx", b"$\0\0\x02x"]
    {
        contract::check_decode(rtsp::Frames::new, bytes);
        assert_eq!(decode(rtsp::Frames::new, bytes, &[1]), (vec![], Some(Fail::Truncated { unread: bytes.len() })));
    }
    for bytes in [&b"SIP/2.0"[..], b"SIP/2.0 200 OK\r\n", b"SIP/2.0 200 OK\r\nl: 2\r\n\r\nx"] {
        contract::check_decode(sip::Frames::new, bytes);
        assert_eq!(decode(sip::Frames::new, bytes, &[1]), (vec![], Some(Fail::Truncated { unread: bytes.len() })));
    }
}

#[test]
fn named_limits_bound_lines_heads_bodies_and_counts() {
    let long = vec![b'x'; rtsp::MAX_LINE + 2];
    contract::check_decode(rtsp::Frames::new, &long);
    contract::check_decode(sip::Frames::new, &long);
    assert_eq!(decode(rtsp::Frames::new, &long, &[1]).1, Some(Fail::Protocol(rtsp::Error::TooLong)));
    assert_eq!(decode(sip::Frames::new, &long, &[1]).1, Some(Fail::Protocol(sip::Error::TooLong)));
    for (start, max) in [("RTSP/2.0 200 OK", rtsp::MAX_HEAD), ("SIP/2.0 200 OK", sip::MAX_HEAD)] {
        let mut bytes = format!("{start}\r\nX: ").into_bytes();
        bytes.resize(max, b'a');
        if start.starts_with("RTSP") {
            contract::check_decode(rtsp::Frames::new, &bytes);
            assert_eq!(decode(rtsp::Frames::new, &bytes, &[1]).1, Some(Fail::Protocol(rtsp::Error::TooLong)));
        } else {
            contract::check_decode(sip::Frames::new, &bytes);
            assert_eq!(decode(sip::Frames::new, &bytes, &[1]).1, Some(Fail::Protocol(sip::Error::TooLong)));
        }
    }
    let mut r = rtsp_body();
    let mut s = sip_body();
    r.body.resize(rtsp::MAX_BODY, 0xa5);
    s.body.resize(sip::MAX_BODY, 0xa5);
    r.set_header("Content-Length", &r.body.len().to_string());
    s.set_header("l", &s.body.len().to_string());
    let rb = Wire::to_bytes(&r).unwrap();
    let sb = Wire::to_bytes(&s).unwrap();
    assert_eq!(decode(rtsp::Frames::new, &rb, &[1]).0, [Ok(rtsp::Item::Message(r.clone()))]);
    assert_eq!(decode(sip::Frames::new, &sb, &[1]).0, [Ok(s.clone())]);
    r.body.push(0);
    s.body.push(0);
    contract::check_wire_value(&r);
    contract::check_wire_value(&s);
    assert!(Wire::to_bytes(&r).is_err());
    assert!(Wire::to_bytes(&s).is_err());
    let mut bytes = b"RTSP/2.0 200 OK\r\n".to_vec();
    bytes.extend_from_slice(&b"X: x\r\n".repeat(rtsp::MAX_HEADERS + 1));
    bytes.extend_from_slice(b"\r\nRTSP/2.0 200 OK\r\n\r\n");
    let (items, failure) = decode(rtsp::Frames::new, &bytes, &[1]);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(rtsp::Error::TooMany));
    assert!(items[1].is_ok());
    let mut bytes = b"SIP/2.0 200 OK\r\n".to_vec();
    bytes.extend_from_slice(&b"X: x\r\n".repeat(sip::MAX_HEADERS));
    bytes.extend_from_slice(b"l: 0\r\n\r\nSIP/2.0 200 OK\r\nl: 0\r\n\r\n");
    let (items, failure) = decode(sip::Frames::new, &bytes, &[1]);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(sip::Error::TooMany));
    assert!(items[1].is_ok());
    let frame = rtsp::Interleaved { channel: 255, data: vec![0xff; rtsp::MAX_INTERLEAVED] };
    let bytes = Wire::to_bytes(&frame).unwrap();
    contract::check_wire::<rtsp::Interleaved>(&bytes);
    assert_eq!(decode(rtsp::Frames::new, &bytes, &[1]).0, [Ok(rtsp::Item::Interleaved(frame))]);
}

#[test]
fn need_never_holds_input_and_large_direct_slices_stay_bounded() {
    let mut r = rtsp::Frames::new();
    let mut s = sip::Frames::new();
    assert_eq!(r.decode(b"RTSP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nx", false), Ok(Step::Need));
    assert_eq!(s.decode(b"SIP/2.0 200 OK\r\nl: 4\r\n\r\nx", false), Ok(Step::Need));
    assert_eq!(r.held(), 0);
    assert_eq!(s.held(), 0);
    let bytes = vec![b'x'; rtsp::MAX_MESSAGE + 10];
    assert_eq!(rtsp::Frames::new().decode(&bytes, false), Err(rtsp::Error::TooLong));
    assert_eq!(sip::Frames::new().decode(&bytes, false), Err(sip::Error::TooLong));
}

#[test]
fn codec_contracts_on_mutated_messages() {
    let mut rng = Lcg::new(0x0516_0554);
    let seeds = [Wire::to_bytes(&rtsp_body()).unwrap(), Wire::to_bytes(&sip_body()).unwrap()];
    for seed in &seeds {
        for _ in 0..100 {
            let mut bytes = seed.clone();
            for _ in 0..3 {
                let at = rng.below(bytes.len() as u64) as usize;
                bytes[at] = rng.next() as u8;
            }
            contract::check_decode(rtsp::Frames::new, &bytes);
            contract::check_decode(sip::Frames::new, &bytes);
            contract::check_wire::<rtsp::Message>(&bytes);
            contract::check_wire::<rtsp::Item>(&bytes);
            contract::check_wire::<sip::Message>(&bytes);
        }
    }
}

#[test]
fn head_limit_accepts_exact_fit_and_wire_refuses_canonical_expansion() {
    // The stream accepts a full head. Wire requires its CRLF re-encoding
    // to fit too, which can add one optional space after a colon.
    let mut r = rtsp::Message::response(rtsp::Version::Rtsp20, 200, "OK");
    let mut s = sip::Message::response(200, "OK");
    r.push_header("X", "");
    s.push_header("X", "");
    s.push_header("l", "0");
    let r_fixed = Wire::to_bytes(&r).unwrap().len();
    let s_fixed = Wire::to_bytes(&s).unwrap().len();
    r.headers[0].value = "a".repeat(rtsp::MAX_HEAD - r_fixed);
    s.headers[0].value = "a".repeat(sip::MAX_HEAD - s_fixed);
    let rb = Wire::to_bytes(&r).unwrap();
    let sb = Wire::to_bytes(&s).unwrap();
    assert_eq!(rb.len(), rtsp::MAX_HEAD);
    assert_eq!(sb.len(), sip::MAX_HEAD);
    contract::check_wire::<rtsp::Message>(&rb);
    contract::check_wire::<sip::Message>(&sb);
    assert!(decode(rtsp::Frames::new, &rb, &[1]).1.is_none());
    assert!(decode(sip::Frames::new, &sb, &[1]).1.is_none());
    let mut rb = rb;
    let mut sb = sb;
    let rat = rb.windows(3).position(|w| w == b"X: ").unwrap() + 2;
    let sat = sb.windows(3).position(|w| w == b"X: ").unwrap() + 2;
    rb[rat] = b'a';
    sb[sat] = b'a';
    assert!(decode(rtsp::Frames::new, &rb, &[1]).0[0].is_ok());
    assert!(decode(sip::Frames::new, &sb, &[1]).0[0].is_ok());
    assert_eq!(<rtsp::Message as Wire>::parse(&rb), Err(rtsp::WireError::Protocol(rtsp::Error::TooLong)));
    assert_eq!(<sip::Message as Wire>::parse(&sb), Err(sip::WireError::Protocol(sip::Error::TooLong)));
    let rb = format!("RTSP/2.0 200 OK\r\nContent-Length: {}\r\n\r\n", rtsp::MAX_BODY + 1);
    let sb = format!("SIP/2.0 200 OK\r\nl: {}\r\n\r\n", sip::MAX_BODY + 1);
    assert_eq!(decode(rtsp::Frames::new, rb.as_bytes(), &[1]).1, Some(Fail::Protocol(rtsp::Error::TooLong)));
    assert_eq!(decode(sip::Frames::new, sb.as_bytes(), &[1]).1, Some(Fail::Protocol(sip::Error::TooLong)));
}

#[test]
fn legacy_decoders_keep_feeds_and_repeated_errors() {
    let bytes = b"bad start\r\nContent-Length: 0\r\n\r\nRTSP/1.0 200 OK\r\n\r\n";
    let mut r = rtsp::Decoder::new();
    r.feed(bytes);
    assert_eq!(r.next_item(), Some(Err(rtsp::Error::StartLine)));
    assert_eq!(r.next_item(), Some(Err(rtsp::Error::StartLine)));
    r.feed(b"dropped");
    assert_eq!(r.buffered(), 0);
    let bytes = b"bad start\r\nl: 0\r\n\r\nSIP/2.0 200 OK\r\nl: 0\r\n\r\n";
    let mut s = sip::Decoder::new();
    assert_eq!(s.feed(bytes), bytes.len());
    assert_eq!(s.next_message(), Some(Err(sip::Error::StartLine)));
    assert_eq!(s.next_message(), Some(Err(sip::Error::StartLine)));
    assert_eq!(s.feed(b"dropped"), 7);
    assert_eq!(s.buffered(), 0);
    let large = vec![b'x'; rtsp::MAX_MESSAGE + 1];
    let mut r = rtsp::Decoder::new();
    r.feed(&large);
    assert_eq!(r.buffered(), large.len());
    let mut s = sip::Decoder::new();
    assert_eq!(s.feed(&large), sip::MAX_MESSAGE);
    assert_eq!(s.feed(b"extra"), 0);
}
