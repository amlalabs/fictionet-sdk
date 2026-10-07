//! RTSP and SIP lines, SDP bodies, recovery, and strict wire values.

use fictionet::stdlib::codec::{
    Decode, Fail, Lcg, Step, Stream, Wire, contract, finish, pump,
    test_support::{decode_all, mutate},
};
use fictionet::stdlib::{rtsp, sdp, sip};

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=media\r\nt=0 0\r\n";
const SDP_CALL: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=call\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 49170 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\na=sendonly\r\n";

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
    message.push_value("CSeq", &sip::CSeq { seq: 1, method: "INVITE".into() }).unwrap();
    message.push_header("c", "application/sdp");
    message.body = Wire::to_bytes(&<sdp::SessionDescription as Wire>::parse(SDP).unwrap()).unwrap();
    message.push_header("l", &message.body.len().to_string());
    message
}

#[test]
fn rtsp_stream_round_trip_with_interleaved_media_and_recovery() {
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
    assert_eq!(decode_all(rtsp::Frames::new, &bytes), (expected.clone(), None));
    for item in expected.iter().flatten() {
        let encoded = Wire::to_bytes(item).unwrap();
        contract::check_wire::<rtsp::Item>(&encoded);
        assert_eq!(<rtsp::Item as Wire>::parse(&encoded), Ok(item.clone()));
        assert_eq!(decode_all(rtsp::Frames::new, &encoded), (vec![Ok(item.clone())], None));
        if let rtsp::Item::Message(m) = item {
            contract::check_wire::<rtsp::Message>(&encoded);
            if !m.body.is_empty() {
                assert_eq!(<sdp::SessionDescription as Wire>::parse(&m.body).unwrap().name, "media");
            }
        }
    }
}

#[test]
fn sip_stream_round_trip_with_recovery_and_bodiless_response() {
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
    assert_eq!(decode_all(sip::Frames::new, &bytes), (expected.clone(), None));
    for message in expected.iter().flatten() {
        let encoded = Wire::to_bytes(message).unwrap();
        contract::check_wire::<sip::Message>(&encoded);
        assert_eq!(<sip::Message as Wire>::parse(&encoded), Ok(message.clone()));
        assert_eq!(decode_all(sip::Frames::new, &encoded), (vec![Ok(message.clone())], None));
        if !message.body.is_empty() {
            contract::check_decode_with_alloc_limit(
                sdp::Descriptions::new,
                &message.body,
                2 * (sdp::MAX_LINE_LEN + 2),
            );
            let (descriptions, failure) = decode_all(sdp::Descriptions::new, &message.body);
            assert_eq!(failure, None);
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
    let partial = 2 + first.len() - 1;
    assert_eq!(stream.push(&bytes[..partial]), partial);
    assert!(stream.next().is_none());
    assert_eq!(stream.held(), 0);
    assert_eq!(stream.push(&bytes[partial..]), bytes.len() - partial);
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
    assert_eq!(decode_all(sip::Frames::new, bytes), (vec![], Some(Fail::Protocol(sip::Error::LineEnding))));
    contract::check_decode_with_alloc_limit(sip::Frames::new, bytes, 2 * sip::MAX_MESSAGE);
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
            assert_eq!(
                decode_all(rtsp::Frames::new, input),
                (vec![], Some(Fail::Protocol(rtsp::Error::LineEnding)))
            );
            contract::check_decode_with_alloc_limit(rtsp::Frames::new, input, 2 * rtsp::MAX_MESSAGE);
        }
    }
}

#[test]
fn line_endings_and_status_body_rules() {
    let lf = b"RTSP/1.0 200 OK\nContent-Length: 1\n\nx";
    assert!(decode_all(rtsp::Frames::new, lf).0[0].is_ok());
    contract::check_wire::<rtsp::Message>(lf);
    let new_lf = b"RTSP/2.0 200 OK\nContent-Length: 1\n\nx";
    assert_eq!(
        decode_all(rtsp::Frames::new, new_lf),
        (vec![], Some(Fail::Protocol(rtsp::Error::LineEnding)))
    );
    let sip_lf = b"SIP/2.0 200 OK\nl: 1\n\nx";
    assert_eq!(decode_all(sip::Frames::new, sip_lf), (vec![], Some(Fail::Protocol(sip::Error::LineEnding))));
    contract::check_decode_with_alloc_limit(rtsp::Frames::new, new_lf, 2 * rtsp::MAX_MESSAGE);
    contract::check_decode_with_alloc_limit(sip::Frames::new, sip_lf, 2 * sip::MAX_MESSAGE);
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
        decode_all(sip::Frames::new, b"SIP/2.0 100 Trying\r\n\r\n").1,
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
        contract::check_decode_with_alloc_limit(rtsp::Frames::new, bytes.as_bytes(), 2 * rtsp::MAX_MESSAGE);
        assert!(decode_all(rtsp::Frames::new, bytes.as_bytes()).1.is_some());
        let bytes = format!("SIP/2.0 200 OK\r\n{headers}\r\n\r\nbody");
        contract::check_decode_with_alloc_limit(sip::Frames::new, bytes.as_bytes(), 2 * sip::MAX_MESSAGE);
        assert!(decode_all(sip::Frames::new, bytes.as_bytes()).1.is_some());
    }
    let repeated = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\nl: 0\r\n\r\n";
    assert_eq!(decode_all(sip::Frames::new, repeated).1, Some(Fail::Protocol(sip::Error::ContentLength)));
    let equal = b"RTSP/2.0 200 OK\r\nContent-Length: 01\r\nContent-Length: 1\r\n\r\nx";
    contract::check_wire::<rtsp::Message>(equal);
    assert!(<rtsp::Message as Wire>::parse(equal).is_ok());
}

#[test]
fn folded_lengths_and_unrelated_bad_headers_keep_boundaries() {
    let rtsp = b"bad start\r\nContent-Length:\r\n 4\r\n\r\nbodyRTSP/1.0 200 OK\r\n\r\n";
    let sip = b"bad start\r\nl:\r\n 4\r\n\r\nbodySIP/2.0 200 OK\r\nl: 0\r\n\r\n";
    contract::check_decode_with_alloc_limit(rtsp::Frames::new, rtsp, 2 * rtsp::MAX_MESSAGE);
    contract::check_decode_with_alloc_limit(sip::Frames::new, sip, 2 * sip::MAX_MESSAGE);
    let (items, failure) = decode_all(rtsp::Frames::new, rtsp);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(rtsp::Error::StartLine));
    assert!(items[1].is_ok());
    let (items, failure) = decode_all(sip::Frames::new, sip);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(sip::Error::StartLine));
    assert!(items[1].is_ok());
    for bad in [&b"Bad Header"[..], b"X: bad\0", b"X: \xff"] {
        let mut bytes = b"RTSP/2.0 200 OK\r\n".to_vec();
        bytes.extend_from_slice(bad);
        bytes.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\nRTSP/2.0 200 OK\r\n\r\n");
        contract::check_decode_with_alloc_limit(rtsp::Frames::new, &bytes, 2 * rtsp::MAX_MESSAGE);
        let (items, failure) = decode_all(rtsp::Frames::new, &bytes);
        assert_eq!(failure, None);
        assert!(items[0].is_err());
        assert!(items[1].is_ok());
        let mut bytes = b"SIP/2.0 200 OK\r\n".to_vec();
        bytes.extend_from_slice(bad);
        bytes.extend_from_slice(b"\r\nl: 0\r\n\r\nSIP/2.0 200 OK\r\nl: 0\r\n\r\n");
        contract::check_decode_with_alloc_limit(sip::Frames::new, &bytes, 2 * sip::MAX_MESSAGE);
        let (items, failure) = decode_all(sip::Frames::new, &bytes);
        assert_eq!(failure, None);
        assert!(items[0].is_err());
        assert!(items[1].is_ok());
    }
}

#[test]
fn sip_datagram_framing_and_limits() {
    let head = b"SIP/2.0 200 OK\r\n\r\n";
    let mut bytes = head.to_vec();
    bytes.resize(head.len() + sip::MAX_BODY, b'x');
    let mut message = sip::Message::read_datagram(&bytes).unwrap();
    assert_eq!(message.body.len(), sip::MAX_BODY);
    assert_eq!(message.content_length(), Ok(None));
    message.push_header("l", &sip::MAX_BODY.to_string());
    contract::check_wire_value(&message);
    assert!(message.to_bytes().is_ok());
    bytes.push(b'x');
    assert_eq!(sip::Message::read_datagram(&bytes), Err(sip::Error::TooLong));

    // Discarded bytes do not count against the body or message limit.
    let mut bytes = b"SIP/2.0 200 OK\r\nl: 01\r\n\r\na".to_vec();
    bytes.resize(sip::MAX_MESSAGE + 1, b'x');
    let message = sip::Message::read_datagram(&bytes).unwrap();
    assert_eq!(message.body, b"a");
    assert_eq!(message.header("l"), Some("01"));
    contract::check_wire_value(&message);
    assert_eq!(sip::Message::read_datagram(&message.to_bytes().unwrap()), Ok(message));
    let declared = format!("SIP/2.0 200 OK\r\nl: {}\r\n\r\n", sip::MAX_BODY + 1);
    assert_eq!(sip::Message::read_datagram(declared.as_bytes()), Err(sip::Error::TooLong));

    let mut head = b"SIP/2.0 200 OK\r\nX: ".to_vec();
    head.resize(sip::MAX_HEAD - 4, b'a');
    head.extend_from_slice(b"\r\n\r\n");
    let mut message = sip::Message::read_datagram(&head).unwrap();
    assert!(message.body.is_empty());
    // Adding the stream length can exceed the canonical head limit.
    message.push_header("l", "0");
    assert_eq!(message.to_bytes(), Err(sip::Error::TooLong));
    head.insert(head.len() - 4, b'a');
    assert_eq!(sip::Message::read_datagram(&head), Err(sip::Error::TooLong));
    assert_eq!(sip::Message::read_datagram(&vec![b'a'; sip::MAX_HEAD]), Err(sip::Error::TooLong));
    let headers = format!("SIP/2.0 200 OK\r\n{}\r\n", "X: a\r\n".repeat(sip::MAX_HEADERS + 1));
    assert_eq!(sip::Message::read_datagram(headers.as_bytes()), Err(sip::Error::TooMany));
}

#[test]
fn exact_parsers_and_transactional_writers_preserve_fields() {
    let rtsp = b"RTSP/1.0 200 OK\r\ncontent-length: 01\r\nX: a\r\n b\r\n\r\nx";
    let sip = b"SIP/2.0 200 OK\r\nl: 01\r\nX: a\r\n b\r\n\r\nx";
    let mut r = <rtsp::Message as Wire>::parse(rtsp).unwrap();
    let mut s = <sip::Message as Wire>::parse(sip).unwrap();
    assert_eq!(Wire::to_bytes(&r).unwrap(), b"RTSP/1.0 200 OK\r\ncontent-length: 01\r\nX: a b\r\n\r\nx");
    assert_eq!(Wire::to_bytes(&s).unwrap(), b"SIP/2.0 200 OK\r\nl: 01\r\nX: a b\r\n\r\nx");
    assert_eq!(
        <rtsp::Message as Wire>::parse(&[rtsp.as_slice(), b"junk"].concat()),
        Err(rtsp::Error::Trailing)
    );
    assert_eq!(<sip::Message as Wire>::parse(&[sip.as_slice(), b"junk"].concat()), Err(sip::Error::Trailing));
    assert_eq!(<rtsp::Interleaved as Wire>::parse(b"$\0\0\0junk"), Err(rtsp::Error::Trailing));
    assert_eq!(sip::Message::parse(b"SIP/2.0 200 OK\r\n\r\nbody"), Err(sip::Error::MissingContentLength));
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
}

#[test]
fn wire_body_length_mismatches_are_unwritable() {
    for (length, body) in [("5", &b"ab"[..]), ("5", b"abcdefg"), ("0", b"x")] {
        let mut r = rtsp::Message::request(rtsp::Version::Rtsp20, "ANNOUNCE", "rtsp://camera/media");
        r.push_header("Content-Length", length);
        r.body = body.to_vec();
        let mut out = b"prefix".to_vec();
        assert_eq!(Wire::write(&r, &mut out), Err(rtsp::Error::Unwritable));
        assert_eq!(out, b"prefix");
        for name in ["Content-Length", "l"] {
            let mut s = sip::Message::request("INVITE", "sip:a@b");
            s.push_header(name, length);
            s.body = body.to_vec();
            assert_eq!(Wire::write(&s, &mut out), Err(sip::Error::Unwritable));
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
        assert_eq!(Wire::write(&r, &mut out), Err(rtsp_error));
        assert_eq!(out, b"prefix");
        assert_eq!(Wire::write(&s, &mut out), Err(sip_error));
        assert_eq!(out, b"prefix");
    }
}

#[test]
fn partial_units_are_driver_truncation() {
    for bytes in
        [&b"RTSP/2.0"[..], b"RTSP/2.0 200 OK\r\n", b"RTSP/2.0 200 OK\r\nContent-Length: 2\r\n\r\nx", b"$\0\0\x02x"]
    {
        contract::check_decode_with_alloc_limit(rtsp::Frames::new, bytes, 2 * rtsp::MAX_MESSAGE);
        assert_eq!(
            decode_all(rtsp::Frames::new, bytes),
            (vec![], Some(Fail::Truncated { unread: bytes.len() }))
        );
    }
    for bytes in [&b"SIP/2.0"[..], b"SIP/2.0 200 OK\r\n", b"SIP/2.0 200 OK\r\nl: 2\r\n\r\nx"] {
        contract::check_decode_with_alloc_limit(sip::Frames::new, bytes, 2 * sip::MAX_MESSAGE);
        assert_eq!(
            decode_all(sip::Frames::new, bytes),
            (vec![], Some(Fail::Truncated { unread: bytes.len() }))
        );
    }
}

#[test]
fn named_limits_bound_lines_heads_bodies_and_counts() {
    let long = vec![b'x'; rtsp::MAX_LINE + 2];
    contract::check_decode_with_alloc_limit(rtsp::Frames::new, &long, 2 * rtsp::MAX_MESSAGE);
    contract::check_decode_with_alloc_limit(sip::Frames::new, &long, 2 * sip::MAX_MESSAGE);
    assert_eq!(decode_all(rtsp::Frames::new, &long).1, Some(Fail::Protocol(rtsp::Error::TooLong)));
    assert_eq!(decode_all(sip::Frames::new, &long).1, Some(Fail::Protocol(sip::Error::TooLong)));
    for (start, max) in [("RTSP/2.0 200 OK", rtsp::MAX_HEAD), ("SIP/2.0 200 OK", sip::MAX_HEAD)] {
        let mut bytes = format!("{start}\r\nX: ").into_bytes();
        bytes.resize(max, b'a');
        if start.starts_with("RTSP") {
            contract::check_decode_with_alloc_limit(rtsp::Frames::new, &bytes, 2 * rtsp::MAX_MESSAGE);
            assert_eq!(decode_all(rtsp::Frames::new, &bytes).1, Some(Fail::Protocol(rtsp::Error::TooLong)));
        } else {
            contract::check_decode_with_alloc_limit(sip::Frames::new, &bytes, 2 * sip::MAX_MESSAGE);
            assert_eq!(decode_all(sip::Frames::new, &bytes).1, Some(Fail::Protocol(sip::Error::TooLong)));
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
    assert_eq!(decode_all(rtsp::Frames::new, &rb).0, [Ok(rtsp::Item::Message(r.clone()))]);
    assert_eq!(decode_all(sip::Frames::new, &sb).0, [Ok(s.clone())]);
    r.body.push(0);
    s.body.push(0);
    contract::check_wire_value(&r);
    contract::check_wire_value(&s);
    assert!(Wire::to_bytes(&r).is_err());
    assert!(Wire::to_bytes(&s).is_err());
    let mut bytes = b"RTSP/2.0 200 OK\r\n".to_vec();
    bytes.extend_from_slice(&b"X: x\r\n".repeat(rtsp::MAX_HEADERS + 1));
    bytes.extend_from_slice(b"\r\nRTSP/2.0 200 OK\r\n\r\n");
    let (items, failure) = decode_all(rtsp::Frames::new, &bytes);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(rtsp::Error::TooMany));
    assert!(items[1].is_ok());
    let mut bytes = b"SIP/2.0 200 OK\r\n".to_vec();
    bytes.extend_from_slice(&b"X: x\r\n".repeat(sip::MAX_HEADERS));
    bytes.extend_from_slice(b"l: 0\r\n\r\nSIP/2.0 200 OK\r\nl: 0\r\n\r\n");
    let (items, failure) = decode_all(sip::Frames::new, &bytes);
    assert_eq!(failure, None);
    assert_eq!(items[0], Err(sip::Error::TooMany));
    assert!(items[1].is_ok());
    let frame = rtsp::Interleaved { channel: 255, data: vec![0xff; rtsp::MAX_INTERLEAVED] };
    let bytes = Wire::to_bytes(&frame).unwrap();
    contract::check_wire::<rtsp::Interleaved>(&bytes);
    assert_eq!(decode_all(rtsp::Frames::new, &bytes).0, [Ok(rtsp::Item::Interleaved(frame))]);
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
                mutate(&mut rng, &mut bytes);
            }
            contract::check_decode_with_alloc_limit(rtsp::Frames::new, &bytes, 2 * rtsp::MAX_MESSAGE);
            contract::check_decode_with_alloc_limit(sip::Frames::new, &bytes, 2 * sip::MAX_MESSAGE);
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
    assert!(decode_all(rtsp::Frames::new, &rb).1.is_none());
    assert!(decode_all(sip::Frames::new, &sb).1.is_none());
    let mut rb = rb;
    let mut sb = sb;
    let rat = rb.windows(3).position(|w| w == b"X: ").unwrap() + 2;
    let sat = sb.windows(3).position(|w| w == b"X: ").unwrap() + 2;
    rb[rat] = b'a';
    sb[sat] = b'a';
    assert!(decode_all(rtsp::Frames::new, &rb).0[0].is_ok());
    assert!(decode_all(sip::Frames::new, &sb).0[0].is_ok());
    assert_eq!(<rtsp::Message as Wire>::parse(&rb), Err(rtsp::Error::TooLong));
    assert_eq!(<sip::Message as Wire>::parse(&sb), Err(sip::Error::TooLong));
    let rb = format!("RTSP/2.0 200 OK\r\nContent-Length: {}\r\n\r\n", rtsp::MAX_BODY + 1);
    let sb = format!("SIP/2.0 200 OK\r\nl: {}\r\n\r\n", sip::MAX_BODY + 1);
    assert_eq!(decode_all(rtsp::Frames::new, rb.as_bytes()).1, Some(Fail::Protocol(rtsp::Error::TooLong)));
    assert_eq!(decode_all(sip::Frames::new, sb.as_bytes()).1, Some(Fail::Protocol(sip::Error::TooLong)));
}

#[test]
fn header_writers_refuse_empty_display_names() {
    let mut address = sip::NameAddr::new("sip:a@b");
    address.display = Some(String::new());
    contract::check_wire_value(&address);
    let mut out = b"prefix".to_vec();
    assert_eq!(address.write(&mut out), Err(sip::Error::Unwritable));
    assert_eq!(out, b"prefix");
    let contacts = sip::Contacts::List(vec![address]);
    contract::check_wire_value(&contacts);
    assert_eq!(contacts.write(&mut out), Err(sip::Error::Unwritable));
    assert_eq!(out, b"prefix");
    // Received empty display names still normalize to an absent name.
    let bytes = b"\"\" <sip:a@b>";
    contract::check_wire::<sip::NameAddr>(bytes);
    assert_eq!(sip::NameAddr::parse(bytes).unwrap(), sip::NameAddr::new("sip:a@b"));
}

#[test]
fn rtsp_header_values_and_transport_lists_have_byte_limits() {
    let long = vec![b'a'; rtsp::MAX_HEAD + 1];
    assert_eq!(rtsp::Session::parse(&long), Err(rtsp::Error::TooLong));
    assert_eq!(rtsp::Range::parse(&long), Err(rtsp::Error::TooLong));
    assert_eq!(rtsp::Transport::parse(&long), Err(rtsp::Error::TooLong));
    assert_eq!(rtsp::Transports::parse(&long), Err(rtsp::Error::TooLong));
    let transport = rtsp::Transport {
        protocol: "a".repeat(rtsp::MAX_HEAD),
        profile: String::new(),
        lower: None,
        params: vec![],
    };
    contract::check_wire_value(&transport);
    let mut too_long = transport.clone();
    too_long.protocol.push('a');
    let mut out = b"prefix".to_vec();
    assert_eq!(too_long.write(&mut out), Err(rtsp::Error::TooLong));
    assert_eq!(out, b"prefix");
    let list = rtsp::Transports { values: vec![transport.clone(), transport] };
    contract::check_wire_value(&list);
    assert_eq!(list.write(&mut out), Err(rtsp::Error::TooLong));
    assert_eq!(out, b"prefix");
    let bytes = b"RTP/AVP;unicast, RTP/AVP/TCP;interleaved=0-1";
    contract::check_wire::<rtsp::Transports>(bytes);
    assert_eq!(rtsp::Transports::parse(bytes).unwrap().values.len(), 2);
}

#[test]
fn sip_header_readers_refuse_canonical_expansion_over_the_limit() {
    let uri = format!("sip:{}@h", "a".repeat(sip::MAX_HEAD - "sip:@h".len()));
    assert_eq!(uri.len(), sip::MAX_HEAD);
    contract::check_wire::<sip::Uri>(uri.as_bytes());
    assert!(sip::Uri::parse(uri.as_bytes()).is_ok());
    // The name-addr writer must add angle brackets around the same URI.
    contract::check_wire::<sip::NameAddr>(uri.as_bytes());
    contract::check_wire::<sip::Contacts>(uri.as_bytes());
    assert_eq!(sip::NameAddr::parse(uri.as_bytes()), Err(sip::Error::TooLong));
    assert_eq!(sip::Contacts::parse(uri.as_bytes()), Err(sip::Error::TooLong));
}

#[test]
fn sdp_offer_and_answer_at_eof() {
    contract::check_decode_with_held_limit(sdp::Descriptions::new, SDP_CALL, sdp::MAX_LEN);
    contract::check_wire::<sdp::SessionDescription>(SDP_CALL);
    let offer = sdp::SessionDescription::parse(SDP_CALL).unwrap();
    for input in [
        SDP_CALL.to_vec(),
        SDP_CALL.iter().copied().filter(|b| *b != b'\r').collect(),
        SDP_CALL[..SDP_CALL.len() - 2].to_vec(),
        SDP_CALL[..SDP_CALL.len() - 1].to_vec(),
    ] {
        let mut stream = Stream::new(sdp::Descriptions::new());
        contract::check_decode_with_alloc_limit(
            sdp::Descriptions::new,
            &input,
            2 * (sdp::MAX_LINE_LEN + 2),
        );
        pump(&mut stream, &input, |_| panic!("description before EOF")).unwrap();
        assert!(stream.held() <= sdp::MAX_LEN);
        let mut descriptions = Vec::new();
        finish(&mut stream, |d| descriptions.push(d)).unwrap();
        assert_eq!(descriptions.as_slice(), core::slice::from_ref(&offer));
        assert_eq!(stream.held(), 0);
        let mut answer = descriptions.pop().unwrap();
        answer.origin.username = "peer".into();
        answer.media[0].attributes.pop();
        answer.media[0]
            .attributes
            .push(sdp::Direction::RecvOnly.to_attribute());
        let bytes = Wire::to_bytes(&answer).unwrap();
        contract::check_wire::<sdp::SessionDescription>(&bytes);
        assert_eq!(
            decode_all(sdp::Descriptions::new, &bytes),
            (vec![answer], None)
        );
    }
    let mut bad = offer;
    bad.name = "bad\nname".into();
    contract::check_wire_value(&bad);
    let mut out = b"prefix".to_vec();
    assert!(Wire::write(&bad, &mut out).is_err());
    assert_eq!(out, b"prefix");
    for bytes in [&b""[..], b"v=0\n", b"v=0\nx=bad\n"] {
        contract::check_decode_with_alloc_limit(
            sdp::Descriptions::new,
            bytes,
            2 * sdp::Descriptions::new().capacity(),
        );
        assert_eq!(
            decode_all(sdp::Descriptions::new, bytes),
            (
                vec![],
                Some(Fail::Protocol(
                    sdp::SessionDescription::parse(bytes).unwrap_err()
                ))
            )
        );
    }
}

#[test]
fn sdp_rejects_oversize_lines_and_bodies() {
    let mut stream = Stream::new(sdp::Descriptions::new());
    let capacity = stream.decoder().capacity();
    assert_eq!(capacity, sdp::MAX_LINE_LEN + 2);
    assert_eq!(stream.push(&vec![b'x'; capacity + 1]), capacity);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(sdp::Error::LineTooLong { line: 1 })))
    );
    assert!(stream.next().is_none());
    let mut body = SDP_CALL.to_vec();
    let line = format!("a=x:{}\r\n", "y".repeat(1000));
    while body.len() + line.len() + 6 <= sdp::MAX_LEN {
        body.extend_from_slice(line.as_bytes());
    }
    let remaining = sdp::MAX_LEN - body.len();
    body.extend_from_slice(format!("a=x:{}\r\n", "z".repeat(remaining - 6)).as_bytes());
    assert_eq!(body.len(), sdp::MAX_LEN);
    assert!(decode_all(sdp::Descriptions::new, &body).1.is_none());
    body.extend_from_slice(b"a=x\r\n");
    for input in [
        body.clone(),
        body.into_iter().filter(|b| *b != b'\r').collect(),
    ] {
        assert_eq!(
            decode_all(sdp::Descriptions::new, &input),
            (vec![], Some(Fail::Protocol(sdp::Error::TooLong)))
        );
    }
    let mut lines = b"v=0\no=- 1 1 IN IP4 192.0.2.1\ns=x\nt=0 0\n".to_vec();
    lines.extend_from_slice(&b"a=x\n".repeat(sdp::MAX_LINES - 4));
    assert!(decode_all(sdp::Descriptions::new, &lines).1.is_none());
    lines.extend_from_slice(b"a=x\n");
    assert_eq!(
        decode_all(sdp::Descriptions::new, &lines),
        (vec![], Some(Fail::Protocol(sdp::Error::TooManyLines)))
    );
}

#[test]
fn sdp_contracts_on_mutated_bodies() {
    let mut rng = Lcg::new(0x5eed);
    for _ in 0..64 {
        let mut bytes = SDP_CALL.to_vec();
        for _ in 0..rng.index(4) {
            mutate(&mut rng, &mut bytes);
        }
        let end = rng.index(bytes.len() + 1);
        bytes.truncate(end);
        contract::check_decode_with_held_limit(sdp::Descriptions::new, &bytes, sdp::MAX_LEN);
        // Adapter consistency: the decoder parses the whole body at EOF.
        let expected = match sdp::SessionDescription::parse(&bytes) {
            Ok(desc) => (vec![desc], None),
            Err(e) => (vec![], Some(Fail::Protocol(e))),
        };
        assert_eq!(decode_all(sdp::Descriptions::new, &bytes), expected);
    }
}
