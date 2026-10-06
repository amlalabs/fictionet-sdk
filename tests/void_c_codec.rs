//! Chunked bodies and RESP streams through the shared codec driver.

use fictionet::stdlib::codec::{
    Decode, Fail, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, decode_all, mutate},
};
use fictionet::stdlib::{resp, sdp, wake_on_lan as wol};

const RESP_LIMIT: usize = 128;
const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=call\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 49170 RTP/AVP 96\r\na=rtpmap:96 opus/48000/2\r\na=sendonly\r\n";
const MAC: wol::Mac = [0, 1, 2, 3, 4, 5];

fn resp_limits() -> resp::Limits {
    resp::Limits {
        max_frame_len: RESP_LIMIT,
        ..resp::Limits::DEFAULT
    }
}

#[test]
fn resp_requests_and_replies() {
    let command = resp::Command::new(["SET", "key", "value"]);
    let mut input = b"\r\n*0\r\n".to_vec();
    Wire::write(&command, &mut input).unwrap();
    input.extend_from_slice(b"GET key\n");
    let expected = [command, resp::Command::new(["GET", "key"])];
    contract::check_decode_with_alloc_limit(
        || resp::Commands::with_limits(resp_limits()),
        &input,
        2 * RESP_LIMIT,
    );
    let (commands, error) = decode_all(|| resp::Commands::with_limits(resp_limits()), &input);
    assert_eq!(error, None);
    assert_eq!(commands, expected);
    let mut replies = Vec::new();
    for command in commands {
        let request = Wire::to_bytes(&command).unwrap();
        contract::check_wire::<resp::Command>(&request);
        assert_eq!(
            <resp::Command as Wire>::parse(&request),
            Ok(command.clone())
        );
        let reply = if command.is("SET") {
            resp::Value::ok()
        } else {
            resp::Value::bulk("value")
        };
        Wire::write(&reply, &mut replies).unwrap();
    }
    contract::check_decode_with_alloc_limit(
        || resp::Values::with_limits(resp_limits()),
        &replies,
        2 * RESP_LIMIT,
    );
    let (values, error) = decode_all(|| resp::Values::with_limits(resp_limits()), &replies);
    assert_eq!(error, None);
    assert_eq!(values, [resp::Value::ok(), resp::Value::bulk("value")]);
    for value in values {
        let bytes = Wire::to_bytes(&value).unwrap();
        contract::check_wire::<resp::Value>(&bytes);
        assert_eq!(<resp::Value as Wire>::parse(&bytes), Ok(value));
    }
}

#[test]
fn resp_limits_and_terminal_errors() {
    assert_eq!(resp::Values::new().capacity(), resp::MAX_FRAME_LEN);
    assert_eq!(resp::Commands::new().capacity(), resp::MAX_FRAME_LEN);
    let limits = resp::Limits {
        max_frame_len: 16,
        ..resp::Limits::DEFAULT
    };
    let bytes = vec![b'+'; limits.max_frame_len + 1];
    let mut commands = Stream::new(resp::Commands::with_limits(limits));
    assert_eq!(commands.push(&bytes), limits.max_frame_len);
    assert_eq!(
        commands.next(),
        Some(Err(Fail::Protocol(resp::ParseError::FrameTooLarge)))
    );
    assert!(commands.next().is_none());
    let mut values = Stream::new(resp::Values::with_limits(limits));
    assert_eq!(values.push(&bytes), limits.max_frame_len);
    assert_eq!(
        values.next(),
        Some(Err(Fail::Protocol(resp::ParseError::FrameTooLarge)))
    );
    assert!(values.next().is_none());
    for bytes in [&b"+OK\r\n$9\r\nabc"[..], b"+OK\r\n:bad\r\n+later\r\n"] {
        contract::check_decode_with_alloc_limit(
            resp::Values::new,
            bytes,
            2 * resp::Values::new().capacity(),
        );
        let (values, error) = decode_all(resp::Values::new, bytes);
        assert_eq!(values, [resp::Value::ok()]);
        assert_eq!(
            error,
            Some(if bytes.ends_with(b"abc") {
                Fail::Truncated { unread: 7 }
            } else {
                Fail::Protocol(resp::ParseError::Malformed(b':'))
            })
        );
    }
    let bytes = b"PING\r\n*1\r\n+bad\r\nGET x\r\n";
    contract::check_decode_with_alloc_limit(
        resp::Commands::new,
        bytes,
        2 * resp::Commands::new().capacity(),
    );
    assert_eq!(
        decode_all(resp::Commands::new, bytes),
        (
            vec![resp::Command::new(["PING"])],
            Some(Fail::Protocol(resp::ParseError::ExpectedBulk(b'+'))),
        )
    );
    for limit in [0, 1, 2, 3, 4, 16, usize::MAX] {
        let limits = resp::Limits {
            max_frame_len: limit,
            ..resp::Limits::DEFAULT
        };
        let make = || resp::Values::with_limits(limits);
        assert!(make().capacity() <= resp::MAX_FRAME_LEN);
        contract::check_decode_with_alloc_limit(make, b"_\r\n+tail", 2 * make().capacity());
        contract::check_decode_with_alloc_limit(
            || resp::Commands::with_limits(limits),
            b"\n*0\r\nPING\n",
            2 * (resp::Commands::with_limits(limits)).capacity(),
        );
    }
}

#[test]
fn resp_strict_writers_preserve_types_and_roll_back() {
    let values = [
        resp::Value::NullArray,
        resp::Value::Array(vec![resp::Value::NullArray, resp::Value::Null]),
        resp::Value::Attribute {
            attributes: vec![(resp::Value::simple("meta"), resp::Value::Integer(1))],
            value: Box::new(resp::Value::Push(vec![
                resp::Value::bulk("message"),
                resp::Value::NullArray,
            ])),
        },
        resp::Value::Verbatim {
            format: *b"txt",
            text: b"hello\nworld".to_vec(),
        },
        resp::Value::Set(vec![resp::Value::Boolean(true), resp::Value::Double(1.5)]),
        resp::Value::Map(vec![(
            resp::Value::BigNumber("+123".into()),
            resp::Value::BulkError(vec![0, 255]),
        )]),
    ];
    for value in values {
        contract::check_wire_value(&value);
        let bytes = Wire::to_bytes(&value).unwrap();
        contract::check_wire::<resp::Value>(&bytes);
        contract::check_decode_with_alloc_limit(
            resp::Values::new,
            &bytes,
            2 * resp::Values::new().capacity(),
        );
    }
    for value in [
        resp::Value::simple("a\nb"),
        resp::Value::BigNumber("not a number".into()),
        resp::Value::Push(vec![]),
        resp::Value::Array(vec![resp::Value::Push(vec![resp::Value::simple("bad")])]),
        resp::Value::simple(vec![b'x'; resp::MAX_LINE_LEN + 1]),
    ] {
        contract::check_wire_value(&value);
        let mut out = b"prefix".to_vec();
        assert_eq!(
            Wire::write(&value, &mut out),
            Err(resp::WireError::Unwritable)
        );
        assert_eq!(out, b"prefix");
    }
    let mut deep = resp::Value::Null;
    for _ in 0..resp::MAX_DEPTH + 1 {
        deep = resp::Value::Array(vec![deep]);
    }
    assert_eq!(Wire::to_bytes(&deep), Err(resp::WireError::Unwritable));
    let command = resp::Command {
        args: vec![vec![0; resp::MAX_BULK_LEN + 1]],
    };
    contract::check_wire_value(&command);
    assert_eq!(Wire::to_bytes(&command), Err(resp::WireError::Unwritable));
    assert_eq!(
        <resp::Value as Wire>::parse(b"+OK\r\n+more\r\n"),
        Err(resp::WireError::Trailing)
    );
    assert_eq!(
        <resp::Value as Wire>::parse(b"+OK\r"),
        Err(resp::WireError::Incomplete)
    );
    assert_eq!(
        <resp::Command as Wire>::parse(b"PING\nGET x\n"),
        Err(resp::WireError::Trailing)
    );
    contract::check_wire::<resp::Command>(b"\r\n");
    // NaN is not reflexive under Value's existing PartialEq. Its wire form is.
    let bytes = Wire::to_bytes(&resp::Value::Double(f64::NAN)).unwrap();
    assert_eq!(bytes, b",nan\r\n");
    let resp::Value::Double(n) = <resp::Value as Wire>::parse(&bytes).unwrap() else {
        panic!()
    };
    assert!(n.is_nan());
    assert_eq!(Wire::to_bytes(&resp::Value::Double(n)).unwrap(), bytes);
}

#[test]
fn resp_scan_resumes_across_lines_and_aggregates() {
    let mut bytes = b"*?\r\n$?\r\n".to_vec();
    bytes.extend_from_slice(&b";1\r\nx\r\n".repeat(4096));
    bytes.extend_from_slice(b";0\r\n+");
    bytes.extend(std::iter::repeat_n(b'y', resp::MAX_LINE_LEN));
    bytes.extend_from_slice(b"\r\n.\r\n");
    let (values, error) = decode_all(resp::Values::new, &bytes);
    assert_eq!(error, None);
    assert_eq!(
        values,
        [resp::Value::Array(vec![
            resp::Value::bulk(vec![b'x'; 4096]),
            resp::Value::simple(vec![b'y'; resp::MAX_LINE_LEN]),
        ])]
    );
    let mut stream = Stream::new(resp::Commands::new());
    let command = resp::Command {
        args: vec![vec![b'z'; 1]; 4096],
    };
    let bytes = Wire::to_bytes(&command).unwrap();
    contract::check_decode_with_alloc_limit(resp::Commands::new, &bytes, 2 * resp::MAX_FRAME_LEN);
    let mut got = Vec::new();
    pump(&mut stream, &bytes, |c| got.push(c)).unwrap();
    finish(&mut stream, |c| got.push(c)).unwrap();
    assert_eq!(got, [command]);
}

#[test]
fn sdp_offer_and_answer_at_eof() {
    contract::check_decode_with_held_limit(sdp::Descriptions::new, SDP, sdp::MAX_LEN);
    contract::check_wire::<sdp::SessionDescription>(SDP);
    let offer = sdp::SessionDescription::parse(SDP).unwrap();
    for input in [
        SDP.to_vec(),
        SDP.iter().copied().filter(|b| *b != b'\r').collect(),
        SDP[..SDP.len() - 2].to_vec(),
        SDP[..SDP.len() - 1].to_vec(),
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
    let mut body = SDP.to_vec();
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
fn wake_on_lan_payload_and_exact_packet() {
    for password in [
        None,
        Some(wol::Password::Four([1, 2, 3, 4])),
        Some(wol::Password::Six([1, 2, 3, 4, 5, 6])),
    ] {
        let packet = wol::MagicPacket { mac: MAC, password };
        contract::check_wire_value(&packet);
        let bytes = Wire::to_bytes(&packet).unwrap();
        contract::check_wire::<wol::MagicPacket>(&bytes);
        let mut payload = b"prefix".to_vec();
        payload.extend_from_slice(&bytes);
        contract::check_decode_with_alloc_limit(
            wol::Packets::new,
            &payload,
            2 * wol::Packets::new().capacity(),
        );
        assert!(<wol::MagicPacket as Wire>::parse(&payload).is_err());
        let mut stream = Stream::new(wol::Packets::new());
        pump(&mut stream, &payload, |_| panic!("packet before EOF")).unwrap();
        let mut got = Vec::new();
        finish(&mut stream, |p| got.push(p)).unwrap();
        assert_eq!(got, [(6, packet)]);
        assert_eq!(
            <wol::MagicPacket as Wire>::parse(&Wire::to_bytes(&got[0].1).unwrap()),
            Ok(packet)
        );
    }
    let bytes = wol::MagicPacket::new(MAC).to_bytes().unwrap();
    for tail in [1, 2, 3, 5, 7] {
        let mut payload = bytes.clone();
        payload.extend(vec![7; tail]);
        assert!(<wol::MagicPacket as Wire>::parse(&payload).is_err());
        assert_eq!(
            decode_all(wol::Packets::new, &payload),
            (vec![(0, wol::MagicPacket::new(MAC))], None)
        );
    }
    contract::check_decode_with_alloc_limit(
        wol::Packets::new,
        b"no packet",
        2 * wol::Packets::new().capacity(),
    );
    assert_eq!(
        decode_all(wol::Packets::new, b"no packet"),
        (vec![], Some(Fail::Protocol(wol::ParseError::NotFound)))
    );
}

#[test]
fn wake_on_lan_rejects_oversize_payload() {
    let mut payload = vec![0; wol::MAX_PAYLOAD - wol::PACKET_LEN];
    payload.extend(wol::MagicPacket::new(MAC).to_bytes().unwrap());
    assert_eq!(
        decode_all(wol::Packets::new, &payload),
        (
            vec![(
                wol::MAX_PAYLOAD - wol::PACKET_LEN,
                wol::MagicPacket::new(MAC)
            )],
            None
        )
    );
    payload.push(0);
    let mut stream = Stream::new(wol::Packets::new());
    assert_eq!(stream.decoder().capacity(), wol::MAX_PAYLOAD + 1);
    assert_eq!(stream.push(&payload), wol::MAX_PAYLOAD + 1);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(wol::ParseError::TooLong)))
    );
    assert!(stream.next().is_none());
    contract::check_decode_with_alloc_limit(
        wol::Packets::new,
        &payload,
        2 * wol::Packets::new().capacity(),
    );
}

#[test]
fn small_resp_capacity_drains_a_long_pipeline() {
    let limits = resp::Limits {
        max_frame_len: 4,
        ..resp::Limits::DEFAULT
    };
    let bytes = b"_\r\n".repeat(100);
    contract::check_decode_with_alloc_limit(|| resp::Values::with_limits(limits), &bytes, 8);
    assert_eq!(
        decode_all(|| resp::Values::with_limits(limits), &bytes),
        (vec![resp::Value::Null; 100], None)
    );
}

#[test]
fn contracts_on_mutated_values_and_bodies() {
    let mut rng = Lcg::new(0x5eed);
    let packet = wol::MagicPacket::with_password(MAC, wol::Password::Six([9; 6]))
        .to_bytes()
        .unwrap();
    let resp = b"|1\r\n+k\r\n%?\r\n+a\r\n:1\r\n.\r\n>2\r\n+event\r\n*?\r\n$?\r\n;1\r\nx\r\n;0\r\n*-1\r\n.\r\n";
    for seed in [resp.as_slice(), SDP, packet.as_slice()] {
        for _ in 0..64 {
            let mut bytes = seed.to_vec();
            for _ in 0..rng.index(4) {
                mutate(&mut rng, &mut bytes);
            }
            let end = rng.index(bytes.len() + 1);
            bytes.truncate(end);
            // Compare strict encodings so NaN retains its wire equality.
            contract::check_decode_with_alloc_limit(
                || resp::Values::new().map(|v| Wire::to_bytes(&v)),
                &bytes,
                2 * (resp::Values::new().map(|v| Wire::to_bytes(&v))).capacity(),
            );
            contract::check_decode_with_alloc_limit(
                resp::Commands::new,
                &bytes,
                2 * resp::Commands::new().capacity(),
            );
            contract::check_decode_with_held_limit(sdp::Descriptions::new, &bytes, sdp::MAX_LEN);
            contract::check_decode_with_alloc_limit(
                wol::Packets::new,
                &bytes,
                2 * wol::Packets::new().capacity(),
            );
            let expected = match sdp::SessionDescription::parse(&bytes) {
                Ok(desc) => (vec![desc], None),
                Err(e) => (vec![], Some(Fail::Protocol(e))),
            };
            assert_eq!(decode_all(sdp::Descriptions::new, &bytes), expected);
            let expected = match wol::MagicPacket::find(&bytes) {
                Ok(packet) => (vec![packet], None),
                Err(e) => (vec![], Some(Fail::Protocol(e))),
            };
            assert_eq!(decode_all(wol::Packets::new, &bytes), expected);
        }
    }
}
