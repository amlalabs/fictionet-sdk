//! Messaging streams, datagrams, strict writers, and compatibility APIs.

use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Step, Stream, Wire, contract, finish, pump, test_support::chunks,
};
use fictionet::stdlib::{amqp, coap, dhcpv6, mqtt, syslog};

fn run<D: Decode>(
    decoder: D,
    bytes: &[u8],
    pattern: &[usize],
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Error: Clone + PartialEq + Debug,
{
    let capacity = decoder.capacity();
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    let mut failure = None;
    for part in chunks(bytes, pattern) {
        match pump(&mut stream, part, |item| items.push(item)) {
            Ok(n) => assert_eq!(n, part.len()),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
        assert!(stream.buffered() <= capacity);
        assert_eq!(stream.held(), 0);
    }
    if failure.is_none() {
        failure = finish(&mut stream, |item| items.push(item)).err();
    }
    assert_eq!(stream.failed(), failure.as_ref());
    assert!(stream.is_done());
    assert!(stream.next().is_none());
    (items, failure)
}

fn encoded<M: Wire + PartialEq + Debug>(value: &M) -> Vec<u8> {
    contract::check_wire_value(value);
    let bytes = Wire::to_bytes(value).unwrap();
    contract::check_wire::<M>(&bytes);
    assert_eq!(&M::parse(&bytes).unwrap(), value);
    bytes
}

fn refuses<M: Wire + PartialEq + Debug>(value: &M) {
    contract::check_wire_value(value);
    let mut out = vec![0x5a, 0xc3, 0x17];
    assert!(value.write(&mut out).is_err());
    assert_eq!(out, [0x5a, 0xc3, 0x17]);
}

#[test]
fn amqp_broker_round_trip_and_payload_errors() {
    let publish = amqp::Method::BasicPublish {
        exchange: String::new(),
        routing_key: "orders".into(),
        mandatory: false,
        immediate: false,
    };
    let frames = amqp::content_frames(
        1,
        &publish,
        &amqp::BasicProperties::default(),
        b"hello",
        amqp::FRAME_MIN_SIZE,
    )
    .unwrap();
    let mut bytes = amqp::PROTOCOL_HEADER.to_vec();
    for frame in &frames {
        bytes.extend(encoded(frame));
    }
    let make = || {
        let mut decoder = amqp::Frames::server();
        decoder.set_frame_max(amqp::FRAME_MIN_SIZE);
        decoder
    };
    contract::check_stack(make, &bytes);
    for pattern in [&[][..], &[1][..], &[3, 1, 37][..]] {
        let (got, error) = run(make(), &bytes, pattern);
        assert_eq!(error, None);
        assert_eq!(got, frames);
        assert_eq!(amqp::Method::parse(&got[0].payload), Ok(publish.clone()));
        assert_eq!(
            amqp::ContentHeader::parse(&got[1].payload)
                .unwrap()
                .body_size,
            5
        );
        let response = amqp::Frame::heartbeat();
        assert_eq!(
            run(amqp::Frames::new(), &encoded(&response), pattern),
            (vec![response], None)
        );
    }

    // The protocol header is skipped and does not enter a frame's span.
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(&bytes), bytes.len());
    let first = stream
        .with_next(|frame, raw, span| {
            assert_eq!(span.start, amqp::PROTOCOL_HEADER.len() as u64);
            assert_eq!(<amqp::Frame as Wire>::parse(raw), Ok(frame.clone()));
            frame
        })
        .unwrap()
        .unwrap();
    assert_eq!(first, frames[0]);
    assert!(stream.decoder().header_received());

    let bad_method = amqp::Frame {
        kind: amqp::FrameKind::Method,
        channel: 1,
        payload: vec![0],
    };
    let mut bytes = encoded(&bad_method);
    bytes.extend(encoded(&amqp::Frame::method(1, &publish).unwrap()));
    let make = || amqp::Frames::new().map(|frame| amqp::Method::parse(&frame.payload));
    contract::check_stack(make, &bytes);
    let (items, error) = run(make(), &bytes, &[1]);
    assert_eq!(error, None);
    assert!(items[0].is_err());
    assert_eq!(items[1], Ok(publish));
}

#[test]
fn mqtt_broker_round_trip_and_terminal_errors() {
    let packets = vec![
        mqtt::Packet::Publish(mqtt::Publish {
            dup: false,
            qos: mqtt::QoS::AtLeastOnce,
            retain: true,
            topic: "sensors/temperature".into(),
            packet_id: Some(7),
            payload: b"21.5".to_vec(),
        }),
        mqtt::Packet::PingReq,
    ];
    let bytes: Vec<u8> = packets.iter().flat_map(encoded).collect();
    let make = || mqtt::Frames::with_limit(64);
    contract::check_stack(make, &bytes);
    for pattern in [&[][..], &[1][..], &[3, 1, 37][..]] {
        let (got, error) = run(make(), &bytes, pattern);
        assert_eq!((got.clone(), error), (packets.clone(), None));
        let replies: Vec<_> = got
            .iter()
            .map(|packet| match packet {
                mqtt::Packet::Publish(publish) => mqtt::Packet::PubAck(publish.packet_id.unwrap()),
                mqtt::Packet::PingReq => mqtt::Packet::PingResp,
                _ => panic!("unexpected packet"),
            })
            .collect();
        let bytes: Vec<u8> = replies.iter().flat_map(encoded).collect();
        assert_eq!(run(make(), &bytes, pattern), (replies, None));
    }
    // The complete PUBACK body is invalid. MQTT ends this connection.
    let bytes = [0x40, 2, 0, 0, 0xd0, 0];
    contract::check_decode(make, &bytes);
    assert_eq!(
        run(make(), &bytes, &[1]),
        (vec![], Some(Fail::Protocol(mqtt::Error::PacketIdZero)))
    );
}

#[test]
fn coap_udp_and_tcp_round_trip() {
    let mut request = coap::Message::new(coap::Type::Confirmable, coap::Code::GET, 17);
    request.token = vec![7];
    request.options.set_uri_path("/temperature");
    let datagram = encoded(&request);
    let got = <coap::Message as Wire>::parse(&datagram).unwrap();
    let mut reply = got.reply(coap::Code::CONTENT, 18);
    reply.payload = b"21.5".to_vec();
    encoded(&reply);

    let request = coap::Frame {
        code: request.code,
        token: request.token,
        options: request.options,
        payload: request.payload,
    };
    let frames = vec![coap::Frame::csm(4096, true), request.clone()];
    let bytes: Vec<u8> = frames.iter().flat_map(encoded).collect();
    contract::check_stack(coap::Frames::new, &bytes);
    for pattern in [&[][..], &[1][..], &[3, 1, 37][..]] {
        assert_eq!(
            run(coap::Frames::new(), &bytes, pattern),
            (frames.clone(), None)
        );
        let mut reply = request.reply(coap::Code::CONTENT);
        reply.payload = b"21.5".to_vec();
        assert_eq!(
            run(coap::Frames::new(), &encoded(&reply), pattern),
            (vec![reply], None)
        );
    }
    // A complete frame whose payload marker has no following payload.
    let bad = [0x10, coap::Code::GET.0, coap::PAYLOAD_MARKER];
    contract::check_decode(coap::Frames::new, &bad);
    assert_eq!(
        run(coap::Frames, &bad, &[1]),
        (vec![], Some(Fail::Protocol(coap::Error::EmptyPayload)))
    );
}

#[test]
fn dhcpv6_tcp_recovers_messages_and_replies() {
    let mut request = dhcpv6::Message::new(dhcpv6::msg::SOLICIT, 0x123456);
    request
        .options
        .push(dhcpv6::DhcpOption::ClientId(dhcpv6::Duid::en(
            32473, b"client",
        )));
    request
        .options
        .push(dhcpv6::DhcpOption::Oro(vec![dhcpv6::opt::DNS_SERVERS]));
    encoded(&request);
    let mut bytes = vec![0, 0]; // A delimited empty message is an item error.
    bytes.extend(encoded(&dhcpv6::Frame(request.clone())));
    bytes.extend_from_slice(&[0, 5, 1, 0, 0, 1, 0]); // Torn option inside a whole message.
    bytes.extend(encoded(&dhcpv6::Frame(request.clone())));
    contract::check_stack(dhcpv6::Frames::new, &bytes);
    let expected = vec![
        Err(dhcpv6::ParseError::Short),
        Ok(request.clone()),
        Err(dhcpv6::ParseError::Truncated),
        Ok(request.clone()),
    ];
    for pattern in [&[][..], &[1][..], &[3, 1, 37][..]] {
        let (items, error) = run(dhcpv6::Frames, &bytes, pattern);
        assert_eq!(error, None);
        assert_eq!(items, expected);
        let mut replies = Vec::new();
        for message in items.into_iter().flatten() {
            let answer =
                message.answer(dhcpv6::msg::ADVERTISE, &dhcpv6::Duid::en(32473, b"server"));
            let bytes = encoded(&dhcpv6::Frame(answer.clone()));
            assert_eq!(
                run(dhcpv6::Frames, &bytes, pattern),
                (vec![Ok(answer.clone())], None)
            );
            replies.push(answer);
        }
        assert_eq!(replies.len(), 2);
    }

    let mut legacy = dhcpv6::Decoder::new();
    let mut got = Vec::new();
    for byte in &bytes {
        assert_eq!(legacy.feed(core::slice::from_ref(byte)), 1);
        got.extend(core::iter::from_fn(|| legacy.next_message()));
    }
    assert_eq!(got, expected);
    assert_eq!(legacy.buffered(), 0);
    assert_eq!(legacy.next_message(), None);
}

#[test]
fn syslog_mixed_framing_and_final_unterminated_message() {
    let first = syslog::Frame::new(
        syslog::Framing::OctetCounting,
        b"<13>1 - host app - - - first\nline".to_vec(),
    );
    let second = syslog::Frame::new(
        syslog::Framing::NonTransparent,
        b"<13>1 - host app - - - second\r".to_vec(),
    );
    let last = syslog::Frame::new(
        syslog::Framing::NonTransparent,
        b"<13>1 - host app - - - last\r".to_vec(),
    );
    let mut bytes = b"\n\r\n".to_vec();
    bytes.extend(encoded(&first));
    bytes.extend(encoded(&second));
    bytes.extend(b"invalid message\n");
    bytes.extend_from_slice(&last.message); // No delimiter at EOF; the CR is data.
    contract::check_decode(syslog::Frames::new, &bytes);
    let make = || syslog::Frames::new().map(|frame| syslog::Entry::parse(&frame.message));
    contract::check_stack(make, &bytes);
    let expected = vec![
        first,
        second,
        syslog::Frame::new(syslog::Framing::NonTransparent, b"invalid message".to_vec()),
        last,
    ];
    for pattern in [&[][..], &[1][..], &[3, 1, 37][..]] {
        assert_eq!(
            run(syslog::Frames::new(), &bytes, pattern),
            (expected.clone(), None)
        );
        let (entries, error) = run(make(), &bytes, pattern);
        assert_eq!(error, None);
        assert!(
            entries[0].is_ok() && entries[1].is_ok() && entries[2].is_err() && entries[3].is_ok()
        );
        let bytes: Vec<u8> = expected.iter().flat_map(encoded).collect();
        assert_eq!(
            run(syslog::Frames::new(), &bytes, pattern),
            (expected.clone(), None)
        );
    }
    let mut stream = Stream::new(syslog::Frames::new());
    assert_eq!(stream.push(b"last\r"), 5);
    assert_eq!(stream.next(), None);
    stream.end();
    assert_eq!(
        stream.with_next(|frame, raw, span| (frame.message, raw.to_vec(), span)),
        Some(Ok((b"last\r".to_vec(), b"last\r".to_vec(), 0..5)))
    );
    assert_eq!(stream.next(), None);
}

#[test]
fn partial_units_and_header_faults() {
    let amqp_partial = [3, 0, 1, 0, 0, 0, 1, b'x'];
    contract::check_decode(amqp::Frames::new, &amqp_partial);
    assert_eq!(
        run(amqp::Frames::new(), &amqp_partial, &[1]),
        (vec![], Some(Fail::Truncated { unread: 8 }))
    );
    assert_eq!(
        run(amqp::Frames::server(), b"AMQP", &[1]),
        (vec![], Some(Fail::Truncated { unread: 4 }))
    );
    assert_eq!(
        run(amqp::Frames::server(), b"NOT AMQP", &[1]),
        (
            vec![],
            Some(Fail::Protocol(amqp::FrameError::ProtocolHeader(
                *b"NOT AMQP"
            )))
        )
    );
    let oversized = [3, 0, 1, 0, 0, 0x10, 0];
    let make = || amqp::Frames::with_limit(amqp::FRAME_MIN_SIZE);
    contract::check_decode(make, &oversized);
    assert_eq!(
        run(make(), &oversized, &[1]),
        (
            vec![],
            Some(Fail::Protocol(amqp::FrameError::TooLarge {
                size: 4096,
                frame_max: amqp::FRAME_MIN_SIZE,
            }))
        )
    );

    for bytes in [&[0x30][..], &[0x30, 3, 0][..], &[0x30, 0x80][..]] {
        contract::check_decode(mqtt::Frames::new, bytes);
        assert_eq!(
            run(mqtt::Frames::new(), bytes, &[1]),
            (
                vec![],
                Some(Fail::Truncated {
                    unread: bytes.len()
                })
            )
        );
    }
    let make = || mqtt::Frames::with_limit(0);
    let bytes = [0x30, 0x80, 0x80, 0x80, 0x00];
    contract::check_decode(make, &bytes);
    assert_eq!(make().capacity(), 5);
    assert_eq!(
        run(make(), &bytes, &[1]),
        (
            vec![],
            Some(Fail::Protocol(mqtt::Error::TooLarge { size: 5, max: 2 }))
        )
    );

    for bytes in [&[0xf0][..], &[0, coap::Code::GET.0, 0x10][..]] {
        contract::check_decode(coap::Frames::new, bytes);
    }
    assert_eq!(
        run(coap::Frames, &[0x10, 1], &[1]),
        (vec![], Some(Fail::Truncated { unread: 2 }))
    );
    let huge = [0xf0, 0xff, 0xff, 0xff, 0xff];
    contract::check_decode(coap::Frames::new, &huge);
    assert_eq!(
        run(coap::Frames, &huge, &[1]),
        (
            vec![],
            Some(Fail::Protocol(coap::Error::TooLong(
                65_805 + u64::from(u32::MAX)
            )))
        )
    );

    for bytes in [&[0][..], &[0, 4, 1][..]] {
        contract::check_decode(dhcpv6::Frames::new, bytes);
        assert_eq!(
            run(dhcpv6::Frames, bytes, &[1]),
            (
                vec![],
                Some(Fail::Truncated {
                    unread: bytes.len()
                })
            )
        );
    }
    for bytes in [&b"12"[..], &b"5 abc"[..]] {
        contract::check_decode(syslog::Frames::new, bytes);
        assert_eq!(
            run(syslog::Frames::new(), bytes, &[1]),
            (
                vec![],
                Some(Fail::Truncated {
                    unread: bytes.len()
                })
            )
        );
    }
    assert_eq!(
        run(syslog::Frames::new(), b"12x", &[1]),
        (
            vec![],
            Some(Fail::Protocol(syslog::DecodeError::Framing(
                syslog::FrameError::Length(b'x')
            )))
        )
    );
    contract::check_decode(syslog::Frames::new, b"999999999999999999999999999999 ");
}

#[test]
fn exact_parsers_and_transactional_writers() {
    let frame = amqp::Frame::heartbeat();
    let mut bytes = encoded(&frame);
    bytes.push(0);
    assert_eq!(
        <amqp::Frame as Wire>::parse(&bytes),
        Err(amqp::FrameParseError::Trailing)
    );
    assert_eq!(
        <amqp::Frame as Wire>::parse(&[]),
        Err(amqp::FrameParseError::Truncated)
    );
    refuses(&amqp::Frame {
        channel: 1,
        ..frame
    });
    refuses(&amqp::Frame::body(0, vec![1]));
    refuses(&amqp::Frame::body(1, vec![0; amqp::MAX_PAYLOAD + 1]));

    assert_eq!(
        <mqtt::Packet as Wire>::parse(&[0xc0, 0, 0]),
        Err(mqtt::Error::TrailingBytes)
    );
    assert_eq!(
        <mqtt::Packet as Wire>::parse(&[0xc0]),
        Err(mqtt::Error::Truncated)
    );
    refuses(&mqtt::Packet::PubAck(0));
    refuses(&mqtt::Packet::ConnAck(mqtt::ConnAck {
        session_present: true,
        code: mqtt::ConnectReturnCode::NotAuthorized,
    }));

    let mut frame = coap::Frame::new(coap::Code::GET);
    assert_eq!(
        <coap::Frame as Wire>::parse(&[0, 1, 0]),
        Err(coap::FrameParseError::Trailing)
    );
    frame.token = vec![0; coap::MAX_TOKEN + 1];
    refuses(&frame);
    frame.token.clear();
    frame.options.0 = vec![
        coap::CoapOption {
            number: 12,
            value: vec![],
        },
        coap::CoapOption {
            number: 11,
            value: vec![],
        },
    ];
    refuses(&frame); // The old writer sorts options; Wire refuses that change.
    assert!(frame.try_to_bytes().is_some());
    frame.options.0.clear();
    frame.payload = vec![0; coap::MAX_FRAME_BODY]; // The marker also needs a byte.
    refuses(&frame);
    let mut message = coap::Message::empty_ack(1);
    message.payload = vec![1];
    refuses(&message);
    assert_eq!(message.to_bytes(), [0x60, 0, 0, 1]);
    // Parsed UDP options remain writable, including reserved block sizes.
    let mut message = coap::Message::new(coap::Type::Confirmable, coap::Code::GET, 1);
    message.options.set_uint(coap::option::BLOCK1, 7);
    assert!(message.try_to_bytes().is_none());
    encoded(&message);

    let mut message = dhcpv6::Message::new(dhcpv6::msg::SOLICIT, 1);
    message.transaction = 1 << 24;
    refuses(&message);
    refuses(&dhcpv6::Frame(message.clone()));
    message.transaction = 1;
    message.hop_count = 1;
    refuses(&message);
    message.hop_count = 0;
    message.options.push(dhcpv6::DhcpOption::Other {
        code: dhcpv6::opt::PREFERENCE,
        data: vec![7],
    });
    refuses(&message); // It would read as Preference, not Other.
    assert!(dhcpv6::Message::parse(&message.to_bytes()).is_ok());
    assert_eq!(
        <dhcpv6::Frame as Wire>::parse(&[0]),
        Err(dhcpv6::FrameParseError::Truncated)
    );
    assert_eq!(
        <dhcpv6::Frame as Wire>::parse(&[0, 4, 1, 0, 0, 1, 0]),
        Err(dhcpv6::FrameParseError::Trailing)
    );

    for frame in [
        syslog::Frame::new(syslog::Framing::NonTransparent, vec![]),
        syslog::Frame::new(
            syslog::Framing::NonTransparent,
            b"1 starts as a count".to_vec(),
        ),
        syslog::Frame::new(syslog::Framing::NonTransparent, b"has\na newline".to_vec()),
        syslog::Frame {
            framing: syslog::Framing::OctetCounting,
            message: b"clipped".to_vec(),
            truncated: true,
        },
        syslog::Frame::new(
            syslog::Framing::OctetCounting,
            vec![0; syslog::MAX_MESSAGE_LEN + 1],
        ),
    ] {
        refuses(&frame);
    }
    assert_eq!(
        <syslog::Frame as Wire>::parse(b"one\ntwo\n"),
        Err(syslog::FrameParseError::Trailing)
    );
    assert_eq!(
        <syslog::Frame as Wire>::parse(b"4 abc"),
        Err(syslog::FrameParseError::Truncated)
    );
    encoded(&syslog::Frame::new(
        syslog::Framing::NonTransparent,
        b"\r".to_vec(),
    ));
}

#[test]
fn dhcpv6_tcp_limit_and_legacy_backpressure() {
    let mut message = dhcpv6::Message::new(dhcpv6::msg::REPLY, 1);
    message.options.push(dhcpv6::DhcpOption::InterfaceId(vec![
        7;
        dhcpv6::MAX_TCP_MESSAGE
            - 8
    ]));
    refuses(&message); // This message fits TCP but exceeds the UDP limit.
    let frame = dhcpv6::Frame(message.clone());
    let bytes = encoded(&frame);
    assert_eq!(bytes.len(), dhcpv6::MAX_BUFFERED);
    contract::check_decode(dhcpv6::Frames::new, &bytes);
    assert_eq!(
        run(dhcpv6::Frames, &bytes, &[1]),
        (vec![Ok(message.clone())], None)
    );
    let mut batch = bytes.clone();
    batch.extend_from_slice(&[0, 0]);
    let mut legacy = dhcpv6::Decoder::new();
    assert_eq!(legacy.feed(&batch), dhcpv6::MAX_BUFFERED);
    assert_eq!(legacy.feed(&[0]), 0);
    assert_eq!(legacy.next_message(), Some(Ok(message)));
    assert_eq!(legacy.feed(batch.get(bytes.len()..).unwrap()), 2);
    assert_eq!(legacy.next_message(), Some(Err(dhcpv6::ParseError::Short)));
    assert_eq!(legacy.buffered(), 0);
}

#[test]
fn syslog_overlong_frames_skip_tails_and_detect_incomplete_counts() {
    for framing in [
        syslog::Framing::OctetCounting,
        syslog::Framing::NonTransparent,
    ] {
        let body = vec![b'x'; syslog::MAX_MESSAGE_LEN + 20];
        let mut bytes = if framing == syslog::Framing::OctetCounting {
            format!("{} ", body.len()).into_bytes()
        } else {
            vec![]
        };
        bytes.extend_from_slice(&body);
        if framing == syslog::Framing::NonTransparent {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(b"next\n");
        contract::check_decode(syslog::Frames::new, &bytes);
        let expected = vec![
            syslog::Frame {
                framing,
                message: vec![b'x'; syslog::MAX_MESSAGE_LEN],
                truncated: true,
            },
            syslog::Frame::new(syslog::Framing::NonTransparent, b"next".to_vec()),
        ];
        for pattern in [&[][..], &[1][..]] {
            assert_eq!(
                run(syslog::Frames::new(), &bytes, pattern),
                (expected.clone(), None)
            );
        }
        assert!(<syslog::Frame as Wire>::parse(&bytes).is_err());
    }
    let mut bytes = format!("{} ", syslog::MAX_MESSAGE_LEN + 10).into_bytes();
    bytes.extend(vec![b'x'; syslog::MAX_MESSAGE_LEN + 3]);
    contract::check_decode(syslog::Frames::new, &bytes);
    let (items, error) = run(syslog::Frames::new(), &bytes, &[1]);
    assert_eq!(items.len(), 1);
    assert!(items[0].truncated);
    assert_eq!(
        error,
        Some(Fail::Protocol(syslog::DecodeError::Incomplete {
            remaining: 7
        }))
    );

    // A CR just past the maximum can still belong to the CRLF trailer.
    let mut bytes = vec![b'x'; syslog::MAX_MESSAGE_LEN];
    bytes.extend_from_slice(b"\r\n");
    contract::check_decode(syslog::Frames::new, &bytes);
    assert_eq!(
        run(syslog::Frames::new(), &bytes, &[1]),
        (
            vec![syslog::Frame::new(
                syslog::Framing::NonTransparent,
                vec![b'x'; syslog::MAX_MESSAGE_LEN]
            )],
            None
        )
    );
}

#[test]
fn legacy_errors_repeat_and_finish_keeps_its_old_policy() {
    let mut amqp = amqp::Decoder::new();
    assert_eq!(amqp.feed(&[0]), 1);
    let error = amqp.next_frame();
    assert_eq!(error, Some(Err(amqp::FrameError::Type(0))));
    assert_eq!(amqp.next_frame(), error);
    assert_eq!(amqp.feed(&[1, 2]), 2);
    assert_eq!(amqp.buffered(), 0);

    let mut mqtt = mqtt::Decoder::new();
    assert_eq!(mqtt.feed(&[0]), 1);
    let error = mqtt.next_packet();
    assert_eq!(error, Some(Err(mqtt::Error::ReservedType(0))));
    assert_eq!(mqtt.next_packet(), error);
    assert_eq!(mqtt.feed(&[1, 2]), 2);
    assert_eq!(mqtt.buffered(), 0);

    let mut coap = coap::Decoder::new();
    assert_eq!(coap.feed(&[9]), 1);
    let error = coap.next_frame();
    assert_eq!(error, Some(Err(coap::Error::TokenLength(9))));
    assert_eq!(coap.next_frame(), error);
    assert_eq!(coap.feed(&[1, 2]), 2);
    assert_eq!(coap.buffered(), 0);

    let mut syslog = syslog::Decoder::new();
    assert_eq!(syslog.feed(b"1x"), 2);
    let error = syslog.next_frame();
    assert_eq!(error, Some(Err(syslog::FrameError::Length(b'x'))));
    assert_eq!(syslog.next_frame(), error);
    assert_eq!(syslog.finish(), None);
    let mut syslog = syslog::Decoder::new();
    assert_eq!(syslog.feed(b"5 abc"), 5);
    assert_eq!(syslog.next_frame(), None);
    assert_eq!(syslog.finish(), None); // Legacy EOF drops partial counted frames.
    assert_eq!(syslog.buffered(), 0);
}

#[test]
fn decoders_have_bounded_capacity_and_no_held_input() {
    for limit in [0, 1, 2, 5, 4096, usize::MAX] {
        let decoder = mqtt::Frames::with_limit(limit);
        assert!((5..=mqtt::MAX_PACKET).contains(&decoder.capacity()));
        assert_eq!(decoder.held(), 0);
        contract::check_decode(
            || mqtt::Frames::with_limit(limit),
            &[0x30, 0x80, 0x80, 0x80, 0x80],
        );
    }
    for limit in [0, 1, amqp::FRAME_MIN_SIZE, u32::MAX] {
        let decoder = amqp::Frames::with_limit(limit);
        assert_eq!(decoder.capacity(), amqp::frame_limit(limit) as usize);
        assert_eq!(decoder.held(), 0);
    }
    assert_eq!(coap::Frames.capacity(), coap::MAX_BUFFERED);
    assert_eq!(dhcpv6::Frames.capacity(), dhcpv6::MAX_BUFFERED);
    assert_eq!(syslog::Frames::new().capacity(), syslog::MAX_BUFFERED);
    assert_eq!(amqp::Frames::new().decode(&[], true), Ok(Step::Need));
    assert_eq!(mqtt::Frames::new().decode(&[], true), Ok(Step::Need));
    assert_eq!(coap::Frames.decode(&[], true), Ok(Step::Need));
    assert_eq!(dhcpv6::Frames.decode(&[], true), Ok(Step::Need));
    assert_eq!(syslog::Frames::new().decode(&[], true), Ok(Step::Need));
}
