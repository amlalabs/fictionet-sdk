//! HTTP/2 and gRPC capture presentation, through the public registry.
#![cfg(feature = "decode")]

use fictionet::{
    events::Transport,
    stdlib::{
        codec::Wire,
        protocols::{grpc, hpack, http2},
    },
};
use fictionet_observe::{Decoded, Observed, Place, Registry, Selection, http2 as capture};

fn headers() -> Vec<u8> {
    let mut fragment = Vec::new();
    hpack::Encoder::new(4096)
        .encode_block(
            &[
                hpack::Field::new(":method", "POST"),
                hpack::Field::new(":path", "/echo/Call"),
                hpack::Field::new("content-type", "application/grpc"),
            ],
            &mut fragment,
        )
        .unwrap();
    http2::Headers {
        stream: 1,
        flags: 4,
        fragment,
        priority: None,
        padding: None,
    }
    .to_bytes()
    .unwrap()
}
fn data(bytes: &[u8], flags: u8) -> Vec<u8> {
    http2::Data {
        stream: 1,
        flags,
        data: bytes.to_vec(),
        padding: None,
    }
    .to_bytes()
    .unwrap()
}

#[test]
fn goaway_releases_only_calls_started_by_its_receiver() {
    for client in [false, true] {
        for role in ["preface", "request", "response", "unknown"] {
            for stream in [1, 2] {
                for sender in [client, !client] {
                    for last_stream in [0, stream] {
                        let mut protocol = Registry::default()
                            .open(Selection {
                                transport: Transport::Tcp,
                                ports: (40000, 443),
                                first: &[],
                                protocol: None,
                                alpn: Some("h2"),
                            })
                            .unwrap();
                        let mut send = |dir, bytes: &[u8]| {
                            let mut packet = Decoded::default();
                            protocol.data(dir, bytes, Place::default(), &mut packet, &[]);
                            packet
                        };
                        if role == "preface" {
                            send(client, http2::PREFACE);
                        }
                        for dir in [client, !client] {
                            send(
                                dir,
                                &http2::Settings {
                                    flags: 0,
                                    entries: Vec::new(),
                                }
                                .to_bytes()
                                .unwrap(),
                            );
                            let mut fields =
                                vec![hpack::Field::new("content-type", "application/grpc")];
                            if dir == client && matches!(role, "preface" | "request") {
                                fields.insert(0, hpack::Field::new(":method", "POST"));
                            } else if dir != client && matches!(role, "preface" | "response") {
                                fields.insert(0, hpack::Field::new(":status", "200"));
                            }
                            let mut fragment = Vec::new();
                            hpack::Encoder::new(4096)
                                .encode_block(&fields, &mut fragment)
                                .unwrap();
                            send(
                                dir,
                                &http2::Headers {
                                    stream,
                                    flags: 4,
                                    fragment,
                                    priority: None,
                                    padding: None,
                                }
                                .to_bytes()
                                .unwrap(),
                            );
                        }
                        let message = [0, 0, 0, 0, 3, b'a', b'b', b'c'];
                        for dir in [client, !client] {
                            send(
                                dir,
                                &http2::Data {
                                    stream,
                                    flags: 0,
                                    data: message[..3].to_vec(),
                                    padding: None,
                                }
                                .to_bytes()
                                .unwrap(),
                            );
                        }
                        send(
                            sender,
                            &http2::GoAway {
                                flags: 0,
                                last_stream,
                                code: 0,
                                debug: Vec::new(),
                            }
                            .to_bytes()
                            .unwrap(),
                        );
                        let released = role != "unknown"
                            && stream > last_stream
                            && (stream % 2 == 1) == (sender != client);
                        for dir in [!client, client] {
                            let packet = send(
                                dir,
                                &http2::Data {
                                    stream,
                                    flags: 1,
                                    data: message[3..].to_vec(),
                                    padding: None,
                                }
                                .to_bytes()
                                .unwrap(),
                            );
                            assert_eq!(
                                packet.layers.iter().any(|layer| layer.name == "gRPC"),
                                !released,
                                "client={client}, role={role}, stream={stream}, sender={sender}, last={last_stream}"
                            );
                            assert!(!packet.tags.contains(&"malformed"));
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn registry_connections_share_the_capture_data_budget() {
    let registry = Registry::default();
    let mut connections = Vec::new();
    let mut refused = 0;
    let mut partial = vec![0, 0, 0x40, 0, 0]; // A 4 MiB message.
    partial.resize(16_384, 0);
    for _ in 0..12 {
        let mut protocol = registry
            .clone()
            .open(Selection {
                transport: Transport::Tcp,
                ports: (40000, 443),
                first: http2::PREFACE,
                protocol: None,
                alpn: None,
            })
            .unwrap();
        let mut packet = Decoded::default();
        protocol.data(
            false,
            &[http2::PREFACE.as_slice(), &headers()].concat(),
            Place::default(),
            &mut packet,
            &[],
        );
        for n in 0..64 {
            let bytes = data(if n == 0 { &partial } else { &[0; 16_384] }, 0);
            packet = Decoded::default();
            protocol.data(false, &bytes, Place::default(), &mut packet, &[]);
            refused += usize::from(packet.tags.contains(&"malformed"));
        }
        connections.push(protocol);
    }
    assert!(
        refused > 0,
        "12 MiB of partial messages must exceed the shared 8 MiB budget"
    );
}

#[test]
fn registration_keeps_the_supplied_budget_across_registry_clones() {
    let budget = capture::CaptureBudget::new(64);
    let mut registry = Registry::new();
    capture::Capture::register(&mut registry, &budget);
    let mut connections = Vec::new();
    for held in [32, 64] {
        let mut protocol = registry
            .clone()
            .open(Selection {
                transport: Transport::Tcp,
                ports: (40000, 443),
                first: http2::PREFACE,
                protocol: None,
                alpn: None,
            })
            .unwrap();
        let mut partial = vec![0, 0, 0, 1, 0];
        partial.resize(32, 0);
        let bytes = [http2::PREFACE.as_slice(), &headers(), &data(&partial, 0)].concat();
        let mut packet = Decoded::default();
        protocol.data(false, &bytes, Place::default(), &mut packet, &[]);
        assert!(!packet.tags.contains(&"malformed"));
        assert_eq!(budget.held(), held);
        connections.push(protocol);
    }
    drop(connections.pop().unwrap());
    assert_eq!(budget.held(), 32);
    drop(connections);
    assert_eq!(budget.held(), 0);
}

#[test]
fn frames_and_grpc_fields_keep_their_packet_byte_ranges() {
    let mut observed = Observed::new(capture::Capture::default());
    let head = headers();
    let message = grpc::Message {
        compressed: false,
        data: b"abc".to_vec(),
    }
    .to_bytes()
    .unwrap();
    let bytes = [
        head.as_slice(),
        &data(&message, 1),
        &http2::Ping {
            flags: 0,
            opaque: *b"12345678",
        }
        .to_bytes()
        .unwrap(),
    ]
    .concat();
    let mut packet = Decoded::default();
    observed.data(
        &bytes,
        Place {
            stream_start: 900,
            buf: 0,
            offset: Some(40),
            len: bytes.len(),
        },
        &mut packet,
    );
    assert_eq!(
        packet
            .layers
            .iter()
            .map(|l| l.name.as_str())
            .collect::<Vec<_>>(),
        [
            "HyperText Transfer Protocol 2",
            "HyperText Transfer Protocol 2",
            "gRPC",
            "HyperText Transfer Protocol 2"
        ]
    );
    let layer = &packet.layers[2];
    assert_eq!(layer.buf, 0);
    assert_eq!(
        layer.range,
        (40 + head.len() + 9, 40 + head.len() + 9 + message.len())
    );
    assert_eq!(
        layer.fields[0].range,
        Some((40 + head.len() + 9, 40 + head.len() + 10))
    );
    assert!(packet.extra.is_empty());
    assert_eq!(
        packet.info,
        "HEADERS[1]: POST /echo/Call, DATA[1] 8 bytes, end, PING"
    );
    assert!(packet.layers_json().contains("gRPC"));
}
#[test]
fn padded_data_keeps_session_credit_and_capture_byte_ranges() {
    for padding in [0, 2, 255] {
        let mut observed = Observed::new(capture::Capture::default());
        let mut session = http2::Session::server_side(http2::Limits::default());
        let head = headers();
        let settings = http2::Settings {
            flags: 0,
            entries: vec![],
        }
        .to_bytes()
        .unwrap();
        let message = grpc::Message {
            compressed: false,
            data: b"abc".to_vec(),
        }
        .to_bytes()
        .unwrap();
        let frame = http2::Data {
            stream: 1,
            flags: 9,
            data: message.clone(),
            padding: Some(vec![0xa5; padding]),
        }
        .to_bytes()
        .unwrap();
        let bytes = [settings.as_slice(), &head, &frame].concat();
        assert_eq!(session.push(&bytes), bytes.len());
        assert!(matches!(
            session.next().unwrap().unwrap(),
            http2::Event::Settings(_)
        ));
        let http2::Event::Headers { fields, .. } = session.next().unwrap().unwrap() else {
            panic!("expected headers");
        };
        assert_eq!(
            session.next().unwrap().unwrap(),
            http2::Event::Data {
                stream: 1,
                data: message.clone(),
                end: true,
            }
        );
        assert!(session.next().is_none());
        assert_eq!(
            session.connection_window(),
            65_535 - (1 + message.len() + padding) as i64
        );
        assert_eq!(session.stream_window(1), Some(session.connection_window()));

        let mut packet = Decoded::default();
        observed.data(
            &bytes,
            Place {
                stream_start: 900,
                buf: 0,
                offset: Some(40),
                len: bytes.len(),
            },
            &mut packet,
        );
        assert!(!packet.tags.contains(&"malformed"));
        for field in fields {
            assert!(
                packet.layers[1].fields.iter().any(|f| {
                    f.name.as_bytes() == field.name && f.value.as_bytes() == field.value
                })
            );
        }
        let grpc = &packet.layers[3];
        let start = 40 + settings.len() + head.len() + http2::HEADER_LEN + 1;
        assert_eq!(grpc.name, "gRPC");
        assert_eq!(grpc.buf, 0);
        assert_eq!(grpc.range, (start, start + message.len()));
        assert_eq!(grpc.fields[0].range, Some((start, start + 1)));
        assert_eq!(
            grpc.fields[2].range,
            Some((start + 5, start + message.len()))
        );
        assert!(packet.extra.is_empty());
    }
}
#[test]
fn frames_split_between_packets_and_messages_split_between_frames_get_buffers() {
    let mut observed = Observed::new(capture::Capture::default());
    let head = headers();
    let message = grpc::Message {
        compressed: false,
        data: b"abcdef".to_vec(),
    }
    .to_bytes()
    .unwrap();
    let first = [head.as_slice(), &data(&message[..3], 0)].concat();
    let mut packet = Decoded::default();
    observed.data(
        &first,
        Place {
            offset: Some(0),
            len: first.len(),
            ..Default::default()
        },
        &mut packet,
    );
    let second = data(&message[3..], 1);
    observed.data(
        &second[..4],
        Place {
            stream_start: first.len() as u64,
            offset: Some(0),
            len: 4,
            ..Default::default()
        },
        &mut packet,
    );
    let mut packet = Decoded::default();
    observed.data(
        &second[4..],
        Place {
            stream_start: (first.len() + 4) as u64,
            offset: Some(0),
            len: second.len() - 4,
            ..Default::default()
        },
        &mut packet,
    );
    assert_eq!(
        packet.extra,
        [
            ("Reassembled HTTP/2 frame".into(), second),
            ("Reassembled gRPC message".into(), message)
        ]
    );
    assert_eq!(packet.layers[0].buf, 1);
    assert_eq!(packet.layers[1].buf, 2);
    assert_eq!(packet.layers[1].fields[2].range, Some((5, 11)));
    assert!(!packet.tags.contains(&"malformed"));
}
#[test]
fn registered_capture_replaces_the_builtin_through_the_same_registry() {
    let mut builtin = Registry::default();
    let mut registered = Registry::default();
    let budget = capture::CaptureBudget::default();
    capture::Capture::register(&mut registered, &budget);
    assert!(builtin.choose(Transport::Tcp, "http2"));
    let selection = Selection {
        protocol: None,
        transport: Transport::Tcp,
        ports: (1, 2),
        first: http2::PREFACE,
        alpn: None,
    };
    let bytes = [
        http2::PREFACE.as_slice(),
        &headers(),
        &data(&[0, 0, 0, 0, 1, b'x'], 1),
    ]
    .concat();
    let mut packets = Vec::new();
    for registry in [builtin, registered] {
        let mut protocol = registry.open(selection).unwrap();
        let mut packet = Decoded::default();
        protocol.data(
            false,
            &bytes,
            Place {
                offset: Some(0),
                len: bytes.len(),
                ..Default::default()
            },
            &mut packet,
            &[],
        );
        packets.push((packet.info.clone(), packet.layers_json()));
    }
    assert_eq!(packets[0], packets[1]);
}
#[test]
fn eof_reports_a_grpc_truncation() {
    let mut observed = Observed::new(capture::Capture::default());
    let mut packet = Decoded::default();
    observed.data(&headers(), Place::default(), &mut packet);
    observed.data(&data(&[0, 0], 0), Place::default(), &mut packet);
    packet = Decoded::default();
    observed.end(&mut packet);
    assert!(packet.tags.contains(&"malformed"));
    assert!(
        packet.info.starts_with("gRPC: truncated message"),
        "{}",
        packet.info
    );
    assert!(!packet.info.contains("HTTP/2"));
    assert!(!observed.waiting());
}

#[test]
fn eof_header_error_names_http2_once() {
    let mut observed = Observed::new(capture::Capture::default());
    let mut packet = Decoded::default();
    let mut head = headers();
    head[4] = 0; // HEADERS without END_HEADERS.
    observed.data(&head, Place::default(), &mut packet);
    packet = Decoded::default();
    observed.end(&mut packet);
    assert!(packet.tags.contains(&"malformed"));
    assert_eq!(
        packet.info,
        "HTTP/2 ProtocolError: incomplete header block at EOF"
    );
}

#[test]
fn header_diagnostics_keep_their_text_and_order() {
    let raw = |kind, flags, stream, body: &[u8]| {
        let mut bytes = http2::FrameHeader {
            kind,
            flags,
            stream,
            length: body.len(),
        }
        .to_bytes()
        .unwrap();
        bytes.extend_from_slice(body);
        bytes
    };
    let interrupted = (
        "Header block",
        "the one before was cut off by this frame, so later headers may not be known",
    );
    let not_decoded = (
        "Header block",
        "not decoded, so later headers may not be known",
    );
    let continues = ("Header block", "continues in the next frame");
    let unexpected = (
        "Header block",
        "a CONTINUATION with no header block to continue",
    );
    let oversized = http2::FrameHeader {
        kind: 1,
        flags: 4,
        stream: 3,
        length: 40_000,
    }
    .to_bytes()
    .unwrap();
    for (frames, malformed, expected) in [
        (vec![raw(1, 0, 1, &[0x82])], false, vec![continues]),
        (
            vec![raw(5, 0, 1, &[0, 0, 0, 2, 0x82])],
            false,
            vec![("Promised stream", "2"), continues],
        ),
        (
            vec![raw(1, 0, 1, &[0x82]), raw(5, 0, 3, &[0, 0, 0, 2, 0x82])],
            true,
            vec![interrupted, ("Promised stream", "2"), continues],
        ),
        (
            vec![raw(1, 0, 1, &[0x82]), oversized],
            true,
            vec![
                interrupted,
                ("Payload", "40000 bytes, too long to keep"),
                not_decoded,
            ],
        ),
        (
            vec![raw(1, 12, 1, &[2])],
            true,
            vec![
                ("Frame", "padding longer than payload"),
                (
                    "Header block",
                    "the frame is too short for its padding or fields",
                ),
                not_decoded,
            ],
        ),
        (
            vec![raw(1, 4, 1, &[0x80])],
            true,
            vec![("Header block", "could not be decoded: it is malformed")],
        ),
        (vec![raw(9, 4, 3, &[0x82])], true, vec![unexpected]),
        (
            vec![raw(1, 0, 1, &[0x82]), raw(9, 4, 3, &[0x82])],
            true,
            vec![interrupted, unexpected],
        ),
        (
            vec![
                raw(1, 0, 1, &vec![0x82; 16_384]),
                raw(9, 0, 1, &vec![0x82; 16_384]),
                raw(9, 0, 1, &vec![0x82; 16_384]),
                raw(9, 0, 1, &vec![0x82; 16_384]),
                raw(9, 4, 1, &[0x82]),
            ],
            false,
            vec![("Header block", "longer than the 64 KiB kept"), not_decoded],
        ),
        (
            vec![raw(5, 0, 1, &[0, 0, 0, 2]), raw(9, 4, 1, &[0x82])],
            false,
            vec![(":method", "GET")],
        ),
    ] {
        let mut observed = Observed::new(capture::Capture::default());
        let mut packet = Decoded::default();
        for frame in frames {
            packet = Decoded::default();
            observed.data(&frame, Place::default(), &mut packet);
        }
        assert_eq!(packet.tags.contains(&"malformed"), malformed);
        assert_eq!(packet.layers.len(), 1);
        let notes: Vec<_> = packet.layers[0]
            .fields
            .iter()
            .filter(|f| f.range.is_none())
            .map(|f| (f.name.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(notes, expected);
    }
}

#[test]
fn refused_frames_are_malformed_and_explain_why() {
    for (kind, stream, body) in [
        (8, 0, vec![0; 4]),
        (4, 0, vec![0, 2, 0, 0, 0, 2]),
        (6, 0, vec![0; 7]),
        (4, 1, vec![]),
        (7, 1, vec![0; 8]),
        (2, 1, vec![0, 0, 0, 1, 2]),
    ] {
        let mut bytes = http2::FrameHeader {
            length: body.len(),
            kind,
            flags: 0,
            stream,
        }
        .to_bytes()
        .unwrap();
        bytes.extend(body);
        let error = http2::Frame::parse(&bytes).unwrap_err();
        let mut observed = Observed::new(capture::Capture::default());
        let mut packet = Decoded::default();
        observed.data(&bytes, Place::default(), &mut packet);
        assert!(packet.tags.contains(&"malformed"));
        assert!(
            packet.layers[0]
                .fields
                .iter()
                .any(|f| { f.name == "Frame" && f.value == error.reason && f.range.is_none() })
        );
        let mut next = Decoded::default();
        observed.data(&headers(), Place::default(), &mut next);
        assert!(!next.tags.contains(&"malformed"));
        assert!(!next.layers.is_empty());
    }
}

#[test]
fn refused_header_frames_still_update_capture_hpack() {
    for (kind, stream, fields) in [
        (1, 0, vec![0, 0, 0, 0, 255]),
        (1, 1, vec![0x80, 0, 0, 1, 255]),
        (5, 0, vec![0x80, 0, 0, 2]),
        (5, 1, vec![0, 0, 0, 0]),
    ] {
        let mut encoder = hpack::Encoder::new(4096);
        let mut fragment = Vec::new();
        let saved = [hpack::Field::new("x-captured", "kept")];
        encoder.encode_block(&saved, &mut fragment).unwrap();
        let mut indexed = Vec::new();
        encoder.encode_block(&saved, &mut indexed).unwrap();
        assert!(indexed.len() < fragment.len());
        let mut body = vec![2];
        body.extend(fields);
        body.extend(fragment);
        body.extend([0xa5; 2]);
        let mut bytes = http2::FrameHeader {
            kind,
            stream,
            flags: if kind == 1 { 0x2c } else { 0xc },
            length: body.len(),
        }
        .to_bytes()
        .unwrap();
        bytes.extend(body);
        let error = http2::Frame::parse(&bytes).unwrap_err();
        let mut observed = Observed::new(capture::Capture::default());
        let mut packet = Decoded::default();
        observed.data(&bytes, Place::default(), &mut packet);
        assert!(packet.tags.contains(&"malformed"));
        assert!(
            packet.layers[0]
                .fields
                .iter()
                .any(|f| f.name == "Frame" && f.value == error.reason)
        );
        assert!(
            packet.layers[0]
                .fields
                .iter()
                .any(|f| f.name == "x-captured" && f.value == "kept")
        );
        if kind == 5 {
            assert!(
                packet.layers[0]
                    .fields
                    .iter()
                    .any(|f| f.name == "Promised stream"
                        && f.value == if stream == 0 { "2" } else { "0" })
            );
        }
        let next = http2::Headers {
            stream: 3,
            flags: 4,
            fragment: indexed,
            priority: None,
            padding: None,
        }
        .to_bytes()
        .unwrap();
        packet = Decoded::default();
        observed.data(&next, Place::default(), &mut packet);
        assert!(!packet.tags.contains(&"malformed"));
        assert!(
            packet.layers[0]
                .fields
                .iter()
                .any(|f| f.name == "x-captured" && f.value == "kept")
        );
    }
}

#[test]
fn batched_grpc_messages_report_the_display_limit() {
    let mut observed = Observed::new(capture::Capture::default());
    let mut packet = Decoded::default();
    observed.data(&headers(), Place::default(), &mut packet);
    packet = Decoded::default();
    observed.data(&data(&vec![0; 300 * 5], 1), Place::default(), &mut packet);
    assert_eq!(
        packet.layers.iter().filter(|l| l.name == "gRPC").count(),
        256
    );
    assert!(packet.layers[0].fields.iter().any(|f| {
        f.name == "gRPC" && f.value == "44 more messages, not shown" && f.range.is_none()
    }));
    assert!(!packet.tags.contains(&"malformed"));
}

#[test]
fn incomplete_grpc_at_trailers_and_gaps_do_not_join_stale_bytes() {
    let mut observed = Observed::new(capture::Capture::default());
    let mut packet = Decoded::default();
    observed.data(&headers(), Place::default(), &mut packet);
    observed.data(&data(&[0, 0], 0), Place::default(), &mut packet);
    observed.data(
        &http2::Headers {
            stream: 1,
            flags: 5,
            fragment: vec![],
            priority: None,
            padding: None,
        }
        .to_bytes()
        .unwrap(),
        Place::default(),
        &mut packet,
    );
    assert!(packet.tags.contains(&"malformed"));
    observed = observed.reset();
    let mut after = Decoded::default();
    observed.data(
        &data(&[0, 0, 0, 0, 1, b'x'], 1),
        Place::default(),
        &mut after,
    );
    assert!(after.layers.is_empty());
    assert!(!observed.waiting());
}
