use fictionet::{
    observe::{Decoded, Match, Observed, Place, Registry, Selection, Transport, http2 as capture},
    stdlib::{codec::Wire, grpc, hpack, http2},
};

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
fn copied_capture_replaces_the_builtin_through_the_same_registry() {
    let mut builtin = Registry::default();
    let mut copied = Registry::default();
    let budget = fictionet_copy_modules::observe_http2::CaptureBudget::default();
    copied.register_with_buffer(
        "http2",
        |_| Match::Yes,
        capture::CAPTURE_READ_AHEAD,
        move |_| fictionet_copy_modules::observe_http2::Capture::pair_in(&budget),
    );
    assert!(builtin.choose(Transport::Tcp, "http2"));
    let selection = Selection {
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
    for registry in [builtin, copied] {
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
