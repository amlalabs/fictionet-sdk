use fictionet::{
    observe::{Decoded, Match, Observed, Place, Registry, Selection, Transport},
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
    let mut observed = Observed::new(http2::Capture::default());
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
    let mut observed = Observed::new(http2::Capture::default());
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
    let budget = fictionet_copy_modules::http2::CaptureBudget::default();
    copied.register_with_buffer(
        "http2",
        |_| Match::Yes,
        http2::CAPTURE_READ_AHEAD,
        move |_| fictionet_copy_modules::http2::Capture::pair_in(&budget),
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
    let mut copied_grpc = Observed::new(fictionet_copy_modules::grpc::Messages::with_limit(32));
    let mut packet = Decoded::default();
    copied_grpc.data(&[0, 0, 0, 0, 0], Place::default(), &mut packet);
    assert_eq!(packet.layers[0].name, "gRPC");
}
#[test]
fn eof_reports_a_grpc_truncation() {
    let mut observed = Observed::new(http2::Capture::default());
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
fn incomplete_grpc_at_trailers_and_gaps_do_not_join_stale_bytes() {
    let mut observed = Observed::new(http2::Capture::default());
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
