//! Check public codec traits through the separate consumer fixture.
//! Copied modules compile without cfg(test) in fictionet-copy-modules.

use fictionet::stdlib::codec::{Decode, Stream, Wire, finish, pump};
use fictionet_copy_modules::*;

#[test]
fn copied_mail_modules_write_through_wire() {
    assert_eq!(
        smtp::Reply::new(250, "Queued").to_bytes().unwrap(),
        b"250 Queued\r\n"
    );
    assert_eq!(
        pop3::Reply::ok("ready").to_bytes().unwrap(),
        b"+OK ready\r\n"
    );
    assert_eq!(
        imap::Response::greeting("ready").to_bytes().unwrap(),
        b"* OK ready\r\n"
    );
}

#[test]
fn copied_modbus_uses_the_public_driver_and_map() {
    let request = modbus::Request::ReadHoldingRegisters {
        address: 2,
        quantity: 1,
    };
    let frame = modbus::Frame {
        transaction: 7,
        unit: 1,
        pdu: request.to_pdu().unwrap(),
    };
    let mut bytes = Vec::new();
    frame.write(&mut bytes).unwrap();
    assert_eq!(<modbus::Frame as Wire>::parse(&bytes).unwrap(), frame);
    let mut stream = Stream::new(modbus::Frames.map(|frame| modbus::Request::parse(&frame.pdu)));
    let mut requests = Vec::new();
    for chunk in bytes.chunks(3) {
        assert_eq!(
            pump(&mut stream, chunk, |item| requests.push(item)).unwrap(),
            chunk.len()
        );
    }
    finish(&mut stream, |item| requests.push(item)).unwrap();
    assert_eq!(requests, [Ok(request)]);
    assert!(stream.is_done());
}

#[test]
fn copied_presenters_plug_into_observe_and_construct_display_items() {
    use fictionet::observe::{
        Decoded, Layer, Match, Observed, Place, Present, Registry, Selection, Transport,
    };
    let mut registry = Registry::new();
    registry.register(
        "modbus",
        |_| Match::Yes,
        |_| {
            [
                observe_protocols::Modbus::new(true),
                observe_protocols::Modbus::new(false),
            ]
        },
    );
    let mut protocol = registry
        .open(Selection {
            transport: Transport::Tcp,
            ports: (40000, 502),
            first: &[],
            alpn: None,
        })
        .unwrap();
    let bytes = [0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1];
    let mut packet = Decoded::default();
    protocol.data(
        false,
        &bytes,
        Place {
            offset: Some(0),
            len: bytes.len(),
            ..Place::default()
        },
        &mut packet,
        &[],
    );
    assert_eq!(packet.proto, "Modbus/TCP");
    assert_eq!(packet.layers[0].range, (0, bytes.len()));
    let item = observe_protocols::Display::from_packet(packet, "Copied frame");
    assert!(observe_protocols::Modbus::summary(&item).contains("transaction 7"));
    assert!(format!("{registry:?}").contains("modbus"));
    assert!(
        format!("{:?}", Observed::new(observe_protocols::Modbus::new(true))).contains("Modbus/TCP")
    );

    let mut packet = Decoded::default();
    packet.application(2, "Custom", "message");
    assert_eq!(packet.level(), 2);
    packet.push(Layer::new("Custom", 0, (0, 1)));
    let item = observe_protocols::Display::from_packet(packet, "Custom bytes");
    let mut layer = Layer::new("Custom", 0, (0, 1));
    observe_protocols::Dns::fields(&item, b"x", &mut layer);
    let mut packet = Decoded::default();
    observe_protocols::Dns::present(
        &item,
        b"x",
        0,
        &fictionet::observe::Placement::new(Place {
            offset: Some(4),
            len: 1,
            ..Place::default()
        }),
        &mut packet,
    );
    assert_eq!(packet.layers[0].range, (4, 5));
    assert_eq!(packet.info, "message");
}

#[test]
fn copied_modbus_session_stops_both_directions_after_bad_framing() {
    use fictionet::observe::{Conversation, Decoded, Match, Place, Registry};
    let mut registry = Registry::new();
    registry.register_protocol(
        "modbus",
        |_| Match::Yes,
        |s, _| Box::new(observe_protocols::ModbusSession::new(s.ports)),
    );
    let mut conversation = Conversation::with_registry(40000, 502, registry);
    let bad = [0, 9, 0, 5, 0, 6, 1, 3, 0, 0, 0, 1];
    let reply = [0, 7, 0, 0, 0, 5, 1, 3, 2, 0x04, 0xd2];
    for (reverse, bytes) in [(false, &bad[..]), (true, &reply[..])] {
        let mut packet = Decoded::default();
        conversation.data(reverse, bytes, Place::default(), &mut packet, &[]);
        assert!(packet.layers.is_empty());
        assert!(packet.tags.is_empty());
        assert!(!conversation.waiting(reverse));
    }
}

#[test]
fn copied_tls_and_selection_driver_use_the_public_registry() {
    use fictionet::observe::{Decoded, Match, Place, Registry};
    let mut registry = Registry::default();
    registry.register_protocol(
        "tls",
        |_| Match::Yes,
        |s, registry| Box::new(observe_tls::TlsSession::new(s.ports, registry.clone())),
    );
    let mut conversation = observe_conversation::Conversation::with_registry(40000, 443, registry);
    let mut packet = Decoded::default();
    let record = [22, 3, 3, 0, 4, 20, 0, 0, 0];
    conversation.data(false, &record[..3], Place::default(), &mut packet, &[]);
    assert!(conversation.waiting(false));
    conversation.data(
        false,
        &record[3..],
        Place {
            stream_start: 3,
            ..Place::default()
        },
        &mut packet,
        &[],
    );
    assert_eq!(packet.proto, "TLS");
    assert_eq!(packet.info, "Finished");
    assert_eq!(packet.layers[0].range, (0, record.len()));
    assert_eq!(packet.extra[0].1, record);
    assert!(!conversation.waiting(false));
    conversation.lost(false);
    assert!(format!("{packet:?}").contains("Finished"));
}

#[test]
fn copied_sse_uses_public_lines_and_wire() {
    let event = sse::Event::new("first\nsecond");
    let bytes = event.to_bytes().unwrap();
    let mut stream = Stream::new(sse::Events::default());
    let mut events = Vec::new();
    for chunk in bytes.chunks(1) {
        pump(&mut stream, chunk, |event| events.push(event)).unwrap();
    }
    finish(&mut stream, |event| events.push(event)).unwrap();
    assert_eq!(events, [event]);
}

#[test]
fn copied_fix_skips_garbled_frames_through_the_public_driver() {
    // FIX 4.4 Vol 2 case 3.b: discard an invalid checksum and continue.
    let good = b"8=FIX.4.4\x019=5\x0135=0\x0110=163\x01";
    let bad = b"8=FIX.4.4\x019=5\x0135=0\x0110=164\x01";
    let mut stream = Stream::new(fix::Frames::default());
    let mut messages = Vec::new();
    pump(&mut stream, bad, |item| messages.push(item)).unwrap();
    pump(&mut stream, good, |item| messages.push(item)).unwrap();
    finish(&mut stream, |item| messages.push(item)).unwrap();
    assert_eq!(messages, [Ok(fix::Message::parse(good).unwrap())]);
    assert_eq!(stream.decoder().garbled(), 1);
    assert!(stream.failed().is_none());
}

#[test]
fn copied_fix_passes_field_failures_to_the_session() {
    // FIX 4.4 Vol 2 case 14.d; Session Layer 4.5.4.
    let mut session = fix::Session::new(
        fix::SessionConfig::new(fix::Version::Fix44, fix::Role::Acceptor, "LOCAL", "PEER").unwrap(),
        1,
        1,
        0,
    )
    .unwrap();
    let mut logon = fix::Message::new(fix::Version::Fix44, b"A").unwrap();
    let time = b"20261006-12:00:00";
    for (tag, value) in [
        (34, b"1".as_slice()),
        (49, b"PEER"),
        (56, b"LOCAL"),
        (52, time),
        (98, b"0"),
        (108, b"30"),
    ] {
        logon.push(tag, value).unwrap();
    }
    session.receive(&logon, 0, time).unwrap();
    let bytes = b"8=FIX.4.4\x019=56\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0158=\x0110=255\x01";
    let mut stream = Stream::new(fix::Frames::default());
    assert_eq!(stream.push(bytes), bytes.len());
    let frame = stream.next().unwrap().unwrap();
    assert_eq!(frame.as_ref().unwrap_err().reason(), 4);
    let actions = session.receive_frame(&frame, 1, time).unwrap();
    let fix::Action::Send(reject) = &actions[0] else {
        panic!("expected Reject")
    };
    assert_eq!(reject.get(371), Some(b"58".as_slice()));
    assert_eq!(reject.get(373), Some(b"4".as_slice()));
    assert_eq!(session.next_inbound(), 3);
    assert_eq!(stream.decoder().garbled(), 0);
}

#[test]
fn copied_fast_uses_templates_and_the_public_driver() {
    let templates = fast::Templates::from_xml(br#"<template xmlns="http://www.fixprotocol.org/ns/fast/td/1.1" name="Example" id="1"><uInt32 name="n"><increment value="1"/></uInt32></template>"#).unwrap();
    let value = fast::Message {
        template_id: 1,
        fields: vec![fast::Value::UInt32(1)],
    };
    let mut bytes = Vec::new();
    fast::Encoder::new(templates.clone())
        .write(&value, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0xc0, 0x81]);
    let mut stream = Stream::new(fast::Frames::new(templates.clone()));
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next().unwrap().unwrap(), value);
    assert_eq!(fast::UInt64::parse(&[0x81]).unwrap(), fast::UInt64(1));
    let mut blocks = Stream::new(fast::BlockFrames::new(fast::Frames::new(
        templates.clone(),
    )));
    assert_eq!(blocks.push(&[0, 0x82, 0xc0, 0x81]), 4);
    assert_eq!(blocks.next().unwrap().unwrap(), value);
    let mut split = Stream::new(fast::BlockFrames::new(fast::Frames::new(
        templates,
    )));
    assert_eq!(split.push(&[0x81, 0xc0, 0x81, 0x81]), 4);
    assert!(matches!(
        split.next(),
        Some(Err(fictionet::stdlib::codec::Fail::Protocol(
            fast::Error::BlockBoundary
        )))
    ));
}

#[test]
fn copied_soupbintcp_frames_through_the_public_driver() {
    // SoupBinTCP 3.00, 2.2.1: Login Accepted, then sequenced data.
    let mut bytes = vec![0, 31, b'A'];
    bytes.extend_from_slice(b"        S1                   7");
    soupbintcp::Packet::SequencedData(b"msg".to_vec())
        .write(&mut bytes)
        .unwrap();
    let mut client = soupbintcp::Client::new(
        soupbintcp::Login {
            username: soupbintcp::Alpha::right_padded("ALICE").unwrap(),
            password: soupbintcp::Alpha::right_padded("SECRET").unwrap(),
            session: soupbintcp::Alpha::blank(),
            sequence: 1,
        },
        soupbintcp::Timers::default(),
        0,
    )
    .unwrap();
    client.start(0).unwrap();
    let mut stream = Stream::new(soupbintcp::Frames::default());
    let mut events = Vec::new();
    for chunk in bytes.chunks(5) {
        pump(&mut stream, chunk, |frame| {
            events.extend(client.receive_frame(&frame, 1).unwrap())
        })
        .unwrap();
    }
    finish(&mut stream, |_| unreachable!()).unwrap();
    assert_eq!(
        events.last(),
        Some(&soupbintcp::Action::Event(soupbintcp::Event::Sequenced {
            sequence: 7
        }))
    );
    assert_eq!(client.next_sequence(), 8);
}

#[test]
fn copied_moldudp64_recovers_a_gap() {
    let session = moldudp64::Session::left_padded("S1").unwrap();
    let mut server =
        moldudp64::Retransmitter::new(session, 1, moldudp64::StoreConfig::default()).unwrap();
    for m in [&b"a"[..], b"b", b"c"] {
        server.push(m).unwrap();
    }
    let mut receiver = moldudp64::Receiver::new(moldudp64::ReceiverConfig::default()).unwrap();
    receiver.receive(&server.packet(1, 1).unwrap(), 0).unwrap();
    let bytes = server.packet(3, 1).unwrap().to_bytes().unwrap();
    let live = <moldudp64::Downstream as Wire>::parse(&bytes).unwrap();
    let actions = receiver.receive(&live, 1).unwrap();
    let Some(moldudp64::Action::Send(request)) = actions.last() else {
        panic!("expected a request")
    };
    let wire = request.to_bytes().unwrap();
    let request = <moldudp64::Request as Wire>::parse(&wire).unwrap();
    let answer = server.answer(&request).unwrap();
    receiver.receive(&answer, 2).unwrap();
    assert_eq!(receiver.expected(), Some(4));
    let mut blocks = Stream::new(moldudp64::Blocks);
    let mut messages = Vec::new();
    pump(&mut blocks, &bytes[moldudp64::HEADER_LENGTH..], |m| {
        messages.push(m)
    })
    .unwrap();
    finish(&mut blocks, |m| messages.push(m)).unwrap();
    assert_eq!(messages, [b"c".to_vec()]);
}

#[test]
fn copied_generated_cme_module_frames_packets() {
    let packet = cme_mdp3::Packet {
        header: cme_mdp3::PacketHeader {
            sequence: 3,
            sending_time: 4,
        },
        messages: vec![
            cme_mdp3::Message::AdminHeartbeat12(cme_mdp3::AdminHeartbeat12 {}),
            cme_mdp3::Message::AdminLogin15(cme_mdp3::AdminLogin15 { heart_bt_int: 30 }),
        ],
    };
    let bytes = packet.to_bytes().unwrap();
    assert_eq!(<cme_mdp3::Packet as Wire>::parse(&bytes).unwrap(), packet);
    let mut stream = Stream::new(cme_mdp3::Frames);
    let mut messages = Vec::new();
    for chunk in bytes[cme_mdp3::PACKET_HEADER..].chunks(3) {
        pump(&mut stream, chunk, |m| messages.push(m)).unwrap();
    }
    finish(&mut stream, |m| messages.push(m)).unwrap();
    assert_eq!(messages, packet.messages);
    assert_eq!(cme_mdp3::Price9::EXPONENT, -9);
}
