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
    use fictionet::events::Transport;
    use fictionet::observe::{Decoded, Layer, Match, Observed, Place, Present, Registry, Selection};
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
fn copied_itch_frames_a_file_and_builds_a_book() {
    // ITCH 5.0, 1.3.1: Add Order, then 1.4.1: Order Executed, each with a
    // two-byte length in front as in a binary ITCH file.
    let header = itch::Header {
        locate: 3,
        tracking: 0,
        timestamp: itch::Timestamp::new(1).unwrap(),
    };
    let add = itch::AddOrder {
        header,
        order_ref: 5,
        side: itch::Side::Sell,
        shares: 100,
        stock: itch::Alpha::right_padded("ZVZZT").unwrap(),
        price: itch::Price4(10_000),
    };
    let executed = itch::OrderExecuted {
        header,
        order_ref: 5,
        executed_shares: 40,
        match_number: 1,
    };
    let mut file = Vec::new();
    for m in [itch::Message::from(add), executed.into()] {
        file.extend_from_slice(&(m.wire_len() as u16).to_be_bytes());
        m.write(&mut file).unwrap();
    }
    let mut stream = Stream::new(itch::Messages::default());
    let mut book = itch::Book::new(itch::BookConfig::default()).unwrap();
    for chunk in file.chunks(7) {
        pump(&mut stream, chunk, |m| {
            book.apply(&m.unwrap()).unwrap();
        })
        .unwrap();
    }
    finish(&mut stream, |_| unreachable!()).unwrap();
    assert_eq!(book.best_ask(3).unwrap().shares, 60);
}

#[test]
fn copied_ouch_exchange_accepts_through_wire() {
    let enter = ouch::EnterOrder {
        user_ref: 1,
        side: ouch::Side::Buy,
        quantity: 10,
        symbol: ouch::Alpha::right_padded("ZVZZT").unwrap(),
        price: ouch::Price(10_000),
        time_in_force: b'0',
        display: b'Y',
        capacity: b'A',
        intermarket_sweep: b'N',
        cross_type: b'N',
        cl_ord_id: ouch::Alpha::right_padded("A1").unwrap(),
        options: ouch::Options::default(),
    };
    let bytes = enter.to_bytes().unwrap();
    let inbound = <ouch::Inbound as Wire>::parse(&bytes).unwrap();
    let mut exchange = ouch::Exchange::new(ouch::ExchangeConfig::default()).unwrap();
    let token = ouch::Token {
        user_ref_idx: 0,
        user_ref: 1,
    };
    assert_eq!(
        exchange.receive(&inbound, 0).unwrap(),
        [ouch::Action::Event(ouch::Event::EnterRequested(token))]
    );
    let accepted = exchange.accept(token, 1).unwrap().to_bytes().unwrap();
    assert!(matches!(
        <ouch::Outbound as Wire>::parse(&accepted),
        Ok(ouch::Outbound::OrderAccepted(_))
    ));
}

#[test]
fn copied_cboe_pitch_frames_units_and_builds_a_book() {
    // Cboe Multicast PITCH, "Sequenced Unit Header with 2 Messages": an
    // Add Order (short) and a Reduce Size (short) on unit 1.
    let add = cboe_pitch::AddOrderShort {
        time_offset: 447_000,
        order_id: 5,
        side: cboe_pitch::Side::Buy,
        quantity: 737,
        symbol: cboe_pitch::Alpha::right_padded("ZVZZT").unwrap(),
        price: cboe_pitch::ShortPrice(1),
        flags: 1,
        extra: Vec::new(),
    };
    let reduce = cboe_pitch::ReduceSizeShort {
        time_offset: 449_000,
        order_id: 5,
        canceled_quantity: 700,
        extra: Vec::new(),
    };
    let unit = cboe_pitch::Unit::of(1, 1, &[add.into(), reduce.into()]).unwrap();
    let bytes = unit.to_bytes().unwrap();
    assert_eq!(bytes.len(), 50);
    let mut stream = Stream::new(cboe_pitch::Units::default());
    let mut book = cboe_pitch::Book::new(cboe_pitch::BookConfig::default()).unwrap();
    let mut gaps = cboe_pitch::GapDetector::new();
    for chunk in bytes.chunks(7) {
        pump(&mut stream, chunk, |u| {
            let u = u.unwrap();
            let seen = gaps.receive(&u);
            for m in &u.messages[seen.skip..] {
                book.apply(u.unit, &<cboe_pitch::Message as Wire>::parse(m).unwrap())
                    .unwrap();
            }
        })
        .unwrap();
    }
    finish(&mut stream, |_| unreachable!()).unwrap();
    let symbol = cboe_pitch::Alpha::right_padded("ZVZZT").unwrap();
    assert_eq!(book.best_bid(symbol).unwrap().quantity, 37);
    assert_eq!(gaps.expected(1), Some(3));
}

#[test]
fn copied_cboe_boe_logs_in_and_acknowledges() {
    use cboe_boe::{Action, Event, OrderEvent, Text};
    let config = cboe_boe::ClientConfig {
        session_sub_id: Text::new("0001").unwrap(),
        username: Text::new("TEST").unwrap(),
        password: Text::new("TESTING").unwrap(),
        no_unspecified_unit_replay: false,
        returns: vec![(0x25, vec![0, 0x40])],
        timers: cboe_boe::Timers::default(),
    };
    let mut client = cboe_boe::Client::new(config, &[], 0).unwrap();
    let mut server = cboe_boe::Server::new(cboe_boe::Timers::default(), 0).unwrap();
    let mut frames = Stream::new(cboe_boe::Frames::<cboe_boe::Inbound>::default());
    for action in client.start(0).unwrap() {
        if let Action::Send(m) = action {
            let bytes = m.to_bytes().unwrap();
            assert_eq!(frames.push(&bytes), bytes.len());
        }
    }
    let login = frames.next().unwrap().unwrap().unwrap();
    assert!(matches!(
        &server.receive(&login, 1).unwrap()[..],
        [Action::Event(Event::LoginRequested(_))]
    ));
    for action in server.accept(0, &[], 2).unwrap() {
        if let Action::Send(m) = action {
            client.receive(&m, 3).unwrap();
        }
    }
    let order = cboe_boe::NewOrder {
        header: cboe_boe::Header::default(),
        cl_ord_id: Text::new("A1").unwrap(),
        side: b'2',
        order_qty: 10,
        fields: cboe_boe::Optional::new()
            .with(cboe_boe::Opt::Price("1.5".parse().unwrap()))
            .unwrap()
            .with(cboe_boe::Opt::Symbol(Text::new("ZVZZT").unwrap()))
            .unwrap()
            .with(cboe_boe::Opt::Capacity(b'A'))
            .unwrap(),
    };
    let sent = client.send(order.into(), 4).unwrap();
    let parsed = <cboe_boe::Inbound as Wire>::parse(&sent.to_bytes().unwrap()).unwrap();
    assert_eq!(
        server.receive(&parsed, 5).unwrap(),
        [Action::Event(Event::Application)]
    );
    let mut exchange = cboe_boe::Exchange::new(
        cboe_boe::ExchangeConfig::default(),
        server.returns().clone(),
    )
    .unwrap();
    let id = Text::new("A1").unwrap();
    assert_eq!(
        exchange.receive(&parsed, 6),
        [Action::Event(OrderEvent::NewOrderRequested(id))]
    );
    let ack = server.send(exchange.accept(id, 2, 7).unwrap(), 7).unwrap();
    let back = <cboe_boe::Outbound as Wire>::parse(&ack.to_bytes().unwrap()).unwrap();
    let cboe_boe::Outbound::OrderAcknowledgment(a) = &back else {
        panic!("{back:?}")
    };
    assert_eq!((a.header.unit, a.header.sequence), (2, 1));
    assert_eq!(a.fields.fields(), [cboe_boe::Opt::Capacity(b'A')]);
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
