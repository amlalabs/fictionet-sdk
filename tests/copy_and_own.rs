//! Compile every protocol file as code owned by a consumer crate.
//!
//! The dev dependency in `tests/copy_and_own/Cargo.toml` uses this same file
//! as its library. That build has no `cfg(test)`, so the copied modules' unit
//! tests are compiled out. The SDK already runs them in `cargo test --lib`;
//! running their parser and fuzz loops again would nearly double that work.
//! This integration target runs only the public-trait checks below.

#![allow(dead_code)]

#[cfg(not(test))]
macro_rules! protocols {
    () => {
        #[path = "../src/stdlib/amqp.rs"]
        pub mod amqp;
        #[path = "../src/stdlib/asn1.rs"]
        pub mod asn1;
        #[path = "../src/stdlib/bacnet.rs"]
        pub mod bacnet;
        #[path = "../src/stdlib/bgp.rs"]
        pub mod bgp;
        #[path = "../src/stdlib/cboe_boe.rs"]
        pub mod cboe_boe;
        #[path = "../src/stdlib/cboe_pitch.rs"]
        pub mod cboe_pitch;
        #[path = "../src/stdlib/coap.rs"]
        pub mod coap;
        #[path = "../src/stdlib/cotp.rs"]
        pub mod cotp;
        #[path = "../src/stdlib/dcerpc.rs"]
        pub mod dcerpc;
        #[path = "../src/stdlib/dhcp.rs"]
        pub mod dhcp;
        #[path = "../src/stdlib/dhcpv6.rs"]
        pub mod dhcpv6;
        #[path = "../src/stdlib/diameter.rs"]
        pub mod diameter;
        #[path = "../src/stdlib/dnp3.rs"]
        pub mod dnp3;
        #[path = "../src/stdlib/dtls.rs"]
        pub mod dtls;
        #[path = "../src/stdlib/enip.rs"]
        pub mod enip;
        #[path = "../src/stdlib/fastcgi.rs"]
        pub mod fastcgi;
        #[path = "../src/stdlib/ftp.rs"]
        pub mod ftp;
        #[path = "../src/stdlib/geneve.rs"]
        pub mod geneve;
        #[path = "../src/stdlib/git_protocol.rs"]
        pub mod git_protocol;
        #[path = "../src/stdlib/gre.rs"]
        pub mod gre;
        #[path = "../src/stdlib/grpc.rs"]
        pub mod grpc;
        #[path = "../src/stdlib/http3.rs"]
        pub mod http3;
        #[path = "../src/stdlib/iec104.rs"]
        pub mod iec104;
        #[path = "../src/stdlib/igmp.rs"]
        pub mod igmp;
        #[path = "../src/stdlib/ike.rs"]
        pub mod ike;
        #[path = "../src/stdlib/imap.rs"]
        pub mod imap;
        #[path = "../src/stdlib/imf.rs"]
        pub mod imf;
        #[path = "../src/stdlib/ipp.rs"]
        pub mod ipp;
        #[path = "../src/stdlib/ipsec.rs"]
        pub mod ipsec;
        #[path = "../src/stdlib/itch.rs"]
        pub mod itch;
        #[path = "../src/stdlib/json.rs"]
        pub mod json;
        #[path = "../src/stdlib/kafka.rs"]
        pub mod kafka;
        #[path = "../src/stdlib/kerberos.rs"]
        pub mod kerberos;
        #[path = "../src/stdlib/l2tp.rs"]
        pub mod l2tp;
        #[path = "../src/stdlib/ldap.rs"]
        pub mod ldap;
        #[path = "../src/stdlib/memcache.rs"]
        pub mod memcache;
        #[path = "../src/stdlib/mime_multipart.rs"]
        pub mod mime_multipart;
        #[path = "../src/stdlib/modbus.rs"]
        pub mod modbus;
        #[path = "../src/stdlib/moldudp64.rs"]
        pub mod moldudp64;
        #[path = "../src/stdlib/mongodb.rs"]
        pub mod mongodb;
        #[path = "../src/stdlib/mqtt.rs"]
        pub mod mqtt;
        #[path = "../src/stdlib/mysql.rs"]
        pub mod mysql;
        #[path = "../src/stdlib/nbdgm.rs"]
        pub mod nbdgm;
        #[path = "../src/stdlib/nbns.rs"]
        pub mod nbns;
        #[path = "../src/stdlib/nbss.rs"]
        pub mod nbss;
        #[path = "../src/stdlib/nfs.rs"]
        pub mod nfs;
        #[path = "../src/stdlib/ntlmssp.rs"]
        pub mod ntlmssp;
        #[path = "../src/stdlib/ntp.rs"]
        pub mod ntp;
        #[path = "../src/stdlib/ocsp.rs"]
        pub mod ocsp;
        #[path = "../src/stdlib/onc_rpc.rs"]
        pub mod onc_rpc;
        #[path = "../src/stdlib/opcua.rs"]
        pub mod opcua;
        #[path = "../src/stdlib/openvpn.rs"]
        pub mod openvpn;
        #[path = "../src/stdlib/ospf.rs"]
        pub mod ospf;
        #[path = "../src/stdlib/ouch.rs"]
        pub mod ouch;
        #[path = "../src/stdlib/pcp.rs"]
        pub mod pcp;
        #[path = "../src/stdlib/pim.rs"]
        pub mod pim;
        #[path = "../src/stdlib/pop3.rs"]
        pub mod pop3;
        #[path = "../src/stdlib/portmap.rs"]
        pub mod portmap;
        #[path = "../src/stdlib/postgres.rs"]
        pub mod postgres;
        #[path = "../src/stdlib/protobuf.rs"]
        pub mod protobuf;
        #[path = "../src/stdlib/proxy_protocol.rs"]
        pub mod proxy_protocol;
        #[path = "../src/stdlib/qpack.rs"]
        pub mod qpack;
        #[path = "../src/stdlib/quic.rs"]
        pub mod quic;
        #[path = "../src/stdlib/radius.rs"]
        pub mod radius;
        #[path = "../src/stdlib/rdp.rs"]
        pub mod rdp;
        #[path = "../src/stdlib/resp.rs"]
        pub mod resp;
        #[path = "../src/stdlib/rfb.rs"]
        pub mod rfb;
        #[path = "../src/stdlib/rip.rs"]
        pub mod rip;
        #[path = "../src/stdlib/rtcp.rs"]
        pub mod rtcp;
        #[path = "../src/stdlib/rtp.rs"]
        pub mod rtp;
        #[path = "../src/stdlib/rtsp.rs"]
        pub mod rtsp;
        #[path = "../src/stdlib/sdp.rs"]
        pub mod sdp;
        #[path = "../src/stdlib/sftp.rs"]
        pub mod sftp;
        #[path = "../src/stdlib/sip.rs"]
        pub mod sip;
        #[path = "../src/stdlib/smb2.rs"]
        pub mod smb2;
        #[path = "../src/stdlib/smtp.rs"]
        pub mod smtp;
        #[path = "../src/stdlib/snmp.rs"]
        pub mod snmp;
        #[path = "../src/stdlib/socks.rs"]
        pub mod socks;
        #[path = "../src/stdlib/soupbintcp.rs"]
        pub mod soupbintcp;
        #[path = "../src/stdlib/spnego.rs"]
        pub mod spnego;
        #[path = "../src/stdlib/ssh.rs"]
        pub mod ssh;
        #[path = "../src/stdlib/stun.rs"]
        pub mod stun;
        #[path = "../src/stdlib/syslog.rs"]
        pub mod syslog;
        #[path = "../src/stdlib/tds.rs"]
        pub mod tds;
        #[path = "../src/stdlib/telnet.rs"]
        pub mod telnet;
        #[path = "../src/stdlib/tftp.rs"]
        pub mod tftp;
        #[path = "../src/stdlib/thrift.rs"]
        pub mod thrift;
        #[path = "../src/stdlib/tpkt.rs"]
        pub mod tpkt;
        #[path = "../src/stdlib/urlencoded_form.rs"]
        pub mod urlencoded_form;
        #[path = "../src/stdlib/vrrp.rs"]
        pub mod vrrp;
        #[path = "../src/stdlib/vxlan.rs"]
        pub mod vxlan;
        #[path = "../src/stdlib/wake_on_lan.rs"]
        pub mod wake_on_lan;
        #[path = "../src/stdlib/websocket.rs"]
        pub mod websocket;
        #[path = "../src/stdlib/whois.rs"]
        pub mod whois;
        #[path = "../src/stdlib/wireguard.rs"]
        pub mod wireguard;
        #[path = "../src/stdlib/x509.rs"]
        pub mod x509;
        #[path = "../src/stdlib/xml.rs"]
        pub mod xml;
        #[path = "../src/stdlib/zabbix.rs"]
        pub mod zabbix;
    };
}

#[cfg(not(test))]
protocols!();

#[cfg(test)]
use fictionet::stdlib::codec::{Decode, Stream, Wire, finish, pump};
#[cfg(test)]
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
        exchange.receive(&inbound, 0),
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
