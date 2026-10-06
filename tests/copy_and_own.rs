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
        #[path = "../src/observe/protocols.rs"]
        pub mod observe_protocols;
        #[path = "../src/observe/tls.rs"]
        pub mod observe_tls;
        #[path = "../src/observe/conversation.rs"]
        pub mod observe_conversation;
        #[path = "../src/stdlib/amqp.rs"]
        pub mod amqp;
        #[path = "../src/stdlib/asn1.rs"]
        pub mod asn1;
        #[path = "../src/stdlib/bacnet.rs"]
        pub mod bacnet;
        #[path = "../src/stdlib/bgp.rs"]
        pub mod bgp;
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
        #[path = "../src/stdlib/hpack.rs"]
        pub mod hpack;
        #[path = "../src/stdlib/huffman.rs"]
        pub mod huffman;
        #[path = "../src/stdlib/http2.rs"]
        pub mod http2;
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
        #[path = "../src/stdlib/json.rs"]
        pub mod json;
        #[path = "../src/stdlib/json_schema.rs"]
        pub mod json_schema;
        #[path = "../src/stdlib/jsonrpc.rs"]
        pub mod jsonrpc;
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
        #[path = "../src/stdlib/prefix_int.rs"]
        pub mod prefix_int;
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
        #[path = "../src/stdlib/spnego.rs"]
        pub mod spnego;
        #[path = "../src/stdlib/ssh.rs"]
        pub mod ssh;
        #[path = "../src/stdlib/sse.rs"]
        pub mod sse;
        #[path = "../src/stdlib/stun.rs"]
        pub mod stun;
        #[path = "../src/stdlib/syslog.rs"]
        pub mod syslog;
        #[path = "../src/stdlib/tcp_stream.rs"]
        pub mod tcp_stream;
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
