//! Protocol files compiled as modules of a separate consumer crate.
//! Unit tests run in the SDK; this fixture only checks public dependencies.
#![cfg(not(test))]
#![allow(dead_code)]

// A macro keeps rustfmt from following the #[path] modules.
macro_rules! protocols {
    () => {
        #[path = "../../src/stdlib/amqp.rs"]
        pub mod amqp;
        #[path = "../../src/stdlib/codec/ascii.rs"]
        pub mod ascii;
        #[path = "../../src/stdlib/asn1.rs"]
        pub mod asn1;
        #[path = "../../src/stdlib/bacnet.rs"]
        pub mod bacnet;
        #[path = "../../src/stdlib/codec/base64.rs"]
        pub mod base64;
        #[path = "../../src/stdlib/bgp.rs"]
        pub mod bgp;
        #[path = "../../src/stdlib/codec/buffer.rs"]
        pub mod buffer;
        #[path = "../../src/stdlib/ca.rs"]
        pub mod ca;
        #[path = "../../src/stdlib/cboe_boe.rs"]
        pub mod cboe_boe;
        #[path = "../../src/stdlib/cboe_pitch.rs"]
        pub mod cboe_pitch;
        #[path = "../../src/stdlib/codec/civil.rs"]
        pub mod civil;
        #[path = "../../src/stdlib/cme_mdp3.rs"]
        pub mod cme_mdp3;
        #[path = "../../src/stdlib/coap.rs"]
        pub mod coap;
        #[path = "../../src/stdlib/codec/combinators.rs"]
        pub mod combinators;
        #[path = "../../src/stdlib/connection.rs"]
        pub mod connection;
        #[path = "../../src/stdlib/cotp.rs"]
        pub mod cotp;
        #[path = "../../src/stdlib/codec/crc32c.rs"]
        pub mod crc32c;
        #[path = "../../src/stdlib/dcerpc.rs"]
        pub mod dcerpc;
        #[path = "../../src/stdlib/codec/declarations.rs"]
        pub mod declarations;
        #[path = "../../src/stdlib/codec/demux.rs"]
        pub mod demux;
        #[path = "../../src/stdlib/dhcp.rs"]
        pub mod dhcp;
        #[path = "../../src/stdlib/dhcpv6.rs"]
        pub mod dhcpv6;
        #[path = "../../src/stdlib/diameter.rs"]
        pub mod diameter;
        #[path = "../../src/stdlib/dnp3.rs"]
        pub mod dnp3;
        #[path = "../../src/stdlib/dns.rs"]
        pub mod dns;
        #[path = "../../src/stdlib/dtls.rs"]
        pub mod dtls;
        #[path = "../../src/stdlib/enip.rs"]
        pub mod enip;
        #[path = "../../src/stdlib/fast.rs"]
        pub mod fast;
        #[path = "../../src/stdlib/fastcgi.rs"]
        pub mod fastcgi;
        #[path = "../../src/stdlib/codec/faults.rs"]
        pub mod faults;
        #[path = "../../src/stdlib/codec/field.rs"]
        pub mod field;
        #[path = "../../src/stdlib/fix.rs"]
        pub mod fix;
        #[path = "../../src/stdlib/codec/frames.rs"]
        pub mod frames;
        #[path = "../../src/stdlib/ftp.rs"]
        pub mod ftp;
        #[path = "../../codegen/tests/golden/recursive.rs"]
        pub mod generated_recursive;
        #[path = "../../src/stdlib/geneve.rs"]
        pub mod geneve;
        #[path = "../../src/stdlib/git_protocol.rs"]
        pub mod git_protocol;
        #[path = "../../src/stdlib/gre.rs"]
        pub mod gre;
        #[path = "../../src/stdlib/grpc.rs"]
        pub mod grpc;
        #[path = "../../src/stdlib/codec/head_body.rs"]
        pub mod head_body;
        #[path = "../../src/stdlib/hpack.rs"]
        pub mod hpack;
        #[path = "../../src/stdlib/http1.rs"]
        pub mod http1;
        #[path = "../../src/stdlib/http2.rs"]
        pub mod http2;
        #[path = "../../src/stdlib/http3.rs"]
        pub mod http3;
        fictionet::cfg_std! {
        #[path = "../../src/stdlib/httpd.rs"]
        pub mod httpd;
        }
        #[path = "../../src/stdlib/codec/generated.rs"]
        pub mod generated;
        #[path = "../../src/stdlib/huffman.rs"]
        pub mod huffman;
        #[path = "../../src/stdlib/icmp.rs"]
        pub mod icmp;
        #[path = "../../src/stdlib/iec104.rs"]
        pub mod iec104;
        #[path = "../../src/stdlib/igmp.rs"]
        pub mod igmp;
        #[path = "../../src/stdlib/ike.rs"]
        pub mod ike;
        #[path = "../../src/stdlib/imap.rs"]
        pub mod imap;
        #[path = "../../src/stdlib/imf.rs"]
        pub mod imf;
        #[path = "../../src/stdlib/codec/interceptor.rs"]
        pub mod interceptor;
        #[path = "../../src/stdlib/ip.rs"]
        pub mod ip;
        #[path = "../../src/stdlib/ipp.rs"]
        pub mod ipp;
        #[path = "../../src/stdlib/ipsec.rs"]
        pub mod ipsec;
        #[path = "../../src/stdlib/itch.rs"]
        pub mod itch;
        #[path = "../../src/stdlib/json.rs"]
        pub mod json;
        #[path = "../../src/stdlib/json_schema.rs"]
        pub mod json_schema;
        #[path = "../../src/stdlib/jsonrpc.rs"]
        pub mod jsonrpc;
        #[path = "../../src/stdlib/kafka.rs"]
        pub mod kafka;
        #[path = "../../src/stdlib/kerberos.rs"]
        pub mod kerberos;
        #[path = "../../src/stdlib/l2tp.rs"]
        pub mod l2tp;
        #[path = "../../src/stdlib/codec/layout.rs"]
        pub mod layout;
        #[path = "../../src/stdlib/codec/lcg.rs"]
        pub mod lcg;
        #[path = "../../src/stdlib/ldap.rs"]
        pub mod ldap;
        #[path = "../../src/stdlib/codec/leb128.rs"]
        pub mod leb128;
        #[path = "../../src/stdlib/link.rs"]
        pub mod link;
        #[path = "../../src/stdlib/memcache.rs"]
        pub mod memcache;
        #[path = "../../src/stdlib/mime_multipart.rs"]
        pub mod mime_multipart;
        #[path = "../../src/stdlib/modbus.rs"]
        pub mod modbus;
        #[path = "../../src/stdlib/moldudp64.rs"]
        pub mod moldudp64;
        #[path = "../../src/stdlib/mongodb.rs"]
        pub mod mongodb;
        #[path = "../../src/stdlib/mqtt.rs"]
        pub mod mqtt;
        #[path = "../../src/stdlib/mysql.rs"]
        pub mod mysql;
        fictionet::cfg_observe! {
        #[path = "../../src/observe/conversation.rs"]
        pub mod observe_conversation;
        }
        fictionet::cfg_observe! {
        #[path = "../../src/observe/http2.rs"]
        pub mod observe_http2;
        }
        fictionet::cfg_observe! {
        #[path = "../../src/observe/protocols.rs"]
        pub mod observe_protocols;
        }
        fictionet::cfg_observe! {
        #[path = "../../src/observe/tls.rs"]
        pub mod observe_tls;
        }
        #[path = "../../src/stdlib/codec/pipe.rs"]
        pub mod pipe;
        #[path = "../../src/stdlib/ports.rs"]
        pub mod ports;
        #[path = "../../src/stdlib/codec/reader.rs"]
        pub mod reader;
        #[path = "../../src/stdlib/codec/recorder.rs"]
        pub mod recorder;
        #[path = "../../src/stdlib/route.rs"]
        pub mod route;
        #[path = "../../src/stdlib/codec/stream.rs"]
        pub mod stream;
        #[path = "../../src/stdlib/tcp.rs"]
        pub mod tcp;
        #[path = "../../src/stdlib/test_support/mod.rs"]
        pub mod test_support;
        #[path = "../../src/stdlib/tls.rs"]
        pub mod tls;
        #[path = "../../src/stdlib/udp.rs"]
        pub mod udp;
        #[path = "../../src/stdlib/codec/work.rs"]
        pub mod work;
        // NBDGM and NBSS use the public NBNS name encoding helpers.
        #[path = "../../src/stdlib/nbdgm.rs"]
        pub mod nbdgm;
        #[path = "../../src/stdlib/nbns.rs"]
        pub mod nbns;
        #[path = "../../src/stdlib/nbss.rs"]
        pub mod nbss;
        #[path = "../../src/stdlib/net.rs"]
        pub mod net;
        #[path = "../../src/stdlib/nfs.rs"]
        pub mod nfs;
        #[path = "../../src/stdlib/ntlmssp.rs"]
        pub mod ntlmssp;
        #[path = "../../src/stdlib/ntp.rs"]
        pub mod ntp;
        #[path = "../../src/stdlib/ocsp.rs"]
        pub mod ocsp;
        #[path = "../../src/stdlib/onc_rpc.rs"]
        pub mod onc_rpc;
        #[path = "../../src/stdlib/opcua.rs"]
        pub mod opcua;
        #[path = "../../src/stdlib/openvpn.rs"]
        pub mod openvpn;
        #[path = "../../src/stdlib/ospf.rs"]
        pub mod ospf;
        #[path = "../../src/stdlib/ouch.rs"]
        pub mod ouch;
        #[path = "../../src/stdlib/pcp.rs"]
        pub mod pcp;
        #[path = "../../src/stdlib/pim.rs"]
        pub mod pim;
        #[path = "../../src/stdlib/pop3.rs"]
        pub mod pop3;
        #[path = "../../src/stdlib/portmap.rs"]
        pub mod portmap;
        #[path = "../../src/stdlib/postgres.rs"]
        pub mod postgres;
        #[path = "../../src/stdlib/prefix_int.rs"]
        pub mod prefix_int;
        #[path = "../../src/stdlib/protobuf.rs"]
        pub mod protobuf;
        #[path = "../../src/stdlib/proxy_protocol.rs"]
        pub mod proxy_protocol;
        #[path = "../../src/stdlib/qpack.rs"]
        pub mod qpack;
        #[path = "../../src/stdlib/quic.rs"]
        pub mod quic;
        #[path = "../../src/stdlib/radius.rs"]
        pub mod radius;
        #[path = "../../src/stdlib/rdp.rs"]
        pub mod rdp;
        #[path = "../../src/stdlib/resp.rs"]
        pub mod resp;
        #[path = "../../src/stdlib/rfb.rs"]
        pub mod rfb;
        #[path = "../../src/stdlib/rip.rs"]
        pub mod rip;
        #[path = "../../src/stdlib/rtcp.rs"]
        pub mod rtcp;
        #[path = "../../src/stdlib/rtp.rs"]
        pub mod rtp;
        #[path = "../../src/stdlib/rtsp.rs"]
        pub mod rtsp;
        #[path = "../../src/stdlib/sandbox.rs"]
        pub mod sandbox;
        #[path = "../../src/stdlib/sbe.rs"]
        pub mod sbe;
        #[path = "../../src/stdlib/sdp.rs"]
        pub mod sdp;
        #[path = "../../src/stdlib/serve.rs"]
        pub mod serve;
        #[path = "../../src/stdlib/session.rs"]
        pub mod session;
        #[path = "../../src/stdlib/sftp.rs"]
        pub mod sftp;
        #[path = "../../src/stdlib/sip.rs"]
        pub mod sip;
        #[path = "../../src/stdlib/smb2.rs"]
        pub mod smb2;
        #[path = "../../src/stdlib/smtp.rs"]
        pub mod smtp;
        // SNMP uses the public ASN.1 integer and length helpers.
        #[path = "../../src/stdlib/snmp.rs"]
        pub mod snmp;
        #[path = "../../src/stdlib/socks.rs"]
        pub mod socks;
        #[path = "../../src/stdlib/soupbintcp.rs"]
        pub mod soupbintcp;
        #[path = "../../src/stdlib/spnego.rs"]
        pub mod spnego;
        #[path = "../../src/stdlib/sse.rs"]
        pub mod sse;
        #[path = "../../src/stdlib/ssh.rs"]
        pub mod ssh;
        #[path = "../../src/stdlib/stun.rs"]
        pub mod stun;
        #[path = "../../src/stdlib/syslog.rs"]
        pub mod syslog;
        #[path = "../../src/stdlib/tcp_reassembly.rs"]
        pub mod tcp_reassembly;
        #[path = "../../src/stdlib/tds.rs"]
        pub mod tds;
        #[path = "../../src/stdlib/telnet.rs"]
        pub mod telnet;
        #[path = "../../src/stdlib/tftp.rs"]
        pub mod tftp;
        #[path = "../../src/stdlib/thrift.rs"]
        pub mod thrift;
        #[path = "../../src/stdlib/tpkt.rs"]
        pub mod tpkt;
        #[path = "../../src/stdlib/urlencoded_form.rs"]
        pub mod urlencoded_form;
        #[path = "../../src/stdlib/vrrp.rs"]
        pub mod vrrp;
        #[path = "../../src/stdlib/vxlan.rs"]
        pub mod vxlan;
        #[path = "../../src/stdlib/wake_on_lan.rs"]
        pub mod wake_on_lan;
        fictionet::cfg_std! {
        #[path = "../../src/stdlib/web.rs"]
        pub mod web;
        }
        #[path = "../../src/stdlib/websocket.rs"]
        pub mod websocket;
        #[path = "../../src/stdlib/whois.rs"]
        pub mod whois;
        #[path = "../../src/stdlib/wireguard.rs"]
        pub mod wireguard;
        #[path = "../../src/stdlib/x509.rs"]
        pub mod x509;
        #[path = "../../src/stdlib/xml.rs"]
        pub mod xml;
        #[path = "../../src/stdlib/zabbix.rs"]
        pub mod zabbix;
    };
}

protocols!();

// These are the copied types, so their Prefixed impls must use public APIs.
fn copied_frames() {
    use fictionet::stdlib::codec::{Decode, Frames, Prefixed};
    fn check<T: Prefixed>(_decoder: Frames<T>)
    where
        Frames<T>: Decode,
    {
    }
    check(Frames::<modbus::Frame>::new());
    check(Frames::<kerberos::Frame>::new());
    check(Frames::<stun::Frame>::new());
    check(Frames::<ocsp::Frame>::new());
    check(Frames::<spnego::Frame>::new());
    check(Frames::<diameter::Message>::with_limit(1024));
    check(Frames::<opcua::Chunk>::with_limit(opcua::Limits::default()));
    check(Frames::<cboe_boe::Inbound>::new());
}

// Copied transports must enter the SDK's serving drivers.
fn copied_transports<S, M>(
    fcx: &fictionet::Cx,
    listener: tcp::Listener,
    socket: udp::Socket,
    local: std::net::SocketAddr,
    service: &mut S,
    state: std::sync::Arc<S::State>,
    make: M,
) where
    S: fictionet::stdlib::serve::Service,
    M: Fn() -> S + Send + Sync + 'static,
    <S::Decoder as fictionet::stdlib::codec::Decode>::Error: Clone + Send,
{
    use fictionet::stdlib::serve::{ServeOptions, datagram, listen};
    let opts = ServeOptions::default();
    listen(fcx, listener, state.clone(), make, opts.clone());
    fn send_future(_: impl std::future::Future + Send) {}
    send_future(datagram(fcx, socket, local, service, &state, &opts));
}

// A copied TCP connection also enters the connection and TLS drivers directly.
fn copied_connection<S>(
    fcx: &fictionet::Cx,
    conn: tcp::TcpConnection,
    info: fictionet::events::ConnInfo,
    service: &mut S,
    state: &S::State,
) where
    S: fictionet::stdlib::serve::Service,
    <S::Decoder as fictionet::stdlib::codec::Decode>::Error: Clone + Send,
{
    use fictionet::stdlib::serve::{ServeOptions, connection};
    drop(connection(
        fcx,
        conn,
        info,
        service,
        state,
        &ServeOptions::default(),
    ));
}

fn copied_tls(fcx: &fictionet::Cx, conn: tcp::TcpConnection) {
    drop(fictionet::stdlib::tls::server(fcx, conn));
}

fn copied_tls_server(fcx: &fictionet::Cx, conn: tcp::TcpConnection) {
    drop(tls::server(fcx, conn));
}

fn copied_router<I: fictionet::Interface>(fcx: &fictionet::Cx, interface: I) {
    let _ = route::router(fcx, vec![("10.0.0.0/24".parse().unwrap(), interface)]);
}

// Copied faults accept either the run capability or a public standalone source.
fn copied_entropy(fcx: &fictionet::Cx) {
    let seed = fictionet::Seed::from_u64(7);
    let source = fictionet::SeededEntropy::new(seed);
    fictionet::cfg_std! {
    let conn = fictionet::events::ConnInfo::default();
    let mut exchange = httpd::Exchange::new(fcx.now(), &source, &conn);
    let _ = exchange.random_u64();
    let _ = httpd::UpgradeHandler::new(|_fcx, _conn| async {});
    }
    let mut faults = faults::Faults::new(64, 0);
    let plan = [faults::Rule {
        when: faults::Trigger::Always,
        fault: faults::ByteFault::Corrupt {
            offset: None,
            xor: 1,
        },
    }];
    faults
        .bytes(fcx, &plan, b"copied", &mut Vec::new())
        .unwrap();
    faults
        .bytes(&source, &plan, b"copied", &mut Vec::new())
        .unwrap();
}

// Copied network drivers and proxy builders use only public run capabilities.
fn copied_clock(fcx: &fictionet::Cx, cx: &mut std::task::Context<'_>) {
    let mut timer = fictionet::Timer::new(fcx);
    let _ = timer.poll_until(cx, fcx.now());
    timer.clear();
    let _ = fcx.mode();
    let _ = fcx.require_real_io();
    copied_client_config(fcx, std::time::SystemTime::UNIX_EPOCH);
    copied_mutex();
    copied_step_and_buffer();
    fictionet::cfg_observe! {
    copied_previews();
    }
    copied_assert_cases();
}

#[allow(dead_code)]
fn copied_connection_limit(fcx: &fictionet::Cx, info: &fictionet::events::ConnInfo) {
    let open = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _guard = net::connection_limit(fcx, info, &open, 1);
}

// The serving driver gives deferred work a child cancellation region.
fn copied_serve_region(fcx: &fictionet::Cx) {
    drop(fcx.region(|child| async move {
        child.cancel();
        Ok(())
    }));
}

fn copied_client_config(fcx: &fictionet::Cx, start: std::time::SystemTime) {
    let _: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVersions> =
        fictionet::stdlib::tls::client_config_builder(fcx, start);
    let _ = sandbox::client_config(fcx, start, None, &[]).unwrap();
}

fn copied_mutex() {
    let value = fictionet::sync::Mutex::new(1);
    let mut guard: fictionet::sync::MutexGuard<'_, i32> = value.lock();
    *guard += 1;
}

fn copied_step_and_buffer() {
    let _: fictionet::stdlib::codec::Step<u64> =
        fictionet::stdlib::codec::Step::Item(1u8, 1).map(u64::from);
    let mut buffer = fictionet::stdlib::codec::Buffer::new(16 * 1024);
    buffer.spare()[0] = 42;
    buffer.commit(1);
    assert_eq!(buffer.unread(), &[42]);
    buffer.consume(1);
}

fictionet::cfg_observe! {
fn copied_previews() {
    assert_eq!(fictionet::observe::hex(&[0, 255]), "00ff");
    assert_eq!(fictionet::observe::protocols::body_preview(b"hello"), Some("hello".into()));
}
}

fn copied_assert_cases() {
    fictionet::assert_cases! {
        <vxlan::Packet as fictionet::stdlib::codec::Wire>::parse;
        (&[]) => Err(vxlan::Error::Truncated(0)),
        (&[0; 7]) => Err(vxlan::Error::Truncated(7)),
    }
}
