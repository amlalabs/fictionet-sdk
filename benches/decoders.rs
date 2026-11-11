use divan::{
    Bencher, black_box,
    counter::{BytesCount, ItemsCount},
};
use fictionet::stdlib::codec::{Decode, Frames, Stream, Wire, finish, pump};
use fictionet::stdlib::protocols::{http1, itch, tpkt};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

fn decode<D: Decode>(
    bencher: Bencher,
    frame: &[u8],
    make: impl Fn() -> D,
    mut consume: impl FnMut(D::Item),
) where
    D::Error: Clone + std::fmt::Debug,
{
    let count = (4 * 1024 * 1024_usize).div_ceil(frame.len());
    let input = frame.repeat(count);
    bencher
        .counter(BytesCount::new(input.len()))
        .counter(ItemsCount::new(count))
        .bench_local(|| {
            let mut stream = Stream::new(make());
            let mut decoded = 0;
            let mut on = |item| {
                consume(item);
                decoded += 1;
            };
            for chunk in black_box(&input).chunks(16 * 1024) {
                assert_eq!(pump(&mut stream, chunk, &mut on).unwrap(), chunk.len());
            }
            finish(&mut stream, &mut on).unwrap();
            assert_eq!(decoded, count);
            assert_eq!(stream.buffered(), 0);
        });
}

#[divan::bench]
fn tpkt_cotp(bencher: Bencher) {
    let mut payload = vec![2, 0xf0, 0x80];
    payload.extend_from_slice(&[0x42; 128]);
    let packet = tpkt::Packet::new(payload).to_bytes().unwrap();
    decode(bencher, &packet, Frames::<tpkt::Packet>::new, |item| {
        black_box(item);
    });
}

#[divan::bench]
fn http1_requests(bencher: Bencher) {
    let request =
        b"POST /orders HTTP/1.1\r\nHost: bench.local\r\nContent-Length: 16\r\n\r\n0123456789abcdef";
    decode(bencher, request, http1::Requests::new, |item| {
        black_box(item);
    });
}

#[divan::bench]
fn itch_add_orders(bencher: Bencher) {
    let order = itch::AddOrder {
        header: itch::Header {
            locate: 7,
            tracking: 0,
            timestamp: itch::Timestamp::new(34_200_000_000_000).unwrap(),
        },
        order_ref: 1,
        side: itch::Side::Buy,
        shares: 300,
        stock: fictionet::stdlib::codec::field::Alpha::right_padded("ZXZZT").unwrap(),
        price: itch::Price4(102_500),
    }
    .to_bytes()
    .unwrap();
    let mut message = (order.len() as u16).to_be_bytes().to_vec();
    message.extend_from_slice(&order);

    decode(
        bencher,
        &message,
        Frames::<itch::Message>::default,
        |item| {
            black_box(item.unwrap());
        },
    );
}

fn drain<D: Decode>(make: impl FnOnce() -> D, input: &[u8], chunk: usize) -> usize
where
    D::Error: Clone + std::fmt::Debug,
{
    drain_stream(Stream::new(make()), input, chunk)
}

fn drain_stream<D: Decode>(mut stream: Stream<D>, input: &[u8], chunk: usize) -> usize
where
    D::Error: Clone + std::fmt::Debug,
{
    let mut items = 0;
    for bytes in black_box(input).chunks(chunk.max(1)) {
        pump(&mut stream, bytes, |item| {
            black_box(item);
            items += 1;
        })
        .unwrap();
    }
    finish(&mut stream, |item| {
        black_box(item);
        items += 1;
    })
    .unwrap();
    assert_eq!(stream.buffered(), 0);
    items
}

macro_rules! repeated {
    ($name:ident, $small:expr, $make:expr, $frame:expr) => {
        #[divan::bench(args = [$small, 4 * $small])]
        fn $name(bencher: Bencher, count: usize) {
            let input = $frame.repeat(count);
            bencher
                .counter(BytesCount::new(input.len()))
                .bench_local(|| drain($make, &input, input.len()));
        }
    };
}

use fictionet::stdlib::protocols::{
    amqp, asn1, bgp, coap, dcerpc, diameter, enip, fastcgi, ftp, git_protocol, ipp, json, jsonrpc,
    kafka, kerberos, ldap, memcache, mime_multipart, modbus, mongodb, mqtt, nbss, onc_rpc, opcua,
    openvpn, pop3, protobuf, proxy_protocol, qpack, quic, radius, resp, rtcp, rtsp, sftp, sip,
    smb2, snmp, socks, ssh, syslog, tds, thrift, websocket, x509, xml, zabbix,
};

repeated!(
    amqp_frames,
    50_000,
    amqp::Frames::new,
    amqp::Frame::heartbeat().to_bytes().unwrap()
);
repeated!(
    asn1_elements,
    asn1::MAX_INPUT / 8,
    || asn1::Elements::new(asn1::Rules::Der),
    [0x05, 0x00]
);
repeated!(
    bgp_frames,
    50_000,
    Frames::<bgp::Frame>::new,
    [vec![0xff; 16], vec![0, 19, 4]].concat()
);
repeated!(
    coap_frames,
    50_000,
    Frames::<coap::Frame>::new,
    coap::Frame {
        token: vec![1],
        ..coap::Frame::new(coap::Code::PING)
    }
    .to_bytes()
    .unwrap()
);
repeated!(
    cotp_packets,
    50_000,
    Frames::<tpkt::Packet>::new,
    tpkt::Packet::new(vec![2, 0xf0, 0x80, 1])
        .to_bytes()
        .unwrap()
);
repeated!(
    dcerpc_pdus,
    50_000,
    Frames::<dcerpc::Pdu>::new,
    dcerpc::Pdu::new(1, dcerpc::Body::Shutdown)
        .to_bytes()
        .unwrap()
);
repeated!(
    diameter_messages,
    50_000,
    Frames::<diameter::Message>::new,
    diameter::Message::request(diameter::command::DEVICE_WATCHDOG, 0, 1, 1)
        .to_bytes()
        .unwrap()
);
repeated!(
    enip_packets,
    50_000,
    Frames::<enip::Packet>::new,
    enip::Packet {
        command: enip::Command::Nop,
        session_handle: 0,
        status: 0,
        sender_context: [0; 8],
        options: 0,
        data: vec![]
    }
    .to_bytes()
    .unwrap()
);

repeated!(ftp_commands, 125_000, ftp::Commands::new, b"NOOP\r\n");
repeated!(ftp_replies, 125_000, ftp::Replies::new, b"200 ok\r\n");
repeated!(
    git_packets,
    50_000,
    Frames::<git_protocol::Packet>::new,
    b"0009done\n"
);
repeated!(json_values, json::MAX_SIZE / 16, json::Values::new, b"0\n");
repeated!(
    kafka_frames,
    50_000,
    Frames::<kafka::Frame>::new,
    kafka::Frame(vec![0, 18, 0, 0, 0, 0, 0, 1, 0xff, 0xff])
        .to_bytes()
        .unwrap()
);
repeated!(
    ldap_messages,
    50_000,
    Frames::<ldap::Message>::new,
    [0x30, 5, 2, 1, 1, 0x42, 0]
);
repeated!(
    memcache_commands,
    6_250,
    memcache::Commands::new,
    b"get key\r\nset key 0 0 1\r\nx\r\n"
);
repeated!(
    memcache_long_lines,
    5,
    memcache::Commands::new,
    [vec![b' '; memcache::MAX_LINE - 3], b"\r\n".to_vec()].concat()
);
repeated!(
    modbus_frames,
    50_000,
    Frames::<modbus::Frame>::new,
    modbus::Frame {
        transaction: 1,
        unit: 1,
        pdu: vec![3, 0, 0, 0, 1]
    }
    .to_bytes()
    .unwrap()
);
repeated!(
    mqtt_packets,
    1 << 19,
    Frames::<mqtt::Packet>::new,
    [0xc0, 0]
);
repeated!(
    nbss_packets,
    50_000,
    Frames::<nbss::Packet>::new,
    nbss::Packet::KeepAlive.to_bytes().unwrap()
);

repeated!(
    openvpn_packets,
    50_000,
    Frames::<openvpn::Frame>::new,
    openvpn::Frame(vec![0x30, 1]).to_bytes().unwrap()
);
repeated!(pop3_lines, 12_500, pop3::Inputs::new, b"NOOP\r\n");
repeated!(
    protobuf_frames,
    protobuf::MAX_MESSAGE / 64,
    Frames::<protobuf::Frame>::new,
    [0]
);
repeated!(
    radius_packets,
    25_000,
    Frames::<radius::Packet>::new,
    radius::Packet::new(radius::Code::StatusServer, 1, [0; 16])
        .to_bytes()
        .unwrap()
);
repeated!(
    rtp_frames,
    50_000,
    Frames::<rtcp::Frame>::new,
    rtcp::Frame(vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        .to_bytes()
        .unwrap()
);
repeated!(
    rtsp_items,
    12_500,
    rtsp::Frames::new,
    b"OPTIONS rtsp://example.com/ RTSP/1.0\r\nCSeq: 1\r\n\r\n$\0\0\x01x"
);
repeated!(
    sftp_packets,
    50_000,
    Frames::<sftp::Packet>::new,
    sftp::Request::Readdir {
        id: 1,
        handle: b"d".to_vec()
    }
    .to_bytes()
    .unwrap()
);
repeated!(
    sip_messages,
    12_500,
    sip::Messages::new,
    b"\r\nOPTIONS sip:a@b SIP/2.0\r\nl: 1\r\n\r\nx"
);
repeated!(
    smb2_frames,
    50_000,
    Frames::<smb2::Frame>::new,
    smb2::Frame {
        payload: b"\xffSMB".to_vec()
    }
    .to_bytes()
    .unwrap()
);
repeated!(
    snmp_messages,
    500_000,
    Frames::<snmp::Message>::new,
    [0x30, 0]
);
repeated!(
    ssh_packets,
    100_000,
    ssh::Events::after_version,
    ssh::Packet::from_message(&ssh::Message::NewKeys)
        .unwrap()
        .to_bytes()
        .unwrap()
);
repeated!(syslog_frames, 100_000, syslog::Frames::new, b"<13>x\n");
repeated!(
    tds_messages,
    50_000,
    tds::Messages::new,
    tds::Message::new(tds::packet_type::SQL_BATCH, vec![b'x', 0])
        .to_bytes()
        .unwrap()
);
repeated!(
    thrift_frames,
    50_000,
    Frames::<thrift::Frame>::new,
    thrift::Frame(vec![1, 2, 3]).to_bytes().unwrap()
);
repeated!(
    websocket_frames,
    524_288,
    || websocket::Messages::for_receiver(fictionet::stdlib::codec::Side::Client),
    [0x8a, 0]
);
repeated!(
    zabbix_packets,
    50_000,
    Frames::<zabbix::Packet>::new,
    zabbix::Packet::new(vec![b'x'; 3]).to_bytes().unwrap()
);

#[divan::bench(args = [1 << 15, 1 << 17])]
fn asn1_bytewise_element(bencher: Bencher, size: usize) {
    let mut input = vec![0x30, 0x80];
    input.extend([0x04, 0].repeat(size / 2));
    input.extend([0, 0]);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(|| asn1::Elements::new(asn1::Rules::Ber), &input, 1));
}

#[divan::bench(args = [15_000, 60_000])]
fn coap_options(bencher: Bencher, size: usize) {
    let mut options = Vec::with_capacity(2 * size);
    for i in 0..size {
        options.push(coap::CoapOption {
            number: 2 + 2 * (i % 2000) as u16 + 2000,
            value: vec![],
        });
        options.push(coap::CoapOption {
            number: coap::option::URI_PATH,
            value: b"p".to_vec(),
        });
    }
    options.sort_by_key(|o| o.number);
    let message = coap::Message {
        options: coap::Options(options),
        ..coap::Message::new(coap::Type::Confirmable, coap::Code::GET, 1)
    };
    bencher
        .counter(ItemsCount::new(2 * size))
        .bench_local(|| black_box(&message).bad_option());
}

#[divan::bench(args = [7_500, 30_000])]
fn ipp_attributes(bencher: Bencher, size: usize) {
    let mut message = ipp::Message::request(ipp::operation::PRINT_JOB, 1);
    for i in 0..size {
        message.add(
            ipp::tag::JOB_ATTRIBUTES,
            ipp::Attribute::new(format!("n{i}"), ipp::Value::Integer(i as i32)),
        );
    }
    let input = message.to_bytes().unwrap();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(ipp::Head::new, &input, input.len()));
}

#[divan::bench(args = [jsonrpc::MAX_LINE / 8, jsonrpc::MAX_LINE / 2])]
fn jsonrpc_bytewise_line(bencher: Bencher, size: usize) {
    let input = format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"{}\"}}\n",
        "x".repeat(size)
    );
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(jsonrpc::Messages::new, input.as_bytes(), 1));
}

#[divan::bench(args = [proxy_protocol::MAX_TLV_VALUE / 4, proxy_protocol::MAX_TLV_VALUE])]
fn proxy_bytewise_header(bencher: Bencher, size: usize) {
    let input = proxy_protocol::V2 {
        command: proxy_protocol::Command::Proxy,
        addresses: proxy_protocol::Addresses::Unspec,
        tlvs: vec![proxy_protocol::Tlv::Noop(vec![0; size])],
    }
    .to_bytes()
    .unwrap();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(proxy_protocol::Headers::new, &input, 1));
}

#[divan::bench(args = [7_500, 30_000])]
fn qpack_long_instruction(bencher: Bencher, size: usize) {
    let input = qpack::EncoderInstruction::InsertWithLiteralName {
        name: vec![b'0'; size],
        value: vec![b'1'; size],
    }
    .to_bytes()
    .unwrap();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            drain(Frames::<qpack::EncoderInstruction>::new, &input, 1);
            let mut table = qpack::Table::new(qpack::MAX_TABLE_CAPACITY);
            table.set_capacity(qpack::MAX_TABLE_CAPACITY).unwrap();
            table
                .apply(qpack::EncoderInstruction::parse(&input).unwrap())
                .unwrap();
            black_box(table);
        });
}

#[divan::bench(args = [1200, 65_527])]
fn quic_wire_admission(bencher: Bencher, size: usize) {
    let input = vec![0x42; size];
    let budget = fictionet_buf::Budget::new(size + 4096);
    bencher.counter(BytesCount::new(size)).bench_local(|| {
        black_box(quinn_proto::PacketBuffer::copy_from(&budget, black_box(&input)).unwrap());
    });
}

#[divan::bench(args = [16_384, 65_536])]
fn quic_sparse_reassembly(bencher: Bencher, size: usize) {
    bencher.counter(ItemsCount::new(size)).bench_local(|| {
        let mut reassembly = quic::Reassembler::new();
        for i in 0..size {
            let far = i + size - 1;
            reassembly.insert(far as u64, &[far as u8]).unwrap();
            reassembly.insert(i as u64, &[i as u8]).unwrap();
            black_box(reassembly.read());
        }
    });
}

#[divan::bench(args = [rtsp::MAX_BODY / 4, rtsp::MAX_BODY])]
fn rtsp_large_body(bencher: Bencher, size: usize) {
    let mut message = rtsp::Message::response(rtsp::Version::Rtsp10, 200, "OK");
    message.body = vec![b'x'; size];
    message.push_header("Content-Length", &size.to_string());
    let input = message.to_bytes().unwrap();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(rtsp::Frames::new, &input, input.len()));
}

#[divan::bench(args = [socks::MAX_USER_ID / 4, socks::MAX_USER_ID])]
fn socks_bytewise_request(bencher: Bencher, size: usize) {
    let input = socks::Socks4Request {
        command: socks::Socks4Command::Connect,
        port: 80,
        destination: socks::Socks4Destination::Domain(vec![b'd'; size]),
        user_id: vec![b'u'; size],
    }
    .to_bytes()
    .unwrap();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(socks::ClientMessages::new, &input, 1));
}

#[divan::bench(args = [12_500, 50_000])]
fn ssh_algorithm_selection(bencher: Bencher, size: usize) {
    let client: Vec<_> = (0..size).map(|i| format!("client-{i:08}")).collect();
    let server: Vec<_> = (0..size).map(|i| format!("server-{i:08}")).collect();
    let mut matching = server.clone();
    matching.push(client[size - 1].clone());
    matching.push(client[123].clone());
    bencher.counter(ItemsCount::new(size)).bench_local(|| {
        black_box(ssh::KexInit::choose(black_box(&client), black_box(&server)));
        ssh::KexInit::choose(black_box(&client), black_box(&matching))
    });
}

#[divan::bench(args = [x509::MAX_PEM_DATA / 4, x509::MAX_PEM_DATA])]
fn pem_bytewise_block(bencher: Bencher, size: usize) {
    let input = x509::PemBlock {
        label: "X".into(),
        data: vec![0x5a; size],
    }
    .to_bytes()
    .unwrap();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(x509::PemBlocks::new, &input, 1));
}

#[divan::bench(args = [2_500, 10_000])]
fn xml_namespace_depth(bencher: Bencher, size: usize) {
    let depth = size / 40;
    let mut document = String::new();
    for level in 0..depth {
        document.push_str("<a");
        for prefix in 0..4 {
            document.push_str(&format!(
                " xmlns:p{level}_{prefix}=\"urn:{level}:{prefix}\""
            ));
        }
        document.push('>');
    }
    document.push_str(&"<b/>".repeat(size));
    document.push_str(&"</a>".repeat(depth));
    bencher
        .counter(BytesCount::new(document.len()))
        .bench_local(|| drain(xml::Events::new, document.as_bytes(), document.len()));
}

#[divan::bench(args = [5_000, 20_000])]
fn xml_shared_namespaces(bencher: Bencher, size: usize) {
    let uri = "u".repeat(64 << 10);
    let mut document = format!("<p:r xmlns:p='{uri}' xmlns='{uri}'>");
    document.push_str(&"<p:a p:b=''/><c/>".repeat(size));
    document.push_str("</p:r>");
    bencher
        .counter(BytesCount::new(document.len()))
        .bench_local(|| drain(xml::Events::new, document.as_bytes(), document.len()));
}

#[divan::bench(args = [1 << 18, 1 << 20])]
fn xml_namespace_prefixes(bencher: Bencher, size: usize) {
    let shared = "u".repeat(size);
    let mut document = format!("<r xmlns:p='{shared}a' xmlns:q='{shared}b'>");
    document.push_str(&"<x p:a='' q:a=''/>".repeat(size / 10));
    document.push_str("</r>");
    bencher
        .counter(BytesCount::new(document.len()))
        .bench_local(|| drain(xml::Events::new, document.as_bytes(), document.len()));
}

fn kerberos_frame(size: usize) -> Vec<u8> {
    let body = kerberos::Message::ApRep(kerberos::ApRep {
        enc_part: kerberos::EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x5a; size],
        },
    })
    .to_bytes()
    .unwrap();
    kerberos::Frame(body).to_bytes().unwrap()
}

repeated!(
    kerberos_messages,
    25_000,
    Frames::<kerberos::Frame>::new,
    kerberos_frame(0)
);
repeated!(
    mongodb_messages,
    25_000,
    Frames::<mongodb::Message>::new,
    mongodb::Message {
        request_id: 1,
        response_to: 0,
        body: mongodb::Body::Msg(mongodb::Msg::new(
            mongodb::Document::new().with("ping", mongodb::Bson::Int32(1))
        )),
    }
    .to_bytes()
    .unwrap()
);

#[divan::bench(args = [kerberos::MAX_MESSAGE / 8, kerberos::MAX_MESSAGE / 2])]
fn kerberos_bytewise_message(bencher: Bencher, size: usize) {
    let input = kerberos_frame(size);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(Frames::<kerberos::Frame>::new, &input, 1));
}

#[divan::bench(args = [15_000, 60_000])]
fn dcerpc_fragmentation(bencher: Bencher, size: usize) {
    let request = dcerpc::Pdu::new(
        7,
        dcerpc::Body::Request {
            alloc_hint: size as u32,
            context_id: 0,
            opnum: 3,
            object: None,
            stub: vec![1; size],
        },
    );
    bencher
        .counter(BytesCount::new(size))
        .bench_local(|| black_box(&request).fragments(25).unwrap());
}

#[divan::bench(args = [25_000, 100_000])]
fn opcua_messages(bencher: Bencher, size: usize) {
    let mut input = Vec::new();
    for sequence_number in 0..size as u32 {
        let message = opcua::Message::Secure(opcua::SecureMessage {
            kind: opcua::SecureKind::Message { token_id: 1 },
            channel_id: 7,
            sequence_number,
            request_id: 1,
            body: vec![1, 2, 3],
        });
        for chunk in message.chunks(&opcua::Limits::default()).unwrap() {
            chunk.write(&mut input).unwrap();
        }
    }
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(opcua::Messages::new, &input, input.len()));
}

#[divan::bench(args = [16_000, 64_000])]
fn netbios_datagram_fragments(bencher: Bencher, size: usize) {
    use fictionet::stdlib::protocols::nbdgm;
    let packet = nbdgm::Packet::datagram(
        nbdgm::DatagramKind::DirectGroup,
        0x1234,
        std::net::Ipv4Addr::new(10, 0, 0, 9),
        138,
        nbdgm::Name::new("HOST", 0),
        nbdgm::Name::new("WORKGROUP", 0x1d),
        vec![0x5a; size],
    );
    bencher.counter(BytesCount::new(size)).bench_local(|| {
        let mut reassembler = nbdgm::Reassembler::new();
        for part in black_box(&packet).split(1).unwrap() {
            black_box(reassembler.push(part));
        }
    });
}

#[divan::bench(args = [pop3::MAX_BODY / 4, pop3::MAX_BODY])]
fn pop3_refused_values(bencher: Bencher, size: usize) {
    let body = pop3::Reply::ok("").with_body(vec![b'\n'; size * 8]);
    let text = pop3::Reply::ok(&"t".repeat(size));
    let requests = [
        pop3::Request::Pass("t".repeat(size)),
        pop3::Request::User("t".repeat(size)),
    ];
    bencher.counter(BytesCount::new(size)).bench_local(|| {
        let mut output = Vec::new();
        assert!(black_box(&body).write(&mut output).is_err());
        assert!(black_box(&text).write(&mut output).is_err());
        for request in &requests {
            assert!(black_box(request).write(&mut output).is_err());
        }
        black_box(output);
    });
}

#[divan::bench(args = [12_500, 50_000])]
fn pop3_multiline_reply(bencher: Bencher, size: usize) {
    let mut input = b"+OK\r\n".to_vec();
    input.extend(b"line\r\n".repeat(size));
    input.extend(b".\r\n");
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| pop3::Reply::parse(black_box(&input)).unwrap());
}

#[divan::bench(args = [mime_multipart::MAX_PARTS / 4, mime_multipart::MAX_PARTS])]
fn multipart_parts(bencher: Bencher, size: usize) {
    let mut input = Vec::new();
    for _ in 0..size {
        input.extend(b"--b\r\n\r\n");
        input.extend(std::iter::repeat_n(b'x', 40_000));
        input.extend(b"\r\n");
    }
    input.extend(b"--b--");
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            black_box(mime_multipart::Multipart::parse(&input, "b").unwrap());
            drain(
                || mime_multipart::Parts::new("b").unwrap(),
                &input,
                input.len(),
            )
        });
}

#[divan::bench(args = [(mime_multipart::MAX_HEADER_BYTES - 9) / 4, 4 * ((mime_multipart::MAX_HEADER_BYTES - 9) / 4)])]
fn multipart_bytewise_headers(bencher: Bencher, size: usize) {
    let mut input = format!("--b\r\nA: {}\r\n\r\nx\r\n", "v".repeat(size))
        .into_bytes()
        .repeat(64);
    input.extend(b"--b--");
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| drain(|| mime_multipart::Parts::new("b").unwrap(), &input, 1));
}

#[divan::bench(args = [12_500, 50_000])]
fn resp_large_values(bencher: Bencher, size: usize) {
    let mut values = format!("*{size}\r\n").into_bytes();
    values.extend(b"_\r\n".repeat(size));
    values.extend(format!("|1\r\n+a\r\n%{size}\r\n").as_bytes());
    values.extend(b":1\r\n#t\r\n".repeat(size));
    values.extend(b"+v\r\n$?\r\n");
    values.extend(b";1\r\nx\r\n".repeat(size));
    values.extend(b";0\r\n");
    let mut command = format!("*{size}\r\n").into_bytes();
    command.extend(b"$1\r\nx\r\n".repeat(size));
    bencher
        .counter(BytesCount::new(values.len() + command.len()))
        .bench_local(|| {
            drain(resp::Values::new, &values, 1);
            drain(resp::Commands::new, &command, 1)
        });
}

#[divan::bench(args = [(resp::MAX_LINE_LEN - 2) / 4, 4 * ((resp::MAX_LINE_LEN - 2) / 4)])]
fn resp_bytewise_lines(bencher: Bencher, size: usize) {
    let value = format!("+{}\r\n", "a".repeat(size));
    let command = format!("x{}\n", "a".repeat(size));
    let invalid_value = format!("${}\r\n", "1".repeat(size));
    let invalid_command = format!("*1\r\n${}\r\n", "1".repeat(size));
    bencher
        .counter(BytesCount::new(value.len() + command.len()))
        .bench_local(|| {
            drain(resp::Values::new, value.as_bytes(), 1);
            drain(resp::Commands::new, command.as_bytes(), 1);
            fn invalid<D: Decode>(make: impl FnOnce() -> D, input: &[u8])
            where
                D::Error: Clone,
            {
                let mut stream = Stream::new(make());
                for byte in input.chunks(1) {
                    if pump(&mut stream, byte, |item| {
                        black_box(item);
                    })
                    .is_err()
                    {
                        break;
                    }
                }
                black_box(finish(&mut stream, |item| {
                    black_box(item);
                }))
                .ok();
            }
            invalid(resp::Values::new, invalid_value.as_bytes());
            invalid(resp::Commands::new, invalid_command.as_bytes());
        });
}

#[divan::bench(args = [20_000, 80_000])]
fn http2_capture_frames(bencher: Bencher, size: usize) {
    use fictionet::stdlib::dissect::{Conversation, Decoded, KeyLog, Place, Registry};
    let input = [0, 0, 0, 0xff, 0, 0, 0, 0, 1].repeat(size);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            let mut conversation =
                Conversation::new(40000, 80, Registry::default(), KeyLog::default());
            let preface = fictionet::stdlib::protocols::http2::PREFACE;
            conversation.data(
                false,
                preface,
                Place {
                    stream_start: 0,
                    buf: 0,
                    offset: Some(0),
                    len: preface.len(),
                },
                &mut Decoded::default(),
            );
            let mut decoded = Decoded::default();
            conversation.data(
                false,
                &input,
                Place {
                    stream_start: preface.len() as u64,
                    buf: 0,
                    offset: Some(0),
                    len: input.len(),
                },
                &mut decoded,
            );
            black_box(decoded);
        });
}

repeated!(
    stun_messages,
    250_000,
    Frames::<fictionet::stdlib::protocols::stun::Frame>::new,
    fictionet::stdlib::protocols::stun::Message::binding_request([1; 12])
        .to_bytes()
        .unwrap()
);

fn rfb_client() -> fictionet::stdlib::protocols::rfb::Client {
    use fictionet::stdlib::protocols::rfb::*;
    let mut client = Client::new();
    fn receive(client: &mut Client, message: ServerMessage) {
        let mut bytes = Vec::new();
        message
            .write(Dialect::V3_8, &PixelFormat::TRUE_COLOR_32, &mut bytes)
            .unwrap();
        assert_eq!(client.push(&bytes), bytes.len());
        client.next().unwrap().unwrap().unwrap();
    }
    receive(&mut client, ServerMessage::Version(Version::V3_8));
    client.send(&ClientMessage::Version(Version::V3_8)).unwrap();
    receive(&mut client, ServerMessage::SecurityTypes(vec![1]));
    client.send(&ClientMessage::SecurityType(1)).unwrap();
    receive(&mut client, ServerMessage::SecurityOk);
    client
        .send(&ClientMessage::ClientInit { shared: false })
        .unwrap();
    receive(
        &mut client,
        ServerMessage::ServerInit(ServerInit {
            width: 1024,
            height: 768,
            format: PixelFormat::TRUE_COLOR_32,
            name: b"desk".to_vec(),
        }),
    );
    client
}

fn rfb_update(size: usize) -> Vec<u8> {
    use fictionet::stdlib::protocols::rfb::*;
    let update = ServerMessage::FramebufferUpdate(vec![
        Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: Contents::Raw(vec![1, 2, 3, 4]),
        };
        size
    ]);
    let mut bytes = Vec::new();
    update
        .write(Dialect::V3_8, &PixelFormat::TRUE_COLOR_32, &mut bytes)
        .unwrap();
    bytes
}

#[divan::bench(args = [fictionet::stdlib::protocols::rfb::MAX_ITEMS / 4, fictionet::stdlib::protocols::rfb::MAX_ITEMS])]
fn rfb_bytewise_update(bencher: Bencher, size: usize) {
    use fictionet::stdlib::protocols::rfb::*;
    let input = rfb_update(size);
    let pointer = ClientMessage::PointerEvent {
        buttons: 0,
        x: 1,
        y: 1,
    }
    .to_bytes()
    .unwrap()
    .repeat(size * 2);
    bencher
        .counter(BytesCount::new(input.len() + pointer.len()))
        .bench_local(|| {
            let mut client = rfb_client();
            for byte in input.chunks(1) {
                assert_eq!(client.push(byte), 1);
                black_box(client.next());
            }
            drain(
                || {
                    let mut messages = ClientMessages::new();
                    messages.set_phase(Phase::Normal).unwrap();
                    messages
                },
                &pointer,
                1,
            )
        });
}

#[divan::bench(args = [fictionet::stdlib::protocols::rfb::MAX_ITEMS / 4, fictionet::stdlib::protocols::rfb::MAX_ITEMS])]
fn rfb_interleaved_pointer_events(bencher: Bencher, size: usize) {
    use fictionet::stdlib::protocols::rfb::*;
    let input = rfb_update(size);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            let mut client = rfb_client();
            assert_eq!(client.push(&input[..4]), 4);
            for rectangle in input[4..].chunks(16) {
                assert_eq!(client.push(rectangle), rectangle.len());
                if client.next().is_none() {
                    black_box(
                        client
                            .send(&ClientMessage::PointerEvent {
                                buttons: 0,
                                x: 1,
                                y: 1,
                            })
                            .unwrap(),
                    );
                }
            }
        });
}

#[divan::bench(args = [50_000, 200_000])]
fn fastcgi_records(bencher: Bencher, count: usize) {
    let input = fastcgi::Record::new(fastcgi::kind::STDIN, 1, b"x")
        .to_bytes()
        .unwrap()
        .repeat(count);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            drain_stream(
                Stream::with_buffer(Frames::<fastcgi::Record>::new(), input.len()),
                &input,
                input.len(),
            )
        });
}

#[divan::bench(args = [1 << 18, 1 << 20])]
fn onc_rpc_records(bencher: Bencher, count: usize) {
    let input = [0x80, 0, 0, 0].repeat(count);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            drain_stream(
                Stream::with_buffer(onc_rpc::records(onc_rpc::MAX_RECORD), input.len()),
                &input,
                input.len(),
            )
        });
}
