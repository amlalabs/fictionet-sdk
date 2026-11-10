//! The `header` and `hop` vectors (see `verification/packet-udp/lean/Ip`):
//! the IPv4 readers (`Header::parse`, `parse_truncated`, `check`,
//! `parse_whole`, `payload` and `dst_port`), the builders (`packet_with`
//! and `packet_with_ipv4_options`), and the router hop (`hop`, with
//! `set_header_checksum` for the recomputed header).

use std::net::IpAddr;

use fictionet::stdlib::network::ip::{self, Fields, Header, Hop, Ipv4Option};
use serde_json::{Value, json};

use crate::support::{self, addr, bytes, num, octets};

/// A header as the vectors write it.
fn parsed(header: Option<Header>) -> Value {
    let Some(h) = header else {
        return Value::Null;
    };
    json!({
        "src": octets(h.src),
        "dst": octets(h.dst),
        "protocol": h.protocol,
        "start": h.payload.start,
        "end": h.payload.end,
        "length": h.length,
        "fragment": h.fragment.map(|f| json!({
            "id": f.id,
            "offset": f.offset,
            "more": f.more,
        })),
    })
}

fn read(case: &Value) {
    let p = bytes(&case["bytes"]);
    let header = Header::parse(&p);
    assert_eq!(parsed(header.clone()), case["parse"], "parse {case}");
    assert_eq!(
        parsed(Header::parse_truncated(&p)),
        case["truncated"],
        "parse_truncated {case}"
    );
    assert_eq!(
        parsed(Header::check(&p).ok()),
        case["check"],
        "check {case}"
    );
    assert_eq!(
        parsed(Header::parse_whole(&p)),
        case["whole"],
        "parse_whole {case}"
    );
    let payload = header.as_ref().map(|h| h.payload(&p).to_vec());
    assert_eq!(json!(payload), case["payload"], "payload {case}");
    let port = header.as_ref().and_then(|h| h.dst_port(&p));
    assert_eq!(json!(port), case["dst_port"], "dst_port {case}");
}

fn option(value: &Value) -> Ipv4Option {
    if value.get("nop").is_some() {
        Ipv4Option::NoOperation
    } else {
        Ipv4Option::Unknown {
            kind: num(&value["kind"]),
            data: bytes(&value["data"]),
        }
    }
}

fn build(case: &Value) {
    let (src, dst) = (addr(&case["src"]), addr(&case["dst"]));
    let fields = Fields {
        ttl: num(&case["ttl"]),
        tos: num(&case["tos"]),
        id: num(&case["id"]),
        dont_fragment: case["dont_fragment"].as_bool().unwrap(),
    };
    let protocol: u8 = num(&case["protocol"]);
    let payload = bytes(&case["payload"]);
    let options: Vec<Ipv4Option> = case["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(option)
        .collect();
    let expected = bytes(&case["expected"]);
    if options.is_empty() {
        let p = ip::packet_with(src, dst, protocol, fields, &payload);
        assert_eq!(p.0, expected, "packet_with {case}");
    }
    if let (IpAddr::V4(s), IpAddr::V4(d)) = (src, dst) {
        let p = ip::packet_with_ipv4_options(s, d, protocol, fields, &options, &payload)
            .expect("options that fit");
        assert_eq!(p.0, expected, "packet_with_ipv4_options {case}");
    }
}

#[test]
fn header() {
    support::cases("header", |case| match case["op"].as_str().unwrap() {
        "parse" => read(case),
        "build" => build(case),
        op => panic!("unknown header op {op}"),
    });
}

#[test]
fn hop() {
    support::cases("hop", |case| {
        let before = bytes(&case["bytes"]);
        let mut p = before.clone();
        let result = match ip::hop(&mut p) {
            Hop::Forward => "forward",
            Hop::Expired => "expired",
            Hop::NotIp => "not_ip",
        };
        assert_eq!(result, case["result"], "{case}");
        assert_eq!(p, bytes(&case["after"]), "{case}");
        if !case["recomputed"].is_null() {
            let recomputed = bytes(&case["recomputed"]);
            let ihl = recomputed.len();
            let mut q = before;
            q[8] -= 1;
            ip::set_header_checksum(&mut q[..ihl]);
            assert_eq!(q[..ihl], recomputed, "set_header_checksum {case}");
            assert_eq!(p[..ihl], recomputed, "hop against recomputing {case}");
        }
    });
}
