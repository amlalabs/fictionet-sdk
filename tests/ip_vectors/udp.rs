//! The `udp` vectors (see `verification/packet-udp/lean/Ip`):
//! `udp::Datagram::parse`, `ip::udp_checksum_ok` and
//! `Datagram::checksum_ok`, `udp::encode` and `udp::encoded_len`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fictionet::stdlib::network::ip;
use fictionet::stdlib::network::udp::{self, Datagram, Error};
use serde_json::{Value, json};

use crate::support::{self, addr, bytes, num};

fn parse(case: &Value) {
    let p = bytes(&case["bytes"]);
    let got = Datagram::parse(&p).map(|d| {
        json!({
            "src_port": d.source_port(),
            "dst_port": d.destination_port(),
            "length": d.as_bytes().len(),
            "payload": d.payload(),
        })
    });
    assert_eq!(json!(got), case["expected"], "{case}");
}

fn checksum_ok(case: &Value) {
    let (src, dst) = (addr(&case["src"]), addr(&case["dst"]));
    let udp = bytes(&case["udp"]);
    let expected = case["expected"].as_bool().unwrap();
    assert_eq!(ip::udp_checksum_ok(src, dst, &udp), expected, "{case}");
    // The datagram's own check, where its length field covers it all.
    if let Some(d) = Datagram::parse(&udp)
        && d.as_bytes().len() == udp.len()
    {
        assert_eq!(d.checksum_ok(src, dst), expected, "Datagram {case}");
    }
}

fn encode(case: &Value) {
    let from = SocketAddr::new(addr(&case["src"]), num(&case["src_port"]));
    let to = SocketAddr::new(addr(&case["dst"]), num(&case["dst_port"]));
    let payload = bytes(&case["payload"]);
    let expected = bytes(&case["expected"]);
    let mut out = vec![0xa5; expected.len() + 3];
    let n = udp::encode(from, to, &payload, &mut out).expect("a datagram that fits");
    assert_eq!(out[..n], expected, "{case}");
    assert!(
        out[n..].iter().all(|&b| b == 0xa5),
        "bytes after the datagram {case}"
    );
}

fn encoded_len(case: &Value) {
    let v4: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
    let v6: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
    let src = if case["v4"].as_bool().unwrap() {
        v4
    } else {
        v6
    };
    let dst = match (
        case["v4"].as_bool().unwrap(),
        case["mixed"].as_bool().unwrap(),
    ) {
        (true, false) | (false, true) => v4,
        _ => v6,
    };
    let got = match udp::encoded_len(src, dst, num(&case["len"])) {
        Ok(n) => json!(n),
        Err(Error::AddressFamily) => json!("family"),
        Err(Error::Length) => json!("length"),
        Err(e) => panic!("encoded_len cannot fail with {e}"),
    };
    assert_eq!(got, case["expected"], "{case}");
}

#[test]
fn udp() {
    support::cases("udp", |case| match case["op"].as_str().unwrap() {
        "parse" => parse(case),
        "checksum_ok" => checksum_ok(case),
        "encode" => encode(case),
        "encoded_len" => encoded_len(case),
        op => panic!("unknown udp op {op}"),
    });
}
