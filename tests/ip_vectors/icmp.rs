//! The `icmp` vectors (see `verification/packet-udp/lean/Ip/Icmp.lean`):
//! packets, and the ICMP or ICMPv6 error or echo reply the Lean model of
//! `Options::error` and `Options::echo_reply` builds for each, or none.
//! Each case names the Rust entry point it calls.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fictionet::Packet;
use fictionet::stdlib::network::icmp;
use fictionet::stdlib::network::ip::{self, Reject};
use serde_json::Value;

use crate::support;

/// An IPv4 or IPv6 address from its octets.
fn addr(value: &Value) -> IpAddr {
    let bytes = support::bytes(value);
    match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        n => panic!("an address of {n} octets"),
    }
}

#[test]
fn icmp_messages_match_the_lean_model() {
    support::cases("icmp", |case| {
        let packet = support::bytes(&case["packet"]);
        let n = |key: &str| case[key].as_u64().unwrap();
        let out = match case["fn"].as_str().unwrap() {
            "error" => icmp::error(
                &packet,
                addr(&case["from"]),
                n("kind") as u8,
                n("code") as u8,
                n("word") as u32,
            ),
            "host_unreachable" => {
                let IpAddr::V4(from) = addr(&case["from"]) else {
                    panic!("host_unreachable from IPv6")
                };
                icmp::host_unreachable(&packet, from)
            }
            "address_unreachable" => {
                let IpAddr::V6(from) = addr(&case["from"]) else {
                    panic!("address_unreachable from IPv4")
                };
                icmp::address_unreachable(&packet, from)
            }
            "time_exceeded" => icmp::time_exceeded(&packet, addr(&case["from"])),
            "parameter_problem" => {
                let reject = &case["reject"];
                let reject = match reject["reject"].as_str().unwrap() {
                    "discard" => Reject::Discard,
                    _ => Reject::Problem {
                        code: reject["code"].as_u64().unwrap() as u8,
                        pointer: reject["pointer"].as_u64().unwrap() as u32,
                    },
                };
                ip::parameter_problem(&packet, reject)
            }
            "echo" => icmp::echo_reply(&Packet(packet.clone()), addr(&case["addr"])),
            other => panic!("unknown entry point {other}"),
        };
        let want = (!case["out"].is_null()).then(|| support::bytes(&case["out"]));
        assert_eq!(
            out.map(|p| p.0),
            want,
            "{} {packet:?}",
            case["fn"].as_str().unwrap()
        );
    });
}
