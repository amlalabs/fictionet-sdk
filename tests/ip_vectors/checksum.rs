//! The `checksum` vectors (see `verification/packet-udp/lean/Ip`):
//! `ip::checksum`, `ip::fold`, two chained calls of `ip::sum`,
//! `ip::pseudo_header_sum` and `ip::transport_checksum` against RFC 1071
//! over the RFC pseudo-headers.

use fictionet::stdlib::network::ip::{self, Endpoints};

use crate::support::{self, addr, bytes, num};

#[test]
fn checksum() {
    support::cases("checksum", |case| {
        let got = match case["op"].as_str().unwrap() {
            "checksum" => ip::checksum(&bytes(&case["data"])),
            "fold" => ip::fold(num(&case["acc"])),
            "split" => ip::fold(ip::sum(ip::sum(0, &bytes(&case["a"])), &bytes(&case["b"]))),
            "pseudo" => {
                let endpoints = Endpoints::new(addr(&case["src"]), addr(&case["dst"])).unwrap();
                let acc =
                    ip::pseudo_header_sum(0, &endpoints, num(&case["protocol"]), num(&case["len"]));
                ip::fold(ip::sum(acc, &bytes(&case["data"])))
            }
            "transport" => ip::transport_checksum(
                addr(&case["src"]),
                addr(&case["dst"]),
                num(&case["protocol"]),
                &bytes(&case["data"]),
            ),
            op => panic!("unknown checksum op {op}"),
        };
        assert_eq!(got, num::<u16>(&case["expected"]), "{case}");
    });
}
