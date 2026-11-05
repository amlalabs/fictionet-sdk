//! PROXY protocol headers, version 1 and 2, as a world behind a proxy
//! reads them at the start of a connection.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet::stdlib::{
    codec::{Decode, Step, Wire},
    protocols::proxy_protocol::Headers,
};

use fictionet::stdlib::protocols::proxy_protocol::{
    Addresses, Command, Header, MAX_HEADER_LEN, MAX_TLV_VALUE, Ssl, SslTlv, Tlv, Transport, V1, V2,
    V2_MAX_BODY, V2_SIGNATURE,
};
use libfuzzer_sys::fuzz_target;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

fn check_exact_and_streaming(data: &[u8]) {
    if let Ok(Step::Item(item, used)) = Headers::new().decode(data, false) {
        assert_eq!(Header::parse(&data[..used]), item);
        if let Ok(header) = item {
            let canonical = header.to_bytes().unwrap();
            assert_eq!(Header::parse(&canonical), Ok(header));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check_exact_and_streaming(data);
    // Reach TLV and LOCAL normalization paths without requiring the fuzzer
    // to discover the fixed signature and length first.
    if let Some((&family, body)) = data.split_first() {
        let body = &body[..body.len().min(V2_MAX_BODY)];
        for command in [0x20, 0x21] {
            let mut bytes = V2_SIGNATURE.to_vec();
            bytes.extend_from_slice(&[command, family]);
            bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
            bytes.extend_from_slice(body);
            check_exact_and_streaming(&bytes);
        }
    }
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Headers::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_HEADER_LEN);
            }
        ),
        decode_all(Headers::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Headers::with_limit(32)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 64);
            }
        ),
        decode_all(|| Headers::with_limit(32), data),
    );
    if let Ok(value) = <Header as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&Header::V1(V1::Unknown(
        data.iter().take(108).copied().collect(),
    )));
    if let Ok(value) = <V1 as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <V2 as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Tlv as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Ssl as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <SslTlv as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    // Headers built from socket addresses taken from the input read back.
    if let Some(a) = data.get(..38) {
        let addr = |b: &[u8], v6: bool| -> SocketAddr {
            let port = u16::from_be_bytes([b[16], b[17]]);
            if v6 {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&b[..16]);
                SocketAddr::from((Ipv6Addr::from(ip), port))
            } else {
                SocketAddr::from((Ipv4Addr::new(b[0], b[1], b[2], b[3]), port))
            }
        };
        let (src, dst) = (
            addr(&a[..18], a[36] & 1 != 0),
            addr(&a[18..36], a[36] & 2 != 0),
        );
        let transport = if a[37] & 1 == 0 {
            Transport::Stream
        } else {
            Transport::Dgram
        };
        let headers = [
            Header::V1(V1::from_addrs(src, dst)),
            Header::V2(V2 {
                command: Command::Proxy,
                addresses: Addresses::from_addrs(transport, src, dst),
                tlvs: vec![],
            }),
        ];
        for h in headers {
            let _ = assert_write(&h);
            let bytes = h.to_bytes().unwrap();
            assert_eq!(Header::parse(&bytes), Ok(h));
        }
    }

    // The raw TLV readers: what they accept a header can carry, and an SSL
    // value they read writes back to the same bytes.
    if let Some((&kind, value)) = data.split_first() {
        if let Ok(tlv) = Tlv::from_raw(kind, value) {
            assert!(value.len() <= MAX_TLV_VALUE);
            assert_eq!(tlv.kind(), kind);
        }
    }
    if let Ok(ssl) = Ssl::parse(data) {
        assert_eq!(ssl.to_bytes().unwrap(), data);
        let h = Header::V2(V2 {
            command: Command::Proxy,
            addresses: Addresses::Unspec,
            tlvs: vec![Tlv::Ssl(ssl)],
        });
        let bytes = h.to_bytes().unwrap();
        assert_eq!(Header::parse(&bytes), Ok(h));
    }

    // Headers with TLVs of every variant built from the input, including
    // oversized fields and variant aliases that writers refuse.
    let mut tlvs = Vec::new();
    let mut rest = data;
    while let [pick, len_hi, len_lo, tail @ ..] = rest {
        // A length byte of 0xff stands for a value far too long to fit.
        let n = if *len_hi == 0xff {
            usize::from(*len_lo) * 1024
        } else {
            usize::from(u16::from_be_bytes([*len_hi & 0x0f, *len_lo]))
        };
        let (v, next) = tail.split_at(n.min(tail.len()));
        let mut v = v.to_vec();
        v.resize(n, *pick);
        rest = next;
        let sub = |v: &[u8]| {
            v.chunks(7)
                .map(|c| SslTlv::from_raw(0x21 + c[0] % 6, &c[1..]).unwrap())
                .collect()
        };
        tlvs.push(match pick % 9 {
            0 => Tlv::Alpn(v),
            1 => Tlv::Authority(v),
            2 => Tlv::Crc32c(u32::from(*len_lo)),
            3 => Tlv::Noop(v),
            4 => Tlv::UniqueId(v),
            5 => Tlv::Ssl(Ssl {
                client: *len_lo,
                verify: u32::from(*len_hi),
                tlvs: sub(&v),
            }),
            6 => Tlv::NetNs(v),
            _ => Tlv::Other {
                kind: *len_hi,
                value: v,
            },
        });
        if tlvs.len() == 64 {
            break;
        }
    }
    if !tlvs.is_empty() {
        let command = if data[0] & 0x80 == 0 {
            Command::Local
        } else {
            Command::Proxy
        };
        let h = Header::V2(V2 {
            command,
            addresses: Addresses::Unspec,
            tlvs,
        });
        let _ = assert_write(&h);
    }
});
