//! PROXY protocol headers, version 1 and 2, as a world behind a proxy
//! reads them at the start of a connection.
#![no_main]

use fictionet::stdlib::proxy_protocol::{Addresses, Command, Decoder, Header, Ssl, SslTlv, Step, Tlv, Transport, MAX_HEADER_LEN, MAX_TLV_VALUE, V1, V2};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = Header::parse(data);

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    let all_at_once = whole.feed(data);
    let mut bytewise = Decoder::new();
    let mut found = Step::NeedMore;
    for (i, b) in data.iter().enumerate() {
        match bytewise.feed(std::slice::from_ref(b)) {
            Step::NeedMore => assert!(bytewise.buffered() <= MAX_HEADER_LEN),
            Step::Header { header, rest } => {
                assert!(rest.is_empty());
                let mut rest = rest;
                rest.extend_from_slice(&data[i + 1..]);
                found = Step::Header { header, rest };
                break;
            }
            Step::Failed { error, bytes } => {
                let mut bytes = bytes;
                bytes.extend_from_slice(&data[i + 1..]);
                found = Step::Failed { error, bytes };
                break;
            }
            Step::Finished => unreachable!(),
        }
    }
    assert_eq!(all_at_once, found);

    match (&parsed, &all_at_once) {
        (Ok(None), Step::NeedMore) => {}
        (Ok(Some((h, used))), Step::Header { header, rest }) => {
            assert_eq!(h, header);
            assert_eq!(rest, &data[*used..]);
            // A header read can be written, and reads back the same.
            let bytes = h.to_bytes();
            let (back, n) = Header::parse(&bytes).unwrap().unwrap();
            assert_eq!(&back, h);
            assert_eq!(n, bytes.len());
        }
        (Err(e), Step::Failed { error, bytes }) => {
            assert_eq!(e, error);
            assert_eq!(bytes, data);
        }
        (p, s) => panic!("parse {p:?}, decoder {s:?}"),
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
        let (src, dst) = (addr(&a[..18], a[36] & 1 != 0), addr(&a[18..36], a[36] & 2 != 0));
        let transport = if a[37] & 1 == 0 { Transport::Stream } else { Transport::Dgram };
        let headers = [
            Header::V1(V1::from_addrs(src, dst)),
            Header::V2(V2 { command: Command::Proxy, addresses: Addresses::from_addrs(transport, src, dst), tlvs: vec![] }),
        ];
        for h in headers {
            let bytes = h.to_bytes();
            let (back, n) = Header::parse(&bytes).unwrap().unwrap();
            assert_eq!(back, h);
            assert_eq!(n, bytes.len());
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
        assert_eq!(ssl.to_value(), data);
        let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Ssl(ssl)] });
        let bytes = h.to_bytes();
        assert_eq!(Header::parse(&bytes), Ok(Some((h, bytes.len()))));
    }

    // Headers with TLVs of every variant built from the input, including
    // ones a writer must cut or leave out. What is written reads back, and
    // writing that again gives the same bytes.
    let mut tlvs = Vec::new();
    let mut rest = data;
    while let [pick, len_hi, len_lo, tail @ ..] = rest {
        // A length byte of 0xff stands for a value far too long to fit.
        let n = if *len_hi == 0xff { usize::from(*len_lo) * 1024 } else { usize::from(u16::from_be_bytes([*len_hi & 0x0f, *len_lo])) };
        let (v, next) = tail.split_at(n.min(tail.len()));
        let mut v = v.to_vec();
        v.resize(n, *pick);
        rest = next;
        let sub = |v: &[u8]| v.chunks(7).map(|c| SslTlv::from_raw(0x21 + c[0] % 6, &c[1..])).collect();
        tlvs.push(match pick % 9 {
            0 => Tlv::Alpn(v),
            1 => Tlv::Authority(v),
            2 => Tlv::Crc32c(u32::from(*len_lo)),
            3 => Tlv::Noop(v),
            4 => Tlv::UniqueId(v),
            5 => Tlv::Ssl(Ssl { client: *len_lo, verify: u32::from(*len_hi), tlvs: sub(&v) }),
            6 => Tlv::NetNs(v),
            _ => Tlv::Other { kind: *len_hi, value: v },
        });
        if tlvs.len() == 64 {
            break;
        }
    }
    if !tlvs.is_empty() {
        let command = if data[0] & 0x80 == 0 { Command::Local } else { Command::Proxy };
        let h = Header::V2(V2 { command, addresses: Addresses::Unspec, tlvs });
        let bytes = h.to_bytes();
        assert!(bytes.len() <= MAX_HEADER_LEN);
        let (back, n) = Header::parse(&bytes).unwrap().unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(back.to_bytes(), bytes);
    }
});
