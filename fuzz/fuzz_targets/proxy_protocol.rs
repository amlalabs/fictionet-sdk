//! PROXY protocol headers, version 1 and 2, as a world behind a proxy
//! reads them at the start of a connection.
#![no_main]

use fictionet::stdlib::proxy_protocol::{Addresses, Command, Decoder, Header, Step, Transport, MAX_HEADER_LEN, V1, V2};
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
});
