//! L2TP datagrams, control messages and AVPs, as a world playing an LNS
//! reads them.
#![no_main]

use fictionet::stdlib::l2tp::{Avp, ControlMessage, Error, Packet, V3Data};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as a datagram. A packet read can be written, no longer
    // than it came, and reads back the same. So does its control message.
    if let Ok(p) = Packet::parse(data) {
        let bytes = p.to_bytes();
        assert!(bytes.len() <= data.len());
        assert_eq!(Packet::parse(&bytes).as_ref(), Ok(&p));
        let body = match &p {
            Packet::V2(v) if v.control => Some(v.payload.as_slice()),
            Packet::V3Control(c) => Some(c.payload.as_slice()),
            _ => None,
        };
        if let Some(Ok(m)) = body.map(ControlMessage::parse) {
            assert_eq!(ControlMessage::parse(&m.to_bytes()), Ok(m));
        }
    }

    // The bytes as an L2TPv3 data message with each cookie length.
    for cookie in [4, 8] {
        if let Ok(d) = V3Data::parse(data, cookie) {
            let bytes = d.to_bytes();
            assert_eq!(bytes.len(), data.len());
            assert_eq!(V3Data::parse(&bytes, cookie), Ok(d));
        }
    }

    // The bytes as a control message body, and as one AVP.
    if let Ok(m) = ControlMessage::parse(data) {
        assert_eq!(ControlMessage::parse(&m.to_bytes()), Ok(m));
    }
    if let Ok((a, used)) = Avp::parse(data) {
        assert_eq!(a.to_bytes(), data[..used]);
    }

    // The datagram growing a byte at a time: each prefix reads or fails
    // without a panic, and one shorter than 2 bytes is Truncated.
    for n in 0..data.len().min(256) {
        let part = Packet::parse(&data[..n]);
        if n < 2 {
            assert_eq!(part, Err(Error::Truncated));
        }
        let _ = ControlMessage::parse(&data[..n]);
    }
});
