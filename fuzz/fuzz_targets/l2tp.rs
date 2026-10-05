//! L2TP datagrams, control messages and AVPs, as a world playing an LNS
//! reads them.
#![no_main]

use fictionet::stdlib::l2tp::{
    Avp, ControlMessage, Error, MAX_AVP_VALUE, MAX_AVPS, MAX_MESSAGE, MessageType, Packet, V3Control, V3Data,
};
use libfuzzer_sys::fuzz_target;

/// What `m` reads back as once written: reserved bits zero, values cut
/// to MAX_AVP_VALUE, AVPs past the limits left out, the type read from
/// its number, and a ZLB holding nothing.
fn written(m: &ControlMessage) -> ControlMessage {
    let Some(t) = m.message_type else {
        return ControlMessage::zlb();
    };
    let message_type = if m.vendor == 0 { MessageType::from_code(t.code()) } else { MessageType::Other(t.code()) };
    let mut used = 8;
    let mut avps = Vec::new();
    for a in &m.avps {
        if avps.len() + 1 >= MAX_AVPS || used + a.encoded_len() > MAX_MESSAGE {
            break;
        }
        used += a.encoded_len();
        let mut value = a.value.clone();
        value.truncate(MAX_AVP_VALUE);
        avps.push(Avp { reserved: 0, value, ..a.clone() });
    }
    ControlMessage { message_type: Some(message_type), mandatory: m.mandatory, vendor: m.vendor, reserved: 0, avps }
}

fuzz_target!(|data: &[u8]| {
    // The bytes as a datagram. A packet read can be written, no longer
    // than it came, and reads back the same. Its control message reads
    // back as the writer's rules say.
    if let Ok(p) = Packet::parse(data) {
        let bytes = p.to_bytes().expect("a packet read has a cookie the writer takes");
        assert!(bytes.len() <= data.len());
        assert_eq!(Packet::parse(&bytes).as_ref(), Ok(&p));
        let body = match &p {
            Packet::V2(v) if v.control => Some(v.payload.as_slice()),
            Packet::V3Control(c) => Some(c.payload.as_slice()),
            _ => None,
        };
        if let Some(Ok(m)) = body.map(ControlMessage::parse) {
            assert_eq!(ControlMessage::parse(&m.to_bytes()), Ok(written(&m)));
        }
    }

    // The bytes as an L2TPv3 data message with each cookie length.
    for cookie in [4, 8] {
        if let Ok(d) = V3Data::parse(data, cookie) {
            let bytes = d.to_bytes().expect("a cookie of 4 or 8 bytes is written");
            assert_eq!(bytes.len(), data.len());
            assert_eq!(V3Data::parse(&bytes, cookie), Ok(d));
        }
    }
    // A cookie of any other length is refused, not cut.
    let cookie = &data[..data.len().min(12)];
    let d = V3Data { session: 1, cookie: cookie.to_vec(), payload: vec![] };
    match d.to_bytes() {
        Ok(b) => assert_eq!(V3Data::parse(&b, cookie.len()), Ok(d)),
        Err(e) => assert_eq!(e, Error::Cookie(cookie.len())),
    }

    // The bytes as a control message body, and as one AVP.
    if let Ok(m) = ControlMessage::parse(data) {
        let body = m.to_bytes();
        assert_eq!(ControlMessage::parse(&body), Ok(written(&m)));
        // The body repeated past what a datagram holds: the writer cuts
        // it between AVPs, so its message still reads.
        if !body.is_empty() {
            let long = body.repeat(MAX_MESSAGE / body.len() + 1);
            let c = V3Control { connection: 1, ns: 0, nr: 0, payload: long };
            let read = V3Control::parse(&c.to_bytes()).map(|c| c.message());
            assert!(matches!(read, Ok(Ok(_) | Err(Error::TooManyAvps))), "{read:?}");
        }
    }
    if let Ok((a, used)) = Avp::parse(data) {
        // Reserved bits are read, and written as zero.
        let mut zeroed = data[..used].to_vec();
        zeroed[0] &= 0xc3;
        assert_eq!(a.to_bytes(), zeroed);
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
