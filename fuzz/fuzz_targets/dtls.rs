//! DTLS records, handshake fragments and hellos, as a world playing a
//! DTLS server reads them from UDP datagrams.
#![no_main]

use fictionet::stdlib::dtls::{
    ClientHello, Fragment, Handshake, HelloVerifyRequest, MAX_MESSAGE_LEN, MAX_REASSEMBLY_BYTES, Reassembler, Record,
    ServerHello, parse_datagram, write_datagram,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte picks the connection ID length; the rest is a datagram.
    let Some((&cid, data)) = data.split_first() else { return };
    let cid_len = cid % 4;

    // A record read writes back to the same bytes, and reads the same.
    if let Ok((r, used)) = Record::parse(data, cid_len) {
        let bytes = r.to_bytes();
        assert_eq!(bytes, data[..used]);
        assert_eq!(Record::parse(&bytes, cid_len), Ok((r, used)));
    }
    if let Ok(records) = parse_datagram(data, cid_len) {
        assert_eq!(write_datagram(&records), data);
    }

    // The bytes as a handshake record's payload. Fragments write back the
    // same, and a reassembler takes them without holding too much.
    if let Ok(fragments) = Fragment::parse_all(data) {
        let bytes: Vec<u8> = fragments.iter().flat_map(|f| f.to_bytes()).collect();
        assert_eq!(bytes, data);
        let mut r = Reassembler::new();
        for f in &fragments {
            let _ = r.add(f);
            assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
            while let Some(m) = r.next_message() {
                let _ = m.parse_body();
            }
        }
    }

    // The bytes as a message, sent a byte at a time, come back whole.
    // Writers cut longer messages, so those would not.
    if data.len() <= MAX_MESSAGE_LEN {
        let m = Handshake { msg_type: cid, message_seq: 0, body: data.to_vec() };
        let mut r = Reassembler::new();
        for f in m.fragments(1) {
            r.add(&f).unwrap();
        }
        assert_eq!(r.next_message(), Some(m));
    }

    // The bytes as hello bodies.
    if let Ok(h) = ClientHello::parse(data) {
        assert_eq!(h.to_bytes(), data);
        let _ = h.supported_versions();
    }
    if let Ok(h) = ServerHello::parse(data) {
        assert_eq!(h.to_bytes(), data);
        let _ = (h.selected_version(), h.is_hello_retry_request());
    }
    if let Ok(h) = HelloVerifyRequest::parse(data) {
        assert_eq!(h.to_bytes(), data);
    }
});
