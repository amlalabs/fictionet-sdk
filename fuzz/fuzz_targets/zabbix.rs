//! Zabbix packets and JSON messages, as a world playing a Zabbix server
//! reads them.
#![no_main]

use fictionet::stdlib::zabbix::{Decoder, Header, Message, Packet, SenderValue};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::with_limit(4096);
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::with_limit(4096);
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        let (back, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
        // A message keeps its JSON text, and its packet reads back the same.
        if let Ok(m) = Message::parse(&p.data) {
            assert_eq!(m.json().as_bytes(), &p.data[..]);
            assert_eq!(Message::parse(&m.to_packet().data), Ok(m));
        }
    }
    // Any bytes as a header or a message on their own.
    let _ = Header::parse(data);
    let _ = Message::parse(data);
    if let Ok(Some((p, used))) = Packet::parse(data) {
        assert!(used <= data.len());
        assert_eq!(Packet::parse(&p.to_bytes()), Ok(Some((p.clone(), used))));
    }
    // Writers take any text, and what they write reads back.
    let text = String::from_utf8_lossy(data);
    let m = Message::active_checks(&text).unwrap();
    assert_eq!(Message::parse(m.json().as_bytes()), Ok(m));
    let m = Message::response(false, Some(&text)).unwrap();
    assert_eq!(Message::parse(&m.to_packet().data), Ok(m));
    let v = SenderValue { host: text.to_string(), key: text.to_string(), value: text.to_string() };
    let m = Message::sender_data(&[v]).unwrap();
    assert_eq!(Message::parse(m.json().as_bytes()), Ok(m));
});
