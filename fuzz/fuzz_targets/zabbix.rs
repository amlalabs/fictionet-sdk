//! Zabbix packets and JSON messages, as a world playing a Zabbix server
//! reads them.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::zabbix::{Frames, Header, Message, Packet, SenderValue};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * Frames::new().capacity());
    contract::check_wire::<Packet>(data);
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_with_alloc_limit(
        || Frames::with_limit(limit), data, 2 * Frames::with_limit(limit).capacity(),
    );
    contract::check_decode_with_alloc_limit(|| Frames::new().map(|packet| Message::parse(&packet.data)), data, 2 * Frames::new().capacity());
    let reserved = data
        .get(..8)
        .map(|bytes| {
            let mut value = [0; 8];
            value.copy_from_slice(bytes);
            u64::from_le_bytes(value)
        })
        .unwrap_or(0);
    let built = Packet {
        flags: data.first().copied().unwrap_or(0),
        reserved,
        data: data.iter().take(fictionet::stdlib::zabbix::DEFAULT_LIMIT + 1).copied().collect(),
    };
    contract::check_wire_value(&built);

    contract::check_decode_with_alloc_limit(|| Frames::with_limit(4096), data, 2 * Frames::with_limit(4096).capacity());
    contract::check_wire::<Header>(data);
    contract::check_wire::<Message>(data);
    for p in decode_all(|| Frames::with_limit(4096), data).0 {
        contract::check_wire_value(&p);
        if let Ok(m) = Message::parse(&p.data) {
            assert_eq!(m.json().as_bytes(), &p.data[..]);
            contract::check_wire_value(&m);
            assert_eq!(Message::parse(&m.to_packet().data), Ok(m));
        }
    }
    // Constructed messages within their limits read back unchanged.
    let text = String::from_utf8_lossy(data);
    let m = Message::active_checks(&text).unwrap();
    contract::check_wire_value(&m);
    let m = Message::response(false, Some(&text)).unwrap();
    contract::check_wire_value(&m);
    assert_eq!(Message::parse(&m.to_packet().data), Ok(m));
    let v = SenderValue { host: text.to_string(), key: text.to_string(), value: text.to_string() };
    let m = Message::sender_data(&[v]).unwrap();
    contract::check_wire_value(&m);
});
