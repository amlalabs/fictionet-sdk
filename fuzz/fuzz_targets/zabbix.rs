//! Zabbix packets and JSON messages, as a world playing a Zabbix server
//! reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::json::{self, Limits, Value};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::zabbix::{Error, Header, Kind, MAX_DEPTH, Message, Packet, SenderValue};
use libfuzzer_sys::fuzz_target;

fn check_message(data: &[u8]) {
    let message = Message::parse(data);
    if let Ok(m) = &message {
        assert_eq!(m.json().as_bytes(), data);
        assert_eq!(m.to_bytes().unwrap(), data);
        assert_eq!(Message::parse(&m.to_packet().data).as_ref(), Ok(m));
    }
    // The value parser has tighter size, number and element limits. When
    // it accepts a value at Zabbix's depth limit, classification must agree.
    let limits = Limits {
        depth: MAX_DEPTH,
        ..Limits::default()
    };
    if let Ok(value) = json::parse_with(data, &limits) {
        let expected = if value.as_object().is_none() {
            Err(Error::NotObject)
        } else if let Some(request) = value.get("request").and_then(Value::as_str) {
            Ok(match request {
                "active checks" => Kind::ActiveChecks,
                "agent data" => Kind::AgentData,
                "sender data" => Kind::SenderData,
                other => Kind::OtherRequest(other.into()),
            })
        } else if let Some(response) = value.get("response").and_then(Value::as_str) {
            Ok(Kind::Response(response.into()))
        } else {
            Err(Error::NoKind)
        };
        assert_eq!(message.map(|m| m.kind().clone()), expected);
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_capacity(Frames::<Packet>::new, data);
    contract::check_wire::<Packet>(data);
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_capacity(|| Frames::<Packet>::with_limit(limit), data);
    contract::check_decode_with_alloc_limit(
        || Frames::<Packet>::new().map(|packet| Message::parse(&packet.data)),
        data,
        2 * Frames::<Packet>::new().capacity(),
    );
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
        data: data
            .iter()
            .take(fictionet::stdlib::zabbix::DEFAULT_LIMIT + 1)
            .copied()
            .collect(),
    };
    contract::check_wire_value(&built);

    contract::check_decode_capacity(|| Frames::<Packet>::with_limit(4096), data);
    contract::check_wire::<Header>(data);
    contract::check_wire::<Message>(data);
    check_message(data);
    let mut json = br#"{"request":"agent data","value":"#.to_vec();
    json.extend_from_slice(data);
    json.push(b'}');
    check_message(&json);
    for p in decode_all(|| Frames::<Packet>::with_limit(4096), data).0 {
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
    let v = SenderValue {
        host: text.to_string(),
        key: text.to_string(),
        value: text.to_string(),
    };
    let m = Message::sender_data(&[v]).unwrap();
    contract::check_wire_value(&m);
});
