//! SSH version exchange, cleartext packets, messages, and primitive fields.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::ssh::*;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Packet>::new, data, 2 * MAX_PACKET);
    contract::check_decode_with_alloc_limit(Events::new, data, 2 * MAX_PACKET);
    contract::check_decode_with_alloc_limit(Events::after_version, data, 2 * MAX_PACKET);
    contract::check_decode_with_alloc_limit(Lines::new, data, 2 * MAX_BANNER_LINE);
    contract::check_decode_with_alloc_limit(
        || Frames::<Packet>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
        510,
    );
    contract::check_wire::<Packet>(data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Line>(data);
    contract::check_wire::<Identification>(data);
    contract::check_wire::<Byte>(data);
    contract::check_wire::<Boolean>(data);
    contract::check_wire::<Uint32>(data);
    contract::check_wire::<Uint64>(data);
    contract::check_wire::<SshString>(data);
    contract::check_wire::<Mpint>(data);
    contract::check_wire::<NameList>(data);
    let payload = &data[..data.len().min(MAX_PAYLOAD + 1)];
    contract::check_wire_value(&Packet {
        payload: payload.to_vec(),
        padding: vec![0; usize::from(data.first().copied().unwrap_or(0))],
    });
    contract::check_wire_value(&SshString(payload.to_vec()));
    contract::check_wire_value(&Message::Other {
        number: data.first().copied().unwrap_or(0),
        data: payload.to_vec(),
    });
    contract::check_wire_value(&Line::Banner(payload.to_vec()));
    for event in decode_all(Events::new, data).0 {
        match event {
            Event::Banner(text) => contract::check_wire_value(&Line::Banner(text)),
            Event::Version(id) => contract::check_wire_value(&id),
            Event::Packet { packet, .. } => {
                contract::check_wire_value(&packet);
                contract::check_wire::<Message>(&packet.payload);
            }
        }
    }
    let mut r = Reader::new(data);
    let _ = (
        r.mpint(),
        r.name_list(usize::MAX),
        r.text(usize::MAX),
        r.uint64(),
        r.boolean(),
    );
});
