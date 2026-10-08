//! Protobuf messages, varints, and delimited framing.
#![no_main]

use fictionet::stdlib::codec::Frames;
use std::collections::BTreeMap;

use fictionet::stdlib::codec::{Wire, contract, test_support::decode_all};
use fictionet::stdlib::protobuf::{Frame, Varint, MAX_MESSAGE, MAX_VARINT_LEN, MAX_FIELDS, Message, Value};
use libfuzzer_sys::fuzz_target;

// Counts fields as MAX_FIELDS does: group members included.
fn total_fields(m: &Message) -> usize {
    m.fields.iter().map(|f| 1 + if let Value::Group(g) = &f.value { total_fields(g) } else { 0 }).sum()
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Frame>::new, data, 2 * (MAX_MESSAGE + MAX_VARINT_LEN));
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Varint>(data);
    contract::check_wire::<Message>(data);
    // Any bytes as a message: what parses writes, and reads back the same.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(&m));
        // Split the fields by number first, then run each helper on one
        // number's fields alone, so the work stays linear in the fields.
        let mut by_number: BTreeMap<u32, Message> = BTreeMap::new();
        for f in &m.fields {
            by_number.entry(f.number).or_default().fields.push(f.clone());
        }
        for (n, part) in &by_number {
            let n = *n;
            let _ = part.string(n);
            // A merged message or group can be written and read back.
            if let Ok(Some(inner)) = part.message(n) {
                let bytes = inner.to_bytes().unwrap();
                assert_eq!(Message::parse(&bytes).map(|p| p.fields.len()), Ok(inner.fields.len()));
            }
            if let Some(g) = part.group(n) {
                assert!(g.to_bytes().is_ok());
            }
            let _ = part.repeated_varints(n);
            let _ = part.repeated_fixed32(n);
            let _ = part.repeated_fixed64(n);
            let _ = part.repeated_strings(n);
            if let Ok(rs) = part.repeated_messages(n) {
                assert!(rs.iter().map(total_fields).sum::<usize>() <= MAX_FIELDS);
            }
        }
    }

    for frame in decode_all(Frames::<Frame>::new, data).0 {
        contract::check_wire_value(&frame);
        let _ = Message::parse(&frame.data);
    }
});
