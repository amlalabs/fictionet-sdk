//! Protobuf messages, varints, and delimited framing.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use std::collections::BTreeMap;

use fictionet::stdlib::codec::Wire;

use fictionet::stdlib::protocols::protobuf::harness::total_fields;
use fictionet::stdlib::protocols::protobuf::{
    Frame, MAX_FIELDS, MAX_MESSAGE, MAX_VARINT_LEN, Message, Varint,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bound = 2 * (MAX_MESSAGE + MAX_VARINT_LEN);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Varint as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    // Any bytes as a message: what parses writes, and reads back the same.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(&m));
        // Split the fields by number first, then run each helper on one
        // number's fields alone, so the work stays linear in the fields.
        let mut by_number: BTreeMap<u32, Message> = BTreeMap::new();
        for f in &m.fields {
            by_number
                .entry(f.number)
                .or_default()
                .fields
                .push(f.clone());
        }
        for (n, part) in &by_number {
            let n = *n;
            let _ = part.string(n);
            // A merged message or group can be written and read back.
            if let Ok(Some(inner)) = part.message(n) {
                let bytes = inner.to_bytes().unwrap();
                assert_eq!(
                    Message::parse(&bytes).map(|p| p.fields.len()),
                    Ok(inner.fields.len())
                );
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
        let _ = assert_write(&frame);
        let _ = Message::parse(&frame.data);
    }
});
