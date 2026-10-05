//! Protobuf messages and their gRPC and delimited framing, as a world
//! playing a gRPC server reads them.
#![no_main]

use std::collections::BTreeMap;

use fictionet::stdlib::protobuf::{Decoder, Frame, Framing, MAX_FIELDS, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
            let _ = part.message(n);
            let _ = part.repeated_varints(n);
            let _ = part.repeated_fixed32(n);
            let _ = part.repeated_fixed64(n);
            let _ = part.repeated_strings(n);
            if let Ok(rs) = part.repeated_messages(n) {
                assert!(rs.iter().map(|r| r.fields.len()).sum::<usize>() <= MAX_FIELDS);
            }
        }
    }

    for framing in [Framing::Grpc, Framing::Delimited] {
        // The stream, split three ways: all at once, a byte at a time, and
        // in chunks whose sizes come from the data.
        let mut whole = Decoder::new(framing);
        whole.feed(data);
        let mut frames = Vec::new();
        while let Some(Ok(f)) = whole.next_frame() {
            frames.push(f);
        }
        let mut bytewise = Decoder::new(framing);
        let mut again = Vec::new();
        for b in data {
            bytewise.feed(std::slice::from_ref(b));
            while let Some(Ok(f)) = bytewise.next_frame() {
                again.push(f);
            }
        }
        assert_eq!(frames, again);
        let mut chunked = Decoder::new(framing);
        let mut third = Vec::new();
        let mut rest = data;
        while let Some(&first) = rest.first() {
            let (head, tail) = rest.split_at(usize::from(first % 16 + 1).min(rest.len()));
            chunked.feed(head);
            rest = tail;
            while let Some(Ok(f)) = chunked.next_frame() {
                third.push(f);
            }
        }
        assert_eq!(frames, third);

        for f in &frames {
            // A frame read can be written, and reads back the same.
            let bytes = f.to_bytes(framing).unwrap();
            assert_eq!(Frame::parse(framing, &bytes), Ok(Some((f.clone(), bytes.len()))));
            let _ = Message::parse(&f.data);
        }
    }
});
