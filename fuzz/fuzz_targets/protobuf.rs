//! Protobuf messages and their gRPC and delimited framing, as a world
//! playing a gRPC server reads them.
#![no_main]
#![allow(deprecated)] // This target also checks the compatibility API.

use std::collections::BTreeMap;

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::protobuf::{Decoder, Frame, Framing, MAX_BUFFERED, MAX_FIELDS, Message, Value};
use libfuzzer_sys::fuzz_target;

// Counts fields as MAX_FIELDS does: group members included.
fn total_fields(m: &Message) -> usize {
    m.fields.iter().map(|f| 1 + if let Value::Group(g) = &f.value { total_fields(g) } else { 0 }).sum()
}

fuzz_target!(|data: &[u8]| {
    use fictionet::stdlib::protobuf::{DelimitedFrame, Frames};
    contract::check_decode(|| Frames::new(Framing::Grpc), data);
    contract::check_decode(|| Frames::new(Framing::Delimited), data);
    contract::check_wire::<Frame>(data);
    contract::check_wire::<DelimitedFrame>(data);
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

    // Fed all at once, more than MAX_BUFFERED bytes break the stream on
    // purpose, while smaller feeds with frames taken out between them do
    // not. So the three ways agree only on streams within the limit.
    if data.len() > MAX_BUFFERED {
        return;
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
            contract::check_wire_value(f);
            contract::check_wire_value(&DelimitedFrame(f.clone()));
            // A frame read can be written, and reads back the same.
            let bytes = f.to_bytes(framing).unwrap();
            assert_eq!(Frame::parse(framing, &bytes), Ok(Some((f.clone(), bytes.len()))));
            let _ = Message::parse(&f.data);
        }
    }
});
