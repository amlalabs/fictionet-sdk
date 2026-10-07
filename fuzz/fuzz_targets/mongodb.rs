//! MongoDB wire protocol messages and BSON documents, as a world playing a
//! database server reads them, and values built from the input as a world
//! writes them.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode_with_alloc_limit, check_wire, check_wire_value};
use fictionet::stdlib::mongodb::{
    Body, Bson, Compressed, Document, Message, Messages, Msg, Query, Reply, Sequence, MAX_MESSAGE_SIZE,
};
use fictionet::stdlib::codec::{Wire, test_support::decode_all};
use libfuzzer_sys::fuzz_target;

/// Bytes taken one at a time from the input, then zeros.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&mut self) -> u8 {
        let (&b, rest) = self.0.split_first().unwrap_or((&0, &[]));
        self.0 = rest;
        b
    }

    fn text(&mut self) -> String {
        let n = usize::from(self.u8() % 8);
        (0..n).map(|_| char::from(b'a' + self.u8() % 4)).collect()
    }
}

/// A value built from the input, nested at most `depth` more levels.
fn value(b: &mut Bytes<'_>, depth: u8) -> Bson {
    match b.u8() % 12 {
        0 => Bson::Int32(i32::from(b.u8())),
        1 => Bson::String(b.text()),
        2 if depth > 0 => Bson::Document(document(b, depth - 1)),
        3 if depth > 0 => Bson::Array((0..b.u8() % 4).map(|_| value(b, depth - 1)).collect()),
        4 => Bson::Binary { subtype: b.u8(), bytes: (0..b.u8() % 8).map(|_| b.u8()).collect() },
        5 => Bson::Regex { pattern: b.text(), options: b.text() },
        6 => Bson::Double(f64::from(b.u8()) / 3.0),
        7 => Bson::Boolean(b.u8() & 1 == 1),
        8 if depth > 0 => Bson::JavaScriptWithScope { code: b.text(), scope: document(b, depth - 1) },
        9 => Bson::Timestamp { time: u32::from(b.u8()), increment: u32::from(b.u8()) },
        10 => Bson::DbPointer { namespace: b.text(), id: [b.u8(); 12] },
        _ => Bson::Null,
    }
}

fn document(b: &mut Bytes<'_>, depth: u8) -> Document {
    let mut doc = Document::new();
    for _ in 0..b.u8() % 5 {
        doc.push(b.text(), value(b, depth));
    }
    doc
}

/// A message built from the input.
fn message(b: &mut Bytes<'_>) -> Message {
    let body = match b.u8() % 4 {
        0 => {
            let mut m = Msg::new(document(b, 3));
            m.flags = u32::from(b.u8() & 3) | (u32::from(b.u8() & 1) << 16) | (u32::from(b.u8() & 1) << 20);
            for _ in 0..b.u8() % 3 {
                let documents = (0..b.u8() % 3).map(|_| document(b, 2)).collect();
                m.sequences.push(Sequence { identifier: b.text(), documents });
            }
            Body::Msg(m)
        }
        1 => Body::Query(Query {
            flags: u32::from(b.u8()),
            collection: b.text(),
            number_to_skip: 0,
            number_to_return: -1,
            query: document(b, 3),
            fields: if b.u8() & 1 == 1 { Some(document(b, 1)) } else { None },
        }),
        2 => Body::Reply(Reply::new((0..b.u8() % 3).map(|_| document(b, 3)).collect())),
        _ => {
            let data: Vec<u8> = (0..b.u8() % 8).map(|_| b.u8()).collect();
            let size = if b.u8() & 1 == 1 { data.len() as i32 } else { i32::from(b.u8()) - 8 };
            Body::Compressed(Compressed {
                original_op_code: 2013,
                uncompressed_size: size,
                compressor: b.u8() % 4,
                data,
            })
        }
    };
    Message { request_id: 1, response_to: 0, body }
}

fuzz_target!(|data: &[u8]| {
    check_decode_with_alloc_limit(Messages::new, data, 2 * MAX_MESSAGE_SIZE);
    check_decode_with_alloc_limit(|| Messages::with_limit(64), data, 128);
    check_wire::<Message>(data);
    check_wire::<Document>(data);
    for message in decode_all(Messages::new, data).0.into_iter().flatten() {
        assert!(message.to_bytes().is_ok(), "{message:?}");
        check_wire_value(&message);
    }
    let mut bytes = Bytes(data);
    check_wire_value(&document(&mut bytes, 4));
    let message = message(&mut bytes);
    check_wire_value(&message);
    if let Ok(encoded) = message.to_bytes() {
        check_decode_with_alloc_limit(Messages::new, &encoded, 2 * MAX_MESSAGE_SIZE);
    }
});
