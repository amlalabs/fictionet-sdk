//! MongoDB wire protocol messages and BSON documents, as a world playing a
//! database server reads them, and values built from the input as a world
//! writes them.
#![no_main]

use fictionet::stdlib::mongodb::{
    Body, Bson, Compressed, Decoder, Document, Message, MessageError, Msg, Query, Reply, Sequence,
};
use libfuzzer_sys::fuzz_target;

/// Every message the decoder gives, stopping where the stream breaks. It
/// feeds `chunk` bytes at a time, at most what the decoder takes, and checks
/// that it never holds more than its capacity.
fn decode(data: &[u8], chunk: usize, limit: usize) -> Vec<Result<Message, MessageError>> {
    let mut decoder = Decoder::with_limit(limit);
    let mut out = Vec::new();
    for piece in data.chunks(chunk.max(1)) {
        let mut piece = piece;
        while !piece.is_empty() {
            let took = decoder.feed(piece);
            assert!(decoder.buffered() <= decoder.capacity());
            piece = &piece[took..];
            let mut got = false;
            while let Some(m) = decoder.next_message() {
                got = true;
                out.push(m);
                if decoder.failed().is_some() {
                    return out;
                }
            }
            // A full decoder always gives a message or an error.
            assert!(took > 0 || got);
        }
    }
    out
}

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
    // The stream, split three ways: all at once, a byte at a time, and
    // through a decoder with a small limit.
    let messages = decode(data, data.len(), usize::MAX);
    assert_eq!(messages, decode(data, 1, usize::MAX));
    let small = decode(data, 7, 64);
    assert!(small.len() <= messages.len() + 1);

    for m in messages.into_iter().flatten() {
        // A message read can be written, and reads back the same. Inputs
        // here are far below the size limits, so writing cannot fail.
        let bytes = m.to_bytes().unwrap();
        let (back, used) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(back, m);
        assert_eq!(used, bytes.len());
    }
    // Any bytes as a BSON document on their own.
    if let Ok((doc, used)) = Document::parse(data) {
        assert!(used <= data.len());
        let bytes = doc.to_bytes().unwrap();
        assert_eq!(Document::parse(&bytes).unwrap(), (doc, bytes.len()));
    }
    // Values built from the bytes, not read: whatever a writer accepts
    // reads back the same.
    let mut b = Bytes(data);
    let doc = document(&mut b, 4);
    if let Ok(bytes) = doc.to_bytes() {
        assert_eq!(Document::parse(&bytes).unwrap(), (doc, bytes.len()));
    }
    let m = message(&mut b);
    if let Ok(bytes) = m.to_bytes() {
        assert_eq!(Message::parse(&bytes).unwrap(), Some((m, bytes.len())));
    }
});
