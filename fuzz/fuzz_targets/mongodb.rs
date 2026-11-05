//! MongoDB wire protocol messages and BSON documents, as a world playing a
//! database server reads them, and values built from the input as a world
//! writes them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::mongodb::{
    Body, Bson, Compressed, Document, MAX_MESSAGE_SIZE, Message, Msg, Query, Reply, Sequence,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
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
        4 => Bson::Binary {
            subtype: b.u8(),
            bytes: (0..b.u8() % 8).map(|_| b.u8()).collect(),
        },
        5 => Bson::Regex {
            pattern: b.text(),
            options: b.text(),
        },
        6 => Bson::Double(f64::from(b.u8()) / 3.0),
        7 => Bson::Boolean(b.u8() & 1 == 1),
        8 if depth > 0 => Bson::JavaScriptWithScope {
            code: b.text(),
            scope: document(b, depth - 1),
        },
        9 => Bson::Timestamp {
            time: u32::from(b.u8()),
            increment: u32::from(b.u8()),
        },
        10 => Bson::DbPointer {
            namespace: b.text(),
            id: [b.u8(); 12],
        },
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
            m.flags = u32::from(b.u8() & 3)
                | (u32::from(b.u8() & 1) << 16)
                | (u32::from(b.u8() & 1) << 20);
            for _ in 0..b.u8() % 3 {
                let documents = (0..b.u8() % 3).map(|_| document(b, 2)).collect();
                m.sequences.push(Sequence {
                    identifier: b.text(),
                    documents,
                });
            }
            Body::Msg(m)
        }
        1 => Body::Query(Query {
            flags: u32::from(b.u8()),
            collection: b.text(),
            number_to_skip: 0,
            number_to_return: -1,
            query: document(b, 3),
            fields: if b.u8() & 1 == 1 {
                Some(document(b, 1))
            } else {
                None
            },
        }),
        2 => Body::Reply(Reply::new(
            (0..b.u8() % 3).map(|_| document(b, 3)).collect(),
        )),
        _ => {
            let data: Vec<u8> = (0..b.u8() % 8).map(|_| b.u8()).collect();
            let size = if b.u8() & 1 == 1 {
                data.len() as i32
            } else {
                i32::from(b.u8()) - 8
            };
            Body::Compressed(Compressed {
                original_op_code: 2013,
                uncompressed_size: size,
                compressor: b.u8() % 4,
                data,
            })
        }
    };
    Message {
        request_id: 1,
        response_to: 0,
        body,
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Message>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE_SIZE);
            }
        ),
        decode_all(Frames::<Message>::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Message>::with_limit(64)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 128);
            }
        ),
        decode_all(|| Frames::<Message>::with_limit(64), data),
    );
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Document as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for message in decode_all(Frames::<Message>::new, data)
        .0
        .into_iter()
        .flatten()
    {
        assert!(message.to_bytes().is_ok(), "{message:?}");
        let _ = assert_write(&message);
    }
    let mut bytes = Bytes(data);
    let _ = assert_write(&document(&mut bytes, 4));
    let message = message(&mut bytes);
    let _ = assert_write(&message);
    if let Ok(encoded) = message.to_bytes() {
        assert_eq!(
            decode_chunks(
                &mut Stream::new(Frames::<Message>::new()),
                chunks(&encoded, &[1, 7, 64]),
                |s| {
                    assert!(s.allocated() <= 2 * MAX_MESSAGE_SIZE);
                }
            ),
            decode_all(Frames::<Message>::new, &encoded),
        );
    }
});
