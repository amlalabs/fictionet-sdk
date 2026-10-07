//! Compile generated modules against the public SDK and run their contracts.
#![allow(dead_code)]

#[path = "golden/blocks.rs"]
mod blocks;
#[path = "golden/float_nulls.rs"]
mod float_nulls;
#[path = "golden/long_names.rs"]
mod long_names;
#[path = "golden/one_field.rs"]
mod one_field;
#[path = "../../tests/codegen.rs"]
mod sdk;
#[path = "golden/short_names.rs"]
mod short_names;

#[test]
fn optional_flags_and_float_null_bits() {
    use fictionet::stdlib::codec::Wire;
    use float_nulls::{Error, Floats};
    let value = Floats {
        small: None,
        large: None,
        decimal: None,
        negative_zero: Some(0.0),
        flag: None,
    };
    let mut bytes = value.to_bytes().unwrap();
    assert_eq!(Floats::parse(&bytes).unwrap(), value);
    *bytes.last_mut().unwrap() = 2;
    assert_eq!(Floats::parse(&bytes), Err(Error::Value));
    let mut invalid = value;
    invalid.small = Some(f32::MAX);
    let mut out = vec![7];
    assert_eq!(invalid.write(&mut out), Err(Error::Value));
    assert_eq!(out, [7]);
}

#[test]
fn blocks_extend_shrink_and_check_headers() {
    use blocks::{Book, Entry, Error, Heartbeat, Message, Price, Side};
    use fictionet::stdlib::codec::Wire;
    let book = Book {
        time: 5,
        code: b"AB".to_vec(),
        entries: vec![Entry {
            price: Price { mantissa: Some(-3) },
            level: 2,
            side: Some(Side::Sell),
        }],
        note: b"hi".to_vec(),
    };
    let message = Message::Book(book.clone());
    let bytes = message.to_bytes().unwrap();
    // Header, 12-byte block, group header, one 16-byte entry, note.
    assert_eq!(bytes.len(), 8 + 12 + 4 + 16 + 2 + 2);
    assert_eq!(&bytes[..8], &[12, 0, 46, 0, 7, 0, 3, 0]);
    assert_eq!(Message::parse(&bytes).unwrap(), message);
    assert_eq!(
        (Price::EXPONENT, Book::SOURCE, Entry::KIND),
        (-9, &b"8"[..], Side::Buy)
    );

    // A newer sender's longer root block: extra bytes are skipped.
    let mut longer = bytes.clone();
    longer[0] = 15;
    longer.splice(20..20, [9, 9, 9]);
    assert_eq!(Message::parse(&longer).unwrap(), message);
    // An older sender's block ends after the fixed fields (11 bytes).
    let mut shorter = bytes.clone();
    shorter[0] = 11;
    shorter.remove(19);
    assert_eq!(Message::parse(&shorter).unwrap(), message);
    shorter[0] = 10;
    shorter.remove(18);
    assert_eq!(Message::parse(&shorter), Err(Error::Layout));

    // Group entries also take their length from the group header.
    let mut entries = bytes.clone();
    entries[20] = 18;
    entries.splice(40..40, [0, 0]);
    assert_eq!(Message::parse(&entries).unwrap(), message);

    for (at, value, error) in [
        (2, 47, Error::Header),
        (4, 8, Error::Header),
        (6, 1, Error::Header),
        (6, 0xff, Error::Value),
        (33, 0, Error::Value),
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        if at == 6 && value == 0xff {
            bad[7] = 0xff;
        }
        assert_eq!(Message::parse(&bad), Err(error), "byte {at}");
    }
    // Gap bytes are ignored when read and written as zero.
    let mut gap = bytes.clone();
    gap[16] = 0x55;
    assert_eq!(Message::parse(&gap).unwrap(), message);

    let heartbeat = Message::Heartbeat(Heartbeat {});
    assert_eq!(heartbeat.to_bytes().unwrap(), [0, 0, 12, 0, 7, 0, 3, 0]);
    let mut out = vec![1];
    let mut invalid = book;
    invalid.entries[0].level = 11;
    assert_eq!(Message::Book(invalid).write(&mut out), Err(Error::Value));
    assert_eq!(out, [1]);
}
