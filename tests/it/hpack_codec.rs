//! Public HPACK and shared Huffman values through the codec tools.
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet::stdlib::{
    codec::{Collect, Lcg, Wire},
    protocols::{
        hpack::{self, Encoder, Field, StringLiteral, Table},
        huffman::{self, HuffmanString},
        prefix_int::Integer,
    },
    test_support,
};
use fictionet::{Budget, Chunk, stdlib::protocols::fields::Fields};

use crate::common::alloc::measuring;

#[test]
fn wire_contracts_and_collection_at_eof() {
    let mut rng = Lcg::new(7541);
    for _ in 0..64 {
        let bytes = rng.bytes(128);
        if let Ok(value) = <Integer<5> as Wire>::parse(&bytes) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <Integer<8> as Wire>::parse(&bytes) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <StringLiteral as Wire>::parse(&bytes) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <Field as Wire>::parse(&bytes) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <HuffmanString as Wire>::parse(&bytes) {
            let _ = assert_write(&value);
        }
        let mut field = Field::new(rng.bytes(64), &bytes);
        field.never_index = rng.coin();
        let _ = assert_write(&field);
        let _ = assert_write(&StringLiteral(bytes.clone()));
        let _ = assert_write(&HuffmanString(bytes));
        let wire = field.to_bytes().unwrap();
        let make = || Collect::<Field>::new(hpack::MAX_BLOCK);
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(&wire, &[1, 7, 64]), |_| {}),
            decode_all(make, &wire)
        );
        let (items, fail) = test_support::decode_all(make, &wire);
        assert_eq!(items, [field]);
        assert_eq!(fail, None);
    }
}

#[test]
fn settings_table_eviction_and_round_trips_through_public_api() {
    let mut rng = Lcg::new(0xcafe7541);
    let mut encoder = Encoder::new(512);
    let mut decoder = Table::new(512);
    for i in 0..128 {
        if i % 16 == 0 {
            let size = rng.index(513);
            encoder.set_settings_limit(size);
            decoder.set_settings_limit(size);
            encoder.set_capacity(size).unwrap();
        }
        let mut fields = vec![
            Field::new(":method", "GET"),
            Field::new("x-number", i.to_string()),
            Field::new("x-bytes", rng.bytes(128)),
        ];
        fields[2].never_index = rng.coin();
        let mut bytes = Vec::new();
        encoder.encode_block(&fields, &mut bytes).unwrap();
        let mut block = Fields::new();
        decoder
            .decode_block(&bytes, &mut block, &Budget::unlimited(), hpack::MAX_DECODED)
            .unwrap();
        assert_eq!(block.left_out(), 0);
        let decoded: Vec<Field> = block
            .iter_marked()
            .map(|(name, value, never_index)| Field {
                name: name.to_vec(),
                value: value.to_vec(),
                never_index,
            })
            .collect();
        assert_eq!(decoded, fields);
        assert_eq!(decoder.table_size(), encoder.table_size());
        assert!(decoder.table_size() <= decoder.settings_limit());
    }
}

#[test]
fn fields_huffman_strings_and_prefix_integers_keep_the_public_contracts() {
    let field = hpack::Field::new("x-owned", [0, 255]);
    let _ = assert_write(&field);
    let bytes = field.to_bytes().unwrap();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Collect::<hpack::Field>::new(hpack::MAX_BLOCK)),
            chunks(&bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Collect::<hpack::Field>::new(hpack::MAX_BLOCK), &bytes)
    );
    let _ = assert_write(&huffman::HuffmanString(vec![0, 255]));
    let integer = Integer::<5> {
        flags: 0x20,
        value: u64::MAX,
    };
    let _ = assert_write(&integer);
    assert_eq!(
        Integer::<5>::parse(&integer.to_bytes().unwrap())
            .unwrap()
            .value,
        u64::MAX
    );
    let mut encoder = hpack::Encoder::default();
    let mut bytes = Vec::new();
    encoder.encode_block(&[field], &mut bytes).unwrap();
    let mut result = Fields::new();
    hpack::Table::default()
        .decode_block(
            &bytes,
            &mut result,
            &Budget::unlimited(),
            hpack::MAX_DECODED,
        )
        .unwrap();
    assert_eq!(result.iter().next().unwrap().0, b"x-owned");
    assert_eq!(
        huffman::decode(&huffman::HuffmanString(vec![0, 255]).to_bytes().unwrap()).unwrap(),
        [0, 255]
    );
}

/// A field with incremental indexing larger than the whole table empties
/// the table and is not added (RFC 7541 section 4.4), and no copy of it is
/// made for the table: decoding it allocates nothing as large as its value.
#[test]
fn an_entry_larger_than_the_table_is_not_copied_for_it() {
    let incremental = |name: &[u8], value: &[u8]| {
        let mut bytes = vec![0x40];
        bytes.extend(StringLiteral(name.to_vec()).to_bytes().unwrap());
        bytes.extend(StringLiteral(value.to_vec()).to_bytes().unwrap());
        bytes
    };
    let mut decoder = Table::new(4096);
    let mut fields = Fields::new();
    let small = incremental(b"x-small", b"kept");
    decoder
        .decode_block(
            &small,
            &mut fields,
            &Budget::unlimited(),
            hpack::MAX_DECODED,
        )
        .unwrap();
    assert_eq!(decoder.table_len(), 1);
    let value = vec![b'v'; 60_000];
    let big = incremental(b"x-big", &value);
    let block = Chunk::block(&Budget::unlimited(), 0, 2 * value.len()).unwrap();
    let mut fields = Fields::in_block(block);
    let (decoded, stats) = measuring(|| {
        decoder.decode_block(&big, &mut fields, &Budget::unlimited(), hpack::MAX_DECODED)
    });
    decoded.unwrap();
    assert_eq!(fields.iter().next().unwrap().1, &value[..]);
    assert_eq!(decoder.table_len(), 0, "the table is emptied");
    assert!(
        stats.largest_request < value.len(),
        "{} bytes allocated at once for a {}-byte entry the table cannot hold",
        stats.largest_request,
        value.len()
    );
}

/// The encoder does as the decoder does: a field larger than its whole
/// table empties the table and is not copied into it, and the table never
/// holds more than `most_held()`.
#[test]
fn an_encoder_entry_larger_than_the_table_is_not_copied_for_it() {
    let mut encoder = Encoder::new(4096);
    let mut out = Vec::new();
    encoder
        .encode_block(&[Field::new("x-small", "kept")], &mut out)
        .unwrap();
    assert!(encoder.table_size() > 0);
    let value = vec![b'v'; 60_000];
    let big = [Field::new("x-big", &value)];
    let mut out = Vec::with_capacity(encoder.block_bound(&big).unwrap());
    let charge = encoder.most_held();
    let (encoded, stats) = measuring(|| encoder.encode_block(&big, &mut out));
    encoded.unwrap();
    assert_eq!(encoder.table_size(), 0, "the table is emptied");
    assert!(
        stats.largest_request < value.len(),
        "{} bytes allocated at once for a {}-byte entry the table cannot hold",
        stats.largest_request,
        value.len()
    );
    assert!(
        encoder.held() <= charge,
        "the table holds {} bytes, past its bound of {charge}",
        encoder.held()
    );
}
