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
use fictionet::{Budget, stdlib::protocols::fields::Fields};

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
