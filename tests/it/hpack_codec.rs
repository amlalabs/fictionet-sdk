//! Public HPACK and shared Huffman values through the codec tools.
use fictionet::stdlib::{
    codec::{Collect, Lcg, Wire},
    hpack::{self, Encoder, Field, StringLiteral, Table},
    huffman::{self, HuffmanString},
    prefix_int::Integer,
    test_support,
    test_support::contract,
};

#[test]
fn wire_contracts_and_collection_at_eof() {
    let mut rng = Lcg::new(7541);
    for _ in 0..64 {
        let bytes = rng.bytes(128);
        contract::check_wire::<Integer<5>>(&bytes);
        contract::check_wire::<Integer<8>>(&bytes);
        contract::check_wire::<StringLiteral>(&bytes);
        contract::check_wire::<Field>(&bytes);
        contract::check_wire::<HuffmanString>(&bytes);
        let mut field = Field::new(rng.bytes(64), &bytes);
        field.never_index = rng.coin();
        contract::check_wire_value(&field);
        contract::check_wire_value(&StringLiteral(bytes.clone()));
        contract::check_wire_value(&HuffmanString(bytes));
        let wire = field.to_bytes().unwrap();
        let make = || Collect::<Field>::new(hpack::MAX_BLOCK);
        contract::check_decode(make, &wire);
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
        let block = decoder.decode_block(&bytes, hpack::MAX_DECODED).unwrap();
        assert_eq!(block.more, 0);
        let back: Vec<_> = block
            .headers
            .into_iter()
            .map(|h| Field {
                name: h.name.unwrap(),
                value: h.value.unwrap(),
                never_index: h.never_index,
            })
            .collect();
        assert_eq!(back, fields);
        assert_eq!(decoder.table_size(), encoder.table_size());
        assert!(decoder.table_size() <= decoder.settings_limit().unwrap());
    }
}

#[test]
fn copied_modules_use_the_same_public_contracts() {
    use fictionet_copy_modules::{hpack as copied, huffman as shared};
    let field = copied::Field::new("x-owned", [0, 255]);
    contract::check_wire_value(&field);
    let bytes = field.to_bytes().unwrap();
    contract::check_decode(|| Collect::<copied::Field>::new(hpack::MAX_BLOCK), &bytes);
    contract::check_wire_value(&shared::HuffmanString(vec![0, 255]));
    let integer = fictionet_copy_modules::prefix_int::Integer::<5> {
        flags: 0x20,
        value: u64::MAX,
    };
    contract::check_wire_value(&integer);
    assert_eq!(
        Integer::<5>::parse(&integer.to_bytes().unwrap())
            .unwrap()
            .value,
        u64::MAX
    );
    let mut encoder = copied::Encoder::default();
    let mut bytes = Vec::new();
    encoder.encode_block(&[field], &mut bytes).unwrap();
    let result = copied::Table::default()
        .decode_block(&bytes, copied::MAX_DECODED)
        .unwrap();
    assert_eq!(
        result.headers[0].name.as_deref(),
        Some(b"x-owned".as_slice())
    );
    assert_eq!(
        huffman::decode(&shared::HuffmanString(vec![0, 255]).to_bytes().unwrap()).unwrap(),
        [0, 255]
    );
}
